package vectorforge

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeebo/blake3"
)

type testHarness struct {
	t            *testing.T
	dir          string
	queueDB      *sql.DB
	embedDB      *sql.DB
	queue        *QueueManager
	payloads     payloadStore
	blobCacheDir string
	server       *HTTPServer
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	cleanup      func()
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	dir := t.TempDir()

	queuePath := filepath.Join(dir, "queue.db")
	embedPath := filepath.Join(dir, "embeddings.db")
	blobDBPath := filepath.Join(dir, "blob.db")
	blobCacheDir := filepath.Join(dir, "blobs")
	tempDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		t.Fatalf("mkdir temp dir: %v", err)
	}

	queueDB, err := openSQLite(queuePath, 1)
	if err != nil {
		t.Fatalf("open queue db: %v", err)
	}
	embedDB, err := openSQLite(embedPath, 2)
	if err != nil {
		_ = queueDB.Close()
		t.Fatalf("open embed db: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := initializeSchemas(ctx, queueDB, embedDB); err != nil {
		_ = queueDB.Close()
		_ = embedDB.Close()
		cancel()
		t.Fatalf("initialize schemas: %v", err)
	}

	logger := log.New(io.Discard, "", 0)
	var queueWG sync.WaitGroup
	qm := NewQueueManager(queueDB, logger, 100, 10, 10*time.Millisecond)
	qm.Start(ctx, &queueWG)

	payloads, err := openLocalBlobPayloadStore(blobDBPath, blobCacheDir)
	if err != nil {
		_ = queueDB.Close()
		_ = embedDB.Close()
		cancel()
		t.Fatalf("open payload store: %v", err)
	}

	cfg := Config{
		LookupChunkSize: 100,
		QueueAckTimeout: 500 * time.Millisecond,
		TempDir:         tempDir,
		MaxPendingJobs:  5000,
	}

	h := &testHarness{
		t:            t,
		dir:          dir,
		queueDB:      queueDB,
		embedDB:      embedDB,
		queue:        qm,
		payloads:     payloads,
		blobCacheDir: blobCacheDir,
		ctx:          ctx,
		cancel:       cancel,
	}
	h.server = NewHTTPServer(cfg, logger, qm, embedDB, payloads)
	h.cleanup = func() {
		cancel()
		queueWG.Wait()
		_ = payloads.Close()
		_ = queueDB.Close()
		_ = embedDB.Close()
	}
	return h
}

func (h *testHarness) close() {
	h.cleanup()
}

func TestLookupReportsPresentProcessingMissing(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	_, err := h.embedDB.Exec(`
INSERT INTO image_embeddings(hash, vector, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
`, "hash_present", []byte("[1,2,3]"))
	if err != nil {
		t.Fatalf("seed embedding: %v", err)
	}

	_, err = h.queue.Enqueue(context.Background(), JobRequest{
		FileHash:   "hash_processing",
		Kind:       embeddingKindImage,
		PayloadRef: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("seed queue: %v", err)
	}

	reqBody := `{"kind":"image","hashes":["hash_present","hash_processing","hash_missing"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/lookup", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 body=%s", w.Code, w.Body.String())
	}

	var out lookupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got := out.Status["hash_present"]; got != "present" {
		t.Fatalf("hash_present status: got %q", got)
	}
	if got := out.Status["hash_processing"]; got != "processing" {
		t.Fatalf("hash_processing status: got %q", got)
	}
	if got := out.Status["hash_missing"]; got != "missing" {
		t.Fatalf("hash_missing status: got %q", got)
	}
}

func TestUploadAcceptsAndPersistsQueueJob(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	payload := []byte("test-image-bytes")
	sum := blake3.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Hash", hash)
	req.Header.Set("X-Embedding-Kind", "image")
	w := httptest.NewRecorder()

	h.server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202 body=%s", w.Code, w.Body.String())
	}

	var count int
	err := h.queueDB.QueryRow(`SELECT COUNT(1) FROM jobs WHERE file_hash = ? AND kind = ? AND status = 'pending';`, hash, embeddingKindImage).Scan(&count)
	if err != nil {
		t.Fatalf("query queue row: %v", err)
	}
	if count != 1 {
		t.Fatalf("pending rows: got %d want 1", count)
	}

	var payloadRef string
	err = h.queueDB.QueryRow(`SELECT file_path FROM jobs WHERE file_hash = ? AND kind = ?;`, hash, embeddingKindImage).Scan(&payloadRef)
	if err != nil {
		t.Fatalf("query payload ref: %v", err)
	}
	cid := blake3.Sum256(payload)
	expectedCID := hex.EncodeToString(cid[:])
	if payloadRef != expectedCID {
		t.Fatalf("payload ref mismatch: got %q want %q", payloadRef, expectedCID)
	}
	payloadPath := filepath.Join(h.blobCacheDir, expectedCID[:2], expectedCID[2:4], expectedCID+".blob")
	if _, err := os.Stat(payloadPath); err != nil {
		t.Fatalf("expected payload cache object %q to exist: %v", payloadPath, err)
	}
}

func TestUploadReturnsAlreadyPresentWhenEmbeddingExists(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	payload := []byte("already-present")
	sum := blake3.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	_, err := h.embedDB.Exec(`
INSERT INTO image_embeddings(hash, vector, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
`, hash, []byte("[9,8,7]"))
	if err != nil {
		t.Fatalf("seed embedding: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Hash", hash)
	req.Header.Set("X-Embedding-Kind", "image")
	w := httptest.NewRecorder()

	h.server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 body=%s", w.Code, w.Body.String())
	}

	var out uploadResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if out.Status != "already_present" {
		t.Fatalf("status: got %q", out.Status)
	}
}

func TestUploadRejectsHashMismatch(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	payload := []byte("payload")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Hash", "deadbeef")
	req.Header.Set("X-Embedding-Kind", "image")
	w := httptest.NewRecorder()

	h.server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 body=%s", w.Code, w.Body.String())
	}
}

func TestLookupRequiresValidKind(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/lookup", bytes.NewBufferString(`{"kind":"video","hashes":["h1"]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.server.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 body=%s", w.Code, w.Body.String())
	}
}

func TestUploadSupportsTextKind(t *testing.T) {
	h := newTestHarness(t)
	defer h.close()

	payload := []byte("this is text content")
	sum := blake3.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Hash", hash)
	req.Header.Set("X-Embedding-Kind", "text")
	w := httptest.NewRecorder()

	h.server.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status: got %d want 202 body=%s", w.Code, w.Body.String())
	}

	var count int
	err := h.queueDB.QueryRow(`SELECT COUNT(1) FROM jobs WHERE file_hash = ? AND kind = ? AND status = 'pending';`, hash, embeddingKindText).Scan(&count)
	if err != nil {
		t.Fatalf("query queue row: %v", err)
	}
	if count != 1 {
		t.Fatalf("pending rows: got %d want 1", count)
	}
}
