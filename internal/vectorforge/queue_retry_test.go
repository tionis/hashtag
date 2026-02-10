package vectorforge

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type queueRetryHarness struct {
	t       *testing.T
	dir     string
	queueDB *sql.DB
	embedDB *sql.DB
	queue   *QueueManager
	logger  *log.Logger
}

func newQueueRetryHarness(t *testing.T) *queueRetryHarness {
	t.Helper()
	dir := t.TempDir()

	queuePath := filepath.Join(dir, "queue.db")
	embedPath := filepath.Join(dir, "embeddings.db")

	queueDB, err := openSQLite(queuePath, 1)
	if err != nil {
		t.Fatalf("open queue db: %v", err)
	}
	embedDB, err := openSQLite(embedPath, 1)
	if err != nil {
		_ = queueDB.Close()
		t.Fatalf("open embeddings db: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initializeSchemas(ctx, queueDB, embedDB); err != nil {
		_ = queueDB.Close()
		_ = embedDB.Close()
		t.Fatalf("initialize schemas: %v", err)
	}

	logger := log.New(io.Discard, "", 0)
	return &queueRetryHarness{
		t:       t,
		dir:     dir,
		queueDB: queueDB,
		embedDB: embedDB,
		queue:   NewQueueManager(queueDB, logger, 64, 1, 10*time.Millisecond),
		logger:  logger,
	}
}

func (h *queueRetryHarness) close() {
	h.t.Helper()
	_ = h.queueDB.Close()
	_ = h.embedDB.Close()
}

func TestApplyResults_RequeuesBeforeTerminalError(t *testing.T) {
	h := newQueueRetryHarness(t)
	defer h.close()

	tempPath := filepath.Join(h.dir, "sample.bin")
	if err := os.WriteFile(tempPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	result, err := h.queueDB.Exec(`
INSERT INTO jobs(file_hash, kind, status, file_path, attempts, updated_at)
VALUES(?, ?, 'pending', ?, 0, CURRENT_TIMESTAMP);
`, "hash-1", embeddingKindImage, tempPath)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}

	ctx := context.Background()
	claimed, err := h.queue.ClaimPending(ctx, 1)
	if err != nil {
		t.Fatalf("claim pending #1: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed #1 count mismatch: got %d want 1", len(claimed))
	}

	applyResults(ctx, h.logger, h.embedDB, h.queue, []WorkerResult{
		{Job: claimed[0], WorkerError: errors.New("first failure")},
	}, 2)

	status, _, attempts := readJobState(t, h.queueDB, jobID)
	if status != jobStatusPending {
		t.Fatalf("status after first failure: got %q want %q", status, jobStatusPending)
	}
	if attempts != 1 {
		t.Fatalf("attempts after first failure: got %d want 1", attempts)
	}
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("expected temp file to remain after retryable failure: %v", err)
	}

	claimed, err = h.queue.ClaimPending(ctx, 1)
	if err != nil {
		t.Fatalf("claim pending #2: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed #2 count mismatch: got %d want 1", len(claimed))
	}

	applyResults(ctx, h.logger, h.embedDB, h.queue, []WorkerResult{
		{Job: claimed[0], WorkerError: errors.New("second failure")},
	}, 2)

	status, _, attempts = readJobState(t, h.queueDB, jobID)
	if status != jobStatusError {
		t.Fatalf("status after terminal failure: got %q want %q", status, jobStatusError)
	}
	if attempts != 2 {
		t.Fatalf("attempts after terminal failure: got %d want 2", attempts)
	}
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("expected payload cache object to remain after terminal failure: %v", err)
	}
}

func TestHandleWorkerFailure_TrimsErrorMessage(t *testing.T) {
	h := newQueueRetryHarness(t)
	defer h.close()

	result, err := h.queueDB.Exec(`
INSERT INTO jobs(file_hash, kind, status, file_path, attempts, updated_at)
VALUES(?, ?, 'processing', ?, 1, CURRENT_TIMESTAMP);
`, "hash-2", embeddingKindImage, filepath.Join(h.dir, "f.bin"))
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}

	tooLong := strings.Repeat("x", 1205)
	status, err := h.queue.HandleWorkerFailure(context.Background(), jobID, 3, errors.New(tooLong))
	if err != nil {
		t.Fatalf("HandleWorkerFailure error: %v", err)
	}
	if status != jobStatusPending {
		t.Fatalf("status mismatch: got %q want %q", status, jobStatusPending)
	}

	_, lastErr, _ := readJobState(t, h.queueDB, jobID)
	if len(lastErr) != 1000 {
		t.Fatalf("last_error length mismatch: got %d want 1000", len(lastErr))
	}
}

func TestEnqueue_ResetsAttemptsWhenRequeueingErrorJob(t *testing.T) {
	h := newQueueRetryHarness(t)
	defer h.close()

	_, err := h.queueDB.Exec(`
INSERT INTO jobs(file_hash, kind, status, file_path, attempts, last_error, updated_at)
VALUES(?, ?, 'error', ?, 9, 'boom', CURRENT_TIMESTAMP);
`, "hash-3", embeddingKindImage, filepath.Join(h.dir, "old.bin"))
	if err != nil {
		t.Fatalf("insert error job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	h.queue.Start(ctx, &wg)
	defer func() {
		cancel()
		wg.Wait()
	}()

	newPath := filepath.Join(h.dir, "new.bin")
	enqueueCtx, enqueueCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer enqueueCancel()
	res, err := h.queue.Enqueue(enqueueCtx, JobRequest{
		FileHash:   "hash-3",
		Kind:       embeddingKindImage,
		PayloadRef: newPath,
	})
	if err != nil {
		t.Fatalf("enqueue error: %v", err)
	}
	if res.StoredPayloadRef != newPath {
		t.Fatalf("stored payload ref mismatch: got %q want %q", res.StoredPayloadRef, newPath)
	}

	var (
		status    string
		filePath  string
		attempts  int
		lastError sql.NullString
	)
	err = h.queueDB.QueryRow(`
SELECT status, file_path, attempts, last_error
FROM jobs
WHERE file_hash = ? AND kind = ?;
`, "hash-3", embeddingKindImage).Scan(&status, &filePath, &attempts, &lastError)
	if err != nil {
		t.Fatalf("query requeued job: %v", err)
	}

	if status != jobStatusPending {
		t.Fatalf("status mismatch: got %q want %q", status, jobStatusPending)
	}
	if filePath != newPath {
		t.Fatalf("file_path mismatch: got %q want %q", filePath, newPath)
	}
	if attempts != 0 {
		t.Fatalf("attempts mismatch: got %d want 0", attempts)
	}
	if lastError.Valid {
		t.Fatalf("last_error should be cleared, got %q", lastError.String)
	}
}

func TestEnqueue_ReplacesLegacyPendingPayloadPath(t *testing.T) {
	h := newQueueRetryHarness(t)
	defer h.close()

	legacyPath := filepath.Join(h.dir, "legacy-upload.bin")
	if _, err := h.queueDB.Exec(`
INSERT INTO jobs(file_hash, kind, status, file_path, attempts, updated_at)
VALUES(?, ?, 'pending', ?, 0, CURRENT_TIMESTAMP);
`, "hash-legacy", embeddingKindImage, legacyPath); err != nil {
		t.Fatalf("insert legacy pending job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	h.queue.Start(ctx, &wg)
	defer func() {
		cancel()
		wg.Wait()
	}()

	newCID := strings.Repeat("b", 64)
	enqueueCtx, enqueueCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer enqueueCancel()
	res, err := h.queue.Enqueue(enqueueCtx, JobRequest{
		FileHash:   "hash-legacy",
		Kind:       embeddingKindImage,
		PayloadRef: newCID,
	})
	if err != nil {
		t.Fatalf("enqueue error: %v", err)
	}
	if res.StoredPayloadRef != newCID {
		t.Fatalf("stored payload ref mismatch: got %q want %q", res.StoredPayloadRef, newCID)
	}

	var stored string
	if err := h.queueDB.QueryRow(`
SELECT file_path
FROM jobs
WHERE file_hash = ? AND kind = ?;
`, "hash-legacy", embeddingKindImage).Scan(&stored); err != nil {
		t.Fatalf("query legacy job: %v", err)
	}
	if stored != newCID {
		t.Fatalf("legacy pending payload path was not replaced: got %q want %q", stored, newCID)
	}
}

func readJobState(t *testing.T, db *sql.DB, jobID int64) (status string, lastError string, attempts int) {
	t.Helper()
	err := db.QueryRow(`
SELECT status, COALESCE(last_error, ''), attempts
FROM jobs
WHERE id = ?;
`, jobID).Scan(&status, &lastError, &attempts)
	if err != nil {
		t.Fatalf("read job state: %v", err)
	}
	return status, lastError, attempts
}
