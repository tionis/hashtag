package vectorforge

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zeebo/blake3"
)

// HTTPServer wraps API handlers and shared state.
type HTTPServer struct {
	cfg      Config
	logger   *log.Logger
	queue    enqueuer
	embedDB  *sql.DB
	payloads payloadStore
}

type enqueuer interface {
	Enqueue(ctx context.Context, job JobRequest) (EnqueueResult, error)
	PendingCount(ctx context.Context) (int, error)
	FindProcessingHashes(ctx context.Context, kind string, hashes []string) (map[string]struct{}, error)
}

func NewHTTPServer(cfg Config, logger *log.Logger, queue *QueueManager, embedDB *sql.DB, payloads payloadStore) *HTTPServer {
	return &HTTPServer{
		cfg:      cfg,
		logger:   logger,
		queue:    queue,
		embedDB:  embedDB,
		payloads: payloads,
	}
}

func (s *HTTPServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/lookup", s.handleLookup)
	mux.HandleFunc("/api/v1/upload", s.handleUpload)
	mux.HandleFunc("/healthz", s.handleHealth)
	return loggingMiddleware(s.logger, mux)
}

func (s *HTTPServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *HTTPServer) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req lookupRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid json: %v", err))
		return
	}

	req.Kind = strings.TrimSpace(req.Kind)
	kind, ok := normalizeEmbeddingKind(req.Kind)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "kind must be one of: image, text")
		return
	}
	if len(req.Hashes) == 0 {
		writeJSONError(w, http.StatusBadRequest, "hashes must not be empty")
		return
	}

	normalized := uniqueNonEmpty(req.Hashes)
	status := make(map[string]string, len(normalized))

	for i := 0; i < len(normalized); i += s.cfg.LookupChunkSize {
		end := min(i+s.cfg.LookupChunkSize, len(normalized))
		chunk := normalized[i:end]

		present, err := findPresentHashes(r.Context(), s.embedDB, kind, chunk)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		processing, err := s.queue.FindProcessingHashes(r.Context(), kind, chunk)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		for _, h := range chunk {
			if _, ok := present[h]; ok {
				status[h] = "present"
				continue
			}
			if _, ok := processing[h]; ok {
				status[h] = "processing"
				continue
			}
			status[h] = "missing"
		}
	}

	writeJSON(w, http.StatusOK, lookupResponse{Status: status})
}

func (s *HTTPServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	hashHeader := strings.TrimSpace(r.Header.Get("X-File-Hash"))
	kindHeader := strings.TrimSpace(r.Header.Get("X-Embedding-Kind"))
	kind, ok := normalizeEmbeddingKind(kindHeader)
	if hashHeader == "" {
		writeJSONError(w, http.StatusBadRequest, "missing X-File-Hash header")
		return
	}
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "missing or invalid X-Embedding-Kind header")
		return
	}

	pending, err := s.queue.PendingCount(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pending > s.cfg.MaxPendingJobs {
		writeJSONError(w, http.StatusTooManyRequests, "queue backlog too large")
		return
	}

	uploadID := uuid.NewString()
	tmpPath := filepath.Join(s.cfg.TempDir, fmt.Sprintf("%s.%s.%s", hashHeader, kind, uploadID))
	if err := os.MkdirAll(filepath.Dir(tmpPath), 0o755); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("create temp dir: %v", err))
		return
	}

	computedHash, computedCID, size, err := streamToFileAndHashes(r.Context(), r.Body, tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("read upload: %v", err))
		return
	}
	if !strings.EqualFold(computedHash, hashHeader) {
		_ = os.Remove(tmpPath)
		writeJSONError(w, http.StatusBadRequest, "uploaded content blake3 does not match X-File-Hash")
		return
	}
	if size == 0 {
		_ = os.Remove(tmpPath)
		writeJSONError(w, http.StatusBadRequest, "empty upload body")
		return
	}

	exists, err := embeddingExists(r.Context(), s.embedDB, hashHeader, kind)
	if err != nil {
		_ = os.Remove(tmpPath)
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if exists {
		_ = os.Remove(tmpPath)
		writeJSON(w, http.StatusOK, uploadResponse{Status: "already_present"})
		return
	}

	payloadRef, err := s.payloads.StoreUploadPayload(r.Context(), tmpPath, computedCID, size)
	_ = os.Remove(tmpPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("cache upload payload: %v", err))
		return
	}

	ackCtx, cancel := context.WithTimeout(r.Context(), s.cfg.QueueAckTimeout)
	defer cancel()

	result, err := s.queue.Enqueue(ackCtx, JobRequest{FileHash: hashHeader, Kind: kind, PayloadRef: payloadRef})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeJSONError(w, http.StatusServiceUnavailable, "queue ack timeout")
			return
		}
		if errors.Is(err, context.Canceled) {
			writeJSONError(w, http.StatusRequestTimeout, "request canceled")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, uploadResponse{Status: "accepted", JobID: result.JobID})
}

func streamToFileAndHashes(ctx context.Context, body io.Reader, path string) (hashHex string, blake3Hex string, bytesWritten int64, err error) {
	f, err := os.Create(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		closeErr := f.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	blake3Hasher := blake3.New()
	writer := io.MultiWriter(f, blake3Hasher)

	buf := make([]byte, 128*1024)
	for {
		select {
		case <-ctx.Done():
			return "", "", 0, ctx.Err()
		default:
		}

		n, readErr := body.Read(buf)
		if n > 0 {
			wn, writeErr := writer.Write(buf[:n])
			bytesWritten += int64(wn)
			if writeErr != nil {
				return "", "", bytesWritten, fmt.Errorf("write temp file: %w", writeErr)
			}
			if wn != n {
				return "", "", bytesWritten, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", "", bytesWritten, readErr
		}
	}

	blake3Hex = hex.EncodeToString(blake3Hasher.Sum(nil))
	return blake3Hex, blake3Hex, bytesWritten, nil
}

func loggingMiddleware(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).String())
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func uniqueNonEmpty(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
