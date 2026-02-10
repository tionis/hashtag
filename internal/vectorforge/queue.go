package vectorforge

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

type enqueueRequest struct {
	job JobRequest
	ack chan enqueueAck
}

type enqueueAck struct {
	result EnqueueResult
	err    error
}

// QueueManager coordinates all writes to queue.db through a single writable handle.
type QueueManager struct {
	db            *sql.DB
	logger        *log.Logger
	enqueueCh     chan enqueueRequest
	batchSize     int
	batchInterval time.Duration
}

func NewQueueManager(db *sql.DB, logger *log.Logger, bufferSize, batchSize int, batchInterval time.Duration) *QueueManager {
	return &QueueManager{
		db:            db,
		logger:        logger,
		enqueueCh:     make(chan enqueueRequest, bufferSize),
		batchSize:     batchSize,
		batchInterval: batchInterval,
	}
}

func (qm *QueueManager) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		qm.runEnqueueLoop(ctx)
	}()
}

func (qm *QueueManager) Enqueue(ctx context.Context, job JobRequest) (EnqueueResult, error) {
	ack := make(chan enqueueAck, 1)
	req := enqueueRequest{job: job, ack: ack}

	select {
	case <-ctx.Done():
		return EnqueueResult{}, ctx.Err()
	case qm.enqueueCh <- req:
	}

	select {
	case <-ctx.Done():
		return EnqueueResult{}, ctx.Err()
	case out := <-ack:
		return out.result, out.err
	}
}

func (qm *QueueManager) runEnqueueLoop(ctx context.Context) {
	ticker := time.NewTicker(qm.batchInterval)
	defer ticker.Stop()

	batch := make([]enqueueRequest, 0, qm.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		pending := batch
		batch = make([]enqueueRequest, 0, qm.batchSize)
		qm.flushBatch(ctx, pending)
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case req := <-qm.enqueueCh:
			batch = append(batch, req)
			if len(batch) >= qm.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (qm *QueueManager) flushBatch(ctx context.Context, batch []enqueueRequest) {
	if len(batch) == 0 {
		return
	}

	txCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := qm.db.BeginTx(txCtx, nil)
	if err != nil {
		qm.ackBatchError(batch, fmt.Errorf("begin enqueue tx: %w", err))
		return
	}

	results := make([]enqueueAck, len(batch))
	const query = `
INSERT INTO jobs (file_hash, kind, status, file_path, updated_at)
VALUES (?, ?, 'pending', ?, CURRENT_TIMESTAMP)
ON CONFLICT(file_hash, kind) DO UPDATE SET
    status = CASE WHEN jobs.status IN ('done', 'error') THEN 'pending' ELSE jobs.status END,
    file_path = CASE
        WHEN jobs.status IN ('done', 'error') OR length(jobs.file_path) != 64
        THEN excluded.file_path
        ELSE jobs.file_path
    END,
    attempts = CASE WHEN jobs.status IN ('done', 'error') THEN 0 ELSE jobs.attempts END,
    last_error = CASE WHEN jobs.status IN ('done', 'error') THEN NULL ELSE jobs.last_error END,
    updated_at = CURRENT_TIMESTAMP
RETURNING id, file_path;
`

	for i, req := range batch {
		var (
			id        int64
			storedRef string
		)
		if err := tx.QueryRowContext(txCtx, query, req.job.FileHash, req.job.Kind, req.job.PayloadRef).Scan(&id, &storedRef); err != nil {
			tx.Rollback()
			qm.ackBatchError(batch, fmt.Errorf("upsert queue job: %w", err))
			return
		}

		results[i] = enqueueAck{
			result: EnqueueResult{
				JobID:            id,
				StoredPayloadRef: storedRef,
				ReusedQueue:      storedRef != req.job.PayloadRef,
			},
		}
	}

	if err := tx.Commit(); err != nil {
		qm.ackBatchError(batch, fmt.Errorf("commit enqueue tx: %w", err))
		return
	}

	for i, req := range batch {
		req.ack <- results[i]
	}
}

func (qm *QueueManager) ackBatchError(batch []enqueueRequest, err error) {
	for _, req := range batch {
		req.ack <- enqueueAck{err: err}
	}
	qm.logger.Printf("queue enqueue batch failed: %v", err)
}

func (qm *QueueManager) ClaimPending(ctx context.Context, limit int) ([]QueueJob, error) {
	if limit <= 0 {
		return nil, nil
	}

	const query = `
UPDATE jobs
SET status = 'processing', updated_at = CURRENT_TIMESTAMP, attempts = attempts + 1
WHERE id IN (
    SELECT id
    FROM jobs
    WHERE status = 'pending'
    ORDER BY id
    LIMIT ?
)
RETURNING id, file_path, file_hash, kind, attempts;
`

	rows, err := qm.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("claim pending jobs: %w", err)
	}
	defer rows.Close()

	jobs := make([]QueueJob, 0, limit)
	for rows.Next() {
		var j QueueJob
		if err := rows.Scan(&j.ID, &j.PayloadRef, &j.FileHash, &j.Kind, &j.Attempts); err != nil {
			return nil, fmt.Errorf("scan claimed job: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed jobs: %w", err)
	}
	return jobs, nil
}

func (qm *QueueManager) MarkDone(ctx context.Context, id int64) error {
	_, err := qm.db.ExecContext(ctx, `
UPDATE jobs
SET status = 'done', last_error = NULL, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
`, id)
	if err != nil {
		return fmt.Errorf("mark job done: %w", err)
	}
	return nil
}

func (qm *QueueManager) MarkError(ctx context.Context, id int64, workerErr error) error {
	msg := "unknown error"
	if workerErr != nil {
		msg = workerErr.Error()
	}
	if len(msg) > 1000 {
		msg = msg[:1000]
	}

	_, err := qm.db.ExecContext(ctx, `
UPDATE jobs
SET status = 'error', last_error = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
`, msg, id)
	if err != nil {
		return fmt.Errorf("mark job error: %w", err)
	}
	return nil
}

// HandleWorkerFailure transitions a processing job back to pending for retry,
// or to terminal error when attempts have reached maxAttempts.
func (qm *QueueManager) HandleWorkerFailure(ctx context.Context, id int64, maxAttempts int, workerErr error) (string, error) {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	msg := "unknown error"
	if workerErr != nil {
		msg = workerErr.Error()
	}
	if len(msg) > 1000 {
		msg = msg[:1000]
	}

	var status string
	if err := qm.db.QueryRowContext(ctx, `
UPDATE jobs
SET status = CASE WHEN attempts >= ? THEN 'error' ELSE 'pending' END,
    last_error = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING status;
`, maxAttempts, msg, id).Scan(&status); err != nil {
		return "", fmt.Errorf("handle worker failure for job %d: %w", id, err)
	}
	return status, nil
}

func (qm *QueueManager) PendingCount(ctx context.Context) (int, error) {
	var count int
	if err := qm.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM jobs WHERE status = 'pending';`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending jobs: %w", err)
	}
	return count, nil
}

func (qm *QueueManager) ResetProcessing(ctx context.Context) (int64, error) {
	result, err := qm.db.ExecContext(ctx, `
UPDATE jobs
SET status = 'pending', updated_at = CURRENT_TIMESTAMP
WHERE status = 'processing';
`)
	if err != nil {
		return 0, fmt.Errorf("reset processing jobs: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

func (qm *QueueManager) CleanupDoneOlderThan(ctx context.Context, olderThan time.Duration) (int64, error) {
	seconds := int(olderThan / time.Second)
	if seconds <= 0 {
		seconds = 3600
	}
	query := `
DELETE FROM jobs
WHERE status = 'done'
  AND updated_at < DATETIME('now', ?);
`
	result, err := qm.db.ExecContext(ctx, query, fmt.Sprintf("-%d seconds", seconds))
	if err != nil {
		return 0, fmt.Errorf("cleanup old done jobs: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

func (qm *QueueManager) FindProcessingHashes(ctx context.Context, kind string, hashes []string) (map[string]struct{}, error) {
	if len(hashes) == 0 {
		return map[string]struct{}{}, nil
	}

	query := fmt.Sprintf(
		`SELECT file_hash FROM jobs WHERE kind = ? AND status IN ('pending', 'processing') AND file_hash IN (%s);`,
		placeholders(len(hashes)),
	)
	args := make([]any, 0, len(hashes)+1)
	args = append(args, kind)
	for _, h := range hashes {
		args = append(args, h)
	}

	rows, err := qm.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query processing hashes: %w", err)
	}
	defer rows.Close()

	out := make(map[string]struct{}, len(hashes))
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan processing hash: %w", err)
		}
		out[hash] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate processing hashes: %w", err)
	}
	return out, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	if n == 1 {
		return "?"
	}
	return strings.TrimRight(strings.Repeat("?,", n), ",")
}
