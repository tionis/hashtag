package vectorforge

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

func startDispatcher(ctx context.Context, wg *sync.WaitGroup, logger *log.Logger, qm *QueueManager, out chan<- QueueJob, claimLimit int, interval time.Duration) {
	if claimLimit <= 0 {
		claimLimit = 1
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jobs, err := qm.ClaimPending(ctx, claimLimit)
				if err != nil {
					logger.Printf("dispatcher claim error: %v", err)
					continue
				}
				for _, job := range jobs {
					select {
					case <-ctx.Done():
						return
					case out <- job:
					}
				}
			}
		}
	}()
}

func startWorkerPool(ctx context.Context, wg *sync.WaitGroup, logger *log.Logger, workers int, client *WorkerClient, payloads payloadStore, in <-chan QueueJob, out chan<- WorkerResult) {
	if workers <= 0 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		workerID := i + 1
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-in:
					payloadPath, err := payloads.ResolvePayloadPath(ctx, job.PayloadRef)
					if err != nil {
						if stat, statErr := os.Stat(job.PayloadRef); statErr == nil && stat.Mode().IsRegular() {
							payloadPath = job.PayloadRef
							logger.Printf("worker %d using legacy queue payload path for job %d", workerID, job.ID)
							err = nil
						} else {
							err = fmt.Errorf("resolve payload %q: %w", job.PayloadRef, err)
						}
					}
					vector := []byte(nil)
					if err == nil {
						vector, err = client.Predict(ctx, job, payloadPath)
					}
					if err != nil {
						logger.Printf("worker %d failed job %d (%s): %v", workerID, job.ID, job.FileHash, err)
					}
					result := WorkerResult{Job: job, VectorJSON: vector, WorkerError: err}
					select {
					case <-ctx.Done():
						return
					case out <- result:
					}
				}
			}
		}()
	}
}

func startIngester(ctx context.Context, wg *sync.WaitGroup, logger *log.Logger, embeddingsDB *sql.DB, qm *QueueManager, in <-chan WorkerResult, batchSize int, batchWait time.Duration, maxAttempts int) {
	if batchSize <= 0 {
		batchSize = 1
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(batchWait)
		defer ticker.Stop()

		buffer := make([]WorkerResult, 0, batchSize)
		flush := func() {
			if len(buffer) == 0 {
				return
			}
			pending := buffer
			buffer = make([]WorkerResult, 0, batchSize)
			applyResults(ctx, logger, embeddingsDB, qm, pending, maxAttempts)
		}

		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case item := <-in:
				buffer = append(buffer, item)
				if len(buffer) >= batchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()
}

func applyResults(ctx context.Context, logger *log.Logger, embeddingsDB *sql.DB, qm *QueueManager, batch []WorkerResult, maxAttempts int) {
	if len(batch) == 0 {
		return
	}

	failed := make(map[int64]error, len(batch))
	pendingInsert := make([]WorkerResult, 0, len(batch))
	for _, item := range batch {
		if item.WorkerError != nil {
			failed[item.Job.ID] = item.WorkerError
			continue
		}
		pendingInsert = append(pendingInsert, item)
	}

	if len(pendingInsert) > 0 {
		txCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		tx, err := embeddingsDB.BeginTx(txCtx, nil)
		if err != nil {
			cancel()
			for _, item := range pendingInsert {
				failed[item.Job.ID] = fmt.Errorf("begin embedding tx: %w", err)
			}
		} else {
			commitErr := upsertEmbeddingsBatch(txCtx, tx, pendingInsert)
			if commitErr != nil {
				for _, item := range pendingInsert {
					failed[item.Job.ID] = commitErr
				}
			}
			cancel()
		}
	}

	for _, item := range batch {
		err := failed[item.Job.ID]
		statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if err != nil {
			nextStatus, failErr := qm.HandleWorkerFailure(statusCtx, item.Job.ID, maxAttempts, err)
			cancel()
			if failErr != nil {
				logger.Printf("handle failure failed for job %d: %v", item.Job.ID, failErr)
				continue
			}

			if nextStatus == jobStatusPending {
				logger.Printf("job %d requeued for retry (%d/%d): %v", item.Job.ID, item.Job.Attempts, maxAttempts, err)
				continue
			}
			if nextStatus == jobStatusError {
				logger.Printf("job %d reached max attempts (%d/%d): %v", item.Job.ID, item.Job.Attempts, maxAttempts, err)
				continue
			}
			logger.Printf("job %d transitioned to unexpected status %q after failure", item.Job.ID, nextStatus)
			continue
		}

		if markErr := qm.MarkDone(statusCtx, item.Job.ID); markErr != nil {
			logger.Printf("mark done failed for job %d: %v", item.Job.ID, markErr)
			cancel()
			continue
		}
		cancel()
	}
}

func upsertEmbeddingsBatch(ctx context.Context, tx *sql.Tx, batch []WorkerResult) error {
	const imageQ = `
INSERT INTO image_embeddings (hash, vector, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(hash) DO UPDATE SET
    vector = excluded.vector,
    updated_at = CURRENT_TIMESTAMP;
`
	const textQ = `
INSERT INTO text_embeddings (hash, vector, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(hash) DO UPDATE SET
    vector = excluded.vector,
    updated_at = CURRENT_TIMESTAMP;
`

	for _, item := range batch {
		query := ""
		switch item.Job.Kind {
		case embeddingKindImage:
			query = imageQ
		case embeddingKindText:
			query = textQ
		default:
			tx.Rollback()
			return fmt.Errorf("unsupported embedding kind %q for job %d", item.Job.Kind, item.Job.ID)
		}

		if _, err := tx.ExecContext(ctx, query, item.Job.FileHash, item.VectorJSON); err != nil {
			tx.Rollback()
			return fmt.Errorf("upsert embedding for job %d: %w", item.Job.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return fmt.Errorf("commit embedding tx: %w", err)
	}
	return nil
}

func startCleanupLoop(ctx context.Context, wg *sync.WaitGroup, logger *log.Logger, qm *QueueManager, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleaned, err := qm.CleanupDoneOlderThan(ctx, time.Hour)
				if err != nil {
					logger.Printf("cleanup loop error: %v", err)
					continue
				}
				if cleaned > 0 {
					logger.Printf("cleanup removed %d completed jobs", cleaned)
				}
			}
		}
	}()
}
