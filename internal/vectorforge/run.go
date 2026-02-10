package vectorforge

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Run boots the VectorForge service and blocks until shutdown.
func Run(ctx context.Context, cfg Config, logger *log.Logger) error {
	if err := os.MkdirAll(cfg.TempDir, 0o755); err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	replication, err := setupReplication(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("setup replication: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := replication.Close(shutdownCtx); err != nil {
			logger.Printf("litestream close error: %v", err)
		}
	}()

	queueDB, err := openSQLite(cfg.DBQueuePath, 1)
	if err != nil {
		return err
	}
	defer queueDB.Close()

	embeddingsDB, err := openSQLite(cfg.DBEmbedPath, 4)
	if err != nil {
		return err
	}
	defer embeddingsDB.Close()

	payloads, err := openLocalBlobPayloadStore(cfg.BlobDBPath, cfg.BlobCacheDir)
	if err != nil {
		return err
	}
	defer payloads.Close()

	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := initializeSchemas(initCtx, queueDB, embeddingsDB); err != nil {
		return err
	}

	queueManager := NewQueueManager(queueDB, logger, cfg.QueueBufferSize, cfg.QueueBatchSize, cfg.QueueBatchInterval)
	recovered, err := queueManager.ResetProcessing(initCtx)
	if err != nil {
		return err
	}
	if recovered > 0 {
		logger.Printf("startup recovery reset %d processing jobs to pending", recovered)
	}

	claimed := make(chan QueueJob, cfg.WorkerConcurrency*4)
	commits := make(chan WorkerResult, cfg.WorkerConcurrency*4)

	var wg sync.WaitGroup
	queueManager.Start(ctx, &wg)
	startDispatcher(ctx, &wg, logger, queueManager, claimed, cfg.WorkerConcurrency, cfg.DispatchInterval)
	startWorkerPool(ctx, &wg, logger, cfg.WorkerConcurrency, NewWorkerClient(cfg.ImageWorkerURL, cfg.TextWorkerURL), payloads, claimed, commits)
	startIngester(ctx, &wg, logger, embeddingsDB, queueManager, commits, cfg.CommitBatchSize, cfg.CommitBatchWait, cfg.MaxJobAttempts)
	startCleanupLoop(ctx, &wg, logger, queueManager, cfg.CleanupInterval)

	api := NewHTTPServer(cfg, logger, queueManager, embeddingsDB, payloads)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("forge vector listening on %s", cfg.ListenAddr)
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("http shutdown error: %v", err)
		}
		wg.Wait()
		return nil
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		wg.Wait()
		return nil
	}
}
