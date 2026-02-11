package main

import (
	"context"
	stderrors "errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/benbjohnson/litestream"
	"github.com/tionis/forge/internal/ingestclient"
)

func hydrateVectorIngestDB(ctx context.Context, cfg ingestclient.Config, logger *log.Logger) {
	targetPath := strings.TrimSpace(cfg.HydratedDBPath)
	if targetPath == "" {
		return
	}

	session, err := loadRemoteBackendSession(ctx)
	if err != nil {
		logger.Printf("vector ingest hydration skipped: remote backend unavailable: %v", err)
		return
	}

	replicaURL, err := buildVectorEmbeddingsReplicaURL(session.Bootstrap, session.Config)
	if err != nil {
		logger.Printf("vector ingest hydration skipped: %v", err)
		return
	}
	maskedURL := maskURLCredentialsForLog(replicaURL)

	client, err := litestream.NewReplicaClientFromURL(replicaURL)
	if err != nil {
		logger.Printf("vector ingest hydration skipped: create replica client failed (%v)", err)
		return
	}
	if err := ensureParentDirForFile(targetPath); err != nil {
		logger.Printf("vector ingest hydration skipped: %v", err)
		return
	}

	tempPath := targetPath + fmt.Sprintf(".hydrate-%d.tmp", time.Now().UTC().UnixNano())
	_ = os.Remove(tempPath)
	defer func() { _ = os.Remove(tempPath) }()

	logger.Printf("vector ingest hydration: restoring hydrated DB from %s", maskedURL)
	replica := litestream.NewReplicaWithClient(nil, client)
	restore := litestream.NewRestoreOptions()
	restore.OutputPath = tempPath
	if err := replica.Restore(ctx, restore); err != nil {
		if stderrors.Is(err, litestream.ErrTxNotAvailable) || stderrors.Is(err, litestream.ErrNoSnapshots) {
			logHydrationFallback(logger, targetPath, "no remote snapshot available")
			return
		}
		logHydrationFallback(logger, targetPath, fmt.Sprintf("restore failed: %v", err))
		return
	}

	if err := os.Rename(tempPath, targetPath); err != nil {
		logHydrationFallback(logger, targetPath, fmt.Sprintf("replace local hydrated DB failed: %v", err))
		return
	}
	logger.Printf("vector ingest hydration: refreshed local hydrated DB %s", targetPath)
}

func buildVectorEmbeddingsReplicaURL(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig) (string, error) {
	base, err := buildVectorReplicaURL(bootstrap, cfg)
	if err != nil {
		return "", err
	}
	return appendURLPath(base, "embeddings")
}

func appendURLPath(baseURL string, segment string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(segment), "/")
	if trimmed == "" {
		return "", fmt.Errorf("url path segment is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	basePath := strings.TrimSuffix(parsed.Path, "/")
	if basePath == "" || basePath == "/" {
		parsed.Path = "/" + trimmed
	} else {
		parsed.Path = basePath + "/" + trimmed
	}
	return parsed.String(), nil
}

func maskURLCredentialsForLog(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.User != nil {
		parsed.User = url.User("***")
	}
	return parsed.String()
}

func ensureParentDirForFile(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create hydrated db parent directory %s: %w", dir, err)
	}
	return nil
}

func logHydrationFallback(logger *log.Logger, targetPath string, reason string) {
	if _, err := os.Stat(targetPath); err == nil {
		logger.Printf("vector ingest hydration warning: %s; using existing local hydrated DB %s", reason, targetPath)
		return
	} else if !os.IsNotExist(err) {
		logger.Printf("vector ingest hydration warning: %s; local hydrated DB unavailable (%v), continuing without precheck cache", reason, err)
		return
	}
	logger.Printf("vector ingest hydration warning: %s; continuing without hydrated precheck DB", reason)
}
