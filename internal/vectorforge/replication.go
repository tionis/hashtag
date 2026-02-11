package vectorforge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/benbjohnson/litestream"
	_ "github.com/benbjohnson/litestream/s3"
)

type replicaTarget struct {
	name       string
	dbPath     string
	replicaURL string
}

type replicaHandle struct {
	name string
	db   *litestream.DB
}

// ReplicationManager controls Litestream lifecycle for vector databases.
type ReplicationManager struct {
	handles []replicaHandle
	enabled bool
}

func setupReplication(ctx context.Context, cfg Config, logger *log.Logger) (*ReplicationManager, error) {
	replicaBaseURL, err := buildReplicaURL(cfg)
	if err != nil {
		return nil, err
	}
	if replicaBaseURL == "" {
		return &ReplicationManager{enabled: false}, nil
	}

	targets, err := buildReplicaTargets(cfg, replicaBaseURL)
	if err != nil {
		return nil, err
	}

	manager := &ReplicationManager{
		enabled: true,
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = manager.Close(cleanupCtx)
	}

	for _, target := range targets {
		if err := ensureParentDir(target.dbPath); err != nil {
			cleanup()
			return nil, err
		}
		client, err := litestream.NewReplicaClientFromURL(target.replicaURL)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("create litestream replica client for %s: %w", target.name, err)
		}
		if cfg.ReplicaRestoreOnStart {
			if err := restoreDBIfMissing(ctx, target.name, target.dbPath, client, logger); err != nil {
				cleanup()
				return nil, err
			}
		}
		db := litestream.NewDB(target.dbPath)
		replica := litestream.NewReplicaWithClient(db, client)
		db.Replica = replica
		if err := db.Open(); err != nil {
			cleanup()
			return nil, fmt.Errorf("open litestream db for %s: %w", target.name, err)
		}
		masked := maskURLCredentials(target.replicaURL)
		logger.Printf("litestream replication enabled (%s): %s", target.name, masked)
		manager.handles = append(manager.handles, replicaHandle{
			name: target.name,
			db:   db,
		})
	}
	return manager, nil
}

func buildReplicaURL(cfg Config) (string, error) {
	if raw := strings.TrimSpace(cfg.ReplicaURL); raw != "" {
		if _, err := url.Parse(raw); err != nil {
			return "", fmt.Errorf("parse replica URL: %w", err)
		}
		return raw, nil
	}
	return "", nil
}

func buildReplicaTargets(cfg Config, replicaBaseURL string) ([]replicaTarget, error) {
	embedURL, err := appendReplicaURLPath(replicaBaseURL, "embeddings")
	if err != nil {
		return nil, fmt.Errorf("build embeddings replica URL: %w", err)
	}
	queueURL, err := appendReplicaURLPath(replicaBaseURL, "queue")
	if err != nil {
		return nil, fmt.Errorf("build queue replica URL: %w", err)
	}
	return []replicaTarget{
		{name: "embeddings", dbPath: cfg.DBEmbedPath, replicaURL: embedURL},
		{name: "queue", dbPath: cfg.DBQueuePath, replicaURL: queueURL},
	}, nil
}

func appendReplicaURLPath(baseURL string, child string) (string, error) {
	trimmedChild := strings.Trim(strings.TrimSpace(child), "/")
	if trimmedChild == "" {
		return "", fmt.Errorf("replica path child is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base replica URL: %w", err)
	}
	basePath := strings.TrimSuffix(u.Path, "/")
	if basePath == "" || basePath == "/" {
		u.Path = "/" + trimmedChild
	} else {
		u.Path = basePath + "/" + trimmedChild
	}
	return u.String(), nil
}

func restoreDBIfMissing(ctx context.Context, name string, dbPath string, client litestream.ReplicaClient, logger *log.Logger) error {
	displayName := strings.TrimSpace(name)
	if displayName == "" {
		displayName = "database"
	}
	if _, err := os.Stat(dbPath); err == nil {
		logger.Printf("litestream restore skipped (%s): local DB already exists", displayName)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s db before restore: %w", displayName, err)
	}

	replica := litestream.NewReplicaWithClient(nil, client)
	opt := litestream.NewRestoreOptions()
	opt.OutputPath = dbPath

	logger.Printf("litestream restore (%s): local DB missing, attempting restore", displayName)
	if err := replica.Restore(ctx, opt); err != nil {
		if errors.Is(err, litestream.ErrTxNotAvailable) || errors.Is(err, litestream.ErrNoSnapshots) {
			logger.Printf("litestream restore (%s): no remote backup found, starting fresh", displayName)
			return nil
		}
		return fmt.Errorf("restore %s db: %w", displayName, err)
	}

	logger.Printf("litestream restore (%s): completed successfully", displayName)
	return nil
}

func (m *ReplicationManager) Close(ctx context.Context) error {
	if m == nil || !m.enabled {
		return nil
	}
	var closeErr error
	for _, handle := range m.handles {
		if handle.db == nil {
			continue
		}
		if err := handle.db.Close(ctx); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("%s replica close: %w", handle.name, err))
		}
	}
	return closeErr
}

func maskURLCredentials(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	return u.String()
}
