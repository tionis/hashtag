package vectorforge

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/benbjohnson/litestream"
	_ "github.com/benbjohnson/litestream/s3"
)

// ReplicationManager controls Litestream lifecycle for embeddings.db replication.
type ReplicationManager struct {
	db         *litestream.DB
	replicaURL string
	enabled    bool
}

func setupReplication(ctx context.Context, cfg Config, logger *log.Logger) (*ReplicationManager, error) {
	replicaURL, err := buildReplicaURL(cfg)
	if err != nil {
		return nil, err
	}
	if replicaURL == "" {
		return &ReplicationManager{enabled: false}, nil
	}

	if err := ensureParentDir(cfg.DBEmbedPath); err != nil {
		return nil, err
	}

	client, err := litestream.NewReplicaClientFromURL(replicaURL)
	if err != nil {
		return nil, fmt.Errorf("create litestream replica client: %w", err)
	}

	if cfg.ReplicaRestoreOnStart {
		if err := restoreEmbeddingsIfMissing(ctx, cfg.DBEmbedPath, client, logger); err != nil {
			return nil, err
		}
	}

	db := litestream.NewDB(cfg.DBEmbedPath)
	replica := litestream.NewReplicaWithClient(db, client)
	db.Replica = replica

	if err := db.Open(); err != nil {
		return nil, fmt.Errorf("open litestream db: %w", err)
	}

	masked := maskURLCredentials(replicaURL)
	logger.Printf("litestream replication enabled: %s", masked)

	return &ReplicationManager{
		db:         db,
		replicaURL: masked,
		enabled:    true,
	}, nil
}

func restoreEmbeddingsIfMissing(ctx context.Context, dbPath string, client litestream.ReplicaClient, logger *log.Logger) error {
	if _, err := os.Stat(dbPath); err == nil {
		logger.Printf("litestream restore skipped: local embeddings DB already exists")
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat embeddings db before restore: %w", err)
	}

	replica := litestream.NewReplicaWithClient(nil, client)
	opt := litestream.NewRestoreOptions()
	opt.OutputPath = dbPath

	logger.Printf("litestream restore: local embeddings DB missing, attempting restore")
	if err := replica.Restore(ctx, opt); err != nil {
		if errors.Is(err, litestream.ErrTxNotAvailable) || errors.Is(err, litestream.ErrNoSnapshots) {
			logger.Printf("litestream restore: no remote backup found, starting fresh")
			return nil
		}
		return fmt.Errorf("restore embeddings db: %w", err)
	}

	logger.Printf("litestream restore: completed successfully")
	return nil
}

func (m *ReplicationManager) Close(ctx context.Context) error {
	if m == nil || !m.enabled || m.db == nil {
		return nil
	}
	return m.db.Close(ctx)
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
