package vectorforge

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/benbjohnson/litestream"
	"github.com/superfly/ltx"
)

type noopReplicaClient struct{}

func (n *noopReplicaClient) Type() string { return "noop" }

func (n *noopReplicaClient) Init(ctx context.Context) error { return nil }

func (n *noopReplicaClient) LTXFiles(ctx context.Context, level int, seek ltx.TXID, useMetadata bool) (ltx.FileIterator, error) {
	return ltx.NewFileInfoSliceIterator(nil), nil
}

func (n *noopReplicaClient) OpenLTXFile(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID, offset int64, size int64) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (n *noopReplicaClient) WriteLTXFile(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID, r io.Reader) (*ltx.FileInfo, error) {
	return &ltx.FileInfo{
		Level:     level,
		MinTXID:   minTXID,
		MaxTXID:   maxTXID,
		Size:      0,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (n *noopReplicaClient) DeleteLTXFiles(ctx context.Context, a []*ltx.FileInfo) error { return nil }

func (n *noopReplicaClient) DeleteAll(ctx context.Context) error { return nil }

func TestSetupReplicationRestartRecoveryDualDBRestore(t *testing.T) {
	temp := t.TempDir()
	cfg := Config{
		DBEmbedPath:           filepath.Join(temp, "vector", "embeddings.db"),
		DBQueuePath:           filepath.Join(temp, "vector", "queue.db"),
		ReplicaURL:            "s3://bucket-a/forge-data/vector",
		ReplicaRestoreOnStart: true,
	}
	logger := log.New(io.Discard, "", 0)
	ctx := context.Background()

	originalFactory := newReplicaClientFromURLFunc
	originalRestore := restoreDBIfMissingFunc
	t.Cleanup(func() {
		newReplicaClientFromURLFunc = originalFactory
		restoreDBIfMissingFunc = originalRestore
	})

	newReplicaClientFromURLFunc = func(raw string) (litestream.ReplicaClient, error) {
		return &noopReplicaClient{}, nil
	}

	restoredWhenMissing := make([]string, 0, 2)
	restoreDBIfMissingFunc = func(ctx context.Context, name string, dbPath string, client litestream.ReplicaClient, logger *log.Logger) error {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			restoredWhenMissing = append(restoredWhenMissing, name)
		} else if err != nil {
			return err
		}
		return nil
	}

	firstManager, err := setupReplication(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("first setupReplication: %v", err)
	}
	if len(restoredWhenMissing) != 2 {
		t.Fatalf("expected restore check for both DBs on first start, got %d (%v)", len(restoredWhenMissing), restoredWhenMissing)
	}
	if err := firstManager.Close(context.Background()); err != nil {
		t.Fatalf("first replication close: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBEmbedPath), 0o755); err != nil {
		t.Fatalf("create embed db parent dir for restart simulation: %v", err)
	}
	if err := os.WriteFile(cfg.DBEmbedPath, []byte{}, 0o600); err != nil {
		t.Fatalf("create embed db file for restart simulation: %v", err)
	}
	if err := os.WriteFile(cfg.DBQueuePath, []byte{}, 0o600); err != nil {
		t.Fatalf("create queue db file for restart simulation: %v", err)
	}

	restoredWhenMissing = restoredWhenMissing[:0]
	secondManager, err := setupReplication(ctx, cfg, logger)
	if err != nil {
		t.Fatalf("second setupReplication: %v", err)
	}
	defer secondManager.Close(context.Background())
	if len(restoredWhenMissing) != 0 {
		t.Fatalf("expected no restore-on-missing for restart with existing DBs, got %d (%v)", len(restoredWhenMissing), restoredWhenMissing)
	}
}
