package forgeconfig

import (
	"path/filepath"
	"testing"
)

func TestDataDirUsesExplicitOverride(t *testing.T) {
	t.Setenv(EnvDataDir, "/tmp/forge-data")
	if got := DataDir(); got != "/tmp/forge-data" {
		t.Fatalf("DataDir override mismatch: got %q", got)
	}
}

func TestCacheDirUsesExplicitOverride(t *testing.T) {
	t.Setenv(EnvCacheDir, "/tmp/forge-cache")
	if got := CacheDir(); got != "/tmp/forge-cache" {
		t.Fatalf("CacheDir override mismatch: got %q", got)
	}
}

func TestDerivedDefaultsFromXDG(t *testing.T) {
	t.Setenv(EnvDataDir, "")
	t.Setenv(EnvCacheDir, "")
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg-data")
	t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-cache")

	if got := SnapshotDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "snapshot.db") {
		t.Fatalf("SnapshotDBPath mismatch: got %q", got)
	}
	if got := BlobDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "blob.db") {
		t.Fatalf("BlobDBPath mismatch: got %q", got)
	}
	if got := BlobCacheDir(); got != filepath.Join("/tmp/xdg-cache", "forge", "blobs") {
		t.Fatalf("BlobCacheDir mismatch: got %q", got)
	}
	if got := RemoteDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "remote.db") {
		t.Fatalf("RemoteDBPath mismatch: got %q", got)
	}
	if got := RefsDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "refs.db") {
		t.Fatalf("RefsDBPath mismatch: got %q", got)
	}
	if got := VectorEmbedDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "vector", "embeddings.db") {
		t.Fatalf("VectorEmbedDBPath mismatch: got %q", got)
	}
	if got := VectorQueueDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "vector", "queue.db") {
		t.Fatalf("VectorQueueDBPath mismatch: got %q", got)
	}
	if got := VectorTempDir(); got != filepath.Join("/tmp/xdg-cache", "forge", "vector", "tmp") {
		t.Fatalf("VectorTempDir mismatch: got %q", got)
	}
	if got := VectorHydratedDBPath(); got != filepath.Join("/tmp/xdg-data", "forge", "embeddings.db") {
		t.Fatalf("VectorHydratedDBPath mismatch: got %q", got)
	}
}
