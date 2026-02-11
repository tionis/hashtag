package vectorforge

import (
	"strings"
	"testing"

	"github.com/tionis/forge/internal/forgeconfig"
)

func resetConfigParseEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		forgeconfig.EnvDataDir,
		forgeconfig.EnvCacheDir,
		"XDG_DATA_HOME",
		"XDG_CACHE_HOME",
		forgeconfig.EnvVectorEmbedDBPath,
		forgeconfig.EnvVectorQueueDBPath,
		forgeconfig.EnvVectorTempDir,
		envVectorReplicaRestoreOnStart,
		envVectorWorkerURL,
		envVectorImageWorkerURL,
		envVectorTextWorkerURL,
		envVectorWorkerConcurrency,
		envVectorLookupChunkSize,
		envVectorQueueAckTimeoutMS,
		envVectorMaxPendingJobs,
		envVectorMaxJobAttempts,
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func TestLoadConfig_DefaultMaxJobAttempts(t *testing.T) {
	resetConfigParseEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.MaxJobAttempts != 3 {
		t.Fatalf("MaxJobAttempts mismatch: got %d want 3", cfg.MaxJobAttempts)
	}
}

func TestLoadConfig_MaxJobAttemptsFromEnv(t *testing.T) {
	resetConfigParseEnv(t)
	t.Setenv(envVectorMaxJobAttempts, "7")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.MaxJobAttempts != 7 {
		t.Fatalf("MaxJobAttempts mismatch: got %d want 7", cfg.MaxJobAttempts)
	}
}

func TestLoadConfig_RejectsNonPositiveMaxJobAttempts(t *testing.T) {
	resetConfigParseEnv(t)
	t.Setenv(envVectorMaxJobAttempts, "0")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), envVectorMaxJobAttempts+" must be > 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfig_DefaultLocalPathsUseForgeXDGDirs(t *testing.T) {
	resetConfigParseEnv(t)
	t.Setenv("XDG_DATA_HOME", "/tmp/forge-test-data")
	t.Setenv("XDG_CACHE_HOME", "/tmp/forge-test-cache")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	if cfg.DBEmbedPath != "/tmp/forge-test-data/forge/vector/embeddings.db" {
		t.Fatalf("DBEmbedPath mismatch: got %q", cfg.DBEmbedPath)
	}
	if cfg.DBQueuePath != "/tmp/forge-test-data/forge/vector/queue.db" {
		t.Fatalf("DBQueuePath mismatch: got %q", cfg.DBQueuePath)
	}
	if cfg.TempDir != "/tmp/forge-test-cache/forge/vector/tmp" {
		t.Fatalf("TempDir mismatch: got %q", cfg.TempDir)
	}
	if cfg.BlobDBPath != "/tmp/forge-test-data/forge/blob.db" {
		t.Fatalf("BlobDBPath mismatch: got %q", cfg.BlobDBPath)
	}
	if cfg.BlobCacheDir != "/tmp/forge-test-cache/forge/blobs" {
		t.Fatalf("BlobCacheDir mismatch: got %q", cfg.BlobCacheDir)
	}
}
