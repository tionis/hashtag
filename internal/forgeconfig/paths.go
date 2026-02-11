package forgeconfig

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	EnvDataDir  = "FORGE_DATA_DIR"
	EnvCacheDir = "FORGE_CACHE_DIR"

	EnvSnapshotDBPath       = "FORGE_PATH_SNAPSHOT_DB"
	EnvBlobDBPath           = "FORGE_PATH_BLOB_DB"
	EnvBlobCacheDir         = "FORGE_PATH_BLOB_CACHE"
	EnvRemoteDBPath         = "FORGE_PATH_REMOTE_DB"
	EnvVectorEmbedDBPath    = "FORGE_PATH_VECTOR_EMBED_DB"
	EnvVectorQueueDBPath    = "FORGE_PATH_VECTOR_QUEUE_DB"
	EnvVectorTempDir        = "FORGE_PATH_VECTOR_TEMP_DIR"
	EnvVectorHydratedDBPath = "FORGE_PATH_VECTOR_HYDRATED_DB"
)

func DataDir() string {
	if custom := strings.TrimSpace(os.Getenv(EnvDataDir)); custom != "" {
		return custom
	}
	if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" {
		return filepath.Join(dataHome, "forge")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".local", "share", "forge")
	}
	return filepath.Join(".", "forge-data")
}

func CacheDir() string {
	if custom := strings.TrimSpace(os.Getenv(EnvCacheDir)); custom != "" {
		return custom
	}
	if cacheHome := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); cacheHome != "" {
		return filepath.Join(cacheHome, "forge")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".cache", "forge")
	}
	return filepath.Join(".", "forge-cache")
}

func SnapshotDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvSnapshotDBPath)); custom != "" {
		return custom
	}
	return filepath.Join(DataDir(), "snapshot.db")
}

func BlobDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvBlobDBPath)); custom != "" {
		return custom
	}
	return filepath.Join(DataDir(), "blob.db")
}

func BlobCacheDir() string {
	if custom := strings.TrimSpace(os.Getenv(EnvBlobCacheDir)); custom != "" {
		return custom
	}
	return filepath.Join(CacheDir(), "blobs")
}

func RemoteDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvRemoteDBPath)); custom != "" {
		return custom
	}
	return filepath.Join(DataDir(), "remote.db")
}

func VectorEmbedDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvVectorEmbedDBPath)); custom != "" {
		return custom
	}
	return filepath.Join(DataDir(), "vector", "embeddings.db")
}

func VectorQueueDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvVectorQueueDBPath)); custom != "" {
		return custom
	}
	return filepath.Join(DataDir(), "vector", "queue.db")
}

func VectorTempDir() string {
	if custom := strings.TrimSpace(os.Getenv(EnvVectorTempDir)); custom != "" {
		return custom
	}
	return filepath.Join(CacheDir(), "vector", "tmp")
}

func VectorHydratedDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(EnvVectorHydratedDBPath)); custom != "" {
		return custom
	}
	return filepath.Join(DataDir(), "embeddings.db")
}
