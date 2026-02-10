package vectorforge

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config carries runtime settings for the VectorForge service.
type Config struct {
	ListenAddr         string
	ImageWorkerURL     string
	TextWorkerURL      string
	WorkerConcurrency  int
	DBEmbedPath        string
	DBQueuePath        string
	TempDir            string
	BlobDBPath         string
	BlobCacheDir       string
	LookupChunkSize    int
	QueueAckTimeout    time.Duration
	QueueBufferSize    int
	QueueBatchSize     int
	QueueBatchInterval time.Duration
	CommitBatchSize    int
	CommitBatchWait    time.Duration
	DispatchInterval   time.Duration
	MaxPendingJobs     int
	MaxJobAttempts     int
	CleanupInterval    time.Duration

	ReplicaURL            string
	ReplicaRestoreOnStart bool
}

// LoadConfig reads environment variables and applies defaults.
func LoadConfig() (Config, error) {
	defaultWorkerURL := strings.TrimRight(getEnv("WORKER_URL", "http://localhost:3003"), "/")
	imageWorkerURL := strings.TrimRight(getEnv("IMAGE_WORKER_URL", defaultWorkerURL), "/")
	textWorkerURL := strings.TrimRight(getEnv("TEXT_WORKER_URL", imageWorkerURL), "/")

	cfg := Config{
		ListenAddr:            getEnv("LISTEN_ADDR", ":8080"),
		ImageWorkerURL:        imageWorkerURL,
		TextWorkerURL:         textWorkerURL,
		WorkerConcurrency:     20,
		DBEmbedPath:           defaultEmbedDBPath(),
		DBQueuePath:           defaultQueueDBPath(),
		TempDir:               defaultTempDir(),
		BlobDBPath:            defaultVectorBlobDBPath(),
		BlobCacheDir:          defaultVectorBlobCacheDir(),
		LookupChunkSize:       500,
		QueueAckTimeout:       5 * time.Second,
		QueueBufferSize:       1000,
		QueueBatchSize:        50,
		QueueBatchInterval:    250 * time.Millisecond,
		CommitBatchSize:       50,
		CommitBatchWait:       250 * time.Millisecond,
		DispatchInterval:      100 * time.Millisecond,
		MaxPendingJobs:        5000,
		MaxJobAttempts:        3,
		CleanupInterval:       time.Hour,
		ReplicaRestoreOnStart: true,
	}

	var err error
	if cfg.WorkerConcurrency, err = intFromEnv("WORKER_CONCURRENCY", cfg.WorkerConcurrency); err != nil {
		return Config{}, err
	}
	if cfg.LookupChunkSize, err = intFromEnv("LOOKUP_CHUNK_SIZE", cfg.LookupChunkSize); err != nil {
		return Config{}, err
	}
	ackTimeoutMS, err := intFromEnv("QUEUE_ACK_TIMEOUT_MS", int(cfg.QueueAckTimeout/time.Millisecond))
	if err != nil {
		return Config{}, err
	}
	cfg.QueueAckTimeout = time.Duration(ackTimeoutMS) * time.Millisecond
	if cfg.MaxPendingJobs, err = intFromEnv("MAX_PENDING_JOBS", cfg.MaxPendingJobs); err != nil {
		return Config{}, err
	}
	if cfg.MaxJobAttempts, err = intFromEnv("MAX_JOB_ATTEMPTS", cfg.MaxJobAttempts); err != nil {
		return Config{}, err
	}
	if cfg.ReplicaRestoreOnStart, err = boolFromEnv("FORGE_VECTOR_REPLICA_RESTORE_ON_START", cfg.ReplicaRestoreOnStart); err != nil {
		return Config{}, err
	}

	if cfg.WorkerConcurrency <= 0 {
		return Config{}, fmt.Errorf("WORKER_CONCURRENCY must be > 0")
	}
	if cfg.ImageWorkerURL == "" {
		return Config{}, fmt.Errorf("IMAGE_WORKER_URL must not be empty")
	}
	if cfg.TextWorkerURL == "" {
		return Config{}, fmt.Errorf("TEXT_WORKER_URL must not be empty")
	}
	if cfg.LookupChunkSize <= 0 {
		return Config{}, fmt.Errorf("LOOKUP_CHUNK_SIZE must be > 0")
	}
	if cfg.QueueAckTimeout <= 0 {
		return Config{}, fmt.Errorf("QUEUE_ACK_TIMEOUT_MS must be > 0")
	}
	if cfg.MaxPendingJobs <= 0 {
		return Config{}, fmt.Errorf("MAX_PENDING_JOBS must be > 0")
	}
	if cfg.MaxJobAttempts <= 0 {
		return Config{}, fmt.Errorf("MAX_JOB_ATTEMPTS must be > 0")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" {
			return trimmed
		}
	}
	return fallback
}

func intFromEnv(key string, fallback int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, nil
}

func boolFromEnv(key string, fallback bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return parsed, nil
}

func defaultEmbedDBPath() string {
	if custom := strings.TrimSpace(os.Getenv("FORGE_VECTOR_EMBED_DB")); custom != "" {
		return custom
	}
	return filepath.Join(defaultForgeDataDir(), "vector", "embeddings.db")
}

func defaultQueueDBPath() string {
	if custom := strings.TrimSpace(os.Getenv("FORGE_VECTOR_QUEUE_DB")); custom != "" {
		return custom
	}
	return filepath.Join(defaultForgeDataDir(), "vector", "queue.db")
}

func defaultTempDir() string {
	if custom := strings.TrimSpace(os.Getenv("FORGE_VECTOR_TEMP_DIR")); custom != "" {
		return custom
	}
	return filepath.Join(defaultForgeCacheDir(), "vector", "tmp")
}

func defaultForgeDataDir() string {
	dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".", "data")
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "forge")
}

func defaultForgeCacheDir() string {
	cacheHome := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME"))
	if cacheHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".", "cache")
		}
		cacheHome = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheHome, "forge")
}
