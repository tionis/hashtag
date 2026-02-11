package vectorforge

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
)

const (
	envVectorListenAddr            = "FORGE_VECTOR_LISTEN_ADDR"
	envVectorWorkerURL             = "FORGE_VECTOR_WORKER_URL"
	envVectorImageWorkerURL        = "FORGE_VECTOR_IMAGE_WORKER_URL"
	envVectorTextWorkerURL         = "FORGE_VECTOR_TEXT_WORKER_URL"
	envVectorWorkerConcurrency     = "FORGE_VECTOR_WORKER_CONCURRENCY"
	envVectorLookupChunkSize       = "FORGE_VECTOR_LOOKUP_CHUNK_SIZE"
	envVectorQueueAckTimeoutMS     = "FORGE_VECTOR_QUEUE_ACK_TIMEOUT_MS"
	envVectorMaxPendingJobs        = "FORGE_VECTOR_MAX_PENDING_JOBS"
	envVectorMaxJobAttempts        = "FORGE_VECTOR_MAX_JOB_ATTEMPTS"
	envVectorReplicaRestoreOnStart = "FORGE_VECTOR_REPLICA_RESTORE_ON_START"
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
	defaultWorkerURL := strings.TrimRight(getEnv(envVectorWorkerURL, "http://localhost:3003"), "/")
	imageWorkerURL := strings.TrimRight(getEnv(envVectorImageWorkerURL, defaultWorkerURL), "/")
	textWorkerURL := strings.TrimRight(getEnv(envVectorTextWorkerURL, imageWorkerURL), "/")

	cfg := Config{
		ListenAddr:            getEnv(envVectorListenAddr, ":8080"),
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
	if cfg.WorkerConcurrency, err = intFromEnv(envVectorWorkerConcurrency, cfg.WorkerConcurrency); err != nil {
		return Config{}, err
	}
	if cfg.LookupChunkSize, err = intFromEnv(envVectorLookupChunkSize, cfg.LookupChunkSize); err != nil {
		return Config{}, err
	}
	ackTimeoutMS, err := intFromEnv(envVectorQueueAckTimeoutMS, int(cfg.QueueAckTimeout/time.Millisecond))
	if err != nil {
		return Config{}, err
	}
	cfg.QueueAckTimeout = time.Duration(ackTimeoutMS) * time.Millisecond
	if cfg.MaxPendingJobs, err = intFromEnv(envVectorMaxPendingJobs, cfg.MaxPendingJobs); err != nil {
		return Config{}, err
	}
	if cfg.MaxJobAttempts, err = intFromEnv(envVectorMaxJobAttempts, cfg.MaxJobAttempts); err != nil {
		return Config{}, err
	}
	if cfg.ReplicaRestoreOnStart, err = boolFromEnv(envVectorReplicaRestoreOnStart, cfg.ReplicaRestoreOnStart); err != nil {
		return Config{}, err
	}

	if cfg.WorkerConcurrency <= 0 {
		return Config{}, fmt.Errorf("%s must be > 0", envVectorWorkerConcurrency)
	}
	if cfg.ImageWorkerURL == "" {
		return Config{}, fmt.Errorf("%s must not be empty", envVectorImageWorkerURL)
	}
	if cfg.TextWorkerURL == "" {
		return Config{}, fmt.Errorf("%s must not be empty", envVectorTextWorkerURL)
	}
	if cfg.LookupChunkSize <= 0 {
		return Config{}, fmt.Errorf("%s must be > 0", envVectorLookupChunkSize)
	}
	if cfg.QueueAckTimeout <= 0 {
		return Config{}, fmt.Errorf("%s must be > 0", envVectorQueueAckTimeoutMS)
	}
	if cfg.MaxPendingJobs <= 0 {
		return Config{}, fmt.Errorf("%s must be > 0", envVectorMaxPendingJobs)
	}
	if cfg.MaxJobAttempts <= 0 {
		return Config{}, fmt.Errorf("%s must be > 0", envVectorMaxJobAttempts)
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
	return forgeconfig.VectorEmbedDBPath()
}

func defaultQueueDBPath() string {
	return forgeconfig.VectorQueueDBPath()
}

func defaultTempDir() string {
	return forgeconfig.VectorTempDir()
}
