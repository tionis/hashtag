package ingestclient

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Config controls ingestion client runtime behavior.
type Config struct {
	ServerURL      string
	RootPath       string
	Kind           string
	HashAlgo       string
	HydratedDBPath string
	Workers        int
	LookupBatch    int
	RequestTimeout time.Duration
	Verbose        bool
}

func LoadConfigFromFlags() (Config, error) {
	return LoadConfigFromArgs(os.Args[1:])
}

func LoadConfigFromArgs(args []string) (Config, error) {
	cfg := Config{}
	fs := flag.NewFlagSet("vector ingest", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)

	defaultHydratedDB := defaultHydratedDBPath()

	fs.StringVar(&cfg.ServerURL, "server", "http://localhost:8080", "Coordinator base URL")
	fs.StringVar(&cfg.RootPath, "root", ".", "Root directory to scan")
	fs.StringVar(&cfg.Kind, "kind", "image", "Embedding kind: image or text")
	fs.StringVar(&cfg.HashAlgo, "algo", "blake3", "Hash algorithm for XATTR cache key (must be blake3)")
	fs.StringVar(&cfg.HydratedDBPath, "hydrated-db", defaultHydratedDB, "Local hydrated embeddings DB path for pre-checks")
	fs.IntVar(&cfg.Workers, "workers", runtime.NumCPU(), "Worker count for hashing and uploads")
	fs.IntVar(&cfg.LookupBatch, "lookup-batch", 500, "Hashes per lookup request")
	fs.DurationVar(&cfg.RequestTimeout, "http-timeout", 120*time.Second, "HTTP request timeout")
	fs.BoolVar(&cfg.Verbose, "v", false, "Verbose logging")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	cfg.Kind = strings.ToLower(strings.TrimSpace(cfg.Kind))
	cfg.HashAlgo = strings.ToLower(strings.TrimSpace(cfg.HashAlgo))
	cfg.HydratedDBPath = strings.TrimSpace(cfg.HydratedDBPath)

	if cfg.ServerURL == "" {
		return Config{}, errors.New("-server is required")
	}
	if !isSupportedKind(cfg.Kind) {
		return Config{}, fmt.Errorf("unsupported -kind %q (supported: image, text)", cfg.Kind)
	}
	if cfg.Workers <= 0 {
		return Config{}, errors.New("-workers must be > 0")
	}
	if cfg.LookupBatch <= 0 {
		return Config{}, errors.New("-lookup-batch must be > 0")
	}
	if cfg.RequestTimeout <= 0 {
		return Config{}, errors.New("-http-timeout must be > 0")
	}
	if !isSupportedAlgo(cfg.HashAlgo) {
		return Config{}, fmt.Errorf("unsupported -algo %q (supported: blake3)", cfg.HashAlgo)
	}

	abs, err := filepath.Abs(cfg.RootPath)
	if err != nil {
		return Config{}, fmt.Errorf("resolve root path: %w", err)
	}
	cfg.RootPath = abs

	if cfg.HydratedDBPath != "" {
		absDB, err := filepath.Abs(cfg.HydratedDBPath)
		if err != nil {
			return Config{}, fmt.Errorf("resolve hydrated db path: %w", err)
		}
		cfg.HydratedDBPath = absDB
	}

	return cfg, nil
}

func isSupportedKind(kind string) bool {
	return kind == "image" || kind == "text"
}

func defaultHydratedDBPath() string {
	if custom := strings.TrimSpace(os.Getenv("FORGE_VECTOR_HYDRATED_DB")); custom != "" {
		return custom
	}

	dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "./embeddings.db"
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "forge", "embeddings.db")
}
