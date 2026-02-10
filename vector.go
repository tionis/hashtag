package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tionis/forge/internal/ingestclient"
	"github.com/tionis/forge/internal/vectorforge"
)

func runVectorServeCommand(args []string) error {
	fs := flag.NewFlagSet("vector serve", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	enableReplication := fs.Bool("replication", false, "Enable remote replication setup via forge remote config")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s vector serve\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Run the Forge vector coordinator service.")
		fmt.Fprintln(fs.Output(), "\nRuntime environment variables:")
		fmt.Fprintln(fs.Output(), "  LISTEN_ADDR, IMAGE_WORKER_URL, TEXT_WORKER_URL, WORKER_CONCURRENCY,")
		fmt.Fprintln(fs.Output(), "  LOOKUP_CHUNK_SIZE, QUEUE_ACK_TIMEOUT_MS, MAX_PENDING_JOBS, MAX_JOB_ATTEMPTS")
		fmt.Fprintln(fs.Output(), "\nLocal storage environment overrides:")
		fmt.Fprintln(fs.Output(), "  FORGE_VECTOR_EMBED_DB, FORGE_VECTOR_QUEUE_DB, FORGE_VECTOR_TEMP_DIR")
		fmt.Fprintln(fs.Output(), "  FORGE_BLOB_DB, FORGE_BLOB_CACHE")
		fmt.Fprintln(fs.Output(), "\nReplication is disabled by default. Enable with -replication.")
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	cfg, err := vectorforge.LoadConfig()
	if err != nil {
		return fmt.Errorf("load vector config: %w", err)
	}
	if *enableReplication {
		if err := configureVectorReplicaFromRemoteConfig(context.Background(), &cfg); err != nil {
			return err
		}
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return vectorforge.Run(ctx, cfg, logger)
}

func runVectorIngestCommand(args []string) error {
	cfg, err := ingestclient.LoadConfigFromArgs(args)
	if err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return ingestclient.Run(ctx, cfg, logger)
}

func configureVectorReplicaFromRemoteConfig(ctx context.Context, cfg *vectorforge.Config) error {
	if cfg == nil {
		return nil
	}
	if strings.TrimSpace(os.Getenv(forgeS3BucketEnv)) == "" {
		return nil
	}

	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		return fmt.Errorf("load remote bootstrap for vector replication: %w", err)
	}
	remoteCfg, _, err := loadRemoteGlobalConfigWithCache(ctx, bootstrap, nil)
	if err != nil {
		return fmt.Errorf("load remote config for vector replication: %w", err)
	}

	replicaURL, err := buildVectorReplicaURL(bootstrap, remoteCfg)
	if err != nil {
		return err
	}
	cfg.ReplicaURL = replicaURL
	return nil
}

func buildVectorReplicaURL(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig) (string, error) {
	bucket := strings.TrimSpace(cfg.S3.Bucket)
	if bucket == "" {
		bucket = strings.TrimSpace(bootstrap.Bucket)
	}
	if bucket == "" {
		return "", fmt.Errorf("vector replication requires bucket configuration")
	}

	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	parts := make([]string, 0, 3)
	if base != "" {
		parts = append(parts, base)
	}
	parts = append(parts, "vector", "embeddings")

	u := &url.URL{
		Scheme: "s3",
		Host:   bucket,
		Path:   "/" + strings.Join(parts, "/"),
	}

	query := u.Query()
	if endpoint := ensureHTTPSEndpointScheme(strings.TrimSpace(bootstrap.EndpointURL)); endpoint != "" {
		query.Set("endpoint", endpoint)
	}
	if region := strings.TrimSpace(bootstrap.Region); region != "" {
		query.Set("region", region)
	}
	if bootstrap.ForcePathStyle {
		query.Set("forcePathStyle", "true")
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func ensureHTTPSEndpointScheme(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	return "https://" + endpoint
}
