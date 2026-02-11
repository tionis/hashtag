package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
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
		fmt.Fprintln(fs.Output(), "  FORGE_VECTOR_LISTEN_ADDR, FORGE_VECTOR_IMAGE_WORKER_URL, FORGE_VECTOR_TEXT_WORKER_URL,")
		fmt.Fprintln(fs.Output(), "  FORGE_VECTOR_WORKER_URL, FORGE_VECTOR_WORKER_CONCURRENCY, FORGE_VECTOR_LOOKUP_CHUNK_SIZE,")
		fmt.Fprintln(fs.Output(), "  FORGE_VECTOR_QUEUE_ACK_TIMEOUT_MS, FORGE_VECTOR_MAX_PENDING_JOBS, FORGE_VECTOR_MAX_JOB_ATTEMPTS,")
		fmt.Fprintln(fs.Output(), "  FORGE_VECTOR_REPLICA_RESTORE_ON_START")
		fmt.Fprintln(fs.Output(), "\nLocal storage environment overrides:")
		fmt.Fprintf(fs.Output(), "  %s, %s, %s\n", forgeconfig.EnvVectorEmbedDBPath, forgeconfig.EnvVectorQueueDBPath, forgeconfig.EnvVectorTempDir)
		fmt.Fprintf(fs.Output(), "  %s, %s\n", forgeconfig.EnvBlobDBPath, forgeconfig.EnvBlobCacheDir)
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

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	cfg, err := vectorforge.LoadConfig()
	if err != nil {
		return fmt.Errorf("load vector config: %w", err)
	}
	var lease *vectorWriterLease
	leaseLost := make(chan error, 1)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	runCtx := ctx
	cancelRun := func() {}

	if *enableReplication {
		setup, err := configureVectorReplicationFromRemoteConfig(ctx, &cfg)
		if err != nil {
			return err
		}
		lease, err = acquireVectorWriterLease(ctx, logger, setup.Bootstrap, setup.Config)
		if err != nil {
			return err
		}
		replicationCtx, replicationCancel := context.WithCancel(ctx)
		runCtx = replicationCtx
		cancelRun = replicationCancel
		go func() {
			select {
			case err := <-lease.Lost():
				if err != nil {
					logger.Printf("vector replication writer lease lost: %v", err)
					select {
					case leaseLost <- err:
					default:
					}
					replicationCancel()
				}
			case <-replicationCtx.Done():
			}
		}()
	}
	defer cancelRun()

	runErr := vectorforge.Run(runCtx, cfg, logger)
	if lease != nil {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		closeErr := lease.Close(closeCtx)
		closeCancel()
		if closeErr != nil && runErr == nil {
			runErr = fmt.Errorf("close vector writer lease: %w", closeErr)
		}
		select {
		case leaseErr := <-leaseLost:
			if leaseErr != nil {
				return fmt.Errorf("vector replication stopped after lease loss: %w", leaseErr)
			}
		default:
		}
	}
	return runErr
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

type vectorLeaseStatusOutput struct {
	Bucket             string `json:"bucket"`
	ObjectKey          string `json:"object_key"`
	Resource           string `json:"resource"`
	ConfiguredMode     string `json:"configured_mode"`
	EffectiveMode      string `json:"effective_mode"`
	Found              bool   `json:"found"`
	OwnerID            string `json:"owner_id,omitempty"`
	LeaseID            string `json:"lease_id,omitempty"`
	ETag               string `json:"etag,omitempty"`
	IssuedAtUTC        string `json:"issued_at_utc,omitempty"`
	ExpiresAtUTC       string `json:"expires_at_utc,omitempty"`
	SecondsUntilExpiry int64  `json:"seconds_until_expiry,omitempty"`
	Expired            bool   `json:"expired"`
}

func runVectorLeaseStatusCommand(args []string) error {
	fs := flag.NewFlagSet("vector lease-status", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s vector lease-status [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show current S3 writer-lease state for vector replication.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}
	resource := fs.String("resource", "", "Override lease resource key")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	ctx := context.Background()
	session, err := loadRemoteBackendSession(ctx)
	if err != nil {
		return err
	}
	configuredMode := strings.ToLower(strings.TrimSpace(session.Config.Coordination.VectorWriterLease.Mode))
	if configuredMode == "" {
		configuredMode = vectorLeaseModeAuto
	}
	effectiveMode, err := resolveVectorLeaseMode(configuredMode, session.Config.S3.Capabilities)
	if err != nil {
		return err
	}
	targetResource := normalizeS3ObjectKey(strings.TrimSpace(*resource))
	if targetResource == "" {
		targetResource = session.Config.Coordination.VectorWriterLease.Resource
	}
	if targetResource == "" {
		targetResource = defaultVectorLeaseResource
	}
	objectKey := vectorWriterLeaseObjectKey(session.Config, targetResource)
	client, err := session.newS3Client(ctx)
	if err != nil {
		return err
	}
	tempLease := &vectorWriterLease{
		client:    client,
		bootstrap: session.Bootstrap,
		objectKey: objectKey,
	}
	record, etag, found, err := tempLease.getCurrentRecord(ctx)
	if err != nil {
		return err
	}

	output := vectorLeaseStatusOutput{
		Bucket:         session.Bootstrap.Bucket,
		ObjectKey:      objectKey,
		Resource:       targetResource,
		ConfiguredMode: configuredMode,
		EffectiveMode:  effectiveMode,
		Found:          found,
		Expired:        false,
	}
	if found {
		output.OwnerID = record.OwnerID
		output.LeaseID = record.LeaseID
		output.ETag = etag
		output.IssuedAtUTC = record.IssuedAtUTC
		output.ExpiresAtUTC = record.ExpiresAtUTC
		if expiresAt, parseErr := parseLeaseExpiry(record.ExpiresAtUTC); parseErr == nil {
			until := time.Until(expiresAt).Seconds()
			output.SecondsUntilExpiry = int64(until)
			output.Expired = expiresAt.Before(time.Now().UTC())
		}
	}
	return renderVectorLeaseStatusOutput(resolvedOutputMode, output)
}

func renderVectorLeaseStatusOutput(mode string, output vectorLeaseStatusOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("bucket=%s\n", output.Bucket)
		fmt.Printf("object_key=%s\n", output.ObjectKey)
		fmt.Printf("resource=%s\n", output.Resource)
		fmt.Printf("configured_mode=%s\n", output.ConfiguredMode)
		fmt.Printf("effective_mode=%s\n", output.EffectiveMode)
		fmt.Printf("found=%t\n", output.Found)
		if output.Found {
			fmt.Printf("owner_id=%s\n", output.OwnerID)
			fmt.Printf("lease_id=%s\n", output.LeaseID)
			fmt.Printf("etag=%s\n", output.ETag)
			fmt.Printf("issued_at_utc=%s\n", output.IssuedAtUTC)
			fmt.Printf("expires_at_utc=%s\n", output.ExpiresAtUTC)
			fmt.Printf("seconds_until_expiry=%d\n", output.SecondsUntilExpiry)
			fmt.Printf("expired=%t\n", output.Expired)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Vector Lease Status")
		printPrettyFields([]outputField{
			{Label: "Bucket", Value: output.Bucket},
			{Label: "Object Key", Value: output.ObjectKey},
			{Label: "Resource", Value: output.Resource},
			{Label: "Configured Mode", Value: output.ConfiguredMode},
			{Label: "Effective Mode", Value: output.EffectiveMode},
			{Label: "Found", Value: strconv.FormatBool(output.Found)},
		})
		if output.Found {
			printPrettySection("Lease")
			printPrettyFields([]outputField{
				{Label: "Owner ID", Value: output.OwnerID},
				{Label: "Lease ID", Value: output.LeaseID},
				{Label: "ETag", Value: output.ETag},
				{Label: "Issued At", Value: output.IssuedAtUTC},
				{Label: "Expires At", Value: output.ExpiresAtUTC},
				{Label: "Seconds Until Expiry", Value: strconv.FormatInt(output.SecondsUntilExpiry, 10)},
				{Label: "Expired", Value: strconv.FormatBool(output.Expired)},
			})
		}
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func buildVectorReplicaURL(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig) (string, error) {
	bucket := strings.TrimSpace(bootstrap.Bucket)
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
