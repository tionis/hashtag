package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	remoteDocExpiresPreserve = -1
)

type remoteConfigWriteOptions struct {
	SigningKeyPath       string
	SigningKeyPassphrase string
	DocumentVersion      int64
	DocumentExpires      int
}

type remoteConfigNodeListOutput struct {
	Bucket            string            `json:"bucket"`
	ConfigKey         string            `json:"config_key"`
	ETag              string            `json:"etag,omitempty"`
	DocumentVersion   int64             `json:"document_version"`
	SignerFingerprint string            `json:"signer_fingerprint"`
	PayloadHash       string            `json:"payload_hash"`
	ExpiresAtUTC      string            `json:"expires_at_utc,omitempty"`
	Nodes             []remoteTrustNode `json:"nodes"`
}

func runRemoteConfigSetCommand(args []string) error {
	fs := flag.NewFlagSet("remote config set", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config set [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Update mutable fields in the signed Forge remote config document.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	objectPrefix := fs.String("object-prefix", "", "Set s3.object_prefix")
	blobPrefix := fs.String("blob-prefix", "", "Set s3.blob_prefix")
	configCacheTTL := fs.Int("config-cache-ttl", -1, "Set cache.remote_config_ttl_seconds")
	capIfNone := fs.String("cap-if-none-match", "", "Set s3.capabilities.conditional_if_none_match (true|false)")
	capIfMatch := fs.String("cap-if-match", "", "Set s3.capabilities.conditional_if_match (true|false)")
	capResponseChecksums := fs.String("cap-response-checksums", "", "Set s3.capabilities.response_checksums (true|false)")
	vectorLeaseMode := fs.String("vector-lease-mode", "", "Set coordination.vector_writer_lease.mode (auto|hard|soft|off)")
	vectorLeaseResource := fs.String("vector-lease-resource", "", "Set coordination.vector_writer_lease.resource")
	vectorLeaseDuration := fs.Int("vector-lease-duration", -1, "Set coordination.vector_writer_lease.duration_seconds")
	vectorLeaseRenewInterval := fs.Int("vector-lease-renew-interval", -1, "Set coordination.vector_writer_lease.renew_interval_seconds")
	signingKeyPath := fs.String("signing-key", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyEnv)), "Path to OpenSSH private key used to sign updated config")
	signingKeyPassphrase := fs.String("signing-key-passphrase", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyPassphraseEnv)), "Passphrase for encrypted OpenSSH private key used by -signing-key")
	documentVersion := fs.Int64("doc-version", 0, "Signed document version (default: auto)")
	documentExpiresSeconds := fs.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
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

	capIfNoneParsed, err := parseOptionalBoolFlag(*capIfNone, "cap-if-none-match")
	if err != nil {
		return err
	}
	capIfMatchParsed, err := parseOptionalBoolFlag(*capIfMatch, "cap-if-match")
	if err != nil {
		return err
	}
	capChecksumsParsed, err := parseOptionalBoolFlag(*capResponseChecksums, "cap-response-checksums")
	if err != nil {
		return err
	}

	ctx := context.Background()
	bootstrap, client, cfg, previousMeta, _, err := loadRemoteConfigForMutation(ctx)
	if err != nil {
		return err
	}

	changed := false
	if value := strings.TrimSpace(*objectPrefix); value != "" {
		cfg.S3.ObjectPrefix = normalizeS3Prefix(value)
		changed = true
	}
	if value := strings.TrimSpace(*blobPrefix); value != "" {
		cfg.S3.BlobPrefix = normalizeS3Prefix(value)
		changed = true
	}
	if *configCacheTTL >= 0 {
		cfg.Cache.RemoteConfigTTLSeconds = *configCacheTTL
		changed = true
	}
	if capIfNoneParsed != nil {
		cfg.S3.Capabilities.ConditionalIfNoneMatch = *capIfNoneParsed
		changed = true
	}
	if capIfMatchParsed != nil {
		cfg.S3.Capabilities.ConditionalIfMatch = *capIfMatchParsed
		changed = true
	}
	if capChecksumsParsed != nil {
		cfg.S3.Capabilities.ResponseChecksums = *capChecksumsParsed
		changed = true
	}
	if value := strings.ToLower(strings.TrimSpace(*vectorLeaseMode)); value != "" {
		cfg.Coordination.VectorWriterLease.Mode = value
		changed = true
	}
	if value := strings.TrimSpace(*vectorLeaseResource); value != "" {
		cfg.Coordination.VectorWriterLease.Resource = normalizeS3ObjectKey(value)
		changed = true
	}
	if *vectorLeaseDuration >= 0 {
		cfg.Coordination.VectorWriterLease.DurationSeconds = *vectorLeaseDuration
		changed = true
	}
	if *vectorLeaseRenewInterval >= 0 {
		cfg.Coordination.VectorWriterLease.RenewIntervalSeconds = *vectorLeaseRenewInterval
		changed = true
	}
	if !changed {
		return fmt.Errorf("no changes requested; pass at least one mutable field flag")
	}

	now := time.Now().UTC()
	cfg.UpdatedAt = now.Format(time.RFC3339Nano)
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		return err
	}

	trustMeta, etag, err := writeSignedRemoteConfigUpdate(ctx, client, bootstrap, cfg, previousMeta, remoteConfigWriteOptions{
		SigningKeyPath:       *signingKeyPath,
		SigningKeyPassphrase: *signingKeyPassphrase,
		DocumentVersion:      *documentVersion,
		DocumentExpires:      *documentExpiresSeconds,
	})
	if err != nil {
		return err
	}

	return renderRemoteConfigShowOutput(resolvedOutputMode, remoteConfigShowOutput{
		Bucket:            bootstrap.Bucket,
		ConfigKey:         bootstrap.ConfigKey,
		ETag:              etag,
		DocumentVersion:   trustMeta.Version,
		SignerFingerprint: trustMeta.SignerFingerprint,
		PayloadHash:       trustMeta.PayloadHash,
		ExpiresAtUTC:      trustMeta.ExpiresAtUTC,
		Config:            cfg,
	})
}

func runRemoteConfigNodeListCommand(args []string) error {
	fs := flag.NewFlagSet("remote config node list", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config node list [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "List trust nodes from the signed Forge remote config document.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

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
	bootstrap, _, cfg, trustMeta, etag, err := loadRemoteConfigForMutation(ctx)
	if err != nil {
		return err
	}
	if err := upsertRemoteConfigCache(bootstrap, cfg, etag, trustMeta, time.Now().UTC()); err != nil {
		return err
	}

	return renderRemoteConfigNodeListOutput(resolvedOutputMode, remoteConfigNodeListOutput{
		Bucket:            bootstrap.Bucket,
		ConfigKey:         bootstrap.ConfigKey,
		ETag:              etag,
		DocumentVersion:   trustMeta.Version,
		SignerFingerprint: trustMeta.SignerFingerprint,
		PayloadHash:       trustMeta.PayloadHash,
		ExpiresAtUTC:      trustMeta.ExpiresAtUTC,
		Nodes:             cfg.Trust.Nodes,
	})
}

func runRemoteConfigNodeAddCommand(args []string) error {
	fs := flag.NewFlagSet("remote config node add", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config node add [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Add a trust node to the signed Forge remote config document.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	name := fs.String("name", "", "Node name")
	publicKey := fs.String("public-key", "", "Node OpenSSH public key")
	roles := fs.String("roles", "", "Comma-separated trust roles")
	revoked := fs.Bool("revoked", false, "Set revoked state on add")
	signingKeyPath := fs.String("signing-key", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyEnv)), "Path to OpenSSH private key used to sign updated config")
	signingKeyPassphrase := fs.String("signing-key-passphrase", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyPassphraseEnv)), "Passphrase for encrypted OpenSSH private key used by -signing-key")
	documentVersion := fs.Int64("doc-version", 0, "Signed document version (default: auto)")
	documentExpiresSeconds := fs.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
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

	nodeName := strings.TrimSpace(*name)
	if nodeName == "" {
		return fmt.Errorf("-name is required")
	}
	nodePublicKey := strings.TrimSpace(*publicKey)
	if nodePublicKey == "" {
		return fmt.Errorf("-public-key is required")
	}

	ctx := context.Background()
	bootstrap, client, cfg, previousMeta, _, err := loadRemoteConfigForMutation(ctx)
	if err != nil {
		return err
	}
	if idx := findRemoteTrustNodeIndex(cfg.Trust.Nodes, nodeName); idx >= 0 {
		return fmt.Errorf("trust node %q already exists", nodeName)
	}

	cfg.Trust.Nodes = append(cfg.Trust.Nodes, remoteTrustNode{
		Name:      nodeName,
		PublicKey: nodePublicKey,
		Roles:     parseRemoteRolesFlag(*roles),
		Revoked:   *revoked,
	})
	now := time.Now().UTC()
	cfg.UpdatedAt = now.Format(time.RFC3339Nano)
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		return err
	}

	trustMeta, etag, err := writeSignedRemoteConfigUpdate(ctx, client, bootstrap, cfg, previousMeta, remoteConfigWriteOptions{
		SigningKeyPath:       *signingKeyPath,
		SigningKeyPassphrase: *signingKeyPassphrase,
		DocumentVersion:      *documentVersion,
		DocumentExpires:      *documentExpiresSeconds,
	})
	if err != nil {
		return err
	}

	return renderRemoteConfigShowOutput(resolvedOutputMode, remoteConfigShowOutput{
		Bucket:            bootstrap.Bucket,
		ConfigKey:         bootstrap.ConfigKey,
		ETag:              etag,
		DocumentVersion:   trustMeta.Version,
		SignerFingerprint: trustMeta.SignerFingerprint,
		PayloadHash:       trustMeta.PayloadHash,
		ExpiresAtUTC:      trustMeta.ExpiresAtUTC,
		Config:            cfg,
	})
}

func runRemoteConfigNodeUpdateCommand(args []string) error {
	fs := flag.NewFlagSet("remote config node update", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config node update [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Update an existing trust node in the signed Forge remote config document.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	name := fs.String("name", "", "Node name")
	publicKey := fs.String("public-key", "", "Replacement OpenSSH public key")
	roles := fs.String("roles", "", "Replacement comma-separated trust roles")
	clearRoles := fs.Bool("clear-roles", false, "Clear node roles")
	revoked := fs.String("revoked", "", "Set revoked state (true|false)")
	signingKeyPath := fs.String("signing-key", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyEnv)), "Path to OpenSSH private key used to sign updated config")
	signingKeyPassphrase := fs.String("signing-key-passphrase", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyPassphraseEnv)), "Passphrase for encrypted OpenSSH private key used by -signing-key")
	documentVersion := fs.Int64("doc-version", 0, "Signed document version (default: auto)")
	documentExpiresSeconds := fs.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
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

	nodeName := strings.TrimSpace(*name)
	if nodeName == "" {
		return fmt.Errorf("-name is required")
	}
	revokedValue, err := parseOptionalBoolFlag(*revoked, "revoked")
	if err != nil {
		return err
	}

	ctx := context.Background()
	bootstrap, client, cfg, previousMeta, _, err := loadRemoteConfigForMutation(ctx)
	if err != nil {
		return err
	}
	idx := findRemoteTrustNodeIndex(cfg.Trust.Nodes, nodeName)
	if idx < 0 {
		return fmt.Errorf("trust node %q does not exist", nodeName)
	}

	changed := false
	if key := strings.TrimSpace(*publicKey); key != "" {
		cfg.Trust.Nodes[idx].PublicKey = key
		changed = true
	}
	if *clearRoles {
		cfg.Trust.Nodes[idx].Roles = nil
		changed = true
	} else if parsedRoles := parseRemoteRolesFlag(*roles); len(parsedRoles) > 0 {
		cfg.Trust.Nodes[idx].Roles = parsedRoles
		changed = true
	}
	if revokedValue != nil {
		cfg.Trust.Nodes[idx].Revoked = *revokedValue
		changed = true
	}
	if !changed {
		return fmt.Errorf("no node changes requested")
	}

	now := time.Now().UTC()
	cfg.UpdatedAt = now.Format(time.RFC3339Nano)
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		return err
	}

	trustMeta, etag, err := writeSignedRemoteConfigUpdate(ctx, client, bootstrap, cfg, previousMeta, remoteConfigWriteOptions{
		SigningKeyPath:       *signingKeyPath,
		SigningKeyPassphrase: *signingKeyPassphrase,
		DocumentVersion:      *documentVersion,
		DocumentExpires:      *documentExpiresSeconds,
	})
	if err != nil {
		return err
	}

	return renderRemoteConfigShowOutput(resolvedOutputMode, remoteConfigShowOutput{
		Bucket:            bootstrap.Bucket,
		ConfigKey:         bootstrap.ConfigKey,
		ETag:              etag,
		DocumentVersion:   trustMeta.Version,
		SignerFingerprint: trustMeta.SignerFingerprint,
		PayloadHash:       trustMeta.PayloadHash,
		ExpiresAtUTC:      trustMeta.ExpiresAtUTC,
		Config:            cfg,
	})
}

func runRemoteConfigNodeRemoveCommand(args []string) error {
	fs := flag.NewFlagSet("remote config node remove", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config node remove [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Remove a trust node from the signed Forge remote config document.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	name := fs.String("name", "", "Node name")
	signingKeyPath := fs.String("signing-key", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyEnv)), "Path to OpenSSH private key used to sign updated config")
	signingKeyPassphrase := fs.String("signing-key-passphrase", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyPassphraseEnv)), "Passphrase for encrypted OpenSSH private key used by -signing-key")
	documentVersion := fs.Int64("doc-version", 0, "Signed document version (default: auto)")
	documentExpiresSeconds := fs.Int("doc-expires-seconds", remoteDocExpiresPreserve, "Signed document expiry in seconds (-1 preserve existing, 0 disable)")
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

	nodeName := strings.TrimSpace(*name)
	if nodeName == "" {
		return fmt.Errorf("-name is required")
	}

	ctx := context.Background()
	bootstrap, client, cfg, previousMeta, _, err := loadRemoteConfigForMutation(ctx)
	if err != nil {
		return err
	}
	idx := findRemoteTrustNodeIndex(cfg.Trust.Nodes, nodeName)
	if idx < 0 {
		return fmt.Errorf("trust node %q does not exist", nodeName)
	}
	cfg.Trust.Nodes = append(cfg.Trust.Nodes[:idx], cfg.Trust.Nodes[idx+1:]...)
	now := time.Now().UTC()
	cfg.UpdatedAt = now.Format(time.RFC3339Nano)
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		return err
	}

	trustMeta, etag, err := writeSignedRemoteConfigUpdate(ctx, client, bootstrap, cfg, previousMeta, remoteConfigWriteOptions{
		SigningKeyPath:       *signingKeyPath,
		SigningKeyPassphrase: *signingKeyPassphrase,
		DocumentVersion:      *documentVersion,
		DocumentExpires:      *documentExpiresSeconds,
	})
	if err != nil {
		return err
	}

	return renderRemoteConfigShowOutput(resolvedOutputMode, remoteConfigShowOutput{
		Bucket:            bootstrap.Bucket,
		ConfigKey:         bootstrap.ConfigKey,
		ETag:              etag,
		DocumentVersion:   trustMeta.Version,
		SignerFingerprint: trustMeta.SignerFingerprint,
		PayloadHash:       trustMeta.PayloadHash,
		ExpiresAtUTC:      trustMeta.ExpiresAtUTC,
		Config:            cfg,
	})
}

func loadRemoteConfigForMutation(ctx context.Context) (remoteS3Bootstrap, *s3.Client, remoteGlobalConfig, remoteSignedDocumentMetadata, string, error) {
	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		return remoteS3Bootstrap{}, nil, remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, "", err
	}
	client, err := newS3ClientFromBootstrap(ctx, bootstrap)
	if err != nil {
		return remoteS3Bootstrap{}, nil, remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, "", err
	}
	cfg, trustMeta, etag, err := loadRemoteGlobalConfigFromS3(ctx, client, bootstrap)
	if err != nil {
		return remoteS3Bootstrap{}, nil, remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, "", err
	}
	return bootstrap, client, cfg, trustMeta, etag, nil
}

func writeSignedRemoteConfigUpdate(ctx context.Context, client *s3.Client, bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig, previousMeta remoteSignedDocumentMetadata, opts remoteConfigWriteOptions) (remoteSignedDocumentMetadata, string, error) {
	now := time.Now().UTC()
	resolvedVersion := opts.DocumentVersion
	if resolvedVersion <= 0 {
		resolvedVersion = now.UnixNano()
		if previousMeta.Version >= resolvedVersion {
			resolvedVersion = previousMeta.Version + 1
		}
	}
	expiresAt, err := resolveRemoteConfigDocumentExpiry(previousMeta, opts.DocumentExpires, now)
	if err != nil {
		return remoteSignedDocumentMetadata{}, "", err
	}
	signer, _, _, err := loadRemoteSigningKey(opts.SigningKeyPath, opts.SigningKeyPassphrase)
	if err != nil {
		return remoteSignedDocumentMetadata{}, "", err
	}
	docPayload, trustMeta, err := createSignedRemoteConfigDocument(cfg, signer, resolvedVersion, now, expiresAt)
	if err != nil {
		return remoteSignedDocumentMetadata{}, "", err
	}
	etag, err := putRemoteGlobalConfigDocumentToS3(ctx, client, bootstrap, docPayload, true, cfg.S3.Capabilities.ConditionalIfNoneMatch)
	if err != nil {
		return remoteSignedDocumentMetadata{}, "", err
	}
	if err := upsertRemoteConfigCache(bootstrap, cfg, etag, trustMeta, now); err != nil {
		return remoteSignedDocumentMetadata{}, "", err
	}
	return trustMeta, etag, nil
}

func resolveRemoteConfigDocumentExpiry(previousMeta remoteSignedDocumentMetadata, expiresSeconds int, now time.Time) (*time.Time, error) {
	switch {
	case expiresSeconds < remoteDocExpiresPreserve:
		return nil, fmt.Errorf("doc-expires-seconds must be >= -1")
	case expiresSeconds == remoteDocExpiresPreserve:
		if strings.TrimSpace(previousMeta.ExpiresAtUTC) == "" {
			return nil, nil
		}
		parsed, err := time.Parse(time.RFC3339Nano, previousMeta.ExpiresAtUTC)
		if err != nil {
			return nil, fmt.Errorf("parse existing document expiry: %w", err)
		}
		utc := parsed.UTC()
		return &utc, nil
	case expiresSeconds == 0:
		return nil, nil
	default:
		parsed := now.UTC().Add(time.Duration(expiresSeconds) * time.Second)
		return &parsed, nil
	}
}

func parseOptionalBoolFlag(raw string, name string) (*bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	value, err := strconv.ParseBool(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse -%s: %w", name, err)
	}
	return &value, nil
}

func parseRemoteRolesFlag(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ';'
	})
	roles := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		roles = append(roles, value)
	}
	return roles
}

func findRemoteTrustNodeIndex(nodes []remoteTrustNode, name string) int {
	needle := strings.TrimSpace(name)
	if needle == "" {
		return -1
	}
	for i := range nodes {
		if strings.TrimSpace(nodes[i].Name) == needle {
			return i
		}
	}
	return -1
}

func renderRemoteConfigNodeListOutput(mode string, output remoteConfigNodeListOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("bucket=%s\n", output.Bucket)
		fmt.Printf("config_key=%s\n", output.ConfigKey)
		fmt.Printf("etag=%s\n", output.ETag)
		fmt.Printf("document_version=%d\n", output.DocumentVersion)
		fmt.Printf("signer_fingerprint=%s\n", output.SignerFingerprint)
		fmt.Printf("payload_hash=%s\n", output.PayloadHash)
		fmt.Printf("expires_at_utc=%s\n", output.ExpiresAtUTC)
		fmt.Printf("node_count=%d\n", len(output.Nodes))
		for i, node := range output.Nodes {
			fmt.Printf("node.%d.name=%s\n", i, node.Name)
			fmt.Printf("node.%d.public_key=%s\n", i, node.PublicKey)
			fmt.Printf("node.%d.roles=%s\n", i, strings.Join(node.Roles, ","))
			fmt.Printf("node.%d.revoked=%t\n", i, node.Revoked)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Remote Config Nodes")
		printPrettyFields([]outputField{
			{Label: "Backend", Value: defaultS3BackendName},
			{Label: "Bucket", Value: output.Bucket},
			{Label: "Config Key", Value: output.ConfigKey},
			{Label: "ETag", Value: output.ETag},
			{Label: "Doc Version", Value: strconv.FormatInt(output.DocumentVersion, 10)},
			{Label: "Signer Fingerprint", Value: output.SignerFingerprint},
			{Label: "Payload Hash", Value: output.PayloadHash},
			{Label: "Expires At", Value: output.ExpiresAtUTC},
			{Label: "Node Count", Value: strconv.Itoa(len(output.Nodes))},
		})
		nodes, _ := json.MarshalIndent(output.Nodes, "", "  ")
		printPrettySection("Nodes")
		fmt.Println(string(nodes))
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
