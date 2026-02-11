package main

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	forgeS3BucketEnv          = "FORGE_S3_BUCKET"
	forgeS3RegionEnv          = "FORGE_S3_REGION"
	forgeS3EndpointURLEnv     = "FORGE_S3_ENDPOINT_URL"
	forgeS3AccessKeyIDEnv     = "FORGE_S3_ACCESS_KEY_ID"
	forgeS3SecretAccessKeyEnv = "FORGE_S3_SECRET_ACCESS_KEY"
	forgeS3SessionTokenEnv    = "FORGE_S3_SESSION_TOKEN"
	forgeS3ForcePathStyleEnv  = "FORGE_S3_FORCE_PATH_STYLE"
	forgeRemoteConfigKeyEnv   = "FORGE_REMOTE_CONFIG_KEY"

	remoteConfigVersion = 1

	defaultRemoteConfigKey             = "forge/config.json"
	defaultS3ObjectPrefix              = "forge"
	defaultS3BlobKeyPrefix             = "blobs"
	defaultS3BackendName               = "s3"
	defaultS3Region                    = "us-east-1"
	defaultRemoteConfigCacheTTLSeconds = 300
	defaultCapabilityIfNone            = true
	defaultCapabilityIfMatch           = false
	defaultCapabilityResponseChecksums = false
	defaultRemoteDocExpiresSeconds     = 0

	defaultVectorLeaseMode                 = "auto"
	defaultVectorLeaseResource             = "vector/embeddings-writer"
	defaultVectorLeaseDurationSeconds      = 45
	defaultVectorLeaseRenewIntervalSeconds = 15
)

type remoteS3Bootstrap struct {
	Bucket         string
	Region         string
	EndpointURL    string
	AccessKeyID    string
	SecretAccess   string
	SessionToken   string
	ForcePathStyle bool
	ConfigKey      string
}

type remoteGlobalConfig struct {
	Version      int                      `json:"version"`
	UpdatedAt    string                   `json:"updated_at,omitempty"`
	Cache        remoteGlobalCache        `json:"cache"`
	S3           remoteGlobalS3Config     `json:"s3"`
	Coordination remoteGlobalCoordination `json:"coordination"`
	Trust        remoteGlobalTrustConfig  `json:"trust,omitempty"`
	Notes        map[string]string        `json:"notes,omitempty"`
}

type remoteGlobalCache struct {
	RemoteConfigTTLSeconds int `json:"remote_config_ttl_seconds"`
}

type remoteGlobalS3Config struct {
	ObjectPrefix string               `json:"object_prefix"`
	BlobPrefix   string               `json:"blob_prefix"`
	Capabilities remoteS3Capabilities `json:"capabilities"`
}

type remoteS3Capabilities struct {
	ConditionalIfNoneMatch bool `json:"conditional_if_none_match"`
	ConditionalIfMatch     bool `json:"conditional_if_match"`
	ResponseChecksums      bool `json:"response_checksums"`
}

type remoteGlobalCoordination struct {
	VectorWriterLease remoteVectorWriterLeaseConfig `json:"vector_writer_lease"`
}

type remoteVectorWriterLeaseConfig struct {
	Mode                 string `json:"mode"`
	Resource             string `json:"resource"`
	DurationSeconds      int    `json:"duration_seconds"`
	RenewIntervalSeconds int    `json:"renew_interval_seconds"`
}

type remoteConfigInitOutput struct {
	Bucket            string             `json:"bucket"`
	ConfigKey         string             `json:"config_key"`
	ETag              string             `json:"etag,omitempty"`
	DocumentVersion   int64              `json:"document_version"`
	SignerFingerprint string             `json:"signer_fingerprint"`
	PayloadHash       string             `json:"payload_hash"`
	ExpiresAtUTC      string             `json:"expires_at_utc,omitempty"`
	Config            remoteGlobalConfig `json:"config"`
}

type remoteConfigShowOutput struct {
	Bucket            string             `json:"bucket"`
	ConfigKey         string             `json:"config_key"`
	ETag              string             `json:"etag,omitempty"`
	DocumentVersion   int64              `json:"document_version"`
	SignerFingerprint string             `json:"signer_fingerprint"`
	PayloadHash       string             `json:"payload_hash"`
	ExpiresAtUTC      string             `json:"expires_at_utc,omitempty"`
	Config            remoteGlobalConfig `json:"config"`
}

func runRemoteConfigInitCommand(args []string) error {
	fs := flag.NewFlagSet("remote config init", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config init [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Write the global Forge remote configuration object to the configured S3 bucket.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	overwrite := fs.Bool("overwrite", false, "Overwrite existing config object")
	objectPrefix := fs.String("object-prefix", defaultS3ObjectPrefix, "Global object prefix for Forge data in the bucket")
	blobPrefix := fs.String("blob-prefix", defaultS3BlobKeyPrefix, "Blob object prefix under object-prefix")
	configCacheTTL := fs.Int("config-cache-ttl", defaultRemoteConfigCacheTTLSeconds, "Local remote-config cache TTL in seconds")
	probeCapabilities := fs.Bool("probe-capabilities", true, "Probe S3 capability flags on the target bucket")
	capIfNone := fs.Bool("cap-if-none-match", defaultCapabilityIfNone, "Manual If-None-Match support value (used when -probe-capabilities=false)")
	capIfMatch := fs.Bool("cap-if-match", defaultCapabilityIfMatch, "Manual If-Match support value (used when -probe-capabilities=false)")
	capResponseChecksums := fs.Bool("cap-response-checksums", defaultCapabilityResponseChecksums, "Manual response-checksum support value (used when -probe-capabilities=false)")
	vectorLeaseMode := fs.String("vector-lease-mode", defaultVectorLeaseMode, "Vector writer lease mode: auto|hard|soft|off")
	vectorLeaseResource := fs.String("vector-lease-resource", defaultVectorLeaseResource, "Vector writer lease resource key")
	vectorLeaseDuration := fs.Int("vector-lease-duration", defaultVectorLeaseDurationSeconds, "Vector writer lease duration in seconds")
	vectorLeaseRenewInterval := fs.Int("vector-lease-renew-interval", defaultVectorLeaseRenewIntervalSeconds, "Vector writer lease renew interval in seconds")
	signingKeyPath := fs.String("signing-key", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyEnv)), "Path to OpenSSH private key used to sign remote config document")
	signingKeyPassphrase := fs.String("signing-key-passphrase", strings.TrimSpace(os.Getenv(forgeTrustSigningKeyPassphraseEnv)), "Passphrase for encrypted OpenSSH private key used by -signing-key")
	documentVersion := fs.Int64("doc-version", 0, "Signed document version (default: auto)")
	documentExpiresSeconds := fs.Int("doc-expires-seconds", defaultRemoteDocExpiresSeconds, "Optional signed document expiry in seconds (0 means no expiry)")
	trustNodesFile := fs.String("trust-nodes-file", "", "Optional path to trust nodes JSON file (array or object with \"nodes\")")
	rootNodeName := fs.String("root-node-name", defaultRemoteRootNodeName, "Node name for signing root key in trust map")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	ctx := context.Background()
	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		return err
	}
	client, err := newS3ClientFromBootstrap(ctx, bootstrap)
	if err != nil {
		return err
	}

	signer, signerAuthorized, _, err := loadRemoteSigningKey(*signingKeyPath, *signingKeyPassphrase)
	if err != nil {
		return err
	}
	extraTrustNodes, err := loadRemoteTrustNodesFromFile(*trustNodesFile)
	if err != nil {
		return err
	}

	cfg := defaultRemoteGlobalConfig()
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	cfg.S3.ObjectPrefix = normalizeS3Prefix(*objectPrefix)
	cfg.S3.BlobPrefix = normalizeS3Prefix(*blobPrefix)
	cfg.Cache.RemoteConfigTTLSeconds = *configCacheTTL
	cfg.Coordination.VectorWriterLease.Mode = strings.ToLower(strings.TrimSpace(*vectorLeaseMode))
	cfg.Coordination.VectorWriterLease.Resource = normalizeS3ObjectKey(*vectorLeaseResource)
	cfg.Coordination.VectorWriterLease.DurationSeconds = *vectorLeaseDuration
	cfg.Coordination.VectorWriterLease.RenewIntervalSeconds = *vectorLeaseRenewInterval
	nodeName := strings.TrimSpace(*rootNodeName)
	if nodeName == "" {
		nodeName = defaultRemoteRootNodeName
	}
	cfg.Trust.Nodes = append(cfg.Trust.Nodes, remoteTrustNode{
		Name:      nodeName,
		PublicKey: signerAuthorized,
		Roles:     []string{"root"},
	})
	cfg.Trust.Nodes = append(cfg.Trust.Nodes, extraTrustNodes...)
	if *probeCapabilities {
		caps, err := detectRemoteS3Capabilities(ctx, client, bootstrap)
		if err != nil {
			return fmt.Errorf("detect remote S3 capabilities: %w", err)
		}
		cfg.S3.Capabilities = caps
	} else {
		cfg.S3.Capabilities.ConditionalIfNoneMatch = *capIfNone
		cfg.S3.Capabilities.ConditionalIfMatch = *capIfMatch
		cfg.S3.Capabilities.ResponseChecksums = *capResponseChecksums
	}
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		return err
	}

	resolvedDocVersion := *documentVersion
	if resolvedDocVersion <= 0 {
		resolvedDocVersion = time.Now().UTC().UnixNano()
		existingRaw, _, fetchErr := loadRemoteConfigObjectFromS3(ctx, client, bootstrap)
		if fetchErr == nil {
			if existingVersion, ok := extractSignedDocumentVersion(existingRaw); ok && existingVersion >= resolvedDocVersion {
				resolvedDocVersion = existingVersion + 1
			}
		} else if !stderrors.Is(fetchErr, errRemoteConfigNotFound) {
			return fmt.Errorf("inspect existing remote config for versioning: %w", fetchErr)
		}
	}
	var expiresAt *time.Time
	if *documentExpiresSeconds > 0 {
		candidate := time.Now().UTC().Add(time.Duration(*documentExpiresSeconds) * time.Second)
		expiresAt = &candidate
	}
	docPayload, trustMeta, err := createSignedRemoteConfigDocument(cfg, signer, resolvedDocVersion, time.Now().UTC(), expiresAt)
	if err != nil {
		return err
	}
	etag, err := putRemoteGlobalConfigDocumentToS3(ctx, client, bootstrap, docPayload, *overwrite, cfg.S3.Capabilities.ConditionalIfNoneMatch)
	if err != nil {
		return err
	}
	if err := upsertRemoteConfigCache(bootstrap, cfg, etag, trustMeta, time.Now().UTC()); err != nil {
		return err
	}

	return renderRemoteConfigInitOutput(resolvedOutputMode, remoteConfigInitOutput{
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

func runRemoteConfigShowCommand(args []string) error {
	fs := flag.NewFlagSet("remote config show", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s remote config show [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Read and print the global Forge remote configuration object from S3.")
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
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	ctx := context.Background()
	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		return err
	}
	client, err := newS3ClientFromBootstrap(ctx, bootstrap)
	if err != nil {
		return err
	}

	cfg, trustMeta, etag, err := loadRemoteGlobalConfigFromS3(ctx, client, bootstrap)
	if err != nil {
		return err
	}
	if err := upsertRemoteConfigCache(bootstrap, cfg, etag, trustMeta, time.Now().UTC()); err != nil {
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

func loadRemoteS3BootstrapFromEnv() (remoteS3Bootstrap, error) {
	bucket := strings.TrimSpace(os.Getenv(forgeS3BucketEnv))
	if bucket == "" {
		return remoteS3Bootstrap{}, fmt.Errorf("%s is required", forgeS3BucketEnv)
	}
	region := strings.TrimSpace(os.Getenv(forgeS3RegionEnv))
	if region == "" {
		region = defaultS3Region
	}

	endpointURL := strings.TrimSpace(os.Getenv(forgeS3EndpointURLEnv))
	accessKeyID := strings.TrimSpace(os.Getenv(forgeS3AccessKeyIDEnv))
	secretAccess := strings.TrimSpace(os.Getenv(forgeS3SecretAccessKeyEnv))
	if (accessKeyID == "") != (secretAccess == "") {
		return remoteS3Bootstrap{}, fmt.Errorf("%s and %s must be set together", forgeS3AccessKeyIDEnv, forgeS3SecretAccessKeyEnv)
	}

	forcePathStyle := false
	forceRaw := strings.TrimSpace(os.Getenv(forgeS3ForcePathStyleEnv))
	if forceRaw != "" {
		parsed, err := strconv.ParseBool(forceRaw)
		if err != nil {
			return remoteS3Bootstrap{}, fmt.Errorf("parse %s: %w", forgeS3ForcePathStyleEnv, err)
		}
		forcePathStyle = parsed
	}

	configKey := normalizeS3ObjectKey(strings.TrimSpace(os.Getenv(forgeRemoteConfigKeyEnv)))
	if configKey == "" {
		configKey = defaultRemoteConfigKey
	}

	return remoteS3Bootstrap{
		Bucket:         bucket,
		Region:         region,
		EndpointURL:    endpointURL,
		AccessKeyID:    accessKeyID,
		SecretAccess:   secretAccess,
		SessionToken:   strings.TrimSpace(os.Getenv(forgeS3SessionTokenEnv)),
		ForcePathStyle: forcePathStyle,
		ConfigKey:      configKey,
	}, nil
}

func defaultRemoteGlobalConfig() remoteGlobalConfig {
	return remoteGlobalConfig{
		Version: remoteConfigVersion,
		Cache: remoteGlobalCache{
			RemoteConfigTTLSeconds: defaultRemoteConfigCacheTTLSeconds,
		},
		S3: remoteGlobalS3Config{
			ObjectPrefix: defaultS3ObjectPrefix,
			BlobPrefix:   defaultS3BlobKeyPrefix,
			Capabilities: remoteS3Capabilities{
				ConditionalIfNoneMatch: defaultCapabilityIfNone,
				ConditionalIfMatch:     defaultCapabilityIfMatch,
				ResponseChecksums:      defaultCapabilityResponseChecksums,
			},
		},
		Coordination: remoteGlobalCoordination{
			VectorWriterLease: remoteVectorWriterLeaseConfig{
				Mode:                 defaultVectorLeaseMode,
				Resource:             defaultVectorLeaseResource,
				DurationSeconds:      defaultVectorLeaseDurationSeconds,
				RenewIntervalSeconds: defaultVectorLeaseRenewIntervalSeconds,
			},
		},
	}
}

func normalizeAndValidateRemoteGlobalConfig(cfg *remoteGlobalConfig, bootstrap remoteS3Bootstrap) error {
	if cfg.Version <= 0 {
		cfg.Version = remoteConfigVersion
	}
	cfg.S3.ObjectPrefix = normalizeS3Prefix(cfg.S3.ObjectPrefix)
	if cfg.S3.ObjectPrefix == "" {
		cfg.S3.ObjectPrefix = defaultS3ObjectPrefix
	}
	cfg.S3.BlobPrefix = normalizeS3Prefix(cfg.S3.BlobPrefix)
	if cfg.S3.BlobPrefix == "" {
		cfg.S3.BlobPrefix = defaultS3BlobKeyPrefix
	}
	if cfg.Cache.RemoteConfigTTLSeconds <= 0 {
		cfg.Cache.RemoteConfigTTLSeconds = defaultRemoteConfigCacheTTLSeconds
	}
	lease := &cfg.Coordination.VectorWriterLease
	lease.Mode = strings.ToLower(strings.TrimSpace(lease.Mode))
	if lease.Mode == "" {
		lease.Mode = defaultVectorLeaseMode
	}
	switch lease.Mode {
	case defaultVectorLeaseMode, vectorLeaseModeHard, vectorLeaseModeSoft, vectorLeaseModeOff:
	default:
		return fmt.Errorf("unsupported coordination.vector_writer_lease.mode %q (supported: auto|hard|soft|off)", lease.Mode)
	}
	if lease.Mode == vectorLeaseModeHard && !(cfg.S3.Capabilities.ConditionalIfNoneMatch && cfg.S3.Capabilities.ConditionalIfMatch) {
		return fmt.Errorf("coordination.vector_writer_lease.mode=hard requires s3 capabilities conditional_if_none_match=true and conditional_if_match=true")
	}
	lease.Resource = normalizeS3ObjectKey(lease.Resource)
	if lease.Resource == "" {
		lease.Resource = defaultVectorLeaseResource
	}
	if lease.DurationSeconds <= 0 {
		lease.DurationSeconds = defaultVectorLeaseDurationSeconds
	}
	if lease.RenewIntervalSeconds <= 0 {
		lease.RenewIntervalSeconds = defaultVectorLeaseRenewIntervalSeconds
	}
	if lease.RenewIntervalSeconds >= lease.DurationSeconds {
		return fmt.Errorf("coordination.vector_writer_lease.renew_interval_seconds (%d) must be less than duration_seconds (%d)", lease.RenewIntervalSeconds, lease.DurationSeconds)
	}
	normalizedNodes, err := normalizeAndValidateRemoteTrustNodes(cfg.Trust.Nodes)
	if err != nil {
		return err
	}
	cfg.Trust.Nodes = normalizedNodes
	return nil
}

func normalizeS3ObjectKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "/")
	key = strings.TrimSuffix(key, "/")
	return key
}

func normalizeS3Prefix(prefix string) string {
	prefix = normalizeS3ObjectKey(prefix)
	if prefix == "." {
		return ""
	}
	return prefix
}

func renderRemoteConfigInitOutput(mode string, output remoteConfigInitOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("bucket=%s\n", output.Bucket)
		fmt.Printf("config_key=%s\n", output.ConfigKey)
		fmt.Printf("etag=%s\n", output.ETag)
		fmt.Printf("document_version=%d\n", output.DocumentVersion)
		fmt.Printf("signer_fingerprint=%s\n", output.SignerFingerprint)
		fmt.Printf("payload_hash=%s\n", output.PayloadHash)
		fmt.Printf("expires_at_utc=%s\n", output.ExpiresAtUTC)
		cfgBytes, _ := json.Marshal(output.Config)
		fmt.Printf("config_json=%s\n", string(cfgBytes))
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Remote Config Initialized")
		printPrettyFields([]outputField{
			{Label: "Backend", Value: defaultS3BackendName},
			{Label: "Bucket", Value: output.Bucket},
			{Label: "Config Key", Value: output.ConfigKey},
			{Label: "ETag", Value: output.ETag},
			{Label: "Doc Version", Value: strconv.FormatInt(output.DocumentVersion, 10)},
			{Label: "Signer Fingerprint", Value: output.SignerFingerprint},
			{Label: "Payload Hash", Value: output.PayloadHash},
			{Label: "Expires At", Value: output.ExpiresAtUTC},
		})
		cfg, _ := json.MarshalIndent(output.Config, "", "  ")
		printPrettySection("Config")
		fmt.Println(string(cfg))
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderRemoteConfigShowOutput(mode string, output remoteConfigShowOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("bucket=%s\n", output.Bucket)
		fmt.Printf("config_key=%s\n", output.ConfigKey)
		fmt.Printf("etag=%s\n", output.ETag)
		fmt.Printf("document_version=%d\n", output.DocumentVersion)
		fmt.Printf("signer_fingerprint=%s\n", output.SignerFingerprint)
		fmt.Printf("payload_hash=%s\n", output.PayloadHash)
		fmt.Printf("expires_at_utc=%s\n", output.ExpiresAtUTC)
		cfgBytes, _ := json.Marshal(output.Config)
		fmt.Printf("config_json=%s\n", string(cfgBytes))
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Remote Config")
		printPrettyFields([]outputField{
			{Label: "Backend", Value: defaultS3BackendName},
			{Label: "Bucket", Value: output.Bucket},
			{Label: "Config Key", Value: output.ConfigKey},
			{Label: "ETag", Value: output.ETag},
			{Label: "Doc Version", Value: strconv.FormatInt(output.DocumentVersion, 10)},
			{Label: "Signer Fingerprint", Value: output.SignerFingerprint},
			{Label: "Payload Hash", Value: output.PayloadHash},
			{Label: "Expires At", Value: output.ExpiresAtUTC},
		})
		cfg, _ := json.MarshalIndent(output.Config, "", "  ")
		printPrettySection("Config")
		fmt.Println(string(cfg))
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
