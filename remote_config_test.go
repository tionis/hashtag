package main

import "testing"

func TestLoadRemoteS3BootstrapFromEnv(t *testing.T) {
	t.Setenv(forgeS3BucketEnv, "bucket-a")
	t.Setenv(forgeS3RegionEnv, "eu-central-2")
	t.Setenv(forgeS3EndpointURLEnv, "https://s3.example.com")
	t.Setenv(forgeS3AccessKeyIDEnv, "key")
	t.Setenv(forgeS3SecretAccessKeyEnv, "secret")
	t.Setenv(forgeS3SessionTokenEnv, "token")
	t.Setenv(forgeS3ForcePathStyleEnv, "true")
	t.Setenv(forgeRemoteConfigKeyEnv, "forge/global-config.json")

	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		t.Fatalf("load remote bootstrap: %v", err)
	}
	if bootstrap.Bucket != "bucket-a" {
		t.Fatalf("expected bucket bucket-a, got %q", bootstrap.Bucket)
	}
	if !bootstrap.ForcePathStyle {
		t.Fatal("expected force path style to be true")
	}
	if bootstrap.ConfigKey != "forge/global-config.json" {
		t.Fatalf("expected config key forge/global-config.json, got %q", bootstrap.ConfigKey)
	}
}

func TestLoadRemoteS3BootstrapFromEnvRequiresBucket(t *testing.T) {
	t.Setenv(forgeS3BucketEnv, "")
	_, err := loadRemoteS3BootstrapFromEnv()
	if err == nil {
		t.Fatal("expected missing bucket to fail")
	}
}

func TestNormalizeAndValidateRemoteGlobalConfig(t *testing.T) {
	bootstrap := remoteS3Bootstrap{
		Bucket:    "bucket-a",
		ConfigKey: "forge/config.json",
	}
	cfg := defaultRemoteGlobalConfig()
	cfg.S3.Bucket = "bucket-a"
	cfg.S3.ObjectPrefix = "/forge-data/"
	cfg.S3.BlobPrefix = "/blob-store/"
	cfg.Cache.RemoteConfigTTLSeconds = 0
	cfg.Coordination.VectorWriterLease.Resource = "/vector/lease/"
	cfg.Coordination.VectorWriterLease.DurationSeconds = 0
	cfg.Coordination.VectorWriterLease.RenewIntervalSeconds = 0
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		t.Fatalf("normalize and validate config: %v", err)
	}
	if cfg.S3.ObjectPrefix != "forge-data" {
		t.Fatalf("expected normalized object prefix forge-data, got %q", cfg.S3.ObjectPrefix)
	}
	if cfg.S3.BlobPrefix != "blob-store" {
		t.Fatalf("expected normalized blob prefix blob-store, got %q", cfg.S3.BlobPrefix)
	}
	if cfg.Cache.RemoteConfigTTLSeconds != defaultRemoteConfigCacheTTLSeconds {
		t.Fatalf("expected default cache ttl %d, got %d", defaultRemoteConfigCacheTTLSeconds, cfg.Cache.RemoteConfigTTLSeconds)
	}
	if cfg.Coordination.VectorWriterLease.Resource != "vector/lease" {
		t.Fatalf("expected normalized lease resource vector/lease, got %q", cfg.Coordination.VectorWriterLease.Resource)
	}
	if cfg.Coordination.VectorWriterLease.DurationSeconds != defaultVectorLeaseDurationSeconds {
		t.Fatalf("expected default lease duration %d, got %d", defaultVectorLeaseDurationSeconds, cfg.Coordination.VectorWriterLease.DurationSeconds)
	}
	if cfg.Coordination.VectorWriterLease.RenewIntervalSeconds != defaultVectorLeaseRenewIntervalSeconds {
		t.Fatalf("expected default lease renew interval %d, got %d", defaultVectorLeaseRenewIntervalSeconds, cfg.Coordination.VectorWriterLease.RenewIntervalSeconds)
	}

	cfg.Policy.EncryptNonConfigData = false
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err == nil {
		t.Fatal("expected encryption policy=false to fail validation")
	}
}

func TestNormalizeAndValidateRemoteGlobalConfigLeaseValidation(t *testing.T) {
	bootstrap := remoteS3Bootstrap{
		Bucket:    "bucket-a",
		ConfigKey: "forge/config.json",
	}
	cfg := defaultRemoteGlobalConfig()
	cfg.S3.Bucket = "bucket-a"
	cfg.S3.Capabilities = remoteS3Capabilities{
		ConditionalIfNoneMatch: true,
		ConditionalIfMatch:     false,
	}
	cfg.Coordination.VectorWriterLease.Mode = vectorLeaseModeHard
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err == nil {
		t.Fatal("expected hard lease mode validation to fail without full CAS capabilities")
	}

	cfg = defaultRemoteGlobalConfig()
	cfg.S3.Bucket = "bucket-a"
	cfg.Coordination.VectorWriterLease.Mode = vectorLeaseModeSoft
	cfg.Coordination.VectorWriterLease.DurationSeconds = 10
	cfg.Coordination.VectorWriterLease.RenewIntervalSeconds = 10
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err == nil {
		t.Fatal("expected renew interval >= duration to fail validation")
	}
}
