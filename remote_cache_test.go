package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultRemoteDBPathUsesEnv(t *testing.T) {
	t.Setenv(forgeRemoteDBEnv, "/tmp/forge-remote-test.db")
	if got := defaultRemoteDBPath(); got != "/tmp/forge-remote-test.db" {
		t.Fatalf("expected remote db path from env, got %q", got)
	}
}

func TestLoadRemoteGlobalConfigWithCache(t *testing.T) {
	temp := t.TempDir()
	t.Setenv(forgeRemoteDBEnv, filepath.Join(temp, "remote.db"))

	bootstrap := remoteS3Bootstrap{
		Bucket:    "bucket-a",
		Region:    "eu-central-2",
		ConfigKey: "forge/config.json",
	}
	fetchCalls := 0
	fetch := func(_ context.Context, _ remoteS3Bootstrap) (remoteGlobalConfig, string, error) {
		fetchCalls++
		cfg := defaultRemoteGlobalConfig()
		cfg.S3.Bucket = "bucket-a"
		cfg.Cache.RemoteConfigTTLSeconds = 3600
		cfg.S3.ObjectPrefix = "forge-a"
		return cfg, "etag-a", nil
	}

	firstCfg, firstETag, err := loadRemoteGlobalConfigWithCache(context.Background(), bootstrap, fetch)
	if err != nil {
		t.Fatalf("first config load with cache: %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("expected fetch calls=1 after first load, got %d", fetchCalls)
	}
	if firstETag != "etag-a" {
		t.Fatalf("expected first etag=etag-a, got %q", firstETag)
	}
	if firstCfg.S3.ObjectPrefix != "forge-a" {
		t.Fatalf("expected first object prefix forge-a, got %q", firstCfg.S3.ObjectPrefix)
	}

	secondCfg, secondETag, err := loadRemoteGlobalConfigWithCache(context.Background(), bootstrap, fetch)
	if err != nil {
		t.Fatalf("second config load with cache: %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("expected second load to hit cache with fetch calls still 1, got %d", fetchCalls)
	}
	if secondETag != "etag-a" {
		t.Fatalf("expected cached etag=etag-a, got %q", secondETag)
	}
	if secondCfg.S3.ObjectPrefix != "forge-a" {
		t.Fatalf("expected cached object prefix forge-a, got %q", secondCfg.S3.ObjectPrefix)
	}
}

func TestLoadRemoteGlobalConfigWithCacheRefreshOnExpiry(t *testing.T) {
	temp := t.TempDir()
	t.Setenv(forgeRemoteDBEnv, filepath.Join(temp, "remote.db"))

	bootstrap := remoteS3Bootstrap{
		Bucket:    "bucket-a",
		Region:    "eu-central-2",
		ConfigKey: "forge/config.json",
	}
	fetchCalls := 0
	fetch := func(_ context.Context, _ remoteS3Bootstrap) (remoteGlobalConfig, string, error) {
		fetchCalls++
		cfg := defaultRemoteGlobalConfig()
		cfg.S3.Bucket = "bucket-a"
		cfg.Cache.RemoteConfigTTLSeconds = 3600
		if fetchCalls == 1 {
			cfg.S3.ObjectPrefix = "forge-first"
			return cfg, "etag-first", nil
		}
		cfg.S3.ObjectPrefix = "forge-second"
		return cfg, "etag-second", nil
	}

	_, _, err := loadRemoteGlobalConfigWithCache(context.Background(), bootstrap, fetch)
	if err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	if fetchCalls != 1 {
		t.Fatalf("expected fetch calls=1 after seed, got %d", fetchCalls)
	}

	db, err := openRemoteConfigDB(defaultRemoteDBPath())
	if err != nil {
		t.Fatalf("open remote db: %v", err)
	}
	if _, err := db.Exec(`UPDATE remote_config_cache SET expires_at_ns = ?`, time.Now().UTC().Add(-time.Minute).UnixNano()); err != nil {
		db.Close()
		t.Fatalf("expire cache row: %v", err)
	}
	db.Close()

	cfg, etag, err := loadRemoteGlobalConfigWithCache(context.Background(), bootstrap, fetch)
	if err != nil {
		t.Fatalf("reload after expiry: %v", err)
	}
	if fetchCalls != 2 {
		t.Fatalf("expected fetch calls=2 after expiry refresh, got %d", fetchCalls)
	}
	if etag != "etag-second" {
		t.Fatalf("expected refreshed etag=etag-second, got %q", etag)
	}
	if cfg.S3.ObjectPrefix != "forge-second" {
		t.Fatalf("expected refreshed object prefix forge-second, got %q", cfg.S3.ObjectPrefix)
	}
}
