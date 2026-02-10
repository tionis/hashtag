package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type remoteConfigCacheKey struct {
	EndpointURL    string
	Region         string
	Bucket         string
	ConfigKey      string
	ForcePathStyle int
}

type remoteConfigCacheRow struct {
	ConfigJSON  string
	ETag        string
	FetchedAtNS int64
	ExpiresAtNS int64
}

type remoteGlobalConfigFetchFunc func(context.Context, remoteS3Bootstrap) (remoteGlobalConfig, string, error)

func defaultRemoteDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(forgeRemoteDBEnv)); custom != "" {
		return custom
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if strings.TrimSpace(dataHome) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return defaultRemoteDBFile
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, snapshotDBDirName, defaultRemoteDBFile)
}

func openRemoteConfigDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create remote db directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open remote db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := initRemoteConfigCacheSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func initRemoteConfigCacheSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		`CREATE TABLE IF NOT EXISTS remote_config_cache (
			endpoint_url TEXT NOT NULL,
			region TEXT NOT NULL,
			bucket TEXT NOT NULL,
			config_key TEXT NOT NULL,
			force_path_style INTEGER NOT NULL,
			config_json TEXT NOT NULL,
			etag TEXT NOT NULL,
			fetched_at_ns INTEGER NOT NULL,
			expires_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY(endpoint_url, region, bucket, config_key, force_path_style)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize remote config cache schema: %w", err)
		}
	}
	return nil
}

func remoteConfigCacheKeyFromBootstrap(bootstrap remoteS3Bootstrap) remoteConfigCacheKey {
	forcePathStyle := 0
	if bootstrap.ForcePathStyle {
		forcePathStyle = 1
	}
	return remoteConfigCacheKey{
		EndpointURL:    strings.TrimSpace(bootstrap.EndpointURL),
		Region:         strings.TrimSpace(bootstrap.Region),
		Bucket:         strings.TrimSpace(bootstrap.Bucket),
		ConfigKey:      strings.TrimSpace(bootstrap.ConfigKey),
		ForcePathStyle: forcePathStyle,
	}
}

func decodeAndValidateRemoteGlobalConfig(payload []byte, bootstrap remoteS3Bootstrap) (remoteGlobalConfig, error) {
	cfg := remoteGlobalConfig{}
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return remoteGlobalConfig{}, fmt.Errorf("decode remote config JSON: %w", err)
	}
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		return remoteGlobalConfig{}, err
	}
	return cfg, nil
}

func lookupRemoteConfigCache(db *sql.DB, key remoteConfigCacheKey) (remoteConfigCacheRow, bool, error) {
	row := remoteConfigCacheRow{}
	err := db.QueryRow(
		`SELECT config_json, etag, fetched_at_ns, expires_at_ns
		 FROM remote_config_cache
		 WHERE endpoint_url = ?
		   AND region = ?
		   AND bucket = ?
		   AND config_key = ?
		   AND force_path_style = ?`,
		key.EndpointURL,
		key.Region,
		key.Bucket,
		key.ConfigKey,
		key.ForcePathStyle,
	).Scan(&row.ConfigJSON, &row.ETag, &row.FetchedAtNS, &row.ExpiresAtNS)
	if err == sql.ErrNoRows {
		return remoteConfigCacheRow{}, false, nil
	}
	if err != nil {
		return remoteConfigCacheRow{}, false, fmt.Errorf("query remote config cache: %w", err)
	}
	return row, true, nil
}

func deleteRemoteConfigCacheRow(db *sql.DB, key remoteConfigCacheKey) error {
	if _, err := db.Exec(
		`DELETE FROM remote_config_cache
		 WHERE endpoint_url = ?
		   AND region = ?
		   AND bucket = ?
		   AND config_key = ?
		   AND force_path_style = ?`,
		key.EndpointURL,
		key.Region,
		key.Bucket,
		key.ConfigKey,
		key.ForcePathStyle,
	); err != nil {
		return fmt.Errorf("delete invalid remote config cache row: %w", err)
	}
	return nil
}

func upsertRemoteConfigCache(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig, etag string, now time.Time) error {
	dbPath := defaultRemoteDBPath()
	db, err := openRemoteConfigDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := upsertRemoteConfigCacheDB(db, remoteConfigCacheKeyFromBootstrap(bootstrap), cfg, etag, now); err != nil {
		return err
	}
	return nil
}

func upsertRemoteConfigCacheDB(db *sql.DB, key remoteConfigCacheKey, cfg remoteGlobalConfig, etag string, now time.Time) error {
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, remoteS3Bootstrap{Bucket: key.Bucket}); err != nil {
		return err
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal remote config cache payload: %w", err)
	}
	ttlSeconds := cfg.Cache.RemoteConfigTTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = defaultRemoteConfigCacheTTLSeconds
	}
	fetchedAtNS := now.UnixNano()
	expiresAtNS := now.Add(time.Duration(ttlSeconds) * time.Second).UnixNano()
	if _, err := db.Exec(
		`INSERT INTO remote_config_cache(
			endpoint_url,
			region,
			bucket,
			config_key,
			force_path_style,
			config_json,
			etag,
			fetched_at_ns,
			expires_at_ns,
			updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(endpoint_url, region, bucket, config_key, force_path_style)
		DO UPDATE SET
			config_json = excluded.config_json,
			etag = excluded.etag,
			fetched_at_ns = excluded.fetched_at_ns,
			expires_at_ns = excluded.expires_at_ns,
			updated_at_ns = excluded.updated_at_ns`,
		key.EndpointURL,
		key.Region,
		key.Bucket,
		key.ConfigKey,
		key.ForcePathStyle,
		string(payload),
		etag,
		fetchedAtNS,
		expiresAtNS,
		fetchedAtNS,
	); err != nil {
		return fmt.Errorf("upsert remote config cache row: %w", err)
	}
	return nil
}

func fetchRemoteGlobalConfigFromS3(ctx context.Context, bootstrap remoteS3Bootstrap) (remoteGlobalConfig, string, error) {
	client, err := newS3ClientFromBootstrap(ctx, bootstrap)
	if err != nil {
		return remoteGlobalConfig{}, "", err
	}
	return loadRemoteGlobalConfigFromS3(ctx, client, bootstrap)
}

func loadRemoteGlobalConfigWithCache(ctx context.Context, bootstrap remoteS3Bootstrap, fetch remoteGlobalConfigFetchFunc) (remoteGlobalConfig, string, error) {
	if fetch == nil {
		fetch = fetchRemoteGlobalConfigFromS3
	}
	dbPath := defaultRemoteDBPath()
	db, err := openRemoteConfigDB(dbPath)
	if err != nil {
		return remoteGlobalConfig{}, "", err
	}
	defer db.Close()

	key := remoteConfigCacheKeyFromBootstrap(bootstrap)
	now := time.Now().UTC()
	if row, found, err := lookupRemoteConfigCache(db, key); err != nil {
		return remoteGlobalConfig{}, "", err
	} else if found {
		cfg, decodeErr := decodeAndValidateRemoteGlobalConfig([]byte(row.ConfigJSON), bootstrap)
		if decodeErr != nil {
			if err := deleteRemoteConfigCacheRow(db, key); err != nil {
				return remoteGlobalConfig{}, "", err
			}
		} else if row.ExpiresAtNS > now.UnixNano() {
			return cfg, row.ETag, nil
		}
	}

	cfg, etag, err := fetch(ctx, bootstrap)
	if err != nil {
		return remoteGlobalConfig{}, "", err
	}
	if err := upsertRemoteConfigCacheDB(db, key, cfg, etag, now); err != nil {
		return remoteGlobalConfig{}, "", err
	}
	return cfg, etag, nil
}
