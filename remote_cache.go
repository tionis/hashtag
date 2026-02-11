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

	"github.com/tionis/forge/internal/forgeconfig"
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
	ConfigJSON        string
	ETag              string
	FetchedAtNS       int64
	ExpiresAtNS       int64
	SignedVersion     int64
	SignedPayloadHash string
	SignerFingerprint string
	SignedExpiresAtNS int64
}

type remoteGlobalConfigFetchResult struct {
	Config remoteGlobalConfig
	ETag   string
	Trust  remoteSignedDocumentMetadata
}

type remoteGlobalConfigFetchFunc func(context.Context, remoteS3Bootstrap) (remoteGlobalConfigFetchResult, error)

func defaultRemoteDBPath() string {
	return forgeconfig.RemoteDBPath()
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
			signed_version INTEGER NOT NULL DEFAULT 0,
			signed_payload_hash TEXT NOT NULL DEFAULT '',
			signer_fingerprint TEXT NOT NULL DEFAULT '',
			signed_expires_at_ns INTEGER NOT NULL DEFAULT 0,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY(endpoint_url, region, bucket, config_key, force_path_style)
		);`,
		`CREATE TABLE IF NOT EXISTS remote_trust_state (
			endpoint_url TEXT NOT NULL,
			region TEXT NOT NULL,
			bucket TEXT NOT NULL,
			config_key TEXT NOT NULL,
			force_path_style INTEGER NOT NULL,
			document_type TEXT NOT NULL,
			version INTEGER NOT NULL,
			payload_hash TEXT NOT NULL,
			signer_fingerprint TEXT NOT NULL,
			verified_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY(endpoint_url, region, bucket, config_key, force_path_style, document_type)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize remote config cache schema: %w", err)
		}
	}
	migrations := []string{
		`ALTER TABLE remote_config_cache ADD COLUMN signed_version INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE remote_config_cache ADD COLUMN signed_payload_hash TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE remote_config_cache ADD COLUMN signer_fingerprint TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE remote_config_cache ADD COLUMN signed_expires_at_ns INTEGER NOT NULL DEFAULT 0`,
	}
	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil && !isSQLiteDuplicateColumnError(err) {
			return fmt.Errorf("apply remote config cache migration %q: %w", migration, err)
		}
	}
	return nil
}

func isSQLiteDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
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
		`SELECT config_json, etag, fetched_at_ns, expires_at_ns, signed_version, signed_payload_hash, signer_fingerprint, signed_expires_at_ns
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
	).Scan(&row.ConfigJSON, &row.ETag, &row.FetchedAtNS, &row.ExpiresAtNS, &row.SignedVersion, &row.SignedPayloadHash, &row.SignerFingerprint, &row.SignedExpiresAtNS)
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

func upsertRemoteConfigCache(bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig, etag string, trustMeta remoteSignedDocumentMetadata, now time.Time) error {
	dbPath := defaultRemoteDBPath()
	db, err := openRemoteConfigDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := upsertRemoteConfigCacheDB(db, remoteConfigCacheKeyFromBootstrap(bootstrap), cfg, etag, trustMeta, now); err != nil {
		return err
	}
	return nil
}

func upsertRemoteConfigCacheDB(db *sql.DB, key remoteConfigCacheKey, cfg remoteGlobalConfig, etag string, trustMeta remoteSignedDocumentMetadata, now time.Time) error {
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, remoteS3Bootstrap{Bucket: key.Bucket}); err != nil {
		return err
	}
	if err := enforceRemoteDocumentTrustState(db, key, trustMeta, now); err != nil {
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
			signed_version,
			signed_payload_hash,
			signer_fingerprint,
			signed_expires_at_ns,
			updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(endpoint_url, region, bucket, config_key, force_path_style)
		DO UPDATE SET
			config_json = excluded.config_json,
			etag = excluded.etag,
			fetched_at_ns = excluded.fetched_at_ns,
			expires_at_ns = excluded.expires_at_ns,
			signed_version = excluded.signed_version,
			signed_payload_hash = excluded.signed_payload_hash,
			signer_fingerprint = excluded.signer_fingerprint,
			signed_expires_at_ns = excluded.signed_expires_at_ns,
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
		trustMeta.Version,
		trustMeta.PayloadHash,
		trustMeta.SignerFingerprint,
		trustMeta.ExpiresAtNS,
		fetchedAtNS,
	); err != nil {
		return fmt.Errorf("upsert remote config cache row: %w", err)
	}
	return nil
}

func fetchRemoteGlobalConfigFromS3(ctx context.Context, bootstrap remoteS3Bootstrap) (remoteGlobalConfigFetchResult, error) {
	client, err := newS3ClientFromBootstrap(ctx, bootstrap)
	if err != nil {
		return remoteGlobalConfigFetchResult{}, err
	}
	cfg, trustMeta, etag, err := loadRemoteGlobalConfigFromS3(ctx, client, bootstrap)
	if err != nil {
		return remoteGlobalConfigFetchResult{}, err
	}
	return remoteGlobalConfigFetchResult{
		Config: cfg,
		ETag:   etag,
		Trust:  trustMeta,
	}, nil
}

func loadRemoteGlobalConfigWithCache(ctx context.Context, bootstrap remoteS3Bootstrap, fetch remoteGlobalConfigFetchFunc) (remoteGlobalConfig, string, error) {
	result, err := loadRemoteGlobalConfigWithCacheDetails(ctx, bootstrap, fetch)
	if err != nil {
		return remoteGlobalConfig{}, "", err
	}
	return result.Config, result.ETag, nil
}

func loadRemoteGlobalConfigWithCacheDetails(ctx context.Context, bootstrap remoteS3Bootstrap, fetch remoteGlobalConfigFetchFunc) (remoteGlobalConfigFetchResult, error) {
	if fetch == nil {
		fetch = fetchRemoteGlobalConfigFromS3
	}
	dbPath := defaultRemoteDBPath()
	db, err := openRemoteConfigDB(dbPath)
	if err != nil {
		return remoteGlobalConfigFetchResult{}, err
	}
	defer db.Close()

	key := remoteConfigCacheKeyFromBootstrap(bootstrap)
	now := time.Now().UTC()
	if row, found, err := lookupRemoteConfigCache(db, key); err != nil {
		return remoteGlobalConfigFetchResult{}, err
	} else if found {
		if row.SignedVersion <= 0 || strings.TrimSpace(row.SignedPayloadHash) == "" {
			if err := deleteRemoteConfigCacheRow(db, key); err != nil {
				return remoteGlobalConfigFetchResult{}, err
			}
		} else {
			cfg, decodeErr := decodeAndValidateRemoteGlobalConfig([]byte(row.ConfigJSON), bootstrap)
			if decodeErr != nil {
				if err := deleteRemoteConfigCacheRow(db, key); err != nil {
					return remoteGlobalConfigFetchResult{}, err
				}
			} else {
				expiresAtUTC := ""
				if row.SignedExpiresAtNS > 0 {
					expiresAtUTC = time.Unix(0, row.SignedExpiresAtNS).UTC().Format(time.RFC3339Nano)
				}
				cacheMeta := remoteSignedDocumentMetadata{
					DocumentType:      remoteDocumentTypeConfig,
					Version:           row.SignedVersion,
					PayloadHash:       row.SignedPayloadHash,
					SignerFingerprint: row.SignerFingerprint,
					ExpiresAtUTC:      expiresAtUTC,
					ExpiresAtNS:       row.SignedExpiresAtNS,
				}
				if err := enforceRemoteDocumentTrustState(db, key, cacheMeta, now); err != nil {
					if deleteErr := deleteRemoteConfigCacheRow(db, key); deleteErr != nil {
						return remoteGlobalConfigFetchResult{}, deleteErr
					}
				} else if row.ExpiresAtNS > now.UnixNano() {
					return remoteGlobalConfigFetchResult{
						Config: cfg,
						ETag:   row.ETag,
						Trust:  cacheMeta,
					}, nil
				}
			}
		}
	}

	fetched, err := fetch(ctx, bootstrap)
	if err != nil {
		return remoteGlobalConfigFetchResult{}, err
	}
	if err := upsertRemoteConfigCacheDB(db, key, fetched.Config, fetched.ETag, fetched.Trust, now); err != nil {
		return remoteGlobalConfigFetchResult{}, err
	}
	return fetched, nil
}
