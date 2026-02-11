package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/tionis/forge/internal/forgeconfig"
	"github.com/zeebo/blake3"
	_ "modernc.org/sqlite"
)

const (
	remoteGCInfoKeySuffix            = "gc/gc_info.json"
	remoteInventorySnapshotsPrefix   = "gc/inventory"
	remoteInventorySnapshotFile      = "inventory.db"
	remoteInventoryDBFormatVersion   = 1
	overlayMetaLastGCInfoCheckNSKey  = "gc_info_last_check_ns"
	overlayMetaLastGenerationKey     = "gc_info_generation"
	inventoryMetaGenerationKey       = "generation"
	inventoryMetaInventoryDBKey      = "inventory_db_key"
	inventoryMetaInventoryDBHash     = "inventory_db_hash"
	inventoryMetaCompletedAtUTC      = "completed_at_utc"
	inventoryMetaFormatVersion       = "inventory_db_format_version"
	remoteInventoryOverlaySourceHint = "local-discovery"
)

type remoteGCInfoDocument struct {
	Generation        string `json:"generation"`
	CompletedAtUTC    string `json:"completed_at_utc,omitempty"`
	InventoryDBKey    string `json:"inventory_db_key"`
	InventoryDBHash   string `json:"inventory_db_hash,omitempty"`
	InventoryDBFormat int    `json:"inventory_db_format_version,omitempty"`
	GCWorkerID        string `json:"gc_worker_id,omitempty"`
	DeletedCount      int64  `json:"deleted_count,omitempty"`
	ScannedCount      int64  `json:"scanned_count,omitempty"`
	PublishedAtUTC    string `json:"published_at_utc,omitempty"`
}

type blobInventoryPublishOutput struct {
	Bucket               string `json:"bucket"`
	Generation           string `json:"generation"`
	InventoryDBKey       string `json:"inventory_db_key"`
	InventoryDBHash      string `json:"inventory_db_hash"`
	InventoryDBFormat    int    `json:"inventory_db_format_version"`
	InventoryETag        string `json:"inventory_etag,omitempty"`
	GCInfoKey            string `json:"gc_info_key"`
	GCInfoETag           string `json:"gc_info_etag,omitempty"`
	ScannedCount         int64  `json:"scanned_count"`
	DeletedCount         int64  `json:"deleted_count"`
	WorkerID             string `json:"gc_worker_id,omitempty"`
	PublishedAtUTC       string `json:"published_at_utc"`
	InventoryLocalDBPath string `json:"inventory_local_db_path"`
}

type overlayBlobRow struct {
	Backend    string
	Bucket     string
	ObjectKey  string
	OID        string
	Size       int64
	ETag       string
	CipherHash string
	LastSeenNS int64
	Source     string
}

func defaultS3BlobsDBPath() string {
	return forgeconfig.S3BlobsDBPath()
}

func defaultS3BlobsOverlayDBPath() string {
	return forgeconfig.S3BlobsOverlayDBPath()
}

func openRemoteInventoryBaseDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create s3 inventory db directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open s3 inventory db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := initRemoteInventoryBaseSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func initRemoteInventoryBaseSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		`CREATE TABLE IF NOT EXISTS remote_blobs (
			backend TEXT NOT NULL,
			bucket TEXT NOT NULL,
			object_key TEXT NOT NULL,
			oid TEXT NOT NULL,
			size INTEGER NOT NULL,
			etag TEXT NOT NULL,
			cipher_hash TEXT NOT NULL,
			last_seen_ns INTEGER NOT NULL,
			scan_id TEXT NOT NULL,
			PRIMARY KEY (backend, bucket, object_key)
		);`,
		"CREATE INDEX IF NOT EXISTS remote_blobs_oid_idx ON remote_blobs(oid);",
		`CREATE TABLE IF NOT EXISTS inventory_meta (
			meta_key TEXT PRIMARY KEY,
			meta_value TEXT NOT NULL,
			updated_at_ns INTEGER NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize s3 inventory db schema: %w", err)
		}
	}
	return nil
}

func openRemoteInventoryOverlayDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create s3 overlay db directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open s3 overlay db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := initRemoteInventoryOverlaySchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func initRemoteInventoryOverlaySchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		`CREATE TABLE IF NOT EXISTS overlay_blobs (
			backend TEXT NOT NULL,
			bucket TEXT NOT NULL,
			object_key TEXT NOT NULL,
			oid TEXT NOT NULL,
			size INTEGER NOT NULL,
			etag TEXT NOT NULL,
			cipher_hash TEXT NOT NULL,
			last_seen_ns INTEGER NOT NULL,
			source TEXT NOT NULL,
			PRIMARY KEY (backend, bucket, object_key)
		);`,
		"CREATE INDEX IF NOT EXISTS overlay_blobs_oid_idx ON overlay_blobs(oid);",
		`CREATE TABLE IF NOT EXISTS overlay_tombstones (
			backend TEXT NOT NULL,
			bucket TEXT NOT NULL,
			object_key TEXT NOT NULL,
			oid TEXT NOT NULL,
			deleted_at_ns INTEGER NOT NULL,
			PRIMARY KEY (backend, bucket, object_key)
		);`,
		"CREATE INDEX IF NOT EXISTS overlay_tombstones_oid_idx ON overlay_tombstones(oid);",
		`CREATE TABLE IF NOT EXISTS overlay_meta (
			meta_key TEXT PRIMARY KEY,
			meta_value TEXT NOT NULL,
			updated_at_ns INTEGER NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize s3 overlay db schema: %w", err)
		}
	}
	return nil
}

func remoteGCInfoObjectKey(cfg remoteGlobalConfig) string {
	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	if base == "" {
		return remoteGCInfoKeySuffix
	}
	return base + "/" + remoteGCInfoKeySuffix
}

func remoteInventorySnapshotObjectKey(cfg remoteGlobalConfig, generation string) (string, error) {
	normalized := normalizeS3ObjectKey(generation)
	if normalized == "" {
		return "", fmt.Errorf("generation must not be empty")
	}
	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	parts := make([]string, 0, 4)
	if base != "" {
		parts = append(parts, base)
	}
	parts = append(parts, remoteInventorySnapshotsPrefix, normalized, remoteInventorySnapshotFile)
	return strings.Join(parts, "/"), nil
}

func remoteBlobObjectsPrefix(cfg remoteGlobalConfig) string {
	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	blobPrefix := normalizeS3Prefix(cfg.S3.BlobPrefix)
	if blobPrefix == "" {
		blobPrefix = defaultS3BlobKeyPrefix
	}
	if base == "" {
		return blobPrefix + "/"
	}
	return base + "/" + blobPrefix + "/"
}

func parseOIDFromBlobObjectKey(objectKey string) (string, bool) {
	trimmed := strings.TrimSpace(objectKey)
	if trimmed == "" {
		return "", false
	}
	lastSlash := strings.LastIndex(trimmed, "/")
	name := trimmed
	if lastSlash >= 0 {
		name = trimmed[lastSlash+1:]
	}
	if !strings.HasSuffix(name, ".fblob") {
		return "", false
	}
	oid := normalizeDigestHex(strings.TrimSuffix(name, ".fblob"))
	if err := validateBlobOID(oid); err != nil {
		return "", false
	}
	return oid, true
}

func upsertInventoryMeta(tx *sql.Tx, key string, value string, updatedAtNS int64) error {
	if _, err := tx.Exec(
		`INSERT INTO inventory_meta(meta_key, meta_value, updated_at_ns)
		VALUES(?, ?, ?)
		ON CONFLICT(meta_key) DO UPDATE SET
			meta_value = excluded.meta_value,
			updated_at_ns = excluded.updated_at_ns`,
		key,
		value,
		updatedAtNS,
	); err != nil {
		return fmt.Errorf("upsert inventory_meta[%s]: %w", key, err)
	}
	return nil
}

func lookupInventoryMeta(db *sql.DB, key string) (string, bool, error) {
	var value string
	err := db.QueryRow(`SELECT meta_value FROM inventory_meta WHERE meta_key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query inventory_meta[%s]: %w", key, err)
	}
	return value, true, nil
}

func upsertOverlayMeta(db *sql.DB, key string, value string, updatedAtNS int64) error {
	if _, err := db.Exec(
		`INSERT INTO overlay_meta(meta_key, meta_value, updated_at_ns)
		VALUES(?, ?, ?)
		ON CONFLICT(meta_key) DO UPDATE SET
			meta_value = excluded.meta_value,
			updated_at_ns = excluded.updated_at_ns`,
		key,
		value,
		updatedAtNS,
	); err != nil {
		return fmt.Errorf("upsert overlay_meta[%s]: %w", key, err)
	}
	return nil
}

func lookupOverlayMeta(db *sql.DB, key string) (string, bool, error) {
	var value string
	err := db.QueryRow(`SELECT meta_value FROM overlay_meta WHERE meta_key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query overlay_meta[%s]: %w", key, err)
	}
	return value, true, nil
}

func upsertRemoteBlobRow(tx *sql.Tx, row blobRemoteInventoryRow) error {
	if _, err := tx.Exec(
		`INSERT INTO remote_blobs(
			backend,
			bucket,
			object_key,
			oid,
			size,
			etag,
			cipher_hash,
			last_seen_ns,
			scan_id
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(backend, bucket, object_key) DO UPDATE SET
			oid = excluded.oid,
			size = excluded.size,
			etag = excluded.etag,
			cipher_hash = excluded.cipher_hash,
			last_seen_ns = excluded.last_seen_ns,
			scan_id = excluded.scan_id`,
		row.Backend,
		row.Bucket,
		row.ObjectKey,
		row.OID,
		row.Size,
		row.ETag,
		row.CipherHash,
		row.LastSeenNS,
		row.ScanID,
	); err != nil {
		return fmt.Errorf("upsert remote_blobs row %q: %w", row.ObjectKey, err)
	}
	return nil
}

func shouldCheckRemoteGCInfo(overlayPath string, ttlSeconds int, now time.Time) (bool, error) {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultRemoteConfigCacheTTLSeconds
	}
	db, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		return false, err
	}
	defer db.Close()

	lastCheckRaw, found, err := lookupOverlayMeta(db, overlayMetaLastGCInfoCheckNSKey)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	lastCheckNS, err := strconv.ParseInt(strings.TrimSpace(lastCheckRaw), 10, 64)
	if err != nil {
		return true, nil
	}
	elapsed := now.Sub(time.Unix(0, lastCheckNS))
	return elapsed >= time.Duration(ttlSeconds)*time.Second, nil
}

func markRemoteGCInfoCheck(overlayPath string, now time.Time, generation string) error {
	db, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		return err
	}
	defer db.Close()

	nowNS := now.UnixNano()
	if err := upsertOverlayMeta(db, overlayMetaLastGCInfoCheckNSKey, strconv.FormatInt(nowNS, 10), nowNS); err != nil {
		return err
	}
	if err := upsertOverlayMeta(db, overlayMetaLastGenerationKey, strings.TrimSpace(generation), nowNS); err != nil {
		return err
	}
	return nil
}

func loadRemoteGCInfo(ctx context.Context, store *s3BlobRemoteStore) (remoteGCInfoDocument, bool, error) {
	key := remoteGCInfoObjectKey(store.cfg)
	resp, err := store.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(store.bootstrap.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3NotFound(err) {
			return remoteGCInfoDocument{}, false, nil
		}
		return remoteGCInfoDocument{}, false, fmt.Errorf("read gc_info pointer s3://%s/%s: %w", store.bootstrap.Bucket, key, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return remoteGCInfoDocument{}, false, fmt.Errorf("read gc_info payload: %w", err)
	}
	doc := remoteGCInfoDocument{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return remoteGCInfoDocument{}, false, fmt.Errorf("decode gc_info payload: %w", err)
	}
	doc.Generation = normalizeS3ObjectKey(doc.Generation)
	doc.InventoryDBKey = normalizeS3ObjectKey(doc.InventoryDBKey)
	if doc.Generation == "" || doc.InventoryDBKey == "" {
		return remoteGCInfoDocument{}, false, fmt.Errorf("gc_info is missing required generation/inventory_db_key")
	}
	return doc, true, nil
}

func loadLocalInventoryGeneration(basePath string) (string, bool, error) {
	if _, err := os.Stat(basePath); err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("stat s3 inventory db %q: %w", basePath, err)
	}
	db, err := openRemoteInventoryBaseDB(basePath)
	if err != nil {
		return "", false, err
	}
	defer db.Close()
	value, found, err := lookupInventoryMeta(db, inventoryMetaGenerationKey)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", true, nil
	}
	return strings.TrimSpace(value), true, nil
}

func replaceLocalInventoryBaseDB(basePath string, payload []byte, gcInfo remoteGCInfoDocument, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		return fmt.Errorf("create s3 inventory db directory: %w", err)
	}
	tempPath := fmt.Sprintf("%s.tmp-%d", basePath, now.UnixNano())
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return fmt.Errorf("write temporary inventory snapshot: %w", err)
	}
	cleanup := func() {
		_ = os.Remove(tempPath)
	}
	defer cleanup()

	db, err := openRemoteInventoryBaseDB(tempPath)
	if err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("start inventory metadata transaction: %w", err)
	}
	defer tx.Rollback()
	nowNS := now.UnixNano()
	if err := upsertInventoryMeta(tx, inventoryMetaGenerationKey, gcInfo.Generation, nowNS); err != nil {
		_ = db.Close()
		return err
	}
	if err := upsertInventoryMeta(tx, inventoryMetaInventoryDBKey, gcInfo.InventoryDBKey, nowNS); err != nil {
		_ = db.Close()
		return err
	}
	if err := upsertInventoryMeta(tx, inventoryMetaInventoryDBHash, strings.TrimSpace(gcInfo.InventoryDBHash), nowNS); err != nil {
		_ = db.Close()
		return err
	}
	if err := upsertInventoryMeta(tx, inventoryMetaCompletedAtUTC, strings.TrimSpace(gcInfo.CompletedAtUTC), nowNS); err != nil {
		_ = db.Close()
		return err
	}
	if err := upsertInventoryMeta(tx, inventoryMetaFormatVersion, strconv.Itoa(gcInfo.InventoryDBFormat), nowNS); err != nil {
		_ = db.Close()
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = db.Close()
		return fmt.Errorf("commit inventory metadata transaction: %w", err)
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("close temporary inventory db: %w", err)
	}

	if err := os.Rename(tempPath, basePath); err != nil {
		return fmt.Errorf("replace local inventory db %q: %w", basePath, err)
	}
	return nil
}

func clearOverlayStateForGeneration(overlayPath string, generation string, now time.Time) error {
	db, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start overlay generation reset transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM overlay_blobs`); err != nil {
		return fmt.Errorf("clear overlay_blobs on generation change: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM overlay_tombstones`); err != nil {
		return fmt.Errorf("clear overlay_tombstones on generation change: %w", err)
	}
	nowNS := now.UnixNano()
	if _, err := tx.Exec(
		`INSERT INTO overlay_meta(meta_key, meta_value, updated_at_ns)
		VALUES(?, ?, ?)
		ON CONFLICT(meta_key) DO UPDATE SET
			meta_value = excluded.meta_value,
			updated_at_ns = excluded.updated_at_ns`,
		overlayMetaLastGenerationKey,
		generation,
		nowNS,
	); err != nil {
		return fmt.Errorf("update overlay generation metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit overlay generation reset: %w", err)
	}
	return nil
}

func hydrateRemoteInventoryCacheIfNeeded(ctx context.Context, store *s3BlobRemoteStore) error {
	if store == nil {
		return nil
	}
	overlayPath := defaultS3BlobsOverlayDBPath()
	basePath := defaultS3BlobsDBPath()
	now := time.Now().UTC()

	shouldCheck, err := shouldCheckRemoteGCInfo(overlayPath, store.cfg.Cache.RemoteConfigTTLSeconds, now)
	if err != nil {
		return err
	}
	if !shouldCheck {
		return nil
	}

	gcInfo, found, err := loadRemoteGCInfo(ctx, store)
	if err != nil {
		return err
	}
	if !found {
		return markRemoteGCInfoCheck(overlayPath, now, "")
	}
	if gcInfo.InventoryDBFormat <= 0 {
		gcInfo.InventoryDBFormat = remoteInventoryDBFormatVersion
	}

	localGeneration, localExists, err := loadLocalInventoryGeneration(basePath)
	if err != nil {
		return err
	}
	if !localExists || localGeneration != gcInfo.Generation {
		resp, err := store.client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(store.bootstrap.Bucket),
			Key:    aws.String(gcInfo.InventoryDBKey),
		})
		if err != nil {
			return fmt.Errorf("download inventory snapshot s3://%s/%s: %w", store.bootstrap.Bucket, gcInfo.InventoryDBKey, err)
		}
		payload, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read inventory snapshot payload: %w", readErr)
		}
		expectedHash := normalizeDigestHex(strings.TrimSpace(gcInfo.InventoryDBHash))
		if expectedHash != "" {
			got := blake3Hex(payload)
			if got != expectedHash {
				return fmt.Errorf("inventory snapshot hash mismatch: expected %s got %s", expectedHash, got)
			}
		}
		if err := replaceLocalInventoryBaseDB(basePath, payload, gcInfo, now); err != nil {
			return err
		}
		if err := clearOverlayStateForGeneration(overlayPath, gcInfo.Generation, now); err != nil {
			return err
		}
	}

	return markRemoteGCInfoCheck(overlayPath, now, gcInfo.Generation)
}

func remoteOIDExistsInUnionCache(basePath string, overlayPath string, backend string, bucket string, oid string) (bool, error) {
	backend = strings.TrimSpace(backend)
	bucket = strings.TrimSpace(bucket)
	oid = normalizeDigestHex(oid)
	if backend == "" || bucket == "" || oid == "" {
		return false, fmt.Errorf("backend, bucket, and oid are required for remote existence lookup")
	}
	if err := validateBlobOID(oid); err != nil {
		return false, err
	}

	overlayDB, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		return false, err
	}
	defer overlayDB.Close()

	var exists int
	if err := overlayDB.QueryRow(
		`SELECT 1 FROM overlay_blobs WHERE backend = ? AND bucket = ? AND oid = ? LIMIT 1`,
		backend,
		bucket,
		oid,
	).Scan(&exists); err == nil {
		return true, nil
	} else if err != sql.ErrNoRows {
		return false, fmt.Errorf("query overlay blob existence: %w", err)
	}

	if err := overlayDB.QueryRow(
		`SELECT 1 FROM overlay_tombstones WHERE backend = ? AND bucket = ? AND oid = ? LIMIT 1`,
		backend,
		bucket,
		oid,
	).Scan(&exists); err == nil {
		return false, nil
	} else if err != sql.ErrNoRows {
		return false, fmt.Errorf("query overlay tombstone existence: %w", err)
	}

	if _, err := os.Stat(basePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat base inventory db %q: %w", basePath, err)
	}
	baseDB, err := openRemoteInventoryBaseDB(basePath)
	if err != nil {
		return false, err
	}
	defer baseDB.Close()
	if err := baseDB.QueryRow(
		`SELECT 1 FROM remote_blobs WHERE backend = ? AND bucket = ? AND oid = ? LIMIT 1`,
		backend,
		bucket,
		oid,
	).Scan(&exists); err == nil {
		return true, nil
	} else if err != sql.ErrNoRows {
		return false, fmt.Errorf("query base inventory existence: %w", err)
	}
	return false, nil
}

func upsertOverlayBlobDiscovery(overlayPath string, row overlayBlobRow) error {
	db, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start overlay discovery transaction: %w", err)
	}
	defer tx.Rollback()
	if row.LastSeenNS == 0 {
		row.LastSeenNS = time.Now().UTC().UnixNano()
	}
	if strings.TrimSpace(row.Source) == "" {
		row.Source = remoteInventoryOverlaySourceHint
	}
	if _, err := tx.Exec(
		`INSERT INTO overlay_blobs(
			backend, bucket, object_key, oid, size, etag, cipher_hash, last_seen_ns, source
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(backend, bucket, object_key) DO UPDATE SET
			oid = excluded.oid,
			size = excluded.size,
			etag = excluded.etag,
			cipher_hash = excluded.cipher_hash,
			last_seen_ns = excluded.last_seen_ns,
			source = excluded.source`,
		row.Backend,
		row.Bucket,
		row.ObjectKey,
		row.OID,
		row.Size,
		row.ETag,
		row.CipherHash,
		row.LastSeenNS,
		row.Source,
	); err != nil {
		return fmt.Errorf("upsert overlay blob discovery %q: %w", row.ObjectKey, err)
	}
	if _, err := tx.Exec(
		`DELETE FROM overlay_tombstones WHERE backend = ? AND bucket = ? AND oid = ?`,
		row.Backend,
		row.Bucket,
		row.OID,
	); err != nil {
		return fmt.Errorf("clear overlay tombstone for oid %q: %w", row.OID, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit overlay discovery transaction: %w", err)
	}
	return nil
}

func recordOverlayBlobDeletion(basePath string, overlayPath string, backend string, bucket string, objectKey string, oid string) error {
	nowNS := time.Now().UTC().UnixNano()

	overlayDB, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		return err
	}
	defer overlayDB.Close()
	tx, err := overlayDB.Begin()
	if err != nil {
		return fmt.Errorf("start overlay delete transaction: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`DELETE FROM overlay_blobs WHERE backend = ? AND bucket = ? AND oid = ?`,
		backend,
		bucket,
		oid,
	); err != nil {
		return fmt.Errorf("delete overlay blob row oid %q: %w", oid, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO overlay_tombstones(backend, bucket, object_key, oid, deleted_at_ns)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(backend, bucket, object_key) DO UPDATE SET
			oid = excluded.oid,
			deleted_at_ns = excluded.deleted_at_ns`,
		backend,
		bucket,
		objectKey,
		oid,
		nowNS,
	); err != nil {
		return fmt.Errorf("upsert overlay tombstone oid %q: %w", oid, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit overlay delete transaction: %w", err)
	}

	if _, err := os.Stat(basePath); err == nil {
		baseDB, openErr := openRemoteInventoryBaseDB(basePath)
		if openErr != nil {
			return openErr
		}
		defer baseDB.Close()
		if _, execErr := baseDB.Exec(`DELETE FROM remote_blobs WHERE backend = ? AND bucket = ? AND oid = ?`, backend, bucket, oid); execErr != nil {
			return fmt.Errorf("delete base inventory row oid %q: %w", oid, execErr)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat base inventory db %q: %w", basePath, err)
	}
	return nil
}

func remoteOIDExistsForS3Store(ctx context.Context, store *s3BlobRemoteStore, oid string) (bool, error) {
	if err := hydrateRemoteInventoryCacheIfNeeded(ctx, store); err != nil {
		return false, err
	}
	return remoteOIDExistsInUnionCache(
		defaultS3BlobsDBPath(),
		defaultS3BlobsOverlayDBPath(),
		store.BackendName(),
		store.BucketName(),
		oid,
	)
}

func upsertRemoteDiscoveryForS3Store(store *s3BlobRemoteStore, row blobRemoteInventoryRow) error {
	objectKey := strings.TrimSpace(row.ObjectKey)
	if objectKey == "" {
		key, err := store.objectKeyForOID(row.OID)
		if err != nil {
			return err
		}
		objectKey = key
	}
	return upsertOverlayBlobDiscovery(defaultS3BlobsOverlayDBPath(), overlayBlobRow{
		Backend:    store.BackendName(),
		Bucket:     store.BucketName(),
		ObjectKey:  objectKey,
		OID:        row.OID,
		Size:       row.Size,
		ETag:       row.ETag,
		CipherHash: row.CipherHash,
		LastSeenNS: row.LastSeenNS,
		Source:     row.ScanID,
	})
}

func recordRemoteDeleteForS3Store(store *s3BlobRemoteStore, oid string) error {
	objectKey, err := store.objectKeyForOID(oid)
	if err != nil {
		return err
	}
	return recordOverlayBlobDeletion(
		defaultS3BlobsDBPath(),
		defaultS3BlobsOverlayDBPath(),
		store.BackendName(),
		store.BucketName(),
		objectKey,
		oid,
	)
}

func scanAndBuildRemoteInventorySnapshot(ctx context.Context, store *s3BlobRemoteStore, dbPath string, generation string) (int64, error) {
	db, err := openRemoteInventoryBaseDB(dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("start inventory snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM remote_blobs`); err != nil {
		return 0, fmt.Errorf("clear remote_blobs before snapshot build: %w", err)
	}

	prefix := remoteBlobObjectsPrefix(store.cfg)
	paginator := s3.NewListObjectsV2Paginator(store.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(store.bootstrap.Bucket),
		Prefix: aws.String(prefix),
	})

	nowNS := time.Now().UTC().UnixNano()
	scannedCount := int64(0)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, fmt.Errorf("list remote blob objects with prefix %q: %w", prefix, err)
		}
		for _, object := range page.Contents {
			objectKey := strings.TrimSpace(aws.ToString(object.Key))
			oid, ok := parseOIDFromBlobObjectKey(objectKey)
			if !ok {
				continue
			}
			etag := strings.Trim(strings.TrimSpace(aws.ToString(object.ETag)), "\"")
			row := blobRemoteInventoryRow{
				Backend:    store.BackendName(),
				Bucket:     store.BucketName(),
				ObjectKey:  objectKey,
				OID:        oid,
				Size:       aws.ToInt64(object.Size),
				ETag:       etag,
				CipherHash: etag,
				LastSeenNS: nowNS,
				ScanID:     generation,
			}
			if err := upsertRemoteBlobRow(tx, row); err != nil {
				return 0, err
			}
			scannedCount++
		}
	}

	if err := upsertInventoryMeta(tx, inventoryMetaGenerationKey, generation, nowNS); err != nil {
		return 0, err
	}
	if err := upsertInventoryMeta(tx, inventoryMetaFormatVersion, strconv.Itoa(remoteInventoryDBFormatVersion), nowNS); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit inventory snapshot transaction: %w", err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return 0, fmt.Errorf("checkpoint inventory snapshot db before upload: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		return 0, fmt.Errorf("switch inventory snapshot db to DELETE journal mode before upload: %w", err)
	}
	return scannedCount, nil
}

func uploadObjectFromFile(ctx context.Context, store *s3BlobRemoteStore, key string, contentType string, path string, ifNoneMatch bool) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open upload file %q: %w", path, err)
	}
	defer file.Close()

	input := &s3.PutObjectInput{
		Bucket:      aws.String(store.bootstrap.Bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(contentType),
	}
	if ifNoneMatch {
		input.IfNoneMatch = aws.String("*")
	}
	resp, err := store.client.PutObject(ctx, input)
	if err != nil {
		return "", fmt.Errorf("upload object s3://%s/%s: %w", store.bootstrap.Bucket, key, err)
	}
	return strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\""), nil
}

func putRemoteGCInfoPointer(ctx context.Context, store *s3BlobRemoteStore, doc remoteGCInfoDocument) (string, error) {
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("encode gc_info document: %w", err)
	}
	key := remoteGCInfoObjectKey(store.cfg)
	input := &s3.PutObjectInput{
		Bucket:      aws.String(store.bootstrap.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(docBytes),
		ContentType: aws.String("application/json"),
	}
	resp, err := store.client.PutObject(ctx, input)
	if err != nil {
		return "", fmt.Errorf("publish gc_info pointer s3://%s/%s: %w", store.bootstrap.Bucket, key, err)
	}
	return strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\""), nil
}

func fileBlake3Hex(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read file for hash %q: %w", path, err)
	}
	sum := blake3.Sum256(raw)
	return fmt.Sprintf("%x", sum[:]), nil
}

func runBlobInventoryPublishCommand(args []string) error {
	fs := flag.NewFlagSet("blob inventory publish", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob inventory publish [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Scan remote blob objects, publish immutable inventory snapshot DB, then publish gc_info pointer.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	defaultGeneration := strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	defaultWorkerID, _ := os.Hostname()
	generation := fs.String("generation", defaultGeneration, "Opaque GC generation ID")
	workerID := fs.String("worker-id", strings.TrimSpace(defaultWorkerID), "GC worker identifier")
	deletedCount := fs.Int64("deleted-count", 0, "Number of remote blobs deleted in this GC cycle")
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
	normalizedGeneration := normalizeS3ObjectKey(*generation)
	if normalizedGeneration == "" {
		return fmt.Errorf("generation must not be empty")
	}

	ctx := context.Background()
	session, err := loadRemoteBackendSession(ctx)
	if err != nil {
		return err
	}
	client, err := session.newS3Client(ctx)
	if err != nil {
		return err
	}
	store := &s3BlobRemoteStore{
		client:    client,
		bootstrap: session.Bootstrap,
		cfg:       session.Config,
	}

	tempDir := os.TempDir()
	if customTmp := strings.TrimSpace(forgeconfig.CacheDir()); customTmp != "" {
		tempDir = customTmp
	}
	localInventoryPath := filepath.Join(tempDir, fmt.Sprintf("forge-inventory-%s.db", normalizedGeneration))
	if err := os.MkdirAll(filepath.Dir(localInventoryPath), 0o755); err != nil {
		return fmt.Errorf("create local inventory snapshot directory: %w", err)
	}

	scannedCount, err := scanAndBuildRemoteInventorySnapshot(ctx, store, localInventoryPath, normalizedGeneration)
	if err != nil {
		return err
	}
	inventoryHash, err := fileBlake3Hex(localInventoryPath)
	if err != nil {
		return err
	}
	inventoryKey, err := remoteInventorySnapshotObjectKey(store.cfg, normalizedGeneration)
	if err != nil {
		return err
	}
	inventoryETag, err := uploadObjectFromFile(
		ctx,
		store,
		inventoryKey,
		"application/vnd.sqlite3",
		localInventoryPath,
		store.cfg.S3.Capabilities.ConditionalIfNoneMatch,
	)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	gcInfo := remoteGCInfoDocument{
		Generation:        normalizedGeneration,
		CompletedAtUTC:    now.Format(time.RFC3339Nano),
		InventoryDBKey:    inventoryKey,
		InventoryDBHash:   inventoryHash,
		InventoryDBFormat: remoteInventoryDBFormatVersion,
		GCWorkerID:        strings.TrimSpace(*workerID),
		DeletedCount:      *deletedCount,
		ScannedCount:      scannedCount,
		PublishedAtUTC:    now.Format(time.RFC3339Nano),
	}
	gcInfoETag, err := putRemoteGCInfoPointer(ctx, store, gcInfo)
	if err != nil {
		return err
	}

	return renderBlobInventoryPublishOutput(resolvedOutputMode, blobInventoryPublishOutput{
		Bucket:               store.BucketName(),
		Generation:           normalizedGeneration,
		InventoryDBKey:       inventoryKey,
		InventoryDBHash:      inventoryHash,
		InventoryDBFormat:    remoteInventoryDBFormatVersion,
		InventoryETag:        inventoryETag,
		GCInfoKey:            remoteGCInfoObjectKey(store.cfg),
		GCInfoETag:           gcInfoETag,
		ScannedCount:         scannedCount,
		DeletedCount:         *deletedCount,
		WorkerID:             strings.TrimSpace(*workerID),
		PublishedAtUTC:       gcInfo.PublishedAtUTC,
		InventoryLocalDBPath: localInventoryPath,
	})
}

func renderBlobInventoryPublishOutput(mode string, output blobInventoryPublishOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("bucket=%s\n", output.Bucket)
		fmt.Printf("generation=%s\n", output.Generation)
		fmt.Printf("inventory_db_key=%s\n", output.InventoryDBKey)
		fmt.Printf("inventory_db_hash=%s\n", output.InventoryDBHash)
		fmt.Printf("inventory_db_format_version=%d\n", output.InventoryDBFormat)
		fmt.Printf("inventory_etag=%s\n", output.InventoryETag)
		fmt.Printf("gc_info_key=%s\n", output.GCInfoKey)
		fmt.Printf("gc_info_etag=%s\n", output.GCInfoETag)
		fmt.Printf("scanned_count=%d\n", output.ScannedCount)
		fmt.Printf("deleted_count=%d\n", output.DeletedCount)
		fmt.Printf("gc_worker_id=%s\n", output.WorkerID)
		fmt.Printf("published_at_utc=%s\n", output.PublishedAtUTC)
		fmt.Printf("inventory_local_db_path=%s\n", output.InventoryLocalDBPath)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob Inventory Publish")
		printPrettyFields([]outputField{
			{Label: "Bucket", Value: output.Bucket},
			{Label: "Generation", Value: output.Generation},
			{Label: "Inventory DB Key", Value: output.InventoryDBKey},
			{Label: "Inventory DB Hash", Value: output.InventoryDBHash},
			{Label: "Inventory DB Format", Value: strconv.Itoa(output.InventoryDBFormat)},
			{Label: "Inventory ETag", Value: output.InventoryETag},
			{Label: "GC Info Key", Value: output.GCInfoKey},
			{Label: "GC Info ETag", Value: output.GCInfoETag},
			{Label: "Scanned Count", Value: strconv.FormatInt(output.ScannedCount, 10)},
			{Label: "Deleted Count", Value: strconv.FormatInt(output.DeletedCount, 10)},
			{Label: "Worker ID", Value: output.WorkerID},
			{Label: "Published At", Value: output.PublishedAtUTC},
			{Label: "Local Snapshot DB", Value: output.InventoryLocalDBPath},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
