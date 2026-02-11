package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoteInventoryObjectKeys(t *testing.T) {
	cfg := defaultRemoteGlobalConfig()
	cfg.S3.ObjectPrefix = "forge-data"

	if got := remoteGCInfoObjectKey(cfg); got != "forge-data/gc/gc_info.json" {
		t.Fatalf("unexpected gc_info key: %q", got)
	}
	gotInventoryKey, err := remoteInventorySnapshotObjectKey(cfg, "gen-123")
	if err != nil {
		t.Fatalf("remoteInventorySnapshotObjectKey: %v", err)
	}
	if gotInventoryKey != "forge-data/gc/inventory/gen-123/inventory.db" {
		t.Fatalf("unexpected inventory snapshot key: %q", gotInventoryKey)
	}
}

func TestRemoteOIDExistsInUnionCache(t *testing.T) {
	temp := t.TempDir()
	basePath := filepath.Join(temp, "s3-blobs.db")
	overlayPath := filepath.Join(temp, "s3-blobs-overlay.db")

	baseDB, err := openRemoteInventoryBaseDB(basePath)
	if err != nil {
		t.Fatalf("openRemoteInventoryBaseDB: %v", err)
	}
	if _, err := baseDB.Exec(
		`INSERT INTO remote_blobs(backend, bucket, object_key, oid, size, etag, cipher_hash, last_seen_ns, scan_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s3",
		"bucket-a",
		"forge/blobs/aa/bb/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fblob",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		123,
		"etag-a",
		"etag-a",
		time.Now().UTC().UnixNano(),
		"scan-a",
	); err != nil {
		_ = baseDB.Close()
		t.Fatalf("seed base remote_blobs: %v", err)
	}
	_ = baseDB.Close()

	exists, err := remoteOIDExistsInUnionCache(
		basePath,
		overlayPath,
		"s3",
		"bucket-a",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil {
		t.Fatalf("remoteOIDExistsInUnionCache(base hit): %v", err)
	}
	if !exists {
		t.Fatal("expected base inventory union hit for oid aaaa...")
	}

	if err := upsertOverlayBlobDiscovery(overlayPath, overlayBlobRow{
		Backend:    "s3",
		Bucket:     "bucket-a",
		ObjectKey:  "forge/blobs/cc/dd/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.fblob",
		OID:        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Size:       456,
		ETag:       "etag-c",
		CipherHash: "etag-c",
		LastSeenNS: time.Now().UTC().UnixNano(),
		Source:     "test",
	}); err != nil {
		t.Fatalf("upsertOverlayBlobDiscovery: %v", err)
	}
	exists, err = remoteOIDExistsInUnionCache(
		basePath,
		overlayPath,
		"s3",
		"bucket-a",
		"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	)
	if err != nil {
		t.Fatalf("remoteOIDExistsInUnionCache(overlay hit): %v", err)
	}
	if !exists {
		t.Fatal("expected overlay inventory union hit for oid cccc...")
	}

	if err := recordOverlayBlobDeletion(
		basePath,
		overlayPath,
		"s3",
		"bucket-a",
		"forge/blobs/aa/bb/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fblob",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	); err != nil {
		t.Fatalf("recordOverlayBlobDeletion: %v", err)
	}
	// Re-insert into base to confirm overlay tombstones take precedence.
	baseDB, err = openRemoteInventoryBaseDB(basePath)
	if err != nil {
		t.Fatalf("openRemoteInventoryBaseDB(reopen): %v", err)
	}
	if _, err := baseDB.Exec(
		`INSERT INTO remote_blobs(backend, bucket, object_key, oid, size, etag, cipher_hash, last_seen_ns, scan_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s3",
		"bucket-a",
		"forge/blobs/aa/bb/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.fblob",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		123,
		"etag-a",
		"etag-a",
		time.Now().UTC().UnixNano(),
		"scan-a2",
	); err != nil {
		_ = baseDB.Close()
		t.Fatalf("re-seed base remote_blobs: %v", err)
	}
	_ = baseDB.Close()

	exists, err = remoteOIDExistsInUnionCache(
		basePath,
		overlayPath,
		"s3",
		"bucket-a",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil {
		t.Fatalf("remoteOIDExistsInUnionCache(tombstone precedence): %v", err)
	}
	if exists {
		t.Fatal("expected tombstone to suppress base entry in union cache")
	}
}

func TestReplaceLocalInventoryBaseDBSetsGenerationMeta(t *testing.T) {
	temp := t.TempDir()
	sourcePath := filepath.Join(temp, "source.db")
	targetPath := filepath.Join(temp, "target.db")

	sourceDB, err := openRemoteInventoryBaseDB(sourcePath)
	if err != nil {
		t.Fatalf("openRemoteInventoryBaseDB(source): %v", err)
	}
	if _, err := sourceDB.Exec(
		`INSERT INTO remote_blobs(backend, bucket, object_key, oid, size, etag, cipher_hash, last_seen_ns, scan_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s3",
		"bucket-a",
		"forge/blobs/ee/ff/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.fblob",
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		42,
		"etag-e",
		"etag-e",
		time.Now().UTC().UnixNano(),
		"scan-e",
	); err != nil {
		_ = sourceDB.Close()
		t.Fatalf("seed source db: %v", err)
	}
	if _, err := sourceDB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = sourceDB.Close()
		t.Fatalf("checkpoint source db: %v", err)
	}
	if _, err := sourceDB.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		_ = sourceDB.Close()
		t.Fatalf("switch source db journal mode: %v", err)
	}
	_ = sourceDB.Close()

	payload, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read source db bytes: %v", err)
	}

	gcInfo := remoteGCInfoDocument{
		Generation:        "gen-xyz",
		InventoryDBKey:    "forge/gc/inventory/gen-xyz/inventory.db",
		InventoryDBHash:   "abc123",
		InventoryDBFormat: remoteInventoryDBFormatVersion,
		CompletedAtUTC:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := replaceLocalInventoryBaseDB(targetPath, payload, gcInfo, time.Now().UTC()); err != nil {
		t.Fatalf("replaceLocalInventoryBaseDB: %v", err)
	}

	targetDB, err := openRemoteInventoryBaseDB(targetPath)
	if err != nil {
		t.Fatalf("openRemoteInventoryBaseDB(target): %v", err)
	}
	defer targetDB.Close()

	var metaGeneration string
	if err := targetDB.QueryRow(`SELECT meta_value FROM inventory_meta WHERE meta_key = ?`, inventoryMetaGenerationKey).Scan(&metaGeneration); err != nil {
		t.Fatalf("query inventory generation meta: %v", err)
	}
	if metaGeneration != "gen-xyz" {
		t.Fatalf("expected generation meta gen-xyz, got %q", metaGeneration)
	}

	var rowCount int
	if err := targetDB.QueryRow(`SELECT COUNT(*) FROM remote_blobs`).Scan(&rowCount); err != nil {
		t.Fatalf("count target remote_blobs: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("expected copied remote_blobs row count=1, got %d", rowCount)
	}
}
