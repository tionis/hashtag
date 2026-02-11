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

func TestApplyRemoteGCInfoToLocalInventoryGenerationBumpResetsOverlay(t *testing.T) {
	temp := t.TempDir()
	basePath := filepath.Join(temp, "s3-blobs.db")
	overlayPath := filepath.Join(temp, "s3-blobs-overlay.db")

	seedBasePath := filepath.Join(temp, "seed-base.db")
	seedBaseDB, err := openRemoteInventoryBaseDB(seedBasePath)
	if err != nil {
		t.Fatalf("openRemoteInventoryBaseDB(seed): %v", err)
	}
	if _, err := seedBaseDB.Exec(
		`INSERT INTO remote_blobs(backend, bucket, object_key, oid, size, etag, cipher_hash, last_seen_ns, scan_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s3",
		"bucket-a",
		"forge/blobs/11/22/1111111111111111111111111111111111111111111111111111111111111111.fblob",
		"1111111111111111111111111111111111111111111111111111111111111111",
		11,
		"etag-1",
		"etag-1",
		time.Now().UTC().UnixNano(),
		"scan-1",
	); err != nil {
		_ = seedBaseDB.Close()
		t.Fatalf("seed generation-1 inventory db: %v", err)
	}
	if _, err := seedBaseDB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = seedBaseDB.Close()
		t.Fatalf("checkpoint generation-1 db: %v", err)
	}
	if _, err := seedBaseDB.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		_ = seedBaseDB.Close()
		t.Fatalf("set generation-1 db journal mode: %v", err)
	}
	_ = seedBaseDB.Close()

	generation1Payload, err := os.ReadFile(seedBasePath)
	if err != nil {
		t.Fatalf("read generation-1 payload: %v", err)
	}
	gcInfo1 := remoteGCInfoDocument{
		Generation:        "gen-1",
		InventoryDBKey:    "forge/gc/inventory/gen-1/inventory.db",
		InventoryDBHash:   blake3Hex(generation1Payload),
		InventoryDBFormat: remoteInventoryDBFormatVersion,
	}
	if err := applyRemoteGCInfoToLocalInventory(basePath, overlayPath, gcInfo1, generation1Payload, time.Now().UTC()); err != nil {
		t.Fatalf("apply generation-1 gc info: %v", err)
	}

	if err := upsertOverlayBlobDiscovery(overlayPath, overlayBlobRow{
		Backend:    "s3",
		Bucket:     "bucket-a",
		ObjectKey:  "forge/blobs/33/44/3333333333333333333333333333333333333333333333333333333333333333.fblob",
		OID:        "3333333333333333333333333333333333333333333333333333333333333333",
		Size:       33,
		ETag:       "etag-3",
		CipherHash: "etag-3",
		LastSeenNS: time.Now().UTC().UnixNano(),
		Source:     "test-overlay",
	}); err != nil {
		t.Fatalf("seed overlay discovery before generation bump: %v", err)
	}

	overlayDB, err := openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		t.Fatalf("openRemoteInventoryOverlayDB(before bump): %v", err)
	}
	if got := mustCount(t, overlayDB, "SELECT COUNT(*) FROM overlay_blobs"); got != 1 {
		_ = overlayDB.Close()
		t.Fatalf("expected 1 overlay blob before generation bump, got %d", got)
	}
	_ = overlayDB.Close()

	seedBasePath2 := filepath.Join(temp, "seed-base-2.db")
	seedBaseDB2, err := openRemoteInventoryBaseDB(seedBasePath2)
	if err != nil {
		t.Fatalf("openRemoteInventoryBaseDB(seed2): %v", err)
	}
	if _, err := seedBaseDB2.Exec(
		`INSERT INTO remote_blobs(backend, bucket, object_key, oid, size, etag, cipher_hash, last_seen_ns, scan_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"s3",
		"bucket-a",
		"forge/blobs/55/66/5555555555555555555555555555555555555555555555555555555555555555.fblob",
		"5555555555555555555555555555555555555555555555555555555555555555",
		55,
		"etag-5",
		"etag-5",
		time.Now().UTC().UnixNano(),
		"scan-5",
	); err != nil {
		_ = seedBaseDB2.Close()
		t.Fatalf("seed generation-2 inventory db: %v", err)
	}
	if _, err := seedBaseDB2.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = seedBaseDB2.Close()
		t.Fatalf("checkpoint generation-2 db: %v", err)
	}
	if _, err := seedBaseDB2.Exec(`PRAGMA journal_mode=DELETE`); err != nil {
		_ = seedBaseDB2.Close()
		t.Fatalf("set generation-2 db journal mode: %v", err)
	}
	_ = seedBaseDB2.Close()
	generation2Payload, err := os.ReadFile(seedBasePath2)
	if err != nil {
		t.Fatalf("read generation-2 payload: %v", err)
	}
	gcInfo2 := remoteGCInfoDocument{
		Generation:        "gen-2",
		InventoryDBKey:    "forge/gc/inventory/gen-2/inventory.db",
		InventoryDBHash:   blake3Hex(generation2Payload),
		InventoryDBFormat: remoteInventoryDBFormatVersion,
	}
	if err := applyRemoteGCInfoToLocalInventory(basePath, overlayPath, gcInfo2, generation2Payload, time.Now().UTC()); err != nil {
		t.Fatalf("apply generation-2 gc info: %v", err)
	}

	overlayDB, err = openRemoteInventoryOverlayDB(overlayPath)
	if err != nil {
		t.Fatalf("openRemoteInventoryOverlayDB(after bump): %v", err)
	}
	defer overlayDB.Close()
	if got := mustCount(t, overlayDB, "SELECT COUNT(*) FROM overlay_blobs"); got != 0 {
		t.Fatalf("expected overlay_blobs to be cleared on generation bump, got %d", got)
	}
	if got := mustCount(t, overlayDB, "SELECT COUNT(*) FROM overlay_tombstones"); got != 0 {
		t.Fatalf("expected overlay_tombstones to be cleared on generation bump, got %d", got)
	}
	var overlayGeneration string
	if err := overlayDB.QueryRow(`SELECT meta_value FROM overlay_meta WHERE meta_key = ?`, overlayMetaLastGenerationKey).Scan(&overlayGeneration); err != nil {
		t.Fatalf("query overlay generation meta after bump: %v", err)
	}
	if overlayGeneration != "gen-2" {
		t.Fatalf("expected overlay generation meta gen-2 after bump, got %q", overlayGeneration)
	}
}
