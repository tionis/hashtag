package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/tionis/forge/internal/forgeconfig"
)

type fakeBlobRemoteStore struct {
	backend string
	bucket  string
	objects map[string][]byte
}

func newFakeBlobRemoteStore(backend string, bucket string) *fakeBlobRemoteStore {
	return &fakeBlobRemoteStore{
		backend: backend,
		bucket:  bucket,
		objects: make(map[string][]byte),
	}
}

func (s *fakeBlobRemoteStore) BackendName() string {
	return s.backend
}

func (s *fakeBlobRemoteStore) BucketName() string {
	return s.bucket
}

func (s *fakeBlobRemoteStore) PutBlob(_ context.Context, oid string, encoded []byte) (string, error) {
	s.objects[oid] = append([]byte(nil), encoded...)
	return blake3Hex(encoded), nil
}

func (s *fakeBlobRemoteStore) GetBlob(_ context.Context, oid string) ([]byte, string, bool, error) {
	payload, ok := s.objects[oid]
	if !ok {
		return nil, "", false, nil
	}
	return append([]byte(nil), payload...), blake3Hex(payload), true, nil
}

func (s *fakeBlobRemoteStore) DeleteBlob(_ context.Context, oid string) (bool, error) {
	_, ok := s.objects[oid]
	if ok {
		delete(s.objects, oid)
		return true, nil
	}
	return false, nil
}

func withFakeBlobRemoteStore(t *testing.T, store blobRemoteStore) {
	t.Helper()
	original := openBlobRemoteStoreFunc
	openBlobRemoteStoreFunc = func(ctx context.Context) (blobRemoteStore, error) {
		return store, nil
	}
	t.Cleanup(func() {
		openBlobRemoteStoreFunc = original
	})
}

func withTempRefsDBPath(t *testing.T, tempDir string) {
	t.Helper()
	t.Setenv(forgeconfig.EnvRefsDBPath, filepath.Join(tempDir, "refs.db"))
}

func TestBlobEncryptDecryptDeterministic(t *testing.T) {
	plain := []byte("forge-blob-deterministic-roundtrip")

	pkg1, err := encryptBlobData(plain)
	if err != nil {
		t.Fatalf("encrypt blob data (first): %v", err)
	}
	pkg2, err := encryptBlobData(plain)
	if err != nil {
		t.Fatalf("encrypt blob data (second): %v", err)
	}

	if pkg1.CID != pkg2.CID {
		t.Fatalf("expected identical CIDs, got %q and %q", pkg1.CID, pkg2.CID)
	}
	if pkg1.OID != pkg2.OID {
		t.Fatalf("expected identical OIDs, got %q and %q", pkg1.OID, pkg2.OID)
	}
	if pkg1.CipherHash != pkg2.CipherHash {
		t.Fatalf("expected identical cipher hashes, got %q and %q", pkg1.CipherHash, pkg2.CipherHash)
	}
	if string(pkg1.Encoded) != string(pkg2.Encoded) {
		t.Fatal("expected deterministic ciphertext payload to be identical")
	}

	decodedPkg, decodedPlain, err := decodeAndDecryptBlobData(pkg1.Encoded)
	if err != nil {
		t.Fatalf("decode/decrypt blob data: %v", err)
	}
	if decodedPkg.CID != pkg1.CID {
		t.Fatalf("expected decoded CID %q, got %q", pkg1.CID, decodedPkg.CID)
	}
	if decodedPkg.OID != pkg1.OID {
		t.Fatalf("expected decoded OID %q, got %q", pkg1.OID, decodedPkg.OID)
	}
	if string(decodedPlain) != string(plain) {
		t.Fatalf("expected plaintext %q, got %q", plain, decodedPlain)
	}
}

func TestBlobPutGetAndListCommandsLocal(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	inputPath := filepath.Join(temp, "input.txt")
	inputData := []byte("local-cache-roundtrip")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")

	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", inputPath}); err != nil {
		t.Fatalf("run blob put command: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	defer db.Close()

	if got := mustCount(t, db, "SELECT COUNT(*) FROM blob_map"); got != 1 {
		t.Fatalf("expected 1 blob mapping, got %d", got)
	}

	var cid string
	var oid string
	var cachePath string
	if err := db.QueryRow(`SELECT cid, oid, cache_path FROM blob_map LIMIT 1`).Scan(&cid, &oid, &cachePath); err != nil {
		t.Fatalf("query blob map row: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache object at %q: %v", cachePath, err)
	}

	outPath := filepath.Join(temp, "output.txt")
	if err := runBlobGetCommand([]string{"-db", dbPath, "-cache", cacheDir, "-cid", cid, "-out", outPath, "-output", "kv"}); err != nil {
		t.Fatalf("run blob get command: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(outData) != string(inputData) {
		t.Fatalf("expected output plaintext %q, got %q", inputData, outData)
	}

	if err := runBlobListCommand([]string{"-db", dbPath, "-limit", "10", "-output", "json"}); err != nil {
		t.Fatalf("run blob ls command: %v", err)
	}

	resolvedCachePath, err := blobPlainCachePath(cacheDir, cid)
	if err != nil {
		t.Fatalf("resolve cache path for cid: %v", err)
	}
	if resolvedCachePath != cachePath {
		t.Fatalf("expected resolved cache path %q, got %q", cachePath, resolvedCachePath)
	}

	if _, err := parseDigestHex32(oid); err != nil {
		t.Fatalf("expected oid to be a valid digest: %v", err)
	}
}

func TestEnsurePlainBlobCacheObjectFallbackFromUnsupportedClone(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	cachePath := filepath.Join(temp, "cache", "a.blob")
	sourcePath := filepath.Join(temp, "source.txt")
	plain := []byte("fallback-from-unsupported-clone")
	if err := os.WriteFile(sourcePath, plain, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	original := cloneFileCoWFunc
	cloneFileCoWFunc = func(dstPath string, srcPath string) error {
		return errReflinkUnsupported
	}
	defer func() {
		cloneFileCoWFunc = original
	}()

	cid := blake3Hex(plain)
	if err := ensurePlainBlobCacheObject(cachePath, sourcePath, plain, cid, false); err != nil {
		t.Fatalf("ensure plain blob cache object with fallback: %v", err)
	}

	got, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache path: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("expected cache content %q, got %q", plain, got)
	}
}

func TestBlobPutGetWithRemoteStore(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	remoteStore := newFakeBlobRemoteStore("s3", "bucket-a")
	withFakeBlobRemoteStore(t, remoteStore)

	inputPath := filepath.Join(temp, "input.txt")
	inputData := []byte("remote-roundtrip-via-cli")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	clientDBPath := filepath.Join(temp, "client.db")
	cacheDir := filepath.Join(temp, "cache")
	if err := runBlobPutCommand([]string{
		"-db", clientDBPath,
		"-cache", cacheDir,
		"-remote",
		"-output", "kv",
		inputPath,
	}); err != nil {
		t.Fatalf("run blob put command with remote: %v", err)
	}

	clientDB, err := sql.Open("sqlite", clientDBPath)
	if err != nil {
		t.Fatalf("open client sqlite db: %v", err)
	}
	defer clientDB.Close()

	if got := mustCount(t, clientDB, "SELECT COUNT(*) FROM blob_map"); got != 1 {
		t.Fatalf("expected 1 blob mapping in client db, got %d", got)
	}
	if got := mustCount(t, clientDB, "SELECT COUNT(*) FROM remote_blob_inventory"); got != 1 {
		t.Fatalf("expected 1 remote inventory row in client db, got %d", got)
	}

	var cid string
	var oid string
	if err := clientDB.QueryRow(`SELECT cid, oid FROM blob_map LIMIT 1`).Scan(&cid, &oid); err != nil {
		t.Fatalf("query client blob map: %v", err)
	}

	if _, exists := remoteStore.objects[oid]; !exists {
		t.Fatalf("expected remote object %s to be present", oid)
	}

	cacheObjectPath, err := blobPlainCachePath(cacheDir, cid)
	if err != nil {
		t.Fatalf("resolve cache object path by cid: %v", err)
	}
	if err := os.Remove(cacheObjectPath); err != nil {
		t.Fatalf("remove cached object to force remote fetch: %v", err)
	}

	outPath := filepath.Join(temp, "output.txt")
	if err := runBlobGetCommand([]string{
		"-db", clientDBPath,
		"-cache", cacheDir,
		"-remote",
		"-cid", cid,
		"-out", outPath,
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob get command with remote fallback: %v", err)
	}

	outData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(outData) != string(inputData) {
		t.Fatalf("expected output plaintext %q, got %q", inputData, outData)
	}

	if _, err := os.Stat(cacheObjectPath); err != nil {
		t.Fatalf("expected fetched blob to be re-cached at %q: %v", cacheObjectPath, err)
	}
}

func TestBlobRemoveCommandLocalByOID(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	inputPath := filepath.Join(temp, "input.txt")
	inputData := []byte("remove-local-by-oid")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", inputPath}); err != nil {
		t.Fatalf("run blob put command: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	defer db.Close()

	var cid string
	var oid string
	if err := db.QueryRow(`SELECT cid, oid FROM blob_map LIMIT 1`).Scan(&cid, &oid); err != nil {
		t.Fatalf("query blob mapping: %v", err)
	}

	cachePath, err := blobPlainCachePath(cacheDir, cid)
	if err != nil {
		t.Fatalf("resolve cache path: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache file before delete: %v", err)
	}

	if err := runBlobRemoveCommand([]string{
		"-db", dbPath,
		"-cache", cacheDir,
		"-oid", oid,
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob rm command local-only: %v", err)
	}

	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("expected cache file to be removed, got err=%v", err)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM blob_map"); got != 0 {
		t.Fatalf("expected 0 blob map rows after local delete, got %d", got)
	}
}

func TestBlobRemoveCommandLocalAndRemote(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	remoteStore := newFakeBlobRemoteStore("s3", "bucket-a")
	withFakeBlobRemoteStore(t, remoteStore)

	inputPath := filepath.Join(temp, "input.txt")
	inputData := []byte("remove-local-and-remote")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	clientDBPath := filepath.Join(temp, "client.db")
	cacheDir := filepath.Join(temp, "cache")
	if err := runBlobPutCommand([]string{
		"-db", clientDBPath,
		"-cache", cacheDir,
		"-remote",
		"-output", "kv",
		inputPath,
	}); err != nil {
		t.Fatalf("run blob put command with remote: %v", err)
	}

	clientDB, err := sql.Open("sqlite", clientDBPath)
	if err != nil {
		t.Fatalf("open client sqlite db: %v", err)
	}
	defer clientDB.Close()

	var cid string
	var oid string
	if err := clientDB.QueryRow(`SELECT cid, oid FROM blob_map LIMIT 1`).Scan(&cid, &oid); err != nil {
		t.Fatalf("query blob map row: %v", err)
	}

	cachePath, err := blobPlainCachePath(cacheDir, cid)
	if err != nil {
		t.Fatalf("resolve plaintext cache path: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected plaintext cache file before delete: %v", err)
	}

	if err := runBlobRemoveCommand([]string{
		"-db", clientDBPath,
		"-cache", cacheDir,
		"-cid", cid,
		"-remote",
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob rm command local+remote: %v", err)
	}

	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatalf("expected local cache file removed, got err=%v", err)
	}
	if got := mustCount(t, clientDB, "SELECT COUNT(*) FROM blob_map"); got != 0 {
		t.Fatalf("expected client blob map to be empty after delete, got %d", got)
	}
	if got := mustCount(t, clientDB, "SELECT COUNT(*) FROM remote_blob_inventory"); got != 0 {
		t.Fatalf("expected client remote inventory to be empty after delete, got %d", got)
	}
	if _, exists := remoteStore.objects[oid]; exists {
		t.Fatalf("expected remote object %s to be deleted", oid)
	}
}

func TestBlobGCApplyKeepsSnapshotReferencedCID(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	snapshotDBPath := filepath.Join(temp, "snapshot.db")
	vectorQueueDBPath := filepath.Join(temp, "queue.db")

	keepPath := filepath.Join(temp, "keep.bin")
	dropPath := filepath.Join(temp, "drop.bin")
	keepData := []byte("blob-gc-keep")
	dropData := []byte("blob-gc-drop")
	if err := os.WriteFile(keepPath, keepData, 0o644); err != nil {
		t.Fatalf("write keep input: %v", err)
	}
	if err := os.WriteFile(dropPath, dropData, 0o644); err != nil {
		t.Fatalf("write drop input: %v", err)
	}

	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", keepPath}); err != nil {
		t.Fatalf("put keep blob: %v", err)
	}
	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", dropPath}); err != nil {
		t.Fatalf("put drop blob: %v", err)
	}

	keepCID := blake3Hex(keepData)
	dropCID := blake3Hex(dropData)

	snapshotDB, err := sql.Open("sqlite", snapshotDBPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	if _, err := snapshotDB.Exec(`
CREATE TABLE tree_entries(
	target_hash TEXT NOT NULL,
	kind TEXT NOT NULL
);
INSERT INTO tree_entries(target_hash, kind) VALUES (?, 'file');
`, keepCID); err != nil {
		_ = snapshotDB.Close()
		t.Fatalf("seed snapshot refs: %v", err)
	}
	_ = snapshotDB.Close()

	if err := runBlobGCCommand([]string{
		"-db", dbPath,
		"-cache", cacheDir,
		"-snapshot-db", snapshotDBPath,
		"-vector-queue-db", vectorQueueDBPath,
		"-apply",
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob gc apply: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open blob db: %v", err)
	}
	defer db.Close()

	if got := mustCount(t, db, "SELECT COUNT(*) FROM blob_map"); got != 1 {
		t.Fatalf("expected 1 blob_map row after gc, got %d", got)
	}
	var remainingCID string
	if err := db.QueryRow(`SELECT cid FROM blob_map LIMIT 1`).Scan(&remainingCID); err != nil {
		t.Fatalf("query remaining cid: %v", err)
	}
	if remainingCID != keepCID {
		t.Fatalf("expected remaining cid %q, got %q", keepCID, remainingCID)
	}

	keepCachePath, err := blobPlainCachePath(cacheDir, keepCID)
	if err != nil {
		t.Fatalf("resolve keep cache path: %v", err)
	}
	if _, err := os.Stat(keepCachePath); err != nil {
		t.Fatalf("expected keep cache file to remain: %v", err)
	}

	dropCachePath, err := blobPlainCachePath(cacheDir, dropCID)
	if err != nil {
		t.Fatalf("resolve drop cache path: %v", err)
	}
	if _, err := os.Stat(dropCachePath); !os.IsNotExist(err) {
		t.Fatalf("expected drop cache file removed, got err=%v", err)
	}
}

func TestBlobGCDryRunDoesNotDelete(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	snapshotDBPath := filepath.Join(temp, "snapshot.db")
	vectorQueueDBPath := filepath.Join(temp, "queue.db")

	inputPath := filepath.Join(temp, "input.bin")
	inputData := []byte("blob-gc-dry-run")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", inputPath}); err != nil {
		t.Fatalf("put blob: %v", err)
	}

	cid := blake3Hex(inputData)
	cachePath, err := blobPlainCachePath(cacheDir, cid)
	if err != nil {
		t.Fatalf("resolve cache path: %v", err)
	}

	if err := runBlobGCCommand([]string{
		"-db", dbPath,
		"-cache", cacheDir,
		"-snapshot-db", snapshotDBPath,
		"-vector-queue-db", vectorQueueDBPath,
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob gc dry-run: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open blob db: %v", err)
	}
	defer db.Close()
	if got := mustCount(t, db, "SELECT COUNT(*) FROM blob_map"); got != 1 {
		t.Fatalf("expected 1 blob_map row after dry-run, got %d", got)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache file to remain after dry-run: %v", err)
	}
}

func TestBlobGCApplyKeepsVectorQueueReferencedCID(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)
	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	snapshotDBPath := filepath.Join(temp, "snapshot.db")
	vectorQueueDBPath := filepath.Join(temp, "queue.db")

	inputPath := filepath.Join(temp, "input.bin")
	inputData := []byte("blob-gc-vector-queue-ref")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", inputPath}); err != nil {
		t.Fatalf("put blob: %v", err)
	}
	cid := blake3Hex(inputData)

	queueDB, err := sql.Open("sqlite", vectorQueueDBPath)
	if err != nil {
		t.Fatalf("open vector queue db: %v", err)
	}
	if _, err := queueDB.Exec(`
CREATE TABLE jobs(
	file_path TEXT NOT NULL,
	status TEXT NOT NULL
);
INSERT INTO jobs(file_path, status) VALUES (?, 'pending');
`, cid); err != nil {
		_ = queueDB.Close()
		t.Fatalf("seed vector queue refs: %v", err)
	}
	_ = queueDB.Close()

	if err := runBlobGCCommand([]string{
		"-db", dbPath,
		"-cache", cacheDir,
		"-snapshot-db", snapshotDBPath,
		"-vector-queue-db", vectorQueueDBPath,
		"-apply",
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob gc apply: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open blob db: %v", err)
	}
	defer db.Close()
	if got := mustCount(t, db, "SELECT COUNT(*) FROM blob_map"); got != 1 {
		t.Fatalf("expected 1 blob_map row after queue-referenced gc, got %d", got)
	}
	cachePath, err := blobPlainCachePath(cacheDir, cid)
	if err != nil {
		t.Fatalf("resolve cache path: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache file for queue-referenced cid to remain: %v", err)
	}
}

func TestBlobPutAndGetUpsertLocalKeepRefs(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)

	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	refsDBPath := filepath.Join(temp, "refs.db")
	inputPath := filepath.Join(temp, "input.bin")
	inputData := []byte("blob-refs-put-get")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", inputPath}); err != nil {
		t.Fatalf("put blob: %v", err)
	}
	cid := blake3Hex(inputData)

	refsDB, err := sql.Open("sqlite", refsDBPath)
	if err != nil {
		t.Fatalf("open refs db: %v", err)
	}
	defer refsDB.Close()

	if got := mustCount(t, refsDB, "SELECT COUNT(*) FROM blob_refs WHERE source = ? AND ref_key = ? AND cid = ?", blobRefSourceLocalKeep, cid, cid); got != 1 {
		t.Fatalf("expected 1 local keep ref after put, got %d", got)
	}

	outPath := filepath.Join(temp, "output.bin")
	if err := runBlobGetCommand([]string{"-db", dbPath, "-cache", cacheDir, "-cid", cid, "-out", outPath, "-output", "kv"}); err != nil {
		t.Fatalf("get blob: %v", err)
	}

	if got := mustCount(t, refsDB, "SELECT COUNT(*) FROM blob_refs WHERE source = ? AND ref_key = ? AND cid = ?", blobRefSourceLocalKeep, cid, cid); got != 1 {
		t.Fatalf("expected local keep ref upsert to remain idempotent, got %d rows", got)
	}
}

func TestBlobRemoveClearsLocalKeepRefs(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)

	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	refsDBPath := filepath.Join(temp, "refs.db")
	inputPath := filepath.Join(temp, "input.bin")
	inputData := []byte("blob-refs-remove")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", inputPath}); err != nil {
		t.Fatalf("put blob: %v", err)
	}
	cid := blake3Hex(inputData)

	if err := runBlobRemoveCommand([]string{"-db", dbPath, "-cache", cacheDir, "-cid", cid, "-output", "kv"}); err != nil {
		t.Fatalf("remove blob: %v", err)
	}

	refsDB, err := sql.Open("sqlite", refsDBPath)
	if err != nil {
		t.Fatalf("open refs db: %v", err)
	}
	defer refsDB.Close()

	if got := mustCount(t, refsDB, "SELECT COUNT(*) FROM blob_refs WHERE source = ? AND ref_key = ?", blobRefSourceLocalKeep, cid); got != 0 {
		t.Fatalf("expected local keep ref to be removed, got %d", got)
	}
}

func TestBlobGCSyncsSnapshotVectorRefsAndPrunesStaleLocalKeepRefs(t *testing.T) {
	temp := t.TempDir()
	withTempRefsDBPath(t, temp)

	dbPath := filepath.Join(temp, "blob.db")
	cacheDir := filepath.Join(temp, "cache")
	refsDBPath := filepath.Join(temp, "refs.db")
	snapshotDBPath := filepath.Join(temp, "snapshot.db")
	vectorQueueDBPath := filepath.Join(temp, "queue.db")

	keepPath := filepath.Join(temp, "keep.bin")
	dropPath := filepath.Join(temp, "drop.bin")
	keepData := []byte("blob-refs-gc-keep")
	dropData := []byte("blob-refs-gc-drop")
	if err := os.WriteFile(keepPath, keepData, 0o644); err != nil {
		t.Fatalf("write keep input: %v", err)
	}
	if err := os.WriteFile(dropPath, dropData, 0o644); err != nil {
		t.Fatalf("write drop input: %v", err)
	}
	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", keepPath}); err != nil {
		t.Fatalf("put keep blob: %v", err)
	}
	if err := runBlobPutCommand([]string{"-db", dbPath, "-cache", cacheDir, "-output", "kv", dropPath}); err != nil {
		t.Fatalf("put drop blob: %v", err)
	}
	keepCID := blake3Hex(keepData)
	dropCID := blake3Hex(dropData)

	snapshotDB, err := sql.Open("sqlite", snapshotDBPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	if _, err := snapshotDB.Exec(`
CREATE TABLE tree_entries(
	target_hash TEXT NOT NULL,
	kind TEXT NOT NULL
);
INSERT INTO tree_entries(target_hash, kind) VALUES (?, 'file');
`, keepCID); err != nil {
		_ = snapshotDB.Close()
		t.Fatalf("seed snapshot refs: %v", err)
	}
	_ = snapshotDB.Close()

	queueDB, err := sql.Open("sqlite", vectorQueueDBPath)
	if err != nil {
		t.Fatalf("open queue db: %v", err)
	}
	if _, err := queueDB.Exec(`
CREATE TABLE jobs(
	file_path TEXT NOT NULL,
	status TEXT NOT NULL
);
INSERT INTO jobs(file_path, status) VALUES (?, 'pending');
`, keepCID); err != nil {
		_ = queueDB.Close()
		t.Fatalf("seed vector queue refs: %v", err)
	}
	_ = queueDB.Close()

	if err := runBlobGCCommand([]string{
		"-db", dbPath,
		"-cache", cacheDir,
		"-snapshot-db", snapshotDBPath,
		"-vector-queue-db", vectorQueueDBPath,
		"-apply",
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob gc apply: %v", err)
	}

	refsDB, err := sql.Open("sqlite", refsDBPath)
	if err != nil {
		t.Fatalf("open refs db: %v", err)
	}
	defer refsDB.Close()

	if got := mustCount(t, refsDB, "SELECT COUNT(*) FROM blob_refs WHERE source = ? AND ref_key = ? AND cid = ?", blobRefSourceSnapshot, keepCID, keepCID); got != 1 {
		t.Fatalf("expected snapshot source ref for keep cid, got %d", got)
	}
	if got := mustCount(t, refsDB, "SELECT COUNT(*) FROM blob_refs WHERE source = ? AND ref_key = ? AND cid = ?", blobRefSourceVector, keepCID, keepCID); got != 1 {
		t.Fatalf("expected vector source ref for keep cid, got %d", got)
	}
	if got := mustCount(t, refsDB, "SELECT COUNT(*) FROM blob_refs WHERE source = ? AND ref_key = ?", blobRefSourceLocalKeep, dropCID); got != 0 {
		t.Fatalf("expected stale local keep ref for dropped cid to be removed, got %d", got)
	}
}
