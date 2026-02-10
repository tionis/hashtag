package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
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
