package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	resolvedCachePath, err := blobObjectPath(cacheDir, oid)
	if err != nil {
		t.Fatalf("resolve cache path for oid: %v", err)
	}
	if resolvedCachePath != cachePath {
		t.Fatalf("expected resolved cache path %q, got %q", cachePath, resolvedCachePath)
	}
}

func TestBlobPutGetWithHTTPServer(t *testing.T) {
	temp := t.TempDir()
	serverRoot := filepath.Join(temp, "server-root")
	serverDBPath := filepath.Join(temp, "server.db")
	serverDB, err := openBlobDB(serverDBPath)
	if err != nil {
		t.Fatalf("open server blob db: %v", err)
	}
	defer serverDB.Close()

	srv := httptest.NewServer(newBlobHTTPHandler(serverRoot, serverDB, "test-http", "bucket-a"))
	defer srv.Close()

	inputPath := filepath.Join(temp, "input.txt")
	inputData := []byte("server-roundtrip-via-cli")
	if err := os.WriteFile(inputPath, inputData, 0o644); err != nil {
		t.Fatalf("write input file: %v", err)
	}

	clientDBPath := filepath.Join(temp, "client.db")
	cacheDir := filepath.Join(temp, "cache")
	if err := runBlobPutCommand([]string{
		"-db", clientDBPath,
		"-cache", cacheDir,
		"-server", srv.URL,
		"-backend", "test-http",
		"-bucket", "bucket-a",
		"-output", "kv",
		inputPath,
	}); err != nil {
		t.Fatalf("run blob put command with server: %v", err)
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

	headResp, err := http.Head(strings.TrimRight(srv.URL, "/") + "/v1/blobs/" + oid)
	if err != nil {
		t.Fatalf("HEAD blob object: %v", err)
	}
	headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HEAD status %d, got %d", http.StatusOK, headResp.StatusCode)
	}

	cacheObjectPath, err := blobObjectPath(cacheDir, oid)
	if err != nil {
		t.Fatalf("resolve cache object path: %v", err)
	}
	if err := os.Remove(cacheObjectPath); err != nil {
		t.Fatalf("remove cached object to force server fetch: %v", err)
	}

	outPath := filepath.Join(temp, "output.txt")
	if err := runBlobGetCommand([]string{
		"-db", clientDBPath,
		"-cache", cacheDir,
		"-server", srv.URL,
		"-backend", "test-http",
		"-bucket", "bucket-a",
		"-cid", cid,
		"-out", outPath,
		"-output", "kv",
	}); err != nil {
		t.Fatalf("run blob get command with server fallback: %v", err)
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
