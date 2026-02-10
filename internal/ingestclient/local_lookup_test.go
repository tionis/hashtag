package ingestclient

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestFilterPresentWithHydratedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "embeddings.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`
CREATE TABLE image_embeddings (
	hash TEXT PRIMARY KEY,
	vector BLOB NOT NULL
);
CREATE TABLE text_embeddings (
	hash TEXT PRIMARY KEY,
	vector BLOB NOT NULL
);
`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO image_embeddings(hash, vector) VALUES (?, ?)`, "a", []byte("[1]")); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	hashToPath := map[string]string{
		"a": "/tmp/a.bin",
		"b": "/tmp/b.bin",
	}
	present, err := filterPresentWithHydratedDB(context.Background(), dbPath, "image", hashToPath, 100)
	if err != nil {
		t.Fatalf("filterPresentWithHydratedDB: %v", err)
	}
	if present != 1 {
		t.Fatalf("present mismatch: got %d want 1", present)
	}
	if _, ok := hashToPath["a"]; ok {
		t.Fatalf("expected hash a to be removed")
	}
	if _, ok := hashToPath["b"]; !ok {
		t.Fatalf("expected hash b to remain")
	}
}

func TestFilterPresentWithHydratedDB_MissingFile(t *testing.T) {
	hashToPath := map[string]string{"a": "/tmp/a.bin"}
	_, err := filterPresentWithHydratedDB(context.Background(), "/does/not/exist.db", "image", hashToPath, 100)
	if err == nil {
		t.Fatal("expected error for missing db path")
	}
}
