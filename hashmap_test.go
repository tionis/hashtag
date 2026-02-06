package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHashmapLookupAndShowCommands(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := openSnapshotDB(dbPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}

	blake3Digest := strings.Repeat("b", 64)
	sha256Digest := strings.Repeat("c", 64)
	md5Digest := strings.Repeat("d", 32)

	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatalf("begin tx: %v", err)
	}
	if err := upsertHashMapping(tx, blake3Digest, "sha256", sha256Digest); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatalf("upsert sha256 mapping: %v", err)
	}
	if err := upsertHashMapping(tx, blake3Digest, "md5", md5Digest); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatalf("upsert md5 mapping: %v", err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatalf("commit tx: %v", err)
	}

	byDigest, err := lookupBlake3DigestsByAlgoDigest(db, "sha256", sha256Digest)
	if err != nil {
		db.Close()
		t.Fatalf("lookupBlake3DigestsByAlgoDigest: %v", err)
	}
	if len(byDigest) != 1 || byDigest[0] != blake3Digest {
		db.Close()
		t.Fatalf("unexpected lookup by digest result: %v", byDigest)
	}

	mappings, err := lookupMappingsByBlake3(db, blake3Digest)
	if err != nil {
		db.Close()
		t.Fatalf("lookupMappingsByBlake3: %v", err)
	}
	if len(mappings) != 2 {
		db.Close()
		t.Fatalf("expected 2 mappings, got %d", len(mappings))
	}
	if mappings[0].Algo != "md5" || mappings[0].Digest != md5Digest {
		db.Close()
		t.Fatalf("unexpected first mapping: %+v", mappings[0])
	}
	if mappings[1].Algo != "sha256" || mappings[1].Digest != sha256Digest {
		db.Close()
		t.Fatalf("unexpected second mapping: %+v", mappings[1])
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	if err := runHashmapLookupCommand([]string{"-db", dbPath, "-algo", "sha256", "-digest", sha256Digest}); err != nil {
		t.Fatalf("run hashmap lookup command: %v", err)
	}
	if err := runHashmapShowCommand([]string{"-db", dbPath, "-blake3", blake3Digest}); err != nil {
		t.Fatalf("run hashmap show command: %v", err)
	}
}
