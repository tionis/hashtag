package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
	_ "modernc.org/sqlite"
)

const (
	blobRefSourceLocalKeep = "blob.local.keep"
	blobRefSourceSnapshot  = "snapshot.tree_entries"
	blobRefSourceVector    = "vector.queue"
)

func defaultRefsDBPath() string {
	return forgeconfig.RefsDBPath()
}

func openBlobRefsDB(path string) (*sql.DB, error) {
	absPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("resolve refs db path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("create refs db directory: %w", err)
	}
	db, err := sql.Open("sqlite", absPath)
	if err != nil {
		return nil, fmt.Errorf("open refs db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := initBlobRefsSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func initBlobRefsSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		`CREATE TABLE IF NOT EXISTS blob_refs (
			source TEXT NOT NULL,
			ref_key TEXT NOT NULL,
			cid TEXT NOT NULL,
			created_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL,
			PRIMARY KEY(source, ref_key)
		);`,
		"CREATE INDEX IF NOT EXISTS blob_refs_cid_idx ON blob_refs(cid);",
		"CREATE INDEX IF NOT EXISTS blob_refs_source_idx ON blob_refs(source);",
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize refs db schema: %w", err)
		}
	}
	return nil
}

func upsertBlobLocalKeepRef(dbPath string, cid string) error {
	db, err := openBlobRefsDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start refs upsert transaction: %w", err)
	}
	defer tx.Rollback()

	if err := upsertBlobRef(tx, blobRefSourceLocalKeep, cid, cid, time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refs upsert transaction: %w", err)
	}
	return nil
}

func deleteBlobLocalKeepRef(dbPath string, cid string) error {
	db, err := openBlobRefsDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start refs delete transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := deleteBlobRefBySourceAndRefKey(tx, blobRefSourceLocalKeep, cid); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refs delete transaction: %w", err)
	}
	return nil
}

func deleteBlobLocalKeepRefs(dbPath string, cids []string) error {
	if len(cids) == 0 {
		return nil
	}
	db, err := openBlobRefsDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start refs delete-many transaction: %w", err)
	}
	defer tx.Rollback()

	seen := make(map[string]struct{}, len(cids))
	for _, raw := range cids {
		cid, err := normalizeBlobCIDForRef(raw)
		if err != nil {
			continue
		}
		if _, exists := seen[cid]; exists {
			continue
		}
		seen[cid] = struct{}{}
		if _, err := deleteBlobRefBySourceAndRefKey(tx, blobRefSourceLocalKeep, cid); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refs delete-many transaction: %w", err)
	}
	return nil
}

func syncBlobGCReferenceSources(dbPath string, syncSnapshot bool, snapshotCIDs map[string]struct{}, syncVector bool, vectorCIDs map[string]struct{}) error {
	db, err := openBlobRefsDB(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start refs sync transaction: %w", err)
	}
	defer tx.Rollback()

	if syncSnapshot {
		if err := replaceBlobRefsForSource(tx, blobRefSourceSnapshot, snapshotCIDs); err != nil {
			return err
		}
	}
	if syncVector {
		if err := replaceBlobRefsForSource(tx, blobRefSourceVector, vectorCIDs); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit refs sync transaction: %w", err)
	}
	return nil
}

func replaceBlobRefsForSource(tx *sql.Tx, source string, cids map[string]struct{}) error {
	normalizedSource := strings.TrimSpace(source)
	if normalizedSource == "" {
		return fmt.Errorf("replace refs source must not be empty")
	}
	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE source = ?`, normalizedSource); err != nil {
		return fmt.Errorf("clear refs for source %q: %w", normalizedSource, err)
	}
	if len(cids) == 0 {
		return nil
	}
	now := time.Now().UTC().UnixNano()
	sorted := make([]string, 0, len(cids))
	for cid := range cids {
		sorted = append(sorted, cid)
	}
	sort.Strings(sorted)
	for _, cid := range sorted {
		if err := upsertBlobRef(tx, normalizedSource, cid, cid, now); err != nil {
			return err
		}
	}
	return nil
}

func upsertBlobRef(tx *sql.Tx, source string, refKey string, cid string, updatedAt int64) error {
	if tx == nil {
		return fmt.Errorf("refs upsert transaction is required")
	}
	normalizedSource := strings.TrimSpace(source)
	if normalizedSource == "" {
		return fmt.Errorf("refs source must not be empty")
	}
	normalizedRefKey := strings.TrimSpace(refKey)
	if normalizedRefKey == "" {
		return fmt.Errorf("refs ref_key must not be empty")
	}
	normalizedCID, err := normalizeBlobCIDForRef(cid)
	if err != nil {
		return fmt.Errorf("normalize refs cid: %w", err)
	}

	now := updatedAt
	if now <= 0 {
		now = time.Now().UTC().UnixNano()
	}
	if _, err := tx.Exec(
		`INSERT INTO blob_refs(source, ref_key, cid, created_at_ns, updated_at_ns)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(source, ref_key) DO UPDATE SET
			cid = excluded.cid,
			updated_at_ns = excluded.updated_at_ns`,
		normalizedSource,
		normalizedRefKey,
		normalizedCID,
		now,
		now,
	); err != nil {
		return fmt.Errorf("upsert refs row source=%q ref_key=%q cid=%q: %w", normalizedSource, normalizedRefKey, normalizedCID, err)
	}
	return nil
}

func deleteBlobRefBySourceAndRefKey(tx *sql.Tx, source string, refKey string) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("refs delete transaction is required")
	}
	normalizedSource := strings.TrimSpace(source)
	if normalizedSource == "" {
		return 0, fmt.Errorf("refs delete source must not be empty")
	}
	normalizedRefKey := strings.TrimSpace(refKey)
	if normalizedRefKey == "" {
		return 0, fmt.Errorf("refs delete ref_key must not be empty")
	}
	res, err := tx.Exec(`DELETE FROM blob_refs WHERE source = ? AND ref_key = ?`, normalizedSource, normalizedRefKey)
	if err != nil {
		return 0, fmt.Errorf("delete refs row source=%q ref_key=%q: %w", normalizedSource, normalizedRefKey, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read refs delete row count: %w", err)
	}
	return rows, nil
}

func normalizeBlobCIDForRef(value string) (string, error) {
	normalized := normalizeDigestHex(strings.TrimSpace(value))
	if _, err := parseDigestHex32(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}
