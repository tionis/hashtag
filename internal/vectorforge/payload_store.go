package vectorforge

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeebo/blake3"
	_ "modernc.org/sqlite"
)

const (
	vectorBlobDBEnv           = "FORGE_BLOB_DB"
	vectorBlobCacheEnv        = "FORGE_BLOB_CACHE"
	vectorBlobDBDefaultFile   = "blob.db"
	vectorBlobCacheDefaultDir = "blobs"

	vectorBlobDigestHexSize = 64
	vectorBlobDigestBytes   = 32
	vectorBlobEncAlgorithm  = "xchacha20poly1305"
	vectorBlobEncVersion    = 1
)

type payloadStore interface {
	StoreUploadPayload(ctx context.Context, sourcePath string, cid string, plainSize int64) (string, error)
	ResolvePayloadPath(ctx context.Context, cid string) (string, error)
	Close() error
}

type localBlobPayloadStore struct {
	db       *sql.DB
	cacheDir string
}

type blobMapCacheRow struct {
	CID       string
	OID       string
	PlainSize int64
	CachePath string
}

func defaultVectorBlobDBPath() string {
	if custom := strings.TrimSpace(os.Getenv(vectorBlobDBEnv)); custom != "" {
		return custom
	}
	return filepath.Join(defaultForgeDataDir(), vectorBlobDBDefaultFile)
}

func defaultVectorBlobCacheDir() string {
	if custom := strings.TrimSpace(os.Getenv(vectorBlobCacheEnv)); custom != "" {
		return custom
	}
	return filepath.Join(defaultForgeCacheDir(), vectorBlobCacheDefaultDir)
}

func openLocalBlobPayloadStore(blobDBPath string, cacheDir string) (*localBlobPayloadStore, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create blob cache directory %q: %w", cacheDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(blobDBPath), 0o755); err != nil {
		return nil, fmt.Errorf("create blob db directory %q: %w", filepath.Dir(blobDBPath), err)
	}

	db, err := sql.Open("sqlite", blobDBPath)
	if err != nil {
		return nil, fmt.Errorf("open blob db %q: %w", blobDBPath, err)
	}
	db.SetMaxOpenConns(1)

	if err := initVectorBlobSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &localBlobPayloadStore{
		db:       db,
		cacheDir: cacheDir,
	}, nil
}

func (s *localBlobPayloadStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func initVectorBlobSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		`CREATE TABLE IF NOT EXISTS blob_map (
			cid TEXT PRIMARY KEY,
			oid TEXT NOT NULL UNIQUE,
			plain_size INTEGER NOT NULL,
			cipher_size INTEGER NOT NULL,
			cipher_hash TEXT NOT NULL,
			enc_algo TEXT NOT NULL,
			enc_version INTEGER NOT NULL,
			cache_path TEXT NOT NULL,
			created_at_ns INTEGER NOT NULL,
			updated_at_ns INTEGER NOT NULL
		);`,
		"CREATE INDEX IF NOT EXISTS blob_map_oid_idx ON blob_map(oid);",
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize vector blob schema: %w", err)
		}
	}
	return nil
}

func (s *localBlobPayloadStore) StoreUploadPayload(_ context.Context, sourcePath string, cid string, plainSize int64) (string, error) {
	if s == nil {
		return "", fmt.Errorf("payload store is not initialized")
	}
	normalizedCID, err := normalizeCID(cid)
	if err != nil {
		return "", err
	}
	cachePath := vectorBlobCachePath(s.cacheDir, normalizedCID)
	if err := ensureCacheObjectFromSource(cachePath, sourcePath, normalizedCID); err != nil {
		return "", err
	}

	now := time.Now().UTC().UnixNano()
	row := blobMapCacheRow{
		CID:       normalizedCID,
		OID:       deriveVectorBlobOIDFromCID(normalizedCID),
		PlainSize: plainSize,
		CachePath: cachePath,
	}
	if err := upsertVectorBlobMap(s.db, row, now); err != nil {
		return "", err
	}

	return normalizedCID, nil
}

func (s *localBlobPayloadStore) ResolvePayloadPath(_ context.Context, cid string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("payload store is not initialized")
	}
	normalizedCID, err := normalizeCID(cid)
	if err != nil {
		return "", err
	}

	directPath := vectorBlobCachePath(s.cacheDir, normalizedCID)
	if stat, err := os.Stat(directPath); err == nil && stat.Mode().IsRegular() {
		return directPath, nil
	}

	row, found, err := lookupVectorBlobMapByCID(s.db, normalizedCID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("payload %q not found in blob_map", normalizedCID)
	}
	if stat, err := os.Stat(row.CachePath); err == nil && stat.Mode().IsRegular() {
		return row.CachePath, nil
	}

	return "", fmt.Errorf("payload %q cache object is missing", normalizedCID)
}

func ensureCacheObjectFromSource(cachePath string, sourcePath string, expectedCID string) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("create blob cache directory %q: %w", filepath.Dir(cachePath), err)
	}

	if stat, err := os.Stat(cachePath); err == nil && stat.Mode().IsRegular() {
		match, verifyErr := verifyCIDForFile(cachePath, expectedCID)
		if verifyErr != nil {
			return verifyErr
		}
		if match {
			return nil
		}
		return fmt.Errorf("existing cache object %q has mismatched cid", cachePath)
	}

	src, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open source payload %q: %w", sourcePath, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(cachePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			match, verifyErr := verifyCIDForFile(cachePath, expectedCID)
			if verifyErr != nil {
				return verifyErr
			}
			if match {
				return nil
			}
			return fmt.Errorf("concurrently created cache object %q has mismatched cid", cachePath)
		}
		return fmt.Errorf("create cache object %q: %w", cachePath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		_ = os.Remove(cachePath)
		return fmt.Errorf("copy payload into cache %q: %w", cachePath, err)
	}
	if err := dst.Sync(); err != nil {
		_ = os.Remove(cachePath)
		return fmt.Errorf("sync cache object %q: %w", cachePath, err)
	}

	return nil
}

func verifyCIDForFile(path string, expectedCID string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open cache object %q: %w", path, err)
	}
	defer f.Close()

	h := blake3.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("hash cache object %q: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	return strings.EqualFold(got, expectedCID), nil
}

func upsertVectorBlobMap(db *sql.DB, row blobMapCacheRow, updatedAtNS int64) error {
	if updatedAtNS <= 0 {
		updatedAtNS = time.Now().UTC().UnixNano()
	}
	createdAtNS := updatedAtNS

	_, err := db.Exec(
		`INSERT INTO blob_map(
			cid,
			oid,
			plain_size,
			cipher_size,
			cipher_hash,
			enc_algo,
			enc_version,
			cache_path,
			created_at_ns,
			updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cid) DO UPDATE SET
			oid = excluded.oid,
			plain_size = excluded.plain_size,
			cipher_size = excluded.cipher_size,
			cipher_hash = excluded.cipher_hash,
			enc_algo = excluded.enc_algo,
			enc_version = excluded.enc_version,
			cache_path = excluded.cache_path,
			updated_at_ns = excluded.updated_at_ns`,
		row.CID,
		row.OID,
		row.PlainSize,
		0,
		"",
		vectorBlobEncAlgorithm,
		vectorBlobEncVersion,
		row.CachePath,
		createdAtNS,
		updatedAtNS,
	)
	if err != nil {
		return fmt.Errorf("upsert blob_map row for cid %q: %w", row.CID, err)
	}
	return nil
}

func lookupVectorBlobMapByCID(db *sql.DB, cid string) (blobMapCacheRow, bool, error) {
	row := blobMapCacheRow{}
	if err := db.QueryRow(
		`SELECT cid, oid, plain_size, cache_path
		 FROM blob_map
		 WHERE cid = ?`,
		cid,
	).Scan(&row.CID, &row.OID, &row.PlainSize, &row.CachePath); err != nil {
		if err == sql.ErrNoRows {
			return blobMapCacheRow{}, false, nil
		}
		return blobMapCacheRow{}, false, fmt.Errorf("lookup blob_map row for cid %q: %w", cid, err)
	}
	return row, true, nil
}

func vectorBlobCachePath(cacheRoot string, cid string) string {
	return filepath.Join(cacheRoot, cid[:2], cid[2:4], cid+".blob")
}

func normalizeCID(cid string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(cid))
	if len(normalized) != vectorBlobDigestHexSize {
		return "", fmt.Errorf("payload cid must be %d hex characters", vectorBlobDigestHexSize)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("invalid payload cid %q: %w", cid, err)
	}
	return normalized, nil
}

func deriveVectorBlobOIDFromCID(cidHex string) string {
	cidBytes, err := hex.DecodeString(cidHex)
	if err != nil || len(cidBytes) != vectorBlobDigestBytes {
		return cidHex
	}
	var cid [vectorBlobDigestBytes]byte
	copy(cid[:], cidBytes)
	return hex.EncodeToString(deriveVectorBlobMaterial(cid, "oid", vectorBlobDigestBytes))
}

func deriveVectorBlobMaterial(cid [vectorBlobDigestBytes]byte, label string, outLen int) []byte {
	if outLen <= 0 {
		return nil
	}
	out := make([]byte, 0, outLen)
	counter := uint32(0)
	for len(out) < outLen {
		h := blake3.New()
		h.Write([]byte("forge.blob.v1:"))
		h.Write([]byte(label))
		counterBuf := []byte{
			byte(counter >> 24),
			byte(counter >> 16),
			byte(counter >> 8),
			byte(counter),
		}
		h.Write(counterBuf)
		h.Write(cid[:])
		sum := h.Sum(nil)
		needed := outLen - len(out)
		if needed >= len(sum) {
			out = append(out, sum...)
		} else {
			out = append(out, sum[:needed]...)
		}
		counter++
	}
	return out
}
