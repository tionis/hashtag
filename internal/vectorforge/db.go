package vectorforge

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

func openSQLite(path string, maxOpenConns int) (*sql.DB, error) {
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite %s: %w", path, err)
	}

	if err := applySQLitePragmas(ctx, db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func applySQLitePragmas(ctx context.Context, db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, q := range pragmas {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("exec pragma %q: %w", q, err)
		}
	}
	return nil
}

func initializeSchemas(ctx context.Context, queueDB, embedDB *sql.DB) error {
	queueSchema := `
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    file_path TEXT NOT NULL,
    worker_id TEXT,
    last_error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    attempts INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_hash_kind ON jobs(file_hash, kind);
CREATE INDEX IF NOT EXISTS idx_jobs_status_updated ON jobs(status, updated_at);
`
	embedSchema := `
CREATE TABLE IF NOT EXISTS image_embeddings (
    hash TEXT NOT NULL,
    vector BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (hash)
);
CREATE TABLE IF NOT EXISTS text_embeddings (
    hash TEXT NOT NULL,
    vector BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (hash)
);
`

	if _, err := queueDB.ExecContext(ctx, queueSchema); err != nil {
		return fmt.Errorf("initialize queue schema: %w", err)
	}
	if _, err := embedDB.ExecContext(ctx, embedSchema); err != nil {
		return fmt.Errorf("initialize embeddings schema: %w", err)
	}
	return nil
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return nil
}
