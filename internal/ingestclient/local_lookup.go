package ingestclient

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func filterPresentWithHydratedDB(ctx context.Context, dbPath, kind string, hashToPath map[string]string, chunkSize int) (int, error) {
	if len(hashToPath) == 0 {
		return 0, nil
	}

	table, err := localEmbeddingTableForKind(kind)
	if err != nil {
		return 0, err
	}
	if _, err := os.Stat(dbPath); err != nil {
		return 0, err
	}
	if chunkSize <= 0 {
		chunkSize = 500
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, fmt.Errorf("open hydrated db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	hashes := make([]string, 0, len(hashToPath))
	for hash := range hashToPath {
		hashes = append(hashes, hash)
	}

	present := 0
	for i := 0; i < len(hashes); i += chunkSize {
		end := i + chunkSize
		if end > len(hashes) {
			end = len(hashes)
		}
		chunk := hashes[i:end]

		query := fmt.Sprintf(`SELECT hash FROM %s WHERE hash IN (%s);`, table, placeholders(len(chunk)))
		args := make([]any, 0, len(chunk))
		for _, h := range chunk {
			args = append(args, h)
		}

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return present, fmt.Errorf("query hydrated db: %w", err)
		}

		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				_ = rows.Close()
				return present, fmt.Errorf("scan hydrated hash: %w", err)
			}
			if _, ok := hashToPath[hash]; ok {
				delete(hashToPath, hash)
				present++
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return present, fmt.Errorf("iterate hydrated hashes: %w", err)
		}
		_ = rows.Close()
	}

	return present, nil
}

func localEmbeddingTableForKind(kind string) (string, error) {
	switch kind {
	case "image":
		return "image_embeddings", nil
	case "text":
		return "text_embeddings", nil
	default:
		return "", fmt.Errorf("unsupported embedding kind %q", kind)
	}
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, (n*2)-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '?')
	}
	return string(out)
}
