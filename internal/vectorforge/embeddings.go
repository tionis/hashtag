package vectorforge

import (
	"context"
	"database/sql"
	"fmt"
)

func embeddingExists(ctx context.Context, db *sql.DB, hash, kind string) (bool, error) {
	table, err := embeddingTableForKind(kind)
	if err != nil {
		return false, err
	}

	var one int
	err = db.QueryRowContext(ctx, fmt.Sprintf(`SELECT 1 FROM %s WHERE hash = ? LIMIT 1;`, table), hash).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query embedding existence: %w", err)
	}
	return true, nil
}

func findPresentHashes(ctx context.Context, db *sql.DB, kind string, hashes []string) (map[string]struct{}, error) {
	if len(hashes) == 0 {
		return map[string]struct{}{}, nil
	}

	table, err := embeddingTableForKind(kind)
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf(
		`SELECT hash FROM %s WHERE hash IN (%s);`,
		table,
		placeholders(len(hashes)),
	)

	args := make([]any, 0, len(hashes))
	for _, hash := range hashes {
		args = append(args, hash)
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query present hashes: %w", err)
	}
	defer rows.Close()

	out := make(map[string]struct{}, len(hashes))
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan present hash: %w", err)
		}
		out[hash] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate present hashes: %w", err)
	}
	return out, nil
}

func embeddingTableForKind(kind string) (string, error) {
	switch kind {
	case embeddingKindImage:
		return "image_embeddings", nil
	case embeddingKindText:
		return "text_embeddings", nil
	default:
		return "", fmt.Errorf("unsupported embedding kind %q", kind)
	}
}
