package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type hashmapIngestStats struct {
	scanned          int
	mappedFiles      int
	mappingsUpserted int
	skippedUncached  int
	skippedStale     int
	skippedNoBlake3  int
	errors           int
}

type hashmapMapping struct {
	Blake3 string
	Algo   string
	Digest string
}

func runHashmapIngestCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("hashmap ingest", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s hashmap ingest [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Scan files and ingest checksum xattr mappings into hash_mappings.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	verbose := fs.Bool("v", false, "Verbose output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	rootPath := fs.Arg(0)
	if rootPath == "" {
		rootPath = "."
	}

	absRootPath, err := filepath.Abs(rootPath)
	if err != nil {
		return fmt.Errorf("resolve root path: %w", err)
	}
	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start hashmap ingest transaction: %w", err)
	}
	defer tx.Rollback()

	stats := &hashmapIngestStats{}
	walkErr := filepath.WalkDir(absRootPath, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			stats.errors++
			if *verbose {
				log.Printf("[hashmap] walk error at %s: %v", path, walkErr)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		stats.scanned++
		if err := ingestHashMappingsFromFile(tx, path, *verbose, stats); err != nil {
			stats.errors++
			if *verbose {
				log.Printf("[hashmap] ingest error at %s: %v", path, err)
			}
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk root path %q: %w", absRootPath, walkErr)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit hashmap ingest transaction: %w", err)
	}

	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("root=%s\n", absRootPath)
	fmt.Printf("scanned=%d\n", stats.scanned)
	fmt.Printf("mapped_files=%d\n", stats.mappedFiles)
	fmt.Printf("mappings_upserted=%d\n", stats.mappingsUpserted)
	fmt.Printf("skipped_uncached=%d\n", stats.skippedUncached)
	fmt.Printf("skipped_stale=%d\n", stats.skippedStale)
	fmt.Printf("skipped_no_blake3=%d\n", stats.skippedNoBlake3)
	fmt.Printf("errors=%d\n", stats.errors)
	return nil
}

func ingestHashMappingsFromFile(tx *sql.Tx, path string, verbose bool, stats *hashmapIngestStats) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file %q: %w", path, err)
	}
	currentMtime := info.ModTime().Unix()

	cachedMtimeBytes, err := getXattr(path, XattrMtimeKey)
	if err != nil {
		stats.skippedUncached++
		return nil
	}

	cachedMtime, err := strconv.ParseInt(string(cachedMtimeBytes), 10, 64)
	if err != nil {
		stats.skippedUncached++
		return nil
	}
	if cachedMtime != currentMtime {
		stats.skippedStale++
		return nil
	}

	keys, err := listXattrs(path)
	if err != nil {
		return fmt.Errorf("list xattrs for %q: %w", path, err)
	}

	hashes := make(map[string]string)
	for _, key := range keys {
		if !strings.HasPrefix(key, XattrPrefix) || key == XattrMtimeKey {
			continue
		}

		algo := strings.TrimPrefix(key, XattrPrefix)
		if algo == "" {
			continue
		}

		value, err := getXattr(path, key)
		if err != nil {
			if verbose {
				log.Printf("[hashmap] skip unreadable xattr %s on %s: %v", key, path, err)
			}
			continue
		}

		digest := strings.TrimSpace(string(value))
		if digest == "" {
			continue
		}
		hashes[algo] = digest
	}

	if len(hashes) == 0 {
		stats.skippedUncached++
		return nil
	}

	blake3Digest := hashes[snapshotHashAlgo]
	if blake3Digest == "" {
		stats.skippedNoBlake3++
		return nil
	}

	mapped := 0
	for algo, digest := range hashes {
		if algo == snapshotHashAlgo {
			continue
		}
		if err := upsertHashMapping(tx, blake3Digest, algo, digest); err != nil {
			return err
		}
		mapped++
	}

	if mapped > 0 {
		stats.mappedFiles++
		stats.mappingsUpserted += mapped
	}

	return nil
}

func upsertHashMapping(tx *sql.Tx, blake3Digest, algo, digest string) error {
	if _, err := tx.Exec(
		`INSERT INTO hash_mappings(blake3, algo, digest)
		 VALUES(?, ?, ?)
		 ON CONFLICT(blake3, algo) DO UPDATE SET digest = excluded.digest`,
		blake3Digest,
		algo,
		digest,
	); err != nil {
		return fmt.Errorf("upsert hash mapping (%s,%s)->%s: %w", blake3Digest, algo, digest, err)
	}
	return nil
}

func runHashmapLookupCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("hashmap lookup", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s hashmap lookup [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Lookup blake3 digests by (algorithm, digest).")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	algo := fs.String("algo", "", "Hash algorithm to search (required)")
	digest := fs.String("digest", "", "Digest to search (required)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	if strings.TrimSpace(*algo) == "" {
		return fmt.Errorf("algo is required")
	}
	if strings.TrimSpace(*digest) == "" {
		return fmt.Errorf("digest is required")
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	blake3Digests, err := lookupBlake3DigestsByAlgoDigest(db, strings.TrimSpace(*algo), strings.TrimSpace(*digest))
	if err != nil {
		return err
	}

	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("algo=%s\n", strings.TrimSpace(*algo))
	fmt.Printf("digest=%s\n", strings.TrimSpace(*digest))
	fmt.Printf("count=%d\n", len(blake3Digests))
	fmt.Println("blake3")
	for _, blake3Digest := range blake3Digests {
		fmt.Println(blake3Digest)
	}
	return nil
}

func lookupBlake3DigestsByAlgoDigest(db *sql.DB, algo, digest string) ([]string, error) {
	rows, err := db.Query(
		`SELECT blake3
		 FROM hash_mappings
		 WHERE algo = ? AND digest = ?
		 ORDER BY blake3 ASC`,
		algo,
		digest,
	)
	if err != nil {
		return nil, fmt.Errorf("query hash mappings for algo=%q digest=%q: %w", algo, digest, err)
	}
	defer rows.Close()

	results := make([]string, 0)
	for rows.Next() {
		var blake3Digest string
		if err := rows.Scan(&blake3Digest); err != nil {
			return nil, fmt.Errorf("scan hash mapping row: %w", err)
		}
		results = append(results, blake3Digest)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate hash mapping rows: %w", err)
	}

	return results, nil
}

func runHashmapShowCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("hashmap show", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s hashmap show [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show all mapped digests for a blake3 digest.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	blake3Digest := fs.String("blake3", "", "BLAKE3 digest to inspect (required)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if strings.TrimSpace(*blake3Digest) == "" {
		return fmt.Errorf("blake3 is required")
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	mappings, err := lookupMappingsByBlake3(db, strings.TrimSpace(*blake3Digest))
	if err != nil {
		return err
	}

	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("blake3=%s\n", strings.TrimSpace(*blake3Digest))
	fmt.Printf("count=%d\n", len(mappings))
	fmt.Println("algo\tdigest")
	for _, mapping := range mappings {
		fmt.Printf("%s\t%s\n", mapping.Algo, mapping.Digest)
	}
	return nil
}

func lookupMappingsByBlake3(db *sql.DB, blake3Digest string) ([]hashmapMapping, error) {
	rows, err := db.Query(
		`SELECT algo, digest
		 FROM hash_mappings
		 WHERE blake3 = ?
		 ORDER BY algo ASC`,
		blake3Digest,
	)
	if err != nil {
		return nil, fmt.Errorf("query mappings for blake3=%q: %w", blake3Digest, err)
	}
	defer rows.Close()

	results := make([]hashmapMapping, 0)
	for rows.Next() {
		var algo string
		var digest string
		if err := rows.Scan(&algo, &digest); err != nil {
			return nil, fmt.Errorf("scan mapping row: %w", err)
		}
		results = append(results, hashmapMapping{
			Blake3: blake3Digest,
			Algo:   algo,
			Digest: digest,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mapping rows: %w", err)
	}

	return results, nil
}
