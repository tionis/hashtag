package main

import (
	"database/sql"
	"fmt"
	flag "github.com/spf13/pflag"
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
	Blake3 string `json:"blake3,omitempty"`
	Algo   string `json:"algo"`
	Digest string `json:"digest"`
}

type hashmapIngestStatsOutput struct {
	Scanned          int `json:"scanned"`
	MappedFiles      int `json:"mapped_files"`
	MappingsUpserted int `json:"mappings_upserted"`
	SkippedUncached  int `json:"skipped_uncached"`
	SkippedStale     int `json:"skipped_stale"`
	SkippedNoBlake3  int `json:"skipped_no_blake3"`
	Errors           int `json:"errors"`
}

type hashmapIngestOutput struct {
	DB    string                   `json:"db"`
	Root  string                   `json:"root"`
	Stats hashmapIngestStatsOutput `json:"stats"`
}

type hashmapLookupOutput struct {
	DB      string   `json:"db"`
	Algo    string   `json:"algo"`
	Digest  string   `json:"digest"`
	Count   int      `json:"count"`
	Blake3s []string `json:"blake3"`
}

type hashmapShowOutput struct {
	DB       string           `json:"db"`
	Blake3   string           `json:"blake3"`
	Count    int              `json:"count"`
	Mappings []hashmapMapping `json:"mappings"`
}

func renderHashmapIngestOutput(mode string, output hashmapIngestOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("root=%s\n", output.Root)
		fmt.Printf("scanned=%d\n", output.Stats.Scanned)
		fmt.Printf("mapped_files=%d\n", output.Stats.MappedFiles)
		fmt.Printf("mappings_upserted=%d\n", output.Stats.MappingsUpserted)
		fmt.Printf("skipped_uncached=%d\n", output.Stats.SkippedUncached)
		fmt.Printf("skipped_stale=%d\n", output.Stats.SkippedStale)
		fmt.Printf("skipped_no_blake3=%d\n", output.Stats.SkippedNoBlake3)
		fmt.Printf("errors=%d\n", output.Stats.Errors)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Hashmap Ingest")
		printPrettyFields([]outputField{
			{Label: "Database", Value: output.DB},
			{Label: "Root", Value: output.Root},
		})

		printPrettySection("Ingest Stats")
		printPrettyFields([]outputField{
			{Label: "Scanned", Value: strconv.Itoa(output.Stats.Scanned)},
			{Label: "Mapped Files", Value: strconv.Itoa(output.Stats.MappedFiles)},
			{Label: "Mappings Upserted", Value: strconv.Itoa(output.Stats.MappingsUpserted)},
			{Label: "Skipped Uncached", Value: strconv.Itoa(output.Stats.SkippedUncached)},
			{Label: "Skipped Stale", Value: strconv.Itoa(output.Stats.SkippedStale)},
			{Label: "Skipped No BLAKE3", Value: strconv.Itoa(output.Stats.SkippedNoBlake3)},
			{Label: "Errors", Value: strconv.Itoa(output.Stats.Errors)},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderHashmapLookupOutput(mode string, output hashmapLookupOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("algo=%s\n", output.Algo)
		fmt.Printf("digest=%s\n", output.Digest)
		fmt.Printf("count=%d\n", output.Count)
		fmt.Println("blake3")
		for _, digest := range output.Blake3s {
			fmt.Println(digest)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Hashmap Lookup")
		printPrettyFields([]outputField{
			{Label: "Database", Value: output.DB},
			{Label: "Algorithm", Value: output.Algo},
			{Label: "Digest", Value: output.Digest},
			{Label: "Matches", Value: strconv.Itoa(output.Count)},
		})
		printPrettySection("BLAKE3 Digests")
		if len(output.Blake3s) == 0 {
			fmt.Println("No matches found.")
			return nil
		}
		rows := make([][]string, 0, len(output.Blake3s))
		for _, digest := range output.Blake3s {
			rows = append(rows, []string{digest})
		}
		printPrettyTable([]string{"BLAKE3"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderHashmapShowOutput(mode string, output hashmapShowOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("db=%s\n", output.DB)
		fmt.Printf("blake3=%s\n", output.Blake3)
		fmt.Printf("count=%d\n", output.Count)
		fmt.Println("algo\tdigest")
		for _, mapping := range output.Mappings {
			fmt.Printf("%s\t%s\n", mapping.Algo, mapping.Digest)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Hashmap Show")
		printPrettyFields([]outputField{
			{Label: "Database", Value: output.DB},
			{Label: "BLAKE3", Value: output.Blake3},
			{Label: "Mappings", Value: strconv.Itoa(output.Count)},
		})
		printPrettySection("Known Digests")
		if len(output.Mappings) == 0 {
			fmt.Println("No mappings found.")
			return nil
		}
		rows := make([][]string, 0, len(output.Mappings))
		for _, mapping := range output.Mappings {
			rows = append(rows, []string{mapping.Algo, mapping.Digest})
		}
		printPrettyTable([]string{"Algorithm", "Digest"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
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

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	verbose := fs.BoolP("verbose", "v", false, "Verbose output")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
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

	return renderHashmapIngestOutput(
		resolvedOutputMode,
		hashmapIngestOutput{
			DB:   absDBPath,
			Root: absRootPath,
			Stats: hashmapIngestStatsOutput{
				Scanned:          stats.scanned,
				MappedFiles:      stats.mappedFiles,
				MappingsUpserted: stats.mappingsUpserted,
				SkippedUncached:  stats.skippedUncached,
				SkippedStale:     stats.skippedStale,
				SkippedNoBlake3:  stats.skippedNoBlake3,
				Errors:           stats.errors,
			},
		},
	)
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

type hashMappingExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func upsertHashMapping(execer hashMappingExecer, blake3Digest, algo, digest string) error {
	if _, err := execer.Exec(
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

func loadHashMappingsForBlake3s(db *sql.DB, blake3Digests []string, algos []string) (map[string]map[string]string, error) {
	results := make(map[string]map[string]string, len(blake3Digests))
	if len(blake3Digests) == 0 || len(algos) == 0 {
		return results, nil
	}

	for _, chunk := range chunkStrings(blake3Digests, 500) {
		query := fmt.Sprintf(
			`SELECT blake3, algo, digest
			 FROM hash_mappings
			 WHERE algo IN (%s) AND blake3 IN (%s)
			 ORDER BY blake3 ASC, algo ASC`,
			sqlPlaceholders(len(algos)),
			sqlPlaceholders(len(chunk)),
		)
		args := make([]any, 0, len(algos)+len(chunk))
		args = append(args, anySlice(algos)...)
		args = append(args, anySlice(chunk)...)

		rows, err := db.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("query hash mappings for %d blake3 digest(s): %w", len(chunk), err)
		}
		for rows.Next() {
			var blake3Digest string
			var algo string
			var digest string
			if err := rows.Scan(&blake3Digest, &algo, &digest); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan hash mapping row: %w", err)
			}
			if _, ok := results[blake3Digest]; !ok {
				results[blake3Digest] = make(map[string]string)
			}
			results[blake3Digest][algo] = digest
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("iterate hash mapping rows: %w", err)
		}
		_ = rows.Close()
	}

	return results, nil
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

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	algo := fs.StringP("algo", "a", "", "Hash algorithm to search (required)")
	digest := fs.StringP("digest", "g", "", "Digest to search (required)")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
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

	return renderHashmapLookupOutput(
		resolvedOutputMode,
		hashmapLookupOutput{
			DB:      absDBPath,
			Algo:    strings.TrimSpace(*algo),
			Digest:  strings.TrimSpace(*digest),
			Count:   len(blake3Digests),
			Blake3s: blake3Digests,
		},
	)
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

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	blake3Digest := fs.StringP("blake3", "b", "", "BLAKE3 digest to inspect (required)")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
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

	return renderHashmapShowOutput(
		resolvedOutputMode,
		hashmapShowOutput{
			DB:       absDBPath,
			Blake3:   strings.TrimSpace(*blake3Digest),
			Count:    len(mappings),
			Mappings: mappings,
		},
	)
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
