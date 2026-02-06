package main

import (
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zeebo/blake3"
	_ "modernc.org/sqlite"
)

const (
	snapshotKindTree    = "tree"
	snapshotKindFile    = "file"
	snapshotKindSymlink = "symlink"

	snapshotHashAlgo      = "blake3"
	snapshotDBEnv         = "FORGE_SNAPSHOT_DB"
	snapshotDBDirName     = "forge"
	snapshotDBDefaultFile = "snapshot.db"

	snapshotXDGTagsKey = "user.xdg.tags"
)

type snapshotStats struct {
	trees    int
	files    int
	symlinks int
	special  int
}

type snapshotOptions struct {
	verbose      bool
	skipAbsPaths map[string]struct{}
}

type treeEntry struct {
	Name        string
	Kind        string
	TargetHash  string
	Mode        uint32
	ModTimeUnix int64
	Size        int64
	LinkTarget  string
	Tags        []string
	TagsHash    string
}

type snapshotPointer struct {
	ID             int64
	Path           string
	SnapshotTimeNS int64
	TargetKind     string
	TargetHash     string
	HashAlgo       string
}

type snapshotDiffChange struct {
	Code   string
	Path   string
	Detail string
}

func runSnapshotCommand(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "history":
			return runSnapshotHistoryCommand(args[1:])
		case "diff":
			return runSnapshotDiffCommand(args[1:])
		case "inspect":
			return runSnapshotInspectCommand(args[1:])
		case "query":
			return runSnapshotQueryCommand(args[1:])
		}
	}

	return runSnapshotCreateCommand(args)
}

func runSnapshotCreateCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  %s snapshot [options] [path]\n  %s snapshot history [options] [path]\n  %s snapshot diff [options] [path]\n  %s snapshot inspect [options]\n  %s snapshot query [options]\n\n", os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		fmt.Fprintln(fs.Output(), "Create a content-addressed filesystem snapshot and store a time/location pointer.")
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

	targetPath := fs.Arg(0)
	if targetPath == "" {
		targetPath = "."
	}

	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}

	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	opts := snapshotOptions{
		verbose: *verbose,
		skipAbsPaths: map[string]struct{}{
			absDBPath:          {},
			absDBPath + "-wal": {},
			absDBPath + "-shm": {},
		},
	}
	if shouldSkipSnapshotPath(absTargetPath, opts.skipAbsPaths) {
		return fmt.Errorf("target path %q conflicts with snapshot db path %q", absTargetPath, absDBPath)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	snapshotTime := time.Now().UTC().UnixNano()
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("start db transaction: %w", err)
	}
	defer tx.Rollback()

	info, err := os.Lstat(absTargetPath)
	if err != nil {
		return fmt.Errorf("stat target path: %w", err)
	}

	stats := &snapshotStats{}
	targetKind := snapshotKindFile
	targetHash := ""

	switch {
	case info.IsDir():
		targetKind = snapshotKindTree
		targetHash, err = ingestDirectory(tx, absTargetPath, stats, opts)
		if err != nil {
			return err
		}
	case info.Mode().IsRegular():
		targetHash, err = hashRegularFileForSnapshot(absTargetPath, info, opts.verbose)
		if err != nil {
			return err
		}
		stats.files++
	case info.Mode()&os.ModeSymlink != 0:
		targetKind = snapshotKindSymlink
		targetHash, _, err = hashSymlink(absTargetPath)
		if err != nil {
			return err
		}
		stats.symlinks++
	default:
		return fmt.Errorf("unsupported target file type for %q: %s", absTargetPath, info.Mode().String())
	}

	if err := insertPointer(tx, absTargetPath, snapshotTime, targetKind, targetHash); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit snapshot transaction: %w", err)
	}

	fmt.Printf("snapshot_time_ns=%d\n", snapshotTime)
	fmt.Printf("path=%s\n", absTargetPath)
	fmt.Printf("target_kind=%s\n", targetKind)
	fmt.Printf("target_hash=%s\n", targetHash)
	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("trees=%d files=%d symlinks=%d special=%d\n", stats.trees, stats.files, stats.symlinks, stats.special)
	return nil
}

func runSnapshotHistoryCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("snapshot history", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snapshot history [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "List snapshots for a path, newest first.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	limit := fs.Int("limit", 20, "Maximum number of history entries to return")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *limit <= 0 {
		return fmt.Errorf("limit must be > 0")
	}

	targetPath := fs.Arg(0)
	if targetPath == "" {
		targetPath = "."
	}

	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
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

	pointers, err := listPointersForPath(db, absTargetPath, *limit)
	if err != nil {
		return err
	}

	fmt.Printf("path=%s\n", absTargetPath)
	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("count=%d\n", len(pointers))
	fmt.Println("snapshot_time_ns\tsnapshot_time_utc\ttarget_kind\ttarget_hash")
	for _, pointer := range pointers {
		t := time.Unix(0, pointer.SnapshotTimeNS).UTC().Format(time.RFC3339Nano)
		fmt.Printf("%d\t%s\t%s\t%s\n", pointer.SnapshotTimeNS, t, pointer.TargetKind, pointer.TargetHash)
	}

	return nil
}

func runSnapshotDiffCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()

	fs := flag.NewFlagSet("snapshot diff", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snapshot diff [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Show differences between two snapshots for a path.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.String("db", defaultDB, "Path to snapshot database")
	fromTime := fs.Int64("from", 0, "Older snapshot time (unix nanoseconds)")
	toTime := fs.Int64("to", 0, "Newer snapshot time (unix nanoseconds)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if (*fromTime == 0) != (*toTime == 0) {
		return fmt.Errorf("from and to must be provided together")
	}

	targetPath := fs.Arg(0)
	if targetPath == "" {
		targetPath = "."
	}

	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
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

	fromPointer, toPointer, err := resolvePointersForDiff(db, absTargetPath, *fromTime, *toTime)
	if err != nil {
		return err
	}

	changes, err := diffPointers(db, fromPointer, toPointer)
	if err != nil {
		return err
	}

	fmt.Printf("path=%s\n", absTargetPath)
	fmt.Printf("db=%s\n", absDBPath)
	fmt.Printf("from_time_ns=%d\n", fromPointer.SnapshotTimeNS)
	fmt.Printf("to_time_ns=%d\n", toPointer.SnapshotTimeNS)
	fmt.Printf("from_kind=%s\n", fromPointer.TargetKind)
	fmt.Printf("to_kind=%s\n", toPointer.TargetKind)
	fmt.Printf("from_hash=%s\n", fromPointer.TargetHash)
	fmt.Printf("to_hash=%s\n", toPointer.TargetHash)
	fmt.Println("code\tpath\tdetail")

	added := 0
	removed := 0
	modified := 0
	typeChanged := 0
	for _, change := range changes {
		fmt.Printf("%s\t%s\t%s\n", change.Code, change.Path, change.Detail)
		switch change.Code {
		case "A":
			added++
		case "D":
			removed++
		case "M":
			modified++
		case "T":
			typeChanged++
		}
	}

	fmt.Printf("summary total=%d added=%d removed=%d modified=%d type=%d\n", len(changes), added, removed, modified, typeChanged)
	return nil
}

func defaultSnapshotDBPath() string {
	if custom := os.Getenv(snapshotDBEnv); custom != "" {
		return custom
	}

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return snapshotDBDefaultFile
		}
		dataHome = filepath.Join(home, ".local", "share")
	}

	return filepath.Join(dataHome, snapshotDBDirName, snapshotDBDefaultFile)
}

func openSnapshotDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(1)
	if err := initSnapshotSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func initSnapshotSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		`CREATE TABLE IF NOT EXISTS trees (
			hash TEXT PRIMARY KEY,
			hash_algo TEXT NOT NULL,
			created_at_ns INTEGER NOT NULL,
			entry_count INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS tree_entries (
			tree_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			target_hash TEXT NOT NULL,
			mode INTEGER NOT NULL,
			mod_time_ns INTEGER NOT NULL,
			size INTEGER NOT NULL,
			link_target TEXT NOT NULL,
			tags_hash TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (tree_hash, name),
			FOREIGN KEY(tree_hash) REFERENCES trees(hash) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS tags (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE
		);`,
		`CREATE TABLE IF NOT EXISTS tree_entry_tags (
			tree_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			tag_id INTEGER NOT NULL,
			PRIMARY KEY (tree_hash, name, tag_id),
			FOREIGN KEY(tree_hash, name) REFERENCES tree_entries(tree_hash, name) ON DELETE CASCADE,
			FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS hash_mappings (
			blake3 TEXT NOT NULL,
			algo TEXT NOT NULL,
			digest TEXT NOT NULL,
			PRIMARY KEY (blake3, algo)
		);`,
		`CREATE TABLE IF NOT EXISTS pointers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL,
			snapshot_time_ns INTEGER NOT NULL,
			target_kind TEXT NOT NULL,
			target_hash TEXT NOT NULL,
			hash_algo TEXT NOT NULL
		);`,
		"CREATE INDEX IF NOT EXISTS pointers_path_time_idx ON pointers(path, snapshot_time_ns DESC);",
		"CREATE INDEX IF NOT EXISTS pointers_target_idx ON pointers(target_hash);",
		"CREATE INDEX IF NOT EXISTS tree_entry_tags_tag_tree_idx ON tree_entry_tags(tag_id, tree_hash);",
		"CREATE INDEX IF NOT EXISTS tree_entry_tags_tree_tag_idx ON tree_entry_tags(tree_hash, tag_id);",
		"CREATE INDEX IF NOT EXISTS hash_mappings_algo_digest_idx ON hash_mappings(algo, digest);",
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize snapshot db schema: %w", err)
		}
	}

	if err := ensureTreeEntriesTagsHashColumn(db); err != nil {
		return err
	}
	if err := verifyForeignKeysEnabled(db); err != nil {
		return err
	}

	return nil
}

func ensureTreeEntriesTagsHashColumn(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(tree_entries);")
	if err != nil {
		return fmt.Errorf("inspect tree_entries schema: %w", err)
	}
	defer rows.Close()

	hasTagsHash := false
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &primaryKey); err != nil {
			return fmt.Errorf("scan tree_entries schema row: %w", err)
		}
		if name == "tags_hash" {
			hasTagsHash = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate tree_entries schema rows: %w", err)
	}

	if hasTagsHash {
		return nil
	}

	if _, err := db.Exec(`ALTER TABLE tree_entries ADD COLUMN tags_hash TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("add tags_hash column to tree_entries: %w", err)
	}
	return nil
}

func verifyForeignKeysEnabled(db *sql.DB) error {
	var enabled int
	if err := db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled); err != nil {
		return fmt.Errorf("check foreign key pragma: %w", err)
	}
	if enabled != 1 {
		return fmt.Errorf("sqlite foreign key enforcement is disabled")
	}
	return nil
}

func listPointersForPath(db *sql.DB, path string, limit int) ([]snapshotPointer, error) {
	rows, err := db.Query(
		`SELECT id, path, snapshot_time_ns, target_kind, target_hash, hash_algo
		 FROM pointers
		 WHERE path = ?
		 ORDER BY snapshot_time_ns DESC, id DESC
		 LIMIT ?`,
		path,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query pointers for path %q: %w", path, err)
	}
	defer rows.Close()

	pointers := make([]snapshotPointer, 0, limit)
	for rows.Next() {
		pointer := snapshotPointer{}
		if err := rows.Scan(
			&pointer.ID,
			&pointer.Path,
			&pointer.SnapshotTimeNS,
			&pointer.TargetKind,
			&pointer.TargetHash,
			&pointer.HashAlgo,
		); err != nil {
			return nil, fmt.Errorf("scan pointer row: %w", err)
		}
		pointers = append(pointers, pointer)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pointers for %q: %w", path, err)
	}

	return pointers, nil
}

func getPointerByPathAndTime(db *sql.DB, path string, snapshotTimeNS int64) (snapshotPointer, error) {
	pointer := snapshotPointer{}
	err := db.QueryRow(
		`SELECT id, path, snapshot_time_ns, target_kind, target_hash, hash_algo
		 FROM pointers
		 WHERE path = ? AND snapshot_time_ns = ?
		 ORDER BY id DESC
		 LIMIT 1`,
		path,
		snapshotTimeNS,
	).Scan(
		&pointer.ID,
		&pointer.Path,
		&pointer.SnapshotTimeNS,
		&pointer.TargetKind,
		&pointer.TargetHash,
		&pointer.HashAlgo,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return snapshotPointer{}, fmt.Errorf("no snapshot found for path %q at time %d", path, snapshotTimeNS)
		}
		return snapshotPointer{}, fmt.Errorf("query snapshot for path %q at time %d: %w", path, snapshotTimeNS, err)
	}

	return pointer, nil
}

func resolvePointersForDiff(db *sql.DB, path string, fromTimeNS, toTimeNS int64) (snapshotPointer, snapshotPointer, error) {
	if fromTimeNS == 0 && toTimeNS == 0 {
		pointers, err := listPointersForPath(db, path, 2)
		if err != nil {
			return snapshotPointer{}, snapshotPointer{}, err
		}
		if len(pointers) < 2 {
			return snapshotPointer{}, snapshotPointer{}, fmt.Errorf("need at least 2 snapshots for path %q", path)
		}

		// listPointersForPath returns newest first.
		return pointers[1], pointers[0], nil
	}

	fromPointer, err := getPointerByPathAndTime(db, path, fromTimeNS)
	if err != nil {
		return snapshotPointer{}, snapshotPointer{}, err
	}
	toPointer, err := getPointerByPathAndTime(db, path, toTimeNS)
	if err != nil {
		return snapshotPointer{}, snapshotPointer{}, err
	}

	if fromPointer.SnapshotTimeNS <= toPointer.SnapshotTimeNS {
		return fromPointer, toPointer, nil
	}

	// Allow callers to provide timestamps in either order.
	return toPointer, fromPointer, nil
}

func diffPointers(db *sql.DB, fromPointer, toPointer snapshotPointer) ([]snapshotDiffChange, error) {
	changes := make([]snapshotDiffChange, 0)

	if fromPointer.TargetKind != toPointer.TargetKind {
		changes = append(changes, snapshotDiffChange{
			Code:   "T",
			Path:   ".",
			Detail: fmt.Sprintf("%s -> %s", fromPointer.TargetKind, toPointer.TargetKind),
		})
		return changes, nil
	}

	switch fromPointer.TargetKind {
	case snapshotKindTree:
		treeCache := make(map[string][]treeEntry)
		if err := diffTreeHashes(db, fromPointer.TargetHash, toPointer.TargetHash, "", treeCache, &changes); err != nil {
			return nil, err
		}
	case snapshotKindFile, snapshotKindSymlink:
		if fromPointer.TargetHash != toPointer.TargetHash {
			changes = append(changes, snapshotDiffChange{
				Code:   "M",
				Path:   ".",
				Detail: fmt.Sprintf("hash %s -> %s", fromPointer.TargetHash, toPointer.TargetHash),
			})
		}
	default:
		if fromPointer.TargetHash != toPointer.TargetHash {
			changes = append(changes, snapshotDiffChange{
				Code:   "M",
				Path:   ".",
				Detail: fmt.Sprintf("hash %s -> %s", fromPointer.TargetHash, toPointer.TargetHash),
			})
		}
	}

	return changes, nil
}

func diffTreeHashes(db *sql.DB, fromTreeHash, toTreeHash, parentPath string, treeCache map[string][]treeEntry, changes *[]snapshotDiffChange) error {
	if fromTreeHash == toTreeHash {
		return nil
	}

	oldEntries, err := loadTreeEntries(db, treeCache, fromTreeHash)
	if err != nil {
		return err
	}
	newEntries, err := loadTreeEntries(db, treeCache, toTreeHash)
	if err != nil {
		return err
	}

	oldByName := make(map[string]treeEntry, len(oldEntries))
	for _, entry := range oldEntries {
		oldByName[entry.Name] = entry
	}
	newByName := make(map[string]treeEntry, len(newEntries))
	for _, entry := range newEntries {
		newByName[entry.Name] = entry
	}

	nameSet := make(map[string]struct{}, len(oldByName)+len(newByName))
	for name := range oldByName {
		nameSet[name] = struct{}{}
	}
	for name := range newByName {
		nameSet[name] = struct{}{}
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		oldEntry, oldExists := oldByName[name]
		newEntry, newExists := newByName[name]
		path := joinSnapshotRelativePath(parentPath, name)

		switch {
		case !oldExists:
			*changes = append(*changes, snapshotDiffChange{
				Code:   "A",
				Path:   path,
				Detail: fmt.Sprintf("kind=%s hash=%s", newEntry.Kind, newEntry.TargetHash),
			})
		case !newExists:
			*changes = append(*changes, snapshotDiffChange{
				Code:   "D",
				Path:   path,
				Detail: fmt.Sprintf("kind=%s hash=%s", oldEntry.Kind, oldEntry.TargetHash),
			})
		case oldEntry.Kind != newEntry.Kind:
			*changes = append(*changes, snapshotDiffChange{
				Code:   "T",
				Path:   path,
				Detail: fmt.Sprintf("%s -> %s", oldEntry.Kind, newEntry.Kind),
			})
		case oldEntry.Kind == snapshotKindTree:
			metaDelta := describeTreeMetadataDelta(oldEntry, newEntry)
			if metaDelta != "" {
				*changes = append(*changes, snapshotDiffChange{
					Code:   "M",
					Path:   path,
					Detail: metaDelta,
				})
			}
			if err := diffTreeHashes(db, oldEntry.TargetHash, newEntry.TargetHash, path, treeCache, changes); err != nil {
				return err
			}
		default:
			detail := describeEntryDelta(oldEntry, newEntry)
			if detail != "" {
				*changes = append(*changes, snapshotDiffChange{
					Code:   "M",
					Path:   path,
					Detail: detail,
				})
			}
		}
	}

	return nil
}

func joinSnapshotRelativePath(parentPath, name string) string {
	if parentPath == "" {
		return name
	}
	return parentPath + "/" + name
}

func describeTreeMetadataDelta(oldEntry, newEntry treeEntry) string {
	parts := make([]string, 0, 3)
	if oldEntry.Mode != newEntry.Mode {
		parts = append(parts, fmt.Sprintf("mode %04o -> %04o", oldEntry.Mode&0o7777, newEntry.Mode&0o7777))
	}
	if oldEntry.ModTimeUnix != newEntry.ModTimeUnix {
		parts = append(parts, fmt.Sprintf("mtime_ns %d -> %d", oldEntry.ModTimeUnix, newEntry.ModTimeUnix))
	}
	if oldEntry.Size != newEntry.Size {
		parts = append(parts, fmt.Sprintf("size %d -> %d", oldEntry.Size, newEntry.Size))
	}
	return strings.Join(parts, ", ")
}

func describeEntryDelta(oldEntry, newEntry treeEntry) string {
	parts := make([]string, 0, 6)
	if oldEntry.TargetHash != newEntry.TargetHash {
		parts = append(parts, fmt.Sprintf("hash %s -> %s", oldEntry.TargetHash, newEntry.TargetHash))
	}
	if oldEntry.Mode != newEntry.Mode {
		parts = append(parts, fmt.Sprintf("mode %04o -> %04o", oldEntry.Mode&0o7777, newEntry.Mode&0o7777))
	}
	if oldEntry.ModTimeUnix != newEntry.ModTimeUnix {
		parts = append(parts, fmt.Sprintf("mtime_ns %d -> %d", oldEntry.ModTimeUnix, newEntry.ModTimeUnix))
	}
	if oldEntry.Size != newEntry.Size {
		parts = append(parts, fmt.Sprintf("size %d -> %d", oldEntry.Size, newEntry.Size))
	}
	if oldEntry.LinkTarget != newEntry.LinkTarget {
		parts = append(parts, fmt.Sprintf("link_target %q -> %q", oldEntry.LinkTarget, newEntry.LinkTarget))
	}
	if oldEntry.TagsHash != newEntry.TagsHash {
		parts = append(parts, fmt.Sprintf("tags_hash %s -> %s", oldEntry.TagsHash, newEntry.TagsHash))
	}
	return strings.Join(parts, ", ")
}

func loadTreeEntries(db *sql.DB, cache map[string][]treeEntry, treeHash string) ([]treeEntry, error) {
	if entries, exists := cache[treeHash]; exists {
		return entries, nil
	}

	rows, err := db.Query(
		`SELECT name, kind, target_hash, mode, mod_time_ns, size, link_target, tags_hash
		 FROM tree_entries
		 WHERE tree_hash = ?
		 ORDER BY name ASC`,
		treeHash,
	)
	if err != nil {
		return nil, fmt.Errorf("query entries for tree %q: %w", treeHash, err)
	}
	defer rows.Close()

	entries := make([]treeEntry, 0)
	for rows.Next() {
		entry := treeEntry{}
		var modeInt int64
		if err := rows.Scan(
			&entry.Name,
			&entry.Kind,
			&entry.TargetHash,
			&modeInt,
			&entry.ModTimeUnix,
			&entry.Size,
			&entry.LinkTarget,
			&entry.TagsHash,
		); err != nil {
			return nil, fmt.Errorf("scan tree entry in tree %q: %w", treeHash, err)
		}
		entry.Mode = uint32(modeInt)
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tree entries for %q: %w", treeHash, err)
	}

	cache[treeHash] = entries
	return entries, nil
}

func ingestDirectory(tx *sql.Tx, dirPath string, stats *snapshotStats, opts snapshotOptions) (string, error) {
	dirEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("read directory %q: %w", dirPath, err)
	}

	entries := make([]treeEntry, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		name := dirEntry.Name()
		childPath := filepath.Join(dirPath, name)
		if shouldSkipSnapshotPath(childPath, opts.skipAbsPaths) {
			continue
		}

		info, err := os.Lstat(childPath)
		if err != nil {
			return "", fmt.Errorf("lstat %q: %w", childPath, err)
		}

		entry := treeEntry{
			Name:        name,
			Mode:        uint32(info.Mode()),
			ModTimeUnix: info.ModTime().UnixNano(),
			Size:        info.Size(),
		}

		tags, err := readNormalizedXDGTags(childPath, opts.verbose)
		if err != nil {
			return "", err
		}
		entry.Tags = tags
		entry.TagsHash = hashNormalizedTags(tags)

		switch {
		case info.IsDir():
			childTreeHash, err := ingestDirectory(tx, childPath, stats, opts)
			if err != nil {
				return "", err
			}
			entry.Kind = snapshotKindTree
			entry.TargetHash = childTreeHash
		case info.Mode().IsRegular():
			fileHash, err := hashRegularFileForSnapshot(childPath, info, opts.verbose)
			if err != nil {
				return "", err
			}
			entry.Kind = snapshotKindFile
			entry.TargetHash = fileHash
			stats.files++
		case info.Mode()&os.ModeSymlink != 0:
			linkHash, linkTarget, err := hashSymlink(childPath)
			if err != nil {
				return "", err
			}
			entry.Kind = "symlink"
			entry.TargetHash = linkHash
			entry.LinkTarget = linkTarget
			entry.Size = int64(len(linkTarget))
			stats.symlinks++
		default:
			entry.Kind = "special"
			entry.TargetHash = blake3Hex([]byte(fmt.Sprintf("%s:%d:%d", info.Mode().String(), info.Size(), info.ModTime().UnixNano())))
			stats.special++
		}

		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	treeHash := hashTree(entries)
	if err := insertTree(tx, treeHash, entries); err != nil {
		return "", err
	}

	stats.trees++
	return treeHash, nil
}

func shouldSkipSnapshotPath(path string, skips map[string]struct{}) bool {
	_, exists := skips[path]
	return exists
}

func hashTree(entries []treeEntry) string {
	hasher := blake3.New()

	writeHashString(hasher, "forge.tree.v1")
	writeHashUint32(hasher, uint32(len(entries)))

	for _, entry := range entries {
		writeHashString(hasher, entry.Name)
		writeHashString(hasher, entry.Kind)
		writeHashString(hasher, entry.TargetHash)
		writeHashUint32(hasher, entry.Mode)
		writeHashInt64(hasher, entry.ModTimeUnix)
		writeHashInt64(hasher, entry.Size)
		writeHashString(hasher, entry.LinkTarget)
		writeHashUint32(hasher, uint32(len(entry.Tags)))
		for _, tag := range entry.Tags {
			writeHashString(hasher, tag)
		}
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func readNormalizedXDGTags(path string, verbose bool) ([]string, error) {
	data, err := getXattr(path, snapshotXDGTagsKey)
	if err != nil {
		if canIgnoreXattrReadError(err) {
			if verbose && (err == syscall.EPERM || err == syscall.EACCES) {
				log.Printf("[snapshot] xattr read skipped for %s (%s): %v", path, snapshotXDGTagsKey, err)
			}
			return nil, nil
		}
		return nil, fmt.Errorf("read xattr %s for %q: %w", snapshotXDGTagsKey, path, err)
	}

	return normalizeTags(string(data)), nil
}

func canIgnoreXattrReadError(err error) bool {
	return err == syscall.ENODATA ||
		err == syscall.ENOENT ||
		err == syscall.EPERM ||
		err == syscall.EACCES ||
		err == syscall.ENOTSUP ||
		err == syscall.EOPNOTSUPP
}

func hashNormalizedTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}

	h := blake3.New()
	writeHashString(h, "forge.tags.v1")
	writeHashUint32(h, uint32(len(tags)))
	for _, tag := range tags {
		writeHashString(h, tag)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeHashString(h hash.Hash, value string) {
	writeHashBytes(h, []byte(value))
}

func writeHashBytes(h hash.Hash, value []byte) {
	writeHashUint32(h, uint32(len(value)))
	_, _ = h.Write(value)
}

func writeHashUint32(h hash.Hash, value uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	_, _ = h.Write(buf[:])
}

func writeHashInt64(h hash.Hash, value int64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(value))
	_, _ = h.Write(buf[:])
}

func insertTree(tx *sql.Tx, treeHash string, entries []treeEntry) error {
	now := time.Now().UTC().UnixNano()
	result, err := tx.Exec(
		`INSERT OR IGNORE INTO trees(hash, hash_algo, created_at_ns, entry_count) VALUES(?, ?, ?, ?)`,
		treeHash,
		snapshotHashAlgo,
		now,
		len(entries),
	)
	if err != nil {
		return fmt.Errorf("insert tree %q: %w", treeHash, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read tree insert row count: %w", err)
	}
	if rowsAffected == 0 {
		return nil
	}

	stmt, err := tx.Prepare(
		`INSERT INTO tree_entries(tree_hash, name, kind, target_hash, mode, mod_time_ns, size, link_target, tags_hash)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return fmt.Errorf("prepare tree entry insert: %w", err)
	}
	defer stmt.Close()

	tagLinkStmt, err := tx.Prepare(
		`INSERT INTO tree_entry_tags(tree_hash, name, tag_id) VALUES(?, ?, ?)`,
	)
	if err != nil {
		return fmt.Errorf("prepare tree entry tag insert: %w", err)
	}
	defer tagLinkStmt.Close()

	tagIDByName := make(map[string]int64)

	for _, entry := range entries {
		if _, err := stmt.Exec(
			treeHash,
			entry.Name,
			entry.Kind,
			entry.TargetHash,
			entry.Mode,
			entry.ModTimeUnix,
			entry.Size,
			entry.LinkTarget,
			entry.TagsHash,
		); err != nil {
			return fmt.Errorf("insert tree entry %q in tree %q: %w", entry.Name, treeHash, err)
		}

		for _, tag := range entry.Tags {
			tagID, exists := tagIDByName[tag]
			if !exists {
				var err error
				tagID, err = ensureTagID(tx, tag)
				if err != nil {
					return err
				}
				tagIDByName[tag] = tagID
			}

			if _, err := tagLinkStmt.Exec(treeHash, entry.Name, tagID); err != nil {
				return fmt.Errorf("insert tree entry tag %q for %q in tree %q: %w", tag, entry.Name, treeHash, err)
			}
		}
	}

	return nil
}

func ensureTagID(tx *sql.Tx, tag string) (int64, error) {
	if _, err := tx.Exec(`INSERT OR IGNORE INTO tags(name) VALUES(?)`, tag); err != nil {
		return 0, fmt.Errorf("insert tag %q: %w", tag, err)
	}

	var tagID int64
	if err := tx.QueryRow(`SELECT id FROM tags WHERE name = ?`, tag).Scan(&tagID); err != nil {
		return 0, fmt.Errorf("query tag id for %q: %w", tag, err)
	}

	return tagID, nil
}

func insertPointer(tx *sql.Tx, path string, snapshotTime int64, targetKind, targetHash string) error {
	if _, err := tx.Exec(
		`INSERT INTO pointers(path, snapshot_time_ns, target_kind, target_hash, hash_algo) VALUES(?, ?, ?, ?, ?)`,
		path,
		snapshotTime,
		targetKind,
		targetHash,
		snapshotHashAlgo,
	); err != nil {
		return fmt.Errorf("insert pointer for %q: %w", path, err)
	}

	return nil
}

func hashRegularFileForSnapshot(path string, info os.FileInfo, verbose bool) (string, error) {
	currentMtime := info.ModTime().Unix()
	blake3Key := XattrPrefix + snapshotHashAlgo

	cachedMtimeBytes, err := getXattr(path, XattrMtimeKey)
	if err == nil {
		cachedMtime, parseErr := strconv.ParseInt(string(cachedMtimeBytes), 10, 64)
		if parseErr == nil && cachedMtime == currentMtime {
			if cachedHash, hashErr := getXattr(path, blake3Key); hashErr == nil {
				return string(cachedHash), nil
			}
		}
	}

	hasher := blake3.New()
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file %q: %w", path, err)
	}
	defer f.Close()

	if _, err := io.CopyBuffer(hasher, f, buf); err != nil {
		return "", fmt.Errorf("read file %q: %w", path, err)
	}

	infoPost, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("re-stat file %q: %w", path, err)
	}
	if info.ModTime() != infoPost.ModTime() {
		return "", fmt.Errorf("file changed while hashing %q", path)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	mtimeStr := strconv.FormatInt(currentMtime, 10)
	if err := setXattr(path, blake3Key, []byte(digest)); err != nil && verbose {
		log.Printf("[snapshot] xattr write skipped for %s (%s): %v", path, blake3Key, err)
	}
	if err := setXattr(path, XattrMtimeKey, []byte(mtimeStr)); err != nil && verbose {
		log.Printf("[snapshot] xattr write skipped for %s (%s): %v", path, XattrMtimeKey, err)
	}

	return digest, nil
}

func hashSymlink(path string) (string, string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", "", fmt.Errorf("read symlink %q: %w", path, err)
	}

	return blake3Hex([]byte(target)), target, nil
}

func blake3Hex(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}
