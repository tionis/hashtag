package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestSnapshotCommandCreatesTreesAndPointer(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o755); err != nil {
		t.Fatalf("mkdirs: %v", err)
	}

	if err := os.WriteFile(filepath.Join(project, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(project, "sub", "b.txt"), []byte("bravo"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", dbPath, project}); err != nil {
		t.Fatalf("run snapshot command: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if got := mustCount(t, db, "SELECT COUNT(*) FROM pointers"); got != 1 {
		t.Fatalf("expected 1 pointer, got %d", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM trees"); got != 2 {
		t.Fatalf("expected 2 trees (root + subdir), got %d", got)
	}

	var rootTreeHash string
	if err := db.QueryRow("SELECT target_hash FROM pointers LIMIT 1").Scan(&rootTreeHash); err != nil {
		t.Fatalf("query root pointer hash: %v", err)
	}

	var rootEntryCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ?", rootTreeHash).Scan(&rootEntryCount); err != nil {
		t.Fatalf("query root tree entries: %v", err)
	}
	if rootEntryCount != 2 {
		t.Fatalf("expected root tree to have 2 entries, got %d", rootEntryCount)
	}
}

func TestSnapshotCommandReusesExistingTrees(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("content"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	if got := mustCount(t, db, "SELECT COUNT(*) FROM pointers"); got != 2 {
		t.Fatalf("expected 2 pointers, got %d", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM trees"); got != 1 {
		t.Fatalf("expected 1 unique tree after two identical snapshots, got %d", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(DISTINCT target_hash) FROM pointers"); got != 1 {
		t.Fatalf("expected pointers to reference same hash, got %d unique hashes", got)
	}
}

func TestSnapshotCommandSkipsSnapshotDBFilesInsideTarget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("content"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	dbPath := filepath.Join(root, "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("run snapshot command: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	var rootTreeHash string
	if err := db.QueryRow("SELECT target_hash FROM pointers ORDER BY id DESC LIMIT 1").Scan(&rootTreeHash); err != nil {
		t.Fatalf("query root tree hash: %v", err)
	}

	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ?", rootTreeHash); got != 1 {
		t.Fatalf("expected only 1 root entry (file.txt), got %d", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ? AND name LIKE 'snapshot.db%'", rootTreeHash); got != 0 {
		t.Fatalf("expected snapshot db files to be excluded from tree, got %d", got)
	}
}

func TestSnapshotCommandRejectsSnapshottingDatabaseFile(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "snapshot.db")
	if err := os.WriteFile(dbPath, []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("write db placeholder: %v", err)
	}

	err := runSnapshotCommand([]string{"-db", dbPath, dbPath})
	if err == nil {
		t.Fatal("expected error when target path equals snapshot db path")
	}
	if !strings.Contains(err.Error(), "conflicts with snapshot db path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSnapshotHistoryReturnsNewestFirst(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "file.txt")
	if err := os.WriteFile(filePath, []byte("v1"), 0o644); err != nil {
		t.Fatalf("write v1: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}

	time.Sleep(2 * time.Millisecond)
	if err := os.WriteFile(filePath, []byte("v2"), 0o644); err != nil {
		t.Fatalf("write v2: %v", err)
	}
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	pointers, err := listPointersForPath(db, root, 10)
	if err != nil {
		t.Fatalf("list pointers: %v", err)
	}
	if len(pointers) != 2 {
		t.Fatalf("expected 2 pointers, got %d", len(pointers))
	}
	if pointers[0].SnapshotTimeNS <= pointers[1].SnapshotTimeNS {
		t.Fatalf("expected newest pointer first, got %d then %d", pointers[0].SnapshotTimeNS, pointers[1].SnapshotTimeNS)
	}
}

func TestSnapshotDiffDetectsAddRemoveAndModify(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "mod.txt"), []byte("old"), 0o644); err != nil {
		t.Fatalf("write mod old: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "remove.txt"), []byte("remove"), 0o644); err != nil {
		t.Fatalf("write remove: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "inner.txt"), []byte("inner-old"), 0o644); err != nil {
		t.Fatalf("write inner old: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}

	time.Sleep(2 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(root, "mod.txt"), []byte("new"), 0o644); err != nil {
		t.Fatalf("write mod new: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "remove.txt")); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "add.txt"), []byte("added"), 0o644); err != nil {
		t.Fatalf("write add: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "inner.txt"), []byte("inner-new"), 0o644); err != nil {
		t.Fatalf("write inner new: %v", err)
	}
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	fromPointer, toPointer, err := resolvePointersForDiff(db, root, 0, 0)
	if err != nil {
		t.Fatalf("resolve pointers for diff: %v", err)
	}

	changes, err := diffPointers(db, fromPointer, toPointer)
	if err != nil {
		t.Fatalf("diff pointers: %v", err)
	}

	if !hasDiffChange(changes, "M", "mod.txt") {
		t.Fatalf("expected modified change for mod.txt; changes=%v", changes)
	}
	if !hasDiffChange(changes, "D", "remove.txt") {
		t.Fatalf("expected removed change for remove.txt; changes=%v", changes)
	}
	if !hasDiffChange(changes, "A", "add.txt") {
		t.Fatalf("expected added change for add.txt; changes=%v", changes)
	}
	if !hasDiffChange(changes, "M", "sub/inner.txt") {
		t.Fatalf("expected modified change for sub/inner.txt; changes=%v", changes)
	}
}

func TestSnapshotSubcommandsHistoryAndDiff(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "file.txt")
	if err := os.WriteFile(filePath, []byte("v1"), 0o644); err != nil {
		t.Fatalf("write v1: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}

	time.Sleep(2 * time.Millisecond)
	if err := os.WriteFile(filePath, []byte("v2"), 0o644); err != nil {
		t.Fatalf("write v2: %v", err)
	}
	if err := runSnapshotCommand([]string{"-db", dbPath, root}); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}

	if err := runSnapshotCommand([]string{"history", "-db", dbPath, root}); err != nil {
		t.Fatalf("snapshot history command failed: %v", err)
	}
	if err := runSnapshotCommand([]string{"diff", "-db", dbPath, root}); err != nil {
		t.Fatalf("snapshot diff command failed: %v", err)
	}
}

func TestSnapshotSubcommandsInspectAndQuery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := openSnapshotDB(dbPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}

	entries := []treeEntry{
		{
			Name:        "a.txt",
			Kind:        snapshotKindFile,
			TargetHash:  strings.Repeat("a", 64),
			Mode:        0o100644,
			ModTimeUnix: 100,
			Size:        3,
			Tags:        []string{"music", "work"},
			TagsHash:    hashNormalizedTags([]string{"music", "work"}),
		},
		{
			Name:        "b.txt",
			Kind:        snapshotKindFile,
			TargetHash:  strings.Repeat("b", 64),
			Mode:        0o100644,
			ModTimeUnix: 100,
			Size:        5,
			Tags:        []string{"music"},
			TagsHash:    hashNormalizedTags([]string{"music"}),
		},
	}
	treeHash := hashTree(entries)

	tx, err := db.Begin()
	if err != nil {
		db.Close()
		t.Fatalf("begin tx: %v", err)
	}
	if err := insertTree(tx, treeHash, entries); err != nil {
		tx.Rollback()
		db.Close()
		t.Fatalf("insert tree: %v", err)
	}
	if err := tx.Commit(); err != nil {
		db.Close()
		t.Fatalf("commit tx: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	if err := runSnapshotCommand([]string{"inspect", "-db", dbPath, "-tree", treeHash}); err != nil {
		t.Fatalf("snapshot inspect command failed: %v", err)
	}
	if err := runSnapshotCommand([]string{"query", "-db", dbPath, "-tree", treeHash, "-tags", "music,work"}); err != nil {
		t.Fatalf("snapshot query command failed: %v", err)
	}
}

func TestSnapshotSchemaForeignKeysEnabled(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := openSnapshotDB(dbPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	defer db.Close()

	var enabled int
	if err := db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled); err != nil {
		t.Fatalf("query pragma foreign_keys: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("expected PRAGMA foreign_keys=1, got %d", enabled)
	}

	if _, err := db.Exec(`INSERT INTO tree_entry_tags(tree_hash, name, tag_id) VALUES('missing', 'entry', 999)`); err == nil {
		t.Fatal("expected foreign key error for invalid tree_entry_tags insert")
	}
}

func TestInsertTreePersistsTagRelations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := openSnapshotDB(dbPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	defer db.Close()

	entry := treeEntry{
		Name:        "file.txt",
		Kind:        snapshotKindFile,
		TargetHash:  strings.Repeat("a", 64),
		Mode:        0o100644,
		ModTimeUnix: 123456789,
		Size:        7,
		Tags:        []string{"media", "music"},
		TagsHash:    hashNormalizedTags([]string{"media", "music"}),
	}
	treeHash := hashTree([]treeEntry{entry})

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := insertTree(tx, treeHash, []treeEntry{entry}); err != nil {
		tx.Rollback()
		t.Fatalf("insert tree: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	if got := mustCount(t, db, "SELECT COUNT(*) FROM tags"); got != 2 {
		t.Fatalf("expected 2 tags, got %d", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entry_tags"); got != 2 {
		t.Fatalf("expected 2 tree_entry_tags rows, got %d", got)
	}

	var storedTagsHash string
	if err := db.QueryRow("SELECT tags_hash FROM tree_entries WHERE tree_hash = ? AND name = ?", treeHash, "file.txt").Scan(&storedTagsHash); err != nil {
		t.Fatalf("query stored tags_hash: %v", err)
	}
	if storedTagsHash != entry.TagsHash {
		t.Fatalf("expected tags_hash=%s, got %s", entry.TagsHash, storedTagsHash)
	}
}

func TestHashMappingsTableStoresMinimalMapping(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := openSnapshotDB(dbPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	defer db.Close()

	blake3Digest := strings.Repeat("b", 64)
	sha256Digest := strings.Repeat("c", 64)
	if _, err := db.Exec(
		`INSERT INTO hash_mappings(blake3, algo, digest) VALUES(?, ?, ?)`,
		blake3Digest,
		"sha256",
		sha256Digest,
	); err != nil {
		t.Fatalf("insert hash mapping: %v", err)
	}

	var got string
	if err := db.QueryRow(`SELECT digest FROM hash_mappings WHERE blake3 = ? AND algo = ?`, blake3Digest, "sha256").Scan(&got); err != nil {
		t.Fatalf("query hash mapping: %v", err)
	}
	if got != sha256Digest {
		t.Fatalf("expected digest %s, got %s", sha256Digest, got)
	}
}

func TestCanIgnoreXattrReadError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "missing xattr", err: syscall.ENODATA, want: true},
		{name: "missing file", err: syscall.ENOENT, want: true},
		{name: "permission denied", err: syscall.EPERM, want: true},
		{name: "io error", err: syscall.EIO, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canIgnoreXattrReadError(tt.err); got != tt.want {
				t.Fatalf("canIgnoreXattrReadError(%v)=%v want %v", tt.err, got, tt.want)
			}
		})
	}
}

func mustCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("query %q failed: %v", query, err)
	}
	return count
}

func hasDiffChange(changes []snapshotDiffChange, code, path string) bool {
	for _, change := range changes {
		if change.Code == code && change.Path == path {
			return true
		}
	}
	return false
}
