package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
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
