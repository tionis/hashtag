package main

import (
	"database/sql"
	"encoding/json"
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

func TestSnapshotCommandSkipsDisappearedEntries(t *testing.T) {
	root := t.TempDir()
	keepPath := filepath.Join(root, "keep.txt")
	missingPath := filepath.Join(root, "vanish.txt")
	if err := os.WriteFile(keepPath, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write keep file: %v", err)
	}
	if err := os.WriteFile(missingPath, []byte("vanish"), 0o644); err != nil {
		t.Fatalf("write vanish file: %v", err)
	}

	origLstat := snapshotLstat
	snapshotLstat = func(path string) (os.FileInfo, error) {
		if path == missingPath {
			return nil, &os.PathError{Op: "lstat", Path: path, Err: syscall.ENOENT}
		}
		return origLstat(path)
	}
	defer func() {
		snapshotLstat = origLstat
	}()

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	err := runSnapshotCommand([]string{"-db", dbPath, root})
	if err == nil {
		t.Fatal("expected partial warning exit when entries disappear during scan")
	}
	if code := resolveCLIExitCode(err); code != exitCodePartialWarnings {
		t.Fatalf("expected exit code %d, got %d (err=%v)", exitCodePartialWarnings, code, err)
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
		t.Fatalf("expected only 1 root entry after skipping disappeared file, got %d", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ? AND name = 'keep.txt'", rootTreeHash); got != 1 {
		t.Fatalf("expected keep.txt to remain in snapshot, got %d entries", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ? AND name = 'vanish.txt'", rootTreeHash); got != 0 {
		t.Fatalf("expected vanish.txt to be skipped, got %d entries", got)
	}
}

func TestSnapshotCommandSkipsPermissionDeniedDirectoryByDefault(t *testing.T) {
	root := t.TempDir()
	keepPath := filepath.Join(root, "keep.txt")
	lockedDir := filepath.Join(root, "locked")
	insideLocked := filepath.Join(lockedDir, "secret.txt")
	if err := os.WriteFile(keepPath, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write keep file: %v", err)
	}
	if err := os.MkdirAll(lockedDir, 0o755); err != nil {
		t.Fatalf("mkdir locked dir: %v", err)
	}
	if err := os.WriteFile(insideLocked, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	origReadDir := snapshotReadDir
	snapshotReadDir = func(path string) ([]os.DirEntry, error) {
		if path == lockedDir {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EACCES}
		}
		return origReadDir(path)
	}
	defer func() {
		snapshotReadDir = origReadDir
	}()

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	err := runSnapshotCommand([]string{"-db", dbPath, root})
	if err == nil {
		t.Fatal("expected partial warning exit when permission-denied directory is skipped")
	}
	if code := resolveCLIExitCode(err); code != exitCodePartialWarnings {
		t.Fatalf("expected exit code %d, got %d (err=%v)", exitCodePartialWarnings, code, err)
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

	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ? AND name = 'keep.txt'", rootTreeHash); got != 1 {
		t.Fatalf("expected keep.txt to remain in snapshot, got %d entries", got)
	}
	if got := mustCount(t, db, "SELECT COUNT(*) FROM tree_entries WHERE tree_hash = ? AND name = 'locked'", rootTreeHash); got != 0 {
		t.Fatalf("expected locked directory to be skipped, got %d entries", got)
	}
}

func TestSnapshotCommandStrictModeFailsOnPermissionDeniedDirectory(t *testing.T) {
	root := t.TempDir()
	lockedDir := filepath.Join(root, "locked")
	if err := os.MkdirAll(lockedDir, 0o755); err != nil {
		t.Fatalf("mkdir locked dir: %v", err)
	}

	origReadDir := snapshotReadDir
	snapshotReadDir = func(path string) ([]os.DirEntry, error) {
		if path == lockedDir {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EACCES}
		}
		return origReadDir(path)
	}
	defer func() {
		snapshotReadDir = origReadDir
	}()

	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	err := runSnapshotCommand([]string{"-db", dbPath, "-strict", root})
	if err == nil {
		t.Fatal("expected strict mode to fail on permission-denied directory")
	}
	if code := resolveCLIExitCode(err); code != exitCodeFailure {
		t.Fatalf("expected exit code %d, got %d (err=%v)", exitCodeFailure, code, err)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied error, got: %v", err)
	}

	db, openErr := sql.Open("sqlite", dbPath)
	if openErr != nil {
		t.Fatalf("open sqlite: %v", openErr)
	}
	defer db.Close()

	if got := mustCount(t, db, "SELECT COUNT(*) FROM pointers"); got != 0 {
		t.Fatalf("expected no snapshot pointer to be committed, got %d", got)
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

func TestSnapshotDiffReportsTagListDelta(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snapshot.db")
	db, err := openSnapshotDB(dbPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	defer db.Close()

	oldEntries := []treeEntry{
		{
			Name:        "song.mp3",
			Kind:        snapshotKindFile,
			TargetHash:  strings.Repeat("a", 64),
			Mode:        0o100644,
			ModTimeUnix: 1,
			Size:        123,
			Tags:        []string{"music", "work"},
		},
	}
	newEntries := []treeEntry{
		{
			Name:        "song.mp3",
			Kind:        snapshotKindFile,
			TargetHash:  strings.Repeat("a", 64),
			Mode:        0o100644,
			ModTimeUnix: 1,
			Size:        123,
			Tags:        []string{"archive", "music"},
		},
	}

	oldTreeHash := hashTree(oldEntries)
	newTreeHash := hashTree(newEntries)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := insertTree(tx, oldTreeHash, oldEntries); err != nil {
		tx.Rollback()
		t.Fatalf("insert old tree: %v", err)
	}
	if err := insertTree(tx, newTreeHash, newEntries); err != nil {
		tx.Rollback()
		t.Fatalf("insert new tree: %v", err)
	}

	const targetPath = "/tmp/snapshot-tag-diff"
	if err := insertPointer(tx, targetPath, 100, snapshotKindTree, oldTreeHash); err != nil {
		tx.Rollback()
		t.Fatalf("insert old pointer: %v", err)
	}
	if err := insertPointer(tx, targetPath, 200, snapshotKindTree, newTreeHash); err != nil {
		tx.Rollback()
		t.Fatalf("insert new pointer: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	fromPointer, toPointer, err := resolvePointersForDiff(db, targetPath, 0, 0)
	if err != nil {
		t.Fatalf("resolve pointers for diff: %v", err)
	}
	changes, err := diffPointers(db, fromPointer, toPointer)
	if err != nil {
		t.Fatalf("diff pointers: %v", err)
	}

	found := false
	for _, change := range changes {
		if change.Code == "M" && change.Path == "song.mp3" {
			if strings.Contains(change.Detail, "tags +archive") && strings.Contains(change.Detail, "tags -work") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected tag list delta in diff details; changes=%v", changes)
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
		},
		{
			Name:        "b.txt",
			Kind:        snapshotKindFile,
			TargetHash:  strings.Repeat("b", 64),
			Mode:        0o100644,
			ModTimeUnix: 100,
			Size:        5,
			Tags:        []string{"music"},
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

func TestSnapshotInspectAndQueryJSONOutput(t *testing.T) {
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
		},
		{
			Name:        "b.txt",
			Kind:        snapshotKindFile,
			TargetHash:  strings.Repeat("b", 64),
			Mode:        0o100644,
			ModTimeUnix: 100,
			Size:        5,
			Tags:        []string{"music"},
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

	inspectOut, err := captureStdout(t, func() error {
		return runSnapshotCommand([]string{"inspect", "-db", dbPath, "-tree", treeHash, "-output", "json"})
	})
	if err != nil {
		t.Fatalf("snapshot inspect json output: %v", err)
	}

	var inspectPayload snapshotInspectOutput
	if err := json.Unmarshal([]byte(inspectOut), &inspectPayload); err != nil {
		t.Fatalf("unmarshal inspect payload: %v\noutput=%s", err, inspectOut)
	}
	if inspectPayload.EntryCount != 2 {
		t.Fatalf("expected entry_count=2, got %d", inspectPayload.EntryCount)
	}
	if len(inspectPayload.Entries) != 2 {
		t.Fatalf("expected 2 inspect entries, got %d", len(inspectPayload.Entries))
	}

	queryOut, err := captureStdout(t, func() error {
		return runSnapshotCommand([]string{"query", "-db", dbPath, "-tree", treeHash, "-tags", "music,work", "-output", "json"})
	})
	if err != nil {
		t.Fatalf("snapshot query json output: %v", err)
	}

	var queryPayload snapshotQueryOutput
	if err := json.Unmarshal([]byte(queryOut), &queryPayload); err != nil {
		t.Fatalf("unmarshal query payload: %v\noutput=%s", err, queryOut)
	}
	if queryPayload.MatchCount != 1 {
		t.Fatalf("expected match_count=1, got %d", queryPayload.MatchCount)
	}
	if len(queryPayload.Matches) != 1 || queryPayload.Matches[0].Path != "a.txt" {
		t.Fatalf("unexpected query matches: %+v", queryPayload.Matches)
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

func TestCanIgnoreSnapshotPathError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "missing path",
			err:  &os.PathError{Op: "lstat", Path: "/tmp/missing", Err: syscall.ENOENT},
			want: true,
		},
		{
			name: "not directory anymore",
			err:  &os.PathError{Op: "open", Path: "/tmp/file/child", Err: syscall.ENOTDIR},
			want: true,
		},
		{
			name: "permission denied",
			err:  &os.PathError{Op: "lstat", Path: "/tmp/protected", Err: syscall.EACCES},
			want: true,
		},
		{
			name: "operation not permitted",
			err:  &os.PathError{Op: "lstat", Path: "/tmp/protected", Err: syscall.EPERM},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canIgnoreSnapshotPathError(tt.err); got != tt.want {
				t.Fatalf("canIgnoreSnapshotPathError(%v)=%v want %v", tt.err, got, tt.want)
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
