package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/zeebo/blake3"
)

func TestFindDuplicateGroupsFindsDuplicateContent(t *testing.T) {
	root := t.TempDir()

	aPath := filepath.Join(root, "a.txt")
	bPath := filepath.Join(root, "b.txt")
	uniquePath := filepath.Join(root, "unique.txt")
	tooSmallPath := filepath.Join(root, "empty.txt")

	if err := os.WriteFile(aPath, []byte("same-content"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(bPath, []byte("same-content"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}
	if err := os.WriteFile(uniquePath, []byte("this is different"), 0o644); err != nil {
		t.Fatalf("write unique.txt: %v", err)
	}
	if err := os.WriteFile(tooSmallPath, []byte{}, 0o644); err != nil {
		t.Fatalf("write empty.txt: %v", err)
	}

	groups, stats, err := findDuplicateGroups(dupesOptions{
		root:        root,
		minSize:     1,
		useCache:    false,
		updateCache: false,
		verbose:     false,
	})
	if err != nil {
		t.Fatalf("findDuplicateGroups: %v", err)
	}

	if len(groups) != 1 {
		t.Fatalf("expected 1 duplicate group, got %d", len(groups))
	}
	if len(groups[0].paths) != 2 {
		t.Fatalf("expected 2 paths in group, got %d", len(groups[0].paths))
	}

	gotPaths := append([]string(nil), groups[0].paths...)
	sort.Strings(gotPaths)
	wantPaths := []string{aPath, bPath}
	if gotPaths[0] != wantPaths[0] || gotPaths[1] != wantPaths[1] {
		t.Fatalf("unexpected duplicate paths: got=%v want=%v", gotPaths, wantPaths)
	}

	if stats.hashed != 2 {
		t.Fatalf("expected hashed=2, got %d", stats.hashed)
	}
	if stats.cacheHits != 0 {
		t.Fatalf("expected cacheHits=0, got %d", stats.cacheHits)
	}
	if stats.skippedTooSmall != 1 {
		t.Fatalf("expected skippedTooSmall=1, got %d", stats.skippedTooSmall)
	}
}

func TestFindDuplicateGroupsUsesXattrCache(t *testing.T) {
	root := t.TempDir()

	aPath := filepath.Join(root, "a.bin")
	bPath := filepath.Join(root, "b.bin")
	content := []byte("duplicate-by-cache")
	if err := os.WriteFile(aPath, content, 0o644); err != nil {
		t.Fatalf("write a.bin: %v", err)
	}
	if err := os.WriteFile(bPath, content, 0o644); err != nil {
		t.Fatalf("write b.bin: %v", err)
	}

	infoA, err := os.Stat(aPath)
	if err != nil {
		t.Fatalf("stat a.bin: %v", err)
	}
	infoB, err := os.Stat(bPath)
	if err != nil {
		t.Fatalf("stat b.bin: %v", err)
	}

	sum := blake3.Sum256(content)
	digest := hex.EncodeToString(sum[:])

	if err := writeBlake3Cache(aPath, infoA.ModTime().Unix(), digest); err != nil {
		t.Skipf("xattr cache not writable on this filesystem: %v", err)
	}
	if err := writeBlake3Cache(bPath, infoB.ModTime().Unix(), digest); err != nil {
		t.Skipf("xattr cache not writable on this filesystem: %v", err)
	}

	groups, stats, err := findDuplicateGroups(dupesOptions{
		root:        root,
		minSize:     1,
		useCache:    true,
		updateCache: false,
		verbose:     false,
	})
	if err != nil {
		t.Fatalf("findDuplicateGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 duplicate group, got %d", len(groups))
	}
	if stats.cacheHits != 2 {
		t.Fatalf("expected cacheHits=2, got %d", stats.cacheHits)
	}
	if stats.hashed != 0 {
		t.Fatalf("expected hashed=0, got %d", stats.hashed)
	}
}

func TestRunDupesCommandJSONOutput(t *testing.T) {
	root := t.TempDir()

	aPath := filepath.Join(root, "a.txt")
	bPath := filepath.Join(root, "b.txt")
	if err := os.WriteFile(aPath, []byte("dupe-json"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(bPath, []byte("dupe-json"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runDupesCommand([]string{"-cache=false", "-output", "json", root})
	})
	if err != nil {
		t.Fatalf("runDupesCommand json: %v", err)
	}

	var payload dupesJSONOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal dupes json output: %v\noutput=%s", err, out)
	}

	if payload.Summary.Groups != 1 {
		t.Fatalf("expected summary.groups=1, got %d", payload.Summary.Groups)
	}
	if payload.Summary.DuplicateFiles != 2 {
		t.Fatalf("expected summary.duplicate_files=2, got %d", payload.Summary.DuplicateFiles)
	}
	if len(payload.Groups) != 1 || len(payload.Groups[0].Paths) != 2 {
		t.Fatalf("unexpected groups payload: %+v", payload.Groups)
	}
}

func TestRunDupesCommandPaths0Output(t *testing.T) {
	root := t.TempDir()

	aPath := filepath.Join(root, "a.txt")
	bPath := filepath.Join(root, "b.txt")
	if err := os.WriteFile(aPath, []byte("dupe-paths0"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(bPath, []byte("dupe-paths0"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runDupesCommand([]string{"-cache=false", "-output", "paths0", root})
	})
	if err != nil {
		t.Fatalf("runDupesCommand paths0: %v", err)
	}

	parts := strings.Split(out, "\x00")
	if len(parts) != 2 {
		t.Fatalf("expected 2 NUL-delimited paths, got %d (%q)", len(parts), out)
	}
	sort.Strings(parts)
	if parts[0] != aPath || parts[1] != bPath {
		t.Fatalf("unexpected paths output: %v", parts)
	}
}

func TestRunDupesCommandRejectsInvalidOutputMode(t *testing.T) {
	root := t.TempDir()
	err := runDupesCommand([]string{"-output", "yaml", root})
	if err == nil {
		t.Fatal("expected error for invalid output mode")
	}
	if !strings.Contains(err.Error(), "unsupported output mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = w

	runErr := fn()

	_ = w.Close()
	os.Stdout = orig

	data, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatalf("read captured stdout: %v", readErr)
	}

	return string(data), runErr
}
