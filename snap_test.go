package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withMockSnapper(t *testing.T, fn snapperExecFunc) {
	t.Helper()
	orig := runSnapperCommand
	runSnapperCommand = fn
	t.Cleanup(func() {
		runSnapperCommand = orig
	})
}

func TestResolveSnapContextSelectsLongestSubvolume(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	target := filepath.Join(work, "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	withMockSnapper(t, func(args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "--jsonout list-configs" {
			t.Fatalf("unexpected snapper args: %q", strings.Join(args, " "))
		}
		return []byte(`{"configs":[{"config":"root","subvolume":"/"},{"config":"work","subvolume":"` + work + `"}]}`), nil
	})

	ctx, err := resolveSnapContext(target, "", false)
	if err != nil {
		t.Fatalf("resolve snap context: %v", err)
	}
	if ctx.Config != "work" {
		t.Fatalf("expected config=work, got %q", ctx.Config)
	}
	if ctx.Subvolume != work {
		t.Fatalf("expected subvolume=%q, got %q", work, ctx.Subvolume)
	}
}

func TestRunSnapLogCommandJSONIncludesStats(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	calls := make([]string, 0)
	withMockSnapper(t, func(args ...string) ([]byte, error) {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "--jsonout list-configs":
			return []byte(`{"configs":[{"config":"home","subvolume":"` + root + `"}]}`), nil
		case "-c home --jsonout list --disable-used-space --columns number,type,date,description,userdata,cleanup,pre-number":
			return []byte(`{"snapshots":[{"number":10,"type":"single","date":"2026-03-01 10:00:00","description":"a"},{"number":11,"type":"single","date":"2026-03-01 11:00:00","description":"b"},{"number":12,"type":"single","date":"2026-03-01 12:00:00","description":"c"}]}`), nil
		case "-c home status 10..11":
			return []byte("+ file-a\nc file-b\n"), nil
		case "-c home status 11..12":
			return []byte("- file-c\nt file-d\n"), nil
		default:
			t.Fatalf("unexpected snapper args: %q", call)
			return nil, nil
		}
	})

	stdout, err := captureStdout(t, func() error {
		return runSnapLogCommand([]string{"-path", target, "-output", "json"})
	})
	if err != nil {
		t.Fatalf("run snap log: %v", err)
	}

	var out snapLogOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal snap log output: %v\n%s", err, stdout)
	}
	if out.Count != 3 {
		t.Fatalf("expected 3 entries, got %d", out.Count)
	}
	if !out.Entries[1].HasStat || out.Entries[1].Summary.Total != 2 || out.Entries[1].Summary.Added != 1 {
		t.Fatalf("unexpected entry[1] summary: %#v", out.Entries[1])
	}
	if !out.Entries[2].HasStat || out.Entries[2].Summary.Removed != 1 || out.Entries[2].Summary.TypeChange != 1 {
		t.Fatalf("unexpected entry[2] summary: %#v", out.Entries[2])
	}
	if len(calls) != 4 {
		t.Fatalf("expected 4 snapper calls, got %d (%v)", len(calls), calls)
	}
}

func TestRunSnapStatusDefaultsToLatestCurrent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	withMockSnapper(t, func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "--jsonout list-configs":
			return []byte(`{"configs":[{"config":"home","subvolume":"` + root + `"}]}`), nil
		case "-c home --jsonout list --disable-used-space --columns number,type,date,description,userdata,cleanup,pre-number":
			return []byte(`{"snapshots":[{"number":4,"type":"single","date":"x"},{"number":7,"type":"single","date":"y"}]}`), nil
		case "-c home status 7..0":
			return []byte("+ one\nc two\n- three\n"), nil
		default:
			t.Fatalf("unexpected snapper args: %q", strings.Join(args, " "))
			return nil, nil
		}
	})

	stdout, err := captureStdout(t, func() error {
		return runSnapStatusCommand([]string{"-path", target, "-output", "json"})
	})
	if err != nil {
		t.Fatalf("run snap status: %v", err)
	}

	var out snapStatusOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal snap status output: %v\n%s", err, stdout)
	}
	if out.Range != "7..0" {
		t.Fatalf("expected range 7..0, got %q", out.Range)
	}
	if out.Summary.Total != 3 || out.Summary.Added != 1 || out.Summary.Removed != 1 || out.Summary.Modified != 1 {
		t.Fatalf("unexpected summary: %#v", out.Summary)
	}
}

func TestRunSnapRestoreApplyUsesUndochange(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	calls := make([]string, 0)
	withMockSnapper(t, func(args ...string) ([]byte, error) {
		call := strings.Join(args, " ")
		calls = append(calls, call)
		switch call {
		case "--jsonout list-configs":
			return []byte(`{"configs":[{"config":"home","subvolume":"` + root + `"}]}`), nil
		case "-c home --jsonout list --disable-used-space --columns number,type,date,description,userdata,cleanup,pre-number":
			return []byte(`{"snapshots":[{"number":3,"type":"single","date":"x"}]}`), nil
		case "-c home undochange 3..0 project/sub/one.txt":
			return []byte("done\n"), nil
		default:
			t.Fatalf("unexpected snapper args: %q", call)
			return nil, nil
		}
	})

	stdout, err := captureStdout(t, func() error {
		return runSnapRestoreCommand([]string{"-path", target, "-apply", "-output", "json", "sub/one.txt"})
	})
	if err != nil {
		t.Fatalf("run snap restore apply: %v", err)
	}

	var out snapRestoreOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal snap restore output: %v\n%s", err, stdout)
	}
	if !out.Apply {
		t.Fatal("expected apply=true")
	}
	if len(out.Files) != 1 || out.Files[0] != "project/sub/one.txt" {
		t.Fatalf("unexpected normalized files: %v", out.Files)
	}
	if out.SnapperStdio != "done" {
		t.Fatalf("unexpected snapper stdio: %q", out.SnapperStdio)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d (%v)", len(calls), calls)
	}
}

func TestRunSnapRestorePreviewFiltersChanges(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "project")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	withMockSnapper(t, func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "--jsonout list-configs":
			return []byte(`{"configs":[{"config":"home","subvolume":"` + root + `"}]}`), nil
		case "-c home --jsonout list --disable-used-space --columns number,type,date,description,userdata,cleanup,pre-number":
			return []byte(`{"snapshots":[{"number":9,"type":"single","date":"x"}]}`), nil
		case "-c home status 9..0":
			return []byte("+ project/sub/new.txt\nc project/other.txt\n"), nil
		default:
			t.Fatalf("unexpected snapper args: %q", strings.Join(args, " "))
			return nil, nil
		}
	})

	stdout, err := captureStdout(t, func() error {
		return runSnapRestoreCommand([]string{"-path", target, "-output", "json", "sub"})
	})
	if err != nil {
		t.Fatalf("run snap restore preview: %v", err)
	}

	var out snapRestoreOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("unmarshal snap restore output: %v\n%s", err, stdout)
	}
	if out.Apply {
		t.Fatal("expected preview mode (apply=false)")
	}
	if out.Summary.Total != 1 || out.Summary.Added != 1 {
		t.Fatalf("unexpected preview summary: %#v", out.Summary)
	}
	if len(out.Changes) != 1 || out.Changes[0].Path != "project/sub/new.txt" {
		t.Fatalf("unexpected preview changes: %#v", out.Changes)
	}
}
