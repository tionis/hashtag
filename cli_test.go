package main

import (
	stderrors "errors"
	"testing"
)

func TestExecuteCLIDisallowsLegacyHashShorthand(t *testing.T) {
	if err := executeCLI([]string{"-algos", "blake3"}); err == nil {
		t.Fatal("expected error for legacy top-level hash flag shorthand")
	}
	if err := executeCLI([]string{"."}); err == nil {
		t.Fatal("expected error for legacy top-level path shorthand")
	}
	if err := executeCLI([]string{"tag"}); err == nil {
		t.Fatal("expected error for removed hash alias command")
	}
}

func TestRootCommandContainsCoreTools(t *testing.T) {
	root := newRootCommand()
	if _, _, err := root.Find([]string{"hash"}); err != nil {
		t.Fatalf("expected hash command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"dupes"}); err != nil {
		t.Fatalf("expected dupes command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"snapshot"}); err != nil {
		t.Fatalf("expected snapshot command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"hashmap"}); err != nil {
		t.Fatalf("expected hashmap command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"tags"}); err != nil {
		t.Fatalf("expected tags command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"remote"}); err != nil {
		t.Fatalf("expected remote command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"blob"}); err != nil {
		t.Fatalf("expected blob command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"snapshot", "inspect"}); err != nil {
		t.Fatalf("expected snapshot inspect command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"snapshot", "query"}); err != nil {
		t.Fatalf("expected snapshot query command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"snapshot", "remote"}); err != nil {
		t.Fatalf("expected snapshot remote command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"hashmap", "ingest"}); err != nil {
		t.Fatalf("expected hashmap ingest command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"hashmap", "lookup"}); err != nil {
		t.Fatalf("expected hashmap lookup command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"hashmap", "show"}); err != nil {
		t.Fatalf("expected hashmap show command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"tags", "get"}); err != nil {
		t.Fatalf("expected tags get command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"tags", "set"}); err != nil {
		t.Fatalf("expected tags set command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"tags", "add"}); err != nil {
		t.Fatalf("expected tags add command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"tags", "remove"}); err != nil {
		t.Fatalf("expected tags remove command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"tags", "clear"}); err != nil {
		t.Fatalf("expected tags clear command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"remote", "config", "init"}); err != nil {
		t.Fatalf("expected remote config init command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"remote", "config", "show"}); err != nil {
		t.Fatalf("expected remote config show command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"blob", "put"}); err != nil {
		t.Fatalf("expected blob put command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"blob", "get"}); err != nil {
		t.Fatalf("expected blob get command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"blob", "ls"}); err != nil {
		t.Fatalf("expected blob ls command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"blob", "rm"}); err != nil {
		t.Fatalf("expected blob rm command to be registered: %v", err)
	}
}

func TestResolveCLIExitCode(t *testing.T) {
	if got := resolveCLIExitCode(nil); got != 0 {
		t.Fatalf("expected nil error to resolve exit code 0, got %d", got)
	}

	if got := resolveCLIExitCode(stderrors.New("boom")); got != exitCodeFailure {
		t.Fatalf("expected regular error to resolve exit code %d, got %d", exitCodeFailure, got)
	}

	partial := newCLIExitError(exitCodePartialWarnings, stderrors.New("partial"))
	if got := resolveCLIExitCode(partial); got != exitCodePartialWarnings {
		t.Fatalf("expected partial warning error to resolve exit code %d, got %d", exitCodePartialWarnings, got)
	}
}
