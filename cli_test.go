package main

import "testing"

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
	if _, _, err := root.Find([]string{"snapshot", "inspect"}); err != nil {
		t.Fatalf("expected snapshot inspect command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"snapshot", "query"}); err != nil {
		t.Fatalf("expected snapshot query command to be registered: %v", err)
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
}
