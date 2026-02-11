package main

import (
	"testing"
	"time"
)

func TestParseOptionalBoolFlag(t *testing.T) {
	value, err := parseOptionalBoolFlag("", "flag")
	if err != nil {
		t.Fatalf("unexpected error for empty value: %v", err)
	}
	if value != nil {
		t.Fatalf("expected nil value for empty input, got %v", *value)
	}

	value, err = parseOptionalBoolFlag("true", "flag")
	if err != nil {
		t.Fatalf("unexpected error for true value: %v", err)
	}
	if value == nil || !*value {
		t.Fatalf("expected true pointer value, got %v", value)
	}

	if _, err := parseOptionalBoolFlag("not-bool", "flag"); err == nil {
		t.Fatal("expected parse error for invalid boolean input")
	}
}

func TestParseRemoteRolesFlag(t *testing.T) {
	roles := parseRemoteRolesFlag("root, writer; reader ,,")
	if len(roles) != 3 {
		t.Fatalf("expected 3 parsed roles, got %d", len(roles))
	}
	if roles[0] != "root" || roles[1] != "writer" || roles[2] != "reader" {
		t.Fatalf("unexpected parsed roles: %#v", roles)
	}
}

func TestResolveRemoteConfigDocumentExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	preserved, err := resolveRemoteConfigDocumentExpiry(remoteSignedDocumentMetadata{}, remoteDocExpiresPreserve, now)
	if err != nil {
		t.Fatalf("unexpected preserve error without prior expiry: %v", err)
	}
	if preserved != nil {
		t.Fatalf("expected nil preserved expiry, got %v", preserved)
	}

	meta := remoteSignedDocumentMetadata{
		ExpiresAtUTC: "2030-01-02T03:04:05Z",
	}
	preserved, err = resolveRemoteConfigDocumentExpiry(meta, remoteDocExpiresPreserve, now)
	if err != nil {
		t.Fatalf("unexpected preserve parse error: %v", err)
	}
	if preserved == nil || preserved.UTC().Format(time.RFC3339) != "2030-01-02T03:04:05Z" {
		t.Fatalf("unexpected preserved expiry: %v", preserved)
	}

	cleared, err := resolveRemoteConfigDocumentExpiry(meta, 0, now)
	if err != nil {
		t.Fatalf("unexpected clear expiry error: %v", err)
	}
	if cleared != nil {
		t.Fatalf("expected nil expiry when clearing, got %v", cleared)
	}

	shifted, err := resolveRemoteConfigDocumentExpiry(meta, 60, now)
	if err != nil {
		t.Fatalf("unexpected shifted expiry error: %v", err)
	}
	expected := now.Add(60 * time.Second)
	if shifted == nil || !shifted.Equal(expected) {
		t.Fatalf("expected shifted expiry %v, got %v", expected, shifted)
	}
}

func TestFindRemoteTrustNodeIndex(t *testing.T) {
	nodes := []remoteTrustNode{
		{Name: "alpha"},
		{Name: "beta"},
	}
	if got := findRemoteTrustNodeIndex(nodes, "beta"); got != 1 {
		t.Fatalf("expected index 1, got %d", got)
	}
	if got := findRemoteTrustNodeIndex(nodes, "missing"); got != -1 {
		t.Fatalf("expected missing index -1, got %d", got)
	}
}
