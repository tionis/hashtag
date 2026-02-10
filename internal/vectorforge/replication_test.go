package vectorforge

import (
	"net/url"
	"testing"
)

func TestBuildReplicaURL_FromExplicitURL(t *testing.T) {
	cfg := Config{ReplicaURL: "s3://bucket/custom/path?endpoint=http://minio:9000"}

	got, err := buildReplicaURL(cfg)
	if err != nil {
		t.Fatalf("buildReplicaURL error: %v", err)
	}
	if got != cfg.ReplicaURL {
		t.Fatalf("unexpected URL:\n got: %s\nwant: %s", got, cfg.ReplicaURL)
	}
}

func TestBuildReplicaURL_Empty(t *testing.T) {
	raw, err := buildReplicaURL(Config{})
	if err != nil {
		t.Fatalf("buildReplicaURL error: %v", err)
	}
	if raw != "" {
		t.Fatalf("expected empty URL, got %q", raw)
	}
}

func TestMaskURLCredentials(t *testing.T) {
	raw := "s3://user:secret@bucket/path?x=1"
	got := maskURLCredentials(raw)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse masked URL: %v", err)
	}
	if u.User == nil {
		t.Fatalf("expected masked userinfo in URL")
	}
	if user := u.User.Username(); user != "***" {
		t.Fatalf("masked username mismatch: got %q", user)
	}
}
