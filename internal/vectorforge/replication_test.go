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

func TestBuildReplicaTargets(t *testing.T) {
	cfg := Config{
		DBEmbedPath: "/tmp/vector-embeddings.db",
		DBQueuePath: "/tmp/vector-queue.db",
	}

	targets, err := buildReplicaTargets(cfg, "s3://bucket-a/forge-data/vector?endpoint=http://minio:9000&region=eu-central-2")
	if err != nil {
		t.Fatalf("buildReplicaTargets error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 replication targets, got %d", len(targets))
	}

	if targets[0].name != "embeddings" {
		t.Fatalf("unexpected first target name: %q", targets[0].name)
	}
	if targets[0].dbPath != cfg.DBEmbedPath {
		t.Fatalf("unexpected embeddings db path: %q", targets[0].dbPath)
	}
	if targets[0].replicaURL != "s3://bucket-a/forge-data/vector/embeddings?endpoint=http://minio:9000&region=eu-central-2" {
		t.Fatalf("unexpected embeddings replica URL: %q", targets[0].replicaURL)
	}

	if targets[1].name != "queue" {
		t.Fatalf("unexpected second target name: %q", targets[1].name)
	}
	if targets[1].dbPath != cfg.DBQueuePath {
		t.Fatalf("unexpected queue db path: %q", targets[1].dbPath)
	}
	if targets[1].replicaURL != "s3://bucket-a/forge-data/vector/queue?endpoint=http://minio:9000&region=eu-central-2" {
		t.Fatalf("unexpected queue replica URL: %q", targets[1].replicaURL)
	}
}

func TestAppendReplicaURLPath(t *testing.T) {
	got, err := appendReplicaURLPath("s3://bucket-a/forge-data/vector/?region=eu-central-2", "queue")
	if err != nil {
		t.Fatalf("appendReplicaURLPath error: %v", err)
	}
	want := "s3://bucket-a/forge-data/vector/queue?region=eu-central-2"
	if got != want {
		t.Fatalf("appendReplicaURLPath mismatch:\n got: %s\nwant: %s", got, want)
	}
}
