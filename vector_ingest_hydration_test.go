package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildVectorEmbeddingsReplicaURL(t *testing.T) {
	bootstrap := remoteS3Bootstrap{
		Bucket:         "bucket-a",
		Region:         "eu-central-2",
		EndpointURL:    "s3.example.test",
		ForcePathStyle: true,
	}
	cfg := remoteGlobalConfig{
		S3: remoteGlobalS3Config{
			ObjectPrefix: "forge-data",
		},
	}

	raw, err := buildVectorEmbeddingsReplicaURL(bootstrap, cfg)
	if err != nil {
		t.Fatalf("buildVectorEmbeddingsReplicaURL error: %v", err)
	}

	expected := "s3://bucket-a/forge-data/vector/embeddings?endpoint=https%3A%2F%2Fs3.example.test&forcePathStyle=true&region=eu-central-2"
	if raw != expected {
		t.Fatalf("replica URL mismatch:\n got: %s\nwant: %s", raw, expected)
	}
}

func TestAppendURLPath(t *testing.T) {
	got, err := appendURLPath("s3://bucket-a/forge-data/vector/?region=eu-central-2", "queue")
	if err != nil {
		t.Fatalf("appendURLPath error: %v", err)
	}
	want := "s3://bucket-a/forge-data/vector/queue?region=eu-central-2"
	if got != want {
		t.Fatalf("appendURLPath mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestLogHydrationFallback_ExistingLocalDB(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "hydrated.db")
	if err := os.WriteFile(targetPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed local hydrated db: %v", err)
	}

	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)
	logHydrationFallback(logger, targetPath, "restore failed")
	out := buf.String()
	if !strings.Contains(out, "using existing local hydrated DB") {
		t.Fatalf("expected existing DB fallback log, got %q", out)
	}
}

func TestLogHydrationFallback_MissingLocalDB(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "missing.db")

	buf := &bytes.Buffer{}
	logger := log.New(buf, "", 0)
	logHydrationFallback(logger, targetPath, "no remote snapshot available")
	out := buf.String()
	if !strings.Contains(out, "continuing without hydrated precheck DB") {
		t.Fatalf("expected missing DB fallback log, got %q", out)
	}
}
