package main

import "testing"

func TestBuildVectorReplicaURL(t *testing.T) {
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

	raw, err := buildVectorReplicaURL(bootstrap, cfg)
	if err != nil {
		t.Fatalf("buildVectorReplicaURL error: %v", err)
	}

	expected := "s3://bucket-a/forge-data/vector/embeddings?endpoint=https%3A%2F%2Fs3.example.test&forcePathStyle=true&region=eu-central-2"
	if raw != expected {
		t.Fatalf("replica URL mismatch:\n got: %s\nwant: %s", raw, expected)
	}
}

func TestEnsureHTTPSEndpointScheme(t *testing.T) {
	if got := ensureHTTPSEndpointScheme("minio:9000"); got != "https://minio:9000" {
		t.Fatalf("unexpected endpoint scheme result: %q", got)
	}
	if got := ensureHTTPSEndpointScheme("http://localhost:9000"); got != "http://localhost:9000" {
		t.Fatalf("unexpected preserved endpoint result: %q", got)
	}
}
