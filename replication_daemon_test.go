package main

import (
	"strings"
	"testing"
)

func TestBuildBackgroundReplicaTargets(t *testing.T) {
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

	targets, err := buildBackgroundReplicaTargets(bootstrap, cfg, "node-a", "/tmp/snapshot.db", "/tmp/refs.db")
	if err != nil {
		t.Fatalf("buildBackgroundReplicaTargets error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	if targets[0].Name != "snapshot" {
		t.Fatalf("unexpected first target name: %q", targets[0].Name)
	}
	if !targets[0].UseAgeCrypto {
		t.Fatal("expected snapshot target to use age encryption")
	}
	if !strings.Contains(targets[0].ReplicaURL, "s3://bucket-a/forge-data/db/snapshot?") {
		t.Fatalf("unexpected snapshot replica URL: %q", targets[0].ReplicaURL)
	}

	if targets[1].Name != "refs" {
		t.Fatalf("unexpected second target name: %q", targets[1].Name)
	}
	if targets[1].UseAgeCrypto {
		t.Fatal("expected refs target to be unencrypted")
	}
	if !strings.Contains(targets[1].ReplicaURL, "s3://bucket-a/forge-data/gc/node-refs/node-a/refs?") {
		t.Fatalf("unexpected refs replica URL: %q", targets[1].ReplicaURL)
	}
}

func TestResolveReplicationNodePublicKey(t *testing.T) {
	nodeSigner := mustSSHSigner(t)
	overrideSigner := mustSSHSigner(t)
	cfg := remoteGlobalConfig{
		Trust: remoteGlobalTrustConfig{
			Nodes: []remoteTrustNode{
				{
					Name:      "node-a",
					PublicKey: normalizeAuthorizedKey(nodeSigner.PublicKey()),
				},
			},
		},
	}

	got, err := resolveReplicationNodePublicKey(cfg, "node-a", "")
	if err != nil {
		t.Fatalf("resolveReplicationNodePublicKey from trust map: %v", err)
	}
	if got != normalizeAuthorizedKey(nodeSigner.PublicKey()) {
		t.Fatalf("unexpected trust-map node key: %q", got)
	}

	override := normalizeAuthorizedKey(overrideSigner.PublicKey())
	got, err = resolveReplicationNodePublicKey(cfg, "node-a", override)
	if err != nil {
		t.Fatalf("resolveReplicationNodePublicKey override: %v", err)
	}
	if got != override {
		t.Fatalf("unexpected override node key: %q", got)
	}
}
