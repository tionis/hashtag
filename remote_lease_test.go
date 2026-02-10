package main

import (
	"strings"
	"testing"
)

func TestDeriveVectorLeaseMode(t *testing.T) {
	tests := []struct {
		name string
		caps remoteS3Capabilities
		want string
	}{
		{
			name: "hard mode when full CAS available",
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: true,
				ConditionalIfMatch:     true,
			},
			want: vectorLeaseModeHard,
		},
		{
			name: "soft mode when only if-none-match",
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: true,
				ConditionalIfMatch:     false,
			},
			want: vectorLeaseModeSoft,
		},
		{
			name: "soft mode when no CAS support",
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: false,
				ConditionalIfMatch:     false,
			},
			want: vectorLeaseModeSoft,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveVectorLeaseMode(tc.caps)
			if got != tc.want {
				t.Fatalf("deriveVectorLeaseMode mismatch: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestVectorWriterLeaseObjectKey(t *testing.T) {
	cfg := remoteGlobalConfig{
		S3: remoteGlobalS3Config{
			ObjectPrefix: "forge-data",
		},
	}
	got := vectorWriterLeaseObjectKey(cfg, vectorLeaseResourceName)
	want := "forge-data/leases/vector/embeddings-writer.json"
	if got != want {
		t.Fatalf("vectorWriterLeaseObjectKey mismatch: got %q want %q", got, want)
	}
}

func TestDefaultVectorLeaseOwnerID(t *testing.T) {
	got := defaultVectorLeaseOwnerID()
	if strings.TrimSpace(got) == "" {
		t.Fatal("defaultVectorLeaseOwnerID must not be empty")
	}
	if !strings.Contains(got, ":") {
		t.Fatalf("defaultVectorLeaseOwnerID should include host:pid, got %q", got)
	}
}
