package main

import (
	"strings"
	"testing"
	"time"
)

func TestResolveVectorLeaseMode(t *testing.T) {
	tests := []struct {
		name string
		mode string
		caps remoteS3Capabilities
		want string
		err  bool
	}{
		{
			name: "hard mode when full CAS available",
			mode: vectorLeaseModeAuto,
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: true,
				ConditionalIfMatch:     true,
			},
			want: vectorLeaseModeHard,
		},
		{
			name: "soft mode when only if-none-match",
			mode: vectorLeaseModeAuto,
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: true,
				ConditionalIfMatch:     false,
			},
			want: vectorLeaseModeSoft,
		},
		{
			name: "soft mode when no CAS support",
			mode: vectorLeaseModeAuto,
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: false,
				ConditionalIfMatch:     false,
			},
			want: vectorLeaseModeSoft,
		},
		{
			name: "off mode",
			mode: vectorLeaseModeOff,
			caps: remoteS3Capabilities{},
			want: vectorLeaseModeOff,
		},
		{
			name: "explicit hard fails without capabilities",
			mode: vectorLeaseModeHard,
			caps: remoteS3Capabilities{
				ConditionalIfNoneMatch: true,
				ConditionalIfMatch:     false,
			},
			err: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveVectorLeaseMode(tc.mode, tc.caps)
			if tc.err {
				if err == nil {
					t.Fatal("expected mode resolution error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveVectorLeaseMode error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolveVectorLeaseMode mismatch: got %q want %q", got, tc.want)
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
	got := vectorWriterLeaseObjectKey(cfg, defaultVectorLeaseResource)
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

func TestVectorLeaseAcquireDelayForAttempt(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{name: "negative attempt clamps to initial", attempt: -1, want: 2 * time.Second},
		{name: "initial attempt", attempt: 0, want: 2 * time.Second},
		{name: "second attempt", attempt: 1, want: 4 * time.Second},
		{name: "third attempt", attempt: 2, want: 8 * time.Second},
		{name: "max cap reached", attempt: 5, want: 30 * time.Second},
		{name: "max cap stays", attempt: 20, want: 30 * time.Second},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := vectorLeaseAcquireDelayForAttempt(tc.attempt)
			if got != tc.want {
				t.Fatalf("vectorLeaseAcquireDelayForAttempt(%d) = %s, want %s", tc.attempt, got, tc.want)
			}
		})
	}
}
