package main

import "testing"

func TestNormalizeBlobRefsNodeID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "simple", in: "node-a", want: "node-a"},
		{name: "trim and sanitize", in: " node a /x ", want: "node_a__x"},
		{name: "allow separators", in: "ed25519:abc123@example", want: "ed25519:abc123@example"},
		{name: "empty", in: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeBlobRefsNodeID(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeBlobRefsNodeID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRemoteBlobRefsObjectKey(t *testing.T) {
	cfg := remoteGlobalConfig{
		S3: remoteGlobalS3Config{
			ObjectPrefix: "forge-data",
		},
	}

	got := remoteBlobRefsObjectKey(cfg, "", "node/a")
	want := "forge-data/gc/node-refs/node_a.json"
	if got != want {
		t.Fatalf("remoteBlobRefsObjectKey mismatch: got %q want %q", got, want)
	}

	gotCustom := remoteBlobRefsObjectKey(cfg, "gc/custom", "node-a")
	wantCustom := "forge-data/gc/custom/node-a.json"
	if gotCustom != wantCustom {
		t.Fatalf("remoteBlobRefsObjectKey custom mismatch: got %q want %q", gotCustom, wantCustom)
	}
}

func TestLiveBlobCIDsSortedAndHash(t *testing.T) {
	live := map[string]struct{}{
		"b000000000000000000000000000000000000000000000000000000000000000": {},
		"a000000000000000000000000000000000000000000000000000000000000000": {},
	}

	cids := liveBlobCIDsSorted(live)
	if len(cids) != 2 {
		t.Fatalf("expected 2 sorted cids, got %d", len(cids))
	}
	if cids[0] != "a000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("expected cids[0] to be sorted ascending, got %q", cids[0])
	}
	if cids[1] != "b000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("expected cids[1] to be sorted ascending, got %q", cids[1])
	}

	hash := blobCIDSetHash(cids)
	if _, err := parseDigestHex32(hash); err != nil {
		t.Fatalf("blobCIDSetHash should be a digest hex string: %v", err)
	}
}

func TestBlobRefsPublishNoRootsEnabled(t *testing.T) {
	err := runBlobRefsPublishCommand([]string{
		"-no-snapshot-refs",
		"-no-vector-refs",
		"-output", "kv",
	})
	if err == nil {
		t.Fatal("expected error when all roots are disabled")
	}
}
