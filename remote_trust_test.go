package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
	"golang.org/x/crypto/ssh"
)

func mustSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create ssh signer: %v", err)
	}
	return signer
}

func withTrustedRootSigners(t *testing.T, signers ...ssh.Signer) {
	t.Helper()
	old := trustedRootPublicKeysLoader
	trustedRootPublicKeysLoader = func() (map[string]ssh.PublicKey, error) {
		roots := make(map[string]ssh.PublicKey, len(signers))
		for _, signer := range signers {
			if signer == nil {
				continue
			}
			pub := signer.PublicKey()
			roots[ssh.FingerprintSHA256(pub)] = pub
		}
		if len(roots) == 0 {
			return nil, fmt.Errorf("no trusted root keys configured")
		}
		return roots, nil
	}
	t.Cleanup(func() {
		trustedRootPublicKeysLoader = old
	})
}

func TestSignedRemoteConfigRoundTrip(t *testing.T) {
	signer := mustSSHSigner(t)
	withTrustedRootSigners(t, signer)

	bootstrap := remoteS3Bootstrap{
		Bucket:    "bucket-a",
		ConfigKey: "forge/config.json",
	}
	cfg := defaultRemoteGlobalConfig()
	cfg.Trust.Nodes = []remoteTrustNode{
		{
			Name:      "root",
			PublicKey: normalizeAuthorizedKey(signer.PublicKey()),
			Roles:     []string{"root"},
		},
	}
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		t.Fatalf("normalize config: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)
	raw, signedMeta, err := createSignedRemoteConfigDocument(cfg, signer, 17, now, &expires)
	if err != nil {
		t.Fatalf("create signed remote config document: %v", err)
	}
	if signedMeta.Version != 17 {
		t.Fatalf("expected signed meta version 17, got %d", signedMeta.Version)
	}

	decodedCfg, decodedMeta, err := decodeAndValidateSignedRemoteGlobalConfig(raw, bootstrap)
	if err != nil {
		t.Fatalf("decode/verify signed remote config: %v", err)
	}
	if decodedMeta.Version != 17 {
		t.Fatalf("expected decoded version 17, got %d", decodedMeta.Version)
	}
	if decodedMeta.SignerFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("unexpected signer fingerprint: %q", decodedMeta.SignerFingerprint)
	}
	if len(decodedCfg.Trust.Nodes) != 1 || decodedCfg.Trust.Nodes[0].Name != "root" {
		t.Fatalf("expected root trust node in decoded payload, got %+v", decodedCfg.Trust.Nodes)
	}
}

func TestSignedRemoteConfigRejectsUntrustedSigner(t *testing.T) {
	signingKey := mustSSHSigner(t)
	otherRoot := mustSSHSigner(t)
	withTrustedRootSigners(t, otherRoot)

	bootstrap := remoteS3Bootstrap{
		Bucket:    "bucket-a",
		ConfigKey: "forge/config.json",
	}
	cfg := defaultRemoteGlobalConfig()
	cfg.Trust.Nodes = []remoteTrustNode{
		{
			Name:      "root",
			PublicKey: normalizeAuthorizedKey(signingKey.PublicKey()),
			Roles:     []string{"root"},
		},
	}
	if err := normalizeAndValidateRemoteGlobalConfig(&cfg, bootstrap); err != nil {
		t.Fatalf("normalize config: %v", err)
	}

	raw, _, err := createSignedRemoteConfigDocument(cfg, signingKey, 1, time.Now().UTC(), nil)
	if err == nil {
		t.Fatal("expected signing with untrusted root to fail")
	}
	// Re-sign using trusted root and verify decode now fails when roots change.
	withTrustedRootSigners(t, signingKey)
	raw, _, err = createSignedRemoteConfigDocument(cfg, signingKey, 1, time.Now().UTC(), nil)
	if err != nil {
		t.Fatalf("create signed remote config with trusted signer: %v", err)
	}
	withTrustedRootSigners(t, otherRoot)
	_, _, err = decodeAndValidateSignedRemoteGlobalConfig(raw, bootstrap)
	if err == nil {
		t.Fatal("expected decode to reject untrusted signer")
	}
}

func TestEnforceRemoteDocumentTrustState(t *testing.T) {
	temp := t.TempDir()
	t.Setenv(forgeconfig.EnvRemoteDBPath, filepath.Join(temp, "remote.db"))
	db, err := openRemoteConfigDB(defaultRemoteDBPath())
	if err != nil {
		t.Fatalf("open remote db: %v", err)
	}
	defer db.Close()

	key := remoteConfigCacheKey{
		EndpointURL:    "s3.example.test",
		Region:         "eu-central-2",
		Bucket:         "bucket-a",
		ConfigKey:      "forge/config.json",
		ForcePathStyle: 0,
	}
	now := time.Now().UTC()
	initial := remoteSignedDocumentMetadata{
		DocumentType:      remoteDocumentTypeConfig,
		Version:           10,
		PayloadHash:       "hash-a",
		SignerFingerprint: "fp-a",
	}
	if err := enforceRemoteDocumentTrustState(db, key, initial, now); err != nil {
		t.Fatalf("enforce initial trust state: %v", err)
	}

	rollback := remoteSignedDocumentMetadata{
		DocumentType:      remoteDocumentTypeConfig,
		Version:           9,
		PayloadHash:       "hash-old",
		SignerFingerprint: "fp-a",
	}
	if err := enforceRemoteDocumentTrustState(db, key, rollback, now); err == nil {
		t.Fatal("expected rollback version to fail")
	}

	conflict := remoteSignedDocumentMetadata{
		DocumentType:      remoteDocumentTypeConfig,
		Version:           10,
		PayloadHash:       "hash-conflict",
		SignerFingerprint: "fp-b",
	}
	if err := enforceRemoteDocumentTrustState(db, key, conflict, now); err == nil {
		t.Fatal("expected same-version hash conflict to fail")
	}

	newer := remoteSignedDocumentMetadata{
		DocumentType:      remoteDocumentTypeConfig,
		Version:           11,
		PayloadHash:       "hash-new",
		SignerFingerprint: "fp-c",
	}
	if err := enforceRemoteDocumentTrustState(db, key, newer, now); err != nil {
		t.Fatalf("enforce newer trust state: %v", err)
	}
}
