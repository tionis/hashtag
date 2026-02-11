package main

import (
	cryptoRand "crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/ssh"
)

const (
	forgeTrustSigningKeyEnv    = "FORGE_TRUST_SIGNING_KEY"
	remoteSignedDocumentSchema = "forge.signed_document.v1"
	remoteDocumentTypeConfig   = "remote_config"
	remoteSignatureNamespace   = "forge-remote-config-v1"
	defaultRemoteRootNodeName  = "root"
)

//go:embed forge.pub
var compiledTrustRootKeysText string

var trustedRootPublicKeysLoader = loadCompiledTrustedRootPublicKeys

type remoteTrustNode struct {
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	Roles     []string `json:"roles,omitempty"`
	Revoked   bool     `json:"revoked,omitempty"`
}

type remoteGlobalTrustConfig struct {
	Nodes []remoteTrustNode `json:"nodes,omitempty"`
}

type remoteSignedDocument struct {
	Schema          string          `json:"schema"`
	DocumentType    string          `json:"document_type"`
	Version         int64           `json:"version"`
	IssuedAtUTC     string          `json:"issued_at_utc"`
	ExpiresAtUTC    string          `json:"expires_at_utc,omitempty"`
	SignerPublicKey string          `json:"signer_public_key"`
	SignatureFormat string          `json:"signature_format"`
	Signature       string          `json:"signature"`
	Payload         json.RawMessage `json:"payload"`
}

type remoteSignedDocumentMetadata struct {
	DocumentType      string
	Version           int64
	PayloadHash       string
	SignerPublicKey   string
	SignerFingerprint string
	ExpiresAtUTC      string
	ExpiresAtNS       int64
}

type remoteTrustStateRow struct {
	Version     int64
	PayloadHash string
}

func loadRemoteSigningKey(path string) (ssh.Signer, string, string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, "", "", fmt.Errorf("remote config signing key is required (set -signing-key or %s)", forgeTrustSigningKeyEnv)
	}
	raw, err := os.ReadFile(trimmed)
	if err != nil {
		return nil, "", "", fmt.Errorf("read signing key %q: %w", trimmed, err)
	}
	parsed, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse signing key %q: %w", trimmed, err)
	}
	signer, err := ssh.NewSignerFromKey(parsed)
	if err != nil {
		return nil, "", "", fmt.Errorf("create signer from %q: %w", trimmed, err)
	}
	authorized := normalizeAuthorizedKey(signer.PublicKey())
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	return signer, authorized, fingerprint, nil
}

func parseAuthorizedKeyString(raw string) (ssh.PublicKey, string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, "", fmt.Errorf("empty authorized key")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, "", err
	}
	authorized := normalizeAuthorizedKey(pub)
	return pub, authorized, nil
}

func normalizeAuthorizedKey(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func loadTrustedRootPublicKeys() (map[string]ssh.PublicKey, error) {
	return trustedRootPublicKeysLoader()
}

func loadCompiledTrustedRootPublicKeys() (map[string]ssh.PublicKey, error) {
	keys := make([]string, 0)
	for _, line := range strings.Split(compiledTrustRootKeysText, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		keys = append(keys, trimmed)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no compiled trusted root keys configured in forge.pub")
	}

	roots := make(map[string]ssh.PublicKey, len(keys))
	for _, raw := range keys {
		pub, _, err := parseAuthorizedKeyString(raw)
		if err != nil {
			return nil, fmt.Errorf("parse trusted root key %q: %w", raw, err)
		}
		roots[ssh.FingerprintSHA256(pub)] = pub
	}
	return roots, nil
}

func ensureTrustedRootSigner(pub ssh.PublicKey) error {
	roots, err := loadTrustedRootPublicKeys()
	if err != nil {
		return err
	}
	fp := ssh.FingerprintSHA256(pub)
	if _, ok := roots[fp]; !ok {
		return fmt.Errorf("signer public key fingerprint %q is not trusted by configured roots", fp)
	}
	return nil
}

func canonicalizeJSON(raw []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func remoteSignatureMessage(docType string, version int64, issuedAtUTC string, expiresAtUTC string, signerAuthorized string, payloadHash string) []byte {
	lines := []string{
		remoteSignatureNamespace,
		"document_type=" + strings.TrimSpace(docType),
		fmt.Sprintf("version=%d", version),
		"issued_at_utc=" + strings.TrimSpace(issuedAtUTC),
		"expires_at_utc=" + strings.TrimSpace(expiresAtUTC),
		"signer_public_key=" + strings.TrimSpace(signerAuthorized),
		"payload_blake3=" + strings.TrimSpace(payloadHash),
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func createSignedRemoteConfigDocument(cfg remoteGlobalConfig, signer ssh.Signer, version int64, issuedAt time.Time, expiresAt *time.Time) ([]byte, remoteSignedDocumentMetadata, error) {
	if version <= 0 {
		return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("signed document version must be > 0")
	}
	if signer == nil {
		return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("signer is required")
	}
	if err := ensureTrustedRootSigner(signer.PublicKey()); err != nil {
		return nil, remoteSignedDocumentMetadata{}, err
	}

	payloadRaw, err := json.Marshal(cfg)
	if err != nil {
		return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("marshal config payload: %w", err)
	}
	payloadCanonical, err := canonicalizeJSON(payloadRaw)
	if err != nil {
		return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("canonicalize config payload: %w", err)
	}
	payloadHash := blake3.Sum256(payloadCanonical)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	issuedAt = issuedAt.UTC()
	expiresAtUTC := ""
	expiresAtNS := int64(0)
	if expiresAt != nil {
		expires := expiresAt.UTC()
		if !expires.After(issuedAt) {
			return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("document expiry must be after issued-at")
		}
		expiresAtUTC = expires.Format(time.RFC3339Nano)
		expiresAtNS = expires.UnixNano()
	}

	signerAuthorized := normalizeAuthorizedKey(signer.PublicKey())
	message := remoteSignatureMessage(
		remoteDocumentTypeConfig,
		version,
		issuedAt.Format(time.RFC3339Nano),
		expiresAtUTC,
		signerAuthorized,
		payloadHashHex,
	)
	sig, err := signer.Sign(cryptoRand.Reader, message)
	if err != nil {
		return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("sign remote config document: %w", err)
	}

	doc := remoteSignedDocument{
		Schema:          remoteSignedDocumentSchema,
		DocumentType:    remoteDocumentTypeConfig,
		Version:         version,
		IssuedAtUTC:     issuedAt.Format(time.RFC3339Nano),
		ExpiresAtUTC:    expiresAtUTC,
		SignerPublicKey: signerAuthorized,
		SignatureFormat: strings.TrimSpace(sig.Format),
		Signature:       base64.StdEncoding.EncodeToString(sig.Blob),
		Payload:         json.RawMessage(payloadCanonical),
	}
	documentRaw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, remoteSignedDocumentMetadata{}, fmt.Errorf("marshal signed remote config document: %w", err)
	}
	documentRaw = append(documentRaw, '\n')

	return documentRaw, remoteSignedDocumentMetadata{
		DocumentType:      remoteDocumentTypeConfig,
		Version:           version,
		PayloadHash:       payloadHashHex,
		SignerPublicKey:   signerAuthorized,
		SignerFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		ExpiresAtUTC:      expiresAtUTC,
		ExpiresAtNS:       expiresAtNS,
	}, nil
}

func decodeSignedRemoteDocumentEnvelope(raw []byte) (remoteSignedDocument, error) {
	doc := remoteSignedDocument{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return remoteSignedDocument{}, fmt.Errorf("decode signed remote document JSON: %w", err)
	}
	if strings.TrimSpace(doc.Schema) != remoteSignedDocumentSchema {
		return remoteSignedDocument{}, fmt.Errorf("unexpected signed document schema %q", doc.Schema)
	}
	if strings.TrimSpace(doc.DocumentType) == "" {
		return remoteSignedDocument{}, fmt.Errorf("signed document missing document_type")
	}
	if doc.Version <= 0 {
		return remoteSignedDocument{}, fmt.Errorf("signed document version must be > 0")
	}
	if strings.TrimSpace(doc.IssuedAtUTC) == "" {
		return remoteSignedDocument{}, fmt.Errorf("signed document missing issued_at_utc")
	}
	if strings.TrimSpace(doc.SignerPublicKey) == "" {
		return remoteSignedDocument{}, fmt.Errorf("signed document missing signer_public_key")
	}
	if strings.TrimSpace(doc.SignatureFormat) == "" {
		return remoteSignedDocument{}, fmt.Errorf("signed document missing signature_format")
	}
	if strings.TrimSpace(doc.Signature) == "" {
		return remoteSignedDocument{}, fmt.Errorf("signed document missing signature")
	}
	if len(doc.Payload) == 0 {
		return remoteSignedDocument{}, fmt.Errorf("signed document missing payload")
	}
	return doc, nil
}

func decodeAndValidateSignedRemoteGlobalConfig(raw []byte, bootstrap remoteS3Bootstrap) (remoteGlobalConfig, remoteSignedDocumentMetadata, error) {
	doc, err := decodeSignedRemoteDocumentEnvelope(raw)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, err
	}
	if doc.DocumentType != remoteDocumentTypeConfig {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("unsupported signed document type %q", doc.DocumentType)
	}

	issuedAt, err := time.Parse(time.RFC3339Nano, doc.IssuedAtUTC)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("parse signed document issued_at_utc: %w", err)
	}
	expiresAtUTC := strings.TrimSpace(doc.ExpiresAtUTC)
	expiresAtNS := int64(0)
	if expiresAtUTC != "" {
		expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtUTC)
		if err != nil {
			return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("parse signed document expires_at_utc: %w", err)
		}
		expiresAtNS = expiresAt.UTC().UnixNano()
		if time.Now().UTC().After(expiresAt.UTC()) {
			return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("signed remote config document expired at %s", expiresAt.UTC().Format(time.RFC3339))
		}
	}

	signerPub, signerAuthorized, err := parseAuthorizedKeyString(doc.SignerPublicKey)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("parse signed document signer key: %w", err)
	}
	roots, err := loadTrustedRootPublicKeys()
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, err
	}
	signerFP := ssh.FingerprintSHA256(signerPub)
	if _, ok := roots[signerFP]; !ok {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("signed remote config signer fingerprint %q is not trusted", signerFP)
	}

	payloadCanonical, err := canonicalizeJSON(doc.Payload)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("canonicalize signed config payload: %w", err)
	}
	payloadHash := blake3.Sum256(payloadCanonical)
	payloadHashHex := hex.EncodeToString(payloadHash[:])

	message := remoteSignatureMessage(
		doc.DocumentType,
		doc.Version,
		issuedAt.UTC().Format(time.RFC3339Nano),
		expiresAtUTC,
		signerAuthorized,
		payloadHashHex,
	)
	sigBlob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(doc.Signature))
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("decode signed config signature: %w", err)
	}
	if err := signerPub.Verify(message, &ssh.Signature{
		Format: strings.TrimSpace(doc.SignatureFormat),
		Blob:   sigBlob,
	}); err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, fmt.Errorf("verify signed remote config signature: %w", err)
	}

	cfg, err := decodeAndValidateRemoteGlobalConfig(payloadCanonical, bootstrap)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, err
	}

	return cfg, remoteSignedDocumentMetadata{
		DocumentType:      doc.DocumentType,
		Version:           doc.Version,
		PayloadHash:       payloadHashHex,
		SignerPublicKey:   signerAuthorized,
		SignerFingerprint: signerFP,
		ExpiresAtUTC:      expiresAtUTC,
		ExpiresAtNS:       expiresAtNS,
	}, nil
}

func extractSignedDocumentVersion(raw []byte) (int64, bool) {
	doc, err := decodeSignedRemoteDocumentEnvelope(raw)
	if err != nil {
		return 0, false
	}
	if doc.DocumentType != remoteDocumentTypeConfig {
		return 0, false
	}
	return doc.Version, true
}

func normalizeAndValidateRemoteTrustNodes(nodes []remoteTrustNode) ([]remoteTrustNode, error) {
	if len(nodes) == 0 {
		return nil, nil
	}
	out := make([]remoteTrustNode, 0, len(nodes))
	seenNames := make(map[string]struct{}, len(nodes))
	seenFingerprints := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		name := strings.TrimSpace(node.Name)
		if name == "" {
			return nil, fmt.Errorf("trust node name must not be empty")
		}
		if _, exists := seenNames[name]; exists {
			return nil, fmt.Errorf("duplicate trust node name %q", name)
		}
		pub, authorized, err := parseAuthorizedKeyString(node.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parse trust node %q public key: %w", name, err)
		}
		fp := ssh.FingerprintSHA256(pub)
		if _, exists := seenFingerprints[fp]; exists {
			return nil, fmt.Errorf("duplicate trust node public key fingerprint %q", fp)
		}
		roles := normalizeRemoteTrustRoles(node.Roles)
		seenNames[name] = struct{}{}
		seenFingerprints[fp] = struct{}{}
		out = append(out, remoteTrustNode{
			Name:      name,
			PublicKey: authorized,
			Roles:     roles,
			Revoked:   node.Revoked,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func normalizeRemoteTrustRoles(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(raw))
	roles := make([]string, 0, len(raw))
	for _, role := range raw {
		normalized := strings.ToLower(strings.TrimSpace(role))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		roles = append(roles, normalized)
	}
	sort.Strings(roles)
	if len(roles) == 0 {
		return nil
	}
	return roles
}

func loadRemoteTrustNodesFromFile(path string) ([]remoteTrustNode, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(trimmed)
	if err != nil {
		return nil, fmt.Errorf("read trust nodes file %q: %w", trimmed, err)
	}

	var asList []remoteTrustNode
	if err := json.Unmarshal(raw, &asList); err == nil {
		return asList, nil
	}
	var wrapped struct {
		Nodes []remoteTrustNode `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("decode trust nodes file %q: %w", trimmed, err)
	}
	return wrapped.Nodes, nil
}

func lookupRemoteTrustState(db *sql.DB, key remoteConfigCacheKey, documentType string) (remoteTrustStateRow, bool, error) {
	row := remoteTrustStateRow{}
	err := db.QueryRow(
		`SELECT version, payload_hash
		 FROM remote_trust_state
		 WHERE endpoint_url = ?
		   AND region = ?
		   AND bucket = ?
		   AND config_key = ?
		   AND force_path_style = ?
		   AND document_type = ?`,
		key.EndpointURL,
		key.Region,
		key.Bucket,
		key.ConfigKey,
		key.ForcePathStyle,
		documentType,
	).Scan(&row.Version, &row.PayloadHash)
	if err == sql.ErrNoRows {
		return remoteTrustStateRow{}, false, nil
	}
	if err != nil {
		return remoteTrustStateRow{}, false, fmt.Errorf("query remote trust state: %w", err)
	}
	return row, true, nil
}

func enforceRemoteDocumentTrustState(db *sql.DB, key remoteConfigCacheKey, meta remoteSignedDocumentMetadata, now time.Time) error {
	if strings.TrimSpace(meta.DocumentType) == "" {
		return fmt.Errorf("signed document metadata missing document type")
	}
	if meta.Version <= 0 {
		return fmt.Errorf("signed document metadata version must be > 0")
	}
	if strings.TrimSpace(meta.PayloadHash) == "" {
		return fmt.Errorf("signed document metadata payload hash must not be empty")
	}

	current, found, err := lookupRemoteTrustState(db, key, meta.DocumentType)
	if err != nil {
		return err
	}
	if found {
		if meta.Version < current.Version {
			return fmt.Errorf("signed document rollback detected for %s: version %d is older than accepted version %d", meta.DocumentType, meta.Version, current.Version)
		}
		if meta.Version == current.Version && strings.TrimSpace(meta.PayloadHash) != strings.TrimSpace(current.PayloadHash) {
			return fmt.Errorf("signed document conflict detected for %s version %d: payload hash mismatch", meta.DocumentType, meta.Version)
		}
	}

	if _, err := db.Exec(
		`INSERT INTO remote_trust_state(
			endpoint_url,
			region,
			bucket,
			config_key,
			force_path_style,
			document_type,
			version,
			payload_hash,
			signer_fingerprint,
			verified_at_ns,
			updated_at_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(endpoint_url, region, bucket, config_key, force_path_style, document_type)
		DO UPDATE SET
			version = CASE
				WHEN excluded.version > remote_trust_state.version THEN excluded.version
				ELSE remote_trust_state.version
			END,
			payload_hash = CASE
				WHEN excluded.version > remote_trust_state.version THEN excluded.payload_hash
				ELSE remote_trust_state.payload_hash
			END,
			signer_fingerprint = CASE
				WHEN excluded.version > remote_trust_state.version THEN excluded.signer_fingerprint
				ELSE remote_trust_state.signer_fingerprint
			END,
			verified_at_ns = excluded.verified_at_ns,
			updated_at_ns = excluded.updated_at_ns`,
		key.EndpointURL,
		key.Region,
		key.Bucket,
		key.ConfigKey,
		key.ForcePathStyle,
		meta.DocumentType,
		meta.Version,
		meta.PayloadHash,
		strings.TrimSpace(meta.SignerFingerprint),
		now.UnixNano(),
		now.UnixNano(),
	); err != nil {
		return fmt.Errorf("upsert remote trust state: %w", err)
	}
	return nil
}
