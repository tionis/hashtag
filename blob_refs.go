package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zeebo/blake3"
)

const (
	forgeNodeIDEnv             = "FORGE_NODE_ID"
	defaultBlobRefsObjectPath  = "gc/node-refs"
	defaultBlobRefsTTLSeconds  = 86400
	blobNodeReferenceSetSchema = "forge.blob_refs.v1"
)

type blobNodeReferenceSet struct {
	Schema              string   `json:"schema"`
	NodeID              string   `json:"node_id"`
	GeneratedAtUTC      string   `json:"generated_at_utc"`
	ExpiresAtUTC        string   `json:"expires_at_utc,omitempty"`
	SnapshotRefsEnabled bool     `json:"snapshot_refs_enabled"`
	VectorRefsEnabled   bool     `json:"vector_refs_enabled"`
	SnapshotRefsFound   int      `json:"snapshot_refs_found"`
	VectorRefsFound     int      `json:"vector_refs_found"`
	CIDCount            int      `json:"cid_count"`
	CIDSetHash          string   `json:"cid_set_hash"`
	CIDs                []string `json:"cids"`
}

type blobRefsPublishOutput struct {
	NodeID              string `json:"node_id"`
	Bucket              string `json:"bucket"`
	ObjectKey           string `json:"object_key"`
	ETag                string `json:"etag,omitempty"`
	GeneratedAtUTC      string `json:"generated_at_utc"`
	ExpiresAtUTC        string `json:"expires_at_utc,omitempty"`
	SnapshotRefsEnabled bool   `json:"snapshot_refs_enabled"`
	VectorRefsEnabled   bool   `json:"vector_refs_enabled"`
	SnapshotRefsFound   int    `json:"snapshot_refs_found"`
	VectorRefsFound     int    `json:"vector_refs_found"`
	CIDCount            int    `json:"cid_count"`
	CIDSetHash          string `json:"cid_set_hash"`
}

func runBlobRefsPublishCommand(args []string) error {
	defaultSnapshot := defaultSnapshotDBPath()
	defaultVectorQueue := defaultVectorQueueDBPathForGC()

	fs := flag.NewFlagSet("blob refs publish", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s blob refs publish [options]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Publish this node's live blob CID reference set to remote S3 for global GC workflows.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	nodeID := fs.String("node", defaultBlobRefsNodeID(), "Logical node ID for this published reference set")
	prefix := fs.String("prefix", defaultBlobRefsObjectPath, "Object key prefix (under object-prefix) for published node reference sets")
	ttlSeconds := fs.Int("ttl", defaultBlobRefsTTLSeconds, "Reference set expiry TTL in seconds (0 disables expiry timestamp)")
	snapshotDBPath := fs.String("snapshot-db", defaultSnapshot, "Path to snapshot database for tree-entry references")
	vectorQueueDBPath := fs.String("vector-queue-db", defaultVectorQueue, "Path to vector queue database for payload references")
	noSnapshotRefs := fs.Bool("no-snapshot-refs", false, "Disable snapshot tree-entry references as publish roots")
	noVectorRefs := fs.Bool("no-vector-refs", false, "Disable vector queue references as publish roots")
	includeErrorJobs := fs.Bool("include-error-jobs", true, "Treat vector queue status=error jobs as publish roots")
	outputMode := fs.String("output", outputModeAuto, "Output mode: auto|pretty|kv|json")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	snapshotRefsEnabled := !*noSnapshotRefs
	vectorRefsEnabled := !*noVectorRefs
	if !snapshotRefsEnabled && !vectorRefsEnabled {
		return fmt.Errorf("no reference roots enabled; keep at least one of snapshot/vector references")
	}

	normalizedNodeID := normalizeBlobRefsNodeID(*nodeID)
	if normalizedNodeID == "" {
		return fmt.Errorf("node id resolves to empty value")
	}

	normalizedPrefix := normalizeS3Prefix(*prefix)
	if normalizedPrefix == "" {
		normalizedPrefix = defaultBlobRefsObjectPath
	}

	absSnapshotPath := ""
	if snapshotRefsEnabled {
		absSnapshotPath, err = filepathAbsIfSet(*snapshotDBPath)
		if err != nil {
			return fmt.Errorf("resolve snapshot db path: %w", err)
		}
	}
	absVectorQueuePath := ""
	if vectorRefsEnabled {
		absVectorQueuePath, err = filepathAbsIfSet(*vectorQueueDBPath)
		if err != nil {
			return fmt.Errorf("resolve vector queue db path: %w", err)
		}
	}

	live := make(map[string]struct{})
	snapshotFound := 0
	vectorFound := 0
	if snapshotRefsEnabled {
		snapshotFound, err = collectLiveBlobRefsFromSnapshotDB(absSnapshotPath, live)
		if err != nil {
			return err
		}
	}
	if vectorRefsEnabled {
		vectorFound, err = collectLiveBlobRefsFromVectorQueueDB(absVectorQueuePath, *includeErrorJobs, live)
		if err != nil {
			return err
		}
	}
	cids := liveBlobCIDsSorted(live)
	setHash := blobCIDSetHash(cids)

	generatedAt := time.Now().UTC()
	expiresAt := time.Time{}
	if *ttlSeconds > 0 {
		expiresAt = generatedAt.Add(time.Duration(*ttlSeconds) * time.Second)
	}

	doc := blobNodeReferenceSet{
		Schema:              blobNodeReferenceSetSchema,
		NodeID:              normalizedNodeID,
		GeneratedAtUTC:      generatedAt.Format(time.RFC3339Nano),
		SnapshotRefsEnabled: snapshotRefsEnabled,
		VectorRefsEnabled:   vectorRefsEnabled,
		SnapshotRefsFound:   snapshotFound,
		VectorRefsFound:     vectorFound,
		CIDCount:            len(cids),
		CIDSetHash:          setHash,
		CIDs:                cids,
	}
	if !expiresAt.IsZero() {
		doc.ExpiresAtUTC = expiresAt.UTC().Format(time.RFC3339Nano)
	}

	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal blob reference set JSON: %w", err)
	}
	payload = append(payload, '\n')

	ctx := context.Background()
	session, err := loadRemoteBackendSession(ctx)
	if err != nil {
		return err
	}
	client, err := session.newS3Client(ctx)
	if err != nil {
		return err
	}
	objectKey := remoteBlobRefsObjectKey(session.Config, normalizedPrefix, normalizedNodeID)
	resp, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(session.Bootstrap.Bucket),
		Key:         aws.String(objectKey),
		Body:        bytes.NewReader(payload),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("write node blob refs object s3://%s/%s: %w", session.Bootstrap.Bucket, objectKey, err)
	}

	output := blobRefsPublishOutput{
		NodeID:              normalizedNodeID,
		Bucket:              session.Bootstrap.Bucket,
		ObjectKey:           objectKey,
		ETag:                strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\""),
		GeneratedAtUTC:      doc.GeneratedAtUTC,
		ExpiresAtUTC:        doc.ExpiresAtUTC,
		SnapshotRefsEnabled: snapshotRefsEnabled,
		VectorRefsEnabled:   vectorRefsEnabled,
		SnapshotRefsFound:   snapshotFound,
		VectorRefsFound:     vectorFound,
		CIDCount:            len(cids),
		CIDSetHash:          setHash,
	}
	return renderBlobRefsPublishOutput(resolvedOutputMode, output)
}

func defaultBlobRefsNodeID() string {
	if configured := strings.TrimSpace(os.Getenv(forgeNodeIDEnv)); configured != "" {
		return configured
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "unknown-host"
	}
	return hostname
}

func normalizeBlobRefsNodeID(nodeID string) string {
	raw := strings.TrimSpace(nodeID)
	if raw == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(raw))
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			builder.WriteRune(ch)
		case ch >= 'A' && ch <= 'Z':
			builder.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			builder.WriteRune(ch)
		case ch == '.', ch == '_', ch == '-', ch == ':', ch == '@':
			builder.WriteRune(ch)
		default:
			builder.WriteByte('_')
		}
	}
	normalized := strings.Trim(builder.String(), "._-")
	return normalized
}

func remoteBlobRefsObjectKey(cfg remoteGlobalConfig, prefix string, nodeID string) string {
	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	prefix = normalizeS3Prefix(prefix)
	if prefix == "" {
		prefix = defaultBlobRefsObjectPath
	}
	normalizedNodeID := normalizeBlobRefsNodeID(nodeID)
	if normalizedNodeID == "" {
		normalizedNodeID = "unknown-node"
	}
	parts := make([]string, 0, 4)
	if base != "" {
		parts = append(parts, base)
	}
	parts = append(parts, prefix, normalizedNodeID+".json")
	return strings.Join(parts, "/")
}

func liveBlobCIDsSorted(live map[string]struct{}) []string {
	if len(live) == 0 {
		return nil
	}
	cids := make([]string, 0, len(live))
	for cid := range live {
		cids = append(cids, cid)
	}
	sort.Strings(cids)
	return cids
}

func blobCIDSetHash(cids []string) string {
	hasher := blake3.New()
	for _, cid := range cids {
		hasher.Write([]byte(strings.TrimSpace(cid)))
		hasher.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func filepathAbsIfSet(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func renderBlobRefsPublishOutput(mode string, output blobRefsPublishOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("node_id=%s\n", output.NodeID)
		fmt.Printf("bucket=%s\n", output.Bucket)
		fmt.Printf("object_key=%s\n", output.ObjectKey)
		fmt.Printf("etag=%s\n", output.ETag)
		fmt.Printf("generated_at_utc=%s\n", output.GeneratedAtUTC)
		fmt.Printf("expires_at_utc=%s\n", output.ExpiresAtUTC)
		fmt.Printf("snapshot_refs_enabled=%t\n", output.SnapshotRefsEnabled)
		fmt.Printf("vector_refs_enabled=%t\n", output.VectorRefsEnabled)
		fmt.Printf("snapshot_refs_found=%d\n", output.SnapshotRefsFound)
		fmt.Printf("vector_refs_found=%d\n", output.VectorRefsFound)
		fmt.Printf("cid_count=%d\n", output.CIDCount)
		fmt.Printf("cid_set_hash=%s\n", output.CIDSetHash)
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Blob Refs Published")
		printPrettyFields([]outputField{
			{Label: "Node ID", Value: output.NodeID},
			{Label: "Bucket", Value: output.Bucket},
			{Label: "Object Key", Value: output.ObjectKey},
			{Label: "ETag", Value: output.ETag},
			{Label: "Generated At", Value: output.GeneratedAtUTC},
			{Label: "Expires At", Value: output.ExpiresAtUTC},
			{Label: "Snapshot Refs Enabled", Value: strconv.FormatBool(output.SnapshotRefsEnabled)},
			{Label: "Vector Refs Enabled", Value: strconv.FormatBool(output.VectorRefsEnabled)},
			{Label: "Snapshot Refs Found", Value: strconv.Itoa(output.SnapshotRefsFound)},
			{Label: "Vector Refs Found", Value: strconv.Itoa(output.VectorRefsFound)},
			{Label: "CID Count", Value: strconv.Itoa(output.CIDCount)},
			{Label: "CID Set Hash", Value: output.CIDSetHash},
		})
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}
