package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	flag "github.com/spf13/pflag"
	"io"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
	_ "modernc.org/sqlite"
)

const (
	envImageEmbeddingsURL   = "FORGE_IMAGE_EMBEDDINGS_URL"
	envImageEmbeddingsToken = "FORGE_IMAGE_EMBEDDINGS_TOKEN"
	envImageEmbeddingsModel = "FORGE_IMAGE_EMBEDDINGS_MODEL"
	envEmbeddingsEndpoint   = "EMBEDDINGS_ENDPOINT"
	envEmbeddingsToken      = "EMBEDDINGS_TOKEN"

	defaultImageEmbeddingsURL   = "https://embeddings.tionis.dev"
	defaultImageEmbeddingsModel = "ViT-SO400M-16-SigLIP2-384__webli"

	defaultSnapshotEmbedSampleLimit = 20
	defaultSnapshotSimilarLimit     = 20

	hashAlgoSHA256 = "sha256"
)

var snapshotImageExtensions = map[string]struct{}{
	".avif": {},
	".bmp":  {},
	".gif":  {},
	".heic": {},
	".heif": {},
	".jpeg": {},
	".jpg":  {},
	".png":  {},
	".tif":  {},
	".tiff": {},
	".webp": {},
}

type snapshotImageHashGroup struct {
	Hash  string
	Paths []string
}

type snapshotEmbedEntryOutput struct {
	Path   string `json:"path"`
	Hash   string `json:"hash"`
	Copies int    `json:"copies"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type snapshotEmbedOutput struct {
	Path            string                     `json:"path"`
	SnapshotTimeNS  int64                      `json:"snapshot_time_ns"`
	SnapshotTimeUTC string                     `json:"snapshot_time_utc"`
	TreeHash        string                     `json:"tree_hash"`
	EmbedDB         string                     `json:"embed_db"`
	BackendURL      string                     `json:"backend_url,omitempty"`
	StoredModel     string                     `json:"stored_model,omitempty"`
	RequestedModel  string                     `json:"requested_model,omitempty"`
	Apply           bool                       `json:"apply"`
	Strict          bool                       `json:"strict"`
	ImagePaths      int                        `json:"image_paths"`
	UniqueHashes    int                        `json:"unique_hashes"`
	PresentHashes   int                        `json:"present_hashes"`
	MissingHashes   int                        `json:"missing_hashes"`
	SelectedHashes  int                        `json:"selected_hashes"`
	EligibleHashes  int                        `json:"eligible_hashes"`
	GeneratedHashes int                        `json:"generated_hashes"`
	WarningCount    int                        `json:"warning_count"`
	FailureCount    int                        `json:"failure_count"`
	Entries         []snapshotEmbedEntryOutput `json:"entries"`
}

type snapshotSimilarMatchOutput struct {
	Path   string  `json:"path"`
	Hash   string  `json:"hash"`
	Copies int     `json:"copies"`
	Score  float64 `json:"score"`
}

type snapshotSimilarOutput struct {
	Path            string                       `json:"path"`
	SnapshotTimeNS  int64                        `json:"snapshot_time_ns"`
	SnapshotTimeUTC string                       `json:"snapshot_time_utc"`
	TreeHash        string                       `json:"tree_hash"`
	EmbedDB         string                       `json:"embed_db"`
	StoredModel     string                       `json:"stored_model,omitempty"`
	QueryPath       string                       `json:"query_path"`
	QueryHash       string                       `json:"query_hash"`
	CandidateCount  int                          `json:"candidate_count"`
	MatchCount      int                          `json:"match_count"`
	Matches         []snapshotSimilarMatchOutput `json:"matches"`
}

type embeddingProxyClient struct {
	baseURL string
	token   string
	model   string
	client  *http.Client
}

type snapshotImageExternalHashes struct {
	ContentSHA256  string
	CacheKeySHA256 string
}

func runSnapshotEmbedCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()
	defaultEmbedDB := forgeconfig.VectorEmbedDBPath()
	defaultBackendURL := firstNonEmptyEnv(envImageEmbeddingsURL, envEmbeddingsEndpoint)
	if defaultBackendURL == "" {
		defaultBackendURL = defaultImageEmbeddingsURL
	}
	defaultModel := strings.TrimSpace(os.Getenv(envImageEmbeddingsModel))
	if defaultModel == "" {
		defaultModel = defaultImageEmbeddingsModel
	}

	fs := flag.NewFlagSet("snapshot embed", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snapshot embed [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Preview or create missing image embeddings for the latest local tree snapshot.")
		fmt.Fprintln(fs.Output(), "Preview is the default. Use -apply to call the backend and write embeddings.")
		fmt.Fprintln(fs.Output(), "\nEnvironment:")
		fmt.Fprintf(fs.Output(), "  %s or %s (default %s)\n", envImageEmbeddingsURL, envEmbeddingsEndpoint, defaultImageEmbeddingsURL)
		fmt.Fprintf(fs.Output(), "  %s or %s (required for -apply)\n", envImageEmbeddingsToken, envEmbeddingsToken)
		fmt.Fprintf(fs.Output(), "  %s (default %s)\n", envImageEmbeddingsModel, defaultImageEmbeddingsModel)
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	embedDBPath := fs.String("embed-db", defaultEmbedDB, "Path to image embeddings database")
	backendURL := fs.String("backend-url", defaultBackendURL, "Embedding backend base URL")
	token := fs.String("token", firstNonEmptyEnv(envImageEmbeddingsToken, envEmbeddingsToken), "Embedding backend bearer token")
	model := fs.String("model", defaultModel, "Embedding model name")
	apply := fs.BoolP("apply", "a", false, "Create missing embeddings (default is preview only)")
	strict := fs.BoolP("strict", "s", false, "Fail if current files are missing or changed since the selected snapshot")
	limit := fs.IntP("limit", "n", 0, "Maximum number of missing hashes to inspect or embed (0 means all)")
	sampleLimit := fs.Int("sample-limit", defaultSnapshotEmbedSampleLimit, "Maximum number of selected hashes to include in output")
	httpTimeout := fs.Duration("http-timeout", 120*time.Second, "HTTP request timeout for backend calls")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *limit < 0 {
		return fmt.Errorf("-limit must be >= 0")
	}
	if *sampleLimit < 0 {
		return fmt.Errorf("-sample-limit must be >= 0")
	}
	if *httpTimeout <= 0 {
		return fmt.Errorf("-http-timeout must be > 0")
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}

	targetPath := fs.Arg(0)
	if targetPath == "" {
		targetPath = "."
	}
	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}
	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	absEmbedDBPath, err := filepath.Abs(*embedDBPath)
	if err != nil {
		return fmt.Errorf("resolve embed db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	pointer, err := resolveLatestSnapshotTreePointer(db, absTargetPath)
	if err != nil {
		return err
	}
	groups, imagePaths, err := collectSnapshotImageHashGroups(db, pointer.TargetHash)
	if err != nil {
		return err
	}

	hashes := make([]string, 0, len(groups))
	for _, group := range groups {
		hashes = append(hashes, group.Hash)
	}

	presentHashes := map[string]struct{}{}
	storedModel := ""
	if len(hashes) > 0 {
		presentHashes, storedModel, err = readImageEmbeddingPresence(absEmbedDBPath, hashes)
		if err != nil {
			return err
		}
	}

	requestedModel := strings.TrimSpace(*model)
	if storedModel != "" && requestedModel != "" && storedModel != requestedModel {
		return fmt.Errorf("embed db model mismatch: stored=%q requested=%q", storedModel, requestedModel)
	}

	missingGroups := make([]snapshotImageHashGroup, 0)
	for _, group := range groups {
		if _, exists := presentHashes[group.Hash]; exists {
			continue
		}
		missingGroups = append(missingGroups, group)
	}
	if *limit > 0 && len(missingGroups) > *limit {
		missingGroups = missingGroups[:*limit]
	}

	output := snapshotEmbedOutput{
		Path:            pointer.Path,
		SnapshotTimeNS:  pointer.SnapshotTimeNS,
		SnapshotTimeUTC: time.Unix(0, pointer.SnapshotTimeNS).UTC().Format(time.RFC3339Nano),
		TreeHash:        pointer.TargetHash,
		EmbedDB:         absEmbedDBPath,
		StoredModel:     storedModel,
		RequestedModel:  requestedModel,
		Apply:           *apply,
		Strict:          *strict,
		ImagePaths:      imagePaths,
		UniqueHashes:    len(groups),
		PresentHashes:   len(presentHashes),
		MissingHashes:   len(groups) - len(presentHashes),
		SelectedHashes:  len(missingGroups),
		Entries:         make([]snapshotEmbedEntryOutput, 0, minInt(len(missingGroups), *sampleLimit)),
	}

	var proxy *embeddingProxyClient
	var embedWriteDB *sql.DB
	cacheAlgo := ""
	mappingsByHash := map[string]map[string]string{}
	cacheHitVectorsByHash := map[string][]byte{}
	cacheMissHashes := map[string]struct{}{}
	failedGroups := make([]string, 0)
	if *apply && len(missingGroups) > 0 {
		if strings.TrimSpace(*backendURL) == "" {
			return fmt.Errorf("-backend-url is required with -apply")
		}
		if strings.TrimSpace(*token) == "" {
			return fmt.Errorf("-token or %s is required with -apply", envImageEmbeddingsToken)
		}
		if strings.TrimSpace(requestedModel) == "" {
			return fmt.Errorf("-model is required with -apply")
		}
		cacheAlgo = embeddingCacheKeyAlgo(requestedModel)
		output.BackendURL = strings.TrimRight(strings.TrimSpace(*backendURL), "/")
		proxy = &embeddingProxyClient{
			baseURL: output.BackendURL,
			token:   strings.TrimSpace(*token),
			model:   requestedModel,
			client:  &http.Client{Timeout: *httpTimeout},
		}
		embedWriteDB, err = openImageEmbeddingDB(absEmbedDBPath, true)
		if err != nil {
			return err
		}
		defer embedWriteDB.Close()

		mappingsByHash, err = loadHashMappingsForBlake3s(db, hashes, []string{hashAlgoSHA256, cacheAlgo})
		if err != nil {
			return err
		}
		cacheKeyToHash := make(map[string]string, len(missingGroups))
		cacheKeys := make([]string, 0, len(missingGroups))
		for _, group := range missingGroups {
			cacheKey := hashMappingDigest(mappingsByHash, group.Hash, cacheAlgo)
			if cacheKey == "" {
				continue
			}
			if _, exists := cacheKeyToHash[cacheKey]; exists {
				continue
			}
			cacheKeyToHash[cacheKey] = group.Hash
			cacheKeys = append(cacheKeys, cacheKey)
		}
		cacheHitsByKey, cacheMissesByKey, lookupErr := proxy.LookupCacheKeys(context.Background(), cacheKeys)
		if lookupErr == nil {
			for cacheKey, vectorJSON := range cacheHitsByKey {
				if hash := strings.TrimSpace(cacheKeyToHash[cacheKey]); hash != "" {
					cacheHitVectorsByHash[hash] = vectorJSON
				}
			}
			for cacheKey := range cacheMissesByKey {
				if hash := strings.TrimSpace(cacheKeyToHash[cacheKey]); hash != "" {
					cacheMissHashes[hash] = struct{}{}
				}
			}
		}
	}

	for _, group := range missingGroups {
		entry := snapshotEmbedEntryOutput{
			Path:   group.Paths[0],
			Hash:   group.Hash,
			Copies: len(group.Paths),
		}
		if !*apply {
			sourcePath, reason := resolveSnapshotLiveImageSource(pointer.Path, group)
			if sourcePath == "" {
				entry.Status = "skipped"
				entry.Reason = reason
				output.WarningCount++
				if *strict {
					failedGroups = append(failedGroups, fmt.Sprintf("%s: %s", group.Paths[0], reason))
				}
			} else {
				entry.Status = "ready"
				output.EligibleHashes++
			}
		} else if vectorJSON, cacheHit := cacheHitVectorsByHash[group.Hash]; cacheHit {
			if upsertErr := upsertImageEmbedding(context.Background(), embedWriteDB, group.Hash, vectorJSON); upsertErr != nil {
				entry.Status = "failed"
				entry.Reason = upsertErr.Error()
				output.FailureCount++
				failedGroups = append(failedGroups, fmt.Sprintf("%s: %v", group.Paths[0], upsertErr))
			} else {
				entry.Status = "generated"
				output.EligibleHashes++
				output.GeneratedHashes++
			}
		} else {
			sourcePath, reason := resolveSnapshotLiveImageSource(pointer.Path, group)
			if sourcePath == "" {
				entry.Status = "skipped"
				entry.Reason = reason
				output.WarningCount++
				if *strict {
					failedGroups = append(failedGroups, fmt.Sprintf("%s: %s", group.Paths[0], reason))
				}
			} else {
				externalHashes := snapshotImageExternalHashes{
					ContentSHA256:  hashMappingDigest(mappingsByHash, group.Hash, hashAlgoSHA256),
					CacheKeySHA256: hashMappingDigest(mappingsByHash, group.Hash, cacheAlgo),
				}
				if externalHashes.ContentSHA256 == "" || externalHashes.CacheKeySHA256 == "" {
					computedHashes, hashErr := computeSnapshotImageExternalHashes(sourcePath, requestedModel)
					if hashErr != nil {
						entry.Status = "failed"
						entry.Reason = hashErr.Error()
						output.FailureCount++
						failedGroups = append(failedGroups, fmt.Sprintf("%s: %v", group.Paths[0], hashErr))
						goto appendEntry
					}
					if externalHashes.ContentSHA256 == "" {
						externalHashes.ContentSHA256 = computedHashes.ContentSHA256
						if upsertErr := upsertHashMapping(db, group.Hash, hashAlgoSHA256, externalHashes.ContentSHA256); upsertErr != nil {
							entry.Status = "failed"
							entry.Reason = upsertErr.Error()
							output.FailureCount++
							failedGroups = append(failedGroups, fmt.Sprintf("%s: %v", group.Paths[0], upsertErr))
							goto appendEntry
						}
						setHashMappingDigest(mappingsByHash, group.Hash, hashAlgoSHA256, externalHashes.ContentSHA256)
					}
					if externalHashes.CacheKeySHA256 == "" {
						externalHashes.CacheKeySHA256 = computedHashes.CacheKeySHA256
						if upsertErr := upsertHashMapping(db, group.Hash, cacheAlgo, externalHashes.CacheKeySHA256); upsertErr != nil {
							entry.Status = "failed"
							entry.Reason = upsertErr.Error()
							output.FailureCount++
							failedGroups = append(failedGroups, fmt.Sprintf("%s: %v", group.Paths[0], upsertErr))
							goto appendEntry
						}
						setHashMappingDigest(mappingsByHash, group.Hash, cacheAlgo, externalHashes.CacheKeySHA256)
					}
				}

				vectorJSON := []byte(nil)
				if externalHashes.CacheKeySHA256 != "" {
					if _, knownMiss := cacheMissHashes[group.Hash]; !knownMiss {
						lookupVector, cacheHit, lookupErr := proxy.LookupCacheKey(context.Background(), externalHashes.CacheKeySHA256)
						if lookupErr == nil && cacheHit {
							vectorJSON = lookupVector
						}
					}
				}
				if vectorJSON == nil {
					var predictErr error
					vectorJSON, predictErr = proxy.PredictFile(context.Background(), sourcePath)
					if predictErr != nil {
						entry.Status = "failed"
						entry.Reason = predictErr.Error()
						output.FailureCount++
						failedGroups = append(failedGroups, fmt.Sprintf("%s: %v", group.Paths[0], predictErr))
						goto appendEntry
					}
				}
				if upsertErr := upsertImageEmbedding(context.Background(), embedWriteDB, group.Hash, vectorJSON); upsertErr != nil {
					entry.Status = "failed"
					entry.Reason = upsertErr.Error()
					output.FailureCount++
					failedGroups = append(failedGroups, fmt.Sprintf("%s: %v", group.Paths[0], upsertErr))
				} else {
					entry.Status = "generated"
					output.EligibleHashes++
					output.GeneratedHashes++
				}
			}
		}
	appendEntry:
		if *sampleLimit == 0 || len(output.Entries) < *sampleLimit {
			output.Entries = append(output.Entries, entry)
		}
	}

	if *apply && embedWriteDB != nil && output.GeneratedHashes > 0 && requestedModel != "" {
		if err := setStoredImageEmbeddingModel(context.Background(), embedWriteDB, requestedModel); err != nil {
			return err
		}
		output.StoredModel = requestedModel
	}

	if err := renderSnapshotEmbedOutput(resolvedOutputMode, output); err != nil {
		return err
	}
	if len(failedGroups) > 0 {
		if *strict && output.WarningCount > 0 && output.FailureCount == 0 {
			return fmt.Errorf("strict snapshot embed validation failed: %s", strings.Join(failedGroups, "; "))
		}
		if output.FailureCount > 0 {
			return fmt.Errorf("snapshot embed failed for %d hash(es): %s", output.FailureCount, strings.Join(failedGroups, "; "))
		}
	}
	if output.WarningCount > 0 {
		log.Printf("[snapshot embed] completed with warnings: %d", output.WarningCount)
		return newCLIExitError(exitCodePartialWarnings, fmt.Errorf("snapshot embed completed with warnings"))
	}
	return nil
}

func runSnapshotSimilarCommand(args []string) error {
	defaultDB := defaultSnapshotDBPath()
	defaultEmbedDB := forgeconfig.VectorEmbedDBPath()

	fs := flag.NewFlagSet("snapshot similar", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s snapshot similar [options] [path]\n\n", os.Args[0])
		fmt.Fprintln(fs.Output(), "Find similar embedded snapshot images using the latest local tree snapshot.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	dbPath := fs.StringP("db", "d", defaultDB, "Path to snapshot database")
	embedDBPath := fs.String("embed-db", defaultEmbedDB, "Path to image embeddings database")
	queryImage := fs.String("image", "", "Snapshot-relative or absolute path to the query image (required)")
	limit := fs.IntP("limit", "n", defaultSnapshotSimilarLimit, "Maximum number of similar results to return")
	outputMode := fs.StringP("output", "o", outputModeAuto, "Output mode: auto|pretty|kv|json")
	applyCommandFlagConventions(fs)
	if err := fs.Parse(normalizePFlagArgs(fs, args)); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *limit < 0 {
		return fmt.Errorf("-limit must be >= 0")
	}

	resolvedOutputMode, err := resolvePrettyKVJSONOutputMode(*outputMode)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*queryImage) == "" {
		return fmt.Errorf("-image is required")
	}

	targetPath := fs.Arg(0)
	if targetPath == "" {
		targetPath = "."
	}
	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve target path: %w", err)
	}
	absDBPath, err := filepath.Abs(*dbPath)
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}
	absEmbedDBPath, err := filepath.Abs(*embedDBPath)
	if err != nil {
		return fmt.Errorf("resolve embed db path: %w", err)
	}

	db, err := openSnapshotDB(absDBPath)
	if err != nil {
		return fmt.Errorf("open snapshot db: %w", err)
	}
	defer db.Close()

	pointer, err := resolveLatestSnapshotTreePointer(db, absTargetPath)
	if err != nil {
		return err
	}
	groups, _, err := collectSnapshotImageHashGroups(db, pointer.TargetHash)
	if err != nil {
		return err
	}

	queryPath, err := normalizeSnapshotQueryImagePath(pointer.Path, *queryImage)
	if err != nil {
		return err
	}

	hashes := make([]string, 0, len(groups))
	var queryGroup snapshotImageHashGroup
	queryFound := false
	for _, group := range groups {
		for _, path := range group.Paths {
			if path == queryPath {
				queryGroup = group
				queryFound = true
			}
		}
		hashes = append(hashes, group.Hash)
	}
	if !queryFound {
		return fmt.Errorf("query image %q not found in latest snapshot for %q", queryPath, pointer.Path)
	}

	embedDB, err := openImageEmbeddingDB(absEmbedDBPath, false)
	if err != nil {
		return err
	}
	defer embedDB.Close()

	storedModel, err := getStoredImageEmbeddingModel(context.Background(), embedDB)
	if err != nil {
		return err
	}
	vectors, err := loadImageEmbeddingVectors(context.Background(), embedDB, hashes)
	if err != nil {
		return err
	}

	queryVector, exists := vectors[queryGroup.Hash]
	if !exists {
		return fmt.Errorf("query image hash %q is not embedded in %s (run snapshot embed -apply first)", queryGroup.Hash, absEmbedDBPath)
	}

	type scoredMatch struct {
		group snapshotImageHashGroup
		score float64
	}
	matches := make([]scoredMatch, 0, len(groups))
	for _, group := range groups {
		if group.Hash == queryGroup.Hash {
			continue
		}
		vector, ok := vectors[group.Hash]
		if !ok {
			continue
		}
		score, scoreErr := cosineSimilarity(queryVector, vector)
		if scoreErr != nil {
			continue
		}
		matches = append(matches, scoredMatch{group: group, score: score})
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score == matches[j].score {
			return matches[i].group.Paths[0] < matches[j].group.Paths[0]
		}
		return matches[i].score > matches[j].score
	})
	if *limit > 0 && len(matches) > *limit {
		matches = matches[:*limit]
	}

	outMatches := make([]snapshotSimilarMatchOutput, 0, len(matches))
	for _, match := range matches {
		outMatches = append(outMatches, snapshotSimilarMatchOutput{
			Path:   match.group.Paths[0],
			Hash:   match.group.Hash,
			Copies: len(match.group.Paths),
			Score:  match.score,
		})
	}

	return renderSnapshotSimilarOutput(
		resolvedOutputMode,
		snapshotSimilarOutput{
			Path:            pointer.Path,
			SnapshotTimeNS:  pointer.SnapshotTimeNS,
			SnapshotTimeUTC: time.Unix(0, pointer.SnapshotTimeNS).UTC().Format(time.RFC3339Nano),
			TreeHash:        pointer.TargetHash,
			EmbedDB:         absEmbedDBPath,
			StoredModel:     storedModel,
			QueryPath:       queryPath,
			QueryHash:       queryGroup.Hash,
			CandidateCount:  len(vectors) - 1,
			MatchCount:      len(outMatches),
			Matches:         outMatches,
		},
	)
}

func renderSnapshotEmbedOutput(mode string, output snapshotEmbedOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("snapshot_time_ns=%d\n", output.SnapshotTimeNS)
		fmt.Printf("snapshot_time_utc=%s\n", output.SnapshotTimeUTC)
		fmt.Printf("tree_hash=%s\n", output.TreeHash)
		fmt.Printf("embed_db=%s\n", output.EmbedDB)
		fmt.Printf("stored_model=%s\n", output.StoredModel)
		fmt.Printf("requested_model=%s\n", output.RequestedModel)
		fmt.Printf("apply=%t\n", output.Apply)
		fmt.Printf("strict=%t\n", output.Strict)
		fmt.Printf("image_paths=%d\n", output.ImagePaths)
		fmt.Printf("unique_hashes=%d\n", output.UniqueHashes)
		fmt.Printf("present_hashes=%d\n", output.PresentHashes)
		fmt.Printf("missing_hashes=%d\n", output.MissingHashes)
		fmt.Printf("selected_hashes=%d\n", output.SelectedHashes)
		fmt.Printf("eligible_hashes=%d\n", output.EligibleHashes)
		fmt.Printf("generated_hashes=%d\n", output.GeneratedHashes)
		fmt.Printf("warning_count=%d\n", output.WarningCount)
		fmt.Printf("failure_count=%d\n", output.FailureCount)
		fmt.Println("path\thash\tcopies\tstatus\treason")
		for _, entry := range output.Entries {
			fmt.Printf("%s\t%s\t%d\t%s\t%s\n", entry.Path, entry.Hash, entry.Copies, entry.Status, entry.Reason)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		title := "Snapshot Embed Preview"
		if output.Apply {
			title = "Snapshot Embed"
		}
		printPrettyTitle(title)
		printPrettyFields([]outputField{
			{Label: "Path", Value: output.Path},
			{Label: "Snapshot Time", Value: fmt.Sprintf("%s (%d)", output.SnapshotTimeUTC, output.SnapshotTimeNS)},
			{Label: "Tree Hash", Value: output.TreeHash},
			{Label: "Embed DB", Value: output.EmbedDB},
			{Label: "Stored Model", Value: output.StoredModel},
			{Label: "Requested Model", Value: output.RequestedModel},
			{Label: "Apply", Value: fmt.Sprintf("%t", output.Apply)},
			{Label: "Strict", Value: fmt.Sprintf("%t", output.Strict)},
		})
		printPrettySection("Summary")
		printPrettyFields([]outputField{
			{Label: "Image Paths", Value: fmt.Sprintf("%d", output.ImagePaths)},
			{Label: "Unique Hashes", Value: fmt.Sprintf("%d", output.UniqueHashes)},
			{Label: "Present Hashes", Value: fmt.Sprintf("%d", output.PresentHashes)},
			{Label: "Missing Hashes", Value: fmt.Sprintf("%d", output.MissingHashes)},
			{Label: "Selected Hashes", Value: fmt.Sprintf("%d", output.SelectedHashes)},
			{Label: "Eligible Hashes", Value: fmt.Sprintf("%d", output.EligibleHashes)},
			{Label: "Generated Hashes", Value: fmt.Sprintf("%d", output.GeneratedHashes)},
			{Label: "Warnings", Value: fmt.Sprintf("%d", output.WarningCount)},
			{Label: "Failures", Value: fmt.Sprintf("%d", output.FailureCount)},
		})
		if len(output.Entries) == 0 {
			return nil
		}
		printPrettySection("Selected Hashes")
		rows := make([][]string, 0, len(output.Entries))
		for _, entry := range output.Entries {
			rows = append(rows, []string{
				entry.Path,
				entry.Hash,
				fmt.Sprintf("%d", entry.Copies),
				entry.Status,
				entry.Reason,
			})
		}
		printPrettyTable([]string{"Path", "Hash", "Copies", "Status", "Reason"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func renderSnapshotSimilarOutput(mode string, output snapshotSimilarOutput) error {
	switch mode {
	case outputModeKV:
		fmt.Printf("path=%s\n", output.Path)
		fmt.Printf("snapshot_time_ns=%d\n", output.SnapshotTimeNS)
		fmt.Printf("snapshot_time_utc=%s\n", output.SnapshotTimeUTC)
		fmt.Printf("tree_hash=%s\n", output.TreeHash)
		fmt.Printf("embed_db=%s\n", output.EmbedDB)
		fmt.Printf("stored_model=%s\n", output.StoredModel)
		fmt.Printf("query_path=%s\n", output.QueryPath)
		fmt.Printf("query_hash=%s\n", output.QueryHash)
		fmt.Printf("candidate_count=%d\n", output.CandidateCount)
		fmt.Printf("match_count=%d\n", output.MatchCount)
		fmt.Println("path\thash\tcopies\tscore")
		for _, match := range output.Matches {
			fmt.Printf("%s\t%s\t%d\t%.6f\n", match.Path, match.Hash, match.Copies, match.Score)
		}
		return nil
	case outputModeJSON:
		return printJSON(output)
	case outputModePretty:
		printPrettyTitle("Snapshot Similar")
		printPrettyFields([]outputField{
			{Label: "Path", Value: output.Path},
			{Label: "Snapshot Time", Value: fmt.Sprintf("%s (%d)", output.SnapshotTimeUTC, output.SnapshotTimeNS)},
			{Label: "Tree Hash", Value: output.TreeHash},
			{Label: "Embed DB", Value: output.EmbedDB},
			{Label: "Stored Model", Value: output.StoredModel},
			{Label: "Query Path", Value: output.QueryPath},
			{Label: "Query Hash", Value: output.QueryHash},
			{Label: "Candidates", Value: fmt.Sprintf("%d", output.CandidateCount)},
			{Label: "Matches", Value: fmt.Sprintf("%d", output.MatchCount)},
		})
		if len(output.Matches) == 0 {
			fmt.Println("No similar embedded snapshot images found.")
			return nil
		}
		printPrettySection("Matches")
		rows := make([][]string, 0, len(output.Matches))
		for _, match := range output.Matches {
			rows = append(rows, []string{
				match.Path,
				match.Hash,
				fmt.Sprintf("%d", match.Copies),
				fmt.Sprintf("%.6f", match.Score),
			})
		}
		printPrettyTable([]string{"Path", "Hash", "Copies", "Score"}, rows)
		return nil
	default:
		return fmt.Errorf("unsupported output mode %q", mode)
	}
}

func resolveLatestSnapshotTreePointer(db *sql.DB, targetPath string) (snapshotPointer, error) {
	resolvedPath, err := resolveSnapshotPointerPath(targetPath)
	if err != nil {
		return snapshotPointer{}, err
	}
	pointers, err := listPointersForPath(db, resolvedPath, 1)
	if err != nil {
		return snapshotPointer{}, err
	}
	if len(pointers) == 0 {
		return snapshotPointer{}, fmt.Errorf("no snapshots found for path %q", resolvedPath)
	}
	if pointers[0].TargetKind != snapshotKindTree {
		return snapshotPointer{}, fmt.Errorf("latest snapshot for %q is %q; image embeddings require a tree snapshot", resolvedPath, pointers[0].TargetKind)
	}
	return pointers[0], nil
}

func collectSnapshotImageHashGroups(db *sql.DB, treeHash string) ([]snapshotImageHashGroup, int, error) {
	records, err := collectTreeEntriesRecursive(db, treeHash)
	if err != nil {
		return nil, 0, err
	}

	pathsByHash := make(map[string][]string)
	imagePaths := 0
	for _, record := range records {
		if record.Entry.Kind != snapshotKindFile {
			continue
		}
		if !isSupportedSnapshotImagePath(record.Path) {
			continue
		}
		imagePaths++
		pathsByHash[record.Entry.TargetHash] = append(pathsByHash[record.Entry.TargetHash], record.Path)
	}

	hashes := make([]string, 0, len(pathsByHash))
	for hash := range pathsByHash {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)

	groups := make([]snapshotImageHashGroup, 0, len(hashes))
	for _, hash := range hashes {
		paths := pathsByHash[hash]
		sort.Strings(paths)
		groups = append(groups, snapshotImageHashGroup{
			Hash:  hash,
			Paths: paths,
		})
	}
	return groups, imagePaths, nil
}

func isSupportedSnapshotImagePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := snapshotImageExtensions[ext]
	return ok
}

func readImageEmbeddingPresence(dbPath string, hashes []string) (map[string]struct{}, string, error) {
	if len(hashes) == 0 {
		return map[string]struct{}{}, "", nil
	}
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, "", nil
		}
		return nil, "", fmt.Errorf("stat embed db %q: %w", dbPath, err)
	}
	db, err := openImageEmbeddingDB(dbPath, false)
	if err != nil {
		return nil, "", err
	}
	defer db.Close()

	present, err := findPresentImageHashes(context.Background(), db, hashes)
	if err != nil {
		return nil, "", err
	}
	storedModel, err := getStoredImageEmbeddingModel(context.Background(), db)
	if err != nil {
		return nil, "", err
	}
	return present, storedModel, nil
}

func resolveSnapshotLiveImageSource(rootPath string, group snapshotImageHashGroup) (string, string) {
	reasons := make([]string, 0, len(group.Paths))
	for _, relPath := range group.Paths {
		candidate := filepath.Join(rootPath, filepath.FromSlash(relPath))
		info, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				reasons = append(reasons, "missing on disk")
				continue
			}
			reasons = append(reasons, err.Error())
			continue
		}
		if !info.Mode().IsRegular() {
			reasons = append(reasons, "not a regular file")
			continue
		}
		currentHash, err := hashRegularFileForSnapshot(candidate, info, false)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		if currentHash != group.Hash {
			reasons = append(reasons, "content hash changed since snapshot")
			continue
		}
		return candidate, ""
	}
	if len(reasons) == 0 {
		return "", "no usable live file matched the snapshot hash"
	}
	return "", reasons[0]
}

func openImageEmbeddingDB(path string, create bool) (*sql.DB, error) {
	if create {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create image embedding db directory: %w", err)
		}
	} else {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("embed db %q does not exist", path)
			}
			return nil, fmt.Errorf("stat embed db %q: %w", path, err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open image embedding db %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := ensureImageEmbeddingSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func ensureImageEmbeddingSchema(db *sql.DB) error {
	stmts := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		`CREATE TABLE IF NOT EXISTS image_embeddings (
			hash TEXT NOT NULL,
			vector BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (hash)
		);`,
		`CREATE TABLE IF NOT EXISTS text_embeddings (
			hash TEXT NOT NULL,
			vector BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (hash)
		);`,
		`CREATE TABLE IF NOT EXISTS embedding_models (
			kind TEXT PRIMARY KEY,
			model TEXT NOT NULL,
			updated_at_ns INTEGER NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize image embedding db schema: %w", err)
		}
	}
	return nil
}

func getStoredImageEmbeddingModel(ctx context.Context, db *sql.DB) (string, error) {
	var model string
	err := db.QueryRowContext(ctx, `SELECT model FROM embedding_models WHERE kind = 'image'`).Scan(&model)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query stored image embedding model: %w", err)
	}
	return model, nil
}

func setStoredImageEmbeddingModel(ctx context.Context, db *sql.DB, model string) error {
	if strings.TrimSpace(model) == "" {
		return nil
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO embedding_models(kind, model, updated_at_ns) VALUES('image', ?, ?)
		 ON CONFLICT(kind) DO UPDATE SET model = excluded.model, updated_at_ns = excluded.updated_at_ns`,
		model,
		time.Now().UTC().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("store image embedding model: %w", err)
	}
	return nil
}

func hashMappingDigest(mappingsByHash map[string]map[string]string, blake3Digest, algo string) string {
	algoMappings, ok := mappingsByHash[blake3Digest]
	if !ok {
		return ""
	}
	return strings.TrimSpace(algoMappings[algo])
}

func setHashMappingDigest(mappingsByHash map[string]map[string]string, blake3Digest, algo, digest string) {
	if _, ok := mappingsByHash[blake3Digest]; !ok {
		mappingsByHash[blake3Digest] = make(map[string]string)
	}
	mappingsByHash[blake3Digest][algo] = digest
}

func findPresentImageHashes(ctx context.Context, db *sql.DB, hashes []string) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(hashes))
	for _, chunk := range chunkStrings(hashes, 500) {
		rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT hash FROM image_embeddings WHERE hash IN (%s)`, sqlPlaceholders(len(chunk))), anySlice(chunk)...)
		if err != nil {
			return nil, fmt.Errorf("query present image hashes: %w", err)
		}
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan present image hash: %w", err)
			}
			out[hash] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("iterate present image hashes: %w", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

func upsertImageEmbedding(ctx context.Context, db *sql.DB, hash string, vectorJSON []byte) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO image_embeddings(hash, vector, created_at, updated_at)
		 VALUES(?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		 ON CONFLICT(hash) DO UPDATE SET vector = excluded.vector, updated_at = CURRENT_TIMESTAMP`,
		hash,
		vectorJSON,
	)
	if err != nil {
		return fmt.Errorf("upsert image embedding for %q: %w", hash, err)
	}
	return nil
}

func loadImageEmbeddingVectors(ctx context.Context, db *sql.DB, hashes []string) (map[string][]float64, error) {
	out := make(map[string][]float64, len(hashes))
	for _, chunk := range chunkStrings(hashes, 500) {
		rows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT hash, vector FROM image_embeddings WHERE hash IN (%s)`, sqlPlaceholders(len(chunk))), anySlice(chunk)...)
		if err != nil {
			return nil, fmt.Errorf("query image embeddings: %w", err)
		}
		for rows.Next() {
			var hash string
			var raw []byte
			if err := rows.Scan(&hash, &raw); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan image embedding row: %w", err)
			}
			vector, err := parseVectorJSON(raw)
			if err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("parse image embedding vector for %q: %w", hash, err)
			}
			out[hash] = vector
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("iterate image embedding rows: %w", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

func parseVectorJSON(raw []byte) ([]float64, error) {
	var vector []float64
	if err := json.Unmarshal(raw, &vector); err != nil {
		return nil, err
	}
	if len(vector) == 0 {
		return nil, fmt.Errorf("vector is empty")
	}
	return vector, nil
}

func normalizeEmbeddingVectorJSON(raw []byte) ([]byte, error) {
	vector, err := parseProxyVector(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(vector)
}

func parseProxyVector(raw []byte) ([]float64, error) {
	var vector []float64
	if err := json.Unmarshal(raw, &vector); err == nil && len(vector) > 0 {
		return vector, nil
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode embedding response: %w", err)
	}
	for _, key := range []string{"clip", "embedding", "vector", "data"} {
		value, ok := envelope[key]
		if !ok {
			continue
		}
		if err := json.Unmarshal(value, &vector); err == nil && len(vector) > 0 {
			return vector, nil
		}
	}
	return nil, fmt.Errorf("response did not include a vector")
}

func (c *embeddingProxyClient) LookupCacheKeys(ctx context.Context, keys []string) (map[string][]byte, map[string]struct{}, error) {
	hits := make(map[string][]byte, len(keys))
	misses := make(map[string]struct{})
	if len(keys) == 0 {
		return hits, misses, nil
	}

	uniqueKeys := make([]string, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		uniqueKeys = append(uniqueKeys, trimmed)
	}

	for _, chunk := range chunkStrings(uniqueKeys, 999) {
		payload, err := json.Marshal(map[string][]string{"keys": chunk})
		if err != nil {
			return nil, nil, fmt.Errorf("marshal cache lookup request: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.baseURL, "/")+"/v1/cache/lookup", strings.NewReader(string(payload)))
		if err != nil {
			return nil, nil, fmt.Errorf("create cache lookup request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.token)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("call cache lookup: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("read cache lookup response: %w", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, nil, fmt.Errorf("cache lookup status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var parsed struct {
			Hits   map[string]json.RawMessage `json:"hits"`
			Misses []string                   `json:"misses"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, nil, fmt.Errorf("decode cache lookup response: %w", err)
		}
		for key, raw := range parsed.Hits {
			vectorJSON, err := normalizeEmbeddingVectorJSON(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("normalize cache lookup hit: %w", err)
			}
			hits[key] = vectorJSON
		}
		for _, key := range parsed.Misses {
			misses[key] = struct{}{}
		}
		for _, key := range chunk {
			if _, ok := hits[key]; !ok {
				if _, miss := misses[key]; !miss {
					misses[key] = struct{}{}
				}
			}
		}
	}
	return hits, misses, nil
}

func (c *embeddingProxyClient) LookupCacheKey(ctx context.Context, key string) ([]byte, bool, error) {
	if strings.TrimSpace(key) == "" {
		return nil, false, fmt.Errorf("cache key is required")
	}
	hits, _, err := c.LookupCacheKeys(ctx, []string{key})
	if err != nil {
		return nil, false, err
	}
	raw, ok := hits[key]
	if !ok {
		return nil, false, nil
	}
	return raw, true, nil
}

func (c *embeddingProxyClient) PredictFile(ctx context.Context, path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open image file: %w", err)
	}
	defer file.Close()

	bodyReader, bodyWriter := io.Pipe()
	writer := multipart.NewWriter(bodyWriter)

	go func() {
		defer bodyWriter.Close()
		defer writer.Close()
		if err := writer.WriteField("entries", fmt.Sprintf(`{"clip":{"visual":{"modelName":%q}}}`, c.model)); err != nil {
			_ = bodyWriter.CloseWithError(err)
			return
		}
		part, err := writer.CreateFormFile("image", filepath.Base(path))
		if err != nil {
			_ = bodyWriter.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, file); err != nil {
			_ = bodyWriter.CloseWithError(err)
			return
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.baseURL, "/")+"/ml/predict", bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create backend request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call embedding backend: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read embedding backend response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("embedding backend status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return normalizeEmbeddingVectorJSON(body)
}

func computeSnapshotImageExternalHashes(path, model string) (snapshotImageExternalHashes, error) {
	file, err := os.Open(path)
	if err != nil {
		return snapshotImageExternalHashes{}, fmt.Errorf("open image for external hashes: %w", err)
	}
	defer file.Close()

	contentHasher := sha256.New()
	cacheKeyHasher := sha256.New()
	if _, err := io.WriteString(cacheKeyHasher, model); err != nil {
		return snapshotImageExternalHashes{}, fmt.Errorf("seed cache key hasher with model: %w", err)
	}
	if _, err := io.WriteString(cacheKeyHasher, "\x00image\x00"); err != nil {
		return snapshotImageExternalHashes{}, fmt.Errorf("seed cache key hasher with kind marker: %w", err)
	}
	if _, err := io.Copy(io.MultiWriter(contentHasher, cacheKeyHasher), file); err != nil {
		return snapshotImageExternalHashes{}, fmt.Errorf("hash image for external mappings: %w", err)
	}

	return snapshotImageExternalHashes{
		ContentSHA256:  hex.EncodeToString(contentHasher.Sum(nil)),
		CacheKeySHA256: hex.EncodeToString(cacheKeyHasher.Sum(nil)),
	}, nil
}

func embeddingCacheKeyAlgo(model string) string {
	return "embedding-cache-key:image:" + strings.TrimSpace(model)
}

func normalizeSnapshotQueryImagePath(rootPath, queryPath string) (string, error) {
	trimmed := strings.TrimSpace(queryPath)
	if trimmed == "" {
		return "", fmt.Errorf("query image path is required")
	}
	if filepath.IsAbs(trimmed) {
		rel, err := filepath.Rel(rootPath, trimmed)
		if err != nil {
			return "", fmt.Errorf("resolve query image path: %w", err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return "", fmt.Errorf("query image %q is outside snapshot root %q", trimmed, rootPath)
		}
		return filepath.ToSlash(rel), nil
	}
	return filepath.ToSlash(filepath.Clean(trimmed)), nil
}

func cosineSimilarity(a, b []float64) (float64, error) {
	if len(a) == 0 || len(b) == 0 {
		return 0, fmt.Errorf("vectors must not be empty")
	}
	if len(a) != len(b) {
		return 0, fmt.Errorf("vector length mismatch: %d != %d", len(a), len(b))
	}
	var dot float64
	var normA float64
	var normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0, fmt.Errorf("vector norm must be > 0")
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB)), nil
}

func sqlPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, "?")
	}
	return strings.Join(parts, ",")
}

func anySlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func chunkStrings(values []string, size int) [][]string {
	if len(values) == 0 {
		return nil
	}
	if size <= 0 {
		size = len(values)
	}
	out := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		out = append(out, values[start:end])
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}
