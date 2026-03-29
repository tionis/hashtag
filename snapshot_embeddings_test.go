package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotEmbedPreviewJSONOutput(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.jpg"), []byte("image-a"))
	writeTestFile(t, filepath.Join(root, "b.png"), []byte("image-b"))
	writeTestFile(t, filepath.Join(root, "note.txt"), []byte("ignore-me"))

	snapshotDBPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", snapshotDBPath, root}); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	embedDBPath := filepath.Join(t.TempDir(), "embeddings.db")
	embedDB, err := openImageEmbeddingDB(embedDBPath, true)
	if err != nil {
		t.Fatalf("open image embedding db: %v", err)
	}
	defer embedDB.Close()

	hashA := mustFileHashForSnapshot(t, filepath.Join(root, "a.jpg"))
	if err := upsertImageEmbedding(context.Background(), embedDB, hashA, []byte(`[1,0]`)); err != nil {
		t.Fatalf("seed image embedding: %v", err)
	}
	if err := setStoredImageEmbeddingModel(context.Background(), embedDB, "preview-model"); err != nil {
		t.Fatalf("set stored image model: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runSnapshotEmbedCommand([]string{
			"-db", snapshotDBPath,
			"-embed-db", embedDBPath,
			"-model", "preview-model",
			"-output", "json",
			root,
		})
	})
	if err != nil {
		t.Fatalf("snapshot embed preview: %v", err)
	}

	var payload snapshotEmbedOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("decode snapshot embed preview output: %v\noutput=%s", err, out)
	}
	if payload.ImagePaths != 2 {
		t.Fatalf("expected 2 image paths, got %d", payload.ImagePaths)
	}
	if payload.UniqueHashes != 2 {
		t.Fatalf("expected 2 unique hashes, got %d", payload.UniqueHashes)
	}
	if payload.PresentHashes != 1 {
		t.Fatalf("expected 1 present hash, got %d", payload.PresentHashes)
	}
	if payload.MissingHashes != 1 {
		t.Fatalf("expected 1 missing hash, got %d", payload.MissingHashes)
	}
	if payload.SelectedHashes != 1 {
		t.Fatalf("expected 1 selected hash, got %d", payload.SelectedHashes)
	}
	if payload.EligibleHashes != 1 {
		t.Fatalf("expected 1 eligible hash, got %d", payload.EligibleHashes)
	}
	if payload.GeneratedHashes != 0 {
		t.Fatalf("expected 0 generated hashes in preview, got %d", payload.GeneratedHashes)
	}
	if payload.StoredModel != "preview-model" {
		t.Fatalf("expected stored model preview-model, got %q", payload.StoredModel)
	}
	if len(payload.Entries) != 1 {
		t.Fatalf("expected 1 selected entry, got %d", len(payload.Entries))
	}
	if payload.Entries[0].Status != "ready" {
		t.Fatalf("expected selected entry status ready, got %q", payload.Entries[0].Status)
	}
	if payload.Entries[0].Path != "b.png" {
		t.Fatalf("expected missing representative path b.png, got %q", payload.Entries[0].Path)
	}
}

func TestSnapshotEmbedApplyStoresEmbeddingAndModel(t *testing.T) {
	root := t.TempDir()
	photoPath := filepath.Join(root, "photo.jpg")
	writeTestFile(t, photoPath, []byte("photo-bytes"))

	snapshotDBPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", snapshotDBPath, root}); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	const model = "clip-test-model"
	externalHashes, err := computeSnapshotImageExternalHashes(photoPath, model)
	if err != nil {
		t.Fatalf("compute external hashes: %v", err)
	}

	var lookupCalls int
	var predictCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer emb_test_token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		switch r.URL.Path {
		case "/v1/cache/lookup":
			lookupCalls++
			var payload struct {
				Keys []string `json:"keys"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode cache lookup payload: %v", err)
			}
			if len(payload.Keys) != 1 || payload.Keys[0] != externalHashes.CacheKeySHA256 {
				t.Fatalf("unexpected cache lookup keys %#v", payload.Keys)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"hits":{"` + externalHashes.CacheKeySHA256 + `":{"object":"embedding","embedding":[0.25,0.75]}}}`))
		case "/ml/predict":
			predictCalls++
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatalf("parse multipart form: %v", err)
			}
			if got := r.FormValue("entries"); !strings.Contains(got, `"modelName":"`+model+`"`) {
				t.Fatalf("unexpected entries payload %q", got)
			}
			f, _, err := r.FormFile("image")
			if err != nil {
				t.Fatalf("open multipart image: %v", err)
			}
			defer f.Close()
			body, err := io.ReadAll(f)
			if err != nil {
				t.Fatalf("read multipart image: %v", err)
			}
			if string(body) != "photo-bytes" {
				t.Fatalf("unexpected uploaded image bytes %q", string(body))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"clip":[0.25,0.75]}`))
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv(envEmbeddingsEndpoint, server.URL)
	t.Setenv(envEmbeddingsToken, "emb_test_token")

	embedDBPath := filepath.Join(t.TempDir(), "embeddings.db")
	out, err := captureStdout(t, func() error {
		return runSnapshotEmbedCommand([]string{
			"-db", snapshotDBPath,
			"-embed-db", embedDBPath,
			"-model", model,
			"-apply",
			"-output", "json",
			root,
		})
	})
	if err != nil {
		t.Fatalf("snapshot embed apply: %v", err)
	}
	if lookupCalls != 1 {
		t.Fatalf("expected 1 cache lookup call, got %d", lookupCalls)
	}
	if predictCalls != 0 {
		t.Fatalf("expected 0 predict calls on cache hit, got %d", predictCalls)
	}

	var payload snapshotEmbedOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("decode snapshot embed apply output: %v\noutput=%s", err, out)
	}
	if payload.GeneratedHashes != 1 {
		t.Fatalf("expected 1 generated hash, got %d", payload.GeneratedHashes)
	}
	if payload.StoredModel != model {
		t.Fatalf("expected stored model %s, got %q", model, payload.StoredModel)
	}

	embedDB, err := openImageEmbeddingDB(embedDBPath, false)
	if err != nil {
		t.Fatalf("open generated image embedding db: %v", err)
	}
	defer embedDB.Close()

	if got := mustCount(t, embedDB, "SELECT COUNT(*) FROM image_embeddings"); got != 1 {
		t.Fatalf("expected 1 image embedding row, got %d", got)
	}
	storedModel, err := getStoredImageEmbeddingModel(context.Background(), embedDB)
	if err != nil {
		t.Fatalf("read stored image model: %v", err)
	}
	if storedModel != model {
		t.Fatalf("expected stored model %s, got %q", model, storedModel)
	}

	var storedVector string
	if err := embedDB.QueryRow(`SELECT CAST(vector AS TEXT) FROM image_embeddings LIMIT 1`).Scan(&storedVector); err != nil {
		t.Fatalf("read stored vector: %v", err)
	}
	if storedVector != `[0.25,0.75]` {
		t.Fatalf("unexpected stored vector %q", storedVector)
	}

	snapshotDB, err := openSnapshotDB(snapshotDBPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	defer snapshotDB.Close()

	hashPhoto := mustFileHashForSnapshot(t, photoPath)
	mappings, err := lookupMappingsByBlake3(snapshotDB, hashPhoto)
	if err != nil {
		t.Fatalf("lookup hash mappings by blake3: %v", err)
	}
	algoToDigest := make(map[string]string, len(mappings))
	for _, mapping := range mappings {
		algoToDigest[mapping.Algo] = mapping.Digest
	}
	if got := algoToDigest[hashAlgoSHA256]; got != externalHashes.ContentSHA256 {
		t.Fatalf("expected sha256 mapping %q, got %q", externalHashes.ContentSHA256, got)
	}
	if got := algoToDigest[embeddingCacheKeyAlgo(model)]; got != externalHashes.CacheKeySHA256 {
		t.Fatalf("expected cache key mapping %q, got %q", externalHashes.CacheKeySHA256, got)
	}
}

func TestSnapshotEmbedApplyUsesBatchedMappedCacheKeysWithoutLiveFiles(t *testing.T) {
	root := t.TempDir()
	firstPath := filepath.Join(root, "first.jpg")
	secondPath := filepath.Join(root, "second.jpg")
	writeTestFile(t, firstPath, []byte("first-photo"))
	writeTestFile(t, secondPath, []byte("second-photo"))

	snapshotDBPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", snapshotDBPath, root}); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	const model = "batched-model"
	firstExternal, err := computeSnapshotImageExternalHashes(firstPath, model)
	if err != nil {
		t.Fatalf("compute first external hashes: %v", err)
	}
	secondExternal, err := computeSnapshotImageExternalHashes(secondPath, model)
	if err != nil {
		t.Fatalf("compute second external hashes: %v", err)
	}
	firstHash := mustFileHashForSnapshot(t, firstPath)
	secondHash := mustFileHashForSnapshot(t, secondPath)

	snapshotDB, err := openSnapshotDB(snapshotDBPath)
	if err != nil {
		t.Fatalf("open snapshot db: %v", err)
	}
	defer snapshotDB.Close()
	for _, tc := range []struct {
		blake3 string
		algo   string
		digest string
	}{
		{firstHash, embeddingCacheKeyAlgo(model), firstExternal.CacheKeySHA256},
		{secondHash, embeddingCacheKeyAlgo(model), secondExternal.CacheKeySHA256},
	} {
		if err := upsertHashMapping(snapshotDB, tc.blake3, tc.algo, tc.digest); err != nil {
			t.Fatalf("seed hash mapping %+v: %v", tc, err)
		}
	}

	if err := os.Remove(firstPath); err != nil {
		t.Fatalf("remove first live file: %v", err)
	}
	if err := os.Remove(secondPath); err != nil {
		t.Fatalf("remove second live file: %v", err)
	}

	var lookupCalls int
	var predictCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer emb_batch_token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		switch r.URL.Path {
		case "/v1/cache/lookup":
			lookupCalls++
			var payload struct {
				Keys []string `json:"keys"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode cache lookup payload: %v", err)
			}
			if len(payload.Keys) != 2 {
				t.Fatalf("expected 2 cache lookup keys, got %#v", payload.Keys)
			}
			got := map[string]struct{}{}
			for _, key := range payload.Keys {
				got[key] = struct{}{}
			}
			for _, expected := range []string{firstExternal.CacheKeySHA256, secondExternal.CacheKeySHA256} {
				if _, ok := got[expected]; !ok {
					t.Fatalf("expected cache lookup key %q in %#v", expected, payload.Keys)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"hits":{"` + firstExternal.CacheKeySHA256 + `":{"embedding":[1,0]},"` + secondExternal.CacheKeySHA256 + `":{"embedding":[0,1]}}}`))
		case "/ml/predict":
			predictCalls++
			t.Fatalf("predict should not be called when cache hits satisfy all missing groups")
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv(envEmbeddingsEndpoint, server.URL)
	t.Setenv(envEmbeddingsToken, "emb_batch_token")

	embedDBPath := filepath.Join(t.TempDir(), "embeddings.db")
	out, err := captureStdout(t, func() error {
		return runSnapshotEmbedCommand([]string{
			"-db", snapshotDBPath,
			"-embed-db", embedDBPath,
			"-model", model,
			"-apply",
			"-output", "json",
			root,
		})
	})
	if err != nil {
		t.Fatalf("snapshot embed apply with batched cache keys: %v", err)
	}
	if lookupCalls != 1 {
		t.Fatalf("expected 1 batched cache lookup call, got %d", lookupCalls)
	}
	if predictCalls != 0 {
		t.Fatalf("expected 0 predict calls, got %d", predictCalls)
	}

	var payload snapshotEmbedOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("decode snapshot embed output: %v\noutput=%s", err, out)
	}
	if payload.GeneratedHashes != 2 {
		t.Fatalf("expected 2 generated hashes, got %d", payload.GeneratedHashes)
	}
	if payload.WarningCount != 0 {
		t.Fatalf("expected 0 warnings, got %d", payload.WarningCount)
	}

	embedDB, err := openImageEmbeddingDB(embedDBPath, false)
	if err != nil {
		t.Fatalf("open embed db: %v", err)
	}
	defer embedDB.Close()
	if got := mustCount(t, embedDB, "SELECT COUNT(*) FROM image_embeddings"); got != 2 {
		t.Fatalf("expected 2 image embeddings, got %d", got)
	}
}

func TestSnapshotSimilarJSONOutput(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "a.jpg"), []byte("image-a"))
	writeTestFile(t, filepath.Join(root, "b.jpg"), []byte("image-b"))
	writeTestFile(t, filepath.Join(root, "c.jpg"), []byte("image-c"))

	snapshotDBPath := filepath.Join(t.TempDir(), "snapshot.db")
	if err := runSnapshotCommand([]string{"-db", snapshotDBPath, root}); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	embedDBPath := filepath.Join(t.TempDir(), "embeddings.db")
	embedDB, err := openImageEmbeddingDB(embedDBPath, true)
	if err != nil {
		t.Fatalf("open image embedding db: %v", err)
	}
	defer embedDB.Close()

	hashA := mustFileHashForSnapshot(t, filepath.Join(root, "a.jpg"))
	hashB := mustFileHashForSnapshot(t, filepath.Join(root, "b.jpg"))
	hashC := mustFileHashForSnapshot(t, filepath.Join(root, "c.jpg"))

	if err := upsertImageEmbedding(context.Background(), embedDB, hashA, []byte(`[1,0]`)); err != nil {
		t.Fatalf("seed embedding a: %v", err)
	}
	if err := upsertImageEmbedding(context.Background(), embedDB, hashB, []byte(`[0.9,0.1]`)); err != nil {
		t.Fatalf("seed embedding b: %v", err)
	}
	if err := upsertImageEmbedding(context.Background(), embedDB, hashC, []byte(`[-1,0]`)); err != nil {
		t.Fatalf("seed embedding c: %v", err)
	}
	if err := setStoredImageEmbeddingModel(context.Background(), embedDB, "search-model"); err != nil {
		t.Fatalf("set stored image model: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runSnapshotSimilarCommand([]string{
			"-db", snapshotDBPath,
			"-embed-db", embedDBPath,
			"-image", "a.jpg",
			"-limit", "2",
			"-output", "json",
			root,
		})
	})
	if err != nil {
		t.Fatalf("snapshot similar: %v", err)
	}

	var payload snapshotSimilarOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("decode snapshot similar output: %v\noutput=%s", err, out)
	}
	if payload.QueryPath != "a.jpg" {
		t.Fatalf("expected query path a.jpg, got %q", payload.QueryPath)
	}
	if payload.QueryHash != hashA {
		t.Fatalf("expected query hash %q, got %q", hashA, payload.QueryHash)
	}
	if payload.StoredModel != "search-model" {
		t.Fatalf("expected stored model search-model, got %q", payload.StoredModel)
	}
	if payload.MatchCount != 2 {
		t.Fatalf("expected 2 matches, got %d", payload.MatchCount)
	}
	if payload.Matches[0].Path != "b.jpg" {
		t.Fatalf("expected closest match b.jpg, got %q", payload.Matches[0].Path)
	}
	if payload.Matches[1].Path != "c.jpg" {
		t.Fatalf("expected second match c.jpg, got %q", payload.Matches[1].Path)
	}
	if payload.Matches[0].Score <= payload.Matches[1].Score {
		t.Fatalf("expected descending similarity scores, got %f then %f", payload.Matches[0].Score, payload.Matches[1].Score)
	}
	if payload.Matches[0].Hash != hashB {
		t.Fatalf("expected first match hash %q, got %q", hashB, payload.Matches[0].Hash)
	}
	if payload.Matches[1].Hash != hashC {
		t.Fatalf("expected second match hash %q, got %q", hashC, payload.Matches[1].Hash)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustFileHashForSnapshot(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	hash, err := hashRegularFileForSnapshot(path, info, false)
	if err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return hash
}
