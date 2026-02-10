package ingestclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type hashedFile struct {
	Hash string
	Path string
}

type lookupRequest struct {
	Kind   string   `json:"kind"`
	Hashes []string `json:"hashes"`
}

type lookupResponse struct {
	Status map[string]string `json:"status"`
}

func Run(ctx context.Context, cfg Config, logger *log.Logger) error {
	client := &http.Client{Timeout: cfg.RequestTimeout}

	hashed, err := hashTree(ctx, cfg, logger)
	if err != nil {
		return err
	}
	if len(hashed) == 0 {
		logger.Printf("no files found under %s", cfg.RootPath)
		return nil
	}
	logger.Printf("discovered %d unique hashes from %d files", len(hashed), countFiles(hashed))

	localPresentCount := 0
	if cfg.HydratedDBPath != "" {
		locallyPresent, err := filterPresentWithHydratedDB(ctx, cfg.HydratedDBPath, cfg.Kind, hashed, cfg.LookupBatch)
		if err != nil {
			if os.IsNotExist(err) {
				if cfg.Verbose {
					logger.Printf("hydrated db precheck skipped (missing %s)", cfg.HydratedDBPath)
				}
			} else {
				logger.Printf("hydrated db precheck unavailable (%s): %v", cfg.HydratedDBPath, err)
			}
		} else {
			localPresentCount = locallyPresent
			logger.Printf("hydrated db precheck: present=%d missing=%d", locallyPresent, len(hashed))
		}
	}

	missing, statusCounts, err := lookupMissing(ctx, client, cfg, hashed)
	if err != nil {
		return err
	}
	statusCounts["present"] += localPresentCount
	logger.Printf("lookup result: present=%d processing=%d missing=%d", statusCounts["present"], statusCounts["processing"], statusCounts["missing"])
	if len(missing) == 0 {
		return nil
	}

	uploaded, alreadyPresent, failed := uploadMissing(ctx, client, cfg, logger, missing)
	logger.Printf("upload result: accepted=%d already_present=%d failed=%d", uploaded, alreadyPresent, failed)
	if failed > 0 {
		return fmt.Errorf("%d uploads failed", failed)
	}
	return nil
}

func hashTree(ctx context.Context, cfg Config, logger *log.Logger) (map[string]string, error) {
	paths := make(chan string, cfg.Workers*4)
	results := make(chan hashedFile, cfg.Workers*4)
	errCh := make(chan error, 1)

	go func() {
		defer close(paths)
		err := filepath.WalkDir(cfg.RootPath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case paths <- path:
				return nil
			}
		})
		if err != nil && err != context.Canceled {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for path := range paths {
				h, err := hashWithXattrCache(path, cfg.HashAlgo)
				if err != nil {
					if cfg.Verbose {
						logger.Printf("hash worker %d skipped %s: %v", workerID, path, err)
					}
					continue
				}
				select {
				case <-ctx.Done():
					return
				case results <- hashedFile{Hash: strings.ToLower(h), Path: path}:
				}
			}
		}(i + 1)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	hashToPath := make(map[string]string)
	for item := range results {
		if _, exists := hashToPath[item.Hash]; exists {
			continue
		}
		hashToPath[item.Hash] = item.Path
	}

	if err := <-errCh; err != nil {
		return nil, err
	}
	return hashToPath, nil
}

func countFiles(unique map[string]string) int {
	return len(unique)
}

func lookupMissing(ctx context.Context, client *http.Client, cfg Config, hashToPath map[string]string) (map[string]string, map[string]int, error) {
	hashes := make([]string, 0, len(hashToPath))
	for h := range hashToPath {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)

	missing := make(map[string]string)
	counts := map[string]int{"present": 0, "processing": 0, "missing": 0}

	for i := 0; i < len(hashes); i += cfg.LookupBatch {
		end := i + cfg.LookupBatch
		if end > len(hashes) {
			end = len(hashes)
		}
		batch := hashes[i:end]

		payload, err := json.Marshal(lookupRequest{Kind: cfg.Kind, Hashes: batch})
		if err != nil {
			return nil, nil, fmt.Errorf("marshal lookup request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+"/api/v1/lookup", bytes.NewReader(payload))
		if err != nil {
			return nil, nil, fmt.Errorf("create lookup request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup request failed: %w", err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("read lookup response: %w", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("lookup status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var out lookupResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, nil, fmt.Errorf("decode lookup response: %w", err)
		}

		for _, h := range batch {
			st := out.Status[h]
			if st == "" {
				st = "missing"
			}
			counts[st]++
			if st == "missing" {
				missing[h] = hashToPath[h]
			}
		}
	}

	return missing, counts, nil
}

func uploadMissing(ctx context.Context, client *http.Client, cfg Config, logger *log.Logger, missing map[string]string) (accepted int, alreadyPresent int, failed int) {
	type uploadTask struct {
		hash string
		path string
	}

	tasks := make(chan uploadTask, cfg.Workers*4)
	results := make(chan int, cfg.Workers*4)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for task := range tasks {
				code := uploadOne(ctx, client, cfg, task)
				if code < 0 && cfg.Verbose {
					logger.Printf("upload worker %d failed %s (%s)", workerID, task.path, task.hash)
				}
				results <- code
			}
		}(i + 1)
	}

	go func() {
		defer close(tasks)
		for hash, path := range missing {
			select {
			case <-ctx.Done():
				return
			case tasks <- uploadTask{hash: hash, path: path}:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for code := range results {
		switch code {
		case http.StatusAccepted:
			accepted++
		case http.StatusOK:
			alreadyPresent++
		default:
			failed++
		}
	}
	return accepted, alreadyPresent, failed
}

func uploadOne(ctx context.Context, client *http.Client, cfg Config, task struct {
	hash string
	path string
}) int {
	f, err := os.Open(task.path)
	if err != nil {
		return -1
	}
	defer f.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+"/api/v1/upload", f)
	if err != nil {
		return -1
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Hash", task.hash)
	req.Header.Set("X-Embedding-Kind", cfg.Kind)

	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode
}
