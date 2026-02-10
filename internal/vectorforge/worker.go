package vectorforge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// WorkerClient sends jobs to the external embedding worker.
type WorkerClient struct {
	imageURL string
	textURL  string
	client   *http.Client
}

func NewWorkerClient(imageURL, textURL string) *WorkerClient {
	return &WorkerClient{
		imageURL: strings.TrimRight(imageURL, "/"),
		textURL:  strings.TrimRight(textURL, "/"),
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (wc *WorkerClient) Predict(ctx context.Context, job QueueJob, payloadPath string) ([]byte, error) {
	baseURL, err := wc.baseURLForKind(job.Kind)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(payloadPath)
	if err != nil {
		return nil, fmt.Errorf("open payload object: %w", err)
	}
	defer f.Close()

	workerURL := baseURL + path.Clean("/predict")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, workerURL, f)
	if err != nil {
		return nil, fmt.Errorf("build worker request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Embedding-Kind", job.Kind)
	req.Header.Set("X-File-Hash", job.FileHash)

	resp, err := wc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute worker request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read worker response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("worker status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	vector, err := extractEmbeddingVector(body)
	if err != nil {
		return nil, fmt.Errorf("parse worker embedding: %w", err)
	}
	return vector, nil
}

func (wc *WorkerClient) baseURLForKind(kind string) (string, error) {
	switch kind {
	case embeddingKindImage:
		if wc.imageURL == "" {
			return "", fmt.Errorf("image worker URL is not configured")
		}
		return wc.imageURL, nil
	case embeddingKindText:
		if wc.textURL == "" {
			return "", fmt.Errorf("text worker URL is not configured")
		}
		return wc.textURL, nil
	default:
		return "", fmt.Errorf("unsupported embedding kind %q", kind)
	}
}

func extractEmbeddingVector(payload []byte) ([]byte, error) {
	if vector, err := normalizeVectorJSON(payload); err == nil {
		return vector, nil
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode response object: %w", err)
	}

	for _, key := range []string{"embedding", "vector", "data"} {
		raw, ok := envelope[key]
		if !ok {
			continue
		}
		vector, err := normalizeVectorJSON(raw)
		if err == nil {
			return vector, nil
		}
	}

	return nil, fmt.Errorf("response did not include a parseable embedding field")
}

func normalizeVectorJSON(raw []byte) ([]byte, error) {
	var f64 []float64
	if err := json.Unmarshal(raw, &f64); err == nil && len(f64) > 0 {
		return json.Marshal(f64)
	}

	var f32 []float32
	if err := json.Unmarshal(raw, &f32); err == nil && len(f32) > 0 {
		return json.Marshal(f32)
	}

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var generic []any
		if err := json.Unmarshal(trimmed, &generic); err == nil && len(generic) > 0 {
			return json.Marshal(generic)
		}
	}

	return nil, fmt.Errorf("not a vector array")
}
