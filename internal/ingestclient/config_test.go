package ingestclient

import (
	"strings"
	"testing"

	"github.com/tionis/forge/internal/forgeconfig"
)

func TestDefaultHydratedDBPathUsesXDGDataHome(t *testing.T) {
	t.Setenv(forgeconfig.EnvVectorHydratedDBPath, "")
	t.Setenv("XDG_DATA_HOME", "/tmp/forge-ingest-data")

	got := defaultHydratedDBPath()
	want := "/tmp/forge-ingest-data/forge/embeddings.db"
	if got != want {
		t.Fatalf("defaultHydratedDBPath mismatch: got %q want %q", got, want)
	}
}

func TestDefaultHydratedDBPathOverride(t *testing.T) {
	t.Setenv(forgeconfig.EnvVectorHydratedDBPath, "/tmp/custom-hydrated.db")

	got := defaultHydratedDBPath()
	if got != "/tmp/custom-hydrated.db" {
		t.Fatalf("defaultHydratedDBPath override mismatch: got %q", got)
	}
}

func TestLoadConfigDefaultsToBlake3(t *testing.T) {
	cfg, err := LoadConfigFromArgs([]string{"-server", "http://localhost:8080"})
	if err != nil {
		t.Fatalf("LoadConfigFromArgs error: %v", err)
	}
	if cfg.HashAlgo != "blake3" {
		t.Fatalf("default hash algo mismatch: got %q want %q", cfg.HashAlgo, "blake3")
	}
}

func TestLoadConfigRejectsUnsupportedAlgo(t *testing.T) {
	_, err := LoadConfigFromArgs([]string{"-server", "http://localhost:8080", "-algo", "sha256"})
	if err == nil {
		t.Fatal("expected error for unsupported algo")
	}
	if !strings.Contains(err.Error(), "supported: blake3") {
		t.Fatalf("unexpected error: %v", err)
	}
}
