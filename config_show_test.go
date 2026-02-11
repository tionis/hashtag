package main

import (
	"testing"
)

func TestRunConfigShowCommandWithoutRemoteBootstrap(t *testing.T) {
	t.Setenv(forgeS3BucketEnv, "")
	if err := runConfigShowCommand([]string{"-output", "json"}); err != nil {
		t.Fatalf("runConfigShowCommand should succeed without remote bootstrap env: %v", err)
	}
}

func TestRunConfigShowCommandWithInvalidVectorRuntimeEnv(t *testing.T) {
	t.Setenv("FORGE_VECTOR_WORKER_CONCURRENCY", "0")
	if err := runConfigShowCommand([]string{"-output", "kv"}); err != nil {
		t.Fatalf("runConfigShowCommand should tolerate invalid vector runtime env and report it in output: %v", err)
	}
}
