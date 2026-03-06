package main

import (
	"encoding/json"
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

func TestRunConfigShowCommandIncludesSkillsDir(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return runConfigShowCommand([]string{"-output", "json"})
	})
	if err != nil {
		t.Fatalf("runConfigShowCommand json: %v", err)
	}
	var payload effectiveConfigOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal config show json: %v\noutput=%s", err, out)
	}
	if payload.Paths.SkillsDir == "" {
		t.Fatal("expected paths.skills_dir to be set")
	}
}
