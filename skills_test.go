package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestListEmbeddedSkillsContainsCoreSkillDocs(t *testing.T) {
	skills, err := listEmbeddedSkills()
	if err != nil {
		t.Fatalf("listEmbeddedSkills: %v", err)
	}
	if len(skills) == 0 {
		t.Fatal("expected at least one embedded skill")
	}

	required := []string{
		"forge-blob",
		"forge-config",
		"forge-dupes",
		"forge-hash",
		"forge-hashmap",
		"forge-overview",
		"forge-remote",
		"forge-replicate",
		"forge-snap",
		"forge-snapshot",
		"forge-tags",
		"forge-vector",
	}

	byName := make(map[string]embeddedSkill, len(skills))
	for _, skill := range skills {
		byName[skill.Name] = skill
	}

	for _, name := range required {
		skill, ok := byName[name]
		if !ok {
			t.Fatalf("missing embedded skill %q", name)
		}
		hasManifest := false
		for _, file := range skill.Files {
			if file == skillManifestFileName {
				hasManifest = true
				break
			}
		}
		if !hasManifest {
			t.Fatalf("embedded skill %q is missing %s", name, skillManifestFileName)
		}
	}
}

func TestRunSkillsListCommandJSONOutput(t *testing.T) {
	out, err := captureStdout(t, func() error {
		return runSkillsListCommand([]string{"-output", "json"})
	})
	if err != nil {
		t.Fatalf("runSkillsListCommand: %v", err)
	}

	var payload skillsListOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal skills list output: %v\nout=%s", err, out)
	}
	if payload.Count == 0 {
		t.Fatalf("expected non-empty skills list output: %+v", payload)
	}
	if len(payload.Skills) != payload.Count {
		t.Fatalf("count mismatch: count=%d len(skills)=%d", payload.Count, len(payload.Skills))
	}
}

func TestRunSkillsInstallCommandInstallsAll(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "skills")

	out, err := captureStdout(t, func() error {
		return runSkillsInstallCommand([]string{"-dir", destination, "-output", "json"})
	})
	if err != nil {
		t.Fatalf("runSkillsInstallCommand: %v", err)
	}

	var payload skillsInstallOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal skills install output: %v\nout=%s", err, out)
	}
	if payload.Selected == 0 {
		t.Fatalf("expected selected > 0: %+v", payload)
	}
	if payload.Installed != payload.Selected {
		t.Fatalf("expected installed=%d selected=%d", payload.Installed, payload.Selected)
	}
	if payload.FilesWritten == 0 {
		t.Fatalf("expected non-zero files written: %+v", payload)
	}
	for _, item := range payload.Skills {
		if item.Status != "installed" {
			t.Fatalf("expected installed status, got %q for %q", item.Status, item.Name)
		}
		manifest := filepath.Join(item.Path, skillManifestFileName)
		if _, err := os.Stat(manifest); err != nil {
			t.Fatalf("missing installed skill manifest %q: %v", manifest, err)
		}
	}
}

func TestRunSkillsInstallCommandSkipsExistingWithoutForce(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "skills")
	if err := runSkillsInstallCommand([]string{"-dir", destination, "-output", "kv"}); err != nil {
		t.Fatalf("initial install failed: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runSkillsInstallCommand([]string{"-dir", destination, "-output", "json"})
	})
	if err != nil {
		t.Fatalf("second install failed: %v", err)
	}

	var payload skillsInstallOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal second install output: %v\nout=%s", err, out)
	}
	if payload.Skipped != payload.Selected {
		t.Fatalf("expected skipped=%d selected=%d", payload.Skipped, payload.Selected)
	}
	if payload.Installed != 0 {
		t.Fatalf("expected installed=0 on second run, got %d", payload.Installed)
	}
	for _, item := range payload.Skills {
		if item.Status != "skipped_exists" {
			t.Fatalf("expected skipped_exists status, got %q for %q", item.Status, item.Name)
		}
	}
}

func TestRunSkillsInstallCommandSupportsSelection(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "skills")

	out, err := captureStdout(t, func() error {
		return runSkillsInstallCommand([]string{"-dir", destination, "-skills", "forge-hash,forge-snapshot", "-output", "json"})
	})
	if err != nil {
		t.Fatalf("runSkillsInstallCommand selection: %v", err)
	}

	var payload skillsInstallOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal selection output: %v\nout=%s", err, out)
	}
	if payload.Selected != 2 {
		t.Fatalf("expected selected=2, got %d", payload.Selected)
	}
	for _, expected := range []string{"forge-hash", "forge-snapshot"} {
		manifest := filepath.Join(destination, expected, skillManifestFileName)
		if _, err := os.Stat(manifest); err != nil {
			t.Fatalf("expected manifest for %q: %v", expected, err)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "forge-blob", skillManifestFileName)); err == nil {
		t.Fatalf("did not expect forge-blob to be installed when selection is limited")
	}
}

func TestRunSkillsInstallCommandRejectsUnknownSelection(t *testing.T) {
	err := runSkillsInstallCommand([]string{"-skills", "forge-hash,missing-skill", "-output", "kv"})
	if err == nil {
		t.Fatal("expected unknown skill selection error")
	}
}

func TestRunSkillsInstallCommandSupportsAllSelection(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "skills")

	out, err := captureStdout(t, func() error {
		return runSkillsInstallCommand([]string{"-dir", destination, "-skills", "all", "-output", "json"})
	})
	if err != nil {
		t.Fatalf("runSkillsInstallCommand all: %v", err)
	}
	var payload skillsInstallOutput
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("unmarshal all selection output: %v\\nout=%s", err, out)
	}
	if payload.Selected == 0 || payload.Selected != payload.Embedded {
		t.Fatalf("expected selected=%d embedded=%d", payload.Selected, payload.Embedded)
	}
}

func TestRunSkillsInstallCommandRejectsAllWithSpecificSelection(t *testing.T) {
	err := runSkillsInstallCommand([]string{"-skills", "all,forge-hash", "-output", "kv"})
	if err == nil {
		t.Fatal("expected invalid mixed all+specific selection error")
	}
}
