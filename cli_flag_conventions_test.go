package main

import (
	"io"
	"testing"

	flag "github.com/spf13/pflag"
)

func TestNormalizePFlagArgsSupportsSingleDashLongFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "output mode")
	verbose := fs.BoolP("verbose", "v", false, "verbose")
	applyCommandFlagConventions(fs)

	args := normalizePFlagArgs(fs, []string{"-output", "json", "-v"})
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse normalized args: %v", err)
	}
	if *output != "json" {
		t.Fatalf("expected output=json, got %q", *output)
	}
	if !*verbose {
		t.Fatal("expected verbose=true")
	}
}

func TestApplyCommandFlagConventionsAddsDBShortAlias(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", "", "db path")
	applyCommandFlagConventions(fs)

	if err := fs.Parse(normalizePFlagArgs(fs, []string{"-d", "/tmp/test.db"})); err != nil {
		t.Fatalf("parse -d alias: %v", err)
	}
	if *db != "/tmp/test.db" {
		t.Fatalf("expected db to be set via -d, got %q", *db)
	}
}

func TestApplyCommandFlagConventionsAddsLongAliasForLegacyShortFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	verbose := fs.Bool("v", false, "legacy verbose")
	applyCommandFlagConventions(fs)

	if err := fs.Parse(normalizePFlagArgs(fs, []string{"--verbose"})); err != nil {
		t.Fatalf("parse --verbose alias: %v", err)
	}
	if !*verbose {
		t.Fatal("expected legacy verbose value to be set through --verbose alias")
	}
}

func TestApplyCommandFlagConventionsPrefersOutForDashO(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "output file")
	outputMode := fs.String("output", "auto", "output mode")
	applyCommandFlagConventions(fs)

	if err := fs.Parse(normalizePFlagArgs(fs, []string{"-o", "file.txt"})); err != nil {
		t.Fatalf("parse -o for out: %v", err)
	}
	if *out != "file.txt" {
		t.Fatalf("expected out to be set via -o, got %q", *out)
	}
	if *outputMode != "auto" {
		t.Fatalf("expected output mode to remain default, got %q", *outputMode)
	}
}
