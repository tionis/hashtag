package main

import (
	"context"
	stderrors "errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/tionis/forge/internal/forgeconfig"
	"github.com/tionis/forge/internal/vectorforge"
)

func TestRunVectorServeCommandStopsOnLeaseLoss(t *testing.T) {
	temp := t.TempDir()
	t.Setenv(forgeconfig.EnvDataDir, temp)
	t.Setenv(forgeconfig.EnvCacheDir, temp)

	originalConfigure := configureVectorReplicationFromRemoteConfigFunc
	originalAcquire := acquireVectorWriterLeaseFunc
	originalRun := runVectorforgeFunc
	t.Cleanup(func() {
		configureVectorReplicationFromRemoteConfigFunc = originalConfigure
		acquireVectorWriterLeaseFunc = originalAcquire
		runVectorforgeFunc = originalRun
	})

	configureVectorReplicationFromRemoteConfigFunc = func(ctx context.Context, cfg *vectorforge.Config) (vectorLeaseSetup, error) {
		return vectorLeaseSetup{}, nil
	}
	lease := &vectorWriterLease{
		mode:          vectorLeaseModeSoft,
		renewComplete: make(chan struct{}),
		lostCh:        make(chan error, 1),
	}
	close(lease.renewComplete)
	acquireVectorWriterLeaseFunc = func(ctx context.Context, logger *log.Logger, bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig) (*vectorWriterLease, error) {
		return lease, nil
	}
	runVectorforgeFunc = func(ctx context.Context, cfg vectorforge.Config, logger *log.Logger) error {
		<-ctx.Done()
		return nil
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		lease.lostCh <- stderrors.New("lease lost by competing writer")
	}()

	err := runVectorServeCommand([]string{})
	if err == nil {
		t.Fatal("expected runVectorServeCommand to fail after lease loss")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "lease loss") {
		t.Fatalf("expected lease loss error, got: %v", err)
	}
}
