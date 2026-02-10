package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/tionis/forge/internal/vectorforge"
)

const (
	vectorLeaseModeAuto = "auto"
	vectorLeaseModeHard = "hard"
	vectorLeaseModeSoft = "soft"
	vectorLeaseModeOff  = "off"

	vectorLeasePrefix = "leases"
)

type vectorWriterLeaseRecord struct {
	Schema       string `json:"schema"`
	Resource     string `json:"resource"`
	Mode         string `json:"mode"`
	OwnerID      string `json:"owner_id"`
	LeaseID      string `json:"lease_id"`
	IssuedAtUTC  string `json:"issued_at_utc"`
	ExpiresAtUTC string `json:"expires_at_utc"`
}

type vectorWriterLease struct {
	client       *s3.Client
	bootstrap    remoteS3Bootstrap
	capabilities remoteS3Capabilities
	mode         string
	objectKey    string
	resource     string
	ownerID      string
	leaseID      string
	logger       *log.Logger

	mu            sync.Mutex
	etag          string
	expiresAt     time.Time
	duration      time.Duration
	renewInterval time.Duration
	released      bool
	lostReported  bool
	renewCancel   context.CancelFunc
	renewComplete chan struct{}
	lostCh        chan error
}

type vectorLeaseSetup struct {
	Bootstrap remoteS3Bootstrap
	Config    remoteGlobalConfig
}

func configureVectorReplicationFromRemoteConfig(ctx context.Context, cfg *vectorforge.Config) (vectorLeaseSetup, error) {
	if cfg == nil {
		return vectorLeaseSetup{}, nil
	}
	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		return vectorLeaseSetup{}, fmt.Errorf("load remote bootstrap for vector replication: %w", err)
	}
	remoteCfg, _, err := loadRemoteGlobalConfigWithCache(ctx, bootstrap, nil)
	if err != nil {
		return vectorLeaseSetup{}, fmt.Errorf("load remote config for vector replication: %w", err)
	}

	replicaURL, err := buildVectorReplicaURL(bootstrap, remoteCfg)
	if err != nil {
		return vectorLeaseSetup{}, err
	}
	cfg.ReplicaURL = replicaURL
	return vectorLeaseSetup{
		Bootstrap: bootstrap,
		Config:    remoteCfg,
	}, nil
}

func resolveVectorLeaseMode(mode string, caps remoteS3Capabilities) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	if normalized == "" {
		normalized = vectorLeaseModeAuto
	}
	switch normalized {
	case vectorLeaseModeAuto:
		if caps.ConditionalIfNoneMatch && caps.ConditionalIfMatch {
			return vectorLeaseModeHard, nil
		}
		return vectorLeaseModeSoft, nil
	case vectorLeaseModeHard:
		if !(caps.ConditionalIfNoneMatch && caps.ConditionalIfMatch) {
			return "", fmt.Errorf("hard lease mode requires both conditional_if_none_match and conditional_if_match support")
		}
		return vectorLeaseModeHard, nil
	case vectorLeaseModeSoft:
		return vectorLeaseModeSoft, nil
	case vectorLeaseModeOff:
		return vectorLeaseModeOff, nil
	default:
		return "", fmt.Errorf("unsupported lease mode %q", normalized)
	}
}

func vectorWriterLeaseObjectKey(cfg remoteGlobalConfig, resource string) string {
	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	parts := make([]string, 0, 4)
	if base != "" {
		parts = append(parts, base)
	}
	parts = append(parts, vectorLeasePrefix, resource+".json")
	return strings.Join(parts, "/")
}

func defaultVectorLeaseOwnerID() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	return hostname + ":" + strconv.Itoa(os.Getpid())
}

func acquireVectorWriterLease(ctx context.Context, logger *log.Logger, bootstrap remoteS3Bootstrap, cfg remoteGlobalConfig) (*vectorWriterLease, error) {
	mode, err := resolveVectorLeaseMode(cfg.Coordination.VectorWriterLease.Mode, cfg.S3.Capabilities)
	if err != nil {
		return nil, err
	}
	if mode == vectorLeaseModeOff {
		return nil, nil
	}
	duration := time.Duration(cfg.Coordination.VectorWriterLease.DurationSeconds) * time.Second
	if duration <= 0 {
		duration = time.Duration(defaultVectorLeaseDurationSeconds) * time.Second
	}
	renewInterval := time.Duration(cfg.Coordination.VectorWriterLease.RenewIntervalSeconds) * time.Second
	if renewInterval <= 0 {
		renewInterval = time.Duration(defaultVectorLeaseRenewIntervalSeconds) * time.Second
	}
	resource := strings.TrimSpace(cfg.Coordination.VectorWriterLease.Resource)
	if resource == "" {
		resource = defaultVectorLeaseResource
	}

	client, err := newS3ClientFromBootstrapWithResponseChecksumValidation(ctx, bootstrap, responseChecksumValidationForCapabilities(cfg.S3.Capabilities))
	if err != nil {
		return nil, err
	}
	lease := &vectorWriterLease{
		client:        client,
		bootstrap:     bootstrap,
		capabilities:  cfg.S3.Capabilities,
		mode:          mode,
		objectKey:     vectorWriterLeaseObjectKey(cfg, resource),
		resource:      resource,
		ownerID:       defaultVectorLeaseOwnerID(),
		leaseID:       uuid.NewString(),
		logger:        logger,
		duration:      duration,
		renewInterval: renewInterval,
		renewComplete: make(chan struct{}),
		lostCh:        make(chan error, 1),
	}
	if err := lease.acquire(ctx); err != nil {
		return nil, err
	}
	lease.startRenewLoop()
	return lease, nil
}

func (l *vectorWriterLease) Lost() <-chan error {
	if l == nil {
		return nil
	}
	return l.lostCh
}

func (l *vectorWriterLease) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return nil
	}
	l.released = true
	cancel := l.renewCancel
	l.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	select {
	case <-l.renewComplete:
	case <-ctx.Done():
		return ctx.Err()
	}
	return l.releaseBestEffort(ctx)
}

func (l *vectorWriterLease) startRenewLoop() {
	renewCtx, cancel := context.WithCancel(context.Background())
	l.mu.Lock()
	l.renewCancel = cancel
	l.mu.Unlock()

	go func() {
		defer close(l.renewComplete)
		ticker := time.NewTicker(l.renewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-renewCtx.Done():
				return
			case <-ticker.C:
				if err := l.renew(renewCtx); err != nil {
					l.reportLoss(err)
					return
				}
			}
		}
	}()
}

func (l *vectorWriterLease) reportLoss(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	if l.lostReported {
		l.mu.Unlock()
		return
	}
	l.lostReported = true
	l.mu.Unlock()

	select {
	case l.lostCh <- err:
	default:
	}
}

func (l *vectorWriterLease) acquire(ctx context.Context) error {
	now := time.Now().UTC()
	record := l.buildRecord(now)

	if l.capabilities.ConditionalIfNoneMatch {
		etag, err := l.putRecord(ctx, record, "*", "")
		if err == nil {
			l.setLeaseState(etag, now.Add(l.duration))
			l.logf("lease acquired (mode=%s key=s3://%s/%s)", l.mode, l.bootstrap.Bucket, l.objectKey)
			return nil
		}
		if !isS3PreconditionFailed(err) {
			return fmt.Errorf("acquire vector lease: %w", err)
		}
	}

	current, etag, found, err := l.getCurrentRecord(ctx)
	if err != nil {
		return err
	}
	if !found {
		etag, err := l.putRecord(ctx, record, "", "")
		if err != nil {
			return fmt.Errorf("create vector lease object: %w", err)
		}
		l.setLeaseState(etag, now.Add(l.duration))
		l.logf("lease acquired (mode=%s key=s3://%s/%s)", l.mode, l.bootstrap.Bucket, l.objectKey)
		return nil
	}

	expiresAt, parseErr := parseLeaseExpiry(current.ExpiresAtUTC)
	if parseErr != nil {
		return fmt.Errorf("parse existing lease expiry: %w", parseErr)
	}
	if expiresAt.After(now) && !strings.EqualFold(current.LeaseID, l.leaseID) {
		return fmt.Errorf("vector writer lease currently held by %s until %s", current.OwnerID, expiresAt.Format(time.RFC3339))
	}

	match := ""
	if l.mode == vectorLeaseModeHard {
		match = etag
	}
	nextETag, err := l.putRecord(ctx, record, "", match)
	if err != nil {
		if l.mode == vectorLeaseModeHard && isS3PreconditionFailed(err) {
			return fmt.Errorf("vector writer lease takeover raced with another writer")
		}
		return fmt.Errorf("take over expired vector writer lease: %w", err)
	}
	l.setLeaseState(nextETag, now.Add(l.duration))
	l.logf("lease acquired (mode=%s key=s3://%s/%s)", l.mode, l.bootstrap.Bucket, l.objectKey)
	return nil
}

func (l *vectorWriterLease) renew(ctx context.Context) error {
	now := time.Now().UTC()
	record := l.buildRecord(now)

	if l.mode == vectorLeaseModeHard {
		match := l.currentETag()
		if strings.TrimSpace(match) == "" {
			return fmt.Errorf("hard lease renew requires etag")
		}
		etag, err := l.putRecord(ctx, record, "", match)
		if err != nil {
			if isS3PreconditionFailed(err) {
				return fmt.Errorf("vector writer lease lost (etag mismatch)")
			}
			return fmt.Errorf("renew hard lease: %w", err)
		}
		l.setLeaseState(etag, now.Add(l.duration))
		return nil
	}

	current, _, found, err := l.getCurrentRecord(ctx)
	if err != nil {
		return err
	}
	if found {
		expiresAt, parseErr := parseLeaseExpiry(current.ExpiresAtUTC)
		if parseErr != nil {
			return fmt.Errorf("parse current soft lease expiry: %w", parseErr)
		}
		if current.LeaseID != l.leaseID && expiresAt.After(now) {
			return fmt.Errorf("vector writer lease lost to %s", current.OwnerID)
		}
	}

	etag, err := l.putRecord(ctx, record, "", "")
	if err != nil {
		return fmt.Errorf("renew soft lease: %w", err)
	}
	l.setLeaseState(etag, now.Add(l.duration))
	return nil
}

func (l *vectorWriterLease) releaseBestEffort(ctx context.Context) error {
	if l.mode != vectorLeaseModeHard {
		return nil
	}
	match := l.currentETag()
	if strings.TrimSpace(match) == "" {
		return nil
	}
	now := time.Now().UTC().Add(-time.Second)
	record := l.buildRecord(now)
	_, err := l.putRecord(ctx, record, "", match)
	if err != nil && !isS3PreconditionFailed(err) {
		return fmt.Errorf("release vector writer lease: %w", err)
	}
	return nil
}

func (l *vectorWriterLease) putRecord(ctx context.Context, record vectorWriterLeaseRecord, ifNoneMatch string, ifMatch string) (string, error) {
	body, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("marshal lease record: %w", err)
	}
	input := &s3.PutObjectInput{
		Bucket:      aws.String(l.bootstrap.Bucket),
		Key:         aws.String(l.objectKey),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	}
	if strings.TrimSpace(ifNoneMatch) != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if strings.TrimSpace(ifMatch) != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	resp, err := l.client.PutObject(ctx, input)
	if err != nil {
		return "", err
	}
	return strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\""), nil
}

func (l *vectorWriterLease) getCurrentRecord(ctx context.Context) (vectorWriterLeaseRecord, string, bool, error) {
	resp, err := l.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.bootstrap.Bucket),
		Key:    aws.String(l.objectKey),
	})
	if err != nil {
		if isS3NotFound(err) {
			return vectorWriterLeaseRecord{}, "", false, nil
		}
		return vectorWriterLeaseRecord{}, "", false, fmt.Errorf("read existing vector lease: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return vectorWriterLeaseRecord{}, "", false, fmt.Errorf("read existing lease payload: %w", err)
	}
	record := vectorWriterLeaseRecord{}
	if err := json.Unmarshal(body, &record); err != nil {
		return vectorWriterLeaseRecord{}, "", false, fmt.Errorf("decode existing lease payload: %w", err)
	}
	etag := strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\"")
	return record, etag, true, nil
}

func parseLeaseExpiry(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty lease expiry")
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func (l *vectorWriterLease) setLeaseState(etag string, expiresAt time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.TrimSpace(etag) != "" {
		l.etag = strings.TrimSpace(etag)
	}
	l.expiresAt = expiresAt.UTC()
}

func (l *vectorWriterLease) currentETag() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.TrimSpace(l.etag)
}

func (l *vectorWriterLease) buildRecord(now time.Time) vectorWriterLeaseRecord {
	issued := now.UTC()
	expires := issued.Add(l.duration).UTC()
	return vectorWriterLeaseRecord{
		Schema:       "forge.vector_writer_lease.v1",
		Resource:     l.resource,
		Mode:         l.mode,
		OwnerID:      l.ownerID,
		LeaseID:      l.leaseID,
		IssuedAtUTC:  issued.Format(time.RFC3339Nano),
		ExpiresAtUTC: expires.Format(time.RFC3339Nano),
	}
}

func (l *vectorWriterLease) logf(format string, args ...any) {
	if l.logger != nil {
		l.logger.Printf(format, args...)
	}
}
