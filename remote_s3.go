package main

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

type blobRemoteStore interface {
	BackendName() string
	BucketName() string
	PutBlob(ctx context.Context, oid string, encoded []byte) (string, error)
	GetBlob(ctx context.Context, oid string) ([]byte, string, bool, error)
	DeleteBlob(ctx context.Context, oid string) (bool, error)
}

type s3BlobRemoteStore struct {
	client    *s3.Client
	bootstrap remoteS3Bootstrap
	cfg       remoteGlobalConfig
}

var errRemoteConfigNotFound = stderrors.New("remote config object not found")

func newS3ClientFromBootstrap(ctx context.Context, bootstrap remoteS3Bootstrap) (*s3.Client, error) {
	return newS3ClientFromBootstrapWithResponseChecksumValidation(ctx, bootstrap, aws.ResponseChecksumValidationWhenRequired)
}

func newS3ClientFromBootstrapWithResponseChecksumValidation(ctx context.Context, bootstrap remoteS3Bootstrap, mode aws.ResponseChecksumValidation) (*s3.Client, error) {
	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(bootstrap.Region),
	}
	if bootstrap.AccessKeyID != "" && bootstrap.SecretAccess != "" {
		loadOptions = append(loadOptions, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(bootstrap.AccessKeyID, bootstrap.SecretAccess, bootstrap.SessionToken),
		))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	awsCfg.ResponseChecksumValidation = mode

	return s3.NewFromConfig(awsCfg, func(opts *s3.Options) {
		if bootstrap.EndpointURL != "" {
			opts.BaseEndpoint = aws.String(bootstrap.EndpointURL)
		}
		opts.UsePathStyle = bootstrap.ForcePathStyle
	}), nil
}

func loadRemoteConfigObjectFromS3(ctx context.Context, client *s3.Client, bootstrap remoteS3Bootstrap) ([]byte, string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(bootstrap.Bucket),
		Key:    aws.String(bootstrap.ConfigKey),
	}
	resp, err := client.GetObject(ctx, input)
	if err != nil {
		if isS3NotFound(err) {
			return nil, "", fmt.Errorf("%w: s3://%s/%s (run `forge remote config init` first)", errRemoteConfigNotFound, bootstrap.Bucket, bootstrap.ConfigKey)
		}
		return nil, "", fmt.Errorf("read remote config object s3://%s/%s: %w", bootstrap.Bucket, bootstrap.ConfigKey, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read remote config payload: %w", err)
	}
	etag := strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\"")
	return payload, etag, nil
}

func loadRemoteGlobalConfigFromS3(ctx context.Context, client *s3.Client, bootstrap remoteS3Bootstrap) (remoteGlobalConfig, remoteSignedDocumentMetadata, string, error) {
	payload, etag, err := loadRemoteConfigObjectFromS3(ctx, client, bootstrap)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, "", err
	}
	cfg, trustMeta, err := decodeAndValidateSignedRemoteGlobalConfig(payload, bootstrap)
	if err != nil {
		return remoteGlobalConfig{}, remoteSignedDocumentMetadata{}, "", fmt.Errorf("verify remote config object s3://%s/%s: %w", bootstrap.Bucket, bootstrap.ConfigKey, err)
	}
	return cfg, trustMeta, etag, nil
}

func putRemoteGlobalConfigDocumentToS3(ctx context.Context, client *s3.Client, bootstrap remoteS3Bootstrap, payload []byte, overwrite bool, supportsIfNoneMatch bool) (string, error) {
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bootstrap.Bucket),
		Key:         aws.String(bootstrap.ConfigKey),
		Body:        bytes.NewReader(payload),
		ContentType: aws.String("application/json"),
	}
	if !overwrite {
		if supportsIfNoneMatch {
			input.IfNoneMatch = aws.String("*")
		} else {
			_, headErr := client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(bootstrap.Bucket),
				Key:    aws.String(bootstrap.ConfigKey),
			})
			if headErr == nil {
				return "", fmt.Errorf("remote config already exists at s3://%s/%s (use -overwrite to replace)", bootstrap.Bucket, bootstrap.ConfigKey)
			}
			if !isS3NotFound(headErr) {
				return "", fmt.Errorf("check existing remote config object s3://%s/%s: %w", bootstrap.Bucket, bootstrap.ConfigKey, headErr)
			}
		}
	}
	resp, err := client.PutObject(ctx, input)
	if err != nil {
		if isS3PreconditionFailed(err) && !overwrite {
			return "", fmt.Errorf("remote config already exists at s3://%s/%s (use -overwrite to replace)", bootstrap.Bucket, bootstrap.ConfigKey)
		}
		return "", fmt.Errorf("write remote config object s3://%s/%s: %w", bootstrap.Bucket, bootstrap.ConfigKey, err)
	}
	etag := strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\"")
	return etag, nil
}

func openConfiguredBlobRemoteStore(ctx context.Context) (blobRemoteStore, error) {
	session, err := loadRemoteBackendSession(ctx)
	if err != nil {
		return nil, err
	}
	client, err := session.newS3Client(ctx)
	if err != nil {
		return nil, err
	}
	return &s3BlobRemoteStore{
		client:    client,
		bootstrap: session.Bootstrap,
		cfg:       session.Config,
	}, nil
}

func responseChecksumValidationForCapabilities(caps remoteS3Capabilities) aws.ResponseChecksumValidation {
	if caps.ResponseChecksums {
		return aws.ResponseChecksumValidationWhenSupported
	}
	return aws.ResponseChecksumValidationWhenRequired
}

func (s *s3BlobRemoteStore) BackendName() string {
	return defaultS3BackendName
}

func (s *s3BlobRemoteStore) BucketName() string {
	return s.bootstrap.Bucket
}

func (s *s3BlobRemoteStore) objectKeyForOID(oid string) (string, error) {
	return remoteBlobObjectKey(s.cfg, oid)
}

func (s *s3BlobRemoteStore) PutBlob(ctx context.Context, oid string, encoded []byte) (string, error) {
	objectKey, err := s.objectKeyForOID(oid)
	if err != nil {
		return "", err
	}
	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bootstrap.Bucket),
		Key:         aws.String(objectKey),
		Body:        bytes.NewReader(encoded),
		ContentType: aws.String("application/octet-stream"),
	}
	if s.cfg.S3.Capabilities.ConditionalIfNoneMatch {
		input.IfNoneMatch = aws.String("*")
	}
	resp, err := s.client.PutObject(ctx, input)
	if err != nil {
		if s.cfg.S3.Capabilities.ConditionalIfNoneMatch && isS3PreconditionFailed(err) {
			headResp, headErr := s.client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(s.bootstrap.Bucket),
				Key:    aws.String(objectKey),
			})
			if headErr != nil {
				return "", fmt.Errorf("put blob %q and resolve existing object: %w (head error: %v)", oid, err, headErr)
			}
			return strings.Trim(strings.TrimSpace(aws.ToString(headResp.ETag)), "\""), nil
		}
		return "", fmt.Errorf("put blob %q to s3://%s/%s: %w", oid, s.bootstrap.Bucket, objectKey, err)
	}
	return strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\""), nil
}

func (s *s3BlobRemoteStore) GetBlob(ctx context.Context, oid string) ([]byte, string, bool, error) {
	objectKey, err := s.objectKeyForOID(oid)
	if err != nil {
		return nil, "", false, err
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bootstrap.Bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, "", false, nil
		}
		return nil, "", false, fmt.Errorf("get blob %q from s3://%s/%s: %w", oid, s.bootstrap.Bucket, objectKey, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, fmt.Errorf("read blob body for %q: %w", oid, err)
	}
	etag := strings.Trim(strings.TrimSpace(aws.ToString(resp.ETag)), "\"")
	return payload, etag, true, nil
}

func (s *s3BlobRemoteStore) DeleteBlob(ctx context.Context, oid string) (bool, error) {
	objectKey, err := s.objectKeyForOID(oid)
	if err != nil {
		return false, err
	}
	_, headErr := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bootstrap.Bucket),
		Key:    aws.String(objectKey),
	})
	if headErr != nil {
		if isS3NotFound(headErr) {
			return false, nil
		}
		return false, fmt.Errorf("head blob %q at s3://%s/%s: %w", oid, s.bootstrap.Bucket, objectKey, headErr)
	}

	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bootstrap.Bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return false, fmt.Errorf("delete blob %q from s3://%s/%s: %w", oid, s.bootstrap.Bucket, objectKey, err)
	}
	return true, nil
}

func remoteBlobObjectKey(cfg remoteGlobalConfig, oid string) (string, error) {
	normalizedOID := normalizeDigestHex(oid)
	if err := validateBlobOID(normalizedOID); err != nil {
		return "", err
	}
	base := normalizeS3Prefix(cfg.S3.ObjectPrefix)
	blobPrefix := normalizeS3Prefix(cfg.S3.BlobPrefix)
	if blobPrefix == "" {
		blobPrefix = defaultS3BlobKeyPrefix
	}

	parts := make([]string, 0, 5)
	if base != "" {
		parts = append(parts, base)
	}
	parts = append(parts, blobPrefix, normalizedOID[:2], normalizedOID[2:4], normalizedOID+".fblob")
	return strings.Join(parts, "/"), nil
}

func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	var noSuchKey *types.NoSuchKey
	if stderrors.As(err, &noSuchKey) {
		return true
	}
	var apiErr smithy.APIError
	if stderrors.As(err, &apiErr) {
		code := strings.TrimSpace(apiErr.ErrorCode())
		return code == "NoSuchKey" || code == "NotFound" || code == "404"
	}
	return false
}

func isS3PreconditionFailed(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if stderrors.As(err, &apiErr) {
		code := strings.TrimSpace(apiErr.ErrorCode())
		return code == "PreconditionFailed" || code == "412"
	}
	return false
}

func isS3APIError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	return stderrors.As(err, &apiErr)
}

func capabilityProbeObjectKey(configKey string) string {
	base := normalizeS3ObjectKey(configKey)
	if base == "" {
		base = defaultRemoteConfigKey
	}
	base = strings.TrimSuffix(base, ".json")
	return fmt.Sprintf("%s.capability-probe/%d-%d", base, time.Now().UTC().UnixNano(), os.Getpid())
}

func detectRemoteS3Capabilities(ctx context.Context, client *s3.Client, bootstrap remoteS3Bootstrap) (remoteS3Capabilities, error) {
	caps := remoteS3Capabilities{}
	probeKey := capabilityProbeObjectKey(bootstrap.ConfigKey)
	bucket := aws.String(bootstrap.Bucket)
	key := aws.String(probeKey)
	defer func() {
		_, _ = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: bucket,
			Key:    key,
		})
	}()

	firstPayload := []byte("forge-capability-probe-v1-a\n")
	wroteProbeWithChecksum := false
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:            bucket,
		Key:               key,
		Body:              bytes.NewReader(firstPayload),
		ContentType:       aws.String("application/octet-stream"),
		ChecksumAlgorithm: types.ChecksumAlgorithmSha256,
	}); err != nil {
		if !isS3APIError(err) {
			return caps, fmt.Errorf("create capability probe object s3://%s/%s: %w", bootstrap.Bucket, probeKey, err)
		}
		if _, fallbackErr := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      bucket,
			Key:         key,
			Body:        bytes.NewReader(firstPayload),
			ContentType: aws.String("application/octet-stream"),
		}); fallbackErr != nil {
			return caps, fmt.Errorf("create capability probe object s3://%s/%s: %w", bootstrap.Bucket, probeKey, fallbackErr)
		}
	} else {
		wroteProbeWithChecksum = true
	}

	if wroteProbeWithChecksum {
		getResp, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket:       bucket,
			Key:          key,
			ChecksumMode: types.ChecksumModeEnabled,
		})
		if err != nil {
			if !isS3APIError(err) {
				return caps, fmt.Errorf("probe response checksum support: %w", err)
			}
		} else {
			caps.ResponseChecksums = hasSupportedResponseChecksum(getResp)
			_, _ = io.Copy(io.Discard, getResp.Body)
			getResp.Body.Close()
		}
	}

	secondPayload := []byte("forge-capability-probe-v1-b\n")
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      bucket,
		Key:         key,
		Body:        bytes.NewReader(secondPayload),
		ContentType: aws.String("application/octet-stream"),
		IfNoneMatch: aws.String("*"),
	}); err != nil {
		if isS3PreconditionFailed(err) {
			caps.ConditionalIfNoneMatch = true
		} else if !isS3APIError(err) {
			return caps, fmt.Errorf("probe If-None-Match support: %w", err)
		}
	}

	headResp, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: bucket,
		Key:    key,
	})
	if err != nil {
		return caps, fmt.Errorf("read capability probe object metadata: %w", err)
	}
	matchValue := strings.TrimSpace(aws.ToString(headResp.ETag))
	if matchValue == "" {
		return caps, nil
	}

	thirdPayload := []byte("forge-capability-probe-v1-c\n")
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      bucket,
		Key:         key,
		Body:        bytes.NewReader(thirdPayload),
		ContentType: aws.String("application/octet-stream"),
		IfMatch:     aws.String(matchValue),
	}); err != nil {
		if isS3PreconditionFailed(err) || isS3APIError(err) {
			caps.ConditionalIfMatch = false
			return caps, nil
		}
		return caps, fmt.Errorf("probe If-Match support (matching ETag): %w", err)
	}

	badMatch := "\"forge-invalid-etag\""
	if _, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      bucket,
		Key:         key,
		Body:        bytes.NewReader(secondPayload),
		ContentType: aws.String("application/octet-stream"),
		IfMatch:     aws.String(badMatch),
	}); err != nil {
		if isS3PreconditionFailed(err) {
			caps.ConditionalIfMatch = true
			return caps, nil
		}
		if isS3APIError(err) {
			caps.ConditionalIfMatch = false
			return caps, nil
		}
		return caps, fmt.Errorf("probe If-Match support (mismatched ETag): %w", err)
	}

	caps.ConditionalIfMatch = false
	return caps, nil
}

func hasSupportedResponseChecksum(resp *s3.GetObjectOutput) bool {
	if resp == nil {
		return false
	}
	return strings.TrimSpace(aws.ToString(resp.ChecksumCRC32)) != "" ||
		strings.TrimSpace(aws.ToString(resp.ChecksumCRC32C)) != "" ||
		strings.TrimSpace(aws.ToString(resp.ChecksumCRC64NVME)) != "" ||
		strings.TrimSpace(aws.ToString(resp.ChecksumSHA1)) != "" ||
		strings.TrimSpace(aws.ToString(resp.ChecksumSHA256)) != ""
}
