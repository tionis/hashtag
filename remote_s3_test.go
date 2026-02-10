package main

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestRemoteBlobObjectKey(t *testing.T) {
	cfg := defaultRemoteGlobalConfig()
	cfg.S3.ObjectPrefix = "forge-data"
	cfg.S3.BlobPrefix = "blob-store"
	oid := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	key, err := remoteBlobObjectKey(cfg, oid)
	if err != nil {
		t.Fatalf("remote blob object key: %v", err)
	}
	expected := "forge-data/blob-store/01/23/" + oid + ".fblob"
	if key != expected {
		t.Fatalf("expected key %q, got %q", expected, key)
	}
}

func TestResponseChecksumValidationForCapabilities(t *testing.T) {
	mode := responseChecksumValidationForCapabilities(remoteS3Capabilities{ResponseChecksums: true})
	if mode != aws.ResponseChecksumValidationWhenSupported {
		t.Fatalf("expected WhenSupported mode when response checksums are supported, got %v", mode)
	}

	mode = responseChecksumValidationForCapabilities(remoteS3Capabilities{ResponseChecksums: false})
	if mode != aws.ResponseChecksumValidationWhenRequired {
		t.Fatalf("expected WhenRequired mode when response checksums are unsupported, got %v", mode)
	}
}

func TestHasSupportedResponseChecksum(t *testing.T) {
	if hasSupportedResponseChecksum(nil) {
		t.Fatal("expected nil response to have no checksum support")
	}

	withoutChecksums := &s3.GetObjectOutput{}
	if hasSupportedResponseChecksum(withoutChecksums) {
		t.Fatal("expected empty response checksum fields to be unsupported")
	}

	withChecksum := &s3.GetObjectOutput{
		ChecksumSHA256: aws.String("abc"),
	}
	if !hasSupportedResponseChecksum(withChecksum) {
		t.Fatal("expected checksum field to be detected as supported")
	}
}
