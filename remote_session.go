package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type remoteBackendSession struct {
	Bootstrap remoteS3Bootstrap
	Config    remoteGlobalConfig
}

func loadRemoteBackendSession(ctx context.Context) (remoteBackendSession, error) {
	bootstrap, err := loadRemoteS3BootstrapFromEnv()
	if err != nil {
		return remoteBackendSession{}, err
	}
	cfg, _, err := loadRemoteGlobalConfigWithCache(ctx, bootstrap, nil)
	if err != nil {
		return remoteBackendSession{}, err
	}
	return remoteBackendSession{
		Bootstrap: bootstrap,
		Config:    cfg,
	}, nil
}

func (s remoteBackendSession) newS3Client(ctx context.Context) (*s3.Client, error) {
	client, err := newS3ClientFromBootstrapWithResponseChecksumValidation(
		ctx,
		s.Bootstrap,
		responseChecksumValidationForCapabilities(s.Config.S3.Capabilities),
	)
	if err != nil {
		return nil, fmt.Errorf("create s3 client from remote backend session: %w", err)
	}
	return client, nil
}
