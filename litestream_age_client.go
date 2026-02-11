package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/benbjohnson/litestream"
	"github.com/superfly/ltx"
)

var ageEnvelopeMagic = [4]byte{'F', 'A', 'G', '1'}

const ageEnvelopeHeaderSize = 12 // 4-byte magic + 8-byte plaintext length

type ageEncryptedReplicaClient struct {
	base       litestream.ReplicaClient
	recipients []age.Recipient
	identities []age.Identity
}

type ageEncryptedLTXFileIterator struct {
	ctx    context.Context
	base   ltx.FileIterator
	client *ageEncryptedReplicaClient

	current *ltx.FileInfo
	err     error
}

func newAgeEncryptedReplicaClient(base litestream.ReplicaClient, recipients []age.Recipient, identities []age.Identity) (litestream.ReplicaClient, error) {
	if base == nil {
		return nil, fmt.Errorf("base replica client is required")
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one age recipient is required")
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("at least one age identity is required")
	}
	return &ageEncryptedReplicaClient{
		base:       base,
		recipients: recipients,
		identities: identities,
	}, nil
}

func (c *ageEncryptedReplicaClient) Type() string {
	return c.base.Type() + "+forge-age"
}

func (c *ageEncryptedReplicaClient) Init(ctx context.Context) error {
	return c.base.Init(ctx)
}

func (c *ageEncryptedReplicaClient) LTXFiles(ctx context.Context, level int, seek ltx.TXID, useMetadata bool) (ltx.FileIterator, error) {
	itr, err := c.base.LTXFiles(ctx, level, seek, useMetadata)
	if err != nil {
		return nil, err
	}
	return &ageEncryptedLTXFileIterator{
		ctx:    ctx,
		base:   itr,
		client: c,
	}, nil
}

func (c *ageEncryptedReplicaClient) OpenLTXFile(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID, offset int64, size int64) (io.ReadCloser, error) {
	plaintext, err := c.readAndDecryptLTX(ctx, level, minTXID, maxTXID)
	if err != nil {
		return nil, err
	}
	sliced, err := applyOffsetAndSize(plaintext, offset, size)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(sliced)), nil
}

func (c *ageEncryptedReplicaClient) WriteLTXFile(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID, r io.Reader) (*ltx.FileInfo, error) {
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read plaintext ltx payload: %w", err)
	}
	ciphertext, err := c.encryptEnvelope(plaintext)
	if err != nil {
		return nil, err
	}
	info, err := c.base.WriteLTXFile(ctx, level, minTXID, maxTXID, bytes.NewReader(ciphertext))
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}
	infoCopy := *info
	infoCopy.Size = int64(len(plaintext))
	return &infoCopy, nil
}

func (c *ageEncryptedReplicaClient) DeleteLTXFiles(ctx context.Context, a []*ltx.FileInfo) error {
	return c.base.DeleteLTXFiles(ctx, a)
}

func (c *ageEncryptedReplicaClient) DeleteAll(ctx context.Context) error {
	return c.base.DeleteAll(ctx)
}

func (c *ageEncryptedReplicaClient) readAndDecryptLTX(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID) ([]byte, error) {
	reader, err := c.base.OpenLTXFile(ctx, level, minTXID, maxTXID, 0, 0)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decryptedReader, err := age.Decrypt(reader, c.identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypt ltx file %s/%s: %w", minTXID.String(), maxTXID.String(), err)
	}
	envelope, err := io.ReadAll(decryptedReader)
	if err != nil {
		return nil, fmt.Errorf("read decrypted ltx envelope: %w", err)
	}
	plaintext, err := decodeAgeEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted ltx envelope: %w", err)
	}
	return plaintext, nil
}

func (c *ageEncryptedReplicaClient) readEncryptedLTXSize(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID) (int64, error) {
	reader, err := c.base.OpenLTXFile(ctx, level, minTXID, maxTXID, 0, 0)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	decryptedReader, err := age.Decrypt(reader, c.identities...)
	if err != nil {
		return 0, fmt.Errorf("decrypt ltx file header %s/%s: %w", minTXID.String(), maxTXID.String(), err)
	}
	header := make([]byte, ageEnvelopeHeaderSize)
	if _, err := io.ReadFull(decryptedReader, header); err != nil {
		return 0, fmt.Errorf("read encrypted ltx envelope header: %w", err)
	}
	if !bytes.Equal(header[:4], ageEnvelopeMagic[:]) {
		return 0, fmt.Errorf("invalid encrypted ltx envelope magic")
	}
	plainSize := binary.BigEndian.Uint64(header[4:])
	if plainSize > uint64((1<<63)-1) {
		return 0, fmt.Errorf("encrypted ltx envelope plaintext size overflow")
	}
	return int64(plainSize), nil
}

func (c *ageEncryptedReplicaClient) encryptEnvelope(plaintext []byte) ([]byte, error) {
	envelope := make([]byte, ageEnvelopeHeaderSize+len(plaintext))
	copy(envelope[:4], ageEnvelopeMagic[:])
	binary.BigEndian.PutUint64(envelope[4:], uint64(len(plaintext)))
	copy(envelope[ageEnvelopeHeaderSize:], plaintext)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, c.recipients...)
	if err != nil {
		return nil, fmt.Errorf("encrypt ltx envelope: %w", err)
	}
	if _, err := w.Write(envelope); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("write encrypted ltx envelope: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finalize encrypted ltx envelope: %w", err)
	}
	return buf.Bytes(), nil
}

func decodeAgeEnvelope(envelope []byte) ([]byte, error) {
	if len(envelope) < ageEnvelopeHeaderSize {
		return nil, fmt.Errorf("encrypted envelope too short: %d", len(envelope))
	}
	if !bytes.Equal(envelope[:4], ageEnvelopeMagic[:]) {
		return nil, fmt.Errorf("invalid encrypted envelope magic")
	}
	plainSize := binary.BigEndian.Uint64(envelope[4:])
	payload := envelope[ageEnvelopeHeaderSize:]
	if uint64(len(payload)) != plainSize {
		return nil, fmt.Errorf("encrypted envelope size mismatch: header=%d payload=%d", plainSize, len(payload))
	}
	return payload, nil
}

func applyOffsetAndSize(plaintext []byte, offset int64, size int64) ([]byte, error) {
	if offset < 0 {
		return nil, fmt.Errorf("offset must be >= 0")
	}
	if size < 0 {
		return nil, fmt.Errorf("size must be >= 0")
	}
	start := int(offset)
	if start > len(plaintext) {
		return []byte{}, nil
	}
	end := len(plaintext)
	if size > 0 {
		candidate := start + int(size)
		if candidate < end {
			end = candidate
		}
	}
	return plaintext[start:end], nil
}

func (itr *ageEncryptedLTXFileIterator) Close() error {
	return itr.base.Close()
}

func (itr *ageEncryptedLTXFileIterator) Next() bool {
	if itr.err != nil {
		return false
	}
	for itr.base.Next() {
		baseItem := itr.base.Item()
		if baseItem == nil {
			continue
		}
		plainSize, err := itr.client.readEncryptedLTXSize(itr.ctx, baseItem.Level, baseItem.MinTXID, baseItem.MaxTXID)
		if err != nil {
			itr.err = err
			return false
		}
		item := *baseItem
		item.Size = plainSize
		itr.current = &item
		return true
	}
	if err := itr.base.Err(); err != nil {
		itr.err = err
	}
	return false
}

func (itr *ageEncryptedLTXFileIterator) Err() error {
	if itr.err != nil {
		return itr.err
	}
	return itr.base.Err()
}

func (itr *ageEncryptedLTXFileIterator) Item() *ltx.FileInfo {
	return itr.current
}
