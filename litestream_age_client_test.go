package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/superfly/ltx"
)

type fakeReplicaClient struct {
	files map[string][]byte
	infos map[string]*ltx.FileInfo
}

func newFakeReplicaClient() *fakeReplicaClient {
	return &fakeReplicaClient{
		files: make(map[string][]byte),
		infos: make(map[string]*ltx.FileInfo),
	}
}

func (f *fakeReplicaClient) Type() string {
	return "fake"
}

func (f *fakeReplicaClient) Init(ctx context.Context) error {
	return nil
}

func (f *fakeReplicaClient) LTXFiles(ctx context.Context, level int, seek ltx.TXID, useMetadata bool) (ltx.FileIterator, error) {
	files := make([]*ltx.FileInfo, 0, len(f.infos))
	for _, info := range f.infos {
		if info.Level != level {
			continue
		}
		if seek > 0 && info.MaxTXID < seek {
			continue
		}
		infoCopy := *info
		files = append(files, &infoCopy)
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].MinTXID != files[j].MinTXID {
			return files[i].MinTXID < files[j].MinTXID
		}
		return files[i].MaxTXID < files[j].MaxTXID
	})
	return ltx.NewFileInfoSliceIterator(files), nil
}

func (f *fakeReplicaClient) OpenLTXFile(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID, offset int64, size int64) (io.ReadCloser, error) {
	key := fakeLTXKey(level, minTXID, maxTXID)
	payload, ok := f.files[key]
	if !ok {
		return nil, io.EOF
	}
	start := int(offset)
	if start > len(payload) {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	end := len(payload)
	if size > 0 {
		candidate := start + int(size)
		if candidate < end {
			end = candidate
		}
	}
	return io.NopCloser(bytes.NewReader(payload[start:end])), nil
}

func (f *fakeReplicaClient) WriteLTXFile(ctx context.Context, level int, minTXID ltx.TXID, maxTXID ltx.TXID, r io.Reader) (*ltx.FileInfo, error) {
	key := fakeLTXKey(level, minTXID, maxTXID)
	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	f.files[key] = payload
	info := &ltx.FileInfo{
		Level:     level,
		MinTXID:   minTXID,
		MaxTXID:   maxTXID,
		Size:      int64(len(payload)),
		CreatedAt: time.Now().UTC(),
	}
	f.infos[key] = info
	return info, nil
}

func (f *fakeReplicaClient) DeleteLTXFiles(ctx context.Context, a []*ltx.FileInfo) error {
	for _, info := range a {
		key := fakeLTXKey(info.Level, info.MinTXID, info.MaxTXID)
		delete(f.files, key)
		delete(f.infos, key)
	}
	return nil
}

func (f *fakeReplicaClient) DeleteAll(ctx context.Context) error {
	clear(f.files)
	clear(f.infos)
	return nil
}

func fakeLTXKey(level int, minTXID ltx.TXID, maxTXID ltx.TXID) string {
	return fmt.Sprintf("%d:%s:%s", level, minTXID.String(), maxTXID.String())
}

func TestAgeEncryptedReplicaClientWriteAndRead(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate x25519 identity: %v", err)
	}

	base := newFakeReplicaClient()
	client, err := newAgeEncryptedReplicaClient(base, []age.Recipient{identity.Recipient()}, []age.Identity{identity})
	if err != nil {
		t.Fatalf("newAgeEncryptedReplicaClient error: %v", err)
	}

	plaintext := []byte("test-ltx-payload")
	if _, err := client.WriteLTXFile(context.Background(), 0, 1, 1, bytes.NewReader(plaintext)); err != nil {
		t.Fatalf("WriteLTXFile error: %v", err)
	}

	rawCipher := base.files[fakeLTXKey(0, 1, 1)]
	if bytes.Contains(rawCipher, plaintext) {
		t.Fatal("expected encrypted payload in base client")
	}

	reader, err := client.OpenLTXFile(context.Background(), 0, 1, 1, 0, 0)
	if err != nil {
		t.Fatalf("OpenLTXFile error: %v", err)
	}
	got, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("read decrypted payload: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted payload mismatch: got %q want %q", string(got), string(plaintext))
	}

	reader, err = client.OpenLTXFile(context.Background(), 0, 1, 1, 5, 4)
	if err != nil {
		t.Fatalf("OpenLTXFile ranged error: %v", err)
	}
	got, err = io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("read ranged payload: %v", err)
	}
	if string(got) != "ltx-" {
		t.Fatalf("unexpected ranged payload: %q", string(got))
	}

	itr, err := client.LTXFiles(context.Background(), 0, 0, false)
	if err != nil {
		t.Fatalf("LTXFiles error: %v", err)
	}
	defer itr.Close()
	if !itr.Next() {
		t.Fatal("expected at least one LTX item")
	}
	item := itr.Item()
	if item == nil {
		t.Fatal("expected LTX item")
	}
	if item.Size != int64(len(plaintext)) {
		t.Fatalf("expected decrypted size %d, got %d", len(plaintext), item.Size)
	}
	if err := itr.Err(); err != nil {
		t.Fatalf("iterator error: %v", err)
	}
}
