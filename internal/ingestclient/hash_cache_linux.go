//go:build linux

package ingestclient

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/zeebo/blake3"
)

const (
	xattrPrefix   = "user.checksum."
	xattrMtimeKey = "user.checksum.mtime"
	bufferSize    = 128 * 1024
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufferSize)
		return &b
	},
}

type algoFactory func() hash.Hash

var algos = map[string]algoFactory{
	"blake3": func() hash.Hash { return blake3.New() },
}

func isSupportedAlgo(name string) bool {
	_, ok := algos[name]
	return ok
}

func hashWithXattrCache(path, algo string) (string, error) {
	factory, ok := algos[algo]
	if !ok {
		return "", fmt.Errorf("unsupported algorithm %q", algo)
	}

	preInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	preMTime := preInfo.ModTime().Unix()

	hashKey := xattrPrefix + algo
	cachedMTime, hasMTime := readCachedMTime(path)
	if hasMTime && cachedMTime == preMTime {
		if cachedHash, err := getXattr(path, hashKey); err == nil {
			h := strings.TrimSpace(string(cachedHash))
			if h != "" {
				return h, nil
			}
		}
	}

	hasher := factory()
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	_, copyErr := io.CopyBuffer(hasher, f, buf)
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}

	postInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if preInfo.ModTime() != postInfo.ModTime() {
		return "", fmt.Errorf("file modified during read: %s", path)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	_ = setXattrBestEffort(path, hashKey, []byte(digest))
	_ = setXattrBestEffort(path, xattrMtimeKey, []byte(strconv.FormatInt(preMTime, 10)))
	return digest, nil
}

func readCachedMTime(path string) (int64, bool) {
	b, err := getXattr(path, xattrMtimeKey)
	if err != nil {
		return 0, false
	}
	t, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return t, true
}

func getXattr(path, name string) ([]byte, error) {
	sz, err := syscall.Getxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	if sz <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, sz)
	n, err := syscall.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func setXattrBestEffort(path, name string, value []byte) error {
	err := syscall.Setxattr(path, name, value, 0)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return nil
	}
	return err
}
