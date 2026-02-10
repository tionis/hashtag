//go:build !linux

package ingestclient

import "fmt"

func isSupportedAlgo(_ string) bool {
	return false
}

func hashWithXattrCache(path, algo string) (string, error) {
	return "", fmt.Errorf("xattr hash cache is only supported on linux (path=%s algo=%s)", path, algo)
}
