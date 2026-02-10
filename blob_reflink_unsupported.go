//go:build !linux

package main

func cloneFileCoW(dstPath string, srcPath string) error {
	return errReflinkUnsupported
}
