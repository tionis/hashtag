//go:build linux

package main

import (
	stderrors "errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func cloneFileCoW(dstPath string, srcPath string) error {
	sourceFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open reflink source %q: %w", srcPath, err)
	}
	defer sourceFile.Close()

	targetFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create reflink destination %q: %w", dstPath, err)
	}
	defer targetFile.Close()

	if err := unix.IoctlFileClone(int(targetFile.Fd()), int(sourceFile.Fd())); err != nil {
		_ = os.Remove(dstPath)
		if stderrors.Is(err, unix.EXDEV) ||
			stderrors.Is(err, unix.EOPNOTSUPP) ||
			stderrors.Is(err, unix.ENOTSUP) ||
			stderrors.Is(err, unix.ENOSYS) ||
			stderrors.Is(err, unix.EINVAL) ||
			stderrors.Is(err, unix.ENOTTY) {
			return errReflinkUnsupported
		}
		return fmt.Errorf("clone file using reflink from %q to %q: %w", srcPath, dstPath, err)
	}

	if err := targetFile.Sync(); err != nil {
		_ = os.Remove(dstPath)
		return fmt.Errorf("sync reflink destination %q: %w", dstPath, err)
	}

	return nil
}
