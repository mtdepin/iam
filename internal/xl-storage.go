package internal

import (
	"errors"
	"github.com/dustin/go-humanize"
	"os"
	"runtime"
	"syscall"
)

const (
	nullVersionID        = "null"
	blockSizeSmall       = 128 * humanize.KiByte // Default r/w block size for smaller objects.
	blockSizeLarge       = 2 * humanize.MiByte   // Default r/w block size for larger objects.
	blockSizeReallyLarge = 4 * humanize.MiByte   // Default write block size for objects per shard >= 64MiB

	// On regular files bigger than this;
	readAheadSize = 16 << 20
	// Read this many buffers ahead.
	readAheadBuffers = 4
	// Size of each buffer.
	readAheadBufSize = 1 << 20

	// Really large streams threshold per shard.
	reallyLargeFileThreshold = 64 * humanize.MiByte // Optimized for HDDs

	// Small file threshold below which data accompanies metadata from storage layer.
	smallFileThreshold = 128 * humanize.KiByte // Optimized for NVMe/SSDs
	// For hardrives it is possible to set this to a lower value to avoid any
	// spike in latency. But currently we are simply keeping it optimal for SSDs.

	// XL metadata file carries per object metadata.
	xlStorageFormatFile = "xl.meta"
)

// No space left on device error
func isSysErrNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}

// Invalid argument, unsupported flags such as O_DIRECT
func isSysErrInvalidArg(err error) bool {
	return errors.Is(err, syscall.EINVAL)
}

// Input/output error
func isSysErrIO(err error) bool {
	return errors.Is(err, syscall.EIO)
}

// Check if the given error corresponds to EISDIR (is a directory).
func isSysErrIsDir(err error) bool {
	return errors.Is(err, syscall.EISDIR)
}

// Check if the given error corresponds to ENOTDIR (is not a directory).
func isSysErrNotDir(err error) bool {
	return errors.Is(err, syscall.ENOTDIR)
}

// Check if the given error corresponds to the ENAMETOOLONG (name too long).
func isSysErrTooLong(err error) bool {
	return errors.Is(err, syscall.ENAMETOOLONG)
}

// Check if the given error corresponds to the ELOOP (too many symlinks).
func isSysErrTooManySymlinks(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

func isSysErrCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// Check if given error corresponds to too many open files
func isSysErrTooManyFiles(err error) bool {
	return errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.EMFILE)
}

func osIsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func osIsPermission(err error) bool {
	return errors.Is(err, os.ErrPermission)
}

func osIsExist(err error) bool {
	return errors.Is(err, os.ErrExist)
}

// Check if the given error corresponds to the specific ERROR_PATH_NOT_FOUND for windows
func isSysErrPathNotFound(err error) bool {
	if runtime.GOOS != globalWindowsOSName {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) {
			return pathErr.Err == syscall.ENOENT
		}
		return false
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		var errno syscall.Errno
		if errors.As(pathErr.Err, &errno) {
			// ERROR_PATH_NOT_FOUND
			return errno == 0x03
		}
	}
	return false
}
