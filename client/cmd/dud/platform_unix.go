// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func setPrivatePathPermissions(path string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

func validatePrivatePathPermissions(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is group- or world-accessible; expected mode 0600", path)
	}
	return nil
}

func lockLocalFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockLocalFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

func availableLocalBytes(path string) (uint64, error) {
	var stats unix.Statfs_t
	if err := unix.Statfs(path, &stats); err != nil {
		return 0, err
	}
	return uint64(stats.Bavail) * uint64(stats.Bsize), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func replaceLocalFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

// Container bind-mount roots cannot be renamed. EBUSY reports the mount-point
// case, while EACCES and EPERM report a root whose container-created parent is
// not writable by the client. The root stays in place and its contents can
// still be erased.
func v2EraseRootIsImmovable(err error) bool {
	return errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM)
}
