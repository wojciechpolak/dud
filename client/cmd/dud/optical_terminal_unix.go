//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func opticalTerminalSize(file *os.File) (int, int, error) {
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return int(size.Col), int(size.Row), nil
}
func enableOpticalTerminal(_ *os.File) (func() error, error) { return func() error { return nil }, nil }
