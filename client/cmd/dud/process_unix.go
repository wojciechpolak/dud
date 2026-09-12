// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//go:build !windows

package main

import (
	"os"
	"syscall"
)

func setProcessPrivateFileMask() {
	syscall.Umask(0o077)
}

func processCleanupSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
}

func processSignalExitCode(signal os.Signal) int {
	return 128 + int(signal.(syscall.Signal))
}
