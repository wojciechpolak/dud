// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//go:build windows

package main

import "os"

func setProcessPrivateFileMask() {}

func processCleanupSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func processSignalExitCode(os.Signal) int {
	return 130
}
