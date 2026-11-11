//go:build !darwin && !linux

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "process CPU measurement requires Linux or macOS")
	os.Exit(2)
}
