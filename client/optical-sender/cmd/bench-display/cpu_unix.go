//go:build darwin || linux

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import "syscall"

func processCPU() float64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(err)
	}
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
}
