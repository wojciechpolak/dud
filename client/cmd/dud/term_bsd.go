// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package main

import "syscall"

const (
	ioctlReadTermios  = uintptr(syscall.TIOCGETA)
	ioctlWriteTermios = uintptr(syscall.TIOCSETA)
)
