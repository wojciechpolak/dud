// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"syscall"
	"unsafe"
)

// isTerminal reports whether fd refers to a terminal. A mode check such
// as os.ModeCharDevice is not enough: /dev/null is also a character
// device but must not count as an interactive terminal.
func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}
