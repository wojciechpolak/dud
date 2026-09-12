// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//go:build !windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func openControllingTerminal() (*v2Terminal, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &v2Terminal{in: file, out: file, close: file.Close}, nil
}

func openInteractiveInput() (*os.File, error) {
	return os.Open("/dev/tty")
}

// isTerminal uses the terminal ioctl because character devices such as
// /dev/null are not interactive terminals.
func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

func disableTerminalEcho(fd uintptr) (func() error, error) {
	var original syscall.Termios
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		ioctlReadTermios,
		uintptr(unsafe.Pointer(&original)),
	)
	if errno != 0 {
		return nil, errno
	}
	updated := original
	updated.Lflag &^= syscall.ECHO
	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		ioctlWriteTermios,
		uintptr(unsafe.Pointer(&updated)),
	)
	if errno != 0 {
		return nil, errno
	}
	return func() error {
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			fd,
			ioctlWriteTermios,
			uintptr(unsafe.Pointer(&original)),
		)
		if errno != 0 {
			return errno
		}
		return nil
	}, nil
}
