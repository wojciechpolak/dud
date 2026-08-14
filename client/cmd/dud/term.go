// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var openV2TTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// isTerminal reports whether fd refers to a terminal. A mode check such
// as os.ModeCharDevice is not enough: /dev/null is also a character
// device but must not count as an interactive terminal.
func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}

func readV2TTYLine(prompt string, hidden bool) (string, error) {
	tty, err := openV2TTY()
	if err != nil {
		return "", errors.New("this operation requires an interactive TTY")
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	var original syscall.Termios
	if hidden {
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			tty.Fd(),
			ioctlReadTermios,
			uintptr(unsafe.Pointer(&original)),
		)
		if errno != 0 {
			return "", errno
		}
		updated := original
		updated.Lflag &^= syscall.ECHO
		_, _, errno = syscall.Syscall(
			syscall.SYS_IOCTL,
			tty.Fd(),
			ioctlWriteTermios,
			uintptr(unsafe.Pointer(&updated)),
		)
		if errno != 0 {
			return "", errno
		}
		defer syscall.Syscall(
			syscall.SYS_IOCTL,
			tty.Fd(),
			ioctlWriteTermios,
			uintptr(unsafe.Pointer(&original)),
		)
	}
	line, readErr := bufio.NewReader(tty).ReadString('\n')
	if hidden {
		_, _ = fmt.Fprintln(tty)
	}
	if readErr != nil {
		return "", readErr
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptV2OriginConfirmation(origin string) (bool, error) {
	value, err := readV2TTYLine(
		fmt.Sprintf("Invitation requests new peer origin %s. Trust this origin? [y/N]: ", origin),
		false,
	)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(value), "y") ||
		strings.EqualFold(strings.TrimSpace(value), "yes"), nil
}
