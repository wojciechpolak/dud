// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func openControllingTerminal() (*v2Terminal, error) {
	input, err := os.OpenFile("CONIN$", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	return &v2Terminal{
		in:  input,
		out: output,
		close: func() error {
			return errors.Join(input.Close(), output.Close())
		},
	}, nil
}

func openInteractiveInput() (*os.File, error) {
	return os.OpenFile("CONIN$", os.O_RDONLY, 0)
}

func isTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}

func disableTerminalEcho(fd uintptr) (func() error, error) {
	handle := windows.Handle(fd)
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(handle, original&^windows.ENABLE_ECHO_INPUT); err != nil {
		return nil, err
	}
	return func() error { return windows.SetConsoleMode(handle, original) }, nil
}
