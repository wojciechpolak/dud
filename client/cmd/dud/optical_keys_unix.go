//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"golang.org/x/sys/unix"
)

// Only the display phase reads shortcut keys. Preflight queries and age prompts
// finish first; in TUI mode Bubble Tea releases input before the operation starts.
func watchOpticalKeys(parent context.Context, finish context.CancelFunc) (func(), error) {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	original, err := unix.IoctlGetTermios(fd, uint(ioctlReadTermios))
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	mode := *original
	mode.Lflag &^= unix.ECHO | unix.ICANON
	mode.Cc[unix.VMIN] = 1
	mode.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, uint(ioctlWriteTermios), &mode); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readOpticalKeys(ctx, opticalKeyInput{ctx: ctx, fd: fd}, finish)
	}()
	return func() {
		cancel()
		<-done
		_ = unix.IoctlSetTermios(fd, uint(ioctlWriteTermios), original)
		_ = unix.Close(fd)
	}, nil
}

type opticalKeyInput struct {
	ctx context.Context
	fd  int
}

func (input opticalKeyInput) Read(buffer []byte) (int, error) {
	for {
		n, err := readOpticalKitty(input.ctx, input.fd, buffer, time.Now().Add(100*time.Millisecond))
		if errors.Is(err, context.DeadlineExceeded) && input.ctx.Err() == nil {
			continue
		}
		if n == 0 && err == nil {
			err = io.EOF
		}
		return n, err
	}
}

func readOpticalKeys(ctx context.Context, input io.Reader, finish context.CancelFunc) {
	reader := uv.NewTerminalReader(input, os.Getenv("TERM"))
	events := make(chan uv.Event)
	go func() {
		defer close(events)
		_ = reader.StreamEvents(ctx, events)
	}()
	// Drain events through reader shutdown before returning terminal ownership.
	for event := range events {
		if key, ok := event.(uv.KeyPressEvent); ok && (key.String() == "q" || key.String() == "Q" || key.String() == "esc") {
			finish()
		}
	}
	finish()
}
