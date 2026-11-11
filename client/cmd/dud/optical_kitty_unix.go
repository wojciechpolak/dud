//go:build !windows

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
	"golang.org/x/sys/unix"
)

const opticalKittySupported = true

func (a *app) openOpticalKitty(ctx context.Context, options display.Options) (display.Renderer, error) {
	file, ok := a.errOut.(*os.File)
	if !ok || !isTerminal(file.Fd()) || os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" {
		return nil, opticalFailure("renderer-unavailable", "Kitty renderer requires terminal stderr and an ANSI-capable TERM")
	}
	columns, rows, err := opticalTerminalSize(file)
	if err != nil {
		return nil, opticalFailure("renderer-unavailable", "Kitty renderer cannot read terminal dimensions")
	}
	width, height, err := queryOpticalKitty(ctx, file, columns, rows)
	if err != nil {
		return nil, opticalFailure("renderer-unavailable", "Kitty renderer unavailable: "+err.Error())
	}
	size := func() (int, int, error) {
		current, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
		if err != nil {
			return 0, 0, err
		}
		if current.Xpixel > 0 && current.Ypixel > 0 {
			return int(current.Xpixel), int(current.Ypixel), nil
		}
		// Docker PTYs can omit pixel dimensions. A changed cell grid invalidates
		// the queried bounds; stop rather than display clipped QR symbols.
		if int(current.Col) != columns || int(current.Row) != rows {
			return 0, 0, errors.New("terminal size changed; restart the optical transfer to query pixel dimensions")
		}
		return width, height, nil
	}
	renderer, err := display.OpenKitty(file, options, size, nil)
	if err != nil {
		return nil, opticalFailure("renderer-unavailable", err.Error())
	}
	return renderer, nil
}

func queryOpticalKitty(ctx context.Context, output *os.File, columns, rows int) (int, int, error) {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, errors.New("cannot open the controlling terminal for graphics queries")
	}
	defer func() { _ = unix.Close(fd) }()
	original, err := unix.IoctlGetTermios(fd, uint(ioctlReadTermios))
	if err != nil {
		return 0, 0, errors.New("cannot read terminal input settings")
	}
	mode := *original
	mode.Lflag &^= unix.ECHO | unix.ICANON
	mode.Cc[unix.VMIN] = 1
	mode.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, uint(ioctlWriteTermios), &mode); err != nil {
		return 0, 0, errors.New("cannot enable terminal query input")
	}
	defer func() { _ = unix.IoctlSetTermios(fd, uint(ioctlWriteTermios), original) }()
	read := func(buffer []byte, deadline time.Time) (int, error) {
		return readOpticalKitty(ctx, fd, buffer, deadline)
	}
	return display.QueryKitty(output, read, columns, rows)
}

func readOpticalKitty(ctx context.Context, fd int, buffer []byte, deadline time.Time) (int, error) {
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		wait := max(1, min(50, int(time.Until(deadline).Milliseconds())))
		ready, err := unix.Poll(fds, wait)
		if errors.Is(err, unix.EINTR) || ready == 0 && err == nil {
			continue
		}
		if err != nil {
			return 0, err
		}
		n, err := unix.Read(fd, buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if n < 0 {
			return 0, err
		}
		return n, err
	}
	return 0, context.DeadlineExceeded
}
