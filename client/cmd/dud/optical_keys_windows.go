// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"time"

	xwindows "github.com/charmbracelet/x/windows"
	"golang.org/x/sys/windows"
)

func watchOpticalKeys(parent context.Context, finish context.CancelFunc) (func(), error) {
	input, err := openInteractiveInput()
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(input.Fd())
	var original uint32
	if err := windows.GetConsoleMode(handle, &original); err != nil {
		_ = input.Close()
		return nil, err
	}
	if err := windows.SetConsoleMode(handle, original&^(windows.ENABLE_LINE_INPUT|windows.ENABLE_ECHO_INPUT)); err != nil {
		_ = input.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var count uint32
				if err := xwindows.GetNumberOfConsoleInputEvents(handle, &count); err != nil {
					finish()
					return
				}
				if count == 0 {
					continue
				}
				var record xwindows.InputRecord
				if err := xwindows.ReadConsoleInput(handle, &record, 1, &count); err != nil {
					finish()
					return
				}
				if record.EventType == xwindows.KEY_EVENT {
					key := record.KeyEvent()
					if key.KeyDown && (key.Char == 'q' || key.Char == 'Q' || key.VirtualKeyCode == 0x1b) {
						finish()
						return
					}
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
		_ = windows.SetConsoleMode(handle, original)
		_ = input.Close()
	}, nil
}
