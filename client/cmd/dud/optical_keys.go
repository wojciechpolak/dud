// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"context"
	"errors"
	"sync"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

type opticalTerminalRenderer struct {
	display.Renderer
	mu     sync.Mutex
	closed bool
	stop   func()
	done   chan struct{}
}

func (renderer *opticalTerminalRenderer) Display(parent context.Context, path string) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	renderer.mu.Lock()
	if renderer.closed {
		renderer.mu.Unlock()
		return nil
	}
	renderer.done = make(chan struct{})
	defer close(renderer.done)
	stop, err := watchOpticalKeys(ctx, cancel)
	if err != nil {
		renderer.mu.Unlock()
		return err
	}
	stopKeys := sync.OnceFunc(func() { cancel(); stop() })
	renderer.stop = stopKeys
	renderer.mu.Unlock()
	defer stopKeys()
	err = renderer.Renderer.Display(ctx, path)
	if errors.Is(err, context.Canceled) && parent.Err() == nil {
		return nil
	}
	return err
}

// Signal cleanup waits for both terminal input restoration and display cleanup
// before process exit can bypass deferred work.
func (renderer *opticalTerminalRenderer) Close() error {
	renderer.mu.Lock()
	renderer.closed = true
	stop, done := renderer.stop, renderer.done
	renderer.mu.Unlock()
	if stop != nil {
		stop()
	}
	err := renderer.Renderer.Close()
	if done != nil {
		<-done
	}
	return err
}
