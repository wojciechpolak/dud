// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

type windowProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	done    chan struct{}
	err     error
	once    sync.Once
}

// OpenWindowHelper exchanges a bounded readiness response before a source is
// read. Helper diagnostics cannot enter the CLI report or disclose private data.
func OpenWindowHelper(ctx context.Context, path string, options Options) (Renderer, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, path, strconv.Itoa(options.Settings.Version), strconv.Itoa(options.Settings.QuietZone), strconv.Itoa(options.Settings.Scale), strconv.Itoa(options.FPS))
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	command.Stderr = io.Discard
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, err
	}
	child := &windowProcess{command: command, input: input, done: make(chan struct{})}
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 256), 4096)
		ready <- scanner.Scan() && scanner.Text() == "DUD-OPTICAL-WINDOW-READY-1"
		_, _ = io.Copy(io.Discard, output)
	}()
	go func() { child.err = command.Wait(); close(child.done) }()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case ok := <-ready:
		if ok {
			return child, nil
		}
	case <-ctx.Done():
	case <-timer.C:
	}
	_ = child.Close()
	return nil, errors.New("optical window helper is unavailable")
}
func (p *windowProcess) Display(ctx context.Context, path string) error {
	if _, err := fmt.Fprintln(p.input, path); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return p.err
	}
}
func (p *windowProcess) Close() error {
	p.once.Do(func() {
		_ = p.input.Close()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-p.done:
		case <-timer.C:
			_ = p.command.Process.Kill()
			<-p.done
		}
	})
	return nil
}
