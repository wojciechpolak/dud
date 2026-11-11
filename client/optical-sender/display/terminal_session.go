// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"sync"
	"time"
)

type terminalRenderer struct {
	output    io.Writer
	options   Options
	checkSize func() error
	paint     func(io.Writer, *image.RGBA) error
	cleanup   string
	closed    chan struct{}
	once      sync.Once
	mu        sync.Mutex
	restore   func() error
}

// OpenTerminal requires enough character cells for every raster pixel. Each
// cell represents two vertical pixels with explicit black/white ANSI colors.
func OpenTerminal(output io.Writer, options Options, size func() (int, int, error), restore func() error) (Renderer, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	checkSize := func() error {
		columns, rows, err := size()
		if err != nil {
			return err
		}
		minimumColumns, minimumRows := options.Side(), (options.Side()+1)/2+1
		if columns < minimumColumns || rows < minimumRows {
			return fmt.Errorf("four optical symbols require at least %d columns and %d rows; terminal has %d columns and %d rows", minimumColumns, minimumRows, columns, rows)
		}
		return nil
	}
	return openTerminalRenderer(output, options, checkSize, renderTerminalRaster, "", restore)
}

func openTerminalRenderer(output io.Writer, options Options, checkSize func() error, paint func(io.Writer, *image.RGBA) error, cleanup string, restore func() error) (Renderer, error) {
	renderer := &terminalRenderer{output: output, options: options, checkSize: checkSize, paint: paint, cleanup: cleanup, closed: make(chan struct{}), restore: restore}
	if err := renderer.checkSize(); err != nil {
		return nil, err
	}
	return renderer, nil
}
func (t *terminalRenderer) Display(ctx context.Context, path string) error {
	encoder, scheduler, first, err := Prepare(path, t.options)
	if err != nil {
		return err
	}
	if _, err := t.writeString("\x1b[?1049h\x1b[?25l\x1b[30;47m\x1b[2J"); err != nil {
		return err
	}
	defer func() { _, _ = t.writeString(t.cleanup + "\x1b[0m\x1b[?25h\x1b[?1049l") }()
	frame := first
	pacer := NewPacer(time.Now(), t.options.FPS)
	repeated := RepeatableFrame(first)
	for {
		if err := t.checkSize(); err != nil {
			return err
		}
		t.mu.Lock()
		select {
		case <-t.closed:
			t.mu.Unlock()
			return nil
		case <-ctx.Done():
			t.mu.Unlock()
			return ctx.Err()
		default:
		}
		err = t.paint(t.output, frame.Raster)
		t.mu.Unlock()
		if err != nil {
			return err
		}
		if repeated {
			return t.waitRepeated(ctx)
		}
		timer := time.NewTimer(max(time.Duration(0), time.Until(pacer.Deadline())))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-t.closed:
			timer.Stop()
			return nil
		case <-timer.C:
		}
		frame = RenderNext(encoder, scheduler, t.options.Settings, 4)
		if frame.Err != nil {
			return frame.Err
		}
		pacer.Advance(time.Now())
	}
}
func (t *terminalRenderer) Close() error {
	var err error
	t.once.Do(func() {
		close(t.closed)
		_, err = t.writeString(t.cleanup + "\x1b[0m\x1b[?25h\x1b[?1049l")
		if t.restore != nil {
			err = errors.Join(err, t.restore())
		}
	})
	return err
}
func (t *terminalRenderer) writeString(value string) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return io.WriteString(t.output, value)
}
func renderTerminalRaster(output io.Writer, raster *image.RGBA) error {
	var text bytes.Buffer
	text.WriteString("\x1b[H")
	for y := 0; y < raster.Bounds().Dy(); y += 2 {
		for x := 0; x < raster.Bounds().Dx(); x++ {
			top := raster.RGBAAt(x, y).R < 128
			bottom := y+1 < raster.Bounds().Dy() && raster.RGBAAt(x, y+1).R < 128
			switch {
			case top && bottom:
				text.WriteRune('█')
			case top:
				text.WriteRune('▀')
			case bottom:
				text.WriteRune('▄')
			default:
				text.WriteByte(' ')
			}
		}
		text.WriteString("\r\n")
	}
	_, err := output.Write(text.Bytes())
	return err
}

func (t *terminalRenderer) waitRepeated(ctx context.Context) error {
	timer := time.NewTicker(250 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.closed:
			return nil
		case <-timer.C:
			if err := t.checkSize(); err != nil {
				return err
			}
		}
	}
}
