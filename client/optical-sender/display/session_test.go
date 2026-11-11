// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package display

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

func displayTestOptions() Options {
	return Options{Settings: QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 4, Scale: 1}, BlockSize: optical.BlockSize, FPS: 30}
}
func TestPresentationPacerSkipsElapsedDeadlinesWithoutCatchup(t *testing.T) {
	start := time.Unix(100, 0)
	p := NewPacer(start, 30)
	interval := time.Second / 30
	if !p.Deadline().Equal(start.Add(interval)) {
		t.Fatal("first deadline differs")
	}
	p.Advance(start)
	if !p.Deadline().Equal(start.Add(interval)) {
		t.Fatal("early tick advanced schedule")
	}
	p.Advance(start.Add(interval*10 + interval/2))
	if !p.Deadline().Equal(start.Add(interval * 11)) {
		t.Fatal("late frame left expired deadlines")
	}
	p.Advance(start.Add(interval*10 + interval/2))
	if !p.Deadline().Equal(start.Add(interval * 11)) {
		t.Fatal("repeated tick introduced a burst")
	}
}
func TestTerminalRasterPreservesAllPixelsAndQuietZoneColors(t *testing.T) {
	raster := image.NewRGBA(image.Rect(0, 0, 4, 2))
	for y := range 2 {
		for x := range 4 {
			raster.SetRGBA(x, y, color.RGBA{255, 255, 255, 255})
		}
	}
	raster.SetRGBA(0, 0, color.RGBA{A: 255})
	raster.SetRGBA(0, 1, color.RGBA{A: 255})
	raster.SetRGBA(1, 0, color.RGBA{A: 255})
	raster.SetRGBA(2, 1, color.RGBA{A: 255})
	var output bytes.Buffer
	if err := renderTerminalRaster(&output, raster); err != nil {
		t.Fatal(err)
	}
	if output.String() != "\x1b[H█▀▄ \r\n" {
		t.Fatalf("pixels %q", output.String())
	}
}
func TestTerminalPreflightAndRuntimeBounds(t *testing.T) {
	options := displayTestOptions()
	side := options.Side()
	for _, size := range [][2]int{{side - 1, side}, {side, side / 2}, {side, side/2 + 1}} {
		r, err := OpenTerminal(io.Discard, options, func() (int, int, error) { return size[0], size[1], nil }, nil)
		if size[0] < side || size[1] < side/2+1 {
			if err == nil {
				t.Fatal("clipped symbols accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
		}
	}
	for _, test := range []struct {
		name    string
		options Options
	}{
		{"version", Options{Settings: QRSettings{Version: 31}, BlockSize: 1600, FPS: 30}},
		{"cadence", Options{Settings: options.Settings, BlockSize: 1600, FPS: 1}},
		{"profile", Options{Settings: options.Settings, BlockSize: 2860, FPS: 30}},
	} {
		if err := test.options.Validate(); err == nil {
			t.Fatal(test.name)
		}
	}
}

type notifiedTerminal struct {
	mu      sync.Mutex
	data    bytes.Buffer
	written chan struct{}
	once    sync.Once
}

func (w *notifiedTerminal) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.data.Write(data)
	if bytes.HasPrefix(data, []byte("\x1b[H")) {
		w.once.Do(func() { close(w.written) })
	}
	return n, err
}
func TestTerminalRankOneRendersOnceAndRestoresOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipher")
	if err := os.WriteFile(path, []byte("opaque ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := &notifiedTerminal{written: make(chan struct{})}
	restores := 0
	r, err := OpenTerminal(output, displayTestOptions(), func() (int, int, error) { return 1000, 1000, nil }, func() error { restores++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Display(context.Background(), path) }()
	select {
	case <-output.written:
	case <-time.After(3 * time.Second):
		t.Fatal("renderer did not present")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("renderer did not stop")
	}
	_ = r.Close()
	output.mu.Lock()
	text := output.data.String()
	output.mu.Unlock()
	if strings.Count(text, "\x1b[H") != 1 || !strings.Contains(text, "\x1b[?25h\x1b[?1049l") || restores != 1 {
		t.Fatal("repeated encoding or incomplete terminal restoration")
	}
}
func TestCiphertextReadRejectsBoundsBeforeDisplayPreparation(t *testing.T) {
	for _, size := range []int64{0, optical.MaxCapsuleSize + 1} {
		path := filepath.Join(t.TempDir(), "cipher")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		if _, _, _, err := Prepare(path, displayTestOptions()); err == nil {
			t.Fatal("unbounded ciphertext prepared")
		}
	}
	if _, err := ReadCiphertext(t.TempDir()); err == nil {
		t.Fatal("directory accepted as ciphertext")
	}
}
func TestWindowHelperPreflightLifecycleAndPrivateDiagnostics(t *testing.T) {
	for _, script := range []string{
		"printf 'private panic details' >&2; exit 1",
		"printf 'DUD-OPTICAL-WINDOW-READY-1\\n'; read path; exit 0",
		"printf 'wrong readiness\\n'; exit 0",
	} {
		path := filepath.Join(t.TempDir(), "helper")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		r, err := OpenWindowHelper(context.Background(), path, displayTestOptions())
		if strings.Contains(script, "read path") {
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Display(context.Background(), "/opaque/ciphertext"); err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
		} else {
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("helper failure escaped or was accepted")
			}
		}
	}
	path := filepath.Join(t.TempDir(), "wait")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := OpenWindowHelper(ctx, path, displayTestOptions()); err == nil {
		t.Fatal("blocked preflight accepted")
	}
}
func TestTerminalOutputFailureStopsPresentation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipher")
	if err := os.WriteFile(path, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer := failingTerminal{}
	r, err := OpenTerminal(writer, displayTestOptions(), func() (int, int, error) { return 1000, 1000, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := r.Display(context.Background(), path); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("output failure discarded", err)
	}
}

type failingTerminal struct{}

func (failingTerminal) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
