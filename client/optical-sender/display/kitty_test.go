// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

func TestKittyPNGChunksPreserveFourSymbolsAtIntegerPixelScales(t *testing.T) {
	for _, version := range []int{30, 40} {
		for _, scale := range []int{1, 2, 3} {
			block := optical.BlockSize
			if version == 40 {
				block = optical.HighDensityBlockSize
			}
			source := make([]byte, block*8)
			for i := range source {
				source[i] = byte(i*73 + (i>>8)*19 + 41)
			}
			encoder, err := optical.NewEncoderWithBlockSize(source, [optical.SessionIDSize]byte{}, block)
			if err != nil {
				t.Fatal(err)
			}
			schedule, err := NewScheduler(encoder, DefaultRepairOverhead)
			if err != nil {
				t.Fatal(err)
			}
			frame := RenderNext(encoder, schedule, QRSettings{Version: version, ErrorCorrection: QRLow, QuietZone: 4, Scale: 1}, 4)
			if frame.Err != nil {
				t.Fatal(frame.Err)
			}
			var output bytes.Buffer
			if err := renderKittyRaster(&output, frame.Raster, 100, 101, scale); err != nil {
				t.Fatal(err)
			}
			packet := output.String()
			if !strings.HasPrefix(packet, "\x1b[H\x1b_Ga=T,t=d,f=100,i=100,p=1,C=1,q=2,m=") || !strings.HasSuffix(packet, kittyDelete(101)) {
				t.Fatal("missing direct transmission, placement or previous-image cleanup")
			}
			var payload strings.Builder
			chunks := strings.Split(strings.TrimPrefix(packet, "\x1b[H"), "\x1b\\")
			for _, chunk := range chunks[:len(chunks)-2] {
				control, data, ok := strings.Cut(chunk, ";")
				if !ok || len(data) > 4096 || len(data)%4 != 0 || strings.Contains(control, ",c=") || strings.Contains(control, ",r=") {
					t.Fatal("invalid chunk or cell-based image scaling")
				}
				payload.WriteString(data)
			}
			if !strings.Contains(chunks[len(chunks)-3], "m=0") {
				t.Fatal("last image chunk does not commit the complete image")
			}
			data, err := base64.StdEncoding.DecodeString(payload.String())
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Bounds().Dx() != frame.Raster.Bounds().Dx()*scale || decoded.Bounds().Dy() != frame.Raster.Bounds().Dy()*scale {
				t.Fatal("image dimensions changed")
			}
			for y := range decoded.Bounds().Dy() {
				for x := range decoded.Bounds().Dx() {
					r, g, b, a := decoded.At(x, y).RGBA()
					original := frame.Raster.RGBAAt(x/scale, y/scale)
					if r != uint32(original.R)*257 || g != r || b != r || a != 65535 {
						t.Fatalf("QR pixel changed at %d,%d", x, y)
					}
				}
			}
		}
	}
}

func TestKittyQueriesRequireAcknowledgementPixelBoundsAndReplyFence(t *testing.T) {
	ack := "\x1b_Gi=31;OK\x1b\\"
	fence := "\x1b[?62;c"
	for _, test := range []struct {
		name, reply   string
		width, height int
	}{
		{"window pixels", ack + "\x1b[4;960;1740t" + fence, 1740, 960},
		{"cell pixels", ack + "\x1b[6;16;10t" + fence, 1740, 960},
		{"zero window uses cells", ack + "\x1b[4;0;0t\x1b[6;16;10t" + fence, 1740, 960},
		{"unsupported", "\x1b[4;960;1740t" + fence, 0, 0},
		{"wrong image", "\x1b_Gi=32;OK\x1b\\\x1b[4;960;1740t" + fence, 0, 0},
		{"rejected PNG", "\x1b_Gi=31;EINVAL:private diagnostic\x1b\\" + fence, 0, 0},
		{"missing pixels", ack + fence, 0, 0},
		{"missing fence", ack + "\x1b[4;960;1740t", 0, 0},
		{"oversized response", strings.Repeat("x", 5000), 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := strings.NewReader(test.reply)
			var query bytes.Buffer
			// Fragment every escape sequence across reads, including its terminator.
			read := func(p []byte, deadline time.Time) (int, error) {
				if time.Until(deadline) > 1500*time.Millisecond {
					t.Fatal("unbounded query deadline")
				}
				return input.Read(p[:1])
			}
			width, height, err := QueryKitty(&query, read, 174, 60)
			if test.width == 0 {
				if err == nil || strings.Contains(err.Error(), "private diagnostic") {
					t.Fatal("invalid or private reply accepted", err)
				}
			} else if err != nil || width != test.width || height != test.height || input.Len() != 0 {
				t.Fatalf("geometry %d x %d, unread %d: %v", width, height, input.Len(), err)
			}
			if !strings.Contains(query.String(), "a=q,t=d,f=100,i=31;") || !strings.HasSuffix(query.String(), "\x1b[14t\x1b[16t\x1b[c") {
				t.Fatal("query does not probe direct PNG and pixel dimensions")
			}
		})
	}
}

func TestKittyPreflightUsesPixelsAndRejectsClipping(t *testing.T) {
	for _, size := range [][2]int{{580, 579}, {579, 580}, {1740, 960}} {
		options := displayTestOptions()
		options.Settings.Scale = 2
		r, err := OpenKitty(io.Discard, options, func() (int, int, error) { return size[0], size[1], nil }, nil)
		if size[0] < 580 || size[1] < 580 {
			if err == nil || !strings.Contains(err.Error(), "580 x 580") {
				t.Fatal("clipped image accepted or missing dimensions", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
		}
	}
}

func TestKittyFillsAvailablePixelsWithWholeModules(t *testing.T) {
	for _, test := range []struct {
		name                   string
		version, width, height int
		minimum, scale, side   int
	}{
		{"balanced landscape", 30, 1740, 960, 2, 3, 870},
		{"balanced portrait", 30, 960, 1740, 2, 3, 870},
		{"high-rate landscape", 40, 1740, 960, 2, 2, 740},
		{"balanced high density", 30, 3840, 2160, 2, 7, 2030},
		{"high-rate high density", 40, 3840, 2160, 2, 5, 1850},
		{"explicit minimum", 30, 1740, 960, 4, 0, 0},
		{"small pixel area", 30, 579, 960, 2, 0, 0},
		{"bounded scale", 30, 65535, 65535, 2, 16, 4640},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := displayTestOptions()
			options.Settings.Version = test.version
			options.Settings.Scale = test.minimum
			if test.version == 40 {
				options.BlockSize = optical.HighDensityBlockSize
			}
			r, err := OpenKitty(io.Discard, options, func() (int, int, error) { return test.width, test.height, nil }, nil)
			if test.scale == 0 {
				if err == nil {
					t.Fatal("renderer shrank below the requested minimum")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			renderer := r.(*terminalRenderer)
			if renderer.options.Settings.Scale != 1 || options.Settings.Scale != test.minimum {
				t.Fatal("QR generation is not bounded to one pixel per module or caller options changed")
			}
			var output bytes.Buffer
			if err := renderer.paint(&output, image.NewRGBA(image.Rect(0, 0, renderer.options.Side(), renderer.options.Side()))); err != nil {
				t.Fatal(err)
			}
			configuration := kittyPNGConfig(t, output.String())
			if configuration.Width != test.side || configuration.Height != test.side {
				t.Fatalf("displayed PNG does not use fitted dimensions: %+v", configuration)
			}
			if test.scale < 16 && (test.side/test.scale)*(test.scale+1) <= min(test.width, test.height) {
				t.Fatal("larger integer modules fit the available area")
			}
		})
	}
}

func TestKittyRankOneReusesImageAndReleasesOwnedImagesOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cipher")
	if err := os.WriteFile(path, []byte("opaque ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := &notifiedTerminal{written: make(chan struct{})}
	restores := 0
	r, err := OpenKitty(output, displayTestOptions(), func() (int, int, error) { return 1740, 960, nil }, func() error { restores++; return nil })
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
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	output.mu.Lock()
	defer output.mu.Unlock()
	text := output.data.String()
	if strings.Count(text, "a=T,") != 1 || strings.Count(text, "a=d,d=I,") < 3 || restores != 1 || !strings.Contains(text, "\x1b[?25h\x1b[?1049l") {
		t.Fatal("image reuse, cleanup or terminal restoration failed")
	}
	configuration := kittyPNGConfig(t, text)
	if configuration.Width != 870 || configuration.Height != 870 {
		t.Fatalf("displayed PNG does not fill the terminal at scale 3: %+v", configuration)
	}
}

func kittyPNGConfig(t *testing.T, packet string) image.Config {
	t.Helper()
	start := strings.Index(packet, "\x1b_Ga=T,")
	if start < 0 {
		t.Fatal("missing Kitty image")
	}
	var payload strings.Builder
	for _, chunk := range strings.Split(packet[start:], "\x1b\\") {
		control, data, ok := strings.Cut(chunk, ";")
		if !ok {
			continue
		}
		payload.WriteString(data)
		if strings.Contains(control, "m=0") {
			break
		}
	}
	data, err := base64.StdEncoding.DecodeString(payload.String())
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

func TestKittyOutputErrorsStopImageTransmission(t *testing.T) {
	raster := image.NewRGBA(image.Rect(0, 0, 2, 2))
	if err := renderKittyRaster(failingTerminal{}, raster, 100, 101, 1); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("output failure discarded", err)
	}
	if _, _, err := QueryKitty(failingTerminal{}, func([]byte, time.Time) (int, error) {
		t.Fatal("read after query output failed")
		return 0, io.EOF
	}, 174, 60); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("query output failure discarded", err)
	}
}
