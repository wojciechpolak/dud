// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"bytes"
	"errors"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

func TestEncodeQRUsesIntegerScaleAndQuietZone(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, 1024), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encoder.Frame(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	settings := QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 4, Scale: 3}
	qr, err := EncodeQR(frame, settings)
	if err != nil {
		t.Fatal(err)
	}
	wantSide := (qr.Modules + 2*settings.QuietZone) * settings.Scale
	if qr.Image.Bounds().Dx() != wantSide || qr.Image.Bounds().Dy() != wantSide {
		t.Fatalf("QR bounds=%v, want %dx%d", qr.Image.Bounds(), wantSide, wantSide)
	}
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	for y := 0; y < settings.QuietZone*settings.Scale; y++ {
		for x := 0; x < wantSide; x++ {
			if qr.Image.RGBAAt(x, y) != white {
				t.Fatalf("quiet zone pixel (%d,%d) is not white", x, y)
			}
		}
	}
}

func TestVersionFortyLowCarriesTheHighDensityProfile(t *testing.T) {
	encoder, err := optical.NewEncoderWithBlockSize(make([]byte, optical.HighDensityBlockSize), [optical.SessionIDSize]byte{}, optical.HighDensityBlockSize)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encoder.Frame(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	qr, err := EncodeQR(frame, QRSettings{Version: 40, ErrorCorrection: QRLow, QuietZone: 4, Scale: 2})
	if err != nil {
		t.Fatal(err)
	}
	if qr.Modules != 177 {
		t.Fatalf("modules=%d, want 177", qr.Modules)
	}
}

func TestQRSettingsRejectUnsafeOrImpossibleValues(t *testing.T) {
	frame := make([]byte, optical.FrameSize)
	tests := []struct {
		name     string
		settings QRSettings
		code     string
	}{
		{name: "version", settings: QRSettings{Version: 0, ErrorCorrection: QRQuart, QuietZone: 4, Scale: 1}, code: "qr-version"},
		{name: "quiet zone", settings: QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 3, Scale: 1}, code: "qr-quiet-zone"},
		{name: "scale", settings: QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 4, Scale: 0}, code: "qr-scale"},
		{name: "correction", settings: QRSettings{Version: 30, ErrorCorrection: "other", QuietZone: 4, Scale: 1}, code: "qr-error-correction"},
		{name: "unsupported version", settings: QRSettings{Version: 31, ErrorCorrection: QRLow, QuietZone: 4, Scale: 1}, code: "qr-version"},
		{name: "version above range", settings: QRSettings{Version: 41, ErrorCorrection: QRLow, QuietZone: 4, Scale: 1}, code: "qr-version"},
		{name: "quiet zone above range", settings: QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 17, Scale: 1}, code: "qr-quiet-zone"},
		{name: "scale above range", settings: QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 4, Scale: 17}, code: "qr-scale"},
		{name: "medium correction", settings: QRSettings{Version: 30, ErrorCorrection: QRMedium, QuietZone: 4, Scale: 1}, code: "qr-error-correction"},
		{name: "quart correction", settings: QRSettings{Version: 30, ErrorCorrection: QRQuart, QuietZone: 4, Scale: 1}, code: "qr-error-correction"},
		{name: "highest correction", settings: QRSettings{Version: 40, ErrorCorrection: QRHighest, QuietZone: 4, Scale: 1}, code: "qr-error-correction"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := EncodeQR(frame, test.settings)
			var codecError *optical.CodecError
			if !errors.As(err, &codecError) || codecError.Code != test.code {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}

func TestTerminalRendererIsExplicitFallback(t *testing.T) {
	encoder, _ := optical.NewEncoder(make([]byte, 10), [optical.SessionIDSize]byte{})
	frame, _ := encoder.Frame(0, 0)
	var output bytes.Buffer
	err := RenderTerminal(&output, frame, QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "██") {
		t.Fatal("terminal fallback emitted no dark modules")
	}
}
func TestQRBinaryFrameRenderingAndBoundaries(t *testing.T) {
	for _, version := range []int{30, 40} {
		for _, quiet := range []int{4, 16} {
			for _, scale := range []int{1, 3} {
				length := optical.FrameSize
				if version == 40 {
					length = optical.HighDensityFrameSize
				}
				frame := make([]byte, length)
				for i := range frame {
					frame[i] = byte(i)
				}
				settings := QRSettings{version, QRLow, quiet, scale}
				qr, err := EncodeQR(frame, settings)
				if err != nil {
					t.Fatal(err)
				}
				matrix, _ := optical.EncodeQRMatrix(frame, version)
				for y := range qr.Image.Bounds().Dy() {
					for x := range qr.Image.Bounds().Dx() {
						mx, my := x/scale-quiet, y/scale-quiet
						want := color.RGBA{255, 255, 255, 255}
						if mx >= 0 && my >= 0 && mx < qr.Modules && my < qr.Modules && matrix.Dark[my*qr.Modules+mx] {
							want = color.RGBA{A: 255}
						}
						if qr.Image.RGBAAt(x, y) != want {
							t.Fatalf("pixel%d,%d", x, y)
						}
					}
				}
				var encoded bytes.Buffer
				if err := png.Encode(&encoded, qr.Image); err != nil {
					t.Fatal(err)
				}
				decoded, err := png.Decode(&encoded)
				if err != nil {
					t.Fatal(err)
				}
				if decoded.Bounds() != qr.Image.Bounds() {
					t.Fatal("PNG bounds")
				}
			}
		}
	}
	for _, length := range []int{0, optical.FrameSize - 1, optical.FrameSize + 1, optical.HighDensityFrameSize + 1} {
		if _, err := EncodeQR(make([]byte, length), QRSettings{30, QRLow, 4, 1}); err == nil {
			t.Fatalf("length%d accepted", length)
		}
	}
	if _, err := EncodeQR(make([]byte, optical.HighDensityFrameSize), QRSettings{30, QRLow, 4, 1}); err == nil {
		t.Fatal("high-density frame fits version30")
	}
	var terminal bytes.Buffer
	if err := RenderTerminal(&terminal, make([]byte, optical.FrameSize), QRSettings{30, QRLow, 4, 16}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(terminal.String(), "\n"), "\n")
	if len(lines) != 145 {
		t.Fatal("terminal height")
	}
	for _, line := range lines {
		if len([]rune(line)) != 290 {
			t.Fatal("terminal width")
		}
	}
}
