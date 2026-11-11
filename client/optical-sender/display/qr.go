// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"fmt"
	"image"
	"image/color"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

// QRErrorCorrection is the QR layer's independent damage-recovery setting.
type QRErrorCorrection string

const (
	QRLow     QRErrorCorrection = "low"
	QRMedium  QRErrorCorrection = "medium"
	QRQuart   QRErrorCorrection = "quart"
	QRHighest QRErrorCorrection = "highest"
)

// QRSettings control density and integer raster scaling without changing an
// optical frame's bytes.
type QRSettings struct {
	Version         int
	ErrorCorrection QRErrorCorrection
	QuietZone       int
	Scale           int
}

// QRImage includes the raster and matrix measurements needed by benchmarks.
type QRImage struct {
	Image   *image.RGBA
	Modules int
}

// EncodeQR encodes one complete binary optical frame into a square QR raster.
func EncodeQR(frame []byte, settings QRSettings) (QRImage, error) {
	if len(frame) != optical.FrameSize && len(frame) != optical.HighDensityFrameSize {
		return QRImage{}, reject("qr-frame-length", "QR input length %d does not match an optical profile", len(frame))
	}
	if settings.Version != 30 && settings.Version != 40 {
		return QRImage{}, reject("qr-version", "QR version %d is unsupported; choose 30 or 40", settings.Version)
	}
	if settings.QuietZone < 4 || settings.QuietZone > 16 {
		return QRImage{}, reject("qr-quiet-zone", "QR quiet zone %d is outside 4..16", settings.QuietZone)
	}
	if settings.Scale < 1 || settings.Scale > 16 {
		return QRImage{}, reject("qr-scale", "QR scale %d is outside 1..16", settings.Scale)
	}
	if settings.ErrorCorrection != QRLow {
		return QRImage{}, reject("qr-error-correction", "QR error correction %q is unsupported; choose low", settings.ErrorCorrection)
	}
	matrix, err := optical.EncodeQRMatrix(frame, settings.Version)
	if err != nil {
		return QRImage{}, err
	}
	modules := matrix.Size
	side := (modules + 2*settings.QuietZone) * settings.Scale
	raster := image.NewRGBA(image.Rect(0, 0, side, side))
	fillRect(raster, raster.Bounds(), color.RGBA{R: 255, G: 255, B: 255, A: 255})
	black := color.RGBA{A: 255}
	for y := range modules {
		for x := range modules {
			if !matrix.Dark[y*modules+x] {
				continue
			}
			left := (x + settings.QuietZone) * settings.Scale
			top := (y + settings.QuietZone) * settings.Scale
			fillRect(raster, image.Rect(left, top, left+settings.Scale, top+settings.Scale), black)
		}
	}
	return QRImage{Image: raster, Modules: modules}, nil
}

func fillRect(target *image.RGBA, rectangle image.Rectangle, value color.RGBA) {
	width := rectangle.Dx() * 4
	start := target.PixOffset(rectangle.Min.X, rectangle.Min.Y)
	row := target.Pix[start : start+width]
	for offset := 0; offset < len(row); offset += 4 {
		row[offset+3] = value.A
		row[offset+2] = value.B
		row[offset+1] = value.G
		row[offset] = value.R
	}
	// Equal rows use byte copies to bound per-pixel work to the first row.
	for y := rectangle.Min.Y + 1; y < rectangle.Max.Y; y++ {
		start := target.PixOffset(rectangle.Min.X, y)
		copy(target.Pix[start:start+width], row)
	}
}

// DescribeQRSettings returns a stable line for benchmark logs.
func DescribeQRSettings(settings QRSettings, modules int) string {
	return fmt.Sprintf("version=%d correction=%s modules=%d quiet=%d scale=%d", settings.Version, settings.ErrorCorrection, modules, settings.QuietZone, settings.Scale)
}

func reject(code, format string, args ...any) error {
	return &optical.CodecError{Code: code, Message: fmt.Sprintf(format, args...)}
}
