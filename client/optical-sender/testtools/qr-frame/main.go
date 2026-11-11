// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// qr-frame renders hostile binary fixtures with the sender's QR settings so
// browser tests exercise image decoding before optical-frame rejection.
package main

import (
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"

	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: qr-frame FRAME PNG")
	}
	frame, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	qr, err := display.EncodeQR(frame, display.QRSettings{
		Version: 30, ErrorCorrection: display.QRLow, QuietZone: 4, Scale: 2,
	})
	if err != nil {
		return err
	}
	side := qr.Image.Bounds().Dx()
	raster := image.NewRGBA(image.Rect(0, 0, side*2, side*2))
	for index := range 4 {
		offset := image.Pt(index%2*side, index/2*side)
		draw.Draw(raster, image.Rectangle{Min: offset, Max: offset.Add(image.Pt(side, side))}, qr.Image, image.Point{}, draw.Src)
	}
	file, err := os.Create(args[1])
	if err != nil {
		return err
	}
	encodeErr := png.Encode(file, raster)
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}
