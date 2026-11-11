// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"regexp"
	"strconv"
	"time"
)

const kittyQueryID = 31

var (
	kittyWindowSize = regexp.MustCompile("\x1b\\[4;([0-9]{1,5});([0-9]{1,5})t")
	kittyCellSize   = regexp.MustCompile("\x1b\\[6;([0-9]{1,5});([0-9]{1,5})t")
	kittyAttributes = regexp.MustCompile("\x1b\\[\\?[0-9;]*c")
)

// QueryKitty probes inline PNG support and pixel geometry through the terminal
// stream. Direct transmission works across container and SSH filesystem boundaries.
func QueryKitty(output io.Writer, read func([]byte, time.Time) (int, error), columns, rows int) (width, height int, err error) {
	var pngData bytes.Buffer
	if err := png.Encode(&pngData, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		return 0, 0, err
	}
	query := fmt.Sprintf("\x1b_Ga=q,t=d,f=100,i=%d;%s\x1b\\\x1b[14t\x1b[16t\x1b[c", kittyQueryID, base64.StdEncoding.EncodeToString(pngData.Bytes()))
	if _, err := io.WriteString(output, query); err != nil {
		return 0, 0, err
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	var response []byte
	buffer := make([]byte, 256)
	for len(response) < 4096 && time.Now().Before(deadline) {
		n, err := read(buffer[:min(len(buffer), 4096-len(response))], deadline)
		response = append(response, buffer[:n]...)
		// Device attributes fence the graphics and size replies before age can
		// acquire the terminal for its passphrase prompt.
		if kittyAttributes.Match(response) {
			return parseKittyGeometry(response, columns, rows)
		}
		if err != nil {
			return 0, 0, errors.New("terminal did not complete Kitty graphics and pixel-size queries")
		}
	}
	if len(response) < 4096 {
		return 0, 0, errors.New("terminal did not complete Kitty graphics and pixel-size queries")
	}
	return 0, 0, errors.New("terminal graphics query response exceeds 4096 bytes")
}

func parseKittyGeometry(response []byte, columns, rows int) (int, int, error) {
	ack := fmt.Sprintf("\x1b_Gi=%d;OK\x1b\\", kittyQueryID)
	if !bytes.Contains(response, []byte(ack)) {
		return 0, 0, errors.New("terminal does not support inline Kitty PNG images")
	}
	if match := kittyWindowSize.FindSubmatch(response); match != nil {
		height, _ := strconv.Atoi(string(match[1]))
		width, _ := strconv.Atoi(string(match[2]))
		if width > 0 && height > 0 && width <= 65535 && height <= 65535 {
			return width, height, nil
		}
	}
	if match := kittyCellSize.FindSubmatch(response); match != nil && columns > 0 && rows > 0 {
		height, _ := strconv.Atoi(string(match[1]))
		width, _ := strconv.Atoi(string(match[2]))
		if width > 0 && height > 0 && columns <= 65535/width && rows <= 65535/height {
			return columns * width, rows * height, nil
		}
	}
	return 0, 0, errors.New("terminal did not report its pixel dimensions")
}

// OpenKitty fills the available pixel area at an integer module scale, bounded
// by 16 pixels per module and the requested minimum scale, without resampling.
// Two owned image IDs keep the previous frame visible until its replacement is
// complete, while bounding retained images and avoiding unrelated placements.
func OpenKitty(output io.Writer, options Options, size func() (int, int, error), restore func() error) (Renderer, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	width, height, err := size()
	if err != nil {
		return nil, err
	}
	moduleSide := options.Side() / options.Settings.Scale
	fitScale := min(16, min(width, height)/moduleSide)
	if fitScale < options.Settings.Scale {
		return nil, fmt.Errorf("optical raster requires at least %d x %d terminal pixels; available %d x %d; enlarge the window or choose a smaller optical scale", options.Side(), options.Side(), width, height)
	}
	side := moduleSide * fitScale
	checkSize := func() error {
		width, height, err := size()
		if err != nil {
			return err
		}
		if width < side || height < side {
			return fmt.Errorf("optical raster requires %d x %d terminal pixels; available %d x %d; restart the optical transfer after resizing", side, side, width, height)
		}
		return nil
	}
	// QR generation retains one pixel per module; expansion belongs to the
	// one-byte PNG palette rather than the four-byte RGBA frame buffers.
	options.Settings.Scale = 1
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	id := (binary.BigEndian.Uint32(random[:]) & 0x3fffffff) + 1
	ids := [2]uint32{id, id + 1}
	next := 0
	paint := func(output io.Writer, raster *image.RGBA) error {
		if err := renderKittyRaster(output, raster, ids[next], ids[1-next], fitScale); err != nil {
			return err
		}
		next = 1 - next
		return nil
	}
	return openTerminalRenderer(output, options, checkSize, paint, kittyDelete(ids[0])+kittyDelete(ids[1]), restore)
}

func kittyDelete(id uint32) string {
	return fmt.Sprintf("\x1b_Ga=d,d=I,i=%d,q=2;\x1b\\", id)
}

func renderKittyRaster(output io.Writer, raster *image.RGBA, id, previous uint32, scale int) error {
	// A two-color PNG preserves every module and compresses repeated scaled rows.
	width, height := raster.Bounds().Dx()*scale, raster.Bounds().Dy()*scale
	monochrome := image.NewPaletted(image.Rect(0, 0, width, height), color.Palette{color.White, color.Black})
	for y := range raster.Bounds().Dy() {
		row := monochrome.Pix[y*scale*monochrome.Stride : y*scale*monochrome.Stride+width]
		for x := range raster.Bounds().Dx() {
			if raster.RGBAAt(x, y).R < 128 {
				for offset := range scale {
					row[x*scale+offset] = 1
				}
			}
		}
		for offset := 1; offset < scale; offset++ {
			copy(monochrome.Pix[(y*scale+offset)*monochrome.Stride:], row)
		}
	}
	var data bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(&data, monochrome); err != nil {
		return err
	}
	payload := base64.StdEncoding.EncodeToString(data.Bytes())
	var packet bytes.Buffer
	packet.WriteString("\x1b[H")
	first := true
	for len(payload) > 0 {
		chunk := min(4096, len(payload))
		more := 0
		if chunk < len(payload) {
			more = 1
		}
		if first {
			_, _ = fmt.Fprintf(&packet, "\x1b_Ga=T,t=d,f=100,i=%d,p=1,C=1,q=2,m=%d;", id, more)
			first = false
		} else {
			_, _ = fmt.Fprintf(&packet, "\x1b_Gm=%d,q=2;", more)
		}
		packet.WriteString(payload[:chunk])
		packet.WriteString("\x1b\\")
		payload = payload[chunk:]
	}
	packet.WriteString(kittyDelete(previous))
	n, err := output.Write(packet.Bytes())
	if err == nil && n != packet.Len() {
		return io.ErrShortWrite
	}
	return err
}
