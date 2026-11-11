// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

// RenderTerminal emits a monochrome ANSI fallback with the same quiet zone.
// It does not claim the cadence or density of the desktop renderer.
func RenderTerminal(output io.Writer, frame []byte, settings QRSettings) error {
	settings.Scale = 1
	qr, err := EncodeQR(frame, settings)
	if err != nil {
		return err
	}
	for y := 0; y < qr.Image.Bounds().Dy(); y++ {
		for x := 0; x < qr.Image.Bounds().Dx(); x++ {
			value := qr.Image.RGBAAt(x, y)
			if value.R < 128 {
				if _, err := io.WriteString(output, "██"); err != nil {
					return err
				}
			} else if _, err := io.WriteString(output, "  "); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(output, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func RunTerminal(encoder *optical.Encoder, scheduler *Scheduler, settings QRSettings, first Frame, limit, fps int, output io.Writer) error {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	defer signal.Stop(interrupt)
	interval := time.NewTicker(time.Second / time.Duration(fps))
	defer interval.Stop()
	next := first
	for index := 0; index < limit; index++ {
		if index > 0 {
			next = RenderNext(encoder, scheduler, settings, 1)
		}
		if next.Err != nil {
			return next.Err
		}
		if _, err := io.WriteString(output, "\x1b[2J\x1b[H"); err != nil {
			return err
		}
		plan := next.Plans[0]
		frame, _ := encoder.Frame(plan.Stripe, plan.Sequence)
		if err := RenderTerminal(output, frame, settings); err != nil {
			return err
		}
		select {
		case <-interrupt:
			return nil
		case <-interval.C:
		}
	}
	return nil
}
