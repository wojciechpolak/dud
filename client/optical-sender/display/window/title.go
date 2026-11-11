// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package window presents optical transfer QR rasters with local display status.
package window

import (
	"fmt"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

type windowTitle struct {
	profile    string
	started    time.Time
	nextUpdate time.Time
	active     bool
}

func newWindowTitle(settings display.QRSettings, blockSize, qrSymbols, fps int) windowTitle {
	profile := "custom"
	if qrSymbols == 4 && settings.ErrorCorrection == display.QRLow {
		switch {
		case settings.Version == 30 && blockSize == optical.BlockSize && fps == 30:
			profile = "balanced"
		case settings.Version == 40 && blockSize == optical.HighDensityBlockSize && fps == 60:
			profile = "high-rate"
		}
	}
	return windowTitle{profile: profile}
}

func (t *windowTitle) ready() string {
	return "DUD optical transfer, " + t.profile + ", ready"
}

func (t *windowTitle) begin(now time.Time) string {
	t.active = true
	t.started = now
	t.nextUpdate = now.Add(time.Second)
	return t.displaying(now)
}

// tick limits title changes independently of QR generation and presentation.
// Late updates use elapsed wall time and schedule no catch-up updates.
func (t *windowTitle) tick(now time.Time) (string, bool) {
	if !t.active || now.Before(t.nextUpdate) {
		return "", false
	}
	t.nextUpdate = now.Add(time.Second)
	return t.displaying(now), true
}

func (t *windowTitle) displaying(now time.Time) string {
	seconds := int64(now.Sub(t.started) / time.Second)
	return fmt.Sprintf("DUD optical transfer, %s, displaying %02d:%02d", t.profile, seconds/60, seconds%60)
}
