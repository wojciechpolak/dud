// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package window

import (
	"fmt"
	"testing"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func TestWindowTitleIdentifiesProfilesAndLocalDisplayState(t *testing.T) {
	for _, test := range []struct {
		name       string
		version    int
		blockSize  int
		symbols    int
		fps        int
		correction display.QRErrorCorrection
		profile    string
	}{
		{"balanced", 30, optical.BlockSize, 4, 30, display.QRLow, "balanced"},
		{"high-rate", 40, optical.HighDensityBlockSize, 4, 60, display.QRLow, "high-rate"},
		{"custom cadence", 30, optical.BlockSize, 4, 60, display.QRLow, "custom"},
		{"custom block size", 40, optical.BlockSize, 4, 60, display.QRLow, "custom"},
		{"single symbol", 40, optical.HighDensityBlockSize, 1, 60, display.QRLow, "custom"},
		{"custom correction", 40, optical.HighDensityBlockSize, 4, 60, display.QRMedium, "custom"},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings := display.QRSettings{Version: test.version, ErrorCorrection: test.correction, QuietZone: 16, Scale: 3}
			title := newWindowTitle(settings, test.blockSize, test.symbols, test.fps)
			prefix := "DUD optical transfer, " + test.profile
			if got := title.ready(); got != prefix+", ready" {
				t.Fatalf("ready title = %q", got)
			}
			start := time.Unix(100, 0)
			if got, changed := title.tick(start.Add(time.Hour)); changed || got != "" {
				t.Fatalf("waiting for Start changed the title: %q", got)
			}
			if got := title.begin(start); got != prefix+", displaying 00:00" {
				t.Fatalf("start title = %q", got)
			}
			if got, changed := title.tick(start.Add(time.Second)); !changed || got != prefix+", displaying 00:01" {
				t.Fatalf("display title = %q, changed = %t", got, changed)
			}
		})
	}
}

func TestWindowTitleUpdatesAtMostOncePerSecondAtSixtyFPS(t *testing.T) {
	title := newWindowTitle(display.QRSettings{Version: 40, ErrorCorrection: display.QRLow}, optical.HighDensityBlockSize, 4, 60)
	start := time.Unix(100, 0)
	title.begin(start)
	lastUpdate := start
	updates := 0
	for tick := 1; tick <= 600; tick++ {
		now := start.Add(time.Duration(tick) * time.Second / 60)
		got, changed := title.tick(now)
		if !changed {
			continue
		}
		updates++
		if now.Sub(lastUpdate) < time.Second {
			t.Fatalf("title changed after only %s", now.Sub(lastUpdate))
		}
		lastUpdate = now
		want := fmt.Sprintf("DUD optical transfer, high-rate, displaying 00:%02d", updates)
		if got != want {
			t.Fatalf("title = %q, want %q", got, want)
		}
	}
	if updates != 10 {
		t.Fatalf("updates over ten seconds = %d, want 10", updates)
	}
}

func TestWindowTitleClockAdvancesWithoutQRFrames(t *testing.T) {
	start := time.Unix(100, 0)
	for _, test := range []struct {
		elapsed time.Duration
		clock   string
	}{
		{time.Second, "00:01"},
		{59*time.Second + 900*time.Millisecond, "00:59"},
		{time.Minute, "01:00"},
		{time.Hour + time.Second, "60:01"},
		{100*time.Minute + 6*time.Second, "100:06"},
	} {
		t.Run(test.clock, func(t *testing.T) {
			title := newWindowTitle(display.QRSettings{Version: 30, ErrorCorrection: display.QRLow}, optical.BlockSize, 4, 30)
			title.begin(start)
			got, changed := title.tick(start.Add(test.elapsed))
			want := "DUD optical transfer, balanced, displaying " + test.clock
			if !changed || got != want {
				t.Fatalf("title = %q, changed = %t, want %q", got, changed, want)
			}
		})
	}
}

func TestWindowTitleSkipsMissedUpdatesWithoutCatchup(t *testing.T) {
	title := newWindowTitle(display.QRSettings{Version: 40, ErrorCorrection: display.QRLow}, optical.HighDensityBlockSize, 4, 60)
	start := time.Unix(100, 0)
	title.begin(start)
	late := start.Add(42*time.Second + 500*time.Millisecond)
	got, changed := title.tick(late)
	if !changed || got != "DUD optical transfer, high-rate, displaying 00:42" {
		t.Fatalf("late update = %q, changed = %t", got, changed)
	}
	for _, now := range []time.Time{late, late.Add(time.Nanosecond), late.Add(999 * time.Millisecond)} {
		if got, changed := title.tick(now); changed || got != "" {
			t.Fatalf("catch-up update at %s = %q", now.Sub(start), got)
		}
	}
	if got, changed := title.tick(late.Add(time.Second)); !changed || got != "DUD optical transfer, high-rate, displaying 00:43" {
		t.Fatalf("next update = %q, changed = %t", got, changed)
	}
}
