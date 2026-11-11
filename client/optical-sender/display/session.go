// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

// Options describes the public geometry and cadence of a four-symbol display.
type Options struct {
	Settings  QRSettings
	BlockSize int
	FPS       int
}

type Renderer interface {
	Display(context.Context, string) error
	Close() error
}

func (o Options) Validate() error {
	if (o.Settings.Version != 30 && o.Settings.Version != 40) || o.Settings.ErrorCorrection != QRLow || o.Settings.QuietZone < 4 || o.Settings.QuietZone > 16 || o.Settings.Scale < 1 || o.Settings.Scale > 16 || (o.FPS != 30 && o.FPS != 60) {
		return errors.New("invalid optical display settings")
	}
	if (o.Settings.Version == 30 && o.BlockSize != optical.BlockSize) || (o.Settings.Version == 40 && o.BlockSize != optical.HighDensityBlockSize) {
		return errors.New("optical QR and block profiles must agree")
	}
	return nil
}

func (o Options) Side() int {
	return 2 * (17 + 4*o.Settings.Version + 2*o.Settings.QuietZone) * o.Settings.Scale
}

// ReadCiphertext bounds the complete file before retaining bytes or QR state.
func ReadCiphertext(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > optical.MaxCapsuleSize {
		return nil, errors.New("ciphertext must be a regular file of 1..64 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, optical.MaxCapsuleSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) < 1 || len(data) > optical.MaxCapsuleSize {
		return nil, errors.New("ciphertext must contain 1..64 MiB")
	}
	return data, nil
}

func Prepare(path string, o Options) (*optical.Encoder, *Scheduler, Frame, error) {
	if err := o.Validate(); err != nil {
		return nil, nil, Frame{}, err
	}
	ciphertext, err := ReadCiphertext(path)
	if err != nil {
		return nil, nil, Frame{}, err
	}
	var id [optical.SessionIDSize]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, nil, Frame{}, err
	}
	encoder, err := optical.NewEncoderWithBlockSize(ciphertext, id, o.BlockSize)
	if err != nil {
		return nil, nil, Frame{}, err
	}
	scheduler, err := NewScheduler(encoder, DefaultRepairOverhead)
	if err != nil {
		return nil, nil, Frame{}, err
	}
	first := RenderNext(encoder, scheduler, o.Settings, 4)
	return encoder, scheduler, first, first.Err
}

// Pacer advances from absolute deadlines and skips missed presentation periods.
// A late frame never triggers a burst of catch-up frames.
type Pacer struct {
	interval time.Duration
	next     time.Time
}

func NewPacer(start time.Time, fps int) *Pacer {
	return &Pacer{interval: time.Second / time.Duration(fps), next: start.Add(time.Second / time.Duration(fps))}
}
func (p *Pacer) Deadline() time.Time { return p.next }
func (p *Pacer) Advance(now time.Time) {
	if !now.Before(p.next) {
		p.next = p.next.Add((now.Sub(p.next)/p.interval + 1) * p.interval)
	}
}
