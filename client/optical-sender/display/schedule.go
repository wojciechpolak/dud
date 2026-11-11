// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Package display composes optical symbols and schedules local renderers.
package display

import (
	"errors"
	"fmt"
	"image"
	"image/draw"
	"sync"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
)

const DefaultRepairOverhead = 25

type Plan struct {
	Stripe      int
	StripeCount int
	Position    int
	Repair      bool
	SourceCount int
	RepairCount int
	Sequence    uint32
	Cycle       uint32
}

type Scheduler struct {
	encoder       *optical.Encoder
	repairPercent int
	stripes       []stripeSchedule
}

type stripeSchedule struct {
	SourceCount        int
	RepairCount        int
	Position           int
	Cycle              uint32
	emitted            uint64
	nextRepairSequence uint64
}

func (s stripeSchedule) frameCount() int {
	if s.repairOnly() {
		return s.RepairCount
	}
	return s.SourceCount + s.RepairCount
}

func (s stripeSchedule) repairOnly() bool {
	// At most 31 sources give maximum-degree repairs the same all-source XOR.
	// Repeating systematic symbols lets a late receiver recover those stripes.
	return s.Cycle > 0 && s.RepairCount > 0 && s.SourceCount > 31
}

type Frame struct {
	Raster   *image.RGBA
	Plans    []Plan
	Modules  int
	Duration time.Duration
	Err      error
}

// NewScheduler binds one immutable encoder to a bounded repair schedule.
func NewScheduler(encoder *optical.Encoder, repairPercent int) (*Scheduler, error) {
	if encoder == nil || repairPercent < 0 || repairPercent > 400 {
		return nil, errors.New("optical scheduler requires an encoder and repair percentage in 0..400")
	}
	return &Scheduler{encoder: encoder, repairPercent: repairPercent}, nil
}

// Next advances one stripe using source-count-weighted interleaving.
func (s *Scheduler) Next() (Plan, error) {
	s.initialize()
	stripe := s.nextStripe()
	state := &s.stripes[stripe]
	cycleLength := state.frameCount()
	position := state.Position
	repairOnly := state.repairOnly()
	repair := repairOnly
	kindPosition := position
	sequence := uint32(position)
	if !repairOnly {
		repairsBefore := position * state.RepairCount / cycleLength
		repairsThrough := (position + 1) * state.RepairCount / cycleLength
		repair = repairsThrough > repairsBefore
		kindPosition = position - repairsBefore
		sequence = uint32(kindPosition)
		if repair {
			kindPosition = repairsThrough - 1
		}
	}
	if repair && !repairOnly {
		sequence = uint32(state.SourceCount + kindPosition)
	}
	if repair && repairOnly {
		var err error
		sequence, err = s.encoder.NextMaximumDegreeRepairSequence(stripe, state.nextRepairSequence)
		if err != nil {
			return Plan{}, err
		}
		state.nextRepairSequence = uint64(sequence) + 1
	}
	plan := Plan{
		Stripe:      stripe,
		StripeCount: s.encoder.StripeCount(),
		Position:    kindPosition,
		Repair:      repair,
		SourceCount: state.SourceCount,
		RepairCount: state.RepairCount,
		Sequence:    sequence,
		Cycle:       state.Cycle,
	}
	state.Position++
	state.emitted++
	if state.Position >= cycleLength {
		state.Position = 0
		state.Cycle++
	}
	return plan, nil
}

func (s *Scheduler) initialize() {
	if s.stripes != nil {
		return
	}
	s.stripes = make([]stripeSchedule, s.encoder.StripeCount())
	for stripe := range s.stripes {
		count, _ := s.encoder.SourceCount(stripe)
		s.stripes[stripe] = stripeSchedule{
			SourceCount:        count,
			RepairCount:        (count*s.repairPercent + 99) / 100,
			nextRepairSequence: uint64(count + (count*s.repairPercent+99)/100),
		}
	}
}

func (s *Scheduler) nextStripe() int {
	next := 0
	for stripe := 1; stripe < len(s.stripes); stripe++ {
		candidate := s.stripes[stripe]
		selected := s.stripes[next]
		if candidate.emitted*uint64(selected.SourceCount) < selected.emitted*uint64(candidate.SourceCount) {
			next = stripe
		}
	}
	return next
}

func FramesPerCycle(encoder *optical.Encoder, repairPercent int) (sourceFrames, repairFrames int) {
	for stripe := 0; stripe < encoder.StripeCount(); stripe++ {
		count, _ := encoder.SourceCount(stripe)
		sourceFrames += count
		repairFrames += (count*repairPercent + 99) / 100
	}
	return sourceFrames, repairFrames
}

func DescribePlan(plan Plan) string {
	position := fmt.Sprintf("source %d/%d", plan.Position+1, plan.SourceCount)
	if plan.Repair {
		position = fmt.Sprintf("repair %d/%d", plan.Position+1, plan.RepairCount)
	}
	return fmt.Sprintf("stripe %d/%d, %s, cycle %d", plan.Stripe+1, plan.StripeCount, position, plan.Cycle+1)
}

func RenderNext(encoder *optical.Encoder, scheduler *Scheduler, settings QRSettings, qrSymbols int) Frame {
	if qrSymbols != 1 && qrSymbols != 4 {
		return Frame{Err: errors.New("optical display requires 1 or 4 symbols")}
	}
	started := time.Now()
	plans := make([]Plan, 0, qrSymbols)
	frames := make([][]byte, 0, qrSymbols)
	for range qrSymbols {
		plan, err := scheduler.Next()
		if err != nil {
			return Frame{Plans: plans, Err: err}
		}
		plans = append(plans, plan)
		frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
		if err != nil {
			return Frame{Plans: plans, Err: err}
		}
		frames = append(frames, frame)
	}
	images, err := encodeQRFrames(frames, settings)
	if err != nil {
		return Frame{Plans: plans, Err: err}
	}
	raster, err := composeQRImages(images)
	return Frame{Raster: raster, Plans: plans, Modules: images[0].Modules, Duration: time.Since(started), Err: err}
}

// RepeatableFrame identifies a rank-one session whose prepared display needs no
// fresh equation: every systematic or repair symbol contains the full ciphertext.
func RepeatableFrame(frame Frame) bool {
	if frame.Err != nil || (len(frame.Plans) != 1 && len(frame.Plans) != 4) {
		return false
	}
	for _, plan := range frame.Plans {
		if plan.StripeCount != 1 || plan.SourceCount != 1 {
			return false
		}
	}
	return true
}

func encodeQRFrames(frames [][]byte, settings QRSettings) ([]QRImage, error) {
	images := make([]QRImage, len(frames))
	errorsByIndex := make([]error, len(frames))
	var group sync.WaitGroup
	for index, frame := range frames {
		group.Add(1)
		go func() {
			defer group.Done()
			images[index], errorsByIndex[index] = EncodeQR(frame, settings)
		}()
	}
	group.Wait()
	for _, err := range errorsByIndex {
		if err != nil {
			return nil, err
		}
	}
	return images, nil
}

func composeQRImages(images []QRImage) (*image.RGBA, error) {
	if len(images) != 1 && len(images) != 4 {
		return nil, fmt.Errorf("QR display frame requires 1 or 4 symbols, got %d", len(images))
	}
	side := images[0].Image.Bounds().Dx()
	grid := 1
	if len(images) == 4 {
		grid = 2
	}
	raster := image.NewRGBA(image.Rect(0, 0, side*grid, side*grid))
	for index, qr := range images {
		if qr.Image.Bounds().Dx() != side || qr.Image.Bounds().Dy() != side {
			return nil, errors.New("QR symbols in one display frame must have equal square bounds")
		}
		offset := image.Pt((index%grid)*side, (index/grid)*side)
		draw.Draw(raster, image.Rectangle{Min: offset, Max: offset.Add(image.Pt(side, side))}, qr.Image, qr.Image.Bounds().Min, draw.Src)
	}
	return raster, nil
}

func FramesForSymbols(symbols, qrSymbols int) int {
	return (symbols + qrSymbols - 1) / qrSymbols
}
