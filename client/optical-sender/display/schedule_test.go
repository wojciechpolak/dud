// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package display

import (
	"bytes"
	"image"
	"image/color"
	"io"
	"testing"

	"filippo.io/age"

	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
)

func TestComposeQRImagesUsesAStableTwoByTwoOrder(t *testing.T) {
	colors := []color.RGBA{
		{R: 255, A: 255},
		{G: 255, A: 255},
		{B: 255, A: 255},
		{R: 255, G: 255, A: 255},
	}
	images := make([]QRImage, 0, len(colors))
	for _, fill := range colors {
		raster := image.NewRGBA(image.Rect(0, 0, 2, 2))
		for y := range 2 {
			for x := range 2 {
				raster.SetRGBA(x, y, fill)
			}
		}
		images = append(images, QRImage{Image: raster, Modules: 1})
	}

	composite, err := composeQRImages(images)
	if err != nil {
		t.Fatal(err)
	}
	if composite.Bounds() != image.Rect(0, 0, 4, 4) {
		t.Fatalf("composite bounds=%v, want 4 by 4", composite.Bounds())
	}
	for index, want := range colors {
		x := (index%2)*2 + 1
		y := (index/2)*2 + 1
		if got := composite.RGBAAt(x, y); got != want {
			t.Fatalf("symbol %d color=%v, want %v", index, got, want)
		}
	}
}

func TestRenderNextGroupsFourIndependentOpticalFrames(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, optical.BlockSize*4), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 0}
	settings := QRSettings{Version: 30, ErrorCorrection: QRLow, QuietZone: 4, Scale: 2}

	display := RenderNext(encoder, scheduler, settings, 4)
	if display.Err != nil {
		t.Fatal(display.Err)
	}
	if len(display.Plans) != 4 {
		t.Fatalf("display plans=%d, want 4", len(display.Plans))
	}
	for index, plan := range display.Plans {
		if plan.Sequence != uint32(index) {
			t.Fatalf("symbol %d sequence=%d, want %d", index, plan.Sequence, index)
		}
	}
	symbolSide := (display.Modules + 2*settings.QuietZone) * settings.Scale
	if got := display.Raster.Bounds(); got != image.Rect(0, 0, symbolSide*2, symbolSide*2) {
		t.Fatalf("display bounds=%v, want %d by %d", got, symbolSide*2, symbolSide*2)
	}
}

func TestDisplayFrameCountRoundsUpIncompleteSymbolGroups(t *testing.T) {
	if got := FramesForSymbols(2049, 4); got != 513 {
		t.Fatalf("display frames=%d, want 513", got)
	}
	if got := FramesForSymbols(2049, 1); got != 2049 {
		t.Fatalf("single-symbol display frames=%d, want 2049", got)
	}
}

func TestRepeatedOneBlockDisplayRecoversEncryptedMessageFromEverySymbol(t *testing.T) {
	plaintext, err := capsule.Encode([]byte("optical hello from iPhone 17"), capsule.Metadata{Type: drop.PayloadMessage, DisplayName: "message.txt"})
	if err != nil {
		t.Fatal(err)
	}
	const passphrase = "optical single-block test passphrase"
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	recipient.SetWorkFactor(10)
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []struct{ version, block int }{{30, optical.BlockSize}, {40, optical.HighDensityBlockSize}} {
		for _, symbols := range []int{1, 4} {
			for _, repair := range []int{0, 25} {
				encoder, err := optical.NewEncoderWithBlockSize(ciphertext.Bytes(), [optical.SessionIDSize]byte{}, profile.block)
				if err != nil {
					t.Fatal(err)
				}
				first := RenderNext(encoder, &Scheduler{encoder: encoder, repairPercent: repair}, QRSettings{Version: profile.version, ErrorCorrection: QRLow, QuietZone: 4, Scale: 2}, symbols)
				if !RepeatableFrame(first) {
					t.Fatalf("version=%d symbols=%d repair=%d: display cannot repeat, err=%v", profile.version, symbols, repair, first.Err)
				}
				// Receiving only a repair symbol, after missing the systematic one,
				// must still recover and decrypt the complete private container.
				for _, plan := range first.Plans {
					frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
					if err != nil {
						t.Fatal(err)
					}
					decoder := optical.NewDecoder()
					if _, err := decoder.Add(frame); err != nil {
						t.Fatal(err)
					}
					recovered, err := decoder.Result()
					if err != nil || !bytes.Equal(recovered, ciphertext.Bytes()) {
						t.Fatalf("recovery differs: %v", err)
					}
					reader, err := age.Decrypt(bytes.NewReader(recovered), identity)
					if err != nil {
						t.Fatal(err)
					}
					decrypted, err := io.ReadAll(reader)
					if err != nil {
						t.Fatal(err)
					}
					metadata, message, err := capsule.Decode(decrypted)
					if err != nil || metadata.Type != drop.PayloadMessage || string(message) != "optical hello from iPhone 17" {
						t.Fatalf("private container differs: metadata=%v message=%q err=%v", metadata, message, err)
					}
				}
			}
		}
	}
}

func TestDisplayRepetitionRequiresExactlyOneSourceBlock(t *testing.T) {
	for _, size := range []int{1, 285, optical.HighDensityBlockSize, optical.HighDensityBlockSize + 1, optical.HighDensityBlockSize*1024 + 1} {
		encoder, err := optical.NewEncoderWithBlockSize(make([]byte, size), [optical.SessionIDSize]byte{}, optical.HighDensityBlockSize)
		if err != nil {
			t.Fatal(err)
		}
		first := RenderNext(encoder, &Scheduler{encoder: encoder, repairPercent: 25}, QRSettings{Version: 40, ErrorCorrection: QRLow, QuietZone: 4, Scale: 2}, 4)
		if first.Err != nil {
			t.Fatal(first.Err)
		}
		if got, want := RepeatableFrame(first), size <= optical.HighDensityBlockSize; got != want {
			t.Fatalf("size=%d repeat=%t, want %t", size, got, want)
		}
	}
}

func TestFrameSchedulerLabelsEverySourceAndRepairPosition(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, optical.BlockSize+1), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 50}
	want := []string{
		"stripe 1/1, source 1/2, cycle 1",
		"stripe 1/1, source 2/2, cycle 1",
		"stripe 1/1, repair 1/1, cycle 1",
		"stripe 1/1, source 1/2, cycle 2",
		"stripe 1/1, source 2/2, cycle 2",
		"stripe 1/1, repair 1/1, cycle 2",
	}
	wantSequence := []uint32{0, 1, 2, 0, 1, 2}
	for index, expected := range want {
		plan := nextPlan(t, scheduler)
		if got := DescribePlan(plan); got != expected {
			t.Fatalf("frame %d label=%q, want %q", index, got, expected)
		}
		if plan.Sequence != wantSequence[index] {
			t.Fatalf("frame %d sequence=%d, want %d", index, plan.Sequence, wantSequence[index])
		}
	}
}

func TestFramesPerCycleCountsEveryStripe(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, optical.MaxStripeSize+optical.BlockSize), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	sourceFrames, repairFrames := FramesPerCycle(encoder, 50)
	if sourceFrames != 1025 || repairFrames != 513 {
		t.Fatalf("cycle source=%d repair=%d, want source=1025 repair=513", sourceFrames, repairFrames)
	}
}

func TestFrameSchedulerDistributesRepairsAcrossSourceFrames(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, optical.BlockSize*4), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 50}
	want := []string{
		"stripe 1/1, source 1/4, cycle 1",
		"stripe 1/1, source 2/4, cycle 1",
		"stripe 1/1, repair 1/2, cycle 1",
		"stripe 1/1, source 3/4, cycle 1",
		"stripe 1/1, source 4/4, cycle 1",
		"stripe 1/1, repair 2/2, cycle 1",
	}
	wantSequence := []uint32{0, 1, 4, 2, 3, 5}
	for index, expected := range want {
		plan := nextPlan(t, scheduler)
		if got := DescribePlan(plan); got != expected {
			t.Fatalf("frame %d label=%q, want %q", index, got, expected)
		}
		if plan.Repair != (index == 2 || index == 5) {
			t.Fatalf("frame %d repair=%t", index, plan.Repair)
		}
		if plan.Sequence != wantSequence[index] {
			t.Fatalf("frame %d sequence=%d, want %d", index, plan.Sequence, wantSequence[index])
		}
	}
}

func TestFrameSchedulerInterleavesUnevenStripesBySourceCount(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, optical.MaxStripeSize+optical.BlockSize*342), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 50}
	counts := [2]int{}
	lastShortStripe := -1
	maximumGap := 0
	for frame := 0; frame < 1536+513; frame++ {
		plan := nextPlan(t, scheduler)
		counts[plan.Stripe]++
		if plan.Stripe == 1 {
			if lastShortStripe >= 0 && frame-lastShortStripe-1 > maximumGap {
				maximumGap = frame - lastShortStripe - 1
			}
			lastShortStripe = frame
		}
	}
	if counts != [2]int{1536, 513} {
		t.Fatalf("cycle emitted stripe counts %v, want [1536 513]", counts)
	}
	if maximumGap > 3 {
		t.Fatalf("short stripe waited behind %d long-stripe frames, want at most 3", maximumGap)
	}
	for stripe, state := range scheduler.stripes {
		if state.Cycle != 1 || state.Position != 0 {
			t.Fatalf("stripe %d ended at cycle=%d position=%d, want cycle=1 position=0", stripe, state.Cycle, state.Position)
		}
	}

	counts = [2]int{}
	for frame := 0; frame < 512+171; frame++ {
		plan := nextPlan(t, scheduler)
		if !plan.Repair {
			t.Fatalf("recovery frame %d repeated a source frame", frame)
		}
		counts[plan.Stripe]++
	}
	if counts != [2]int{512, 171} {
		t.Fatalf("recovery cycle emitted stripe counts %v, want [512 171]", counts)
	}
	for stripe, state := range scheduler.stripes {
		if state.Cycle != 2 || state.Position != 0 {
			t.Fatalf("stripe %d ended at cycle=%d position=%d, want cycle=2 position=0", stripe, state.Cycle, state.Position)
		}
	}
}

func TestSixteenMiBInterleavedStreamRecoversWithPhysicalRunLoss(t *testing.T) {
	capsule := make([]byte, 16*1024*1024)
	encoder, err := optical.NewEncoder(capsule, [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 25}
	decoder := optical.NewDecoder()
	accepted := 0
	emitted := 0
	for ; emitted < 50_000 && !decoder.Complete(); emitted++ {
		plan := nextPlan(t, scheduler)
		// The aborted phone run decoded 57.5 percent of the four displayed QR
		// symbols. Vary losses by display position and frame so this also checks
		// that eleven interleaved stripes do not stay tied to one quadrant.
		if (emitted*17+(emitted%4)*29)%100 >= 58 {
			continue
		}
		frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.Add(frame); err != nil {
			t.Fatal(err)
		}
		accepted++
	}
	if !decoder.Complete() {
		t.Fatalf("16 MiB stream did not complete after %d accepted frames", accepted)
	}
	const threeMinuteSymbolBudget = 3 * 60 * 30 * 4
	if emitted > threeMinuteSymbolBudget {
		t.Fatalf("16 MiB stream used %d displayed symbols, three-minute budget is %d", emitted, threeMinuteSymbolBudget)
	}
	t.Logf("completed after %d displayed symbols and %d accepted frames", emitted, accepted)
	result, err := decoder.Result()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, capsule) {
		t.Fatal("16 MiB stream reconstructed different bytes")
	}
}

func TestTenPercentInitialRepairsMeetSuccessfulPhoneYieldGates(t *testing.T) {
	capsule := make([]byte, 16*1024*1024)
	encoder, err := optical.NewEncoder(capsule, [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 10}
	sourceFrames, _ := FramesPerCycle(encoder, scheduler.repairPercent)
	decoder := optical.NewDecoder()
	accepted := 0
	emitted := 0
	for ; emitted < 30_000 && !decoder.Complete(); emitted++ {
		plan := nextPlan(t, scheduler)
		if (emitted*17+(emitted%4)*29)%100 >= 90 {
			continue
		}
		frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.Add(frame); err != nil {
			t.Fatal(err)
		}
		accepted++
	}
	if !decoder.Complete() {
		t.Fatalf("stream did not complete after %d accepted frames", accepted)
	}
	const threeMinuteSymbolBudget = 3 * 60 * 30 * 4
	if emitted > threeMinuteSymbolBudget {
		t.Fatalf("16 MiB stream used %d displayed symbols, three-minute budget is %d", emitted, threeMinuteSymbolBudget)
	}
	maximumAccepted := (sourceFrames*125 + 99) / 100
	if accepted > maximumAccepted {
		t.Fatalf("16 MiB stream accepted %d frames, 25-percent overhead limit is %d", accepted, maximumAccepted)
	}
	t.Logf("completed after %d displayed symbols and %d accepted frames", emitted, accepted)
}

func TestFrameSchedulerRepeatsSourcesWhenRepairsAreDisabled(t *testing.T) {
	encoder, err := optical.NewEncoder(make([]byte, optical.BlockSize*2), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 0}
	wantSequence := []uint32{0, 1, 0, 1}
	for index, expected := range wantSequence {
		plan := nextPlan(t, scheduler)
		if plan.Repair || plan.Sequence != expected {
			t.Fatalf("frame %d repair=%t sequence=%d, want source sequence %d", index, plan.Repair, plan.Sequence, expected)
		}
	}
}

func TestFrameSchedulerUsesOddMaximumDegreeForRecoveryCycles(t *testing.T) {
	const sourceCount = 32
	encoder, err := optical.NewEncoder(make([]byte, optical.BlockSize*sourceCount), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 50}
	for range sourceCount + sourceCount/2 {
		nextPlan(t, scheduler)
	}

	previousSequence := uint32(sourceCount + sourceCount/2 - 1)
	for index := range 32 {
		plan := nextPlan(t, scheduler)
		if !plan.Repair || plan.Cycle == 0 {
			t.Fatalf("recovery frame %d has repair=%t cycle=%d", index, plan.Repair, plan.Cycle)
		}
		if plan.Sequence <= previousSequence {
			t.Fatalf("recovery sequence=%d follows %d, want a fresh increasing sequence", plan.Sequence, previousSequence)
		}
		frameBytes, err := encoder.Frame(plan.Stripe, plan.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := optical.ParseFrame(frameBytes)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Degree != 31 {
			t.Fatalf("recovery degree=%d, want 31", frame.Degree)
		}
		previousSequence = plan.Sequence
	}
}

func TestReceiverJoiningAfterInitialCycleRecoversFromRepairFrames(t *testing.T) {
	const sourceCount = 64
	encoder, err := optical.NewEncoder(make([]byte, optical.BlockSize*sourceCount), [optical.SessionIDSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	scheduler := &Scheduler{encoder: encoder, repairPercent: 25}
	for range sourceCount + sourceCount/4 {
		nextPlan(t, scheduler)
	}

	decoder := optical.NewDecoder()
	for frameIndex := 0; frameIndex < sourceCount*4 && !decoder.Complete(); frameIndex++ {
		plan := nextPlan(t, scheduler)
		if !plan.Repair || plan.Cycle == 0 {
			t.Fatalf("late receiver got non-recovery frame at index %d", frameIndex)
		}
		frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.Add(frame); err != nil {
			t.Fatal(err)
		}
	}
	if !decoder.Complete() {
		t.Fatal("repair-only stream did not reach full rank")
	}
}

func TestLateReceiverRecoversSmallStripesInBothProfiles(t *testing.T) {
	for _, blockSize := range []int{optical.BlockSize, optical.HighDensityBlockSize} {
		for sourceCount := 2; sourceCount <= 31; sourceCount++ {
			payload := make([]byte, blockSize*sourceCount-1)
			for index := range payload {
				payload[index] = byte(index*17 + sourceCount)
			}
			encoder, err := optical.NewEncoderWithBlockSize(payload, [optical.SessionIDSize]byte{}, blockSize)
			if err != nil {
				t.Fatal(err)
			}
			scheduler, err := NewScheduler(encoder, DefaultRepairOverhead)
			if err != nil {
				t.Fatal(err)
			}
			sources, repairs := FramesPerCycle(encoder, DefaultRepairOverhead)
			for range sources + repairs {
				nextPlan(t, scheduler)
			}
			decoder := optical.NewDecoder()
			for frameIndex := 0; frameIndex < sources+repairs && !decoder.Complete(); frameIndex++ {
				plan := nextPlan(t, scheduler)
				frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := decoder.Add(frame); err != nil {
					t.Fatal(err)
				}
			}
			recovered, err := decoder.Result()
			if err != nil || !bytes.Equal(recovered, payload) {
				t.Fatalf("block size=%d source count=%d: late recovery failed: %v", blockSize, sourceCount, err)
			}
		}
	}
}

func TestReceiverRecoversSmallFinalStripeAfterMissingItsInitialCycle(t *testing.T) {
	for _, blockSize := range []int{optical.BlockSize, optical.HighDensityBlockSize} {
		for _, tailSources := range []int{2, 31} {
			payload := bytes.Repeat([]byte{0x53}, blockSize*(optical.MaxSourceBlocks+tailSources)-1)
			encoder, err := optical.NewEncoderWithBlockSize(payload, [optical.SessionIDSize]byte{}, blockSize)
			if err != nil {
				t.Fatal(err)
			}
			scheduler, err := NewScheduler(encoder, DefaultRepairOverhead)
			if err != nil {
				t.Fatal(err)
			}
			decoder := optical.NewDecoder()
			sources, repairs := FramesPerCycle(encoder, DefaultRepairOverhead)
			for index := 0; index < 3*(sources+repairs) && !decoder.Complete(); index++ {
				plan := nextPlan(t, scheduler)
				if plan.Stripe == 1 && plan.Cycle == 0 {
					continue
				}
				if plan.Stripe == 0 && plan.Cycle > 0 && !plan.Repair {
					t.Fatal("large stripe repeated systematic symbols")
				}
				frame, err := encoder.Frame(plan.Stripe, plan.Sequence)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := decoder.Add(frame); err != nil {
					t.Fatal(err)
				}
			}
			recovered, err := decoder.Result()
			if err != nil || !bytes.Equal(recovered, payload) {
				t.Fatalf("block size=%d tail sources=%d: recovery failed: %v", blockSize, tailSources, err)
			}
		}
	}
}

func nextPlan(t *testing.T, scheduler *Scheduler) Plan {
	t.Helper()
	plan, err := scheduler.Next()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
