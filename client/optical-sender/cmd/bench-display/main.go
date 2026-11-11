//go:build darwin || linux

// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// bench-display measures the production four-symbol renderer without a window.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

func main() {
	frames := flag.Int("frames", 1000, "generated four-symbol frames per profile")
	scale := flag.Int("scale", 2, "integer raster pixels per module")
	flag.Parse()
	if *frames < 1000 || *frames > 10000 || *scale < 1 || *scale > 16 {
		panic("frames must be 1000..10000 and scale 1..16")
	}
	var results []any
	for _, profile := range []struct {
		name                string
		version, block, fps int
	}{{"balanced", 30, optical.BlockSize, 30}, {"high-rate", 40, optical.HighDensityBlockSize, 60}} {
		settings := display.QRSettings{Version: profile.version, ErrorCorrection: display.QRLow, QuietZone: 4, Scale: *scale}
		source := make([]byte, 16*1024*1024)
		for i := range source {
			source[i] = byte(i*73 + (i>>8)*19 + 41)
		}
		encoder, err := optical.NewEncoderWithBlockSize(source, [optical.SessionIDSize]byte{}, profile.block)
		must(err)
		scheduler, err := display.NewScheduler(encoder, display.DefaultRepairOverhead)
		must(err)
		for range 20 {
			must(display.RenderNext(encoder, scheduler, settings, 4).Err)
		}
		durations := make([]float64, *frames)
		intervals := make([]float64, *frames-1)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		cpuStart := processCPU()
		start := time.Now()
		previous := start
		overBudget := 0
		budget := 1000 / float64(profile.fps)
		threshold := 33.333
		if profile.fps == 60 {
			threshold = 16.667
		}
		for i := range *frames {
			frame := display.RenderNext(encoder, scheduler, settings, 4)
			must(frame.Err)
			durations[i] = float64(frame.Duration) / float64(time.Millisecond)
			now := time.Now()
			if i > 0 {
				intervals[i-1] = float64(now.Sub(previous)) / float64(time.Millisecond)
			}
			previous = now
			if durations[i] >= budget {
				overBudget++
			}
			runtime.KeepAlive(frame.Raster)
		}
		elapsed := time.Since(start).Seconds()
		cpu := processCPU() - cpuStart
		runtime.ReadMemStats(&after)
		allocatedBytes, allocations := after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs
		ordered := append([]float64(nil), durations...)
		sort.Float64s(ordered)
		quantile := func(p float64) float64 { return ordered[int(float64(len(ordered)-1)*p)] }
		paced := measurePacing(encoder, settings, *frames, profile.fps)
		// A rank-one display retains its prepared raster; it has no producer loop.
		single, err := optical.NewEncoderWithBlockSize([]byte("single-block encrypted message fixture"), [optical.SessionIDSize]byte{}, profile.block)
		must(err)
		singleSchedule, err := display.NewScheduler(single, display.DefaultRepairOverhead)
		must(err)
		prepared := display.RenderNext(single, singleSchedule, settings, 4)
		must(prepared.Err)
		if !display.RepeatableFrame(prepared) {
			panic("rank-one display must repeat")
		}
		runtime.ReadMemStats(&before)
		reuseStart := time.Now()
		for range *frames {
			runtime.KeepAlive(prepared.Raster)
		}
		reuseSeconds := time.Since(reuseStart).Seconds()
		var reused runtime.MemStats
		runtime.ReadMemStats(&reused)
		results = append(results, map[string]any{
			"profile": profile.name, "frames": *frames, "symbolsPerFrame": 4,
			"version": profile.version, "blockBytes": profile.block, "scale": *scale,
			"medianMilliseconds": quantile(.5), "p95Milliseconds": quantile(.95),
			"frameBudgetMilliseconds": budget, "p95ThresholdMilliseconds": threshold, "p95GatePassed": quantile(.95) < threshold,
			"overBudgetFrames": overBudget, "elapsedSeconds": elapsed,
			"generatedFramesPerSecond": float64(*frames) / elapsed,
			"processCPUSeconds":        cpu,
			"allocatedBytes":           allocatedBytes,
			"allocations":              allocations,
			"generationMilliseconds":   durations, "unpacedCompletionIntervalsMilliseconds": intervals,
			"pacedGeneration": paced,
			"singleBlock":     map[string]any{"preparedMilliseconds": float64(prepared.Duration) / float64(time.Millisecond), "reusedFrames": *frames, "reuseSeconds": reuseSeconds, "reuseAllocatedBytes": reused.TotalAlloc - before.TotalAlloc, "reuseAllocations": reused.Mallocs - before.Mallocs},
		})
	}
	report := map[string]any{"schemaVersion": 1, "recordedAt": time.Now().UTC(), "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "gomaxprocs": runtime.GOMAXPROCS(0), "results": results,
		"method": "20 warm-up frames, then full production RenderNext scheduling, fountain frame construction, concurrent QR encoding, rasterization and composition. CPU is process user plus system time. Allocation counters include concurrent workers and GC. Raw completion intervals describe an unpaced generator, not presentation.",
		"limits": []string{"No window, GPU upload, display vsync, terminal output or camera capture is measured.", "Throughput is generated display frames, not received plaintext goodput.", "Single-block reuse measures retained raster references, not GUI presentation or terminal maintenance."}}
	must(json.NewEncoder(os.Stdout).Encode(report))
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("benchmark failed: %v", err))
	}
}

func measurePacing(encoder *optical.Encoder, settings display.QRSettings, frames, fps int) map[string]any {
	scheduler, err := display.NewScheduler(encoder, display.DefaultRepairOverhead)
	must(err)
	start := time.Now()
	pacer := display.NewPacer(start, fps)
	previous := start
	intervals := make([]float64, 0, frames-1)
	late := make([]float64, 0, frames)
	missed := 0
	cpuStart := processCPU()
	for i := range frames {
		frame := display.RenderNext(encoder, scheduler, settings, 4)
		must(frame.Err)
		deadline := pacer.Deadline()
		if time.Now().After(deadline) {
			missed++
		}
		time.Sleep(max(0, time.Until(deadline)))
		now := time.Now()
		late = append(late, float64(now.Sub(deadline))/float64(time.Millisecond))
		if i > 0 {
			intervals = append(intervals, float64(now.Sub(previous))/float64(time.Millisecond))
		}
		previous = now
		pacer.Advance(now)
		runtime.KeepAlive(frame.Raster)
	}
	return map[string]any{"frames": frames, "elapsedSeconds": time.Since(start).Seconds(), "processCPUSeconds": processCPU() - cpuStart, "generationMissedDeadlines": missed, "completionIntervalsMilliseconds": intervals, "deadlineLatenessMilliseconds": late, "method": "Full RenderNext followed by the production absolute-deadline Pacer and host timer. No presentation, terminal I/O or camera is involved."}
}
