// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	v2ProgressTerminalInterval    = 100 * time.Millisecond
	v2ProgressNonterminalInterval = 2 * time.Second
	v2ProgressDisplayDelay        = 250 * time.Millisecond
)

type v2ProgressFlags struct {
	force    bool
	disabled bool
}

func (flags *v2ProgressFlags) parse(argument string) error {
	switch argument {
	case "--progress":
		if flags.disabled {
			return errors.New("--progress and --no-progress are mutually exclusive")
		}
		flags.force = true
	case "--no-progress":
		if flags.force {
			return errors.New("--progress and --no-progress are mutually exclusive")
		}
		flags.disabled = true
	default:
		return fmt.Errorf("unknown progress option %q", argument)
	}
	return nil
}

type v2ProgressTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type v2RealProgressTicker struct {
	ticker *time.Ticker
}

func (ticker v2RealProgressTicker) Chan() <-chan time.Time { return ticker.ticker.C }
func (ticker v2RealProgressTicker) Stop()                  { ticker.ticker.Stop() }

type v2ProgressReporterConfig struct {
	out       io.Writer
	peer      string
	json      bool
	flags     v2ProgressFlags
	terminal  func(io.Writer) bool
	now       func() time.Time
	newTicker func(time.Duration) v2ProgressTicker
}

type v2ProgressReporter struct {
	mu sync.Mutex

	out      io.Writer
	peer     string
	enabled  bool
	terminal bool
	now      func() time.Time
	started  time.Time
	phaseAt  time.Time
	phase    string
	current  int64
	total    int64
	rateBase int64
	shown    bool
	failed   bool
	stopped  bool
	paused   bool
	lastSize int

	done   chan struct{}
	ticker v2ProgressTicker
	wait   sync.WaitGroup
}

func newV2ProgressReporter(config v2ProgressReporterConfig) *v2ProgressReporter {
	if config.terminal == nil {
		config.terminal = v2ProgressWriterIsTerminal
	}
	if config.now == nil {
		config.now = time.Now
	}
	if config.newTicker == nil {
		config.newTicker = func(interval time.Duration) v2ProgressTicker {
			return v2RealProgressTicker{ticker: time.NewTicker(interval)}
		}
	}
	terminal := config.terminal(config.out)
	enabled := !config.flags.disabled && (config.flags.force || (!config.json && terminal))
	reporter := &v2ProgressReporter{
		out: config.out, peer: safeTerminalText(config.peer), enabled: enabled,
		terminal: terminal, now: config.now, done: make(chan struct{}),
	}
	if !enabled {
		return reporter
	}
	reporter.started = config.now()
	interval := v2ProgressNonterminalInterval
	if terminal {
		interval = v2ProgressTerminalInterval
	}
	reporter.ticker = config.newTicker(interval)
	reporter.wait.Add(1)
	go reporter.run()
	return reporter
}

func (a *app) newV2ProgressReporter(peer string, jsonOutput bool, flags v2ProgressFlags) *v2ProgressReporter {
	return newV2ProgressReporter(v2ProgressReporterConfig{
		out: a.errOut, peer: peer, json: jsonOutput, flags: flags,
	})
}

func v2ProgressWriterIsTerminal(writer io.Writer) bool {
	file, ok := writer.(interface{ Fd() uintptr })
	return ok && isTerminal(file.Fd())
}

func (reporter *v2ProgressReporter) run() {
	defer reporter.wait.Done()
	for {
		select {
		case <-reporter.ticker.Chan():
			reporter.render()
		case <-reporter.done:
			return
		}
	}
}

func (reporter *v2ProgressReporter) Phase(phase string, total int64) {
	reporter.phaseWithProgress(phase, 0, total, 0)
}

func (reporter *v2ProgressReporter) PhaseResumed(phase string, completed, total int64) {
	reporter.phaseWithProgress(phase, completed, total, completed)
}

func (reporter *v2ProgressReporter) phaseWithProgress(phase string, current, total, rateBase int64) {
	if reporter == nil || !reporter.enabled {
		return
	}
	now := reporter.now()
	if current < 0 {
		current = 0
	}
	if total > 0 && current > total {
		current = total
	}
	reporter.mu.Lock()
	if reporter.stopped || reporter.failed {
		reporter.mu.Unlock()
		return
	}
	reporter.phase = safeTerminalText(phase)
	reporter.paused = false
	reporter.phaseAt = now
	reporter.current = current
	reporter.total = total
	reporter.rateBase = rateBase
	terminal := reporter.terminal
	reporter.mu.Unlock()
	if !terminal {
		reporter.render()
	}
}

func (reporter *v2ProgressReporter) Set(current, total int64) {
	if reporter == nil || !reporter.enabled {
		return
	}
	reporter.mu.Lock()
	if !reporter.stopped && !reporter.failed {
		if current < 0 {
			current = 0
		}
		if total > 0 && current > total {
			current = total
		}
		reporter.current = current
		if total >= 0 {
			reporter.total = total
		}
	}
	reporter.mu.Unlock()
}

func (reporter *v2ProgressReporter) render() {
	if reporter == nil || !reporter.enabled {
		return
	}
	now := reporter.now()
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	if reporter.stopped || reporter.failed || reporter.paused || reporter.phase == "" {
		return
	}
	if reporter.terminal && now.Sub(reporter.started) < v2ProgressDisplayDelay {
		return
	}
	line := reporter.lineLocked(now)
	var err error
	if reporter.terminal {
		padding := reporter.lastSize - len(line)
		if padding < 0 {
			padding = 0
		}
		_, err = fmt.Fprintf(reporter.out, "\r%s%s", line, strings.Repeat(" ", padding))
		reporter.lastSize = len(line)
	} else {
		_, err = fmt.Fprintln(reporter.out, line)
	}
	if err != nil {
		reporter.failed = true
		return
	}
	reporter.shown = true
}

func (reporter *v2ProgressReporter) lineLocked(now time.Time) string {
	elapsed := now.Sub(reporter.started)
	if elapsed < 0 {
		elapsed = 0
	}
	line := fmt.Sprintf("%s: %s", reporter.peer, reporter.phase)
	if reporter.current > 0 || reporter.total > 0 {
		if reporter.total > 0 {
			percentage := float64(reporter.current) * 100 / float64(reporter.total)
			line += fmt.Sprintf(" %s (%6.2f%%)", formatV2ProgressTransfer(reporter.current, reporter.total), percentage)
		} else {
			line += " " + formatV2ProgressBytes(reporter.current)
		}
	} else if reporter.phase != "complete" && reporter.phase != "failed" {
		if reporter.terminal {
			frames := "|/-\\"
			frame := frames[int(elapsed/(100*time.Millisecond))%len(frames)]
			line += fmt.Sprintf(" [%c]", frame)
		} else {
			line += " ..."
		}
	}
	phaseElapsed := now.Sub(reporter.phaseAt).Seconds()
	attemptBytes := reporter.current - reporter.rateBase
	if attemptBytes > 0 && phaseElapsed > 0 {
		rate := float64(attemptBytes) / phaseElapsed
		line += fmt.Sprintf(" %12s", formatV2ProgressRate(rate))
		if reporter.total > reporter.current && rate > 0 {
			remaining := time.Duration(float64(reporter.total-reporter.current)/rate*float64(time.Second) + 0.5)
			line += fmt.Sprintf(" ETA %8s", formatV2ProgressDuration(remaining))
		}
	}
	line += fmt.Sprintf(" elapsed %8s", formatV2ProgressDuration(elapsed))
	return line
}

func formatV2ProgressTransfer(current, total int64) string {
	if current < 0 {
		current = 0
	}
	if total < 0 {
		total = 0
	}
	if current > total {
		current = total
	}
	for _, unit := range []struct {
		bytes int64
		name  string
	}{
		{1024 * 1024 * 1024, "GiB"},
		{1024 * 1024, "MiB"},
		{1024, "KiB"},
	} {
		if total < unit.bytes {
			continue
		}
		totalText := fmt.Sprintf("%.2f", float64(total)/float64(unit.bytes))
		currentText := fmt.Sprintf("%*.2f", len(totalText), float64(current)/float64(unit.bytes))
		return fmt.Sprintf("%s %s/%s %s", currentText, unit.name, totalText, unit.name)
	}
	totalText := fmt.Sprintf("%d", total)
	return fmt.Sprintf("%*d B/%s B", len(totalText), current, totalText)
}

func formatV2ProgressBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	return formatV2ByteCount(uint64(value))
}

func formatV2ProgressRate(value float64) string {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		value = 0
	}
	return formatV2ByteCount(uint64(value)) + "/s"
}

func formatV2ProgressDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	seconds := int64(value.Round(time.Second) / time.Second)
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := seconds / 60
	seconds %= 60
	if minutes < 60 {
		return fmt.Sprintf("%dm%02ds", minutes, seconds)
	}
	hours := minutes / 60
	minutes %= 60
	return fmt.Sprintf("%dh%02dm", hours, minutes)
}

func (reporter *v2ProgressReporter) Clear() {
	if reporter == nil || !reporter.enabled {
		return
	}
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.paused = true
	reporter.clearLocked()
}

func (reporter *v2ProgressReporter) clearLocked() {
	if !reporter.terminal || !reporter.shown || reporter.failed {
		return
	}
	if _, err := fmt.Fprintf(reporter.out, "\r%s\r", strings.Repeat(" ", reporter.lastSize)); err != nil {
		reporter.failed = true
		return
	}
	reporter.shown = false
	reporter.lastSize = 0
}

func (reporter *v2ProgressReporter) Complete() {
	reporter.stop("complete")
}

func (reporter *v2ProgressReporter) Fail() {
	reporter.stop("failed")
}

func (reporter *v2ProgressReporter) Stop() {
	reporter.stop("")
}

func (reporter *v2ProgressReporter) stop(finalPhase string) {
	if reporter == nil || !reporter.enabled {
		return
	}
	if finalPhase != "" {
		reporter.Phase(finalPhase, 0)
	}
	reporter.mu.Lock()
	if reporter.stopped {
		reporter.mu.Unlock()
		return
	}
	if reporter.terminal && finalPhase != "" && reporter.shown {
		line := reporter.lineLocked(reporter.now())
		padding := reporter.lastSize - len(line)
		if padding < 0 {
			padding = 0
		}
		if _, err := fmt.Fprintf(reporter.out, "\r%s%s\n", line, strings.Repeat(" ", padding)); err != nil {
			reporter.failed = true
		}
		reporter.shown = false
	} else {
		reporter.clearLocked()
	}
	reporter.stopped = true
	close(reporter.done)
	ticker := reporter.ticker
	reporter.mu.Unlock()
	if ticker != nil {
		ticker.Stop()
	}
	reporter.wait.Wait()
}

type v2ObservedReader struct {
	reader   io.Reader
	read     int64
	total    int64
	observe  func(int64, int64)
	progress func()
}

func (reader *v2ObservedReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	if count > 0 {
		reader.read += int64(count)
		if reader.progress != nil {
			reader.progress()
		}
		if reader.observe != nil {
			reader.observe(reader.read, reader.total)
		}
	}
	return count, err
}
