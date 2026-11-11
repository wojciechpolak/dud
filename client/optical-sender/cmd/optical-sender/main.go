// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image/png"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

const (
	maxFrameOutput         = 10_000
	defaultFramesPerSecond = 60
	defaultQRVersion       = 40
	defaultBlockSize       = optical.HighDensityBlockSize
)

type options struct {
	ciphertextFile  string
	files           stringListFlag
	message         string
	passphrase      bool
	recipients      stringListFlag
	recipientsFile  string
	ageBin          string
	renderer        string
	framesDirectory string
	frameLimit      int
	fps             int
	repairOverhead  int
	qrVersion       int
	errorCorrection string
	quietZone       int
	scale           int
	qrSymbols       int
	blockSize       int
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }

func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type benchmarkReport struct {
	Renderer                       string  `json:"renderer"`
	Frames                         int     `json:"frames"`
	QRSymbols                      int     `json:"qrSymbols"`
	QRSymbolsPerDisplayFrame       int     `json:"qrSymbolsPerDisplayFrame"`
	QRVersion                      int     `json:"qrVersion"`
	ErrorCorrection                string  `json:"errorCorrection"`
	Modules                        int     `json:"modules"`
	QuietZone                      int     `json:"quietZone"`
	Scale                          int     `json:"scale"`
	RasterPixels                   int     `json:"rasterPixels"`
	MeanMilliseconds               float64 `json:"meanMilliseconds"`
	P50Milliseconds                float64 `json:"p50Milliseconds"`
	P95Milliseconds                float64 `json:"p95Milliseconds"`
	FramesPerSecond                float64 `json:"framesPerSecond"`
	QRSymbolsPerSecond             float64 `json:"qrSymbolsPerSecond"`
	PotentialPayloadBytesPerSecond float64 `json:"potentialPayloadBytesPerSecond"`
}

func main() {
	opts := parseOptions()
	if err := run(opts, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseOptions() options {
	var opts options
	flag.StringVar(&opts.ciphertextFile, "ciphertext", "", "opaque age ciphertext for carrier tests")
	flag.Var(&opts.files, "file", "plaintext file or directory; may be repeated")
	flag.StringVar(&opts.message, "m", "", "plaintext message")
	flag.BoolVar(&opts.passphrase, "passphrase", false, "encrypt with an age passphrase")
	flag.Var(&opts.recipients, "recipient", "age recipient; may be repeated")
	flag.Var(&opts.recipients, "r", "age recipient; may be repeated")
	flag.StringVar(&opts.recipientsFile, "recipient-file", "", "age recipients file")
	flag.StringVar(&opts.recipientsFile, "R", "", "age recipients file")
	flag.StringVar(&opts.ageBin, "age-bin", environmentDefault("DUD_AGE_BIN", "age"), "age executable")
	flag.StringVar(&opts.renderer, "renderer", "window", "window, terminal, frames, or benchmark")
	flag.StringVar(&opts.framesDirectory, "frames-dir", "", "PNG output directory for the frames renderer")
	flag.IntVar(&opts.frameLimit, "frame-limit", 0, "stop after this many frames")
	flag.IntVar(&opts.fps, "fps", defaultFramesPerSecond, "display frames per second")
	flag.IntVar(&opts.repairOverhead, "repair-overhead", display.DefaultRepairOverhead, "unique repair frames per 100 source blocks")
	flag.IntVar(&opts.qrVersion, "qr-version", defaultQRVersion, "QR version: 30 or 40")
	flag.StringVar(&opts.errorCorrection, "error-correction", "low", "QR error correction: low")
	flag.IntVar(&opts.quietZone, "quiet-zone", 4, "white QR modules on every edge")
	flag.IntVar(&opts.scale, "scale", 2, "integer display pixels per QR module")
	flag.IntVar(&opts.qrSymbols, "qr-symbols", 4, "QR symbols in each display frame: 1 or 4")
	flag.IntVar(&opts.blockSize, "block-size", defaultBlockSize, "source bytes in each optical frame: 1600 or 2860")
	flag.Parse()
	return opts
}

func run(opts options, output, errorsOutput io.Writer) error {
	if opts.fps < 1 || opts.fps > 60 {
		return errors.New("--fps must be between 1 and 60")
	}
	if opts.repairOverhead < 0 || opts.repairOverhead > 400 {
		return errors.New("--repair-overhead must be between 0 and 400")
	}
	if opts.frameLimit < 0 || opts.frameLimit > maxFrameOutput {
		return fmt.Errorf("--frame-limit must be between 0 and %d", maxFrameOutput)
	}
	if opts.qrSymbols != 1 && opts.qrSymbols != 4 {
		return errors.New("--qr-symbols must be 1 or 4")
	}
	if opts.blockSize != optical.BlockSize && opts.blockSize != optical.HighDensityBlockSize {
		return errors.New("--block-size must be 1600 or 2860")
	}
	if opts.renderer == "terminal" && opts.qrSymbols != 1 {
		return errors.New("--qr-symbols must be 1 with the terminal renderer")
	}
	if opts.renderer != "window" && opts.frameLimit == 0 {
		return errors.New("--frame-limit is required outside the window renderer")
	}
	if opts.renderer == "frames" && opts.framesDirectory == "" {
		return errors.New("--frames-dir is required with --renderer frames")
	}
	capsule, err := loadOpticalCiphertext(opts, output, errorsOutput)
	if err != nil {
		return err
	}
	var sessionID [optical.SessionIDSize]byte
	if _, err := rand.Read(sessionID[:]); err != nil {
		return fmt.Errorf("create session ID: %w", err)
	}
	encoder, err := optical.NewEncoderWithBlockSize(capsule, sessionID, opts.blockSize)
	if err != nil {
		return err
	}
	settings := display.QRSettings{
		Version:         opts.qrVersion,
		ErrorCorrection: display.QRErrorCorrection(opts.errorCorrection),
		QuietZone:       opts.quietZone,
		Scale:           opts.scale,
	}
	scheduler, err := display.NewScheduler(encoder, opts.repairOverhead)
	if err != nil {
		return err
	}
	first := display.RenderNext(encoder, scheduler, settings, opts.qrSymbols)
	if first.Err != nil {
		return first.Err
	}
	fmt.Fprintf(errorsOutput, "Optical transfer fixture: %s block-size=%d fps=%d repair-overhead=%d%% qr-symbols=%d raster=%dx%d\n", display.DescribeQRSettings(settings, first.Modules), encoder.BlockSize(), opts.fps, opts.repairOverhead, opts.qrSymbols, first.Raster.Bounds().Dx(), first.Raster.Bounds().Dy())
	sourceFrames, repairFrames := display.FramesPerCycle(encoder, opts.repairOverhead)
	cycleDisplayFrames := display.FramesForSymbols(sourceFrames+repairFrames, opts.qrSymbols)
	cycleDuration := time.Duration(cycleDisplayFrames) * time.Second / time.Duration(opts.fps)
	fmt.Fprintf(errorsOutput, "Initial cycle: stripes=%d source=%d repair=%d symbols=%d display-frames=%d duration=%s\n", encoder.StripeCount(), sourceFrames, repairFrames, sourceFrames+repairFrames, cycleDisplayFrames, cycleDuration)
	if repairFrames > 0 {
		recoveryDisplayFrames := display.FramesForSymbols(repairFrames, opts.qrSymbols)
		recoveryDuration := time.Duration(recoveryDisplayFrames) * time.Second / time.Duration(opts.fps)
		fmt.Fprintf(errorsOutput, "Recovery cycle: repair=%d selection=maximum-degree display-frames=%d duration=%s\n", repairFrames, recoveryDisplayFrames, recoveryDuration)
	}
	fmt.Fprintln(errorsOutput, "Set display brightness high enough for clean whites without glare. The window renderer waits for a click, Space, or Enter. Press Q or Escape to stop it.")

	switch opts.renderer {
	case "window":
		return runWindow(encoder, scheduler, settings, first, opts.qrSymbols, opts.fps, errorsOutput)
	case "terminal":
		return display.RunTerminal(encoder, scheduler, settings, first, opts.frameLimit, opts.fps, output)
	case "frames":
		return writeFrames(encoder, scheduler, settings, first, opts.frameLimit, opts.framesDirectory, output)
	case "benchmark":
		return runBenchmark(encoder, scheduler, settings, first, opts.qrSymbols, opts.frameLimit, output)
	default:
		return fmt.Errorf("unsupported renderer %q", opts.renderer)
	}
}

func loadOpticalCiphertext(opts options, output, errorsOutput io.Writer) ([]byte, error) {
	if opts.ciphertextFile != "" {
		if len(opts.files) > 0 || opts.message != "" || opts.passphrase || len(opts.recipients) > 0 || opts.recipientsFile != "" {
			return nil, errors.New("--ciphertext cannot be combined with plaintext or encryption options")
		}
		return readBoundedCiphertext(opts.ciphertextFile)
	}
	if len(opts.files) > 0 && opts.message != "" {
		return nil, errors.New("optical upload accepts only one source: --file, -m, or stdin")
	}
	if opts.passphrase && (len(opts.recipients) > 0 || opts.recipientsFile != "") {
		return nil, errors.New("optical upload accepts either --passphrase or recipient options, not both")
	}
	if opts.recipientsFile != "" {
		info, err := os.Stat(opts.recipientsFile)
		if err != nil || info.IsDir() {
			return nil, fmt.Errorf("Recipients file not found: %s", opts.recipientsFile)
		}
	}

	plainPath, removePlain, err := opticalTempFile("dud-optical-plain-")
	if err != nil {
		return nil, err
	}
	defer removePlain()
	containerPath, removeContainer, err := opticalTempFile("dud-optical-container-")
	if err != nil {
		return nil, err
	}
	defer removeContainer()
	ciphertextPath, removeCiphertext, err := opticalTempFile("dud-optical-age-")
	if err != nil {
		return nil, err
	}
	defer removeCiphertext()

	prepared, err := drop.PrepareInput(plainPath, drop.InputOptions{
		Files: []string(opts.files), Message: opts.message,
	}, drop.InputEnvironment{
		Stdin: os.Stdin, Stderr: errorsOutput, CommandOutput: output, StdinIsTTY: inputIsTerminal(),
	})
	if err != nil {
		return nil, err
	}
	if err := capsule.WriteFile(containerPath, prepared); err != nil {
		return nil, fmt.Errorf("build encrypted capsule: %w", err)
	}
	runAge := func(args ...string) error {
		command := exec.Command(opts.ageBin, args...)
		command.Stdin = os.Stdin
		if terminal, err := os.Open("/dev/tty"); err == nil {
			defer func() { _ = terminal.Close() }()
			command.Stdin = terminal
		}
		command.Stdout = output
		command.Stderr = errorsOutput
		return command.Run()
	}
	createTemp := func(pattern string) (string, error) {
		path, _, err := opticalTempFile(pattern)
		return path, err
	}
	if err := drop.EncryptFile(containerPath, ciphertextPath, drop.EncryptionOptions{
		InlineRecipients: []string(opts.recipients), RecipientsFile: opts.recipientsFile,
	}, runAge, createTemp, func(path string) { _ = os.Remove(path) }); err != nil {
		return nil, err
	}
	return readBoundedCiphertext(ciphertextPath)
}

func readBoundedCiphertext(path string) ([]byte, error) {
	return display.ReadCiphertext(path)
}

func opticalTempFile(pattern string) (string, func(), error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", nil, err
	}
	path := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func inputIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func environmentDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func writeFrames(encoder *optical.Encoder, scheduler *display.Scheduler, settings display.QRSettings, first display.Frame, limit int, directory string, output io.Writer) error {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	next := first
	for index := 0; index < limit; index++ {
		if index > 0 {
			next = display.RenderNext(encoder, scheduler, settings, len(first.Plans))
		}
		if next.Err != nil {
			return next.Err
		}
		name := filepath.Join(directory, fmt.Sprintf("frame-%08d.png", index))
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		encodeErr := png.Encode(file, next.Raster)
		closeErr := file.Close()
		if encodeErr != nil {
			return encodeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	_, err := fmt.Fprintf(output, "wrote %d PNG frames to %s\n", limit, directory)
	return err
}

func runBenchmark(encoder *optical.Encoder, scheduler *display.Scheduler, settings display.QRSettings, first display.Frame, qrSymbols, limit int, output io.Writer) error {
	durations := make([]time.Duration, 0, limit)
	durations = append(durations, first.Duration)
	modules := first.Modules
	started := time.Now()
	for len(durations) < limit {
		next := display.RenderNext(encoder, scheduler, settings, qrSymbols)
		if next.Err != nil {
			return next.Err
		}
		durations = append(durations, next.Duration)
	}
	elapsed := time.Since(started) + first.Duration
	sort.Slice(durations, func(left, right int) bool { return durations[left] < durations[right] })
	total := time.Duration(0)
	for _, duration := range durations {
		total += duration
	}
	framesPerSecond := float64(limit) / elapsed.Seconds()
	report := benchmarkReport{
		Renderer:                       "qr-generation",
		Frames:                         limit,
		QRSymbols:                      limit * qrSymbols,
		QRSymbolsPerDisplayFrame:       qrSymbols,
		QRVersion:                      settings.Version,
		ErrorCorrection:                string(settings.ErrorCorrection),
		Modules:                        modules,
		QuietZone:                      settings.QuietZone,
		Scale:                          settings.Scale,
		RasterPixels:                   first.Raster.Bounds().Dx(),
		MeanMilliseconds:               milliseconds(total) / float64(limit),
		P50Milliseconds:                milliseconds(durations[(limit-1)/2]),
		P95Milliseconds:                milliseconds(durations[(limit*95-1)/100]),
		FramesPerSecond:                framesPerSecond,
		QRSymbolsPerSecond:             framesPerSecond * float64(qrSymbols),
		PotentialPayloadBytesPerSecond: framesPerSecond * float64(qrSymbols*encoder.BlockSize()),
	}
	encoderOutput := json.NewEncoder(output)
	encoderOutput.SetIndent("", "  ")
	return encoderOutput.Encode(report)
}

func milliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}
