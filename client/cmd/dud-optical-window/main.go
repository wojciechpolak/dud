// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build nativewindow

// This local helper owns Ebitengine's process initialization and window loop.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
	"github.com/wojciechpolak/dud/client/optical-sender/display/window"
)

func main() {
	if run() != nil {
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("invalid window invocation")
	}
	values := make([]int, 4)
	for i := range values {
		value, err := strconv.Atoi(os.Args[i+1])
		if err != nil {
			return err
		}
		values[i] = value
	}
	block := optical.HighDensityBlockSize
	if values[0] == 30 {
		block = optical.BlockSize
	}
	options := display.Options{Settings: display.QRSettings{Version: values[0], ErrorCorrection: display.QRLow, QuietZone: values[1], Scale: values[2]}, FPS: values[3], BlockSize: block}
	if err := window.Check(options); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "DUD-OPTICAL-WINDOW-READY-1"); err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 256), 4096)
	if !scanner.Scan() {
		return fmt.Errorf("missing ciphertext input")
	}
	encoder, scheduler, first, err := display.Prepare(scanner.Text(), options)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	return window.RunWindowContext(ctx, encoder, scheduler, options.Settings, first, 4, options.FPS, io.Discard)
}
