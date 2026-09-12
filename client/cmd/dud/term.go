// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type v2Terminal struct {
	in    *os.File
	out   *os.File
	close func() error
}

var openV2TTY = openControllingTerminal

func readV2TTYLine(prompt string, hidden bool) (string, error) {
	terminal, err := openV2TTY()
	if err != nil {
		return "", errors.New("this operation requires an interactive TTY")
	}
	defer terminal.close()
	if _, err := fmt.Fprint(terminal.out, prompt); err != nil {
		return "", err
	}
	restore := func() error { return nil }
	if hidden {
		restore, err = disableTerminalEcho(terminal.in.Fd())
		if err != nil {
			return "", err
		}
		defer restore()
	}
	line, readErr := bufio.NewReader(terminal.in).ReadString('\n')
	if hidden {
		_, _ = fmt.Fprintln(terminal.out)
	}
	if readErr != nil {
		return "", readErr
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptV2OriginConfirmation(origin string) (bool, error) {
	value, err := readV2TTYLine(
		fmt.Sprintf("Invitation requests new peer origin %s. Trust this origin? [y/N]: ", origin),
		false,
	)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(value), "y") ||
		strings.EqualFold(strings.TrimSpace(value), "yes"), nil
}
