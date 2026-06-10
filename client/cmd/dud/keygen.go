// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

type keygenOptions struct {
	out          string
	recipientOut string
	pq           bool
	input        string
}

func parseKeygenOptions(args []string) (keygenOptions, error) {
	var opts keygenOptions

	for len(args) > 0 {
		switch args[0] {
		case "--out":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.out = args[1]
			args = args[2:]
		case "--recipient-out", "-R":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.recipientOut = args[1]
			args = args[2:]
		case "--pq":
			opts.pq = true
			args = args[1:]
		default:
			if strings.HasPrefix(args[0], "-") {
				return opts, fatalError("Unknown keygen option: " + args[0])
			}
			if opts.input != "" {
				return opts, fatalError("keygen accepts at most one input path")
			}
			opts.input = args[0]
			args = args[1:]
		}
	}

	return opts, nil
}

func validateKeygenOptions(opts keygenOptions) error {
	if opts.input != "" {
		if opts.pq {
			return fatalError("keygen does not accept --pq when converting an identity to recipients")
		}
		if opts.out != "" && opts.recipientOut != "" {
			return fatalError("keygen accepts only one recipient output target: --out or -R")
		}
		return nil
	}
	if opts.recipientOut != "" && opts.out == "" {
		return fatalError("keygen requires --out when generating a new identity with -R")
	}
	return nil
}

func (a *app) cmdKeygen(args []string) error {
	opts, err := parseKeygenOptions(args)
	if err != nil {
		return err
	}
	if err := validateKeygenOptions(opts); err != nil {
		return err
	}

	if opts.input != "" {
		keygenArgs := []string{"-y"}
		if opts.recipientOut != "" {
			keygenArgs = append(keygenArgs, "-o", opts.recipientOut)
		} else if opts.out != "" {
			keygenArgs = append(keygenArgs, "-o", opts.out)
		}
		keygenArgs = append(keygenArgs, opts.input)
		return a.runCommand(a.cfg.AgeKeygenBin, keygenArgs, a.in, a.out, a.errOut)
	}

	if opts.pq {
		supports, err := a.ageKeygenSupportsPQ()
		if err != nil {
			return err
		}
		if !supports {
			return fatalError("The bundled age-keygen does not support -pq. Rebuild the client image with age v1.3.0 or later.")
		}
	}

	keygenArgs := []string{}
	if opts.pq {
		keygenArgs = append(keygenArgs, "-pq")
	}
	if opts.out != "" {
		keygenArgs = append(keygenArgs, "-o", opts.out)
	}
	if err := a.runCommand(a.cfg.AgeKeygenBin, keygenArgs, a.in, a.out, a.errOut); err != nil {
		return err
	}
	if opts.recipientOut != "" {
		var recipients bytes.Buffer
		cmd := exec.Command(a.cfg.AgeKeygenBin, "-y", opts.out)
		cmd.Stdout = &recipients
		cmd.Stderr = a.errOut
		if err := cmd.Run(); err != nil {
			return err
		}
		return os.WriteFile(opts.recipientOut, recipients.Bytes(), 0o600)
	}
	return nil
}

// Help text is inspected regardless of the exit status: some CLIs exit
// non-zero for --help, and the shell version only grepped the output.
func (a *app) ageKeygenSupportsPQ() (bool, error) {
	cmd := exec.Command(a.cfg.AgeKeygenBin, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) == 0 {
		return false, err
	}
	return strings.Contains(string(output), "-pq"), nil
}
