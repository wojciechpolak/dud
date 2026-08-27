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
	outputJSON   bool
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
		case "--json":
			if err := markJSONOption(&opts.outputJSON); err != nil {
				return opts, err
			}
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
	// Without --out, age-keygen writes the new private identity to stdout. A JSON
	// report cannot share that stream, so --json requires an output file.
	if opts.outputJSON && opts.out == "" {
		return fatalError("keygen requires --out when generating a new identity with --json")
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
		recipientFile := opts.recipientOut
		if recipientFile == "" {
			recipientFile = opts.out
		}
		if recipientFile != "" {
			keygenArgs = append(keygenArgs, "-o", recipientFile)
		}
		keygenArgs = append(keygenArgs, opts.input)
		if !opts.outputJSON {
			return a.runCommand(a.cfg.AgeKeygenBin, keygenArgs, a.in, a.out, a.errOut)
		}
		// Recipients are public, so the report may include them. This process does
		// not read the source identity again.
		var recipients bytes.Buffer
		if err := a.runCommand(a.cfg.AgeKeygenBin, keygenArgs, a.in, &recipients, a.errOut); err != nil {
			return err
		}
		if recipientFile != "" {
			return writeJSON(a.out, map[string]any{
				"ok": true, "recipient_file": recipientFile, "pq": false,
			})
		}
		return writeJSON(a.out, map[string]any{
			"ok": true, "recipient": strings.TrimSpace(recipients.String()), "pq": false,
		})
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
	recipient := ""
	if opts.recipientOut != "" || opts.outputJSON {
		var recipients bytes.Buffer
		cmd := exec.Command(a.cfg.AgeKeygenBin, "-y", opts.out)
		cmd.Stdout = &recipients
		cmd.Stderr = a.errOut
		if err := cmd.Run(); err != nil {
			return err
		}
		recipient = strings.TrimSpace(recipients.String())
		if opts.recipientOut != "" {
			if err := os.WriteFile(opts.recipientOut, recipients.Bytes(), 0o600); err != nil {
				return err
			}
		}
	}
	if opts.outputJSON {
		// The report contains recipients and paths only. The identity remains in
		// the file written by age-keygen and is never echoed.
		report := map[string]any{
			"ok":            true,
			"recipient":     recipient,
			"identity_file": opts.out,
			"pq":            opts.pq,
		}
		if opts.recipientOut != "" {
			report["recipient_file"] = opts.recipientOut
		}
		return writeJSON(a.out, report)
	}
	return nil
}

// ageKeygenSupportsPQ reads help text even when the command exits non-zero.
// Some CLIs return a non-zero status for --help.
func (a *app) ageKeygenSupportsPQ() (bool, error) {
	cmd := exec.Command(a.cfg.AgeKeygenBin, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) == 0 {
		return false, err
	}
	return strings.Contains(string(output), "-pq"), nil
}
