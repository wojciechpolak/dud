// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
)

type downloadOptions struct {
	id           string
	out          string
	outDir       string
	outputStdout bool
	baseURL      string
	identity     string
	extract      bool
	dohURL       string
	outputJSON   bool
}

func parseDownloadOptions(args []string, defaultBaseURL, defaultDOHURL string) (downloadOptions, error) {
	opts := downloadOptions{
		baseURL: defaultBaseURL,
		dohURL:  defaultDOHURL,
	}

	for len(args) > 0 {
		switch args[0] {
		case "--id":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.id = args[1]
			args = args[2:]
		case "--out":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.out = args[1]
			args = args[2:]
		case "--stdout":
			opts.outputStdout = true
			args = args[1:]
		case "--extract":
			opts.extract = true
			args = args[1:]
		case "--out-dir":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.outDir = args[1]
			args = args[2:]
		case "--identity", "-i":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.identity = args[1]
			args = args[2:]
		case "--url":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.baseURL = args[1]
			args = args[2:]
		case "--doh-url":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.dohURL = args[1]
			args = args[2:]
		case "--json":
			if err := markJSONOption(&opts.outputJSON); err != nil {
				return opts, err
			}
			args = args[1:]
		default:
			return opts, fatalError("Unknown download option: " + args[0])
		}
	}

	return opts, nil
}

func validateDownloadOptions(opts downloadOptions) error {
	if opts.id == "" {
		return fatalError("download requires --id")
	}
	if opts.extract && opts.outputStdout {
		return fatalError("download does not support --stdout with --extract")
	}
	if opts.extract && opts.out != "" {
		return fatalError("download accepts --out-dir instead of --out when using --extract")
	}
	if opts.out != "" && opts.outputStdout {
		return fatalError("download accepts only one output target: --out or --stdout")
	}
	// The payload owns stdout under --stdout. A JSON report would interleave with
	// it, so the command rejects this combination.
	if opts.outputJSON && opts.outputStdout {
		return fatalError("download does not support --json with --stdout")
	}
	if !opts.extract && opts.outDir != "" {
		return fatalError("download accepts --out-dir only with --extract")
	}
	if !opts.extract && opts.out == "" && !opts.outputStdout {
		return fatalError("download requires either --out or --stdout")
	}
	if opts.identity != "" {
		if info, err := os.Stat(opts.identity); err != nil || info.IsDir() {
			return fatalError("Identity file not found: " + opts.identity)
		}
	}
	return nil
}

func (a *app) cmdDownload(args []string) error {
	opts, err := parseDownloadOptions(args, a.cfg.BaseURL, a.cfg.DOHURL)
	if err != nil {
		return err
	}
	if err := validateDownloadOptions(opts); err != nil {
		return err
	}
	a.cfg.DOHURL = opts.dohURL

	encryptedFile, err := tempFile("dud-download-age-")
	if err != nil {
		return err
	}
	defer removeTempFile(encryptedFile)
	plainFile, err := tempFile("dud-download-plain-")
	if err != nil {
		return err
	}
	defer removeTempFile(plainFile)

	if err := a.getDownload(encryptedFile, opts); err != nil {
		return err
	}
	if opts.identity != "" {
		if err := a.runAge("--decrypt", "-i", opts.identity, "-o", plainFile, encryptedFile); err != nil {
			return err
		}
	} else {
		if err := a.runAge("--decrypt", "-o", plainFile, encryptedFile); err != nil {
			return err
		}
	}

	if opts.extract {
		if opts.outDir == "" {
			opts.outDir = "./dud-" + opts.id
		}
		if err := os.MkdirAll(opts.outDir, 0o700); err != nil {
			return err
		}
		listing, err := exec.Command("tar", "-tf", plainFile).Output()
		if err != nil {
			return err
		}
		if err := validateBundleListing(listing); err != nil {
			return err
		}
		cmd := exec.Command("tar", "-xf", plainFile, "-C", opts.outDir)
		cmd.Stdout = a.out
		cmd.Stderr = a.errOut
		if err := cmd.Run(); err != nil {
			return err
		}
		if opts.outputJSON {
			return writeJSON(a.out, a.downloadReport(opts, opts.outDir, plainFile))
		}
		fmt.Fprintf(a.out, "Extracted bundle to %s\n", opts.outDir)
		return nil
	}

	if opts.outputStdout {
		f, err := os.Open(plainFile)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(a.out, f)
		return err
	}
	if err := copyFile(opts.out, plainFile); err != nil {
		return err
	}
	if opts.outputJSON {
		return writeJSON(a.out, a.downloadReport(opts, opts.out, plainFile))
	}
	return nil
}

// downloadReport describes the plaintext output. It reads the byte count from
// the decrypted temporary file, which measures the output rather than the
// ciphertext transfer.
func (a *app) downloadReport(opts downloadOptions, output, plainFile string) map[string]any {
	report := map[string]any{
		"ok":        true,
		"id":        opts.id,
		"output":    output,
		"extracted": opts.extract,
	}
	if info, err := os.Stat(plainFile); err == nil {
		report["bytes"] = info.Size()
	}
	return report
}

// getDownload streams ciphertext into its temporary file and reads through
// EOF. The server performs --delete-after-read cleanup only after sending the
// whole object.
func (a *app) getDownload(encryptedFile string, opts downloadOptions) error {
	response, err := a.dropRequest(
		context.Background(),
		opts.baseURL+"/v1/files/"+url.PathEscape(opts.id),
		v2Request{Method: http.MethodGet, StreamResponse: true},
	)
	if err != nil {
		return err
	}
	defer response.Stream.Close()

	file, err := os.Create(encryptedFile)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, response.Stream)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
