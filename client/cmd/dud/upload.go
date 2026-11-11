// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/wojciechpolak/dud/client/drop"
)

type uploadResponse struct {
	ID              string `json:"id"`
	ExpiresAt       string `json:"expiresAt"`
	DeleteAfterRead bool   `json:"deleteAfterRead"`
}

type uploadOptions struct {
	optical             bool
	opticalProfile      string
	opticalRenderer     string
	opticalQuietZone    int
	opticalScale        int
	explicitFlags       map[string]bool
	files               []string
	message             string
	ttl                 string
	deleteAfterRead     bool
	passphraseRequested bool
	inlineRecipients    []string
	recipientsFile      string
	outputJSON          bool
	outputQR            bool
	baseURL             string
	dohURL              string
}

func parseUploadOptions(args []string, defaultBaseURL, defaultDOHURL string) (uploadOptions, error) {
	opts := uploadOptions{
		ttl:            "24h",
		opticalProfile: "high-rate", opticalRenderer: "window", opticalQuietZone: 4, opticalScale: 2,
		explicitFlags: make(map[string]bool),
		outputQR:      true,
		baseURL:       defaultBaseURL,
		dohURL:        defaultDOHURL,
	}

	for len(args) > 0 {
		opts.explicitFlags[args[0]] = true
		switch args[0] {
		case "--optical":
			opts.optical = true
			args = args[1:]
		case "--optical-profile", "--optical-renderer":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			if args[0] == "--optical-profile" {
				opts.opticalProfile = args[1]
			} else {
				opts.opticalRenderer = args[1]
			}
			args = args[2:]
		case "--optical-quiet-zone", "--optical-scale":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			value, err := strconv.Atoi(args[1])
			if err != nil {
				return opts, fatalError("Invalid optical integer option")
			}
			if args[0] == "--optical-scale" {
				opts.opticalScale = value
			} else {
				opts.opticalQuietZone = value
			}
			args = args[2:]
		case "--file":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.files = append(opts.files, args[1])
			args = args[2:]
		case "-m":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.message = args[1]
			args = args[2:]
		case "--ttl":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.ttl = args[1]
			args = args[2:]
		case "--delete-after-read":
			opts.deleteAfterRead = true
			args = args[1:]
		case "--passphrase":
			opts.passphraseRequested = true
			args = args[1:]
		case "--recipient", "-r":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.inlineRecipients = append(opts.inlineRecipients, args[1])
			args = args[2:]
		case "--recipient-file", "-R":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.recipientsFile = args[1]
			args = args[2:]
		case "--json":
			if err := markJSONOption(&opts.outputJSON); err != nil {
				return opts, err
			}
			args = args[1:]
		case "--no-qr":
			opts.outputQR = false
			args = args[1:]
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
		default:
			return opts, fatalError("Unknown upload option: " + args[0])
		}
	}

	return opts, nil
}

func (opts uploadOptions) sourceCount() int {
	count := 0
	if len(opts.files) > 0 {
		count++
	}
	if opts.message != "" {
		count++
	}
	return count
}

func (opts uploadOptions) recipientMode() bool {
	return len(opts.inlineRecipients) > 0 || opts.recipientsFile != ""
}

func validateUploadOptions(opts uploadOptions, cfg config) error {
	if opts.optical {
		return validateOpticalUploadOptions(opts)
	}
	for name := range opts.explicitFlags {
		if strings.HasPrefix(name, "--optical-") {
			return fatalError("Optical display options require --optical")
		}
	}
	if opts.sourceCount() > 1 {
		return fatalError("upload accepts only one source: --file, -m, or stdin")
	}
	if opts.recipientsFile != "" {
		if info, err := os.Stat(opts.recipientsFile); err != nil || info.IsDir() {
			return fatalError("Recipients file not found: " + opts.recipientsFile)
		}
	}
	if cfg.SecretToken == "" {
		return fatalError("upload requires DUD_DROP_SECRET")
	}
	if opts.passphraseRequested && opts.recipientMode() {
		return fatalError("upload accepts either --passphrase or recipient options, not both")
	}
	return nil
}

func parseUploadResponse(data []byte) (uploadResponse, error) {
	var response uploadResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return response, withCLISteps(fatalError("upload returned an invalid response"), localCLIStep("Check server logs before uploading again.", "--version"))
	}
	if response.ID == "" || response.ExpiresAt == "" {
		return response, withCLISteps(fatalError("upload returned an invalid response"), localCLIStep("Check server logs before uploading again.", "--version"))
	}
	return response, nil
}

func buildReceiveCommand(prefix, id, baseURL string, bundle bool) string {
	cmd := fmt.Sprintf("%s --id %s --url %s", prefix, cliShellArg(id), cliShellArg(baseURL))
	if bundle {
		cmd += " --extract"
	} else if prefix == "dud receive" || prefix == "dud download" {
		cmd += " --out PATH"
	}
	return cmd
}

func (a *app) printUploadResponse(response uploadResponse, receiveCommand string) error {
	fmt.Fprintln(a.out, "Upload complete")
	report := &textReport{}
	drop := report.section("")
	drop.add("ID", response.ID)
	drop.add("Expires", response.ExpiresAt)
	drop.add("Delete after read", v2YesNo(response.DeleteAfterRead))
	drop.add("Receive", receiveCommand)
	drop.note("Receive on the other device; use --identity PATH for recipient encryption.")
	return report.write(a.out)
}

func (a *app) printUploadQR(id string) error {
	if a.showQRCode != nil {
		return a.showQRCode(id)
	}
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "QR Code:")
	return a.runCommand(a.cfg.QREncodeBin, []string{"-t", "ansiutf8", id}, nil, a.out, a.errOut)
}

// writeUploadPlaintext assembles the bytes to upload into one file and reports
// whether they were bundled into an archive. A directory, or more than one
// path, becomes a bundle; a single file is copied as it is, so the download
// side writes back the same file rather than an archive containing it.
func (a *app) writeUploadPlaintext(plainFile string, opts uploadOptions) (bool, error) {
	prepared, err := drop.PrepareInput(plainFile, drop.InputOptions{
		Files: opts.files, Message: opts.message,
	}, drop.InputEnvironment{
		Context: a.commandContext(), Stdin: a.in, Stderr: a.errOut, CommandOutput: a.out, StdinIsTTY: stdinIsTTY(),
	})
	if err != nil {
		return false, err
	}
	return prepared.Bundle, nil
}

// encryptUploadPlaintext encrypts the assembled plaintext with age. Recipients
// given on the command line are written to a file rather than passed as
// arguments, so they do not appear in this host's process list.
func (a *app) encryptUploadPlaintext(plainFile, encryptedFile string, opts uploadOptions) error {
	return drop.EncryptFile(plainFile, encryptedFile, drop.EncryptionOptions{
		InlineRecipients: opts.inlineRecipients,
		RecipientsFile:   opts.recipientsFile,
	}, a.runAge, tempFile, removeTempFile)
}

// reportUpload renders what the server returned for an upload, including the
// command that downloads it again.
func (a *app) reportUpload(data []byte, opts uploadOptions, receivePrefix string, bundle bool) error {
	if opts.outputJSON {
		if _, err := a.out.Write(data); err != nil {
			return err
		}
		fmt.Fprintln(a.out)
		return nil
	}
	response, err := parseUploadResponse(data)
	if err != nil {
		return err
	}
	if err := a.printUploadResponse(response, buildReceiveCommand(receivePrefix, response.ID, opts.baseURL, bundle)); err != nil {
		return err
	}
	if opts.outputQR {
		return a.printUploadQR(response.ID)
	}
	return nil
}

func (a *app) cmdUpload(args []string, receivePrefix string) error {
	opts, err := parseUploadOptions(args, a.cfg.DropBaseURL, a.cfg.DOHURL)
	if hasOpticalUploadFlag(args) {
		if err != nil {
			return a.reportOpticalFailure(hasJSONFlag(args), opticalFailure("usage", "Invalid optical upload arguments"))
		}
		if err := validateUploadOptions(opts, a.cfg); err != nil {
			return a.reportOpticalFailure(opts.outputJSON, err)
		}
		return a.cmdOpticalUpload(opts)
	}
	if err != nil {
		return cliUsageHint(err)
	}
	if err := validateUploadOptions(opts, a.cfg); err != nil {
		return err
	}
	a.cfg.DOHURL = opts.dohURL

	plainFile, err := tempFile("dud-upload-plain-")
	if err != nil {
		return err
	}
	defer removeTempFile(plainFile)
	encryptedFile, err := tempFile("dud-upload-age-")
	if err != nil {
		return err
	}
	defer removeTempFile(encryptedFile)

	bundle, err := a.writeUploadPlaintext(plainFile, opts)
	if err != nil {
		return err
	}
	a.transferObserver("encryption")
	if err := a.encryptUploadPlaintext(plainFile, encryptedFile, opts); err != nil {
		return err
	}
	data, err := a.postUpload(encryptedFile, opts)
	if err != nil {
		return err
	}
	return a.reportUpload(data, opts, receivePrefix, bundle)
}

// dropUploadResponseLimit bounds the JSON envelope the upload route returns.
// It is generous next to the three short fields the server actually sends, and
// it keeps a misbehaving origin from streaming an unbounded "response" into
// memory on a route that has no reason to produce one.
const dropUploadResponseLimit = 64 * 1024

// postUpload streams the age ciphertext straight from its temp file. The whole
// payload is never held in memory, and the exact size is declared up front, so
// the request is never chunked.
func (a *app) postUpload(encryptedFile string, opts uploadOptions) ([]byte, error) {
	file, err := os.Open(encryptedFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	deleteAfterRead := "false"
	if opts.deleteAfterRead {
		deleteAfterRead = "true"
	}
	headers := http.Header{}
	headers.Set("content-type", "application/octet-stream")
	headers.Set("x-dud-ttl", opts.ttl)
	headers.Set("x-dud-delete-after-read", deleteAfterRead)
	headers.Set("x-dud-secret-token", a.cfg.SecretToken)

	response, err := a.dropRequest(a.commandContext(), opts.baseURL+"/v1/files", v2Request{
		Method:           http.MethodPost,
		Headers:          headers,
		BodyStream:       file,
		ContentLength:    info.Size(),
		MaxResponseBytes: dropUploadResponseLimit,
		ObserveUpload:    a.transferObserver("upload"),
	})
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}
