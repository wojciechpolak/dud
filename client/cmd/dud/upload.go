// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type uploadResponse struct {
	ID              string `json:"id"`
	ExpiresAt       string `json:"expiresAt"`
	DeleteAfterRead bool   `json:"deleteAfterRead"`
}

type uploadOptions struct {
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
		ttl:      "24h",
		outputQR: true,
		baseURL:  defaultBaseURL,
		dohURL:   defaultDOHURL,
	}

	for len(args) > 0 {
		switch args[0] {
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
		return response, fatalError("Upload succeeded but returned an unexpected JSON response.")
	}
	if response.ID == "" || response.ExpiresAt == "" {
		return response, fatalError("Upload succeeded but returned an unexpected JSON response.")
	}
	return response, nil
}

func buildReceiveCommand(prefix, id, baseURL string, bundle bool) string {
	cmd := fmt.Sprintf("%s --id %s --url %s", prefix, id, baseURL)
	if bundle {
		cmd += " --extract"
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
	return report.write(a.out)
}

func (a *app) printUploadQR(id string) error {
	fmt.Fprintln(a.out)
	fmt.Fprintln(a.out, "QR Code:")
	return a.runCommand(a.cfg.QREncodeBin, []string{"-t", "ansiutf8", id}, nil, a.out, a.errOut)
}

func (a *app) createBundleArchive(archivePath string, sources []string) error {
	args := []string{"-cf", archivePath}
	seen := map[string]bool{}

	for _, source := range sources {
		if source == "" {
			continue
		}
		info, err := os.Lstat(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fatalError("Path not found: " + source)
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fatalError("Bundle sources cannot include symlinks: " + source)
		}
		if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fatalError("Bundle sources cannot include symlinks: " + source)
			}
			return nil
		}); err != nil {
			return err
		}

		archiveName := filepath.Base(source)
		if archiveName == "" || archiveName == "." || archiveName == ".." {
			return fatalError("Bundle source has an invalid top-level name: " + source)
		}
		if seen[archiveName] {
			return fatalError("Bundle sources must have unique top-level names: " + archiveName)
		}
		seen[archiveName] = true
		args = append(args, "-C", filepath.Dir(source), archiveName)
	}

	cmd := exec.Command("tar", args...)
	cmd.Stdout = a.out
	cmd.Stderr = a.errOut
	return cmd.Run()
}

// writeUploadPlaintext assembles the bytes to upload into one file and reports
// whether they were bundled into an archive. A directory, or more than one
// path, becomes a bundle; a single file is copied as it is, so the download
// side writes back the same file rather than an archive containing it.
func (a *app) writeUploadPlaintext(plainFile string, opts uploadOptions) (bool, error) {
	if len(opts.files) == 0 {
		return false, a.writeUploadInput(plainFile, opts)
	}
	bundle := false
	pathCount := 0
	for _, source := range opts.files {
		if source == "" {
			continue
		}
		info, err := os.Stat(source)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, fatalError("Path not found: " + source)
			}
			return false, err
		}
		pathCount++
		if info.IsDir() || pathCount > 1 {
			bundle = true
		}
	}
	if bundle {
		return true, a.createBundleArchive(plainFile, opts.files)
	}
	return false, copyFile(plainFile, opts.files[0])
}

// writeUploadInput writes the plaintext of an upload that names no files: the
// message given on the command line, or standard input.
func (a *app) writeUploadInput(plainFile string, opts uploadOptions) error {
	if opts.message != "" {
		return os.WriteFile(plainFile, []byte(opts.message), 0o600)
	}
	if stdinIsTTY() {
		fmt.Fprintln(a.errOut, "Enter plaintext, then press Ctrl-D when finished.")
	}
	out, err := os.Create(plainFile)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, a.in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// encryptUploadPlaintext encrypts the assembled plaintext with age. Recipients
// given on the command line are written to a file rather than passed as
// arguments, so they do not appear in this host's process list.
func (a *app) encryptUploadPlaintext(plainFile, encryptedFile string, opts uploadOptions) error {
	if !opts.recipientMode() {
		return a.runAge("--encrypt", "--passphrase", "-o", encryptedFile, plainFile)
	}
	ageArgs := []string{"--encrypt"}
	if len(opts.inlineRecipients) > 0 {
		inlineRecipientsFile, err := tempFile("dud-upload-recipients-txt-")
		if err != nil {
			return err
		}
		defer removeTempFile(inlineRecipientsFile)
		if err := os.WriteFile(inlineRecipientsFile, []byte(strings.Join(opts.inlineRecipients, "\n")+"\n"), 0o600); err != nil {
			return err
		}
		ageArgs = append(ageArgs, "-R", inlineRecipientsFile)
	}
	if opts.recipientsFile != "" {
		ageArgs = append(ageArgs, "-R", opts.recipientsFile)
	}
	ageArgs = append(ageArgs, "-o", encryptedFile, plainFile)
	return a.runAge(ageArgs...)
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
	if err != nil {
		return err
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

	response, err := a.dropRequest(context.Background(), opts.baseURL+"/v1/files", v2Request{
		Method:           http.MethodPost,
		Headers:          headers,
		BodyStream:       file,
		ContentLength:    info.Size(),
		MaxResponseBytes: dropUploadResponseLimit,
	})
	if err != nil {
		return nil, err
	}
	return response.Body, nil
}
