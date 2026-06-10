// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"fmt"
	"strings"
)

func (a *app) interactiveMenu() error {
	r := bufio.NewReader(a.in)
	a.in = r
	fmt.Fprint(a.out, "\ndud — Discreet Upload/Download\n\n")
	fmt.Fprintln(a.out, "  1) test")
	fmt.Fprintln(a.out, "  2) upload")
	fmt.Fprintln(a.out, "  3) download")
	fmt.Fprintln(a.out, "  4) keygen")
	fmt.Fprintln(a.out, "  5) git")
	fmt.Fprintln(a.out, "  6) flush")
	fmt.Fprintln(a.out, "  q) quit")
	fmt.Fprint(a.out, "\nChoice: ")
	choice := readLine(r)
	switch choice {
	case "1", "test":
		return a.interactiveTest(r)
	case "2", "upload":
		return a.interactiveUpload(r)
	case "3", "download":
		return a.interactiveDownload(r)
	case "4", "keygen":
		return a.interactiveKeygen(r)
	case "5", "git":
		return a.interactiveGit(r)
	case "6", "flush":
		return a.interactiveFlush(r)
	case "q", "quit":
		return nil
	default:
		return fatalError("Unknown choice: " + choice)
	}
}

func readLine(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func (a *app) interactiveTest(r *bufio.Reader) error {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	return a.cmdTest([]string{"--url", serverURL + "/v1/test"})
}

func (a *app) interactiveUpload(r *bufio.Reader) error {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	fmt.Fprintln(a.out, "Upload source:")
	fmt.Fprintln(a.out, "  1) file path")
	fmt.Fprintln(a.out, "  2) typed or pasted text (Ctrl-D to finish)")
	fmt.Fprintln(a.out, "  3) one-line message")
	fmt.Fprint(a.out, "Choice [1]: ")
	sourceChoice := readLine(r)
	if sourceChoice == "" {
		sourceChoice = "1"
	}

	file := ""
	message := ""
	switch sourceChoice {
	case "1", "file":
		fmt.Fprint(a.out, "File path: ")
		file = readLine(r)
		if file == "" {
			return fatalError("file path required")
		}
		file = absPathIfRelative(file)
	case "2", "text", "stdin":
	case "3", "message":
		fmt.Fprint(a.out, "Message: ")
		message = readLine(r)
		if message == "" {
			return fatalError("message required")
		}
	default:
		return fatalError("Unknown upload source: " + sourceChoice)
	}

	encryptionArgs, err := a.interactiveEncryptionArgs(r)
	if err != nil {
		return err
	}
	fmt.Fprint(a.out, "TTL [24h]: ")
	ttl := readLine(r)
	if ttl == "" {
		ttl = "24h"
	}
	fmt.Fprint(a.out, "Delete after read? [y/N]: ")
	ans := readLine(r)
	args := []string{"--ttl", ttl, "--url", serverURL}
	if strings.HasPrefix(strings.ToLower(ans), "y") {
		args = append(args, "--delete-after-read")
	}
	args = append(args, encryptionArgs...)
	switch sourceChoice {
	case "1", "file":
		args = append([]string{"--file", file}, args...)
	case "3", "message":
		args = append([]string{"-m", message}, args...)
	}
	return a.cmdUpload(args, "dud receive")
}

func (a *app) interactiveEncryptionArgs(r *bufio.Reader) ([]string, error) {
	fmt.Fprintln(a.out, "Encryption mode:")
	fmt.Fprintln(a.out, "  1) passphrase")
	fmt.Fprintln(a.out, "  2) recipient string")
	fmt.Fprintln(a.out, "  3) recipient file")
	fmt.Fprint(a.out, "Choice [1]: ")
	choice := readLine(r)
	if choice == "" {
		choice = "1"
	}
	switch choice {
	case "1", "passphrase":
		return nil, nil
	case "2", "recipient":
		fmt.Fprint(a.out, "Recipient: ")
		recipient := readLine(r)
		if recipient == "" {
			return nil, fatalError("recipient required")
		}
		return []string{"-r", recipient}, nil
	case "3", "recipient-file":
		fmt.Fprint(a.out, "Recipient file: ")
		recipientFile := readLine(r)
		if recipientFile == "" {
			return nil, fatalError("recipient file required")
		}
		return []string{"-R", absPathIfRelative(recipientFile)}, nil
	default:
		return nil, fatalError("Unknown encryption mode: " + choice)
	}
}

func (a *app) interactiveDownload(r *bufio.Reader) error {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	fmt.Fprint(a.out, "File ID: ")
	id := readLine(r)
	if id == "" {
		return fatalError("file ID required")
	}
	fmt.Fprintln(a.out, "Download output:")
	fmt.Fprintln(a.out, "  1) file path")
	fmt.Fprintln(a.out, "  2) stdout")
	fmt.Fprintln(a.out, "  3) extract bundle")
	fmt.Fprint(a.out, "Choice [1]: ")
	outputChoice := readLine(r)
	if outputChoice == "" {
		outputChoice = "1"
	}
	args := []string{"--id", id, "--url", serverURL}
	switch outputChoice {
	case "1", "file":
		fmt.Fprint(a.out, "Output path: ")
		out := readLine(r)
		if out == "" {
			return fatalError("output path required")
		}
		args = append(args, "--out", absPathIfRelative(out))
	case "2", "stdout":
		args = append(args, "--stdout")
	case "3", "extract":
		fmt.Fprintf(a.out, "Output directory (leave empty for ./dud-%s): ", id)
		outDir := readLine(r)
		args = append(args, "--extract")
		if outDir != "" {
			args = append(args, "--out-dir", absPathIfRelative(outDir))
		}
	default:
		return fatalError("Unknown download output: " + outputChoice)
	}
	fmt.Fprint(a.out, "Identity file (leave empty if not needed): ")
	identity := readLine(r)
	if identity != "" {
		args = append(args, "-i", absPathIfRelative(identity))
	}
	return a.cmdDownload(args)
}

func (a *app) interactiveGit(r *bufio.Reader) error {
	fmt.Fprintln(a.out, "Git mode:")
	fmt.Fprintln(a.out, "  1) push")
	fmt.Fprintln(a.out, "  2) fetch")
	fmt.Fprintln(a.out, "  b) back")
	fmt.Fprintln(a.out, "  q) quit")
	fmt.Fprint(a.out, "Choice [1]: ")
	choice := readLine(r)
	if choice == "" {
		choice = "1"
	}
	switch choice {
	case "1", "push", "send":
		return a.interactiveGitPush(r)
	case "2", "fetch", "receive":
		return a.interactiveGitFetch(r)
	case "b", "back":
		return a.interactiveMenu()
	case "q", "quit":
		return nil
	default:
		return fatalError("Unknown git mode: " + choice)
	}
}

func (a *app) interactiveGitPush(r *bufio.Reader) error {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	encryptionArgs, err := a.interactiveEncryptionArgs(r)
	if err != nil {
		return err
	}
	fmt.Fprint(a.out, "TTL [24h]: ")
	ttl := readLine(r)
	if ttl == "" {
		ttl = "24h"
	}
	args := []string{"--ttl", ttl, "--url", serverURL}
	fmt.Fprint(a.out, "Delete after read? [y/N]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		args = append(args, "--delete-after-read")
	}
	fmt.Fprint(a.out, "Show QR code? [Y/n]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "n") {
		args = append(args, "--no-qr")
	}
	args = append(args, encryptionArgs...)
	return a.cmdGitPush(args)
}

func (a *app) interactiveGitFetch(r *bufio.Reader) error {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	fmt.Fprint(a.out, "File ID: ")
	id := readLine(r)
	if id == "" {
		return fatalError("file ID required")
	}
	args := []string{"--id", id, "--url", serverURL}
	fmt.Fprint(a.out, "Identity file (leave empty if not needed): ")
	identity := readLine(r)
	if identity != "" {
		args = append(args, "-i", absPathIfRelative(identity))
	}
	fmt.Fprint(a.out, "Remote name [dud]: ")
	remote := readLine(r)
	if remote == "" {
		remote = "dud"
	}
	args = append(args, "--remote", remote)
	return a.cmdGitFetch(args)
}

func (a *app) interactiveKeygen(r *bufio.Reader) error {
	fmt.Fprintln(a.out, "Keygen mode:")
	fmt.Fprintln(a.out, "  1) generate a new identity")
	fmt.Fprintln(a.out, "  2) convert an identity to recipients")
	fmt.Fprint(a.out, "Choice [1]: ")
	choice := readLine(r)
	if choice == "" {
		choice = "1"
	}
	switch choice {
	case "1", "generate":
		args := []string{}
		fmt.Fprint(a.out, "Post-quantum key? [y/N]: ")
		if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
			args = append(args, "--pq")
		}
		fmt.Fprint(a.out, "Identity output path (leave empty for stdout): ")
		out := readLine(r)
		if out != "" {
			out = absPathIfRelative(out)
			args = append(args, "--out", out)
			fmt.Fprint(a.out, "Recipient output path (leave empty to skip): ")
			recipientOut := readLine(r)
			if recipientOut != "" {
				args = append(args, "-R", absPathIfRelative(recipientOut))
			}
		}
		return a.cmdKeygen(args)
	case "2", "convert":
		fmt.Fprint(a.out, "Identity file: ")
		input := readLine(r)
		if input == "" {
			return fatalError("identity file required")
		}
		args := []string{absPathIfRelative(input)}
		fmt.Fprint(a.out, "Recipient output path (leave empty for stdout): ")
		recipientOut := readLine(r)
		if recipientOut != "" {
			args = append([]string{"-R", absPathIfRelative(recipientOut)}, args...)
		}
		return a.cmdKeygen(args)
	default:
		return fatalError("Unknown keygen mode: " + choice)
	}
}

func (a *app) interactiveFlush(r *bufio.Reader) error {
	fmt.Fprint(a.out, "Flush all expired files? [y/N]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		return a.cmdFlush(nil)
	}
	fmt.Fprintln(a.out, "Cancelled.")
	return nil
}
