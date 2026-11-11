// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender"
)

// opticalRecipients snapshots native recipients before age can consume them.
// Plugin recipients are excluded because a plugin can access a network or ask
// an external service for key material during a local optical operation.
func opticalRecipients(opts uploadOptions) (drop.EncryptionOptions, error) {
	recipients := append([]string(nil), opts.inlineRecipients...)
	if opts.recipientsFile != "" {
		file, err := os.Open(opts.recipientsFile)
		if err != nil {
			return drop.EncryptionOptions{}, opticalFailure("input", "Optical recipient file is unavailable")
		}
		defer func() { _ = file.Close() }()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return drop.EncryptionOptions{}, opticalFailure("input", "Optical recipient file is unavailable")
		}
		if info.Size() > optical.MaxCapsuleSize {
			return drop.EncryptionOptions{}, opticalFailure("ciphertext-limit", "Optical recipient configuration exceeds the ciphertext budget")
		}
		scanner := bufio.NewScanner(io.LimitReader(file, optical.MaxCapsuleSize+1))
		scanner.Buffer(make([]byte, 4096), 4096)
		for scanner.Scan() {
			value := strings.TrimSpace(scanner.Text())
			if value != "" && !strings.HasPrefix(value, "#") {
				recipients = append(recipients, value)
			}
		}
		if scanner.Err() != nil {
			return drop.EncryptionOptions{}, opticalFailure("encryption", "Optical native recipient configuration is invalid")
		}
	}
	for index, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		recipients[index] = recipient
		if _, err := age.ParseX25519Recipient(recipient); err == nil {
			continue
		}
		if _, err := age.ParseHybridRecipient(recipient); err == nil {
			continue
		}
		return drop.EncryptionOptions{}, opticalFailure("encryption", "Optical encryption requires native X25519 or hybrid recipients")
	}
	if opts.recipientMode() && len(recipients) == 0 {
		return drop.EncryptionOptions{}, opticalFailure("encryption", "Optical recipient configuration is empty")
	}
	return drop.EncryptionOptions{InlineRecipients: recipients}, nil
}
