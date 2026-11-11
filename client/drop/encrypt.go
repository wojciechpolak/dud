// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package drop

import (
	"os"
	"strings"
)

type EncryptionOptions struct {
	InlineRecipients []string
	RecipientsFile   string
}

func (opts EncryptionOptions) RecipientMode() bool {
	return len(opts.InlineRecipients) > 0 || opts.RecipientsFile != ""
}

type AgeRunner func(args ...string) error
type TempFileCreator func(pattern string) (string, error)
type TempFileRemover func(path string)

// EncryptFile keeps recipients supplied on the command line out of the age
// process arguments. The caller owns the age process and scratch-file cleanup
// policy, so native carriers can preserve their terminal and cleanup behavior.
func EncryptFile(input, output string, opts EncryptionOptions, run AgeRunner, createTemp TempFileCreator, removeTemp TempFileRemover) error {
	if !opts.RecipientMode() {
		return run("--encrypt", "--passphrase", "-o", output, input)
	}
	ageArgs := []string{"--encrypt"}
	if len(opts.InlineRecipients) > 0 {
		inlineRecipientsFile, err := createTemp("dud-upload-recipients-txt-")
		if err != nil {
			return err
		}
		defer removeTemp(inlineRecipientsFile)
		if err := os.WriteFile(inlineRecipientsFile, []byte(strings.Join(opts.InlineRecipients, "\n")+"\n"), 0o600); err != nil {
			return err
		}
		ageArgs = append(ageArgs, "-R", inlineRecipientsFile)
	}
	if opts.RecipientsFile != "" {
		ageArgs = append(ageArgs, "-R", opts.RecipientsFile)
	}
	ageArgs = append(ageArgs, "-o", output, input)
	return run(ageArgs...)
}
