// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// The capsule-handoff test tool keeps encryption, identities, and recovered
// plaintext on the native side of the synthetic-camera browser test.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/wojciechpolak/dud/client/drop"
	"github.com/wojciechpolak/dud/client/optical-sender/capsule"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 5 {
		return errors.New("usage: capsule-handoff encrypt MODE SOURCE CIPHERTEXT SECRET | decrypt MODE CIPHERTEXT SECRET PAYLOAD")
	}
	switch args[0] {
	case "encrypt":
		return encrypt(args[1], args[2], args[3], args[4])
	case "decrypt":
		return decrypt(args[1], args[2], args[3], args[4])
	default:
		return errors.New("operation must be encrypt or decrypt")
	}
}

func encrypt(mode, source, ciphertextPath, secretPath string) error {
	payload, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	encoded, err := capsule.Encode(payload, capsule.Metadata{
		Type: drop.PayloadFile, DisplayName: filepath.Base(source), ArchiveFormat: drop.ArchiveNone,
	})
	if err != nil {
		return err
	}
	recipient, err := createRecipient(mode, secretPath)
	if err != nil {
		return err
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return err
	}
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return os.WriteFile(ciphertextPath, ciphertext.Bytes(), 0o600)
}

func createRecipient(mode, secretPath string) (age.Recipient, error) {
	var recipient age.Recipient
	var secret string
	switch mode {
	case "passphrase":
		secret = "correct horse battery staple"
		value, err := age.NewScryptRecipient(secret)
		if err != nil {
			return nil, err
		}
		recipient = value
	case "X25519":
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		recipient, secret = identity.Recipient(), identity.String()
	case "hybrid":
		identity, err := age.GenerateHybridIdentity()
		if err != nil {
			return nil, err
		}
		recipient, secret = identity.Recipient(), identity.String()
	default:
		return nil, fmt.Errorf("unsupported encryption mode %q", mode)
	}
	if err := os.WriteFile(secretPath, []byte(secret), 0o600); err != nil {
		return nil, err
	}
	return recipient, nil
}

func decrypt(mode, ciphertextPath, secretPath, payloadPath string) error {
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	var identities []age.Identity
	if mode == "passphrase" {
		identity, err := age.NewScryptIdentity(string(secret))
		if err != nil {
			return err
		}
		identities = []age.Identity{identity}
	} else {
		identities, err = age.ParseIdentities(strings.NewReader(string(secret)))
		if err != nil {
			return err
		}
	}
	ciphertext, err := os.ReadFile(ciphertextPath)
	if err != nil {
		return err
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return err
	}
	encoded, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	metadata, payload, err := capsule.Decode(encoded)
	if err != nil {
		return err
	}
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Type          drop.PayloadType   `json:"type"`
		DisplayName   string             `json:"displayName"`
		ArchiveFormat drop.ArchiveFormat `json:"archiveFormat"`
		PlaintextSize uint64             `json:"plaintextSize"`
		PlaintextSHA  string             `json:"plaintextSHA256"`
	}{metadata.Type, metadata.DisplayName, metadata.ArchiveFormat, metadata.PlaintextSize, hex.EncodeToString(metadata.PlaintextSHA[:])})
}
