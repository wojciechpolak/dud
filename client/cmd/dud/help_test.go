// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type unreadableHelpInput struct{ t *testing.T }

func (input unreadableHelpInput) Read([]byte) (int, error) {
	input.t.Error("help read stdin")
	return 0, io.EOF
}

func TestCommandHelpWorksOfflineForEveryTopic(t *testing.T) {
	root := filepath.Join(t.TempDir(), "uninitialized")
	t.Setenv("DUD_HOME", root)
	t.Setenv("DUD_PROFILE", "invalid/profile")
	t.Setenv("DUD_CONNECT_TO", "invalid")
	for path, topic := range commandHelpTopics {
		t.Run(path, func(t *testing.T) {
			for _, flag := range []string{"--help", "-h"} {
				var stdout, stderr bytes.Buffer
				a := newApp(unreadableHelpInput{t}, &stdout, &stderr)
				a.cfg.GitBin, a.cfg.AgeBin, a.cfg.AgeKeygenBin = "missing-git", "missing-age", "missing-keygen"
				a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
					t.Fatal("help opened a transport")
					return nil, nil
				}
				args := append(strings.Fields(path), flag)
				if code := a.main(args); code != 0 || stderr.Len() != 0 {
					t.Fatalf("%v: code %d, stderr %q", args, code, stderr.String())
				}
				for _, fragment := range []string{topic.description, "Usage\n", "Options\n", "Example\n", topic.example} {
					if !strings.Contains(stdout.String(), fragment) {
						t.Fatalf("%v omitted %q: %s", args, fragment, stdout.String())
					}
				}
				if len(helpUsage(path)) == 0 {
					t.Fatalf("%s has no usage", path)
				}
				for _, option := range strings.Fields(topic.options) {
					if _, ok := helpOptions[option]; !ok {
						t.Fatalf("unknown option %s", option)
					}
				}
			}
		})
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("help initialized state: %v", err)
	}
}

func TestCommandHelpFormsAndAliasesSelectTheSameTopic(t *testing.T) {
	for _, group := range [][]string{
		{"git --help", "git -h", "git help", "help git"},
		{"peer --help", "peer help", "help peer"},
		{"git push --help", "help git push", "git help push", "git send --help", "help git send", "git push laptop --current --help"},
		{"git fetch --help", "git receive -h", "git help receive", "git fetch laptop --help"},
		{"peer reset --help", "peer help reset", "help peer reset", "peer reset laptop --yes --help"},
		{"config show --help", "config help show", "help config show"},
		{"erase peer --help", "help erase peer", "erase peer laptop --yes --help"},
		{"version --help", "--version --help"},
	} {
		var expected string
		for index, command := range group {
			var stdout, stderr bytes.Buffer
			a := newApp(unreadableHelpInput{t}, &stdout, &stderr)
			if code := a.main(strings.Fields(command)); code != 0 {
				t.Fatalf("%s: %s", command, stderr.String())
			}
			if index == 0 {
				expected = stdout.String()
			}
			if stdout.String() != expected {
				t.Fatalf("%s selects different help", command)
			}
		}
	}
}

func TestCommandHelpPreservesOptionValuesAndPositionalAliases(t *testing.T) {
	for _, path := range []string{"send", "upload", "receive", "download", "git push", "git fetch", "peer show", "keygen", "init"} {
		topic := commandHelpTopics[path]
		for _, option := range strings.Fields(topic.options) {
			if helpOptions[option].value == "" {
				continue
			}
			for _, value := range []string{"help", "--help", "-h"} {
				args := append(strings.Fields(path), option, value)
				a := newApp(unreadableHelpInput{t}, &bytes.Buffer{}, &bytes.Buffer{})
				if handled, err := a.commandHelp(args); handled || err != nil {
					t.Fatalf("help consumed value in %v", args)
				}
				args = append(args, "--help")
				if handled, err := a.commandHelp(args); !handled || err != nil {
					t.Fatalf("help flag after value in %v: %v", args, err)
				}
			}
		}
	}
	for _, command := range []string{"send help -m hello", "receive help", "peer show help", "peer rename help other", "erase peer help --yes", "git push help", "send laptop -m --help", "send laptop --message help", "upload -m help", "keygen help", "send laptop -- --help"} {
		a := newApp(unreadableHelpInput{t}, &bytes.Buffer{}, &bytes.Buffer{})
		if handled, err := a.commandHelp(strings.Fields(command)); handled || err != nil {
			t.Fatalf("help consumed data in %s", command)
		}
	}
}

func TestUnknownHelpTopicPointsToItsGroup(t *testing.T) {
	for _, test := range []struct{ command, hint string }{
		{"help unknown", "dud help"}, {"help git unknown", "dud help git"},
		{"peer help unknown", "dud help peer"}, {"peer unknown --help", "dud help peer"},
		{"help erase unknown", "dud help erase"}, {"help git push unknown", "dud help git"},
	} {
		var stdout, stderr bytes.Buffer
		a := newApp(unreadableHelpInput{t}, &stdout, &stderr)
		if code := a.main(strings.Fields(test.command)); code != 1 || stdout.Len() != 0 ||
			!strings.Contains(stderr.String(), "Unknown help topic") || !strings.Contains(stderr.String(), test.hint) {
			t.Fatalf("%s: stdout %q, stderr %q", test.command, stdout.String(), stderr.String())
		}
	}
}

func TestGroupHelpListsOnlyRelevantCommands(t *testing.T) {
	for _, test := range []struct{ path, present, absent string }{
		{"git", "push", "enrollment-key"}, {"peer", "enrollment-key", "git push"},
		{"config", "validate", "enrollment-key"}, {"erase", "pairings", "enrollment-key"},
	} {
		var stdout bytes.Buffer
		a := newApp(unreadableHelpInput{t}, &stdout, &bytes.Buffer{})
		if err := a.run([]string{test.path, "help"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "Subcommands\n") || !strings.Contains(stdout.String(), test.present) || strings.Contains(stdout.String(), test.absent) {
			t.Fatalf("%s help = %s", test.path, stdout.String())
		}
	}
}
