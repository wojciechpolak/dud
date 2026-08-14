// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

// interactiveMenuCase drives a keystroke sequence into the menu and states the
// argument vector the menu must hand to the command line.
type interactiveMenuCase struct {
	name     string
	input    string
	want     []string
	wantErr  string
	wantQuit bool
}

func runInteractiveMenuCase(t *testing.T, test interactiveMenuCase) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(test.input), &stdout, &stderr)
	reader := bufio.NewReader(a.in)
	a.in = reader
	args, err := a.interactiveCommand(reader)
	if test.wantQuit {
		if !errors.Is(err, errInteractiveQuit) {
			t.Fatalf("error = %v, want the quit sentinel", err)
		}
		if args != nil {
			t.Fatalf("quitting produced args %q", args)
		}
		return
	}
	if test.wantErr != "" {
		if err == nil || err.Error() != test.wantErr {
			t.Fatalf("error = %v, want %q", err, test.wantErr)
		}
		if args != nil {
			t.Fatalf("failed choice produced args %q", args)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v (stdout %q)", err, stdout.String())
	}
	if !slices.Equal(args, test.want) {
		t.Fatalf("args = %q, want %q", args, test.want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestInteractiveEncryptionAndDownloadCoverAllChoices(t *testing.T) {
	// The expected download arguments exercise the built-in default, not a
	// caller's DUD_BASE_URL override.
	t.Setenv("DUD_BASE_URL", "")

	for _, test := range []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{"1\n", nil, false}, {"2\nage1recipient\n", []string{"-r", "age1recipient"}, false}, {"3\n/tmp/recipients\n", []string{"-R", "/tmp/recipients"}, false},
		{"2\n\n", nil, true}, {"3\n\n", nil, true}, {"bad\n", nil, true},
	} {
		var stdout bytes.Buffer
		a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
		args, err := a.interactiveEncryptionArgs(bufio.NewReader(strings.NewReader(test.input)))
		if test.wantErr {
			if err == nil {
				t.Fatalf("encryption input %q unexpectedly succeeded", test.input)
			}
		} else if err != nil || !slices.Equal(args, test.want) {
			t.Fatalf("encryption input %q = %v, %v", test.input, args, err)
		}
	}
	for _, test := range []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{"\nid\n1\n/tmp/out\n\n", []string{"download", "--id", "id", "--url", v2DefaultBaseURL, "--out", "/tmp/out"}, false},
		{"\nid\n2\n\n", []string{"download", "--id", "id", "--url", v2DefaultBaseURL, "--stdout"}, false},
		{"\nid\n3\n/tmp/extract\n/tmp/key\n", []string{"download", "--id", "id", "--url", v2DefaultBaseURL, "--extract", "--out-dir", "/tmp/extract", "-i", "/tmp/key"}, false},
		{"\n\n", nil, true}, {"\nid\nbad\n", nil, true},
	} {
		a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		args, err := a.interactiveDownload(bufio.NewReader(strings.NewReader(test.input)))
		if test.wantErr {
			if err == nil {
				t.Fatalf("download input %q unexpectedly succeeded", test.input)
			}
		} else if err != nil || !slices.Equal(args, test.want) {
			t.Fatalf("download input %q = %v, %v", test.input, args, err)
		}
	}
}

func TestInteractiveKeygenCoversGenerateConvertAndValidation(t *testing.T) {
	for _, test := range []struct {
		input   string
		want    []string
		wantErr bool
	}{
		{"1\ny\n/tmp/identity\n/tmp/recipient\n", []string{"keygen", "--pq", "--out", "/tmp/identity", "-R", "/tmp/recipient"}, false},
		{"generate\n\n\n", []string{"keygen"}, false},
		{"2\n/tmp/identity\n/tmp/recipient\n", []string{"keygen", "-R", "/tmp/recipient", "/tmp/identity"}, false},
		{"convert\n\n", nil, true}, {"bad\n", nil, true},
	} {
		a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		args, err := a.interactiveKeygen(bufio.NewReader(strings.NewReader(test.input)))
		if test.wantErr {
			if err == nil {
				t.Fatalf("keygen input %q unexpectedly succeeded", test.input)
			}
		} else if err != nil || !slices.Equal(args, test.want) {
			t.Fatalf("keygen input %q = %v, %v", test.input, args, err)
		}
	}
}

func TestInteractiveStatusChoiceCoversDirectCommands(t *testing.T) {
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	for choice, want := range map[string][]string{"1": {"peer", "list"}, "doctor": {"doctor"}, "7": {"capabilities"}} {
		args, err := a.interactiveStatusChoice(bufio.NewReader(strings.NewReader("")), choice)
		if err != nil || !slices.Equal(args, want) {
			t.Fatalf("status %q = %v, %v", choice, args, err)
		}
	}
	if _, err := a.interactiveStatusChoice(bufio.NewReader(strings.NewReader("")), "bad"); err == nil {
		t.Fatal("invalid status choice accepted")
	}
}

func TestInteractiveStatusChoiceCoversPeerAndAllTargets(t *testing.T) {
	_, _ = newPairedV2TestPeer(t, "laptop")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	for _, test := range []struct {
		choice, input string
		want          []string
	}{
		{"show", "1\n", []string{"peer", "show", "laptop"}}, {"sync", "1\n", []string{"sync", "laptop"}}, {"sync", "2\n", []string{"sync"}},
		{"inbox", "1\n", []string{"inbox", "laptop"}}, {"inbox", "2\n", []string{"inbox"}}, {"git", "1\n", []string{"git", "status", "laptop"}}, {"git-status", "2\n", []string{"git", "status"}},
	} {
		args, err := a.interactiveStatusChoice(bufio.NewReader(strings.NewReader(test.input)), test.choice)
		if err != nil || !slices.Equal(args, test.want) {
			t.Fatalf("status %q = %v, %v", test.choice, args, err)
		}
	}
}

func TestInteractivePeersChoiceCoversEveryPeerAction(t *testing.T) {
	_, _ = newPairedV2TestPeer(t, "laptop")
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	for _, test := range []struct {
		choice, input string
		want          []string
	}{
		{"invite", "tablet\n", []string{"peer", "invite", "tablet"}}, {"accept", "tablet\n", []string{"peer", "accept", "tablet"}}, {"list", "", []string{"peer", "list"}},
		{"show", "1\n", []string{"peer", "show", "laptop"}}, {"rename", "1\ntablet\n", []string{"peer", "rename", "laptop", "tablet"}}, {"remove", "1\ny\n", []string{"peer", "remove", "laptop", "--yes"}}, {"revoke", "1\ny\n", []string{"peer", "revoke", "laptop", "--yes"}},
	} {
		args, err := a.interactivePeersChoice(bufio.NewReader(strings.NewReader(test.input)), test.choice)
		if err != nil || !slices.Equal(args, test.want) {
			t.Fatalf("peers %q = %v, %v", test.choice, args, err)
		}
	}
	for _, test := range []struct{ choice, input string }{{"invite", "\n"}, {"accept", "\n"}, {"rename", "1\n\n"}, {"remove", "1\nn\n"}, {"revoke", "1\nn\n"}, {"bad", ""}} {
		_, err := a.interactivePeersChoice(bufio.NewReader(strings.NewReader(test.input)), test.choice)
		if test.choice == "remove" || test.choice == "revoke" {
			if err != nil {
				t.Fatalf("cancelled %s = %v", test.choice, err)
			}
		} else if err == nil {
			t.Fatalf("peers %q unexpectedly succeeded", test.choice)
		}
	}
}

// The dead drop mode of every verb must stay reachable on a host that never
// initialized a V2 device, so these cases run against empty local state.
func TestInteractiveMenuDispatchesDeadDropModeWithoutPeerState(t *testing.T) {
	setTestV2Homes(t)
	tests := []interactiveMenuCase{
		{
			name:  "send falls back to the dead drop entry",
			input: "1\n\n\n3\n/tmp/payload.bin\n\n\n\n\n",
			want: []string{
				"upload", "--file", "/tmp/payload.bin",
				"--ttl", "24h", "--url", v2DefaultBaseURL,
			},
		},
		{
			name:  "receive falls back to the dead drop entry",
			input: "2\n\n\nabcd-ef01\n2\n\n",
			want: []string{
				"download", "--id", "abcd-ef01",
				"--url", v2DefaultBaseURL, "--stdout",
			},
		},
		{
			name:  "git push falls back to the dead drop entry",
			input: "3\n1\n\n\n\n\n\n\n",
			want:  []string{"git", "push", "--ttl", "24h", "--url", v2DefaultBaseURL},
		},
		{
			name:  "git fetch falls back to the dead drop entry",
			input: "3\n2\n\n\nabcd-ef01\n\n\n",
			want: []string{
				"git", "fetch", "--id", "abcd-ef01",
				"--url", v2DefaultBaseURL, "--remote", "dud",
			},
		},
		{
			name:  "the dead drop entry is selectable by its own number",
			input: "1\n1\n\n2\n\n\n\n",
			want:  []string{"upload", "--ttl", "24h", "--url", v2DefaultBaseURL},
		},
		{
			name:    "a peer target without local state stays a typed alias",
			input:   "1\nlaptop\n1\nhello\n\n\n\n",
			wantErr: "",
			want:    []string{"send", "laptop", "-m", "hello", "--ttl", "168h"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runInteractiveMenuCase(t, test) })
	}
}

// The peer mode of every verb selects its target from the picker, which lists
// the active peers of the initialized device.
func TestInteractiveMenuDispatchesPeerMode(t *testing.T) {
	setTestV2Homes(t)
	initializeInteractiveTestPeers(t)
	tests := []interactiveMenuCase{
		{
			name:  "send a message to the first listed peer",
			input: "1\n1\n1\nhello\n\n\n\n",
			want:  []string{"send", "laptop", "-m", "hello", "--ttl", "168h"},
		},
		{
			name:  "send repeated file collections with every send option",
			input: "1\n2\n3\n/tmp/one\n/tmp/two\n\nbundle\n12h\ny\n",
			want: []string{
				"send", "phone",
				"--file", "/tmp/one", "--file", "/tmp/two",
				"--name", "bundle", "--ttl", "12h", "--delete-after-read",
			},
		},
		{
			name:  "receive with every receive option",
			input: "2\nlaptop\n3\n/tmp/out\nn\n30s\n",
			want: []string{
				"receive", "laptop", "--out-dir", "/tmp/out",
				"--no-extract", "--wait", "30s", "--interactive",
			},
		},
		{
			name:  "receive into a single output file",
			input: "2\n2\n2\n/tmp/out.bin\n\n\n",
			want:  []string{"receive", "phone", "--out", "/tmp/out.bin", "--interactive"},
		},
		{
			name:  "peer git push of the current branch",
			input: "3\n1\n2\n2\n\n",
			want:  []string{"git", "push", "phone", "--current", "--ttl", "168h"},
		},
		{
			name:  "peer git push of selected branches",
			input: "3\n1\n1\n3\nmain\nrelease\n\n24h\n",
			want: []string{
				"git", "push", "laptop",
				"--branch", "main", "--branch", "release", "--ttl", "24h",
			},
		},
		{
			name:  "peer git fetch that associates and allows rewrites",
			input: "3\n2\n1\ny\ny\n",
			want:  []string{"git", "fetch", "laptop", "--associate", "--allow-rewrite"},
		},
		{
			name:  "peer git status for one peer",
			input: "3\n3\n2\n",
			want:  []string{"git", "status", "phone"},
		},
		{
			name:  "peer git status for all peers",
			input: "3\n3\n3\n",
			want:  []string{"git", "status"},
		},
		{
			name:  "peer invite",
			input: "4\n1\nfriend\n",
			want:  []string{"peer", "invite", "friend"},
		},
		{
			name:  "peer accept",
			input: "4\n2\nfriend\n",
			want:  []string{"peer", "accept", "friend"},
		},
		{
			name:  "peer list",
			input: "4\n3\n",
			want:  []string{"peer", "list"},
		},
		{
			name:  "peer show lists inactive peers too",
			input: "4\n4\n1\n",
			want:  []string{"peer", "show", "archive"},
		},
		{
			name:  "peer rename",
			input: "4\n5\n2\nworkstation\n",
			want:  []string{"peer", "rename", "laptop", "workstation"},
		},
		{
			name:  "peer remove requires confirmation",
			input: "4\n6\n2\ny\n",
			want:  []string{"peer", "remove", "laptop", "--yes"},
		},
		{
			name:  "declined peer removal dispatches nothing",
			input: "4\n6\n2\n\n",
			want:  nil,
		},
		{
			name:  "peer revoke requires confirmation",
			input: "4\n7\n3\ny\n",
			want:  []string{"peer", "revoke", "phone", "--yes"},
		},
		{
			name:  "status synchronizes one peer",
			input: "5\n3\n2\n",
			want:  []string{"sync", "phone"},
		},
		{
			name:  "status synchronizes every peer",
			input: "5\n3\n3\n",
			want:  []string{"sync"},
		},
		{
			name:  "status previews one peer inbox",
			input: "5\n4\n1\n",
			want:  []string{"inbox", "laptop"},
		},
		{
			name:  "status previews every peer inbox",
			input: "5\n4\n3\n",
			want:  []string{"inbox"},
		},
		{
			name:  "status reports git synchronization",
			input: "5\n5\n1\n",
			want:  []string{"git", "status", "laptop"},
		},
		{
			name:  "status runs the transport doctor",
			input: "5\n6\n",
			want:  []string{"doctor"},
		},
		{
			name:  "status reads server capabilities",
			input: "5\n7\n",
			want:  []string{"capabilities"},
		},
		{
			name:  "setup initializes a device",
			input: "6\n1\ndesktop\n\n\n\n",
			want: []string{
				"init", "--device", "desktop",
				"--url", v2DefaultBaseURL,
				"--doh-url", v2DefaultDOHURL,
				"--ech-mode", v2DefaultECHMode,
			},
		},
		{
			name:  "setup shows the configuration",
			input: "6\n2\n",
			want:  []string{"config", "show"},
		},
		{
			name:  "setup validates the configuration",
			input: "6\n3\n",
			want:  []string{"config", "validate"},
		},
		{
			name:  "setup migrates the configuration",
			input: "6\n4\n",
			want:  []string{"migrate"},
		},
		{
			name:  "erase defaults to a dry run",
			input: "6\n5\n1\n\n",
			want:  []string{"erase", "pairings", "--dry-run"},
		},
		{
			name:  "erase of one peer can be confirmed",
			input: "6\n5\n2\n2\nn\ny\n",
			want:  []string{"erase", "peer", "laptop", "--yes"},
		},
		{
			name:  "erase of all state can include the repository",
			input: "6\n5\n4\ny\nn\ny\n",
			want:  []string{"erase", "all", "--repo", "--yes"},
		},
		{
			name:  "declined erase dispatches nothing",
			input: "6\n5\n3\nn\n\n",
			want:  nil,
		},
		{
			name:  "tools run the transport test",
			input: "7\n1\n\n",
			want:  []string{"test", "--url", v2DefaultBaseURL + "/v1/test"},
		},
		{
			name:  "tools generate a post-quantum identity",
			input: "7\n2\n1\ny\n\n",
			want:  []string{"keygen", "--pq"},
		},
		{
			name:  "tools convert an identity to recipients",
			input: "7\n2\n2\n/tmp/key.txt\n/tmp/recipients.txt\n",
			want:  []string{"keygen", "-R", "/tmp/recipients.txt", "/tmp/key.txt"},
		},
		{
			name:  "tools flush expired drop files",
			input: "7\n3\ny\n",
			want:  []string{"flush"},
		},
		{
			name:  "declined flush dispatches nothing",
			input: "7\n3\n\n",
			want:  nil,
		},
		{
			name:  "back returns to the top level without dispatching",
			input: "3\nb\n",
			want:  nil,
		},
		{
			name:    "a number outside the picker is not treated as an alias",
			input:   "1\n9\n",
			wantErr: "Unknown target: 9",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runInteractiveMenuCase(t, test) })
	}
}

// Both send paths offer the same three payload sources in the same positions,
// so the source a transfer carries never depends on the target that selected it.
func TestInteractiveMenuSharesOnePayloadStepAcrossBothSendPaths(t *testing.T) {
	setTestV2Homes(t)
	initializeInteractiveTestPeers(t)
	tests := []interactiveMenuCase{
		{
			name:  "a peer takes a short message",
			input: "1\n1\n1\nhello\n\n\n\n",
			want:  []string{"send", "laptop", "-m", "hello", "--ttl", "168h"},
		},
		{
			name:  "a dead drop takes a short message",
			input: "1\n3\n\n1\nhello\n\n\n\n",
			want: []string{
				"upload", "-m", "hello", "--ttl", "24h", "--url", v2DefaultBaseURL,
			},
		},
		{
			// The peer path names the terminal explicitly; the drop path reads
			// it whenever no source option is present, so it adds no argument.
			name:  "a peer takes long text from this terminal",
			input: "1\n1\n2\n\n\n\n",
			want:  []string{"send", "laptop", "--stdin", "--ttl", "168h"},
		},
		{
			name:  "a dead drop takes long text from this terminal",
			input: "1\n3\n\n2\n\n\n\n",
			want:  []string{"upload", "--ttl", "24h", "--url", v2DefaultBaseURL},
		},
		{
			name:  "a peer takes repeated paths",
			input: "1\n1\n3\n/tmp/one\n/tmp/two\n\n\n\n\n",
			want: []string{
				"send", "laptop", "--file", "/tmp/one", "--file", "/tmp/two",
				"--ttl", "168h",
			},
		},
		{
			name:  "a dead drop takes repeated paths",
			input: "1\n3\n\n3\n/tmp/one\n/tmp/two\n\n\n\n\n",
			want: []string{
				"upload", "--file", "/tmp/one", "--file", "/tmp/two",
				"--ttl", "24h", "--url", v2DefaultBaseURL,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runInteractiveMenuCase(t, test) })
	}
}

// Back leaves one step, so a wrong turn costs the step that made it rather than
// the whole session. Each case walks in, backs out, and then completes a
// different branch from the step it landed on.
func TestInteractiveMenuBackReturnsToThePreviousStep(t *testing.T) {
	setTestV2Homes(t)
	initializeInteractiveTestPeers(t)
	tests := []interactiveMenuCase{
		{
			name:  "back at the payload step returns to the send target",
			input: "1\n1\nb\n2\n1\nhello\n\n\n\n",
			want:  []string{"send", "phone", "-m", "hello", "--ttl", "168h"},
		},
		{
			name:  "back at the send target returns to the top level",
			input: "1\nb\n",
			want:  nil,
		},
		{
			name:  "back at the receive output step returns to the receive target",
			input: "2\n1\nb\n2\n1\n\n\n",
			want:  []string{"receive", "phone", "--interactive"},
		},
		{
			name:  "back at the push scope returns to the push target",
			input: "3\n1\n1\nb\n2\n2\n\n",
			want:  []string{"git", "push", "phone", "--current", "--ttl", "168h"},
		},
		{
			name:  "back at the push target returns to the git mode",
			input: "3\n1\nb\n3\n3\n",
			want:  []string{"git", "status"},
		},
		{
			name:  "back at the encryption step returns to the payload step",
			input: "1\n3\n\n1\nhello\nb\n1\nagain\n\n\n\n",
			want: []string{
				"upload", "-m", "again", "--ttl", "24h", "--url", v2DefaultBaseURL,
			},
		},
		{
			name:  "back at a peer picker returns to the peers menu",
			input: "4\n4\nb\n3\n",
			want:  []string{"peer", "list"},
		},
		{
			name:  "back at the erase scope returns to the setup menu",
			input: "6\n5\nb\n2\n",
			want:  []string{"config", "show"},
		},
		{
			name:  "back at the keygen mode returns to the tools menu",
			input: "7\n2\nb\n1\n\n",
			want:  []string{"test", "--url", v2DefaultBaseURL + "/v1/test"},
		},
		{
			name:     "quit inside a nested step leaves the menu",
			input:    "1\n1\nq\n",
			wantQuit: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runInteractiveMenuCase(t, test) })
	}
}

// The dead drop words stay accepted at the top level and keep reaching the same
// operations with the same prompts, whatever position they hold in the menu.
func TestInteractiveMenuKeepsDropWordsAtTheTopLevel(t *testing.T) {
	setTestV2Homes(t)
	tests := []interactiveMenuCase{
		{
			name:  "test",
			input: "test\n\n",
			want:  []string{"test", "--url", v2DefaultBaseURL + "/v1/test"},
		},
		{
			name:  "upload",
			input: "upload\n\n1\nhello\n\n\n\n",
			want: []string{
				"upload", "-m", "hello", "--ttl", "24h", "--url", v2DefaultBaseURL,
			},
		},
		{
			name:  "download",
			input: "download\n\nabcd-ef01\n2\n\n",
			want: []string{
				"download", "--id", "abcd-ef01", "--url", v2DefaultBaseURL, "--stdout",
			},
		},
		{
			name:  "keygen",
			input: "keygen\n1\n\n\n",
			want:  []string{"keygen"},
		},
		{
			name:  "flush",
			input: "flush\ny\n",
			want:  []string{"flush"},
		},
		{
			name:  "git",
			input: "git\n2\n\n\nabcd-ef01\n\nmirror\n",
			want: []string{
				"git", "fetch", "--id", "abcd-ef01",
				"--url", v2DefaultBaseURL, "--remote", "mirror",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runInteractiveMenuCase(t, test) })
	}
}

func TestInteractiveMenuRejectsUnknownChoicesAndEndsQuietly(t *testing.T) {
	setTestV2Homes(t)
	tests := []interactiveMenuCase{
		{
			name:    "unknown top-level choice",
			input:   "bogus\n",
			wantErr: "Unknown choice: bogus",
		},
		{
			name:    "unknown git mode",
			input:   "3\nbogus\n",
			wantErr: "Unknown git mode: bogus",
		},
		{
			name:    "unknown peers choice",
			input:   "4\nbogus\n",
			wantErr: "Unknown peers choice: bogus",
		},
		{
			name:    "unknown status choice",
			input:   "5\nbogus\n",
			wantErr: "Unknown status choice: bogus",
		},
		{
			name:    "unknown setup choice",
			input:   "6\nbogus\n",
			wantErr: "Unknown setup choice: bogus",
		},
		{
			name:    "unknown tools choice",
			input:   "7\nbogus\n",
			wantErr: "Unknown tools choice: bogus",
		},
		{
			name:    "unknown payload source",
			input:   "1\nlaptop\nbogus\n",
			wantErr: "Unknown payload: bogus",
		},
		{
			name:    "an invalid typed alias is rejected before dispatch",
			input:   "1\nnot a peer\n",
			wantErr: `peer alias "not a peer" contains an unsupported character`,
		},
		{
			name:     "end of input at the top level quits",
			input:    "",
			wantQuit: true,
		},
		{
			name:     "end of input inside a verb quits",
			input:    "5\n",
			wantQuit: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { runInteractiveMenuCase(t, test) })
	}
}

// The menu stays up between commands, so one session can run several of them.
func TestInteractiveMenuReturnsToTheTopLevelAfterEachCommand(t *testing.T) {
	setTestV2Homes(t)
	initializeInteractiveTestPeers(t)
	var stdout, stderr bytes.Buffer
	// Two peer listings, a cancelled flush, a trip into git and back, then quit.
	a := newApp(strings.NewReader("4\n3\n5\n1\n7\n3\n\n3\nb\nq\n"), &stdout, &stderr)
	if err := a.interactiveMenu(); err != nil {
		t.Fatalf("interactive menu returned %v (stderr %q)", err, stderr.String())
	}
	if listings := strings.Count(stdout.String(), "laptop   ACTIVE"); listings != 2 {
		t.Fatalf("peer listings = %d, want 2: %q", listings, stdout.String())
	}
	// One banner per top-level prompt: the four choices above plus the quit.
	if banners := strings.Count(stdout.String(), "dud — Discreet Upload/Download"); banners != 5 {
		t.Fatalf("menu renders = %d, want 5: %q", banners, stdout.String())
	}
	if !strings.Contains(stdout.String(), "Cancelled.") {
		t.Fatalf("declined flush left no trace: %q", stdout.String())
	}
}

// A failing command still ends the session with its own status, so a scripted
// run cannot lose a failure in a redrawn menu.
func TestInteractiveMenuStopsOnCommandFailure(t *testing.T) {
	setTestV2Homes(t)
	t.Setenv("DUD_TEST_STDIN_TTY", "1")
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader("5\n1\n4\n3\nq\n"), &stdout, &stderr)
	if code := a.main(nil); code != 1 {
		t.Fatalf("main returned %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "not initialized") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if banners := strings.Count(stdout.String(), "dud — Discreet Upload/Download"); banners != 1 {
		t.Fatalf("menu renders = %d, want 1: %q", banners, stdout.String())
	}
}

func initializeInteractiveTestPeers(t *testing.T) {
	t.Helper()
	if _, _, err := initializeV2Config(
		"desktop",
		v2DefaultBaseURL,
		v2DefaultDOHURL,
		v2DefaultECHMode,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers["laptop"] = v2PeerProfile{Status: "active", BaseURL: cfg.BaseURL}
		cfg.Peers["phone"] = v2PeerProfile{Status: "active", BaseURL: cfg.BaseURL}
		cfg.Peers["archive"] = v2PeerProfile{Status: "unpaired", BaseURL: cfg.BaseURL}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
