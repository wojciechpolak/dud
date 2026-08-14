// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bufio"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// errInteractiveQuit ends the menu loop without reporting a failure. It never
// reaches main, so quitting keeps the successful exit status.
var errInteractiveQuit = errors.New("interactive quit")

// errInteractiveBack returns to the previous step instead of dispatching. Every
// prompt below the top level offers it, so no step is a dead end that only
// Ctrl-C can leave. The step that receives it re-renders itself, and the first
// step of a verb propagates it to the top level, which redraws.
var errInteractiveBack = errors.New("interactive back")

// The interactive menu is organized around verbs, not protocol versions. Each
// verb collects a command line and hands it to a.run, so the menu selects the
// transfer mode exactly the way the argument rules in main.go and git.go do: a
// positional peer alias selects peer transfer, a leading flag selects the dead
// drop transfer.
//
// The menu stays up: a command that completes returns to the top level, and
// only an explicit quit or end of input leaves it. A command or prompt that
// fails still ends the menu with its own exit status, so a scripted run cannot
// lose a failure in a redrawn menu.
func (a *app) interactiveMenu() error {
	r := bufio.NewReader(a.in)
	a.in = r
	for {
		args, err := a.interactiveCommand(r)
		if errors.Is(err, errInteractiveQuit) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(args) == 0 {
			continue
		}
		// Separate the command's own output from the prompts that selected it.
		fmt.Fprintln(a.out)
		if err := a.run(args); err != nil {
			return err
		}
	}
}

// interactiveCommand renders the top level and returns the argument vector the
// selected verb resolved to. An empty vector means "nothing to run this time",
// which is how going back and declined confirmations return to the menu.
func (a *app) interactiveCommand(r *bufio.Reader) ([]string, error) {
	fmt.Fprint(a.out, "\ndud — Discreet Upload/Download\n\n")
	fmt.Fprintln(a.out, "  1) send")
	fmt.Fprintln(a.out, "  2) receive")
	fmt.Fprintln(a.out, "  3) git")
	fmt.Fprintln(a.out, "  4) peers")
	fmt.Fprintln(a.out, "  5) status")
	fmt.Fprintln(a.out, "  6) setup")
	fmt.Fprintln(a.out, "  7) tools")
	fmt.Fprintln(a.out, "  q) quit")
	fmt.Fprint(a.out, "\nChoice: ")
	choice, ok := readLineOK(r)
	if !ok {
		return nil, errInteractiveQuit
	}
	args, err := a.interactiveVerb(r, choice)
	// Back at a verb's first step has no earlier step to return to, so it lands
	// here and the caller redraws the top level.
	if errors.Is(err, errInteractiveBack) {
		return nil, nil
	}
	return args, err
}

func (a *app) interactiveVerb(r *bufio.Reader, choice string) ([]string, error) {
	switch choice {
	case "1", "send":
		return a.interactiveSend(r)
	case "2", "receive":
		return a.interactiveReceive(r)
	case "3", "git":
		return a.interactiveGit(r)
	case "4", "peer", "peers":
		return a.interactivePeers(r)
	case "5", "status":
		return a.interactiveStatus(r)
	case "6", "setup":
		return a.interactiveSetup(r)
	case "7", "tools":
		return a.interactiveTools(r)
	// The dead drop words stay accepted at the top level and keep leading
	// straight to the operation they have always named.
	case "test":
		return a.interactiveTest(r)
	case "upload":
		return a.interactiveUpload(r)
	case "download":
		return a.interactiveDownload(r)
	case "keygen":
		return a.interactiveKeygen(r)
	case "flush":
		return a.interactiveFlush(r)
	case "q", "quit":
		return nil, errInteractiveQuit
	default:
		return nil, fatalError("Unknown choice: " + choice)
	}
}

// readMenuChoice renders the two entries every prompt below the top level
// shares and reads the selection. fallback is the entry an empty line selects;
// an empty fallback leaves the choice to the caller's own switch, which reports
// it as unknown.
func (a *app) readMenuChoice(r *bufio.Reader, fallback string) (string, error) {
	fmt.Fprintln(a.out, "  b) back")
	fmt.Fprintln(a.out, "  q) quit")
	if fallback == "" {
		fmt.Fprint(a.out, "Choice: ")
	} else {
		fmt.Fprintf(a.out, "Choice [%s]: ", fallback)
	}
	choice, ok := readLineOK(r)
	if !ok {
		return "", errInteractiveQuit
	}
	switch choice {
	case "b", "back":
		return "", errInteractiveBack
	case "q", "quit":
		return "", errInteractiveQuit
	case "":
		return fallback, nil
	}
	return choice, nil
}

// interactiveStep runs one menu: render draws the entries, and resolve turns
// the selection into a command. Going back inside a later step re-renders this
// menu, and going back at this menu returns to the caller's own step.
func (a *app) interactiveStep(
	r *bufio.Reader,
	fallback string,
	render func(),
	resolve func(string) ([]string, error),
) ([]string, error) {
	for {
		render()
		choice, err := a.readMenuChoice(r, fallback)
		if err != nil {
			return nil, err
		}
		args, err := resolve(choice)
		if errors.Is(err, errInteractiveBack) {
			continue
		}
		return args, err
	}
}

// peerPicker describes a numbered target step. extraLabel names the single
// non-peer entry a verb offers, which is the dead drop path for the transfer
// verbs and "all peers" for the reporting verbs. The entry is a numbered
// position rather than a reserved alias, so a peer named "drop" or "all" stays
// reachable.
type peerPicker struct {
	title      string
	extraLabel string
	includeAll bool
}

// choosePeer renders the target step and reports the selected peer alias, or
// extra=true when the trailing non-peer entry was selected. Typing an alias
// outright stays a shortcut.
func (a *app) choosePeer(r *bufio.Reader, picker peerPicker) (string, bool, error) {
	aliases, unavailable := interactivePeerAliases(picker.includeAll)
	fmt.Fprintln(a.out, picker.title)
	for index, alias := range aliases {
		fmt.Fprintf(a.out, "  %d) %s\n", index+1, alias)
	}
	entries := len(aliases)
	if picker.extraLabel != "" {
		entries++
		fmt.Fprintf(a.out, "  %d) %s\n", entries, picker.extraLabel)
	}
	if len(aliases) == 0 {
		fmt.Fprintf(a.out, "No peers available (%s); use setup to initialize this device and peers to pair one.\n", unavailable)
	}
	// With nothing listed the only selection left is a typed alias, so the
	// prompt requires one rather than defaulting to an entry that is not there.
	fallback := "1"
	if entries == 0 {
		fallback = ""
	}
	choice, err := a.readMenuChoice(r, fallback)
	if err != nil {
		return "", false, err
	}
	if choice == "" {
		return "", false, fatalError("peer alias required")
	}
	// A numbered list always selects by position, so a mistyped number fails
	// here instead of reaching a command as an alias that cannot exist. Every
	// peer the picker knows about is listed, so a peer whose alias is a number
	// stays selectable by its position.
	if index, err := strconv.Atoi(choice); err == nil && entries != 0 {
		if index >= 1 && index <= len(aliases) {
			return aliases[index-1], false, nil
		}
		if picker.extraLabel != "" && index == entries {
			return "", true, nil
		}
		return "", false, fatalError("Unknown target: " + choice)
	}
	if err := validateV2PeerAlias(choice); err != nil {
		return "", false, err
	}
	return choice, false, nil
}

// interactivePeerAliases lists the peers the menu can address. A device that is
// not initialized is not an error here: the caller degrades to its dead drop
// entry and points at setup instead of failing inside a command that assumed
// initialization.
func interactivePeerAliases(includeAll bool) ([]string, string) {
	cfg, _, err := loadV2Config()
	if err != nil {
		return nil, err.Error()
	}
	aliases := make([]string, 0, len(cfg.Peers))
	for alias, peer := range cfg.Peers {
		if includeAll || peer.Status == "active" {
			aliases = append(aliases, alias)
		}
	}
	if len(aliases) == 0 {
		return nil, "no paired peers"
	}
	sort.Strings(aliases)
	return aliases, ""
}

// chooseTransfer runs the target step and then the step the selected target
// needs. Going back inside that second step returns to the picker, and going
// back at the picker returns to the caller's own step.
func (a *app) chooseTransfer(
	r *bufio.Reader,
	picker peerPicker,
	drop func(*bufio.Reader) ([]string, error),
	peer func(*bufio.Reader, string) ([]string, error),
) ([]string, error) {
	for {
		alias, extra, err := a.choosePeer(r, picker)
		if err != nil {
			return nil, err
		}
		var args []string
		if extra {
			args, err = drop(r)
		} else {
			args, err = peer(r, alias)
		}
		if errors.Is(err, errInteractiveBack) {
			continue
		}
		return args, err
	}
}

func (a *app) interactiveSend(r *bufio.Reader) ([]string, error) {
	return a.chooseTransfer(
		r,
		peerPicker{title: "Send to:", extraLabel: "dead drop — share by ID"},
		a.interactiveUpload,
		a.interactivePeerSend,
	)
}

func (a *app) interactiveReceive(r *bufio.Reader) ([]string, error) {
	return a.chooseTransfer(
		r,
		peerPicker{title: "Receive from:", extraLabel: "dead drop — share by ID"},
		a.interactiveDownload,
		a.interactivePeerReceive,
	)
}

// interactivePayload is the one payload step both send paths use, so choosing a
// peer or a dead drop never changes what can be sent. stdinFlag names the
// option that makes the command read this terminal to end of input; the drop
// upload reads it whenever no source option is present, so it passes "".
func (a *app) interactivePayload(r *bufio.Reader, stdinFlag string) ([]string, error) {
	fmt.Fprintln(a.out, "Payload:")
	fmt.Fprintln(a.out, "  1) short message (one line)")
	fmt.Fprintln(a.out, "  2) long text (typed or pasted, Ctrl-D to finish)")
	fmt.Fprintln(a.out, "  3) files or directories")
	choice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
	}
	switch choice {
	case "1", "message":
		fmt.Fprint(a.out, "Message: ")
		message := readLine(r)
		if message == "" {
			return nil, fatalError("message required")
		}
		return []string{"-m", message}, nil
	case "2", "text", "stdin":
		if stdinFlag == "" {
			return nil, nil
		}
		return []string{stdinFlag}, nil
	case "3", "file", "files":
		var args []string
		for {
			fmt.Fprint(a.out, "File or directory path (blank to finish): ")
			path := readLine(r)
			if path == "" {
				break
			}
			args = append(args, "--file", absPathIfRelative(path))
		}
		if len(args) == 0 {
			return nil, fatalError("file path required")
		}
		return args, nil
	default:
		return nil, fatalError("Unknown payload: " + choice)
	}
}

func (a *app) interactivePeerSend(r *bufio.Reader, alias string) ([]string, error) {
	payload, err := a.interactivePayload(r, "--stdin")
	if err != nil {
		return nil, err
	}
	args := append([]string{"send", alias}, payload...)
	fmt.Fprint(a.out, "Display name (leave empty for the default): ")
	if name := readLine(r); name != "" {
		args = append(args, "--name", name)
	}
	fmt.Fprint(a.out, "TTL [168h]: ")
	ttl := readLine(r)
	if ttl == "" {
		ttl = "168h"
	}
	args = append(args, "--ttl", ttl)
	fmt.Fprint(a.out, "Delete after read? [y/N]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		args = append(args, "--delete-after-read")
	}
	return args, nil
}

func (a *app) interactivePeerReceive(r *bufio.Reader, alias string) ([]string, error) {
	args := []string{"receive", alias}
	fmt.Fprintln(a.out, "Receive output:")
	fmt.Fprintln(a.out, "  1) automatic")
	fmt.Fprintln(a.out, "  2) single output file")
	fmt.Fprintln(a.out, "  3) output directory")
	choice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
	}
	switch choice {
	case "1", "automatic":
	case "2", "file", "out":
		fmt.Fprint(a.out, "Output path: ")
		out := readLine(r)
		if out == "" {
			return nil, fatalError("output path required")
		}
		args = append(args, "--out", absPathIfRelative(out))
	case "3", "dir", "out-dir":
		fmt.Fprint(a.out, "Output directory: ")
		outDir := readLine(r)
		if outDir == "" {
			return nil, fatalError("output directory required")
		}
		args = append(args, "--out-dir", absPathIfRelative(outDir))
	default:
		return nil, fatalError("Unknown receive output: " + choice)
	}
	fmt.Fprint(a.out, "Extract received collections? [Y/n]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "n") {
		args = append(args, "--no-extract")
	}
	fmt.Fprint(a.out, "Wait for a delivery (duration, blank for none): ")
	if wait := readLine(r); wait != "" {
		args = append(args, "--wait", wait)
	}
	// --interactive drives the verified collection confirmation, which reads
	// the same buffered reader this menu installed on a.in.
	return append(args, "--interactive"), nil
}

func readLine(r *bufio.Reader) string {
	line, _ := readLineOK(r)
	return line
}

// readLineOK reports ok=false only when input ended before any characters of
// the line were read, which lets the top level exit quietly at end of input
// instead of reporting an empty choice as unknown.
func readLineOK(r *bufio.Reader) (string, bool) {
	line, err := r.ReadString('\n')
	value := strings.TrimRight(line, "\r\n")
	if err != nil && value == "" {
		return "", false
	}
	return value, true
}

func (a *app) interactiveTest(r *bufio.Reader) ([]string, error) {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	return []string{"test", "--url", serverURL + "/v1/test"}, nil
}

func (a *app) interactiveUpload(r *bufio.Reader) ([]string, error) {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	// The drop upload reads this terminal whenever no source option is present,
	// so its long-text entry contributes no argument.
	for {
		payload, err := a.interactivePayload(r, "")
		if err != nil {
			return nil, err
		}
		encryptionArgs, err := a.interactiveEncryptionArgs(r)
		if errors.Is(err, errInteractiveBack) {
			continue
		}
		if err != nil {
			return nil, err
		}
		fmt.Fprint(a.out, "TTL [24h]: ")
		ttl := readLine(r)
		if ttl == "" {
			ttl = "24h"
		}
		fmt.Fprint(a.out, "Delete after read? [y/N]: ")
		ans := readLine(r)
		args := append([]string{"upload"}, payload...)
		args = append(args, "--ttl", ttl, "--url", serverURL)
		if strings.HasPrefix(strings.ToLower(ans), "y") {
			args = append(args, "--delete-after-read")
		}
		return append(args, encryptionArgs...), nil
	}
}

func (a *app) interactiveEncryptionArgs(r *bufio.Reader) ([]string, error) {
	fmt.Fprintln(a.out, "Encryption mode:")
	fmt.Fprintln(a.out, "  1) passphrase")
	fmt.Fprintln(a.out, "  2) recipient string")
	fmt.Fprintln(a.out, "  3) recipient file")
	choice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
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

func (a *app) interactiveDownload(r *bufio.Reader) ([]string, error) {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	fmt.Fprint(a.out, "File ID: ")
	id := readLine(r)
	if id == "" {
		return nil, fatalError("file ID required")
	}
	fmt.Fprintln(a.out, "Download output:")
	fmt.Fprintln(a.out, "  1) file path")
	fmt.Fprintln(a.out, "  2) stdout")
	fmt.Fprintln(a.out, "  3) extract bundle")
	outputChoice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
	}
	args := []string{"--id", id, "--url", serverURL}
	switch outputChoice {
	case "1", "file":
		fmt.Fprint(a.out, "Output path: ")
		out := readLine(r)
		if out == "" {
			return nil, fatalError("output path required")
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
		return nil, fatalError("Unknown download output: " + outputChoice)
	}
	fmt.Fprint(a.out, "Identity file (leave empty if not needed): ")
	identity := readLine(r)
	if identity != "" {
		args = append(args, "-i", absPathIfRelative(identity))
	}
	return append([]string{"download"}, args...), nil
}

func (a *app) interactiveGit(r *bufio.Reader) ([]string, error) {
	return a.interactiveStep(r, "1", func() {
		fmt.Fprintln(a.out, "Git mode:")
		fmt.Fprintln(a.out, "  1) push")
		fmt.Fprintln(a.out, "  2) fetch")
		fmt.Fprintln(a.out, "  3) status")
	}, func(choice string) ([]string, error) {
		switch choice {
		case "1", "push", "send":
			return a.chooseTransfer(
				r,
				peerPicker{title: "Push to:", extraLabel: "dead drop — share by ID"},
				a.interactiveGitPush,
				a.interactivePeerGitPush,
			)
		case "2", "fetch", "receive":
			return a.chooseTransfer(
				r,
				peerPicker{title: "Fetch from:", extraLabel: "dead drop — share by ID"},
				a.interactiveGitFetch,
				a.interactivePeerGitFetch,
			)
		case "3", "status":
			alias, all, err := a.choosePeer(r, peerPicker{title: "Git status for:", extraLabel: "all peers"})
			if err != nil {
				return nil, err
			}
			if all {
				return []string{"git", "status"}, nil
			}
			return []string{"git", "status", alias}, nil
		default:
			return nil, fatalError("Unknown git mode: " + choice)
		}
	})
}

func (a *app) interactiveGitPush(r *bufio.Reader) ([]string, error) {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	encryptionArgs, err := a.interactiveEncryptionArgs(r)
	if err != nil {
		return nil, err
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
	return append([]string{"git", "push"}, args...), nil
}

func (a *app) interactiveGitFetch(r *bufio.Reader) ([]string, error) {
	fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
	serverURL := readLine(r)
	if serverURL == "" {
		serverURL = a.cfg.BaseURL
	}
	fmt.Fprint(a.out, "File ID: ")
	id := readLine(r)
	if id == "" {
		return nil, fatalError("file ID required")
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
	return append([]string{"git", "fetch"}, args...), nil
}

func (a *app) interactivePeerGitPush(r *bufio.Reader, alias string) ([]string, error) {
	args := []string{"git", "push", alias}
	fmt.Fprintln(a.out, "Push scope:")
	fmt.Fprintln(a.out, "  1) all branches and tags")
	fmt.Fprintln(a.out, "  2) current branch")
	fmt.Fprintln(a.out, "  3) selected branches")
	choice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
	}
	switch choice {
	case "1", "all":
	case "2", "current":
		args = append(args, "--current")
	case "3", "branch", "branches":
		for {
			fmt.Fprint(a.out, "Branch name (blank to finish): ")
			branch := readLine(r)
			if branch == "" {
				break
			}
			args = append(args, "--branch", branch)
		}
		if len(args) == 3 {
			return nil, fatalError("branch name required")
		}
	default:
		return nil, fatalError("Unknown push scope: " + choice)
	}
	fmt.Fprint(a.out, "TTL [168h]: ")
	ttl := readLine(r)
	if ttl == "" {
		ttl = "168h"
	}
	return append(args, "--ttl", ttl), nil
}

func (a *app) interactivePeerGitFetch(r *bufio.Reader, alias string) ([]string, error) {
	args := []string{"git", "fetch", alias}
	fmt.Fprint(a.out, "Associate this repository with the peer's repository? [y/N]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		args = append(args, "--associate")
	}
	fmt.Fprint(a.out, "Allow non-fast-forward ref rewrites? [y/N]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		args = append(args, "--allow-rewrite")
	}
	return args, nil
}

func (a *app) interactivePeers(r *bufio.Reader) ([]string, error) {
	return a.interactiveStep(r, "", func() {
		fmt.Fprintln(a.out, "Peers:")
		fmt.Fprintln(a.out, "  1) create invitation")
		fmt.Fprintln(a.out, "  2) accept invitation")
		fmt.Fprintln(a.out, "  3) list")
		fmt.Fprintln(a.out, "  4) show")
		fmt.Fprintln(a.out, "  5) rename")
		fmt.Fprintln(a.out, "  6) remove")
		fmt.Fprintln(a.out, "  7) revoke")
	}, func(choice string) ([]string, error) {
		return a.interactivePeersChoice(r, choice)
	})
}

func (a *app) interactivePeersChoice(r *bufio.Reader, choice string) ([]string, error) {
	switch choice {
	case "1", "invite":
		// Pairing names a peer that does not exist yet, and the pairing
		// short authentication string is read from the controlling terminal
		// inside the command itself.
		fmt.Fprint(a.out, "Peer alias: ")
		alias := readLine(r)
		if alias == "" {
			return nil, fatalError("peer alias required")
		}
		return []string{"peer", "invite", alias}, nil
	case "2", "accept":
		fmt.Fprint(a.out, "Peer alias: ")
		alias := readLine(r)
		if alias == "" {
			return nil, fatalError("peer alias required")
		}
		return []string{"peer", "accept", alias}, nil
	case "3", "list":
		return []string{"peer", "list"}, nil
	case "4", "show":
		alias, _, err := a.choosePeer(r, peerPicker{title: "Show peer:", includeAll: true})
		if err != nil {
			return nil, err
		}
		return []string{"peer", "show", alias}, nil
	case "5", "rename":
		oldAlias, _, err := a.choosePeer(r, peerPicker{title: "Rename peer:", includeAll: true})
		if err != nil {
			return nil, err
		}
		fmt.Fprint(a.out, "New peer alias: ")
		newAlias := readLine(r)
		if newAlias == "" {
			return nil, fatalError("both peer aliases are required")
		}
		return []string{"peer", "rename", oldAlias, newAlias}, nil
	case "6", "remove":
		alias, _, err := a.choosePeer(r, peerPicker{title: "Remove peer:", includeAll: true})
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(a.out, "Remove peer %q and its pending local state? [y/N]: ", alias)
		if !strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
			fmt.Fprintln(a.out, "Cancelled.")
			return nil, nil
		}
		return []string{"peer", "remove", alias, "--yes"}, nil
	case "7", "revoke":
		alias, _, err := a.choosePeer(r, peerPicker{title: "Revoke peer:", includeAll: true})
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(a.out, "Revoke peer %q and disable its server capabilities? [y/N]: ", alias)
		if !strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
			fmt.Fprintln(a.out, "Cancelled.")
			return nil, nil
		}
		return []string{"peer", "revoke", alias, "--yes"}, nil
	default:
		return nil, fatalError("Unknown peers choice: " + choice)
	}
}

func (a *app) interactiveStatus(r *bufio.Reader) ([]string, error) {
	return a.interactiveStep(r, "", func() {
		fmt.Fprintln(a.out, "Status:")
		fmt.Fprintln(a.out, "  1) peer list")
		fmt.Fprintln(a.out, "  2) peer detail")
		fmt.Fprintln(a.out, "  3) synchronize peers")
		fmt.Fprintln(a.out, "  4) what is waiting to be received")
		fmt.Fprintln(a.out, "  5) git synchronization state")
		fmt.Fprintln(a.out, "  6) transport doctor")
		fmt.Fprintln(a.out, "  7) server capabilities")
	}, func(choice string) ([]string, error) {
		return a.interactiveStatusChoice(r, choice)
	})
}

func (a *app) interactiveStatusChoice(r *bufio.Reader, choice string) ([]string, error) {
	switch choice {
	case "1", "list":
		return []string{"peer", "list"}, nil
	case "2", "show":
		alias, _, err := a.choosePeer(r, peerPicker{title: "Show peer:", includeAll: true})
		if err != nil {
			return nil, err
		}
		return []string{"peer", "show", alias}, nil
	case "3", "sync":
		alias, all, err := a.choosePeer(r, peerPicker{title: "Synchronize:", extraLabel: "all peers"})
		if err != nil {
			return nil, err
		}
		if all {
			return []string{"sync"}, nil
		}
		return []string{"sync", alias}, nil
	case "4", "inbox":
		alias, all, err := a.choosePeer(r, peerPicker{title: "Inbox for:", extraLabel: "all peers"})
		if err != nil {
			return nil, err
		}
		if all {
			return []string{"inbox"}, nil
		}
		return []string{"inbox", alias}, nil
	case "5", "git", "git-status":
		alias, all, err := a.choosePeer(r, peerPicker{title: "Git status for:", extraLabel: "all peers"})
		if err != nil {
			return nil, err
		}
		if all {
			return []string{"git", "status"}, nil
		}
		return []string{"git", "status", alias}, nil
	case "6", "doctor":
		return []string{"doctor"}, nil
	case "7", "capabilities":
		return []string{"capabilities"}, nil
	default:
		return nil, fatalError("Unknown status choice: " + choice)
	}
}

func (a *app) interactiveSetup(r *bufio.Reader) ([]string, error) {
	return a.interactiveStep(r, "", func() {
		paths, pathsErr := resolveV2Paths()
		fmt.Fprintln(a.out, "Setup:")
		if pathsErr == nil {
			fmt.Fprintf(a.out, "  Config: %s\n", paths.Config)
		}
		fmt.Fprintln(a.out, "  1) initialize device")
		fmt.Fprintln(a.out, "  2) show configuration")
		fmt.Fprintln(a.out, "  3) validate configuration")
		fmt.Fprintln(a.out, "  4) migrate configuration")
		fmt.Fprintln(a.out, "  5) erase local state")
	}, func(choice string) ([]string, error) {
		return a.interactiveSetupChoice(r, choice)
	})
}

func (a *app) interactiveSetupChoice(r *bufio.Reader, choice string) ([]string, error) {
	switch choice {
	case "1", "init":
		fmt.Fprint(a.out, "Device name: ")
		device := readLine(r)
		if device == "" {
			return nil, fatalError("device name required")
		}
		fmt.Fprintf(a.out, "Server URL [%s]: ", a.cfg.BaseURL)
		serverURL := readLine(r)
		if serverURL == "" {
			serverURL = a.cfg.BaseURL
		}
		fmt.Fprintf(a.out, "DoH URL [%s]: ", a.cfg.DOHURL)
		dohURL := readLine(r)
		if dohURL == "" {
			dohURL = a.cfg.DOHURL
		}
		fmt.Fprintf(a.out, "ECH mode [%s]: ", a.cfg.ECHMode)
		echMode := readLine(r)
		if echMode == "" {
			echMode = a.cfg.ECHMode
		}
		return []string{
			"init",
			"--device", device,
			"--url", serverURL,
			"--doh-url", dohURL,
			"--ech-mode", echMode,
		}, nil
	case "2", "show":
		return []string{"config", "show"}, nil
	case "3", "validate":
		return []string{"config", "validate"}, nil
	case "4", "migrate":
		return []string{"migrate"}, nil
	case "5", "erase":
		return a.interactiveErase(r)
	default:
		return nil, fatalError("Unknown setup choice: " + choice)
	}
}

func (a *app) interactiveErase(r *bufio.Reader) ([]string, error) {
	fmt.Fprintln(a.out, "Erase scope:")
	fmt.Fprintln(a.out, "  1) pending pairings")
	fmt.Fprintln(a.out, "  2) one peer")
	fmt.Fprintln(a.out, "  3) repository state")
	fmt.Fprintln(a.out, "  4) all local DUD state")
	choice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
	}
	args := []string{"erase"}
	scope := ""
	switch choice {
	case "1", "pairings":
		scope, args = "pending pairings", append(args, "pairings")
	case "2", "peer":
		alias, _, err := a.choosePeer(r, peerPicker{title: "Erase peer:", includeAll: true})
		if err != nil {
			return nil, err
		}
		scope, args = "peer "+alias, append(args, "peer", alias)
	case "3", "repo":
		scope, args = "repository state", append(args, "repo")
	case "4", "all":
		scope, args = "all local DUD state", append(args, "all")
		fmt.Fprint(a.out, "Include repository state? [y/N]: ")
		if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
			args = append(args, "--repo")
		}
	default:
		return nil, fatalError("Unknown erase scope: " + choice)
	}
	fmt.Fprint(a.out, "Inspect only, without erasing? [Y/n]: ")
	if !strings.HasPrefix(strings.ToLower(readLine(r)), "n") {
		return append(args, "--dry-run"), nil
	}
	fmt.Fprintf(a.out, "Permanently erase %s? [y/N]: ", scope)
	if !strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		fmt.Fprintln(a.out, "Cancelled.")
		return nil, nil
	}
	return append(args, "--yes"), nil
}

func (a *app) interactiveTools(r *bufio.Reader) ([]string, error) {
	return a.interactiveStep(r, "", func() {
		fmt.Fprintln(a.out, "Tools:")
		fmt.Fprintln(a.out, "  1) transport test")
		fmt.Fprintln(a.out, "  2) keygen")
		fmt.Fprintln(a.out, "  3) flush expired drop files")
	}, func(choice string) ([]string, error) {
		switch choice {
		case "1", "test":
			return a.interactiveTest(r)
		case "2", "keygen":
			return a.interactiveKeygen(r)
		case "3", "flush":
			return a.interactiveFlush(r)
		default:
			return nil, fatalError("Unknown tools choice: " + choice)
		}
	})
}

func (a *app) interactiveKeygen(r *bufio.Reader) ([]string, error) {
	fmt.Fprintln(a.out, "Keygen mode:")
	fmt.Fprintln(a.out, "  1) generate a new identity")
	fmt.Fprintln(a.out, "  2) convert an identity to recipients")
	choice, err := a.readMenuChoice(r, "1")
	if err != nil {
		return nil, err
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
		return append([]string{"keygen"}, args...), nil
	case "2", "convert":
		fmt.Fprint(a.out, "Identity file: ")
		input := readLine(r)
		if input == "" {
			return nil, fatalError("identity file required")
		}
		args := []string{absPathIfRelative(input)}
		fmt.Fprint(a.out, "Recipient output path (leave empty for stdout): ")
		recipientOut := readLine(r)
		if recipientOut != "" {
			args = append([]string{"-R", absPathIfRelative(recipientOut)}, args...)
		}
		return append([]string{"keygen"}, args...), nil
	default:
		return nil, fatalError("Unknown keygen mode: " + choice)
	}
}

func (a *app) interactiveFlush(r *bufio.Reader) ([]string, error) {
	fmt.Fprint(a.out, "Flush all expired files? [y/N]: ")
	if strings.HasPrefix(strings.ToLower(readLine(r)), "y") {
		return []string{"flush"}, nil
	}
	fmt.Fprintln(a.out, "Cancelled.")
	return nil, nil
}
