// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"sort"
	"strings"
)

// Guidance uses the same short placeholders as command help. Remote aliases
// and profiles belong to the device where the printed command is run.
const cliPlaceholderHelp = "PEER is the alias on that device; select its profile if needed. NAME is a device name or unused alias. PATH is a path you choose."

type helpTopic struct {
	description string
	options     string
	arguments   string
	example     string
	notes       string
}

type helpOption struct {
	value       string
	description string
}

// The option arities also guide help recognition: a value such as --help
// belongs to its option and must never turn a transfer into a help request.
var helpOptions = map[string]helpOption{
	"--json":                 {"", "Report the result as JSON; automatic progress is disabled."},
	"--url":                  {"URL", "Select the server URL; paired peers use their pinned origin."},
	"--doh-url":              {"URL", "Select the HTTPS DNS-over-HTTPS resolver."},
	"--ech-mode":             {"hard|off", "Select ECH mode; the default is hard."},
	"--file":                 {"PATH", "Read an input file or directory; repeat for a collection when sending."},
	"-m":                     {"TEXT", "Send the literal message text."},
	"--message":              {"TEXT", "Peer alias for -m."},
	"--stdin":                {"", "Read peer message text from stdin."},
	"--name":                 {"NAME", "Set the peer delivery's display name."},
	"--ttl":                  {"DURATION", "Set expiry: the default is 24h for dead drops and 168h for peers."},
	"--delete-after-read":    {"", "Request one-time consumption; expiry alone does not make a dead drop single-use."},
	"--passphrase":           {"", "Encrypt a dead drop using a prompted passphrase."},
	"--recipient":            {"AGE_RECIPIENT", "Encrypt a dead drop to an age recipient."},
	"-r":                     {"AGE_RECIPIENT", "Alias for --recipient."},
	"--recipient-file":       {"PATH", "Read dead drop age recipients from a file."},
	"-R":                     {"PATH", "Recipient file; for keygen, write the public recipient to this path."},
	"--recipient-out":        {"PATH", "Write the keygen public recipient to this path; alias: -R."},
	"--no-qr":                {"", "Suppress the HTTP dead drop QR code."},
	"--id":                   {"ID", "Select a dead drop ID or a peer descriptor digest, as shown in Usage."},
	"--out":                  {"PATH", "Choose the output path; keygen writes the private identity here."},
	"-o":                     {"PATH", "Peer receive alias for --out."},
	"--out-dir":              {"DIR", "Choose the receive or extraction directory."},
	"--stdout":               {"", "Write the decrypted dead drop payload to stdout; incompatible with --json."},
	"--extract":              {"", "Extract a dead drop collection; existing top-level paths are rejected."},
	"--identity":             {"PATH", "Decrypt a dead drop with this age identity; omission prompts for a passphrase."},
	"-i":                     {"PATH", "Alias for --identity."},
	"--remote":               {"NAME", "Set the dead drop Git fetch remote; the default is dud."},
	"--pq":                   {"", "Generate a hybrid post-quantum age identity."},
	"--device":               {"NAME", "Name this device in its peer profile."},
	"--yes":                  {"", "Give the explicit consent required by the operation."},
	"--dry-run":              {"", "Preview local erasure without removing state."},
	"--repo":                 {"", "Include repository state with erase all."},
	"--expires":              {"DURATION", "Set the peer invitation lifetime."},
	"--new":                  {"", "Propose another relationship reset after a completed reset."},
	"--cancel":               {"", "Cancel a relationship reset before server activation; requires --yes."},
	"--refresh-capabilities": {"", "Reissue peer server authorization before synchronizing."},
	"--progress":             {"", "Force newline-delimited transfer progress on stderr."},
	"--no-progress":          {"", "Disable progress while preserving warnings and results."},
	"-v":                     {"", "Print the full transfer status and recovery details."},
	"--verbose":              {"", "Alias for -v; JSON always includes the complete status."},
	"--wait":                 {"DURATION", "Wait for a peer delivery only when the inbox starts empty."},
	"--max":                  {"N", "Receive at most N peer deliveries."},
	"--on-conflict":          {"skip|refuse|overwrite", "Handle an existing output with different contents; the default is skip."},
	"--no-extract":           {"", "Keep a received peer collection as an archive."},
	"--collection-overwrite": {"refuse", "Alias for --on-conflict refuse."},
	"--interactive":          {"", "Ask for peer collection output choices in the terminal."},
	"--branch":               {"NAME", "Include this Git branch in a peer checkpoint; repeat for multiple branches."},
	"--current":              {"", "Select the current branch for the peer Git checkpoint."},
	"--full":                 {"", "Publish a full Git checkpoint."},
	"--incremental":          {"", "Publish an incremental Git checkpoint from an acknowledged base."},
	"--associate":            {"", "Explicitly associate the repository with a trusted incoming peer checkpoint."},
	"--allow-rewrite":        {"", "Permit a peer Git checkpoint to rewrite remote-tracking refs."},
}

const transferHelpOptions = "--json --progress --no-progress -v --verbose"
const networkHelpOptions = "--url --doh-url --ech-mode --json"
const dropEncryptionHelpOptions = "--ttl --delete-after-read --passphrase --recipient -r --recipient-file -R --json --no-qr --url --doh-url"
const dropSendHelpOptions = "--file -m " + dropEncryptionHelpOptions
const dropReceiveHelpOptions = "--id --out --stdout --extract --out-dir --identity -i --json --url --doh-url"
const peerSendHelpOptions = "--message --stdin --name " + transferHelpOptions
const peerReceiveHelpOptions = "-o --wait --max --on-conflict --no-extract --collection-overwrite --interactive " + transferHelpOptions
const transferModeHelp = "A positional peer alias selects a peer transfer. A leading flag selects a dead drop. Paired peers reject --url, --doh-url and --ech-mode."

var commandHelpTopics = map[string]helpTopic{
	"version":             {"Print the DUD version.", "", "", "dud --version", ""},
	"help":                {"Show general or command-specific help.", "", "COMMAND and SUBCOMMAND select the help topic.", "dud help git push", "Use --help or -h on any command. Groups also accept help before a subcommand."},
	"install":             {"Print a Docker host wrapper script to stdout.", "", "", "dud install > dud-wrapper.sh", ""},
	"shell-init":          {"Print a Docker shell function definition to stdout.", "", "", "dud shell-init", ""},
	"test":                {"Check dead drop connectivity and server authorization.", "--json --url --doh-url", "", "dud test --json", ""},
	"upload":              {"Send a dead drop or a delivery to a paired peer.", dropSendHelpOptions + " " + peerSendHelpOptions, "PEER is the local alias of a paired device.", "dud upload --file report.txt --passphrase", transferModeHelp},
	"send":                {"Send a delivery to a paired peer or create a dead drop.", dropSendHelpOptions + " " + peerSendHelpOptions, "PEER is the local alias of a paired device.", "dud send laptop -m 'hello'", transferModeHelp + " Publishing returns without waiting for the peer's acknowledgement."},
	"download":            {"Receive a dead drop or deliveries from a paired peer.", dropReceiveHelpOptions + " " + peerReceiveHelpOptions, "PEER is the local alias of a paired device.", "dud download --id ID --out report.txt", transferModeHelp},
	"receive":             {"Receive deliveries from a paired peer or recover a dead drop.", dropReceiveHelpOptions + " " + peerReceiveHelpOptions, "PEER is the local alias of a paired device.", "dud receive laptop --out-dir received", transferModeHelp + " Peer receive drains oldest first. --id selects a saved descriptor digest. A Git checkpoint stops the drain and requires git fetch in the matching repository."},
	"flush":               {"Remove server-side dead drops using the configured upload secret.", "--json --url --doh-url", "", "dud flush --json", ""},
	"keygen":              {"Generate an age identity or derive a public recipient from an identity.", "--pq --out --recipient-out -R --json", "INPUT is an existing identity; omit it to generate a key.", "dud keygen --out identity.txt -R recipient.txt", "Keep the private identity secret; share only its public recipient."},
	"init":                {"Initialize a device and its local peer profile.", "--device " + networkHelpOptions, "", "dud init --device desktop --url https://dud.example.com", ""},
	"doctor":              {"Diagnose peer configuration, transport and delivery state.", networkHelpOptions, "", "dud doctor", ""},
	"capabilities":        {"Report peer server capabilities.", networkHelpOptions, "", "dud capabilities --json", ""},
	"migrate":             {"Migrate local peer configuration to its supported layout.", "--json", "", "dud migrate --json", ""},
	"config":              {"Inspect and validate local peer configuration.", "", "", "dud config show", ""},
	"config show":         {"Show local peer configuration with secrets redacted.", "--json", "", "dud config show --json", ""},
	"config validate":     {"Validate local peer configuration.", "--json", "", "dud config validate", ""},
	"erase":               {"Erase selected local peer state with explicit consent.", "", "", "dud erase pairings --dry-run", "Preview with --dry-run before confirming with --yes."},
	"erase pairings":      {"Erase local pairings and their delivery state.", "--yes --dry-run --json", "", "dud erase pairings --dry-run", ""},
	"erase peer":          {"Erase one peer's local state.", "--yes --dry-run --json", "NAME is the local peer alias.", "dud erase peer laptop --dry-run", ""},
	"erase repo":          {"Erase DUD state belonging to the working repository.", "--yes --dry-run --json", "", "dud erase repo --dry-run", ""},
	"erase all":           {"Erase this profile's local peer state.", "--yes --dry-run --repo --json", "", "dud erase all --dry-run", "--repo also includes DUD state in the working repository."},
	"peer":                {"Pair devices and inspect or manage peer relationships.", "", "", "dud peer list", "NAME and PEER are local aliases, selected independently on each device."},
	"peer invite":         {"Create an invitation and wait for the other device to accept it.", "--expires --json", "NAME is the local alias for the invited device.", "dud peer invite laptop", "Share the pairing code through a trusted channel; keep the invitation running."},
	"peer accept":         {"Accept a pairing invitation using a prompted code.", "--json", "NAME is the local alias for the inviting device.", "dud peer accept desktop", "The pairing code is entered at the terminal prompt."},
	"peer list":           {"List local peer aliases and relationship states.", "--json", "", "dud peer list", ""},
	"peer show":           {"Show a peer's configuration, delivery state and recovery details.", "--json", "NAME is the local peer alias.", "dud peer show laptop", ""},
	"peer rename":         {"Rename a local peer alias.", "--json", "OLD is the existing alias; NEW is its replacement.", "dud peer rename laptop notebook", ""},
	"peer resume":         {"Inspect or consent to resuming quarantined peer chains.", "--yes --json", "NAME is the local peer alias.", "dud peer resume laptop", "--yes consents to abandoning skipped deliveries; ask the sender to resend their contents."},
	"peer reset":          {"Inspect or coordinate a relationship reset with both devices.", "--new --cancel --yes --json", "NAME is the local peer alias.", "dud peer reset laptop", "Without --yes, show reset status and next steps. --yes proposes or continues a reset; --new starts another after completion. --cancel --yes cancels before server activation."},
	"peer abandon":        {"Abandon a saved outbound delivery with explicit consent.", "--id --yes --json", "NAME is the local peer alias; --id is the delivery descriptor digest.", "dud peer abandon laptop --id DIGEST --yes", ""},
	"peer revoke":         {"Revoke a peer relationship with explicit consent.", "--yes --json", "NAME is the local peer alias.", "dud peer revoke laptop --yes", ""},
	"peer remove":         {"Remove a local peer profile with explicit consent.", "--yes --json", "NAME is the local peer alias.", "dud peer remove laptop --yes", ""},
	"peer enrollment-key": {"Derive a server enrollment key from a prompted operator passphrase.", "--json", "", "dud peer enrollment-key", "Only the inviter needs the enrollment secret on a gated deployment."},
	"sync":                {"Retry saved publications and collect peer acknowledgements.", "--refresh-capabilities --json --progress --no-progress", "PEER is an optional local alias; omission selects all active peers.", "dud sync laptop", "Resume queued work with sync rather than repeating send or git push, which creates another delivery."},
	"inbox":               {"Inspect the oldest waiting peer delivery without committing it.", "--json", "PEER is an optional local alias; omission selects all active peers.", "dud inbox laptop", "The server exposes the oldest delivery, not the full queue. Inspecting it downloads its payload."},
	"git":                 {"Transfer Git checkpoints through peers or dead drops.", "", "", "dud git push laptop --current", "push/send and fetch/receive are alias pairs. A positional peer alias selects peer transfer; leading flags select a dead drop."},
	"git push":            {"Publish a Git checkpoint to a peer or a dead drop.", dropEncryptionHelpOptions + " --branch --current --full --incremental " + transferHelpOptions, "PEER is the local alias of a paired device.", "dud git push laptop --current", transferModeHelp + " Peer checkpoints return after publication and await receipt confirmation. --verbose includes checkpoint metadata and delivery status. --full and --incremental are mutually exclusive."},
	"git fetch":           {"Import a Git checkpoint from a peer or a dead drop.", "--id --identity -i --remote --json --url --doh-url --associate --allow-rewrite " + transferHelpOptions, "PEER is the local alias of a paired device; --id selects a dead drop.", "dud git fetch desktop --associate", transferModeHelp + " Peer fetch updates remote-tracking refs and reports confirmation publication. Local branches and the working tree stay unchanged. --verbose includes checkpoint metadata, delivery status, and integration commands."},
	"git status":          {"Report repository synchronization and peer delivery details.", "--json", "PEER is an optional local alias; omission selects all active peers.", "dud git status laptop", ""},
}

func canonicalHelpPath(path string) string {
	switch path {
	case "--version":
		return "version"
	case "git send":
		return "git push"
	case "git receive":
		return "git fetch"
	}
	return path
}

func helpChildren(path string) []string {
	children := []string{}
	for candidate := range commandHelpTopics {
		parent, _, _ := strings.Cut(candidate, " ")
		if parent == path && candidate != path {
			children = append(children, candidate)
		}
	}
	sort.Strings(children)
	return children
}

func unknownHelpTopic(path, parent string) error {
	command := "help"
	if parent != "" {
		command += " " + parent
	}
	return withCLISteps(fatalError("Unknown help topic: "+safeTerminalText(path)), localCLIStep("Choose a help topic.", command))
}

func (a *app) helpPath(parts []string) error {
	if len(parts) == 0 {
		a.usage()
		return nil
	}
	path := ""
	for _, part := range parts {
		candidate := canonicalHelpPath(strings.TrimSpace(path + " " + part))
		if _, ok := commandHelpTopics[candidate]; !ok {
			parent := path
			if len(helpChildren(parent)) == 0 {
				parent, _, _ = strings.Cut(parent, " ")
				if len(helpChildren(parent)) == 0 {
					parent = ""
				}
			}
			return unknownHelpTopic(candidate, parent)
		}
		path = candidate
	}
	return a.showCommandHelp(path)
}

func isHelpFlag(value string) bool { return value == "--help" || value == "-h" }

// commandHelp resolves only command positions and unconsumed help flags.
// Bare help in a leaf's arguments remains a peer alias or ordinary input.
func (a *app) commandHelp(args []string) (bool, error) {
	if args[0] == "help" && len(args) == 2 && isHelpFlag(args[1]) {
		return true, a.showCommandHelp("help")
	}
	if args[0] == "help" || isHelpFlag(args[0]) {
		return true, a.helpPath(args[1:])
	}
	path := canonicalHelpPath(args[0])
	topic, known := commandHelpTopics[path]
	if !known {
		return false, nil
	}
	rest := args[1:]
	if len(helpChildren(path)) != 0 && len(rest) != 0 {
		if rest[0] == "help" || isHelpFlag(rest[0]) {
			return true, a.helpPath(append([]string{path}, rest[1:]...))
		}
		child := canonicalHelpPath(path + " " + rest[0])
		var ok bool
		topic, ok = commandHelpTopics[child]
		if !ok {
			for _, arg := range rest[1:] {
				if isHelpFlag(arg) {
					return true, unknownHelpTopic(child, path)
				}
			}
			return false, nil
		}
		path, rest = child, rest[1:]
	}
	allowed := strings.Fields(topic.options)
	for index := 0; index < len(rest); index++ {
		arg := rest[index]
		if arg == "--" {
			break
		}
		if isHelpFlag(arg) {
			return true, a.showCommandHelp(path)
		}
		for _, option := range allowed {
			if arg == option && helpOptions[option].value != "" {
				index++
				break
			}
		}
	}
	return false, nil
}

func helpUsage(path string) []string {
	paths := []string{path}
	switch path {
	case "install", "shell-init":
		return []string{"dud " + path}
	case "version":
		return []string{"dud --version", "dud version"}
	case "help":
		return []string{"dud help [COMMAND [SUBCOMMAND]]", "dud COMMAND [SUBCOMMAND] --help"}
	case "config show", "config validate":
		return []string{"dud " + path + " [--json]"}
	case "send", "upload":
		paths = []string{"upload", "send"}
	case "receive", "download":
		paths = []string{"download", "receive"}
	}
	lines := []string{}
	for _, line := range strings.Split(usageText, "\n") {
		for _, candidate := range paths {
			prefix := "  dud " + candidate
			if line == prefix || strings.HasPrefix(line, prefix+" ") {
				lines = append(lines, strings.TrimSpace(line))
				break
			}
		}
	}
	return lines
}

func (a *app) showCommandHelp(path string) error {
	topic := commandHelpTopics[path]
	report := &textReport{}
	report.section("").add("dud "+path+" — "+topic.description, "")
	usage := report.section("Usage")
	for _, line := range helpUsage(path) {
		usage.add(line, "")
	}
	if children := helpChildren(path); len(children) != 0 {
		section := report.section("Subcommands")
		for _, child := range children {
			section.add(strings.TrimPrefix(child, path+" "), commandHelpTopics[child].description)
		}
		if path == "git" {
			section.add("send / receive", "Aliases for push / fetch.")
		}
	}
	if topic.arguments != "" {
		report.section("Arguments").note(topic.arguments)
	}
	section := report.section("Options")
	seen := map[string]bool{}
	for _, name := range strings.Fields(topic.options) {
		if seen[name] {
			continue
		}
		seen[name] = true
		option := helpOptions[name]
		label := name
		if option.value != "" {
			label += " " + option.value
		}
		section.add(label, option.description)
	}
	section.add("-h, --help", "Show this command's help without executing it.")
	if topic.notes != "" {
		report.section("Notes").note(topic.notes)
	}
	report.section("Example").add(topic.example, "")
	for _, placeholder := range []string{"PEER", "NAME", "PATH"} {
		if strings.Contains(strings.Join(helpUsage(path), " "), placeholder) {
			report.section("Placeholders").note(cliPlaceholderHelp)
			break
		}
	}
	return report.write(a.out)
}
