// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These cover what the dead drop commands put on the wire and what they do
// with the answer. The request never leaves the process: the transport seam
// records it.

const testDropID = "3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe"

func writeRecordingAge(t *testing.T, logPath, output string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "age-record.sh")
	script := `#!/bin/sh
printf '%s\n' "$@" > "` + logPath + `"
out=""
input=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2; continue ;;
    -R|-i) shift 2; continue ;;
    -*) shift; continue ;;
  esac
  input="$1"
  shift
done
`
	if output == "" {
		script += `if [ -n "$input" ] && [ -n "$out" ]; then cp "$input" "$out"; fi
`
	} else {
		script += `printf '%s' '` + output + `' > "$out"
`
	}
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRecordingQREncode(t *testing.T, logPath string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "qrencode-record.sh")
	script := `#!/bin/sh
printf '%s\n' "$@" > "` + logPath + `"
printf '[qr]\n'
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestUploadPostsTheCiphertextWithItsHeaders(t *testing.T) {
	source := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(source, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageLog := filepath.Join(t.TempDir(), "age.log")
	qrLog := filepath.Join(t.TempDir(), "qr.log")

	a, transport, stdout, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = writeRecordingAge(t, ageLog, "")
	a.cfg.QREncodeBin = writeRecordingQREncode(t, qrLog)
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{
			StatusCode: http.StatusOK,
			Body: []byte(`{"id":"` + testDropID +
				`","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}`),
		}, nil
	}

	if err := a.run([]string{
		"upload", "--file", source, "--ttl", "48h", "--delete-after-read",
	}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}

	request := transport.only(t)
	if request.Method != http.MethodPost || request.Path != "/v1/files" {
		t.Fatalf("request = %s %s", request.Method, request.Path)
	}
	if string(request.Body) != "plaintext" {
		t.Fatalf("uploaded body = %q", request.Body)
	}
	if request.ContentLength != int64(len("plaintext")) {
		t.Fatalf("declared length = %d", request.ContentLength)
	}
	for name, want := range map[string]string{
		"content-type":            "application/octet-stream",
		"x-dud-ttl":               "48h",
		"x-dud-delete-after-read": "true",
		"x-dud-secret-token":      "top-secret",
	} {
		if got := request.header(name); got != want {
			t.Fatalf("header %s = %q, want %q", name, got, want)
		}
	}

	ageArgs, err := os.ReadFile(ageLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ageArgs), "--passphrase") {
		t.Fatalf("age args = %q", ageArgs)
	}
	for _, want := range []string{
		"Upload complete",
		"ID                 " + testDropID,
		"Expires            2026-04-20T12:00:00.000Z",
		"Delete after read  yes",
		"Receive            dud receive --id " + testDropID + " --url https://dud.example.com",
		"QR Code:",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout omitted %q:\n%s", want, stdout.String())
		}
	}
	qrArgs, err := os.ReadFile(qrLog)
	if err != nil {
		t.Fatal(err)
	}
	if string(qrArgs) != "-t\nansiutf8\n"+testDropID+"\n" {
		t.Fatalf("qrencode args = %q", qrArgs)
	}
}

func TestUploadStreamsEachSourceForm(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(file, []byte("file payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{name: "file", args: []string{"upload", "--file", file, "--json"}, want: "file payload"},
		{name: "message", args: []string{"upload", "-m", "hello from dud", "--json"}, want: "hello from dud"},
		{name: "stdin", args: []string{"upload", "--json"}, stdin: "stdin plaintext", want: "stdin plaintext"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, transport, stdout, stderr := newDropTestApp(t, test.stdin)
			transport.respond = uploadJSONResponder(testDropID)
			if err := a.run(test.args); err != nil {
				t.Fatalf("%v (stderr %s)", err, stderr.String())
			}
			if got := string(transport.only(t).Body); got != test.want {
				t.Fatalf("uploaded body = %q, want %q", got, test.want)
			}
			want := `{"id":"` + testDropID +
				`","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}` + "\n"
			if stdout.String() != want {
				t.Fatalf("--json stdout = %q, want %q", stdout.String(), want)
			}
		})
	}
}

func TestUploadBundlesMultipleSourcesAndAdvertisesExtraction(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "alpha.txt")
	nested := filepath.Join(root, "docs")
	if err := os.WriteFile(first, []byte("alpha payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "beta.txt"), []byte("beta payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	a, transport, stdout, stderr := newDropTestApp(t, "")
	transport.respond = uploadJSONResponder(testDropID)
	if err := a.run([]string{"send", "--file", first, "--file", nested, "--no-qr"}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Receive            dud receive --id "+testDropID+
		" --url https://dud.example.com --extract") {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "QR Code:") {
		t.Fatalf("--no-qr still printed a QR code:\n%s", stdout.String())
	}

	archive := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(archive, transport.only(t).Body, 0o600); err != nil {
		t.Fatal(err)
	}
	listing, err := exec.Command("tar", "-tf", archive).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"alpha.txt", "docs/beta.txt"} {
		if !strings.Contains(string(listing), want) {
			t.Fatalf("bundle listing omitted %q:\n%s", want, listing)
		}
	}
}

func TestUploadEncryptsToRecipientsInsteadOfAPassphrase(t *testing.T) {
	source := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(source, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageLog := filepath.Join(t.TempDir(), "age.log")

	a, transport, _, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = writeRecordingAge(t, ageLog, "")
	transport.respond = uploadJSONResponder(testDropID)
	if err := a.run([]string{
		"upload", "--file", source,
		"-r", "age1examplepublickey0000000000000000000000000000000000000000000000",
		"--json",
	}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	args, err := os.ReadFile(ageLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--encrypt") || !strings.Contains(string(args), "-R") {
		t.Fatalf("age args = %q", args)
	}
	if strings.Contains(string(args), "--passphrase") {
		t.Fatalf("recipient mode fell back to a passphrase: %q", args)
	}
}

func TestUploadAcceptsBothRecipientFileSpellings(t *testing.T) {
	source := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(source, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	recipients := filepath.Join(t.TempDir(), "recipients.txt")
	if err := os.WriteFile(recipients,
		[]byte("age1examplepublickey0000000000000000000000000000000000000000000000\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"-R", "--recipient-file"} {
		t.Run(flag, func(t *testing.T) {
			ageLog := filepath.Join(t.TempDir(), "age.log")
			a, transport, _, stderr := newDropTestApp(t, "")
			a.cfg.AgeBin = writeRecordingAge(t, ageLog, "")
			transport.respond = uploadJSONResponder(testDropID)
			if err := a.run([]string{"upload", "--file", source, flag, recipients, "--json"}); err != nil {
				t.Fatalf("%v (stderr %s)", err, stderr.String())
			}
			args, err := os.ReadFile(ageLog)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(args), "-R\n"+recipients) {
				t.Fatalf("age args = %q", args)
			}
		})
	}
}

func TestDownloadWritesDecryptedOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output.bin")
	ageLog := filepath.Join(t.TempDir(), "age.log")

	a, transport, _, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = writeRecordingAge(t, ageLog, "plain payload")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: []byte("ciphertext")}, nil
	}

	if err := a.run([]string{"download", "--id", testDropID, "--out", output}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	request := transport.only(t)
	if !request.Streamed {
		t.Fatal("download did not stream the response body")
	}
	if request.Path != "/v1/files/"+testDropID {
		t.Fatalf("route = %q", request.Path)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "plain payload" {
		t.Fatalf("output = %q", body)
	}
	args, err := os.ReadFile(ageLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--decrypt") {
		t.Fatalf("age args = %q", args)
	}
}

// --json reports where the plaintext landed, which is the one fact a caller
// cannot recover from the exit status alone.
func TestDownloadJSONReportsTheCommittedOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output.bin")
	a, transport, stdout, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = writeRecordingAge(t, filepath.Join(t.TempDir(), "age.log"), "plain payload")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: []byte("ciphertext")}, nil
	}
	if err := a.run([]string{"download", "--id", testDropID, "--out", output, "--json"}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	if report["ok"] != true || report["id"] != testDropID || report["output"] != output {
		t.Fatalf("report = %#v", report)
	}
	if report["extracted"] != false || report["bytes"] != float64(len("plain payload")) {
		t.Fatalf("report = %#v", report)
	}
}

// The payload owns stdout under --stdout, so a JSON document cannot also go
// there. Refusing beats interleaving the two.
func TestDownloadRejectsJSONWithStdout(t *testing.T) {
	a, _, _, _ := newDropTestApp(t, "")
	err := a.run([]string{"download", "--id", testDropID, "--stdout", "--json"})
	if err == nil || !strings.Contains(err.Error(), "--json with --stdout") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Every command rejects a repeated --json the same way, so a typo never
// silently changes what a script reads.
func TestRepeatedJSONOptionIsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"test", "--json", "--json"},
		{"flush", "--json", "--json"},
		{"download", "--id", testDropID, "--out", "x", "--json", "--json"},
	} {
		a, _, _, _ := newDropTestApp(t, "")
		err := a.run(args)
		if err == nil || !strings.Contains(err.Error(), "only once") {
			t.Fatalf("%v: unexpected error %v", args, err)
		}
	}
}

func TestDownloadWritesToStdout(t *testing.T) {
	a, transport, stdout, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = writeRecordingAge(t, filepath.Join(t.TempDir(), "age.log"), "plain stdout")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: []byte("ciphertext")}, nil
	}
	if err := a.run([]string{"download", "--id", testDropID, "--stdout"}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	if stdout.String() != "plain stdout" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestDownloadDecryptsWithAnExplicitIdentity(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(identity, []byte("AGE-SECRET-KEY-1EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ageLog := filepath.Join(t.TempDir(), "age.log")
	output := filepath.Join(t.TempDir(), "output.bin")

	a, transport, _, stderr := newDropTestApp(t, "")
	a.cfg.AgeBin = writeRecordingAge(t, ageLog, "plain with identity")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: []byte("ciphertext")}, nil
	}
	if err := a.run([]string{
		"download", "--id", testDropID, "-i", identity, "--out", output,
	}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	args, err := os.ReadFile(ageLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "-i\n"+identity) {
		t.Fatalf("age args = %q", args)
	}
}

func TestReceiveExtractsABundledArchive(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("alpha payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "beta.txt"), []byte("beta payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "bundle.tar")
	if err := exec.Command("tar", "-cf", archive, "-C", root, "alpha.txt", "docs").Run(); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "extracted")

	a, transport, stdout, stderr := newDropTestApp(t, "")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: payload}, nil
	}
	if err := a.run([]string{
		"receive", "--id", testDropID, "--extract", "--out-dir", target,
	}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Extracted bundle to "+target) {
		t.Fatalf("stdout = %s", stdout.String())
	}
	for name, want := range map[string]string{
		"alpha.txt":     "alpha payload",
		"docs/beta.txt": "beta payload",
	} {
		body, err := os.ReadFile(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want {
			t.Fatalf("%s = %q, want %q", name, body, want)
		}
	}
}

func TestFlushPostsTheSecretTokenAndPrintsTheSummary(t *testing.T) {
	body := []byte(`{"ok":true,"deletedCount":3,"partial":false}`)
	a, transport, stdout, stderr := newDropTestApp(t, "")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: body}, nil
	}
	if err := a.run([]string{"flush"}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	request := transport.only(t)
	if request.Method != http.MethodPost || request.Path != "/v1/admin/flush" {
		t.Fatalf("request = %s %s", request.Method, request.Path)
	}
	if request.header("x-dud-secret-token") != "top-secret" {
		t.Fatalf("secret token header = %q", request.header("x-dud-secret-token"))
	}
	if stdout.String() != "Deleted   3\nComplete  yes\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

// --json hands back exactly what the server said, so a caller parsing the sweep
// summary never has to trust this client's re-encoding of it.
func TestFlushJSONPassesTheServerSummaryThrough(t *testing.T) {
	body := []byte(`{"ok":true,"deletedCount":3,"partial":true}`)
	a, transport, stdout, stderr := newDropTestApp(t, "")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: body}, nil
	}
	if err := a.run([]string{"flush", "--json"}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	if stdout.String() != string(body)+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

// A partial sweep is the case an operator has to act on, so text mode says so
// rather than leaving it to a boolean the reader has to interpret.
func TestFlushTextReportsAnIncompleteSweep(t *testing.T) {
	a, transport, stdout, stderr := newDropTestApp(t, "")
	transport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"ok":true,"deletedCount":200,"partial":true}`),
		}, nil
	}
	if err := a.run([]string{"flush"}); err != nil {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	for _, want := range []string{"Deleted   200", "Complete  no", "run it again"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout omitted %q: %q", want, stdout.String())
		}
	}
}

// A round trip through a real Git bundle proves the two drop routes still
// carry bytes the other side can use, not just the right headers.
func TestGitPushAndFetchRoundTripARealBundle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not available")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	for _, dir := range []string{source, target} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		runGit(t, dir, "init", "-b", "main")
		runGit(t, dir, "config", "user.email", "dud@example.com")
		runGit(t, dir, "config", "user.name", "DUD Test")
	}
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("hello git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, source, "add", "README.md")
	runGit(t, source, "commit", "-m", "initial")
	runGit(t, source, "tag", "v1")

	var stored []byte
	pushApp, pushTransport, _, pushErr := newDropTestApp(t, "")
	pushTransport.respond = func(request recordedDropRequest) (*v2Response, error) {
		stored = append([]byte(nil), request.Body...)
		return uploadJSONResponder(testDropID)(request)
	}
	pushApp.cfg.GitBin = "git"
	if err := runInDirectory(t, source, func() error {
		return pushApp.run([]string{"git", "push", "--json"})
	}); err != nil {
		t.Fatalf("git push: %v (stderr %s)", err, pushErr.String())
	}
	if len(stored) == 0 {
		t.Fatal("git push uploaded an empty bundle")
	}

	fetchApp, fetchTransport, fetchOut, fetchErr := newDropTestApp(t, "")
	fetchTransport.respond = func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{StatusCode: http.StatusOK, Body: stored}, nil
	}
	fetchApp.cfg.GitBin = "git"
	if err := runInDirectory(t, target, func() error {
		return fetchApp.run([]string{"git", "fetch", "--id", testDropID, "--remote", "source"})
	}); err != nil {
		t.Fatalf("git fetch: %v (stderr %s)", err, fetchErr.String())
	}
	if !strings.Contains(fetchOut.String(), "git merge --ff-only source/main") {
		t.Fatalf("stdout = %s", fetchOut.String())
	}
	for _, ref := range []string{"refs/remotes/source/main", "refs/tags/v1"} {
		runGit(t, target, "rev-parse", "--verify", ref)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, output)
	}
}

// runInDirectory runs one command from a working directory, which the Git
// paths read through the git binary rather than through an option.
func runInDirectory(t *testing.T, dir string, run func() error) error {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Fatal(err)
		}
	}()
	return run()
}

// The menu is the only path that reads a payload from the terminal, so it has
// to reach the same request the flag-driven upload does.
func TestInteractiveUploadSendsTypedText(t *testing.T) {
	setTestV2Homes(t)
	t.Setenv("DUD_TEST_STDIN_TTY", "1")
	a, transport, stdout, stderr := newDropTestApp(t, "1\n\n\n2\n\n\n\nmenu payload")
	a.cfg.QREncodeBin = writeRecordingQREncode(t, filepath.Join(t.TempDir(), "qr.log"))
	transport.respond = uploadJSONResponder(testDropID)

	if err := a.run(nil); err != nil && err.Error() != "" {
		t.Fatalf("%v (stderr %s)", err, stderr.String())
	}
	if got := string(transport.only(t).Body); got != "menu payload" {
		t.Fatalf("uploaded body = %q", got)
	}
	if !strings.Contains(stdout.String(), "Payload:") {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if strings.Count(stderr.String(), "Enter plaintext, then press Ctrl-D when finished.") != 1 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
