// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"io"
	"os/exec"
	"regexp"
	"strings"
)

type gitFetchOptions struct {
	id         string
	baseURL    string
	identity   string
	remote     string
	dohURL     string
	outputJSON bool
}

func parseGitFetchOptions(args []string, defaultBaseURL, defaultDOHURL string) (gitFetchOptions, error) {
	opts := gitFetchOptions{
		baseURL: defaultBaseURL,
		remote:  "dud",
		dohURL:  defaultDOHURL,
	}

	for len(args) > 0 {
		switch args[0] {
		case "--id":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.id = args[1]
			args = args[2:]
		case "--identity", "-i":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.identity = args[1]
			args = args[2:]
		case "--remote":
			if err := needValue(args, args[0]); err != nil {
				return opts, err
			}
			opts.remote = args[1]
			args = args[2:]
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
		case "--json":
			if err := markJSONOption(&opts.outputJSON); err != nil {
				return opts, err
			}
			args = args[1:]
		default:
			return opts, fatalError("Unknown git fetch option: " + args[0])
		}
	}

	return opts, nil
}

func validateGitFetchOptions(opts gitFetchOptions) error {
	if opts.id == "" {
		return fatalError("git fetch requires --id")
	}
	return validateGitRemoteName(opts.remote)
}

func (a *app) cmdGit(args []string) error {
	if len(args) == 0 {
		return fatalError("git requires a subcommand: push, fetch, send, or receive")
	}
	subcommand := args[0]
	rest := args[1:]
	switch subcommand {
	case "push", "send":
		if len(rest) != 0 && !strings.HasPrefix(rest[0], "-") {
			return a.cmdV2GitPush(rest)
		}
		return a.cmdGitPush(rest)
	case "fetch", "receive":
		if len(rest) != 0 && !strings.HasPrefix(rest[0], "-") {
			return a.cmdV2GitFetch(rest)
		}
		return a.cmdGitFetch(rest)
	case "status":
		return a.cmdV2GitStatus(rest)
	case "help", "-h", "--help":
		a.usage()
		return nil
	default:
		return fatalError("Unknown git subcommand: " + subcommand)
	}
}

func (a *app) requireGitRepository(action string) error {
	cmd := exec.Command(a.cfg.GitBin, "rev-parse", "--git-dir")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fatalError("git " + action + " requires a Git repository")
	}
	return nil
}

func validateGitRemoteName(remote string) error {
	if remote == "" {
		return fatalError("git fetch requires a non-empty remote name")
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	if !valid.MatchString(remote) {
		return fatalError("git remote name may contain only letters, numbers, '.', '_', and '-'")
	}
	if strings.HasPrefix(remote, ".") || strings.HasSuffix(remote, ".") || strings.Contains(remote, "..") {
		return fatalError("git remote name must not start with '.', end with '.', or contain '..'")
	}
	return nil
}

func (a *app) gitBundleHintBranch(bundle string) string {
	cmd := exec.Command(a.cfg.GitBin, "ls-remote", bundle, "refs/heads/*")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	var branches []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		idx := strings.Index(line, "refs/heads/")
		if idx >= 0 {
			branches = append(branches, line[idx+len("refs/heads/"):])
		}
	}
	for _, branch := range branches {
		if branch == "main" {
			return "main"
		}
	}
	for _, branch := range branches {
		if branch == "master" {
			return "master"
		}
	}
	if len(branches) > 0 {
		return branches[0]
	}
	return ""
}

func (a *app) cmdGitPush(args []string) error {
	for _, arg := range args {
		if arg == "--file" || arg == "-m" {
			return fatalError("git push creates its own bundle and does not accept " + arg)
		}
	}
	if err := a.requireGitRepository("push"); err != nil {
		return err
	}
	bundleFile, err := tempFile("dud-git-push-bundle-")
	if err != nil {
		return err
	}
	defer removeTempFile(bundleFile)

	cmd := exec.Command(a.cfg.GitBin, "bundle", "create", bundleFile, "--branches", "--tags")
	cmd.Stdout = a.out
	cmd.Stderr = a.errOut
	if err := cmd.Run(); err != nil {
		return err
	}
	return a.cmdUpload(append([]string{"--file", bundleFile}, args...), "dud git fetch")
}

func (a *app) cmdGitFetch(args []string) error {
	opts, err := parseGitFetchOptions(args, a.cfg.BaseURL, a.cfg.DOHURL)
	if err != nil {
		return err
	}
	if err := validateGitFetchOptions(opts); err != nil {
		return err
	}
	if err := a.requireGitRepository("fetch"); err != nil {
		return err
	}
	a.cfg.DOHURL = opts.dohURL

	bundleFile, err := tempFile("dud-git-fetch-bundle-")
	if err != nil {
		return err
	}
	defer removeTempFile(bundleFile)

	downloadArgs := []string{"--id", opts.id, "--out", bundleFile, "--url", opts.baseURL}
	if opts.identity != "" {
		downloadArgs = append(downloadArgs, "-i", opts.identity)
	}
	if err := a.cmdDownload(downloadArgs); err != nil {
		return err
	}

	// Under --json the report owns stdout, so git's own chatter moves to
	// stderr rather than being interleaved into the document.
	gitOut := a.out
	if opts.outputJSON {
		gitOut = a.errOut
	}
	cmd := exec.Command(a.cfg.GitBin, "bundle", "verify", bundleFile)
	cmd.Stdout = gitOut
	cmd.Stderr = a.errOut
	if err := cmd.Run(); err != nil {
		return err
	}
	hintBranch := a.gitBundleHintBranch(bundleFile)
	cmd = exec.Command(a.cfg.GitBin, "fetch", bundleFile, "+refs/heads/*:refs/remotes/"+opts.remote+"/*", "refs/tags/*:refs/tags/*")
	cmd.Stdout = gitOut
	cmd.Stderr = a.errOut
	if err := cmd.Run(); err != nil {
		return err
	}
	if opts.outputJSON {
		return writeJSON(a.out, map[string]any{
			"ok":          true,
			"id":          opts.id,
			"remote":      opts.remote,
			"hint_branch": hintBranch,
		})
	}
	report := &textReport{}
	fetched := report.section("")
	fetched.add("Fetched into", "refs/remotes/"+opts.remote+"/*")
	if hintBranch != "" {
		fetched.addf("Apply with", "git merge --ff-only %s/%s", opts.remote, hintBranch)
	}
	return report.write(a.out)
}
