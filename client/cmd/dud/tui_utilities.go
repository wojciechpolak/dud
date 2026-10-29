// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"errors"
	"strings"
)

func isTUIUtilityAction(action string) bool {
	return strings.HasPrefix(action, "git-") || strings.HasPrefix(action, "erase-") || strings.HasPrefix(action, "peer-") || action == "keygen" || action == "keygen-convert" || action == "transport-test" || action == "flush"
}

func newTUIUtilityForm(action string, deadDrop bool) *tuiForm {
	form := &tuiForm{action: action}
	add := form.addInput
	check := func(key, label string, checked bool) {
		form.fields = append(form.fields, tuiField{key: key, label: label, toggle: true, checked: checked})
	}
	switch action {
	case "git-push":
		ttl := "168h"
		if deadDrop {
			ttl = "24h"
			add("url", "Dead drop server URL", "")
			add("recipient", "Age recipient (blank: age asks for a passphrase)", "")
		} else {
			add("branches", "Selected branches, separated by spaces (blank: all)", "")
			check("current", "Current branch only", false)
			add("mode", "Checkpoint mode (auto, full or incremental)", "auto")
		}
		add("ttl", "Lifetime", ttl)
		if deadDrop {
			check("delete", "Delete after read", false)
		}
	case "git-fetch":
		if deadDrop {
			add("url", "Dead drop server URL", "")
			add("id", "Dead drop ID", "")
			add("identity", "Age identity file (blank: age asks for a passphrase)", "")
			add("remote", "Remote-tracking name", "dud")
		} else {
			check("associate", "Associate this repository with the incoming peer checkpoint", false)
			check("rewrite", "Allow rewriting remote-tracking refs", false)
		}
	case "transport-test", "flush":
		add("url", "Dead drop server URL", "")
	case "keygen":
		add("out", "Private identity output file (required)", "")
		add("recipients", "Recipient output file (optional)", "")
		check("pq", "Post-quantum identity", false)
	case "keygen-convert":
		add("identity", "Input identity file", "")
		add("out", "Recipient output file (blank: display public recipients)", "")
	case "peer-rename":
		add("alias", "New local peer alias", "")
	case "peer-remove":
		check("confirm", "Remove this peer and its pending local state", false)
	case "peer-revoke":
		check("confirm", "Revoke this peer and disable its server capabilities", false)
	default:
		check("dry", "Inspect only, without erasing", true)
		if action == "erase-all" {
			check("repo", "Include repository state", false)
		}
		check("confirm", "Permanently erase the selected local state", false)
	}
	form.setTheme(defaultTUITheme())
	return form
}

func (model *tuiModel) prepareUtilityForm() {
	if !isTUIUtilityAction(model.form.action) {
		return
	}
	for index := range model.form.fields {
		field := &model.form.fields[index]
		if field.key == "url" {
			field.input.SetValue(model.app.cfg.DropBaseURL)
		}
	}
}

func (form *tuiForm) utilityArguments(target tuiItem, cfg config) ([]string, error) {
	switch form.action {
	case "git-push":
		return form.gitPushArguments(target, cfg)
	case "git-fetch":
		return form.gitFetchArguments(target, cfg)
	case "transport-test":
		if _, _, err := splitDropURL(form.value("url")); err != nil {
			return nil, err
		}
		return []string{"test", "--url", strings.TrimRight(form.value("url"), "/") + "/v1/test"}, nil
	case "flush":
		return []string{"flush", "--url", form.value("url")}, nil
	case "keygen", "keygen-convert":
		return form.keygenArguments()
	case "peer-rename":
		if err := validateV2PeerAlias(form.value("alias")); err != nil {
			return nil, err
		}
		return []string{"peer", "rename", target.id, form.value("alias")}, nil
	case "peer-remove", "peer-revoke":
		if !form.checked("confirm") {
			return nil, errors.New("Confirm the selected peer operation before running it.")
		}
		return []string{"peer", strings.TrimPrefix(form.action, "peer-"), target.id, "--yes"}, nil
	default:
		args := []string{"erase", strings.TrimPrefix(form.action, "erase-")}
		if form.action == "erase-peer" {
			args = append(args, target.id)
		}
		if form.checked("repo") {
			args = append(args, "--repo")
		}
		if form.checked("dry") {
			return append(args, "--dry-run"), nil
		}
		if !form.checked("confirm") {
			return nil, errors.New("Confirm permanent erasure, or keep Inspect only selected.")
		}
		return append(args, "--yes"), nil
	}
}

func (form *tuiForm) gitPushArguments(target tuiItem, cfg config) ([]string, error) {
	args := []string{"git", "push"}
	if target.deadDrop {
		args = append(args, "--ttl", form.value("ttl"))
		if url := form.value("url"); url != "" {
			args = append(args, "--url", url)
		}
		if recipient := form.value("recipient"); recipient != "" {
			args = append(args, "--recipient", recipient)
		} else {
			args = append(args, "--passphrase")
		}
		if form.checked("delete") {
			args = append(args, "--delete-after-read")
		}
		opts, err := parseUploadOptions(args[2:], cfg.DropBaseURL, cfg.DOHURL)
		if err != nil {
			return nil, err
		}
		return args, validateUploadOptions(opts, cfg)
	}
	args = append(args, target.id, "--ttl", form.value("ttl"))
	if form.checked("current") {
		args = append(args, "--current")
	}
	for _, branch := range strings.Fields(form.value("branches")) {
		args = append(args, "--branch", branch)
	}
	switch form.value("mode") {
	case "auto":
	case "full":
		args = append(args, "--full")
	case "incremental":
		args = append(args, "--incremental")
	default:
		return nil, errors.New("Checkpoint mode must be auto, full or incremental.")
	}
	_, err := parseV2GitPushOptions(args[2:])
	return args, err
}

func (form *tuiForm) gitFetchArguments(target tuiItem, cfg config) ([]string, error) {
	args := []string{"git", "fetch"}
	if target.deadDrop {
		args = append(args, "--id", form.value("id"), "--remote", form.value("remote"))
		if url := form.value("url"); url != "" {
			args = append(args, "--url", url)
		}
		if identity := form.value("identity"); identity != "" {
			args = append(args, "--identity", identity)
		}
		opts, err := parseGitFetchOptions(args[2:], cfg.DropBaseURL, cfg.DOHURL)
		if err != nil {
			return nil, err
		}
		return args, validateGitFetchOptions(opts)
	}
	args = append(args, target.id)
	if form.checked("associate") {
		args = append(args, "--associate")
	}
	if form.checked("rewrite") {
		args = append(args, "--allow-rewrite")
	}
	_, err := parseV2GitFetchOptions(args[2:])
	return args, err
}

func (form *tuiForm) keygenArguments() ([]string, error) {
	args := []string{"keygen"}
	if form.action == "keygen-convert" {
		if form.value("identity") == "" {
			return nil, errors.New("Choose an input identity file.")
		}
		args = append(args, form.value("identity"))
	} else {
		if form.value("out") == "" || form.value("out") == "-" {
			return nil, errors.New("Choose a private identity output file.")
		}
		if form.checked("pq") {
			args = append(args, "--pq")
		}
	}
	if out := form.value("out"); out != "" {
		args = append(args, "--out", out)
	}
	if recipients := form.value("recipients"); recipients != "" {
		args = append(args, "-R", recipients)
	}
	opts, err := parseKeygenOptions(args[1:])
	if err != nil {
		return nil, err
	}
	return args, validateKeygenOptions(opts)
}
