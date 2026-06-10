// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func (a *app) cmdTest(args []string) error {
	targetURL := a.cfg.BaseURL + "/v1/test"
	for len(args) > 0 {
		switch args[0] {
		case "--url":
			if err := needValue(args, args[0]); err != nil {
				return err
			}
			targetURL = args[1]
			args = args[2:]
		case "--doh-url":
			if err := needValue(args, args[0]); err != nil {
				return err
			}
			a.cfg.DOHURL = args[1]
			args = args[2:]
		default:
			return fatalError("Unknown test option: " + args[0])
		}
	}

	responseFile, err := tempFile("dud-test-response-")
	if err != nil {
		return err
	}
	defer removeTempFile(responseFile)
	traceFile, err := tempFile("dud-test-trace-")
	if err != nil {
		return err
	}
	defer removeTempFile(traceFile)

	trace, err := os.Create(traceFile)
	if err != nil {
		return err
	}
	curlErr := a.runSecureCurlWithStderr(trace, "--verbose", "--output", responseFile, targetURL)
	trace.Close()
	if curlErr != nil {
		traceData, _ := os.ReadFile(traceFile)
		fmt.Fprint(a.errOut, string(traceData))
		return curlErr
	}

	traceData, err := os.ReadFile(traceFile)
	if err == nil {
		a.printTestDetails(string(traceData))
	}
	fmt.Fprintln(a.out, "Response:")
	data, err := os.ReadFile(responseFile)
	if err != nil {
		return err
	}
	a.out.Write(data)
	fmt.Fprintln(a.out)
	return nil
}

func (a *app) printTestDetails(trace string) {
	lineValue := func(prefix string) string {
		for _, line := range strings.Split(trace, "\n") {
			if strings.HasPrefix(line, prefix) {
				return strings.TrimPrefix(line, prefix)
			}
		}
		return ""
	}

	tlsSummary := lineValue("* SSL connection using ")
	alpnSummary := lineValue("* ALPN: server accepted ")
	echStatus, echInner, echOuter := parseECHTrace(trace)

	fmt.Fprintln(a.out, "Transport:")
	fmt.Fprintf(a.out, "  doh resolver: %s\n", a.cfg.DOHURL)
	fmt.Fprintf(a.out, "  ech mode: %s\n", a.cfg.ECHMode)
	if tlsSummary != "" {
		fmt.Fprintf(a.out, "  tls: %s\n", tlsSummary)
	}
	if alpnSummary != "" {
		fmt.Fprintf(a.out, "  alpn: %s\n", alpnSummary)
	}
	if echStatus != "" {
		fmt.Fprintf(a.out, "  ech: %s\n", echStatus)
	} else {
		fmt.Fprintln(a.out, "  ech: unavailable")
	}
	if echInner != "" {
		fmt.Fprintf(a.out, "  inner sni: %s\n", echInner)
	}
	if echOuter != "" {
		fmt.Fprintf(a.out, "  outer sni: %s\n", echOuter)
	}
}

var (
	echStatusRe = regexp.MustCompile(`^\* ECH: result: status is ([^,]*)`)
	echFullRe   = regexp.MustCompile(`^\* ECH: result: status is [^,]*, inner is ([^,]*), outer is (.*)$`)
)

// parseECHTrace mirrors the shell version's three independent sed
// passes: the status must be reported even when curl prints a
// status-only line (grease mode, ECH failures) without the
// "inner is ..., outer is ..." part.
func parseECHTrace(trace string) (string, string, string) {
	status, inner, outer := "", "", ""
	for _, line := range strings.Split(trace, "\n") {
		if status == "" {
			if m := echStatusRe.FindStringSubmatch(line); m != nil {
				status = m[1]
			}
		}
		if inner == "" && outer == "" {
			if m := echFullRe.FindStringSubmatch(line); m != nil {
				inner, outer = m[1], m[2]
			}
		}
	}
	return status, inner, outer
}
