// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package main

func (a *app) cmdOptical(args []string) error {
	if len(args) == 0 {
		return fatalError("optical requires send or decrypt")
	}
	switch args[0] {
	case "send":
		return a.cmdUpload(append([]string{"--optical"}, args[1:]...), "dud optical decrypt")
	case "decrypt":
		opts, err := parseDownloadOptions(args[1:], "", "")
		if err != nil {
			return a.reportOpticalDecryptFailure(opticalDecryptFlagPresent(args[1:], "--json"), opticalFailure("usage", "Invalid optical decrypt arguments"))
		}
		if err := validateOpticalDecryptOptions(opts); err != nil {
			return a.reportOpticalDecryptFailure(opts.outputJSON, err)
		}
		return a.cmdOpticalDecrypt(opts)
	default:
		return fatalError("Unknown optical command: " + safeTerminalText(args[0]))
	}
}
