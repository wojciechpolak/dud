// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "fmt"

func (a *app) cmdFlush(args []string) error {
	baseURL := a.cfg.BaseURL
	for len(args) > 0 {
		switch args[0] {
		case "--url":
			if err := needValue(args, args[0]); err != nil {
				return err
			}
			baseURL = args[1]
			args = args[2:]
		case "--doh-url":
			if err := needValue(args, args[0]); err != nil {
				return err
			}
			a.cfg.DOHURL = args[1]
			args = args[2:]
		default:
			return fatalError("Unknown flush option: " + args[0])
		}
	}
	if a.cfg.SecretToken == "" {
		return fatalError("flush requires DUD_SECRET_TOKEN")
	}
	if err := a.runSecureCurl("-X", "POST", "-H", "x-dud-secret-token: "+a.cfg.SecretToken, baseURL+"/v1/admin/flush"); err != nil {
		return err
	}
	fmt.Fprintln(a.out)
	return nil
}
