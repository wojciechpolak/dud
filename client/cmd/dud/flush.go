// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// dropFlushResponseLimit bounds the sweep summary the admin route returns.
const dropFlushResponseLimit = 64 * 1024

// flushResponse is the sweep summary the admin route returns.
type flushResponse struct {
	OK           bool `json:"ok"`
	DeletedCount int  `json:"deletedCount"`
	Partial      bool `json:"partial"`
}

func (a *app) cmdFlush(args []string) error {
	baseURL := a.cfg.BaseURL
	jsonOutput := false
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
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			args = args[1:]
		default:
			return fatalError("Unknown flush option: " + args[0])
		}
	}
	if a.cfg.SecretToken == "" {
		return fatalError("flush requires DUD_DROP_SECRET")
	}
	headers := http.Header{}
	headers.Set("x-dud-secret-token", a.cfg.SecretToken)
	response, err := a.dropRequest(context.Background(), baseURL+"/v1/admin/flush", v2Request{
		Method:           http.MethodPost,
		Headers:          headers,
		MaxResponseBytes: dropFlushResponseLimit,
	})
	if err != nil {
		return err
	}
	// The server already answers in JSON, so --json passes its body through
	// unchanged rather than re-encoding fields this client does not own.
	if jsonOutput {
		a.out.Write(response.Body)
		fmt.Fprintln(a.out)
		return nil
	}
	summary := flushResponse{}
	if err := json.Unmarshal(response.Body, &summary); err != nil {
		// An origin that answered with something else is still worth showing;
		// the operator can read the body even when this client cannot parse it.
		a.out.Write(response.Body)
		fmt.Fprintln(a.out)
		return nil
	}
	report := &textReport{}
	sweep := report.section("")
	sweep.addf("Deleted", "%d", summary.DeletedCount)
	sweep.add("Complete", v2YesNo(!summary.Partial))
	if summary.Partial {
		sweep.note(
			"The sweep hit its iteration bound before the store was clean; " +
				"run it again to continue.",
		)
	}
	return report.write(a.out)
}
