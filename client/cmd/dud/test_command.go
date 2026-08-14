// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
)

// dropTestResponseLimit bounds the health-check body the route returns.
const dropTestResponseLimit = 64 * 1024

func (a *app) cmdTest(args []string) error {
	targetURL := a.cfg.BaseURL + "/v1/test"
	jsonOutput := false
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
		case "--json":
			if err := markJSONOption(&jsonOutput); err != nil {
				return err
			}
			args = args[1:]
		default:
			return fatalError("Unknown test option: " + args[0])
		}
	}

	response, err := a.dropRequest(context.Background(), targetURL, v2Request{
		Method:           http.MethodGet,
		MaxResponseBytes: dropTestResponseLimit,
	})
	if err != nil {
		return err
	}
	// Hard mode asserts the accepted handshake rather than trusting a
	// rejection to have failed the connection: a server that silently ignores
	// ECH would otherwise be reported as protected.
	if a.cfg.ECHMode == "hard" && (response.TLS == nil || !response.TLS.ECHAccepted) {
		return fatalError("ECH hard mode requires an accepted ECH handshake, and this connection did not complete one")
	}
	if jsonOutput {
		return writeJSON(a.out, a.testReport(targetURL, response))
	}
	if err := a.printTestDetails(targetURL, response).write(a.out); err != nil {
		return err
	}
	fmt.Fprintln(a.out, "\nResponse:")
	a.out.Write(response.Body)
	fmt.Fprintln(a.out)
	return nil
}

// testReport describes the transport the health check actually negotiated.
// It reports what the connection did, not what was configured, so a server
// that quietly ignored ECH is visible rather than assumed.
func (a *app) testReport(targetURL string, response *v2Response) map[string]any {
	report := map[string]any{
		"ok":           true,
		"url":          targetURL,
		"doh_url":      a.cfg.DOHURL,
		"ech_mode":     a.cfg.ECHMode,
		"status":       response.StatusCode,
		"response":     string(response.Body),
		"ech":          v2TestECHState(response.TLS),
		"tls_version":  "",
		"cipher_suite": "",
		"alpn":         "",
		"inner_sni":    "",
		"outer_sni":    "",
	}
	if connection := response.TLS; connection != nil {
		report["tls_version"] = tlsVersionName(connection.Version)
		report["cipher_suite"] = tls.CipherSuiteName(connection.CipherSuite)
		report["alpn"] = connection.NegotiatedProtocol
		report["inner_sni"] = connection.ServerName
		report["outer_sni"] = connection.ECHPublicName
	}
	return report
}

func v2TestECHState(connection *v2ConnectionInfo) string {
	switch {
	case connection == nil:
		return "unavailable"
	case connection.ECHAccepted:
		return "succeeded"
	default:
		return "not attempted"
	}
}

func (a *app) printTestDetails(targetURL string, response *v2Response) *textReport {
	out := &textReport{}
	transport := out.section("Transport")
	transport.add("url", targetURL)
	transport.add("doh resolver", a.cfg.DOHURL)
	transport.add("ech mode", a.cfg.ECHMode)
	transport.add("ech", v2TestECHState(response.TLS))
	connection := response.TLS
	if connection == nil {
		return out
	}
	transport.addf("tls", "%s / %s", tlsVersionName(connection.Version), tls.CipherSuiteName(connection.CipherSuite))
	if connection.NegotiatedProtocol != "" {
		transport.add("alpn", connection.NegotiatedProtocol)
	}
	if connection.ServerName != "" {
		transport.add("inner sni", connection.ServerName)
	}
	if connection.ECHPublicName != "" {
		transport.add("outer sni", connection.ECHPublicName)
	}
	return out
}

// tlsVersionName keeps the "TLSv1.3" spelling the summary has always used;
// tls.VersionName writes it as "TLS 1.3".
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return tls.VersionName(version)
	}
}
