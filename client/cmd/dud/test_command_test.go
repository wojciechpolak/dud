// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func healthyConnection() *v2ConnectionInfo {
	return &v2ConnectionInfo{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_256_GCM_SHA384,
		NegotiatedProtocol: "h2",
		ServerName:         "dud.example.com",
		ECHAccepted:        true,
		ECHPublicName:      "cloudflare-ech.com",
	}
}

func connectionResponder(connection *v2ConnectionInfo, body string) func(recordedDropRequest) (*v2Response, error) {
	return func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{
			StatusCode:  http.StatusOK,
			ContentType: "application/json",
			Body:        []byte(body),
			TLS:         connection,
		}, nil
	}
}

func TestTestCommandReportsTheConnectionState(t *testing.T) {
	a, transport, stdout, _ := newDropTestApp(t, "")
	transport.respond = connectionResponder(healthyConnection(), `{"ok":true}`)

	if err := a.run([]string{"test"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Transport",
		"  doh resolver  https://cloudflare-dns.com/dns-query",
		"  ech mode      hard",
		"  ech           succeeded",
		"  tls           TLSv1.3 / TLS_AES_256_GCM_SHA384",
		"  alpn          h2",
		"  inner sni     dud.example.com",
		"  outer sni     cloudflare-ech.com",
		"Response:\n{\"ok\":true}",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout omitted %q:\n%s", want, stdout.String())
		}
	}
}

// The JSON report describes the handshake that happened rather than the mode
// that was requested, so a server that ignored ECH is visible to a script.
func TestTestCommandJSONReportsTheNegotiatedTransport(t *testing.T) {
	a, transport, stdout, _ := newDropTestApp(t, "")
	transport.respond = connectionResponder(healthyConnection(), `{"ok":true}`)

	if err := a.run([]string{"test", "--json"}); err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	for key, want := range map[string]any{
		"ok":           true,
		"doh_url":      "https://cloudflare-dns.com/dns-query",
		"ech_mode":     "hard",
		"ech":          "succeeded",
		"tls_version":  "TLSv1.3",
		"cipher_suite": "TLS_AES_256_GCM_SHA384",
		"alpn":         "h2",
		"inner_sni":    "dud.example.com",
		"outer_sni":    "cloudflare-ech.com",
		"response":     `{"ok":true}`,
	} {
		if report[key] != want {
			t.Fatalf("report[%q] = %#v, want %#v", key, report[key], want)
		}
	}
}

// Hard mode must assert the accepted handshake itself. Trusting a rejected
// handshake to have failed the connection would report an unprotected
// connection as protected.
func TestTestCommandRequiresAnAcceptedECHHandshakeInHardMode(t *testing.T) {
	connection := healthyConnection()
	connection.ECHAccepted = false
	connection.ECHPublicName = ""

	a, transport, stdout, _ := newDropTestApp(t, "")
	transport.respond = connectionResponder(connection, `{"ok":true}`)

	err := a.run([]string{"test"})
	if err == nil || !strings.Contains(err.Error(), "accepted ECH handshake") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stdout.String(), "ech           succeeded") {
		t.Fatalf("a rejected handshake was reported as succeeded:\n%s", stdout.String())
	}
}

func TestTestCommandReportsECHOffWithoutFailing(t *testing.T) {
	connection := healthyConnection()
	connection.ECHAccepted = false
	connection.ECHPublicName = ""

	a, transport, stdout, _ := newDropTestApp(t, "")
	a.cfg.ECHMode = "off"
	transport.respond = connectionResponder(connection, `{"ok":true}`)

	if err := a.run([]string{"test"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "ech mode      off") ||
		!strings.Contains(stdout.String(), "ech           not attempted") {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "outer sni") {
		t.Fatalf("an unused ECH config reported an outer SNI:\n%s", stdout.String())
	}
}

func TestTestCommandHonorsTheURLAndResolverOverrides(t *testing.T) {
	a, transport, stdout, _ := newDropTestApp(t, "")
	a.cfg.ECHMode = "off"
	transport.respond = connectionResponder(nil, `{"ok":true}`)

	if err := a.run([]string{
		"test",
		"--url", "https://alt.example.test/v1/test",
		"--doh-url", "https://resolver.example.test/dns-query",
	}); err != nil {
		t.Fatal(err)
	}
	request := transport.only(t)
	if request.Origin != "https://alt.example.test" || request.Path != "/v1/test" {
		t.Fatalf("target = %s%s", request.Origin, request.Path)
	}
	if transport.options[0].DOHURL != "https://resolver.example.test/dns-query" {
		t.Fatalf("resolver = %q", transport.options[0].DOHURL)
	}
	if !strings.Contains(stdout.String(), "doh resolver  https://resolver.example.test/dns-query") {
		t.Fatalf("stdout = %s", stdout.String())
	}
}

// The public name of the ECHConfig the handshake used is a property of the
// validated configuration, so it can be reported without parsing a trace.
func TestECHPublicNameComesFromTheConfigList(t *testing.T) {
	list := buildECHConfigList(t, "cloudflare-ech.com")
	if err := validateECHConfigList(list); err != nil {
		t.Fatal(err)
	}
	if got := v2ECHPublicName(list); got != "cloudflare-ech.com" {
		t.Fatalf("public name = %q", got)
	}
}

func TestECHPublicNameRejectsMalformedLists(t *testing.T) {
	list := buildECHConfigList(t, "cloudflare-ech.com")
	for _, truncated := range []int{0, 2, 5, len(list) - 1} {
		if got := v2ECHPublicName(list[:truncated]); got != "" {
			t.Fatalf("truncated list of %d bytes yielded %q", truncated, got)
		}
	}
	// A list carrying only an unsupported version has no usable public name.
	unsupported := append([]byte(nil), list...)
	unsupported[2], unsupported[3] = 0xfe, 0x0a
	if got := v2ECHPublicName(unsupported); got != "" {
		t.Fatalf("unsupported version yielded %q", got)
	}
}

// buildECHConfigList assembles a draft-13 ECHConfigList around one public
// name, matching the layout crypto/tls parses.
func buildECHConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	var contents []byte
	contents = append(contents, 0x01)                   // config_id
	contents = append(contents, 0x00, 0x20)             // kem_id
	contents = append(contents, 0x00, 0x04)             // public_key length
	contents = append(contents, 0xaa, 0xbb, 0xcc, 0xdd) // public_key
	contents = append(contents, 0x00, 0x04)             // cipher_suites length
	contents = append(contents, 0x00, 0x01, 0x00, 0x01) // one suite
	contents = append(contents, 0x40)                   // maximum_name_length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0x00, 0x00) // extensions

	config := []byte{0xfe, 0x0d, byte(len(contents) >> 8), byte(len(contents))}
	config = append(config, contents...)
	return append([]byte{byte(len(config) >> 8), byte(len(config))}, config...)
}
