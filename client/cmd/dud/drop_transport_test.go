// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The dead drop commands reach the network only through the injected
// transport seam, so these helpers stand in for a server without one running.

type recordedDropRequest struct {
	Method        string
	Origin        string
	Path          string
	Headers       http.Header
	Body          []byte
	ContentLength int64
	Streamed      bool
}

func (request recordedDropRequest) header(name string) string {
	return request.Headers.Get(name)
}

type dropTestTransport struct {
	options  []v2TransportOptions
	requests []recordedDropRequest
	// respond answers each recorded request. A nil respond returns 200 with an
	// empty body.
	respond func(recordedDropRequest) (*v2Response, error)
}

func (transport *dropTestTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	recorded := recordedDropRequest{
		Method:        request.Method,
		Origin:        request.Origin,
		Path:          request.Path,
		Headers:       request.Headers.Clone(),
		Body:          append([]byte(nil), request.Body...),
		ContentLength: request.ContentLength,
		Streamed:      request.StreamResponse,
	}
	if recorded.Headers == nil {
		recorded.Headers = http.Header{}
	}
	if request.BodyStream != nil {
		body, err := io.ReadAll(request.BodyStream)
		if err != nil {
			return nil, err
		}
		if int64(len(body)) != request.ContentLength {
			return nil, errors.New("streaming request declared the wrong ContentLength")
		}
		recorded.Body = body
	}
	transport.requests = append(transport.requests, recorded)

	response := &v2Response{StatusCode: http.StatusOK}
	if transport.respond != nil {
		var err error
		response, err = transport.respond(recorded)
		if err != nil {
			return nil, err
		}
	}
	if request.StreamResponse && response.Stream == nil {
		response.Stream = io.NopCloser(bytes.NewReader(response.Body))
		response.Body = nil
	}
	return response, nil
}

func (transport *dropTestTransport) only(t *testing.T) recordedDropRequest {
	t.Helper()
	if len(transport.requests) != 1 {
		t.Fatalf("dead drop requests = %d, want exactly 1", len(transport.requests))
	}
	return transport.requests[0]
}

// newDropTestApp wires an app to a recording transport and a pass-through age
// so a whole command can run end to end without a network or real crypto.
func newDropTestApp(t *testing.T, stdin string) (*app, *dropTestTransport, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	transport := &dropTestTransport{}
	a := newApp(strings.NewReader(stdin), &stdout, &stderr)
	a.cfg.AgeBin = writePassthroughAge(t)
	a.cfg.SecretToken = "top-secret"
	a.cfg.BaseURL = "https://dud.example.com"
	a.cfg.DOHURL = "https://cloudflare-dns.com/dns-query"
	a.cfg.ECHMode = "hard"
	a.newV2Transport = func(options v2TransportOptions) (v2Transport, error) {
		transport.options = append(transport.options, options)
		return transport, nil
	}
	return a, transport, &stdout, &stderr
}

func uploadJSONResponder(id string) func(recordedDropRequest) (*v2Response, error) {
	body := `{"id":"` + id + `","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}`
	return func(recordedDropRequest) (*v2Response, error) {
		return &v2Response{
			StatusCode:  http.StatusOK,
			ContentType: "application/json",
			Body:        []byte(body),
		}, nil
	}
}

func TestSplitDropURLAcceptsBaseAndCompleteURLs(t *testing.T) {
	tests := []struct {
		raw        string
		wantOrigin string
		wantPath   string
	}{
		{"https://dud.example.com/v1/files", "https://dud.example.com", "/v1/files"},
		{"https://dud.example.com", "https://dud.example.com", "/"},
		{"https://dud.example.com:8443/v1/test", "https://dud.example.com:8443", "/v1/test"},
		{"https://dud.example.com:443/v1/test", "https://dud.example.com", "/v1/test"},
		// A base URL written with a trailing slash must not turn into a
		// scheme-relative path once a route is appended to it.
		{"https://dud.example.com//v1/files", "https://dud.example.com", "/v1/files"},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			origin, path, err := splitDropURL(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if origin != test.wantOrigin || path != test.wantPath {
				t.Fatalf("split = %q %q, want %q %q", origin, path, test.wantOrigin, test.wantPath)
			}
		})
	}
}

func TestSplitDropURLRejectsUnusableTargets(t *testing.T) {
	for _, raw := range []string{
		"http://dud.example.com/v1/test",
		"https://dud.example.com/v1/test?x=1",
		"https://dud.example.com/v1/test#fragment",
		"https://192.0.2.1/v1/test",
		"https://user:pass@dud.example.com/v1/test",
		"https://localhost/v1/test",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := splitDropURL(raw); err == nil {
				t.Fatalf("%q was accepted", raw)
			}
		})
	}
}

// Every dead drop command must hand the transport the same resolver, ECH mode,
// and CA bundle the configuration selected.
func TestDropCommandsBuildTheTransportFromConfiguration(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(bundle, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
	}{
		{"test", []string{"test"}},
		{"upload", []string{"upload", "--passphrase", "-m", "hello", "--json"}},
		{"download", []string{"download", "--id", "abcd", "--stdout"}},
		{"flush", []string{"flush"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a, transport, _, stderr := newDropTestApp(t, "")
			transport.respond = uploadJSONResponder("aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")
			a.cfg.DOHURL = "https://resolver.example.test/dns-query"
			a.cfg.ECHMode = "off"
			a.cfg.CABundle = bundle
			if err := a.run(test.args); err != nil {
				t.Fatalf("%v: %v (stderr %s)", test.args, err, stderr.String())
			}
			if len(transport.options) != 1 {
				t.Fatalf("transports built = %d, want 1", len(transport.options))
			}
			options := transport.options[0]
			if options.DOHURL != "https://resolver.example.test/dns-query" ||
				options.ECHMode != "off" ||
				options.CABundle != bundle {
				t.Fatalf("transport options = %#v", options)
			}
		})
	}
}

// DUD_CONNECT_TO reaches the transport, which is what refuses it. The commands
// must not quietly drop it on the floor instead.
func TestDropCommandsForwardConnectToSoTheTransportCanRefuseIt(t *testing.T) {
	a, transport, _, _ := newDropTestApp(t, "")
	a.cfg.ConnectTo = "dud.example.com:443:127.0.0.1:8443"
	if err := a.run([]string{"flush"}); err != nil {
		t.Fatal(err)
	}
	if transport.options[0].ConnectTo != "dud.example.com:443:127.0.0.1:8443" {
		t.Fatalf("ConnectTo = %q", transport.options[0].ConnectTo)
	}

	// And the production transport is the thing that rejects it.
	if _, err := newProductionV2Transport(v2TransportOptions{
		DOHURL:    "https://cloudflare-dns.com/dns-query",
		ECHMode:   "hard",
		ConnectTo: "dud.example.com:443:127.0.0.1:8443",
	}); err == nil || !strings.Contains(err.Error(), "DUD_CONNECT_TO") {
		t.Fatalf("production transport accepted DUD_CONNECT_TO: %v", err)
	}
}

// A resolution failure names the layer that chose the target, so the commands
// have to hand the transport that provenance. Drop commands read only DUD_* and
// the compiled defaults, and each resolves its own --url, so the effective
// origin is what distinguishes an override from the configured base URL.
func TestDropCommandsReportWhichLayerChoseTheTarget(t *testing.T) {
	tests := []struct {
		name          string
		environment   string
		echEnv        string
		args          []string
		wantOrigin    string
		wantECHSource string
	}{
		{
			name:          "compiled defaults",
			args:          []string{"flush"},
			wantOrigin:    v2NetworkSourceDefault,
			wantECHSource: v2NetworkSourceDefault,
		},
		{
			name:          "environment",
			environment:   "https://drops.example.test",
			echEnv:        "hard",
			args:          []string{"flush"},
			wantOrigin:    v2NetworkSourceEnvironment,
			wantECHSource: v2NetworkSourceEnvironment,
		},
		{
			name:          "command line",
			args:          []string{"flush", "--url", "https://other.example.test"},
			wantOrigin:    v2NetworkSourceCLI,
			wantECHSource: v2NetworkSourceDefault,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DUD_BASE_URL", test.environment)
			t.Setenv("DUD_ECH_MODE", test.echEnv)
			a, transport, _, stderr := newDropTestApp(t, "")
			transport.respond = uploadJSONResponder("aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa")
			if test.environment != "" {
				a.cfg.BaseURL = test.environment
			}
			if err := a.run(test.args); err != nil {
				t.Fatalf("%v: %v (stderr %s)", test.args, err, stderr.String())
			}
			options := transport.options[0]
			if options.OriginSource != test.wantOrigin || options.ECHModeSource != test.wantECHSource {
				t.Fatalf("sources = %q/%q, want %q/%q",
					options.OriginSource, options.ECHModeSource, test.wantOrigin, test.wantECHSource)
			}
		})
	}
}

func TestDropCommandsRejectAnInvalidECHMode(t *testing.T) {
	a, _, _, _ := newDropTestApp(t, "")
	a.cfg.ECHMode = "soft"
	err := a.run([]string{"flush"})
	if err == nil || err.Error() != "DUD_ECH_MODE must be either 'hard' or 'off'" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDropTransportUsesTLS13AndECHFromTheProductionOptions(t *testing.T) {
	config, err := newV2TLSConfig("", "dud.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS version window = %d..%d", config.MinVersion, config.MaxVersion)
	}
}
