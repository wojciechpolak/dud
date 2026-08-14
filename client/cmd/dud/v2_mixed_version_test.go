// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The mixed-version matrix has three server shapes. A V1 client and a V2 client
// must each behave predictably against all three, and neither may quietly
// downgrade or half-complete an operation on the wrong one.
type v2ServerShape struct {
	name      string
	v1Routes  bool
	v2Routes  bool
	protocols []uint64
	document  []byte
}

var v2ServerShapes = []v2ServerShape{
	{name: "v1-only", v1Routes: true},
	{name: "dual-stack", v1Routes: true, v2Routes: true, protocols: []uint64{1, 2}},
	{name: "v2-only", v2Routes: true, protocols: []uint64{2}},
}

// encodeV2CapabilityDocument rebuilds the frozen discovery vector with a
// different protocol registry, which is the only field a deployment's V1 flag
// changes.
func encodeV2CapabilityDocument(t *testing.T, protocols []uint64) []byte {
	t.Helper()
	frozen, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := decodeV2Capabilities(frozen)
	if err != nil {
		t.Fatal(err)
	}
	document, err := v2EncMode.Marshal(map[int]any{
		1: protocols,
		2: capabilities.Features,
		3: capabilities.Limits,
		4: capabilities.Enforcement,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeV2Capabilities(document); err != nil {
		t.Fatalf("rebuilt capability document is invalid: %v", err)
	}
	return document
}

var errMixedVersionStop = errors.New("stop after capability discovery")

// mixedVersionTransport answers discovery for one server shape and refuses
// everything after it, so a test observes the version decision alone.
type mixedVersionTransport struct {
	shape     v2ServerShape
	discovery int
}

func (transport *mixedVersionTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	if request.Method == "GET" && request.Path == "/v2/capabilities" {
		transport.discovery++
		if !transport.shape.v2Routes {
			return &v2Response{StatusCode: 404, ContentType: "text/html; charset=utf-8"}, nil
		}
		return &v2Response{
			StatusCode:  200,
			ContentType: v2CBORContentType,
			Body:        transport.shape.document,
		}, nil
	}
	return nil, errMixedVersionStop
}

// newMixedVersionTransport attaches the discovery document a shape would serve,
// which is nothing at all for a deployment without V2 routes.
func newMixedVersionTransport(t *testing.T, shape v2ServerShape) *mixedVersionTransport {
	t.Helper()
	if shape.v2Routes {
		shape.document = encodeV2CapabilityDocument(t, shape.protocols)
	}
	return &mixedVersionTransport{shape: shape}
}

// mixedVersionDropTransport serves only the dead drop routes a shape exposes
// and answers 404 for the rest, which is the status the CLI turns into the
// exit code a shell sees.
type mixedVersionDropTransport struct {
	shape v2ServerShape
	paths []string
}

func (transport *mixedVersionDropTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.paths = append(transport.paths, request.Path)
	if request.BodyStream != nil {
		if _, err := io.Copy(io.Discard, request.BodyStream); err != nil {
			return nil, err
		}
	}
	served := strings.HasPrefix(request.Path, "/v1/") && transport.shape.v1Routes ||
		strings.HasPrefix(request.Path, "/v2/") && transport.shape.v2Routes
	if !served {
		return &v2Response{StatusCode: 404}, nil
	}
	body := []byte(`{"id":"aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa",` +
		`"expiresAt":"2026-01-01T00:00:00.000Z","deleteAfterRead":false}`)
	if request.StreamResponse {
		return &v2Response{StatusCode: 200, Stream: io.NopCloser(bytes.NewReader(body))}, nil
	}
	return &v2Response{StatusCode: 200, Body: body}, nil
}

func writePassthroughAge(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "age-mock.sh")
	script := `#!/bin/sh
output=""
input=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2; continue ;;
    -*) shift; continue ;;
  esac
  input="$1"
  shift
done
if [ -n "$input" ] && [ -n "$output" ]; then cp "$input" "$output"; fi
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// A dead drop client only ever speaks /v1. It must keep working against a
// dual-stack deployment and fail with a usable exit code against a V2-only
// one, never with a partial local result.
func TestLegacyCommandsAcrossServerShapes(t *testing.T) {
	for _, shape := range v2ServerShapes {
		t.Run(shape.name, func(t *testing.T) {
			transport := &mixedVersionDropTransport{shape: shape}
			wantCode := 0
			if !shape.v1Routes {
				wantCode = 22
			}
			for _, invocation := range [][]string{
				{"upload", "--passphrase", "-m", "hello", "--json"},
				{"download", "--id", strings.Repeat("a", 32), "--out", filepath.Join(t.TempDir(), "out")},
				{"flush"},
			} {
				a, _, _, stderr := newDropTestApp(t, "passphrase\n")
				a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
				if code := a.main(invocation); code != wantCode {
					t.Fatalf("%v exit = %d, want %d (stderr %s)", invocation, code, wantCode, stderr.String())
				}
			}
			for _, path := range transport.paths {
				if strings.HasPrefix(path, "/v2/") {
					t.Fatalf("a dead drop command negotiated a v2 route: %s", path)
				}
			}
		})
	}
}

// Peer operations require protocol v2. Against a V1-only deployment they must
// refuse with a usable alternative; a deployment's V1 flag must otherwise make
// no difference to them.
func TestPeerCapabilityDiscoveryAcrossServerShapes(t *testing.T) {
	for _, shape := range v2ServerShapes {
		t.Run(shape.name, func(t *testing.T) {
			transport := newMixedVersionTransport(t, shape)
			capabilities, err := requireV2Features(
				context.Background(),
				transport,
				"https://dud.example.com",
				2, 3, 9, 10, 11,
			)
			if transport.discovery != 1 {
				t.Fatalf("discovery requests = %d", transport.discovery)
			}
			if !shape.v2Routes {
				if err == nil ||
					!strings.Contains(err.Error(), "does not offer protocol v2") ||
					!strings.Contains(err.Error(), "dud upload --file PATH") {
					t.Fatalf("legacy refusal = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("peer discovery failed: %v", err)
			}
			if !containsV2Uint(capabilities.Protocols, 2) {
				t.Fatalf("protocols = %v", capabilities.Protocols)
			}
			if containsV2Uint(capabilities.Protocols, 1) != shape.v1Routes {
				t.Fatalf("protocol advertisement %v disagrees with shape %s", capabilities.Protocols, shape.name)
			}
		})
	}
}

func TestPeerInviteRefusesLegacyServerWithoutLocalState(t *testing.T) {
	for _, shape := range v2ServerShapes {
		t.Run(shape.name, func(t *testing.T) {
			setTestV2Homes(t)
			_, paths, err := initializeV2Config(
				"desktop",
				"https://dud.example.com",
				"https://dns.google/dns-query",
				"hard",
			)
			if err != nil {
				t.Fatal(err)
			}
			transport := newMixedVersionTransport(t, shape)
			var stdout, stderr bytes.Buffer
			a := newApp(strings.NewReader(""), &stdout, &stderr)
			a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
			code := a.main([]string{"peer", "invite", "laptop"})
			if code == 0 {
				t.Fatalf("invite unexpectedly completed: %s", stdout.String())
			}
			if shape.v2Routes {
				// Discovery succeeded; the invite only stopped at the rendezvous.
				if !strings.Contains(stderr.String(), errMixedVersionStop.Error()) {
					t.Fatalf("v2 invite stopped early: %s", stderr.String())
				}
				return
			}
			if !strings.Contains(stderr.String(), "does not offer protocol v2") {
				t.Fatalf("legacy invite error = %s", stderr.String())
			}
			if _, err := loadV2PendingPairing(paths, "laptop"); err == nil {
				t.Fatal("a refused invite left pending pairing state behind")
			}
			cfg, _, err := loadV2Config()
			if err != nil {
				t.Fatal(err)
			}
			if _, exists := cfg.Peers["laptop"]; exists {
				t.Fatal("a refused invite created a peer profile")
			}
		})
	}
}
