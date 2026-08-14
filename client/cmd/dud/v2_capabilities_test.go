// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const v2CapabilitiesVectorHex = "a4018201020286020305090a0b03a9011a06400000021a00040000031a00278d0004184005190100060407183c081a0c8000000919100004a201020201"

func TestDecodeV2CapabilitiesMatchesFrozenVector(t *testing.T) {
	body, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := decodeV2Capabilities(body)
	if err != nil {
		t.Fatal(err)
	}
	if !containsV2Uint(capabilities.Protocols, 2) ||
		!containsV2Uint(capabilities.Features, 9) ||
		capabilities.Limits[8] != 209715200 ||
		capabilities.Enforcement[1] != 2 {
		t.Fatalf("decoded capabilities = %#v", capabilities)
	}
}

func TestV2ServerContractRetainsValidatedCapabilityDocument(t *testing.T) {
	body, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := decodeV2Capabilities(body)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := newV2ServerContract(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := contract.capabilities()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Limits[3] != capabilities.Limits[3] || !containsV2Uint(restored.Features, 11) {
		t.Fatalf("restored capabilities = %#v", restored)
	}
	contract.Limits[3]++
	if _, err := contract.capabilities(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered contract error = %v", err)
	}
}

func TestV2PeerRuntimeUsesStoredCapabilitiesWithoutDiscovery(t *testing.T) {
	body, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := decodeV2Capabilities(body)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := newV2ServerContract(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	transport := &capabilitiesStubTransport{body: body}
	runtime := &v2PeerRuntime{
		state:     &v2PeerDeliveryState{ServerContract: contract},
		transport: transport,
	}
	if err := runtime.requirePeerFeatures(); err != nil {
		t.Fatal(err)
	}
	if transport.called != 0 {
		t.Fatalf("normal peer capability validation performed %d discovery requests", transport.called)
	}
	if runtime.maxTTL != capabilities.Limits[3] {
		t.Fatalf("runtime max TTL = %d", runtime.maxTTL)
	}
	if err := runtime.requireGitFeatures(); err != nil {
		t.Fatal(err)
	}
	if transport.called != 0 {
		t.Fatalf("Git feature validation performed %d discovery requests", transport.called)
	}
}

func TestDecodeV2CapabilitiesRejectsNonDeterministicAndIncompleteResponses(t *testing.T) {
	nonMinimal := []byte{0xa1, 0x18, 0x01, 0x80}
	if _, err := decodeV2Capabilities(nonMinimal); err == nil {
		t.Fatal("non-minimal CBOR was accepted")
	}
	body, err := v2EncMode.Marshal(map[int]any{
		1: []uint64{1},
		2: []uint64{1, 2},
		3: map[uint64]uint64{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1},
		4: map[uint64]uint64{1: 2, 2: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeV2Capabilities(body); err == nil || !strings.Contains(err.Error(), "protocol v2") {
		t.Fatalf("missing v2 protocol error = %v", err)
	}
	body, err = v2EncMode.Marshal(map[int]any{
		1: []uint64{2},
		2: []uint64{1, 2},
		3: map[uint64]uint64{1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1},
		4: map[uint64]uint64{1: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeV2Capabilities(body); err == nil || !strings.Contains(err.Error(), "enforcement field 2") {
		t.Fatalf("missing enforcement error = %v", err)
	}
}

func TestCapabilitiesCommandUsesMandatoryTransportAndValidatesPayload(t *testing.T) {
	setTestV2Homes(t)
	if _, _, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard"); err != nil {
		t.Fatal(err)
	}
	body, _ := hex.DecodeString(v2CapabilitiesVectorHex)
	transport := &capabilitiesStubTransport{body: body}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return transport, nil
	}
	if code := a.main([]string{"capabilities", "--json"}); code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	if transport.called != 1 {
		t.Fatalf("transport calls = %#v", transport)
	}
	if !strings.Contains(stdout.String(), `"atomic-delivery"`) ||
		!strings.Contains(stdout.String(), `"quota_enforcement": "atomic"`) {
		t.Fatalf("output = %s", stdout.String())
	}
}

func TestCapabilitiesDiscoveryRejectsWrongMediaType(t *testing.T) {
	body, _ := hex.DecodeString(v2CapabilitiesVectorHex)
	transport := &capabilitiesStubTransport{
		body:        body,
		contentType: "application/octet-stream",
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return transport, nil
	}
	_, _, err := a.fetchV2Capabilities(
		context.Background(),
		v2NetworkSettings{
			BaseURL: v2NetworkOption{Value: "https://dud.example.com", Source: v2NetworkSourceConfig},
			DOHURL:  v2NetworkOption{Value: "https://dns.google/dns-query", Source: v2NetworkSourceConfig},
			ECHMode: v2NetworkOption{Value: "hard", Source: v2NetworkSourceConfig},
		},
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("media type error = %v", err)
	}
}

func TestV2FeatureDiscoveryAgainstLegacyServerFailsWithSafeAlternative(t *testing.T) {
	transport := &capabilitiesStubTransport{statusCode: 404}
	_, err := requireV2Features(
		context.Background(),
		transport,
		"https://dud.example.com",
		3,
	)
	if err == nil ||
		!strings.Contains(err.Error(), "does not offer protocol v2") ||
		!strings.Contains(err.Error(), "dud upload --file PATH") {
		t.Fatalf("legacy server error = %v", err)
	}
}

type capabilitiesStubTransport struct {
	body        []byte
	contentType string
	statusCode  int
	called      int
}

func (transport *capabilitiesStubTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.called++
	if request.Method != "GET" || request.Path != "/v2/capabilities" {
		return nil, errors.New("unexpected capability request")
	}
	if request.Headers.Get("Accept") != v2CBORContentType {
		return nil, errors.New("missing v2 CBOR accept header")
	}
	contentType := transport.contentType
	if contentType == "" {
		contentType = v2CBORContentType
	}
	statusCode := transport.statusCode
	if statusCode == 0 {
		statusCode = 200
	}
	return &v2Response{
		StatusCode:  statusCode,
		ContentType: contentType,
		Body:        append([]byte(nil), transport.body...),
	}, nil
}
