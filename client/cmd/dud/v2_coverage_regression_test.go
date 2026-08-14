// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testV2Capabilities(t *testing.T) *v2Capabilities {
	t.Helper()
	body, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := decodeV2Capabilities(body)
	if err != nil {
		t.Fatal(err)
	}
	return capabilities
}

func TestV2CapabilityValidationCoversMalformedRegistries(t *testing.T) {
	valid := testV2Capabilities(t)
	for _, test := range []struct {
		name   string
		change func(*v2Capabilities)
	}{
		{"duplicate protocols", func(value *v2Capabilities) { value.Protocols = []uint64{2, 2} }},
		{"unsorted features", func(value *v2Capabilities) { value.Features = []uint64{3, 2} }},
		{"missing limit", func(value *v2Capabilities) { delete(value.Limits, 9) }},
		{"zero limit", func(value *v2Capabilities) { value.Limits[1] = 0 }},
		{"invalid quota enforcement", func(value *v2Capabilities) { value.Enforcement[1] = 3 }},
		{"invalid consume enforcement", func(value *v2Capabilities) { value.Enforcement[2] = 3 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := &v2Capabilities{
				Protocols: append([]uint64(nil), valid.Protocols...), Features: append([]uint64(nil), valid.Features...),
				Limits: map[uint64]uint64{}, Enforcement: map[uint64]uint64{},
			}
			for key, item := range valid.Limits {
				value.Limits[key] = item
			}
			for key, item := range valid.Enforcement {
				value.Enforcement[key] = item
			}
			test.change(value)
			body, err := v2CapabilityDocumentBytes(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeV2Capabilities(body); err == nil {
				t.Fatal("malformed capability document was accepted")
			}
		})
	}
	if err := requireV2CapabilityFeatures(valid, 2, 99); err == nil || !strings.Contains(err.Error(), "99") {
		t.Fatalf("feature requirement error = %v", err)
	}
	if v2LimitName(99) != "limit 99" || !strictlyIncreasingV2([]uint64{1}) || strictlyIncreasingV2(nil) {
		t.Fatal("capability helpers returned unexpected values")
	}
}

func TestV2PeerStateRejectsCorruptionAndPrunesReplay(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	clone := func() *v2PeerDeliveryState {
		body, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		var copy v2PeerDeliveryState
		if err := json.Unmarshal(body, &copy); err != nil {
			t.Fatal(err)
		}
		return &copy
	}
	for _, test := range []struct {
		name   string
		change func(*v2PeerDeliveryState)
	}{
		{"bad secret", func(value *v2PeerDeliveryState) { value.InboundRelationshipSecret = "bad" }},
		{"missing capability map", func(value *v2PeerDeliveryState) { value.Capabilities = nil }},
		{"bad contract", func(value *v2PeerDeliveryState) { value.ServerContract.DocumentDigest = "bad" }},
		{"missing chain", func(value *v2PeerDeliveryState) { delete(value.Chains, "in:data") }},
		{"bad pending control id", func(value *v2PeerDeliveryState) { value.PendingControlEventIDs = []string{"bad"} }},
		{"bad sent digest", func(value *v2PeerDeliveryState) { value.Chains["out:data"].SendDigest = "bad" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := clone()
			test.change(value)
			if err := validateV2PeerDeliveryState(value, state.RelationshipID); err == nil {
				t.Fatal("corrupt state was accepted")
			}
		})
	}
	value := clone()
	value.Chains["in:data"].ReceiveWatermark = v2ReplayHistoryLimit + 1_000
	value.Chains["in:data"].Replay = map[uint64]v2ReplayEntry{}
	for index := uint64(1); index <= v2ReplayHistoryLimit+20; index++ {
		value.Chains["in:data"].Replay[index] = v2ReplayEntry{Sequence: index, ExpiresAt: 200}
	}
	value.Chains["in:control"].Replay[1] = v2ReplayEntry{Sequence: 1, ExpiresAt: 1}
	pruneV2ReplayHistory(value, 100)
	if _, exists := value.Chains["in:control"].Replay[1]; exists || len(value.Chains["in:data"].Replay) > v2ReplayHistoryLimit {
		t.Fatalf("replay pruning failed: %#v", value.Chains)
	}
	if v2BackoffDuration(0) != 0 || v2BackoffDuration(20) != 256*time.Second || v2BackoffWithJitter(0) != 0 {
		t.Fatal("unexpected peer-state backoff")
	}
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
}

func TestV2PeerStateValidatesQueuedDurableWork(t *testing.T) {
	_, state := newPairedV2TestPeer(t, "laptop")
	state.PendingCompletions = []v2PendingCompletion{{
		DeliveryID: strings.Repeat("01", 16), SourceSlot: strings.Repeat("02", 16), SourceSlotEpoch: 1,
		TargetSlot: strings.Repeat("03", 16), TargetSlotEpoch: 1, PolicyDigest: strings.Repeat("04", 32),
		DescriptorDigest: strings.Repeat("05", 32), Result: 0, OperationID: strings.Repeat("06", 16), Acknowledgement: v2Base64URL([]byte("ack")),
	}}
	state.PendingGranularDeliveries = []v2PendingGranularDelivery{{
		OperationID: strings.Repeat("07", 16), EncryptedDescriptor: v2Base64URL([]byte("descriptor")), PayloadCiphertext: v2Base64URL([]byte("payload")),
		DataSlot: strings.Repeat("08", 16), SlotEpoch: 1, RequestedPolicy: v2Base64URL([]byte("policy")), DescriptorDigest: strings.Repeat("09", 32), Sequence: 1,
	}}
	state.PendingControlPublications = []v2PendingControlPublication{{
		OperationID: strings.Repeat("0a", 16), EncryptedEvent: v2Base64URL([]byte("event")), ControlSlot: strings.Repeat("0b", 16), SlotEpoch: 1,
	}}
	state.PendingControlEventIDs = []string{strings.Repeat("0c", 16)}
	if err := validateV2PeerDeliveryState(state, state.RelationshipID); err != nil {
		t.Fatalf("valid queued state rejected: %v", err)
	}
	state.PendingCompletions[0].Result = 2
	if err := validateV2PeerDeliveryState(state, state.RelationshipID); err == nil {
		t.Fatal("invalid completion result accepted")
	}
}

func TestV2DeliveryOptionAndProtocolHelpersRejectInvalidInputs(t *testing.T) {
	for _, args := range [][]string{
		nil, {"--json"}, {"laptop", "--ttl", "0s", "-m", "hello"}, {"laptop", "-m", "a", "-m", "b"},
		{"laptop", "--recipient", "x", "-m", "hello"}, {"laptop", "-m", "hello", "extra"}, {"laptop", "-m", "hello", "--json", "--json"},
	} {
		if _, err := parseV2PeerSendOptions(args); err == nil {
			t.Fatalf("options unexpectedly accepted: %v", args)
		}
	}
	opts, err := parseV2PeerSendOptions([]string{"laptop", "--delete-after-read", "--ttl", "1h", "--name", "note", "-m", "hello", "--json"})
	if err != nil || opts.alias != "laptop" || opts.message != "hello" || !opts.deleteAfterRead || !opts.json {
		t.Fatalf("options = %#v, %v", opts, err)
	}
	if v2PayloadKind(1) != "message" || v2PayloadKind(2) != "file" || v2PayloadKind(3) != "collection" || v2PayloadKind(4) != "Git checkpoint" || v2PayloadKind(9) != "payload type 9" {
		t.Fatal("payload kinds are incomplete")
	}
	if _, err := decodeV2ControlEventIDs([]string{"bad"}); err == nil {
		t.Fatal("invalid control event id was accepted")
	}
	ids, err := decodeV2ControlEventIDs([]string{strings.Repeat("a", 32)})
	if err != nil || len(ids) != 1 {
		t.Fatalf("control IDs = %x, %v", ids, err)
	}
	if got := v2ControlRecoveryEpochs(10, 5); len(got) != 1 || got[0] != 5 {
		t.Fatalf("recovery epochs = %v", got)
	}
	if err := validateV2EffectivePolicy(map[int]any{1: uint64(20), 2: uint64(1), 3: uint64(2), 4: uint64(0)}, map[int]any{1: uint64(21), 2: uint64(1), 3: uint64(2), 4: uint64(0)}); err == nil {
		t.Fatal("weaker policy was accepted")
	}
	if _, err := decryptV2Payload([]byte("not age"), nil, 1); err == nil {
		t.Fatal("invalid encrypted payload was accepted")
	}
	if v2TransportPolicyMap(v2TransportPolicy{ExpiresAt: 1})[1].(uint64) != 1 {
		t.Fatal("policy map mismatch")
	}
}

func TestV2PeerReportingLifecycleAndEraseParsing(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	for _, args := range [][]string{
		{"peer", "list"}, {"peer", "list", "--json"}, {"peer", "show", "laptop"}, {"peer", "show", "laptop", "--json"},
		{"peer", "rename", "laptop", "tablet"}, {"peer", "show", "tablet", "--json"}, {"peer", "remove", "tablet", "--yes", "--json"},
	} {
		if err := a.run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if !strings.Contains(stdout.String(), `"removed": true`) {
		t.Fatalf("lifecycle output = %s", stdout.String())
	}
	for _, args := range [][]string{
		nil, {"unknown", "--yes"}, {"pairings"}, {"peer", "--yes"}, {"all", "--repo", "--yes", "--dry-run"}, {"repo", "--repo", "--yes"}, {"pairings", "--wat"},
	} {
		if _, err := parseV2EraseOptions(args); err == nil {
			t.Fatalf("erase options unexpectedly accepted: %v", args)
		}
	}
	opts, err := parseV2EraseOptions([]string{"all", "--repo", "--dry-run", "--json"})
	if err != nil || !opts.IncludeRepo || !opts.DryRun || !opts.JSON {
		t.Fatalf("erase options = %#v, %v", opts, err)
	}
	if got := sortedUniqueStrings([]string{"b", "a", "b", ""}); strings.Join(got, ",") != "a,b" {
		t.Fatalf("sorted unique = %v", got)
	}
}

func TestV2DoctorAndConfigurationCommandsReportLocalState(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	body, err := hex.DecodeString(v2CapabilitiesVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, jsonOutput := range []bool{false, true} {
		var stdout bytes.Buffer
		a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
		a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
			return &capabilitiesStubTransport{body: body}, nil
		}
		args := []string{"doctor"}
		if jsonOutput {
			args = append(args, "--json")
		}
		if err := a.run(args); err != nil {
			t.Fatalf("doctor %v: %v", args, err)
		}
		if !strings.Contains(stdout.String(), "laptop") {
			t.Fatalf("doctor output = %s", stdout.String())
		}
	}
	for _, args := range [][]string{{"config", "validate"}, {"config", "validate", "--json"}, {"migrate"}, {"migrate", "--json"}} {
		if err := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}).run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if doctorOriginTitle("peer:laptop") != "peer laptop" || doctorOriginTitle("global") != "global" || !isWellKnownV2Resolver("dns.google") || isWellKnownV2Resolver("resolver.example") {
		t.Fatal("doctor display helpers returned unexpected values")
	}
}

func TestV2SendPublishesFileAndCollectionPayloads(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	file := filepath.Join(directory, "note.txt")
	if err := os.WriteFile(file, []byte("note"), 0o600); err != nil {
		t.Fatal(err)
	}
	collection := filepath.Join(directory, "collection")
	if err := os.Mkdir(collection, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(collection, "item.txt"), []byte("item"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &echoingV2DeliveryTransport{}, nil }
	if err := a.run([]string{"send", "laptop", "--file", file, "--name", "renamed", "--json"}); err != nil {
		t.Fatal(err)
	}
	if err := a.run([]string{"send", "laptop", "--file", collection, "--json"}); err != nil {
		t.Fatal(err)
	}
	stored, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Sent) != 2 {
		t.Fatalf("sent deliveries = %#v", stored.Sent)
	}
	foundCollection := false
	for _, sent := range stored.Sent {
		foundCollection = foundCollection || sent.PayloadType == 3 && sent.TypeMetadata != ""
	}
	if !foundCollection {
		t.Fatalf("collection delivery was not recorded: %#v", stored.Sent)
	}
}

func TestV2EraseStagingHelpersHandleFilesDirectoriesAndUnsafeEntries(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	directory := filepath.Join(root, "directory")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if exists, err := validateV2EraseFile(file); err != nil || !exists {
		t.Fatalf("file validation = %v, %v", exists, err)
	}
	if exists, err := validateV2EraseDirectory(directory); err != nil || !exists {
		t.Fatalf("directory validation = %v, %v", exists, err)
	}
	if _, err := validateV2EraseFile(directory); err == nil {
		t.Fatal("directory was accepted as file")
	}
	if _, err := validateV2EraseDirectory(file); err == nil {
		t.Fatal("file was accepted as directory")
	}
	stagedFile, exists, err := stageV2ErasePath(file, false)
	if err != nil || !exists {
		t.Fatalf("stage file = %#v, %v, %v", stagedFile, exists, err)
	}
	if err := rollbackV2ErasePaths([]v2StagedErasePath{stagedFile}); err != nil {
		t.Fatal(err)
	}
	stagedDirectory, exists, err := stageV2ErasePath(directory, true)
	if err != nil || !exists {
		t.Fatalf("stage directory = %#v, %v, %v", stagedDirectory, exists, err)
	}
	result := newV2EraseResult("test")
	if err := removeV2ErasePaths([]v2StagedErasePath{stagedDirectory}, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 1 || result.Removed[0] != directory {
		t.Fatalf("removal result = %#v", result)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := validateV2EraseFile(link); err == nil {
		t.Fatal("symlink was accepted for erasure")
	}
	var stdout, stderr bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &stderr)
	if err := a.renderV2EraseResult(v2EraseResult{Removed: []string{"x"}, Retained: []string{"y"}, Warnings: []string{"z"}}, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Removed:") || !strings.Contains(stderr.String(), "RETAINED: y") {
		t.Fatalf("erase report = %q / %q", stdout.String(), stderr.String())
	}
}

func TestV2GranularProtocolRejectsMalformedLocalAndServerValues(t *testing.T) {
	validProof := v2GranularSlotProofInput{
		TokenSecret: bytes.Repeat([]byte{1}, 32), Direction: "inviter->invitee", Scope: "read", Chain: 0,
		Slot: bytes.Repeat([]byte{2}, 16), Epoch: 1, Nonce: bytes.Repeat([]byte{3}, 16), ExpiresAt: 10,
	}
	for _, proof := range []v2GranularSlotProofInput{
		{TokenSecret: validProof.TokenSecret, Direction: validProof.Direction, Scope: validProof.Scope, Slot: []byte{1}},
		{TokenSecret: validProof.TokenSecret, Direction: "invalid", Scope: validProof.Scope, Slot: validProof.Slot},
		{TokenSecret: validProof.TokenSecret, Direction: validProof.Direction, Scope: "invalid", Slot: validProof.Slot},
	} {
		if _, err := v2GranularCapabilityContext(proof); err == nil {
			t.Fatal("invalid proof context was accepted")
		}
	}
	if _, err := deriveV2DailyCapabilityLookupIDClient([]byte("bad"), 1); err == nil {
		t.Fatal("short capability secret was accepted")
	}
	for _, args := range []struct {
		method, origin, path string
		proof                v2GranularSlotProofInput
	}{
		{"", "https://dud.example.com", "/v2/inbox", validProof},
		{"POST", "", "/v2/inbox", validProof},
		{"POST", "https://dud.example.com", "", validProof},
		{"POST", "https://dud.example.com", "/v2/inbox", v2GranularSlotProofInput{}},
	} {
		if _, err := encodeV2GranularSlotProof(args.proof, args.method, args.origin, args.path, make([]byte, 32), 0, false); err == nil {
			t.Fatal("invalid proof was encoded")
		}
	}
	if _, err := encodeV2GranularInboxRequest("", []v2GranularSlotProofInput{validProof}, nil, nil); err == nil {
		t.Fatal("empty inbox origin accepted")
	}
	if _, err := encodeV2GranularInboxRequest("https://dud.example.com", nil, nil, nil); err == nil {
		t.Fatal("empty inbox proofs accepted")
	}
	if _, err := encodeV2GranularInboxRequest("https://dud.example.com", []v2GranularSlotProofInput{validProof}, nil, [][]byte{{1}}); err == nil {
		t.Fatal("short control id accepted")
	}
	for _, response := range []*v2GranularInboxResponse{
		nil,
		{Header: map[int]any{10: nil}},
		{Header: map[int]any{1: []any{}, 2: []any{}, 3: []byte{1}, 7: uint64(0), 8: uint64(0)}},
		{Header: map[int]any{1: []any{}, 2: []any{}, 3: nil, 4: []byte{1}, 7: uint64(0), 8: uint64(0)}},
	} {
		if _, err := decodeV2GranularInboxDelivery(response); err == nil {
			t.Fatal("malformed inbox response was accepted")
		}
	}
	if _, err := encodeV2GranularControlEventRequest("", make([]byte, 16), []byte("event"), validProof); err == nil {
		t.Fatal("empty control origin accepted")
	}
	if _, err := encodeV2GranularDeliveryRequest("", make([]byte, 16), []byte("descriptor"), map[int]any{}, nil, validProof, nil, nil); err == nil {
		t.Fatal("empty delivery origin accepted")
	}
	if _, err := encodeV2GranularCompletionRequest("", make([]byte, 16), make([]byte, 16), make([]byte, 16), make([]byte, 32), make([]byte, 32), 0, make([]byte, 16), []byte("ack"), validProof, validProof); err == nil {
		t.Fatal("empty completion origin accepted")
	}
}

func TestV2GitAndReceiveOptionParsersCoverSupportedFlags(t *testing.T) {
	push, err := parseV2GitPushOptions([]string{"laptop", "--branch", "main", "--branch", "release", "--ttl", "1h", "--json"})
	if err != nil || len(push.Branches) != 2 || push.TTL != time.Hour || !push.JSON {
		t.Fatalf("push options = %#v, %v", push, err)
	}
	fetch, err := parseV2GitFetchOptions([]string{"laptop", "--associate", "--allow-rewrite", "--json"})
	if err != nil || !fetch.Associate || !fetch.AllowRewrite || !fetch.JSON {
		t.Fatalf("fetch options = %#v, %v", fetch, err)
	}
	for _, args := range [][]string{
		nil, {"laptop", "--branch"}, {"laptop", "--ttl", "0s"}, {"laptop", "--current", "--branch", "main"}, {"laptop", "--incremental"}, {"laptop", "extra"},
	} {
		if _, err := parseV2GitPushOptions(args); err == nil {
			t.Fatalf("push options accepted: %v", args)
		}
	}
	for _, args := range [][]string{nil, {"laptop", "--incremental"}, {"laptop", "--url", "x"}, {"laptop", "extra"}, {"laptop", "--json", "--json"}} {
		if _, err := parseV2GitFetchOptions(args); err == nil {
			t.Fatalf("fetch options accepted: %v", args)
		}
	}
	digest := strings.Repeat("a", 64)
	receive, err := parseV2PeerReceiveOptions([]string{"laptop", "--max", "2", "--on-conflict", "overwrite", "--out-dir", "out", "--id", digest, "--no-extract", "--interactive", "--json"})
	if err == nil || !strings.Contains(err.Error(), "--id and --max") {
		t.Fatalf("incompatible receive options = %#v, %v", receive, err)
	}
	receive, err = parseV2PeerReceiveOptions([]string{"laptop", "--on-conflict", "refuse", "--collection-overwrite", "refuse", "--wait", "1s", "--no-extract", "--json"})
	if err != nil || receive.onConflict != "refuse" || receive.wait != time.Second || !receive.noExtract || !receive.json {
		t.Fatalf("receive options = %#v, %v", receive, err)
	}
	for _, args := range [][]string{
		nil, {"laptop", "--max", "0"}, {"laptop", "--on-conflict", "bad"}, {"laptop", "--collection-overwrite", "overwrite"}, {"laptop", "--wait", "-1s"}, {"laptop", "--out", "x", "--out-dir", "y"}, {"laptop", "--id", "bad"}, {"laptop", "extra"},
	} {
		if _, err := parseV2PeerReceiveOptions(args); err == nil {
			t.Fatalf("receive options accepted: %v", args)
		}
	}
}

func TestV2TransportRequestAndHTTPErrorValidation(t *testing.T) {
	for _, request := range []v2Request{
		{Origin: "https://dud.example.com", Path: "/"},
		{Method: "post", Origin: "https://dud.example.com", Path: "/"},
		{Method: "POST", Origin: "https://DUD.example.com", Path: "/"},
		{Method: "POST", Origin: "https://dud.example.com", Path: "relative"},
		{Method: "POST", Origin: "https://dud.example.com", Path: "/x?query=1"},
		{Method: "POST", Origin: "https://dud.example.com", Path: "/", Body: []byte("x"), BodyStream: strings.NewReader("x"), ContentLength: 1},
		{Method: "POST", Origin: "https://dud.example.com", Path: "/", ContentLength: 1},
	} {
		if _, err := validateV2Request(request); err == nil {
			t.Fatalf("request accepted: %#v", request)
		}
	}
	if _, err := newV2TLSConfig("/missing/ca.pem", "dud.example.com", nil); err == nil {
		t.Fatal("missing CA bundle accepted")
	}
	if _, err := canonicalV2DOHURL("https://dns.google/dns-query?x=1"); err == nil {
		t.Fatal("DoH query accepted")
	}
	for _, response := range []*v2Response{
		{StatusCode: 500}, {StatusCode: 400, ContentType: v2CBORContentType, Body: []byte("bad")},
		{StatusCode: 401, ContentType: v2CBORContentType, Body: mustV2CBORTestBytes(t, map[int]any{1: uint64(9), 2: "denied"})},
	} {
		if err := decodeV2HTTPError(response); err == nil {
			t.Fatal("HTTP error did not decode")
		}
	}
	transport := &v2CoverageResponseTransport{response: &v2Response{StatusCode: 200, ContentType: "text/plain", Body: []byte("x")}}
	if _, err := doV2CBORRequest(t.Context(), transport, "GET", "https://dud.example.com", "/v2/test", nil, nil, 100); err == nil {
		t.Fatal("unexpected response content type accepted")
	}
}

func TestV2PairingProgressAndAdminCapabilityFailureModes(t *testing.T) {
	setTestV2Homes(t)
	cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	pending, _, _, err := a.newV2Invitation(cfg, paths, "laptop", cfg.BaseURL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []uint64{2, 3, 4, 5, 6} {
		transport := &pairingFlowTransport{locator: pending.RendezvousLocator, statusPhase: phase}
		got, progressErr := a.progressV2Pairing(cfg, paths, pending, transport)
		if phase == 2 || phase == 3 {
			if progressErr != nil || got != phase {
				t.Fatalf("phase %d = %d, %v", phase, got, progressErr)
			}
		} else if progressErr == nil {
			t.Fatalf("phase %d was accepted", phase)
		}
	}
	pending.ExpiresAt = 1
	if err := a.waitV2Pairing(cfg, paths, pending, &pairingFlowTransport{}, true); err == nil {
		t.Fatal("expired pairing waited")
	}
	if _, err := loadV2AdminCapability(paths); err == nil {
		t.Fatal("missing admin capability accepted")
	}
	if err := os.WriteFile(paths.AdminCapability, []byte("bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadV2AdminCapability(paths); err == nil {
		t.Fatal("bad admin capability accepted")
	}
	if err := os.WriteFile(paths.AdminCapability, []byte(v2Base64URL(bytes.Repeat([]byte{9}, 32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if capability, err := loadV2AdminCapability(paths); err != nil || len(capability) != 32 {
		t.Fatalf("admin capability = %x, %v", capability, err)
	}
}

func TestV2TTYPromptSeamReadsVisibleInputAndConfirmsOrigins(t *testing.T) {
	previous := openV2TTY
	t.Cleanup(func() { openV2TTY = previous })
	file := filepath.Join(t.TempDir(), "tty")
	if err := os.WriteFile(file, []byte("prompt:  yes \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openV2TTY = func() (*os.File, error) { return os.OpenFile(file, os.O_RDWR, 0) }
	value, err := readV2TTYLine("prompt: ", false)
	if err != nil || value != " yes " {
		t.Fatalf("TTY line = %q, %v", value, err)
	}
	if err := os.WriteFile(file, []byte("Invitation requests new peer origin https://dud.example.com. Trust this origin? [y/N]: y\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, err := promptV2OriginConfirmation("https://dud.example.com")
	if err != nil || !ok {
		t.Fatalf("origin confirmation = %v, %v", ok, err)
	}
	openV2TTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	if _, err := readV2TTYLine("prompt: ", false); err == nil {
		t.Fatal("TTY open failure was accepted")
	}
	if err := os.WriteFile(file, []byte("prompt: "), 0o600); err != nil {
		t.Fatal(err)
	}
	openV2TTY = func() (*os.File, error) { return os.Open(file) }
	if _, err := readV2TTYLine("prompt: ", false); err == nil {
		t.Fatal("read-only TTY accepted a prompt write")
	}
	openV2TTY = func() (*os.File, error) { return os.OpenFile(file, os.O_RDWR, 0) }
	if _, err := readV2TTYLine("prompt: ", true); err == nil {
		t.Fatal("non-terminal hidden input was accepted")
	}
	if _, err := readV2TTYLine("prompt: ", false); err == nil {
		t.Fatal("empty TTY input was accepted")
	}
}

func TestV2HaltedRelationshipRevocationUsesTheAdminCapability(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := os.WriteFile(paths.AdminCapability, []byte(v2Base64URL(bytes.Repeat([]byte{7}, 32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	relationshipID, err := hex.DecodeString(state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	transport := &v2CoverageResponseTransport{response: &v2Response{StatusCode: 202}}
	runtime := &v2PeerRuntime{paths: paths, relationshipID: relationshipID, origin: "https://dud.example.com", transport: transport}
	if err := runtime.revokeHaltedRelationship(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestV2PeerRemoveCancelsAnActivePendingInvitation(t *testing.T) {
	setTestV2Homes(t)
	cfg, paths, err := initializeV2Config("desktop", "https://dud.example.com", "https://dns.google/dns-query", "hard")
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	pending, _, _, err := a.newV2Invitation(cfg, paths, "laptop", cfg.BaseURL, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeV2PendingPairing(paths, pending); err != nil {
		t.Fatal(err)
	}
	if err := ensureV2InviterPendingProfile("laptop", pending, cfg.ECHMode); err != nil {
		t.Fatal(err)
	}
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &v2CoverageResponseTransport{response: &v2Response{StatusCode: 202}}, nil
	}
	if err := a.run([]string{"peer", "remove", "laptop", "--yes", "--json"}); err != nil {
		t.Fatal(err)
	}
	updated, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := updated.Peers["laptop"]; exists {
		t.Fatal("pending peer was not removed")
	}
	if _, err := loadV2PendingPairing(paths, "laptop"); err == nil {
		t.Fatal("pending pairing was not removed")
	}
}

func TestV2ReportAndProtocolUtilityVariants(t *testing.T) {
	for input, expected := range map[any]uint64{uint64(1): 1, uint32(2): 2, uint(3): 3, int(4): 4} {
		value, ok := asV2Uint(input)
		if !ok || value != expected {
			t.Fatalf("asV2Uint(%T) = %d, %v", input, value, ok)
		}
	}
	if _, ok := asV2Uint(-1); ok || v2UintEquals("bad", 1) {
		t.Fatal("invalid V2 integer accepted")
	}
	if info := v2ConnectionInfoFrom(nil, nil); info != nil {
		t.Fatal("nil connection state returned info")
	}
	info := v2ConnectionInfoFrom(&tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, ServerName: "dud.example.com"}, nil)
	if info == nil || info.ServerName != "dud.example.com" {
		t.Fatalf("connection info = %#v", info)
	}
	if info := v2ConnectionInfoFrom(&tls.ConnectionState{ECHAccepted: true}, nil); info == nil || !info.ECHAccepted {
		t.Fatalf("ECH connection info = %#v", info)
	}
	if addresses := v2BootstrapAddresses(&v2LocalConfig{DOHBootstrap: []string{"1.1.1.1", "not-an-address"}}); len(addresses) != 2 || !addresses[0].IsValid() || addresses[1].IsValid() {
		t.Fatalf("bootstrap addresses = %v", addresses)
	}
	status := v2DeliveryStatus{PendingCompletions: 1}
	result := v2ReceiveJSON("laptop", nil, &v2ReceiveStop{Reason: "git", Detail: "checkpoint", Sequence: 2, Next: "next"}, status)
	if result["received"] != false || result["acknowledgement"] != false || result["stopped"] == nil {
		t.Fatalf("receive JSON = %#v", result)
	}
	result = v2ReceiveJSON("laptop", []v2ReceivedItem{{Sequence: 1, DescriptorDigest: "digest", Output: "output"}}, nil, v2DeliveryStatus{})
	if result["sequence"] != uint64(1) || result["descriptor_digest"] != "digest" {
		t.Fatalf("single receive JSON = %#v", result)
	}
	var output bytes.Buffer
	report := &textReport{}
	report.section("Test").notef("value %d", 1)
	if err := report.write(&output); err != nil || !strings.Contains(output.String(), "value 1") {
		t.Fatalf("report = %q, %v", output.String(), err)
	}
	for source, want := range map[string]string{v2NetworkSourceCLI: "--url", v2NetworkSourceEnvironment: "DUD_BASE_URL", v2NetworkSourcePeer: "the peer profile", v2NetworkSourceConfig: "the local configuration", "default": "the compiled default"} {
		if got := v2NetworkLayerName(source, "--url"); got != want {
			t.Fatalf("network layer %q = %q", source, got)
		}
	}
	if v2NetworkLayerName(v2NetworkSourceEnvironment, "--doh-url") != "DUD_DOH_URL" || v2NetworkLayerName(v2NetworkSourceEnvironment, "--ech-mode") != "DUD_ECH_MODE" {
		t.Fatal("environment network layer names are incorrect")
	}
	for advertised, want := range map[string]string{"refs/heads/main": "refs/remotes/laptop/main", "refs/tags/v1": "refs/dud/tags/laptop/v1"} {
		if got, err := v2GitRemoteRef("laptop", advertised); err != nil || got != want {
			t.Fatalf("remote ref = %q, %v", got, err)
		}
	}
	if _, err := v2GitRemoteRef("laptop", "refs/notes/x"); err == nil {
		t.Fatal("unsupported ref accepted")
	}
	for _, test := range []struct {
		opts    v2PeerReceiveOptions
		drained []v2ReceivedItem
		stop    *v2ReceiveStop
	}{
		{v2PeerReceiveOptions{alias: "laptop"}, nil, nil},
		{v2PeerReceiveOptions{alias: "laptop"}, []v2ReceivedItem{{Sequence: 1, Outcome: "received", Output: "file"}}, nil},
		{v2PeerReceiveOptions{alias: "laptop"}, []v2ReceivedItem{{Sequence: 1, Outcome: "message"}}, nil},
		{v2PeerReceiveOptions{alias: "laptop"}, []v2ReceivedItem{{Sequence: 1, Outcome: "skipped", Conflict: "file", DescriptorDigest: "digest"}, {Sequence: 2, Outcome: "received", Output: "file2"}}, &v2ReceiveStop{Reason: "blocked", Next: "next"}},
	} {
		var text, errText bytes.Buffer
		a := newApp(strings.NewReader(""), &text, &errText)
		if err := a.renderV2ReceiveReport(test.opts, test.drained, test.stop, v2DeliveryStatus{}); err != nil {
			t.Fatal(err)
		}
	}
	config, err := newV2TLSConfig("", "dud.example.com", nil)
	if err != nil || config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("TLS config = %#v, %v", config, err)
	}
	dohClient, err := newV2DOHClient(v2TransportOptions{DOHURL: "https://dns.google/dns-query", DOHBootstrap: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if transport, ok := dohClient.Transport.(*http.Transport); !ok || transport.DialContext == nil {
		t.Fatalf("DoH transport = %#v", dohClient.Transport)
	}
	if url, err := canonicalV2DOHURL("https://dns.google"); err != nil || url != "https://dns.google/dns-query" {
		t.Fatalf("canonical DoH URL = %q, %v", url, err)
	}
	if _, err := canonicalV2DOHURL("https://dns.google/a%2Fb"); err == nil {
		t.Fatal("noncanonical DoH path accepted")
	}
}

func mustV2CBORTestBytes(t *testing.T, value any) []byte {
	t.Helper()
	body, err := v2EncMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type v2CoverageResponseTransport struct{ response *v2Response }

func (transport *v2CoverageResponseTransport) Do(_ context.Context, _ v2Request) (*v2Response, error) {
	return transport.response, nil
}
