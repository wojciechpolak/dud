// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// newPairedV2TestPeer installs an active peer profile plus its durable
// delivery state so command-level tests can exercise reporting without
// pairing against a server.
func newPairedV2TestPeer(t *testing.T, alias string) (v2Paths, *v2PeerDeliveryState) {
	t.Helper()
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
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		t.Fatal(err)
	}
	relationshipID := bytesRepeatV2(0x31, 16)
	hpkeKey, err := v2HPKEPrivateKey(seed, relationshipID)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	relationship := hex.EncodeToString(relationshipID)
	if _, err := updateV2Config(func(cfg *v2LocalConfig) error {
		cfg.Peers[alias] = v2PeerProfile{
			Status:                   "active",
			RelationshipID:           relationship,
			PeerPseudonymousID:       strings.Repeat("32", 16),
			PeerAgeRecipient:         v2Base64URL(hpkeKey.PublicKey().Bytes()),
			PeerSigningPublicKey:     v2Base64URL(signingKey.Public().(ed25519.PublicKey)),
			BaseURL:                  "https://dud.example.com",
			InboxCapabilityReference: "deliveries/" + relationship + ".json",
			GitRemote:                alias,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	capabilities := map[string]string{}
	for _, direction := range []string{"inviter->invitee", "invitee->inviter"} {
		for _, scope := range []string{"write", "read", "ack"} {
			capabilities[direction+"|"+scope] = v2Base64URL(bytesRepeatV2(0x51, 32))
		}
	}
	state := &v2PeerDeliveryState{
		Version:                    v2DeliveryStateVersion,
		RelationshipID:             relationship,
		Role:                       0,
		OutboundRelationshipSecret: v2Base64URL(bytesRepeatV2(0x61, 32)),
		InboundRelationshipSecret:  v2Base64URL(bytesRepeatV2(0x62, 32)),
		Capabilities:               capabilities,
		ServerContract:             mustV2TestServerContract(t),
		CapabilitiesIssuedAt:       uint64(time.Now().Unix()),
		CapabilitiesExpireAt:       uint64(time.Now().Add(20 * 24 * time.Hour).Unix()),
		Chains: map[string]*v2ChainState{
			"out:data":    emptyV2ChainState(),
			"out:control": emptyV2ChainState(),
			"in:data":     emptyV2ChainState(),
			"in:control":  emptyV2ChainState(),
		},
		PendingControlPublications: []v2PendingControlPublication{},
		PendingGranularDeliveries:  []v2PendingGranularDelivery{},
		PendingCompletions:         []v2PendingCompletion{},
		InboundTransfers:           map[string]v2InboundTransfer{},
		Sent:                       map[string]v2SentDelivery{},
		SignedAcknowledgements:     map[string]string{},
		DataScanEpoch:              v2SlotEpoch(time.Now()),
		ControlScanEpoch:           v2SlotEpoch(time.Now()),
		PendingDataEpochs:          []uint64{},
		PendingControlEventIDs:     []string{},
	}
	return paths, state
}

func queuedV2TestCompletion() v2PendingCompletion {
	return v2PendingCompletion{
		DeliveryID:       strings.Repeat("01", 16),
		SourceSlot:       strings.Repeat("02", 16),
		SourceSlotEpoch:  20_000,
		TargetSlot:       strings.Repeat("03", 16),
		TargetSlotEpoch:  20_000,
		PolicyDigest:     strings.Repeat("04", 32),
		DescriptorDigest: strings.Repeat("05", 32),
		OperationID:      strings.Repeat("06", 16),
		Acknowledgement:  v2Base64URL([]byte("encrypted-acknowledgement")),
		CreatedAt:        uint64(time.Now().Unix()),
	}
}

func TestV2DeliveryStatusNamesEveryCategory(t *testing.T) {
	state := &v2PeerDeliveryState{
		PendingGranularDeliveries: []v2PendingGranularDelivery{{}},
		PendingCompletions:        []v2PendingCompletion{{}, {}},
		PendingControlPublications: []v2PendingControlPublication{
			{}, {}, {},
		},
		Sent: map[string]v2SentDelivery{
			"aa": {Sequence: 1, Acknowledged: true},
			"bb": {Sequence: 2},
			"cc": {Sequence: 3},
		},
		UndrainedControl:    true,
		LastSuccessfulDrain: 1_700_000_000,
		Halted:              true,
		HaltReason:          "relationship revoked locally",
		Chains: map[string]*v2ChainState{
			"out:data":   {},
			"in:data":    {Quarantined: true, QuarantineReason: "gap before sequence 4"},
			"in:control": {Quarantined: true, QuarantineReason: "fork at sequence 2"},
		},
	}
	status := v2DeliveryStatusOf(state)
	if !status.needsAttention() {
		t.Fatal("queued, undrained, quarantined, halted state reported nothing to attend to")
	}
	if len(status.QuarantinedChains) != 2 ||
		status.QuarantinedChains[0].Chain != "in:control" ||
		status.QuarantinedChains[1].Chain != "in:data" {
		t.Fatalf("quarantined chains = %#v", status.QuarantinedChains)
	}
	block := status.report("Status").String()
	for _, fragment := range []string{
		"queued deliveries          1",
		"queued completions         2",
		"queued control events      3",
		"unacknowledged deliveries  2",
		"undrained control          yes",
		"- in:control (fork at sequence 2)",
		"- in:data (gap before sequence 4)",
		"halted                     yes (relationship revoked locally)",
	} {
		if !strings.Contains(block, fragment) {
			t.Fatalf("status block %q omitted %q", block, fragment)
		}
	}
	fields := status.fields()
	for key, expected := range map[string]any{
		"pending_deliveries":           1,
		"pending_completions":          2,
		"pending_control_publications": 3,
		"unacknowledged_deliveries":    2,
		"undrained_control":            true,
		"halted":                       true,
		"halt_reason":                  "relationship revoked locally",
		"last_successful_drain":        uint64(1_700_000_000),
	} {
		if fields[key] != expected {
			t.Fatalf("status field %q = %#v, want %#v", key, fields[key], expected)
		}
	}
	if _, exists := fields["quarantined_chains"]; !exists {
		t.Fatal("status fields omitted quarantined_chains")
	}
}

func TestV2SyncReportsQueuedWorkInJSONAndText(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.PendingCompletions = append(state.PendingCompletions, queuedV2TestCompletion())
	state.UndrainedControl = true
	state.Chains["in:data"].Quarantined = true
	state.Chains["in:data"].QuarantineReason = "gap before sequence 7"
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &failingPeerTransport{}, nil
	}
	if err := a.run([]string{"sync", "laptop", "--json"}); err == nil {
		t.Fatal("sync hid an incomplete drain")
	}
	var results []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("sync results = %#v", results)
	}
	result := results[0]
	if result["pending_completions"] != float64(1) || result["undrained_control"] != true {
		t.Fatalf("sync JSON queue state = %#v", result)
	}
	quarantined, ok := result["quarantined_chains"].([]any)
	if !ok || len(quarantined) != 1 {
		t.Fatalf("sync JSON quarantined chains = %#v", result["quarantined_chains"])
	}
	entry := quarantined[0].(map[string]any)
	if entry["chain"] != "in:data" || entry["reason"] != "gap before sequence 7" {
		t.Fatalf("sync JSON quarantine entry = %#v", entry)
	}

	stdout.Reset()
	if err := a.run([]string{"sync", "laptop"}); err == nil {
		t.Fatal("sync hid an incomplete drain")
	}
	text := stdout.String()
	for _, fragment := range []string{
		"Peer laptop",
		"result                     incomplete",
		"queued completions         1",
		"undrained control          yes",
		"- in:data (gap before sequence 7)",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("sync text %q omitted %q", text, fragment)
		}
	}
}

func TestV2ReceiveReportsStatusWhenNothingIsPending(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.UndrainedControl = true
	state.Chains["in:control"].Quarantined = true
	state.Chains["in:control"].QuarantineReason = "fork at sequence 3"
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &emptySlotTransport{}, nil
	}
	if err := a.run([]string{"receive", "laptop", "--json"}); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["received"] != false || result["undrained_control"] != true {
		t.Fatalf("receive JSON = %#v", result)
	}
	if _, exists := result["pending_completions"]; !exists {
		t.Fatalf("receive JSON omitted queued completions: %#v", result)
	}
	quarantined, ok := result["quarantined_chains"].([]any)
	if !ok || len(quarantined) != 1 {
		t.Fatalf("receive JSON quarantined chains = %#v", result["quarantined_chains"])
	}

	stdout.Reset()
	if err := a.run([]string{"receive", "laptop"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Status\n  queued deliveries          0\n  queued completions         0") ||
		!strings.Contains(stdout.String(), "- in:control (fork at sequence 3)") {
		t.Fatalf("receive text = %s", stdout.String())
	}
}

// echoingV2DeliveryTransport accepts one granular delivery and returns the
// requested transport policy unchanged, which is the smallest server answer a
// successful send accepts.
type echoingV2DeliveryTransport struct {
	requests int
}

func (transport *echoingV2DeliveryTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	transport.requests++
	if request.Method != "POST" || request.Path != "/v2/deliveries" {
		return nil, errors.New("unexpected granular delivery request")
	}
	header, _, err := decodeV2GranularFrame(request.Body, 4, 5)
	if err != nil {
		return nil, err
	}
	policy, err := normalizeV2Map(header[3])
	if err != nil {
		return nil, err
	}
	body, err := v2EncMode.Marshal(map[int]any{
		1: bytesRepeatV2(0x71, 16),
		2: policy,
		3: false,
		4: []any{},
		5: []any{},
	})
	if err != nil {
		return nil, err
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
}

func TestV2SendReportsStatusInJSONAndText(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.UndrainedControl = true
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &echoingV2DeliveryTransport{}, nil
	}
	if err := a.run([]string{"send", "laptop", "-m", "hello", "--json"}); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["sequence"] != float64(1) || result["pending_deliveries"] != float64(0) ||
		result["unacknowledged_deliveries"] != float64(1) || result["undrained_control"] != true {
		t.Fatalf("send JSON = %#v", result)
	}
	if _, exists := result["pending_completions"]; !exists {
		t.Fatalf("send JSON omitted queued completions: %#v", result)
	}

	stdout.Reset()
	if err := a.run([]string{"send", "laptop", "-m", "hello again"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Sent to laptop as data sequence 2") ||
		!strings.Contains(stdout.String(), "Status\n  queued deliveries          0\n  queued completions         0\n  queued control events      0\n  unacknowledged deliveries  2\n  inbound waiting            no\n  undrained control          yes") {
		t.Fatalf("send text = %s", stdout.String())
	}
}

// TestV2StatusSeparatesQueuedWorkFromUnacknowledgedDeliveries pins the
// distinction the counters exist to draw: a delivery that published cleanly
// leaves no local queue behind, yet stays unacknowledged until the peer
// receives it and its acknowledgement is drained.
func TestV2StatusSeparatesQueuedWorkFromUnacknowledgedDeliveries(t *testing.T) {
	state := &v2PeerDeliveryState{
		Sent: map[string]v2SentDelivery{
			"aa": {Sequence: 1},
		},
	}
	status := v2DeliveryStatusOf(state)
	if status.PendingDeliveries != 0 || status.UnacknowledgedDeliveries != 1 {
		t.Fatalf("published delivery status = %#v", status)
	}
	if status.needsAttention() {
		t.Fatal("an unacknowledged delivery was reported as needing attention")
	}
	sent := state.Sent["aa"]
	sent.Acknowledged = true
	state.Sent["aa"] = sent
	if acknowledged := v2DeliveryStatusOf(state); acknowledged.UnacknowledgedDeliveries != 0 {
		t.Fatalf("acknowledged delivery status = %#v", acknowledged)
	}
}

func TestV2PeerShowAndDoctorReportHaltedRelationship(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.Halted = true
	state.HaltReason = "relationship revoked locally"
	state.PendingGranularDeliveries = append(state.PendingGranularDeliveries, v2PendingGranularDelivery{
		OperationID:         strings.Repeat("07", 16),
		EncryptedDescriptor: v2Base64URL([]byte("descriptor")),
		PayloadCiphertext:   v2Base64URL([]byte("payload")),
		DataSlot:            strings.Repeat("08", 16),
		SlotEpoch:           20_000,
		RequestedPolicy:     v2Base64URL([]byte("policy")),
		DescriptorDigest:    strings.Repeat("09", 32),
		Sequence:            1,
		CreatedAt:           uint64(time.Now().Unix()),
	})
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	if err := a.run([]string{"peer", "show", "laptop"}); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"queued deliveries          1",
		"halted                     yes (relationship revoked locally)",
	} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("peer show text %q omitted %q", stdout.String(), fragment)
		}
	}

	stdout.Reset()
	a = newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if code := a.main([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	if !strings.Contains(stdout.String(), "Delivery\n    queued deliveries          1") ||
		!strings.Contains(stdout.String(), "halted                     yes (relationship revoked locally)") {
		t.Fatalf("doctor text = %s", stdout.String())
	}

	stdout.Reset()
	a = newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return &stubV2Transport{}, nil }
	if code := a.main([]string{"doctor", "--json"}); code != 0 {
		t.Fatalf("doctor code = %d", code)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	origins := report["origins"].([]any)
	peer := origins[len(origins)-1].(map[string]any)
	delivery, ok := peer["delivery"].(map[string]any)
	if !ok {
		t.Fatalf("doctor peer origin = %#v", peer)
	}
	if delivery["halted"] != true || delivery["halt_reason"] != "relationship revoked locally" ||
		delivery["pending_deliveries"] != float64(1) {
		t.Fatalf("doctor delivery = %#v", delivery)
	}
}

func TestQuarantinedV2GitDeliveriesListUnpromotedCheckpoints(t *testing.T) {
	state := &v2GitPeerState{
		Inbound: map[string]v2GitInboundState{
			"aa": {Sequence: 4, Phase: "verified"},
			"bb": {Sequence: 5, Phase: "output-committed"},
			"cc": {Sequence: 6, Phase: "payload-verified"},
		},
	}
	quarantined := quarantinedV2GitDeliveries(state)
	if len(quarantined) != 2 ||
		quarantined[0]["descriptor_digest"] != "aa" ||
		quarantined[1]["descriptor_digest"] != "cc" {
		t.Fatalf("quarantined Git deliveries = %#v", quarantined)
	}
	// A quarantined checkpoint leaves every shared counter at zero, so the block
	// has to raise itself here without -v or the condition goes unreported.
	block := v2GitStatusReport(false, v2DeliveryStatus{}, quarantined, nil).String()
	if !strings.Contains(block, "- aa (verified)") || !strings.Contains(block, "- cc (payload-verified)") {
		t.Fatalf("quarantine block = %q", block)
	}
	empty := v2GitStatusReport(true, v2DeliveryStatus{}, nil, nil).String()
	if !strings.Contains(empty, "quarantined Git deliveries  none") {
		t.Fatalf("empty quarantine block = %q", empty)
	}
	if strings.Contains(empty, "refused Git deliveries") {
		t.Fatalf("empty report named refused deliveries: %q", empty)
	}
	if quiet := v2GitStatusReport(false, v2DeliveryStatus{}, nil, nil).String(); quiet != "" {
		t.Fatalf("clean Git status block without --verbose = %q", quiet)
	}
	refused := v2GitStatusReport(false, v2DeliveryStatus{}, nil, []map[string]any{
		{"descriptor_digest": "dd", "reason": "Git metadata is invalid"},
	}).String()
	if !strings.Contains(refused, "- dd (Git metadata is invalid)") {
		t.Fatalf("refused block = %q", refused)
	}
}

// A send that went cleanly has nothing to report beyond what it did. The
// counters are still one flag away, and a relationship in trouble still raises
// them without being asked, so the quiet default never hides a stalled peer.
func TestV2SendKeepsStatusBehindVerboseUntilSomethingNeedsAttention(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &echoingV2DeliveryTransport{}, nil
	}
	if err := a.run([]string{"send", "laptop", "-m", "hello"}); err != nil {
		t.Fatal(err)
	}
	// Byte-exact, because both halves matter: no status block on a clean run,
	// and no wording that claims this command waits for an acknowledgement it
	// never waits for.
	quiet := stdout.String()
	if quiet != "Sent to laptop as data sequence 1.\n"+
		"Not acknowledged yet; 'dud sync laptop' collects the acknowledgement.\n" {
		t.Fatalf("send text = %q", quiet)
	}

	stdout.Reset()
	if err := a.run([]string{"send", "laptop", "-m", "hello again", "-v"}); err != nil {
		t.Fatal(err)
	}
	verbose := stdout.String()
	for _, row := range []string{
		"Status\n  queued deliveries          0",
		"unacknowledged deliveries  2",
		"inbound waiting            no",
		"quarantined chains         none",
		"halted                     no",
	} {
		if !strings.Contains(verbose, row) {
			t.Fatalf("send -v text %q omitted %q", verbose, row)
		}
	}
}

// A quarantined chain is exactly the case the quiet default must not swallow.
func TestV2SendReportsStatusWithoutVerboseWhenAChainIsQuarantined(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	state.Chains["in:control"].Quarantined = true
	state.Chains["in:control"].QuarantineReason = "fork at sequence 3"
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &echoingV2DeliveryTransport{}, nil
	}
	if err := a.run([]string{"send", "laptop", "-m", "hello"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "quarantined chains         1") ||
		!strings.Contains(stdout.String(), "- in:control (fork at sequence 3)") {
		t.Fatalf("send hid a quarantined chain: %q", stdout.String())
	}
}

// A receive that empties the queue reports what arrived and stops there.
func TestV2ReceiveKeepsStatusBehindVerboseWhenNothingIsPending(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	a := newApp(strings.NewReader(""), &stdout, &bytes.Buffer{})
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
		return &emptySlotTransport{}, nil
	}
	if err := a.run([]string{"receive", "laptop"}); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "No pending delivery from laptop.\n" {
		t.Fatalf("clean receive text = %q", stdout.String())
	}

	stdout.Reset()
	if err := a.run([]string{"receive", "laptop", "--verbose"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Status\n  queued deliveries          0") {
		t.Fatalf("receive --verbose text = %q", stdout.String())
	}
}

// --json is a machine contract: every counter stays in it, and -v changes
// nothing there. The flag is still accepted so scripts can pass it uniformly.
func TestV2VerboseOptionIsRejectedTwiceAndIgnoredByJSON(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	newSender := func(stdout *bytes.Buffer) *app {
		a := newApp(strings.NewReader(""), stdout, &bytes.Buffer{})
		a.newV2Transport = func(v2TransportOptions) (v2Transport, error) {
			return &echoingV2DeliveryTransport{}, nil
		}
		return a
	}
	var stdout bytes.Buffer
	err := newSender(&stdout).run([]string{"send", "laptop", "-m", "hello", "-v", "--verbose"})
	if err == nil || !strings.Contains(err.Error(), "--verbose may be specified only once") {
		t.Fatalf("duplicate --verbose error = %v", err)
	}

	stdout.Reset()
	if err := newSender(&stdout).run([]string{"send", "laptop", "-m", "hello", "--json"}); err != nil {
		t.Fatal(err)
	}
	plain := map[string]any{}
	if err := json.Unmarshal(stdout.Bytes(), &plain); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if err := newSender(&stdout).run([]string{"send", "laptop", "-m", "hello", "--json", "-v"}); err != nil {
		t.Fatal(err)
	}
	verbose := map[string]any{}
	if err := json.Unmarshal(stdout.Bytes(), &verbose); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sortedKeys(plain), sortedKeys(verbose)) {
		t.Fatalf("--json keys differ with -v: %v vs %v", sortedKeys(plain), sortedKeys(verbose))
	}
}
