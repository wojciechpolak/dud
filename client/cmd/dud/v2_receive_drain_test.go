// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// v2TestPeerCrypto carries the key material withV2Peer derives at run time, so
// a test can build the deliveries a peer would have published without pairing
// two devices against a server.
type v2TestPeerCrypto struct {
	relationshipID []byte
	localID        []byte
	peerID         []byte
	signingKey     ed25519.PrivateKey
	recipient      age.Recipient
	inboundSecret  []byte
	origin         string
	role           uint64
}

func newV2TestPeerCrypto(t *testing.T, paths v2Paths, state *v2PeerDeliveryState, alias string) v2TestPeerCrypto {
	t.Helper()
	cfg, _, err := loadV2Config()
	if err != nil {
		t.Fatal(err)
	}
	peer := cfg.Peers[alias]
	relationshipID, err := hex.DecodeString(peer.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loadV2MasterSeed(paths)
	if err != nil {
		t.Fatal(err)
	}
	localID, err := deriveV2DeviceID(seed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := hex.DecodeString(peer.PeerPseudonymousID)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := deriveV2SigningKey(seed, relationshipID, 0)
	if err != nil {
		t.Fatal(err)
	}
	rawRecipient, err := decodeV2Base64URL(peer.PeerAgeRecipient, 1216)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.ParseHybridRecipient(bech32Encode("age1pq", rawRecipient))
	if err != nil {
		t.Fatal(err)
	}
	inboundSecret, err := decodeV2Base64URL(state.InboundRelationshipSecret, 32)
	if err != nil {
		t.Fatal(err)
	}
	return v2TestPeerCrypto{
		relationshipID: relationshipID,
		localID:        localID,
		peerID:         peerID,
		signingKey:     signingKey,
		recipient:      recipient,
		inboundSecret:  inboundSecret,
		origin:         "https://dud.example.com",
		role:           state.Role,
	}
}

// stubbedV2Delivery is one published delivery as the server would hold it.
type stubbedV2Delivery struct {
	id         []byte
	slot       []byte
	epoch      uint64
	descriptor []byte
	payload    []byte
	policy     map[int]any
	digest     string
}

// buildInboundV2Delivery signs and encrypts one delivery in the peer's outbound
// direction, which is this device's inbound direction.
func buildInboundV2Delivery(t *testing.T, crypto v2TestPeerCrypto, sequence uint64, previousDigest string, payloadType uint64, displayName string, plaintext []byte) stubbedV2Delivery {
	t.Helper()
	var typeMetadata map[int]any
	if payloadType == 4 {
		typeMetadata = encodeV2GitMetadata(v2GitMetadata{
			RepositoryID:  bytesRepeatV2(0x2a, 16),
			ObjectFormat:  1,
			BundleVersion: 3,
			Refs:          map[string][]byte{"refs/heads/main": bytesRepeatV2(0x2b, 20)},
			Prerequisites: [][]byte{},
		})
	}
	var archiveFormat *uint64
	if payloadType == 3 {
		entries, err := inspectV2CollectionArchive(plaintext, uint64(len(plaintext)))
		if err != nil {
			t.Fatal(err)
		}
		tops := map[string]bool{}
		for _, entry := range entries {
			tops[strings.Split(entry.name, "/")[0]] = true
		}
		names := make([]any, 0, len(tops))
		for name := range tops {
			names = append(names, name)
		}
		sort.Slice(names, func(left, right int) bool { return names[left].(string) < names[right].(string) })
		typeMetadata = map[int]any{1: uint64(len(names)), 2: names}
		format := uint64(1)
		archiveFormat = &format
	}
	now := uint64(time.Now().Unix())
	policy := v2TransportPolicy{ExpiresAt: now + 86_400, Consume: 0, ClaimLeaseSeconds: 300, AckMode: 1}
	payloadCiphertext, err := encryptV2Payload(plaintext, crypto.recipient)
	if err != nil {
		t.Fatal(err)
	}
	descriptorID, err := newV2DescriptorID()
	if err != nil {
		t.Fatal(err)
	}
	plainDigest := sha256.Sum256(plaintext)
	cipherDigest := sha256.Sum256(payloadCiphertext)
	plaintextSize := uint64(len(plaintext))
	descriptor := v2Descriptor{
		DescriptorID:      descriptorID,
		PayloadType:       payloadType,
		RelationshipID:    crypto.relationshipID,
		Direction:         v2InboundDirection(crypto.role),
		Chain:             0,
		KeyEpoch:          0,
		Sequence:          sequence,
		PreviousDigest:    mustDecodeHexV2(previousDigest, 32),
		SenderDeviceID:    crypto.peerID,
		RecipientDeviceID: crypto.localID,
		CanonicalOrigin:   crypto.origin,
		CreatedAt:         now,
		TransportPolicy:   policy,
		PayloadHash:       plainDigest[:],
		ChunkHashes:       [][]byte{cipherDigest[:]},
		DisplayName:       displayName,
		ArchiveFormat:     archiveFormat,
		PlaintextSize:     &plaintextSize,
		TypeMetadata:      typeMetadata,
	}
	descriptorCiphertext, err := encryptV2Envelope(descriptor, crypto.signingKey, crypto.recipient)
	if err != nil {
		t.Fatal(err)
	}
	signedMap, err := descriptorMap(descriptor, crypto.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := v2EncMode.Marshal(signedMap)
	if err != nil {
		t.Fatal(err)
	}
	descriptorDigest := sha256.Sum256(signedBytes)
	epoch := v2SlotEpoch(time.Now())
	slot, err := deriveV2Slot(crypto.inboundSecret, "data", epoch)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	id[0] = byte(sequence)
	id[15] = 0x0d
	return stubbedV2Delivery{
		id:         id,
		slot:       slot,
		epoch:      epoch,
		descriptor: descriptorCiphertext,
		payload:    payloadCiphertext,
		policy:     v2TransportPolicyMap(policy),
		digest:     hex.EncodeToString(descriptorDigest[:]),
	}
}

// drainingInboxTransport answers like the server: one inbox read returns the
// oldest pending delivery and never consumes it, and only a completion retires
// it. Draining N deliveries therefore costs N inbox reads and N completions.
type drainingInboxTransport struct {
	queue         []stubbedV2Delivery
	inboxRequests int
	completions   int
	// holdHead keeps the head in the queue after its completion, which is how a
	// delivery this device has already applied comes back on the next read.
	holdHead bool
}

func (transport *drainingInboxTransport) Do(_ context.Context, request v2Request) (*v2Response, error) {
	if request.Method != "POST" {
		return nil, errors.New("unexpected method " + request.Method)
	}
	if strings.HasSuffix(request.Path, "/complete") {
		transport.completions++
		if len(transport.queue) == 0 {
			return nil, errors.New("completion without a pending delivery")
		}
		head := transport.queue[0]
		if !transport.holdHead {
			transport.queue = transport.queue[1:]
		}
		body, err := v2EncMode.Marshal(map[int]any{
			1: head.id,
			2: bytesRepeatV2(0x7a, 16),
			3: false,
		})
		if err != nil {
			return nil, err
		}
		return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
	}
	if request.Path != "/v2/inbox" {
		return nil, errors.New("unexpected path " + request.Path)
	}
	transport.inboxRequests++
	var query map[int]any
	if err := v2DecMode.Unmarshal(request.Body, &query); err != nil {
		return nil, err
	}
	rawProofs, ok := query[1].([]any)
	if !ok {
		return nil, errors.New("inbox request data proofs are invalid")
	}
	pendingEpochs := map[uint64]bool{}
	for _, delivery := range transport.queue {
		pendingEpochs[delivery.epoch] = true
	}
	results := make([]any, 0, len(rawProofs))
	pending := []any{}
	seen := map[uint64]bool{}
	var head *stubbedV2Delivery
	for _, raw := range rawProofs {
		proof, err := normalizeV2Map(raw)
		if err != nil {
			return nil, err
		}
		slot, _ := proof[1].([]byte)
		epoch, _ := asV2Uint(proof[2])
		more := pendingEpochs[epoch]
		results = append(results, map[int]any{1: proof[1], 2: proof[2], 3: more})
		if more && !seen[epoch] {
			seen[epoch] = true
			pending = append(pending, epoch)
		}
		if head == nil && len(transport.queue) != 0 && bytes.Equal(slot, transport.queue[0].slot) {
			head = &transport.queue[0]
		}
	}
	header := map[int]any{1: results, 2: []any{}, 9: pending}
	var payload []byte
	if head != nil {
		payload = head.payload
		header[3] = head.id
		header[4] = head.slot
		header[5] = head.descriptor
		header[6] = head.policy
	}
	digest := sha256.Sum256(payload)
	header[7] = uint64(len(payload))
	header[8] = digest[:]
	body, err := encodeV2GranularFrame(header, payload, 7, 8)
	if err != nil {
		return nil, err
	}
	return &v2Response{StatusCode: 200, ContentType: v2CBORContentType, Body: body}, nil
}

// queueInboundV2TestDeliveries chains sequence 1..len(files) onto the inbound
// data chain, the way a peer that sent several files in a row would.
func queueInboundV2TestDeliveries(t *testing.T, crypto v2TestPeerCrypto, names []string) []stubbedV2Delivery {
	t.Helper()
	queue := make([]stubbedV2Delivery, 0, len(names))
	previous := strings.Repeat("00", 32)
	for index, name := range names {
		delivery := buildInboundV2Delivery(
			t, crypto, uint64(index+1), previous, 2, name,
			[]byte("contents of "+name+"\n"),
		)
		previous = delivery.digest
		queue = append(queue, delivery)
	}
	return queue
}

func newDrainingV2TestApp(t *testing.T, transport v2Transport, stdout, stderr *bytes.Buffer) *app {
	t.Helper()
	a := newApp(strings.NewReader(""), stdout, stderr)
	a.newV2Transport = func(v2TransportOptions) (v2Transport, error) { return transport, nil }
	return a
}

// One receive has to empty the queue. Before this, two files meant three
// invocations: one per file, plus one to learn there was nothing left.
func TestV2ReceiveDrainsEveryPendingDeliveryInOneRun(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	queue := queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE", "README.md"})
	transport := &drainingInboxTransport{queue: queue}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	// -v because a fully drained queue is the quiet case: nothing is queued,
	// undrained, quarantined, or waiting, so the block this asserts on is only
	// printed on request.
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir, "-v"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LICENSE", "README.md"} {
		body, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
		if string(body) != "contents of "+name+"\n" {
			t.Fatalf("%s = %q", name, body)
		}
	}
	if transport.completions != 2 {
		t.Fatalf("completions = %d, want one per delivery", transport.completions)
	}
	// Two deliveries plus the read that found the queue empty.
	if transport.inboxRequests != 3 {
		t.Fatalf("inbox requests = %d", transport.inboxRequests)
	}
	text := stdout.String()
	if !strings.Contains(text, "Received 2 deliveries from laptop.") ||
		!strings.Contains(text, "1 LICENSE") ||
		!strings.Contains(text, "2 README.md") {
		t.Fatalf("receive text = %s", text)
	}
	if !strings.Contains(text, "inbound waiting            no") {
		t.Fatalf("drained receive still reports waiting work: %s", text)
	}
	drained, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if drained.Chains["in:data"].ReceiveWatermark != 2 {
		t.Fatalf("watermark = %d", drained.Chains["in:data"].ReceiveWatermark)
	}
	expiresAt, _ := asV2Uint(queue[0].policy[1])
	transfer, exists := drained.InboundTransfers[queue[0].digest]
	if !exists || transfer.ExpiresAt != expiresAt {
		t.Fatalf("received transfer expiry = %#v, want %d", transfer, expiresAt)
	}
}

// readV2SingleTransferPayload names the one durable payload a run retained, so
// a test can assert on the path DUD chose without recomputing the digest.
func readV2SingleTransferPayload(t *testing.T, transferDir string) string {
	t.Helper()
	entries, err := os.ReadDir(transferDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("transfers directory holds %d entries, want exactly one", len(entries))
	}
	return filepath.Join(transferDir, entries[0].Name())
}

func assertNoV2RetainedPayloads(t *testing.T, transferDir string) {
	t.Helper()
	entries, err := os.ReadDir(transferDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("receive left plaintext under %s: %v", transferDir, entries)
	}
}

// The durable copy exists so that a crash mid-receive can resume through it.
// Once the committed output holds the same bytes it is redundant, and it is
// plaintext: keeping it until the sender's chosen lifetime expired would leave
// a second copy of every ordinary delivery under the world directory, at a path
// the operator never named and the report never mentioned.
func TestV2ReceiveDiscardsItsOwnCopyOnceTheOutputHoldsThePayload(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	queue := queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"})
	transport := &drainingInboxTransport{queue: queue}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir, "--json"}); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(outDir, "LICENSE")); err != nil || string(body) != "contents of LICENSE\n" {
		t.Fatalf("committed output = %q, %v", body, err)
	}
	assertNoV2RetainedPayloads(t, filepath.Join(paths.StateDir, "transfers", state.RelationshipID))

	// The record outlives the copy: it is what refuses a redelivery as a replay
	// and what 'receive --id' resolves. Only the paths into the discarded copy
	// are cleared, so the expiry pruner has nothing left to chase.
	drained, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	transfer := drained.InboundTransfers[queue[0].digest]
	if transfer.Phase != "output-committed" || transfer.PlaintextPayload != "" || transfer.TemporaryOutput != "" {
		t.Fatalf("discarded transfer = %#v", transfer)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	deliveries, _ := result["deliveries"].([]any)
	if len(deliveries) != 1 {
		t.Fatalf("receive JSON = %#v", result)
	}
	item, _ := deliveries[0].(map[string]any)
	if _, announced := item["output_expires_at"]; announced {
		t.Fatalf("discarded delivery still announces a copy with a deadline: %#v", item)
	}
	if _, retained := item["retained_payload"]; retained {
		t.Fatalf("discarded delivery still names a retained payload: %#v", item)
	}
}

// Discarding the copy must not cost the documented recovery command, so it
// reads the committed output instead — the same bytes, at the path the operator
// chose, rather than a duplicate held on disk in case this command is run.
func TestV2ReceiveByDigestFallsBackToTheCommittedOutput(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	queue := queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"})
	transport := &drainingInboxTransport{queue: queue}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir}); err != nil {
		t.Fatal(err)
	}
	assertNoV2RetainedPayloads(t, filepath.Join(paths.StateDir, "transfers", state.RelationshipID))

	rescued := filepath.Join(t.TempDir(), "rescued")
	stdout.Reset()
	if err := a.run([]string{"receive", "laptop", "--id", queue[0].digest, "--out", rescued}); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(rescued); err != nil || string(body) != "contents of LICENSE\n" {
		t.Fatalf("recovered payload = %q, %v", body, err)
	}
}

// Falling back to the committed output means exporting a file the operator can
// have edited since, so the fallback is checked against the digest the
// descriptor signed. Exporting the edit as though it were the delivery would be
// worse than refusing.
func TestV2ReceiveByDigestRefusesAnEditedCommittedOutput(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	queue := queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"})
	transport := &drainingInboxTransport{queue: queue}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "LICENSE"), []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.run([]string{"receive", "laptop", "--id", queue[0].digest, "--out", filepath.Join(t.TempDir(), "rescued")})
	if err == nil || !strings.Contains(err.Error(), "no longer matches delivery") {
		t.Fatalf("export of an edited output = %v", err)
	}
}

func TestV2ReceiveExtractsACollectionDelivery(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("collection\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive, _, err := createV2CollectionArchive([]string{source})
	if err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	delivery := buildInboundV2Delivery(t, crypto, 1, strings.Repeat("00", 32), 3, "collection.tar", archive)
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{delivery}}
	destination := filepath.Join(t.TempDir(), "collection")
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", destination}); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(destination, filepath.Base(source), "README.md")); err != nil || string(body) != "collection\n" {
		t.Fatalf("collection output = %q, %v", body, err)
	}
	// An extracted collection is the one delivery whose durable archive outlives
	// the run: the committed output is a directory, so it cannot stand in for
	// the archive the way an ordinary file output does. The report has to name
	// the archive, because it is plaintext at a path the operator did not pick.
	report := stdout.String()
	if !strings.Contains(report, "Received 1 delivery from laptop.") ||
		!strings.Contains(report, destination) {
		t.Fatalf("collection report = %s", report)
	}
	transfers := filepath.Join(paths.StateDir, "transfers", state.RelationshipID)
	retained := readV2SingleTransferPayload(t, transfers)
	if !strings.Contains(report, "archive retained at "+retained) {
		t.Fatalf("collection report does not name the retained archive: %s", report)
	}
	if body, err := os.ReadFile(retained); err != nil || !bytes.Equal(body, archive) {
		t.Fatalf("retained archive = %v", err)
	}
}

// --max 1 is the old behaviour, and its report has to stay exactly what it was:
// scripts and the end-to-end suite read that one line.
func TestV2ReceiveMaxOneKeepsTheSingleDeliveryReport(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	transport := &drainingInboxTransport{queue: queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE", "README.md"})}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir, "--max", "1"}); err != nil {
		t.Fatal(err)
	}
	if transport.inboxRequests != 1 || transport.completions != 1 {
		t.Fatalf("bounded receive made %d reads and %d completions", transport.inboxRequests, transport.completions)
	}
	want := "Received data sequence 1 from laptop at " + filepath.Join(outDir, "LICENSE") + ".\nStatus\n"
	if !strings.HasPrefix(stdout.String(), want) {
		t.Fatalf("bounded receive text = %q", stdout.String())
	}
	if _, err := os.Lstat(filepath.Join(outDir, "README.md")); err == nil {
		t.Fatal("bounded receive drained past its limit")
	}
}

// A head this device already applied is never retired by a read, so a drain
// that kept polling it would spin forever.
func TestV2ReceiveStopsInsteadOfSpinningOnAnAlreadyAppliedHead(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	transport := &drainingInboxTransport{
		queue:    queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"}),
		holdHead: true,
	}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir}); err != nil {
		t.Fatal(err)
	}
	if transport.inboxRequests != 2 {
		t.Fatalf("inbox requests = %d, want the delivery and one more", transport.inboxRequests)
	}
	if !strings.Contains(stdout.String(), "awaits server retirement") {
		t.Fatalf("receive text = %s", stdout.String())
	}
}

// A Git checkpoint shares the data chain with files, so one can sit behind
// them. Everything ahead of it must still land, and the report has to name the
// command that takes it.
func TestV2ReceiveStopsAtAGitCheckpointWithoutLosingEarlierDeliveries(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	queue := queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"})
	queue = append(queue, buildInboundV2Delivery(t, crypto, 2, queue[0].digest, 4, "bundle", []byte("# v2 git bundle\n")))
	transport := &drainingInboxTransport{queue: queue}
	outDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir}); err != nil {
		t.Fatalf("a blocked queue head failed a run that committed work: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outDir, "LICENSE")); err != nil {
		t.Fatalf("the delivery ahead of the checkpoint was lost: %v", err)
	}
	text := stdout.String()
	if !strings.Contains(text, "stopped at sequence 2") ||
		!strings.Contains(text, "Git checkpoint at sequence 2") ||
		!strings.Contains(text, "dud git fetch laptop") {
		t.Fatalf("receive text = %s", text)
	}
	// The checkpoint is still queued, so the report must not claim otherwise.
	if !strings.Contains(text, "inbound waiting            yes") {
		t.Fatalf("blocked receive reported an empty queue: %s", text)
	}
}

// A checkpoint with nothing committed ahead of it has no partial result worth
// reporting, so it fails the way the single-delivery receive always did.
func TestV2ReceiveFailsWhenAGitCheckpointBlocksTheWholeRun(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{
		buildInboundV2Delivery(t, crypto, 1, strings.Repeat("00", 32), 4, "bundle", []byte("# v2 git bundle\n")),
	}}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	err := a.run([]string{"receive", "laptop", "--out-dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "dud git fetch laptop") {
		t.Fatalf("blocked receive error = %v", err)
	}
}

// The conflict is on the second delivery, so each policy is measured by what it
// does to the queue rather than by whether the run started at all.
func TestV2ReceiveConflictPolicies(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		policy        string
		wantBody      string
		wantText      string
		wantDelivered int
	}{
		{
			name: "skip keeps the queue moving", policy: "skip",
			wantBody: "local edit\n", wantText: "skipped", wantDelivered: 2,
		},
		{
			name: "overwrite replaces the file", policy: "overwrite",
			wantBody: "contents of README.md\n", wantText: "Received 2 deliveries", wantDelivered: 2,
		},
		{
			name: "refuse stops the drain", policy: "refuse",
			wantBody: "local edit\n", wantText: "would overwrite", wantDelivered: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			paths, state := newPairedV2TestPeer(t, "laptop")
			if err := writeV2PeerDeliveryState(paths, state); err != nil {
				t.Fatal(err)
			}
			crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
			transport := &drainingInboxTransport{queue: queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE", "README.md"})}
			outDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(outDir, "README.md"), []byte("local edit\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
			if err := a.run([]string{"receive", "laptop", "--out-dir", outDir, "--on-conflict", testCase.policy}); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(outDir, "README.md"))
			if err != nil || string(body) != testCase.wantBody {
				t.Fatalf("README.md = %q, %v", body, err)
			}
			if !strings.Contains(stdout.String(), testCase.wantText) {
				t.Fatalf("receive text = %s", stdout.String())
			}
			// Refusing leaves the conflicting delivery queued for a later run;
			// skipping and overwriting both acknowledge it and move on.
			if transport.completions != testCase.wantDelivered {
				t.Fatalf("%s acknowledged %d deliveries", testCase.policy, transport.completions)
			}
		})
	}
}

// Refusing with nothing yet committed has no partial result to report, so it
// keeps the wording and the non-zero exit the one-at-a-time receive always had.
func TestV2ReceiveRefuseFailsWhenTheFirstDeliveryConflicts(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	transport := &drainingInboxTransport{queue: queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"})}
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "LICENSE"), []byte("local edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	err := a.run([]string{"receive", "laptop", "--out-dir", outDir, "--on-conflict", "refuse"})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite existing output") {
		t.Fatalf("refused receive error = %v", err)
	}
	if transport.completions != 0 {
		t.Fatal("a refused delivery was acknowledged")
	}
}

// Skipping still commits and acknowledges, so the payload has to remain
// reachable: that is the whole reason skipping is safe to make the default.
func TestV2ReceiveSkippedOutputStaysRecoverableByDigest(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	queue := queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE"})
	transport := &drainingInboxTransport{queue: queue}
	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "LICENSE"), []byte("local edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", outDir}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "recover with: dud receive laptop --id "+queue[0].digest) {
		t.Fatalf("skip report = %s", stdout.String())
	}
	rescued := filepath.Join(outDir, "rescued")
	stdout.Reset()
	if err := a.run([]string{"receive", "laptop", "--id", queue[0].digest, "--out", rescued}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(rescued)
	if err != nil || string(body) != "contents of LICENSE\n" {
		t.Fatalf("recovered payload = %q, %v", body, err)
	}
}

func TestV2ReceiveJSONReportsEveryDrainedDelivery(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	transport := &drainingInboxTransport{queue: queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE", "README.md"})}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", t.TempDir(), "--json"}); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["received"] != true || result["count"] != float64(2) {
		t.Fatalf("receive JSON = %#v", result)
	}
	deliveries, ok := result["deliveries"].([]any)
	if !ok || len(deliveries) != 2 {
		t.Fatalf("receive JSON deliveries = %#v", result["deliveries"])
	}
	first, _ := deliveries[0].(map[string]any)
	if first["sequence"] != float64(1) || first["display_name"] != "LICENSE" || first["outcome"] != "received" {
		t.Fatalf("first delivery = %#v", first)
	}
	// The single-delivery keys only make sense for a run that drained one.
	if _, exists := result["sequence"]; exists {
		t.Fatalf("multi-delivery JSON echoed a single sequence: %#v", result)
	}
	if result["inbound_waiting"] != false {
		t.Fatalf("drained JSON still reports waiting work: %#v", result)
	}
}

// A message payload is the output, so it owns stdout. Once a drain can mix a
// message with a file, the report has to move off stdout for the whole run or
// piping a receive would interleave prose with the messages.
func TestV2ReceiveKeepsMessagePayloadsAloneOnStdout(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	first := buildInboundV2Delivery(t, crypto, 1, strings.Repeat("00", 32), 1, "", []byte("first message\n"))
	second := buildInboundV2Delivery(t, crypto, 2, first.digest, 1, "", []byte("second message\n"))
	third := buildInboundV2Delivery(t, crypto, 3, second.digest, 2, "LICENSE", []byte("contents of LICENSE\n"))
	transport := &drainingInboxTransport{queue: []stubbedV2Delivery{first, second, third}}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"receive", "laptop", "--out-dir", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "first message\nsecond message\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Received 3 deliveries from laptop.") ||
		!strings.Contains(stderr.String(), "message written to stdout") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

// The inbox preview must leave the queue exactly as it found it: reads do not
// consume, and this one must not commit, acknowledge, or advance a watermark.
func TestV2InboxPreviewsTheHeadWithoutCommittingIt(t *testing.T) {
	paths, state := newPairedV2TestPeer(t, "laptop")
	if err := writeV2PeerDeliveryState(paths, state); err != nil {
		t.Fatal(err)
	}
	crypto := newV2TestPeerCrypto(t, paths, state, "laptop")
	transport := &drainingInboxTransport{queue: queueInboundV2TestDeliveries(t, crypto, []string{"LICENSE", "README.md"})}
	var stdout, stderr bytes.Buffer
	a := newDrainingV2TestApp(t, transport, &stdout, &stderr)
	if err := a.run([]string{"inbox", "laptop"}); err != nil {
		t.Fatal(err)
	}
	text := stdout.String()
	if !strings.Contains(text, "Inbox laptop") ||
		!strings.Contains(text, "next delivery  sequence 1") ||
		!strings.Contains(text, "kind           file") ||
		!strings.Contains(text, "name           LICENSE") ||
		!strings.Contains(text, "more waiting   yes") {
		t.Fatalf("inbox text = %s", text)
	}
	if !strings.Contains(text, "Only the oldest delivery is visible") {
		t.Fatalf("inbox omitted its own limitation: %s", text)
	}
	if transport.inboxRequests != 1 || transport.completions != 0 {
		t.Fatalf("preview made %d reads and %d completions", transport.inboxRequests, transport.completions)
	}
	previewed, err := loadV2PeerDeliveryState(paths, state.RelationshipID)
	if err != nil {
		t.Fatal(err)
	}
	if previewed.Chains["in:data"].ReceiveWatermark != 0 ||
		len(previewed.InboundTransfers) != 0 ||
		len(previewed.PendingCompletions) != 0 {
		t.Fatalf("preview committed state: %#v", previewed.Chains["in:data"])
	}
	// The delivery is still there afterwards, so a receive still gets it.
	stdout.Reset()
	if err := a.run([]string{"receive", "laptop", "--out-dir", t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Received 2 deliveries from laptop.") {
		t.Fatalf("receive after preview = %s", stdout.String())
	}
}
