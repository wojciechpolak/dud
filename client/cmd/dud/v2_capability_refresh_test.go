// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

type capabilityRefreshSyncTransport struct {
	issuer      capabilityReissueTransport
	inbox       emptySlotTransport
	paths       []string
	refuse      bool
	refuseInbox bool
}

func (transport *capabilityRefreshSyncTransport) Do(ctx context.Context, request v2Request) (*v2Response, error) {
	transport.paths = append(transport.paths, request.Path)
	if request.Path == "/v2/inbox" {
		var query map[int]any
		if err := v2DecMode.Unmarshal(request.Body, &query); err != nil {
			return nil, err
		}
		controls, ok := query[2].([]any)
		if !ok || len(controls) == 0 {
			return nil, errors.New("sync omitted its control proofs")
		}
		slot, err := normalizeV2Map(controls[0])
		if err != nil {
			return nil, err
		}
		proofBytes, _ := slot[4].([]byte)
		var proof map[int]any
		if err := v2DecMode.Unmarshal(proofBytes, &proof); err != nil {
			return nil, err
		}
		epoch, _ := asV2Uint(slot[2])
		expected, err := deriveV2DailyCapabilityLookupIDClient(bytesRepeatV2(0x92, 32), epoch)
		if err != nil {
			return nil, err
		}
		lookup, _ := proof[1].([]byte)
		if !bytes.Equal(lookup, expected) {
			return nil, errors.New("sync used a stale capability after refresh")
		}
		if transport.refuseInbox {
			body, err := v2EncMode.Marshal(map[int]any{1: uint64(1), 2: "Inbox request is invalid."})
			return &v2Response{StatusCode: 400, ContentType: v2CBORContentType, Body: body}, err
		}
		return transport.inbox.Do(ctx, request)
	}
	if transport.refuse && request.Path == "/v2/capabilities/reissue" {
		body, err := v2EncMode.Marshal(map[int]any{1: uint64(3), 2: "Relationship is revoked."})
		return &v2Response{StatusCode: 403, ContentType: v2CBORContentType, Body: body}, err
	}
	return transport.issuer.Do(ctx, request)
}

func requireV2SyncRefreshResult(t *testing.T, err error, refused bool) {
	t.Helper()
	if refused {
		if err == nil || !strings.Contains(err.Error(), "check the server logs") || strings.Contains(err.Error(), "--refresh-capabilities") {
			t.Fatalf("refreshed sync gave circular recovery advice: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestV2SyncRefreshesCapabilitiesBeforeDeliveryRequests(t *testing.T) {
	for _, name := range []string{"valid", "expired", "revoked", "halted", "locked", "refused after refresh"} {
		t.Run(name, func(t *testing.T) {
			paths, state := newPairedV2TestPeer(t, "laptop")
			if name == "expired" {
				state.CapabilitiesExpireAt = 1
			}
			if name == "halted" {
				state.Halted, state.HaltReason = true, "peer rollback"
			}
			state.Chains["out:data"].SendSequence = 9
			state.Chains["out:data"].SendDigest = hex.EncodeToString(bytesRepeatV2(0x81, 32))
			if err := writeV2PeerDeliveryState(paths, state); err != nil {
				t.Fatal(err)
			}
			if name == "locked" {
				unlock, err := acquireV2ConfigLock(paths)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(unlock)
			}
			relationshipID, err := hex.DecodeString(state.RelationshipID)
			if err != nil {
				t.Fatal(err)
			}
			seed, err := loadV2MasterSeed(paths)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := deriveV2RelationshipIdentity(seed, relationshipID, 0)
			if err != nil {
				t.Fatal(err)
			}
			transport := &capabilityRefreshSyncTransport{
				issuer:      capabilityReissueTransport{grant: encryptV2TestCapabilityGrant(t, identity.Recipient(), relationshipID, state.Role, "https://dud.example.com")},
				refuse:      name == "revoked",
				refuseInbox: name == "refused after refresh",
			}
			a := newDrainingV2TestApp(t, transport, &bytes.Buffer{}, &bytes.Buffer{})
			err = a.run([]string{"sync", "laptop", "--refresh-capabilities", "--json"})
			stored, loadErr := loadV2PeerDeliveryState(paths, state.RelationshipID)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if name == "revoked" || name == "halted" || name == "locked" {
				if err == nil {
					t.Fatal("sync accepted unavailable authorization")
				}
				expectedPaths := []string{"/v2/capabilities", "/v2/capabilities/reissue"}
				if name == "halted" || name == "locked" {
					expectedPaths = nil
				}
				if !slices.Equal(transport.paths, expectedPaths) || !reflect.DeepEqual(stored, state) {
					t.Fatalf("failed refresh changed state or attempted delivery: paths %v", transport.paths)
				}
				return
			}
			requireV2SyncRefreshResult(t, err, name == "refused after refresh")
			if !slices.Equal(transport.paths, []string{"/v2/capabilities", "/v2/capabilities/reissue", "/v2/inbox"}) {
				t.Fatalf("refresh request order = %v", transport.paths)
			}
			if stored.CapabilityReissues != 1 || transport.issuer.reissues != 1 || stored.CapabilitiesExpireAt <= state.CapabilitiesIssuedAt {
				t.Fatal("sync did not persist exactly one capability refresh")
			}
			if stored.InboundRelationshipSecret != state.InboundRelationshipSecret || stored.OutboundRelationshipSecret != state.OutboundRelationshipSecret || !reflect.DeepEqual(stored.Chains, state.Chains) {
				t.Fatal("capability refresh changed relationship keys or chains")
			}
		})
	}
}

func TestV2SyncParsesCapabilityRefresh(t *testing.T) {
	for _, args := range [][]string{
		{"laptop", "--refresh-capabilities", "--json", "--no-progress"},
		{"--refresh-capabilities", "--json", "--no-progress"},
	} {
		opts, err := parseV2SyncOptions(args)
		if err != nil || !opts.refreshCapabilities || !opts.json || !opts.progress.disabled {
			t.Fatalf("refresh options %v: %#v, %v", args, opts, err)
		}
	}
	if _, err := parseV2SyncOptions([]string{"laptop", "--refresh-capabilities", "--refresh-capabilities"}); err == nil {
		t.Fatal("sync accepted a repeated capability refresh option")
	}
}
