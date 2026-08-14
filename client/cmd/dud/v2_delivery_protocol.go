// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const (
	v2SlotEpochSeconds     = uint64(86400)
	v2AuthorizationSkew    = uint64(300)
	v2DeliveryRecoveryDays = uint64(30)
	v2SequenceAheadLimit   = uint64(1000)
	v2ControlDrainTimeout  = 10 * time.Second
)

func v2DirectionName(value uint64) string {
	if value == 0 {
		return "inviter->invitee"
	}
	return "invitee->inviter"
}

func v2OutboundDirection(role uint64) uint64 {
	return role
}

func v2InboundDirection(role uint64) uint64 {
	return 1 - role
}

func v2SlotEpoch(now time.Time) uint64 {
	return uint64(now.Unix()) / v2SlotEpochSeconds
}

func deriveV2Slot(secret []byte, chain string, epoch uint64) ([]byte, error) {
	if len(secret) != 32 || (chain != "data" && chain != "control") {
		return nil, errors.New("slot derivation input is invalid")
	}
	return hkdf.Key(
		sha256.New,
		secret,
		nil,
		fmt.Sprintf("dud/v2/slot|%s|%d", chain, epoch),
		16,
	)
}

func v2CapabilitySecret(state *v2PeerDeliveryState, direction uint64, scope string) ([]byte, error) {
	key := v2DirectionName(direction) + "|" + scope
	value, exists := state.Capabilities[key]
	if !exists {
		return nil, fmt.Errorf("peer state does not contain %s capability", key)
	}
	return decodeV2Base64URL(value, 32)
}
