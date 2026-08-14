// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
package main

import "testing"

func FuzzV2InvitationDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, value []byte) {
		_, _ = decodeV2Invitation(value)
	})
}

func FuzzV2SignedEnvelopeValidator(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, value []byte) {
		_, _ = validateSignedV2Envelope(value, v2DescriptorExpectation{})
	})
}

func FuzzV2CollectionArchiveInspector(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not a compressed tar archive"))
	f.Fuzz(func(t *testing.T, value []byte) {
		_, _ = inspectV2CollectionArchive(value, uint64(len(value)))
	})
}

func FuzzV2GitMetadataDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, value []byte) {
		var decoded any
		if err := v2DecMode.Unmarshal(value, &decoded); err == nil {
			_, _ = decodeV2GitMetadata(decoded)
		}
	})
}
