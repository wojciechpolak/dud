// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package optical

import "testing"

func FuzzQRMatrixBounds(f *testing.F) {
	f.Add([]byte{}, 30)
	f.Add([]byte{0, 255, 128, 1}, 40)
	f.Add(make([]byte, 1732), 30)
	f.Add(make([]byte, 2953), 40)
	f.Add(make([]byte, 2954), 40)
	f.Add([]byte{1}, 31)
	f.Fuzz(func(t *testing.T, payload []byte, version int) {
		matrix, err := encodeQRMatrix(payload, version)
		profile, profileErr := profileQR(version)
		valid := profileErr == nil && len(payload) <= profile.dataWords-3
		if valid != (err == nil) {
			t.Fatalf("version=%d length=%d error=%v", version, len(payload), err)
		}
		if !valid {
			return
		}
		if matrix.size != profile.size || len(matrix.dark) != profile.size*profile.size || len(matrix.function) != len(matrix.dark) {
			t.Fatal("matrix bounds")
		}
		matrixMask(t, matrix)
	})
}
