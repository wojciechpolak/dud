// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package optical

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

type qrOracle struct {
	Version int      `json:"version"`
	Payload string   `json:"payload"`
	Rows    []string `json:"rows"`
}

func readQROracles(t *testing.T) []qrOracle {
	t.Helper()
	files, err := filepath.Glob("testdata/qr/oracle-*.json")
	if err != nil || len(files) != 8 {
		t.Fatalf("oracle fixtures: %v, count=%d", err, len(files))
	}
	vectors := make([]qrOracle, len(files))
	for i, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &vectors[i]); err != nil {
			t.Fatal(err)
		}
	}
	return vectors
}

// The level-L format codewords are the BCH results in ISO/IEC 18004:2015
// Annex C, after XOR with 0x5412, in mask order.
var qrLowFormats = [8]int{0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976}

func matrixMask(t *testing.T, m qrMatrix) int {
	t.Helper()
	bits := 0
	for i := range 8 {
		if m.dark[8*m.size+m.size-1-i] {
			bits |= 1 << i
		}
	}
	for i := 8; i < 15; i++ {
		if m.dark[(m.size-15+i)*m.size+8] {
			bits |= 1 << i
		}
	}
	for mask, format := range qrLowFormats {
		if bits == format {
			return mask
		}
	}
	t.Fatalf("invalid format %04x", bits)
	return -1
}

func TestQRMatrixMatchesIndependentEncoderAtItsMask(t *testing.T) {
	for i, vector := range readQROracles(t) {
		t.Run(fmt.Sprintf("v%d-vector%d", vector.Version, i), func(t *testing.T) {
			payload, err := base64.StdEncoding.DecodeString(vector.Payload)
			if err != nil {
				t.Fatal(err)
			}
			m, err := encodeQRMatrix(payload, vector.Version)
			if err != nil {
				t.Fatal(err)
			}
			oracle := qrMatrix{size: len(vector.Rows), dark: make([]bool, m.size*m.size)}
			for y, row := range vector.Rows {
				if len(row) != m.size {
					t.Fatal("oracle row length")
				}
				for x, value := range row {
					oracle.dark[y*m.size+x] = value == '1'
				}
			}
			m.applyMask(matrixMask(t, m))
			mask := matrixMask(t, oracle)
			m.applyMask(mask)
			m.format(mask)
			for i, dark := range m.dark {
				if dark != oracle.dark[i] {
					t.Fatalf("module (%d,%d) differs at oracle mask %d", i%m.size, i/m.size, mask)
				}
			}
		})
	}
}

func TestQRByteSegmentCapacityAndPadding(t *testing.T) {
	for _, version := range []int{30, 40} {
		p, _ := profileQR(version)
		for _, length := range []int{0, 1, p.dataWords - 4, p.dataWords - 3} {
			payload := bytes.Repeat([]byte{0xa5}, length)
			words, err := qrDataWords(payload, p)
			if err != nil {
				t.Fatal(err)
			}
			if len(words) != p.dataWords || words[0] != 0x40|byte(length>>12) || words[1] != byte(length>>4) || words[2]>>4 != byte(length&15) {
				t.Fatalf("invalid byte header: %x", words[:3])
			}
			for i := range payload {
				if words[i+2]<<4|words[i+3]>>4 != 0xa5 {
					t.Fatalf("payload byte %d", i)
				}
			}
			if words[length+2]&15 != 0 {
				t.Fatal("nonzero terminator")
			}
			for i := length + 3; i < len(words); i++ {
				want := byte(0xec)
				if (i-length-3)%2 == 1 {
					want = 0x11
				}
				if words[i] != want {
					t.Fatal("invalid pad word")
				}
			}
		}
		if _, err := qrDataWords(make([]byte, p.dataWords-2), p); err == nil {
			t.Fatal("over-capacity data accepted")
		}
	}
}

func TestQRReedSolomonPolynomialAndSyndromes(t *testing.T) {
	// Annex A lists the generator coefficients as powers of alpha=2.
	exponents := []int{41, 173, 145, 152, 216, 31, 179, 182, 50, 48, 110, 86, 239, 96, 222, 125, 42, 173, 226, 193, 224, 130, 156, 37, 251, 216, 238, 40, 192, 180}
	generator := qrGenerator()
	for i, exponent := range exponents {
		value := byte(1)
		for range exponent {
			value = qrMultiply(value, 2)
		}
		if generator[i+1] != value {
			t.Fatalf("generator coefficient %d", i)
		}
	}
	for _, length := range []int{115, 116, 118, 119} {
		data := make([]byte, length)
		for i := range data {
			data[i] = byte(i*71 + 19)
		}
		parity := qrParity(data, generator)
		block := append(data, parity[:]...)
		root := byte(1)
		for i := range 30 {
			value := byte(0)
			for _, coefficient := range block {
				value = qrMultiply(value, root) ^ coefficient
			}
			if value != 0 {
				t.Fatalf("syndrome %d for length %d", i, length)
			}
			root = qrMultiply(root, 2)
		}
	}
}

func TestQRFunctionPatternsAndRemainder(t *testing.T) {
	for _, version := range []int{30, 40} {
		p, _ := profileQR(version)
		m := newQRMatrix(p)
		available := 0
		for _, function := range m.function {
			if !function {
				available++
			}
		}
		want := (p.dataWords+(p.shortBlocks+p.longBlocks)*30)*8 + p.remainder
		if available != want {
			t.Fatalf("v%d data modules %d want %d", version, available, want)
		}
		for _, c := range [][2]int{{3, 3}, {m.size - 4, 3}, {3, m.size - 4}} {
			for dy := -3; dy <= 3; dy++ {
				for dx := -3; dx <= 3; dx++ {
					want := max(absQR(dx), absQR(dy)) != 2
					if m.dark[(c[1]+dy)*m.size+c[0]+dx] != want {
						t.Fatal("finder pattern")
					}
				}
			}
		}
		for mask, format := range qrLowFormats {
			if qrBCH(8|mask, 10, 0x537)^0x5412 != format {
				t.Fatalf("format mask %d", mask)
			}
			m.format(mask)
			if matrixMask(t, m) != mask {
				t.Fatal("format placement")
			}
			if !m.dark[(m.size-8)*m.size+8] {
				t.Fatal("fixed dark module")
			}
		}
		wantVersion := 0x1ed75
		if version == 40 {
			wantVersion = 0x28c69
		}
		if qrBCH(version, 12, 0x1f25) != wantVersion {
			t.Fatal("version BCH")
		}
		for i := range 18 {
			x, y := m.size-11+i%3, i/3
			want := wantVersion&(1<<i) != 0
			if m.dark[y*m.size+x] != want || m.dark[x*m.size+y] != want {
				t.Fatal("version placement")
			}
		}
	}
}

func TestQRMaskPredicatesAndFunctionExclusion(t *testing.T) {
	// Every predicate repeats within a 6x6 tile.
	predicates := [8]string{
		"101010010101101010010101101010010101",
		"111111000000111111000000111111000000",
		"100100100100100100100100100100100100",
		"100100001001010010100100001001010010",
		"111000111000000111000111111000111000",
		"111111100000100100101010100100100000",
		"111111111000110110101010101101100011",
		"101010000111100011010101111000011100",
	}
	for mask, predicate := range predicates {
		for y := range 6 {
			for x := range 6 {
				if qrMask(mask, x, y) != (predicate[y*6+x] == '1') {
					t.Fatalf("mask%d at %d,%d", mask, x, y)
				}
			}
		}
		p, _ := profileQR(30)
		m := newQRMatrix(p)
		before := append([]bool(nil), m.dark...)
		m.applyMask(mask)
		for i, function := range m.function {
			if function && m.dark[i] != before[i] {
				t.Fatal("masked function module")
			}
		}
		m.applyMask(mask)
		for i := range before {
			if m.dark[i] != before[i] {
				t.Fatal("mask not self-inverse")
			}
		}
	}
}

func TestQRLinePenaltyRules(t *testing.T) {
	for _, test := range []struct {
		line string
		want int
	}{
		{"11111", 3}, {"0000000", 5}, {"1111100000", 6},
		{"00001011101", 40}, {"10111010000", 40}, {"000010111010000", 40},
		{"1011101", 0}, {"10000101110100001", 40},
	} {
		line := make([]bool, len(test.line))
		for i, v := range test.line {
			line[i] = v == '1'
		}
		if got := qrLinePenalty(line); got != test.want {
			t.Fatalf("%s score=%d want=%d", test.line, got, test.want)
		}
	}
}

// referenceQRPenalty scores direct module windows independently of the encoder.
func referenceQRPenalty(m qrMatrix) int {
	score, dark := 0, 0
	at := func(x, y int) bool { return m.dark[y*m.size+x] }
	for y := range m.size {
		for x := range m.size {
			if at(x, y) {
				dark++
			}
			if x+1 < m.size && y+1 < m.size && at(x, y) == at(x+1, y) && at(x, y) == at(x, y+1) && at(x, y) == at(x+1, y+1) {
				score += 3
			}
		}
	}
	for _, vertical := range []bool{false, true} {
		for row := range m.size {
			line := func(i int) bool {
				if vertical {
					return at(row, i)
				}
				return at(i, row)
			}
			for i := 0; i < m.size; {
				end := i + 1
				for end < m.size && line(end) == line(i) {
					end++
				}
				if end-i >= 5 {
					score += end - i - 2
				}
				i = end
			}
			for i := 0; i+7 <= m.size; i++ {
				pattern := ""
				for j := range 7 {
					if line(i + j) {
						pattern += "1"
					} else {
						pattern += "0"
					}
				}
				if pattern != "1011101" {
					continue
				}
				light := false
				for _, start := range []int{i - 4, i + 7} {
					if start < 0 || start+4 > m.size {
						continue
					}
					white := true
					for j := range 4 {
						if line(start + j) {
							white = false
						}
					}
					light = light || white
				}
				if light {
					score += 40
				}
			}
		}
	}
	deviation := float64(dark)*100/float64(m.size*m.size) - 50
	if deviation < 0 {
		deviation = -deviation
	}
	return score + int(deviation/5)*10
}

func TestQRSelectsLowestPenaltyWithStableTies(t *testing.T) {
	for _, vector := range readQROracles(t) {
		payload, _ := base64.StdEncoding.DecodeString(vector.Payload)
		m, err := encodeQRMatrix(payload, vector.Version)
		if err != nil {
			t.Fatal(err)
		}
		selected := matrixMask(t, m)
		m.applyMask(selected)
		best, lowest := 0, int(^uint(0)>>1)
		for mask := range 8 {
			m.applyMask(mask)
			m.format(mask)
			score := referenceQRPenalty(m)
			if score != m.penalty() {
				t.Fatalf("v%d mask%d penalty mismatch", vector.Version, mask)
			}
			if score < lowest {
				best, lowest = mask, score
			}
			m.applyMask(mask)
		}
		if selected != best {
			t.Fatalf("selected%d want%d", selected, best)
		}
		again, _ := encodeQRMatrix(payload, vector.Version)
		if matrixMask(t, again) != selected {
			t.Fatal("nondeterministic mask")
		}
	}
}

// TestQRDecoderVectors exports raster fixtures only when the Node decoder test
// supplies a scratch directory. All forced masks and automatic selection carry
// the same exact binary payload through the independent decoder.
func TestQRDecoderVectors(t *testing.T) {
	directory := os.Getenv("DUD_QR_TEST_OUTPUT")
	if directory == "" {
		return
	}
	type entry struct {
		File    string `json:"file"`
		Payload string `json:"payload"`
		Version int    `json:"version"`
		Mask    int    `json:"mask"`
		Side    int    `json:"side"`
	}
	entries := []entry{}
	for index, vector := range readQROracles(t) {
		payload, _ := base64.StdEncoding.DecodeString(vector.Payload)
		m, err := encodeQRMatrix(payload, vector.Version)
		if err != nil {
			t.Fatal(err)
		}
		selected := matrixMask(t, m)
		m.applyMask(selected)
		for mask := -1; mask < 8; mask++ {
			chosen := mask
			if mask < 0 {
				chosen = selected
			}
			m.applyMask(chosen)
			m.format(chosen)
			raster := image.NewRGBA(image.Rect(0, 0, (m.size+8)*2, (m.size+8)*2))
			fillRect(raster, raster.Bounds(), color.RGBA{255, 255, 255, 255})
			for y := range m.size {
				for x := range m.size {
					if m.dark[y*m.size+x] {
						fillRect(raster, image.Rect((x+4)*2, (y+4)*2, (x+5)*2, (y+5)*2), color.RGBA{A: 255})
					}
				}
			}
			file := fmt.Sprintf("v%d-vector%d-mask%d.png", vector.Version, index, mask)
			var output bytes.Buffer
			if err := png.Encode(&output, raster); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, file), output.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, file+".rgba"), raster.Pix, 0600); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, entry{file, vector.Payload, vector.Version, chosen, raster.Bounds().Dx()})
			m.applyMask(chosen)
		}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "vectors.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestQREqualMinimumPenaltyChoosesSmallestMask(t *testing.T) {
	payload := make([]byte, FrameSize)
	state := uint32(32)
	for i := range payload {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		payload[i] = byte(state)
	}
	matrix, err := encodeQRMatrix(payload, 30)
	if err != nil {
		t.Fatal(err)
	}
	chosen := matrixMask(t, matrix)
	matrix.applyMask(chosen)
	scores := [8]int{}
	for mask := range 8 {
		matrix.applyMask(mask)
		matrix.format(mask)
		scores[mask] = referenceQRPenalty(matrix)
		matrix.applyMask(mask)
	}
	if scores[2] != scores[4] || chosen != 2 {
		t.Fatalf("scores=%v chosen=%d", scores, chosen)
	}
	for _, score := range scores {
		if score < scores[2] {
			t.Fatal("tie is not minimum")
		}
	}
}

func TestQRBlockAndBalancePenalties(t *testing.T) {
	for _, test := range []struct {
		size  int
		solid bool
		want  int
	}{
		{3, true, 112}, {5, true, 178}, {3, false, 10}, {10, false, 0},
	} {
		m := qrMatrix{size: test.size, dark: make([]bool, test.size*test.size)}
		for y := range m.size {
			for x := range m.size {
				m.dark[y*m.size+x] = test.solid || (x+y)%2 == 0
			}
		}
		if score := m.penalty(); score != test.want {
			t.Fatalf("size%d solid%v score%d want%d", test.size, test.solid, score, test.want)
		}
	}
}

func fillRect(target *image.RGBA, rectangle image.Rectangle, value color.RGBA) {
	for y := rectangle.Min.Y; y < rectangle.Max.Y; y++ {
		for x := rectangle.Min.X; x < rectangle.Max.X; x++ {
			target.SetRGBA(x, y, value)
		}
	}
}
