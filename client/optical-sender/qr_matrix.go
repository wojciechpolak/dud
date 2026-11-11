// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package optical

// ISO/IEC 18004:2015, Tables 1, 7, 9 and Annex E define these Model 2
// byte-mode, level-L profiles. Each block has 30 error-correction codewords.
type qrProfile struct {
	version, size, dataWords, shortBlocks, longBlocks, shortData, remainder int
	alignment                                                               []int
}

func profileQR(version int) (qrProfile, error) {
	switch version {
	case 30:
		return qrProfile{30, 137, 1735, 5, 10, 115, 3, []int{6, 26, 52, 78, 104, 130}}, nil
	case 40:
		return qrProfile{40, 177, 2956, 19, 6, 118, 0, []int{6, 30, 58, 86, 114, 142, 170}}, nil
	default:
		return qrProfile{}, reject("qr-version", "QR version %d is unsupported; choose 30 or 40", version)
	}
}

// qrDataWords uses a single byte segment with a 16-bit count and no ECI.
// The optical carrier preserves bytes independently of text encodings.
func qrDataWords(payload []byte, profile qrProfile) ([]byte, error) {
	if len(payload) > profile.dataWords-3 {
		return nil, reject("qr-capacity", "binary payload of %d bytes exceeds QR version %d L capacity", len(payload), profile.version)
	}
	words := make([]byte, profile.dataWords)
	bit := 0
	put := func(value, count int) {
		for i := count - 1; i >= 0; i-- {
			words[bit/8] |= byte((value>>i)&1) << (7 - bit%8)
			bit++
		}
	}
	put(4, 4)
	put(len(payload), 16)
	for _, value := range payload {
		put(int(value), 8)
	}
	// The four-bit terminator also completes the final byte for these profiles.
	put(0, 4)
	for i := bit / 8; i < len(words); i++ {
		words[i] = 0xec
		if (i-bit/8)%2 == 1 {
			words[i] = 0x11
		}
	}
	return words, nil
}

// qrMultiply operates in GF(256) modulo x^8+x^4+x^3+x^2+1.
func qrMultiply(a, b byte) byte {
	product := byte(0)
	for b != 0 {
		if b&1 != 0 {
			product ^= a
		}
		high := a&0x80 != 0
		a <<= 1
		if high {
			a ^= 0x1d
		}
		b >>= 1
	}
	return product
}

// qrGenerator constructs the monic product of (x + alpha^i), i=0..29,
// with alpha=2, as specified in ISO/IEC 18004:2015 Annex A.
func qrGenerator() [31]byte {
	var polynomial [31]byte
	polynomial[0] = 1
	root := byte(1)
	for degree := 0; degree < 30; degree++ {
		for i := degree + 1; i > 0; i-- {
			polynomial[i] ^= qrMultiply(polynomial[i-1], root)
		}
		root = qrMultiply(root, 2)
	}
	return polynomial
}

func qrParity(data []byte, generator [31]byte) [30]byte {
	var remainder [30]byte
	for _, value := range data {
		factor := value ^ remainder[0]
		copy(remainder[:], remainder[1:])
		remainder[29] = 0
		for i := range remainder {
			remainder[i] ^= qrMultiply(factor, generator[i+1])
		}
	}
	return remainder
}

func qrInterleave(data []byte, profile qrProfile) []byte {
	count := profile.shortBlocks + profile.longBlocks
	blocks := make([][]byte, count)
	parity := make([][30]byte, count)
	generator := qrGenerator()
	offset := 0
	for i := range blocks {
		length := profile.shortData
		if i >= profile.shortBlocks {
			length++
		}
		blocks[i] = data[offset : offset+length]
		parity[i] = qrParity(blocks[i], generator)
		offset += length
	}
	words := make([]byte, 0, len(data)+30*count)
	for column := 0; column <= profile.shortData; column++ {
		for _, block := range blocks {
			if column < len(block) {
				words = append(words, block[column])
			}
		}
	}
	for column := range 30 {
		for _, block := range parity {
			words = append(words, block[column])
		}
	}
	return words
}

type qrMatrix struct {
	size           int
	dark, function []bool
}

func newQRMatrix(profile qrProfile) qrMatrix {
	m := qrMatrix{size: profile.size, dark: make([]bool, profile.size*profile.size), function: make([]bool, profile.size*profile.size)}
	// Timing modules are overwritten where finder and alignment patterns intersect.
	for i := range m.size {
		m.setFunction(6, i, i%2 == 0)
		m.setFunction(i, 6, i%2 == 0)
	}
	for _, center := range [][2]int{{3, 3}, {m.size - 4, 3}, {3, m.size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				distance := max(absQR(dx), absQR(dy))
				m.setFunction(center[0]+dx, center[1]+dy, distance != 2 && distance != 4)
			}
		}
	}
	last := len(profile.alignment) - 1
	for iy, y := range profile.alignment {
		for ix, x := range profile.alignment {
			if (ix == 0 && iy == 0) || (ix == last && iy == 0) || (ix == 0 && iy == last) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					m.setFunction(x+dx, y+dy, max(absQR(dx), absQR(dy)) != 1)
				}
			}
		}
	}
	m.format(0)
	version := qrBCH(profile.version, 12, 0x1f25)
	for i := range 18 {
		x, y := m.size-11+i%3, i/3
		m.setFunction(x, y, version&(1<<i) != 0)
		m.setFunction(y, x, version&(1<<i) != 0)
	}
	return m
}

func (m qrMatrix) setFunction(x, y int, dark bool) {
	if x >= 0 && y >= 0 && x < m.size && y < m.size {
		i := y*m.size + x
		m.dark[i], m.function[i] = dark, true
	}
}

func qrBCH(data, degree, generator int) int {
	value := data << degree
	for i := 17; i >= degree; i-- {
		if value&(1<<i) != 0 {
			value ^= generator << (i - degree)
		}
	}
	return data<<degree | value
}

func (m qrMatrix) format(mask int) {
	bits := qrBCH(8|mask, 10, 0x537) ^ 0x5412
	for i := range 15 {
		var x, y int
		switch {
		case i < 6:
			x, y = 8, i
		case i < 8:
			x, y = 8, i+1
		case i == 8:
			x, y = 7, 8
		default:
			x, y = 14-i, 8
		}
		m.setFunction(x, y, bits&(1<<i) != 0)
		if i < 8 {
			m.setFunction(m.size-1-i, 8, bits&(1<<i) != 0)
		} else {
			m.setFunction(8, m.size-15+i, bits&(1<<i) != 0)
		}
	}
	m.setFunction(8, m.size-8, true)
}

func (m qrMatrix) place(words []byte) {
	bit := 0
	upward := true
	for right := m.size - 1; right > 0; right -= 2 {
		if right == 6 {
			right--
		}
		for row := range m.size {
			y := row
			if upward {
				y = m.size - 1 - row
			}
			for x := right; x >= right-1; x-- {
				i := y*m.size + x
				if m.function[i] {
					continue
				}
				if bit < len(words)*8 {
					m.dark[i] = words[bit/8]&(1<<(7-bit%8)) != 0
				}
				bit++
			}
		}
		upward = !upward
	}
}

func qrMask(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	case 7:
		return ((x+y)%2+x*y%3)%2 == 0
	default:
		panic("invalid internal QR mask")
	}
}

func (m qrMatrix) applyMask(mask int) {
	for y := range m.size {
		for x := range m.size {
			i := y*m.size + x
			if !m.function[i] && qrMask(mask, x, y) {
				m.dark[i] = !m.dark[i]
			}
		}
	}
}

func qrLinePenalty(line []bool) int {
	score, run := 0, 1
	for i := 1; i < len(line); i++ {
		if line[i] == line[i-1] {
			run++
		} else {
			if run >= 5 {
				score += run - 2
			}
			run = 1
		}
	}
	if run >= 5 {
		score += run - 2
	}
	for i := 0; i+7 <= len(line); i++ {
		if !line[i] || line[i+1] || !line[i+2] || !line[i+3] || !line[i+4] || line[i+5] || !line[i+6] {
			continue
		}
		before, after := i >= 4, i+11 <= len(line)
		if before {
			for _, dark := range line[i-4 : i] {
				before = before && !dark
			}
		}
		if after {
			for _, dark := range line[i+7 : i+11] {
				after = after && !dark
			}
		}
		if before || after {
			score += 40
		}
	}
	return score
}

func (m qrMatrix) penalty() int {
	score, dark := 0, 0
	column := make([]bool, m.size)
	for y := range m.size {
		score += qrLinePenalty(m.dark[y*m.size : (y+1)*m.size])
		for x := range m.size {
			i := y*m.size + x
			if m.dark[i] {
				dark++
			}
			if x > 0 && y > 0 && m.dark[i] == m.dark[i-1] && m.dark[i] == m.dark[i-m.size] && m.dark[i] == m.dark[i-m.size-1] {
				score += 3
			}
			column[x] = m.dark[x*m.size+y]
		}
		score += qrLinePenalty(column)
	}
	return score + absQR(20*dark-10*m.size*m.size)/(m.size*m.size)*10
}

func encodeQRMatrix(payload []byte, version int) (qrMatrix, error) {
	profile, err := profileQR(version)
	if err != nil {
		return qrMatrix{}, err
	}
	data, err := qrDataWords(payload, profile)
	if err != nil {
		return qrMatrix{}, err
	}
	m := newQRMatrix(profile)
	m.place(qrInterleave(data, profile))
	best, lowest := 0, int(^uint(0)>>1)
	for mask := range 8 {
		m.applyMask(mask)
		m.format(mask)
		score := m.penalty()
		if score < lowest {
			best, lowest = mask, score
		}
		m.applyMask(mask)
	}
	m.applyMask(best)
	m.format(best)
	return m, nil
}

func absQR(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

// QRMatrix contains one caller-owned Model 2 module grid in row-major order.
type QRMatrix struct {
	Size int
	Dark []bool
}

// EncodeQRMatrix encodes a binary byte segment using bounded level-L profiles.
func EncodeQRMatrix(payload []byte, version int) (QRMatrix, error) {
	matrix, err := encodeQRMatrix(payload, version)
	if err != nil {
		return QRMatrix{}, err
	}
	return QRMatrix{Size: matrix.size, Dark: matrix.dark}, nil
}
