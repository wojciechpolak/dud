# QR encoder oracle fixtures

These fixtures contain the binary payload and complete row-major module matrix
returned by `github.com/yeqown/go-qrcode/v2` v2.3.0 through its public
byte-mode, fixed-version, level-L API. The capture ran at repository revision
`4eb7eeb` with the sender settings stated here. No dependency source was read or
copied to write the encoder. The capture program and comparison executable live
outside the optical Go module; the module tests consume only these JSON files.

The `zero` and `cycle` payloads are all-zero bytes and repeated byte values 0
through 255. The `random` and `capacity` payloads use xorshift32 initialized
with `0x12345678`, applying unsigned 32-bit XOR shifts of left 13, right 17, and
left 5 for each byte, then retaining its low byte. Frame-sized inputs have 1,692
bytes for Version 30 and 2,952 bytes for Version 40. Capacity inputs have 1,732
and 2,953 bytes respectively.

Tests compare every module after selecting the oracle's mask. This checks data,
parity, interleaving, function patterns, format/version fields and remainder
bits without requiring the encoder to choose the oracle's mask. Separate tests
check minimum penalty and lowest-numbered ties, and the receiver's original
TypeScript decoder checks all eight masks plus automatic selection for every
fixture. The sender verification at `416fd43` also used ZBar through its public
API. The capture and verification records are available at their recorded Git
revisions. SHA-256 checks in the product fixture test pin all eight JSON files.

The implementation's algorithm references are ISO/IEC 18004:2015 clauses 6.3,
7.4.5, 7.4.9 through 7.10, Tables 1, 7, 9 through 12, and Annexes A, C, D and E.
The standard is identified on the
[ISO catalogue](https://www.iso.org/standard/62021.html). A reference copy was
read outside the repository from
[this PDF](https://gcore.jsdelivr.net/gh/tonycrane/tonycrane.github.io/p/409d352d/ISO_IEC18004-2015.pdf).
The repository contains original code and test data, not a copy of the standard.
