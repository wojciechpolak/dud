// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// QR's alpha=2 enumerates every nonzero field element modulo polynomial 0x11d.
// Frozen tables are shared by calls; zero has no logarithm and is handled first.
const FIELD = (() => {
  const logarithms = new Array<number>(256).fill(0);
  const powers = new Array<number>(510);
  let value = 1;
  for (let exponent = 0; exponent < 255; exponent++) {
    powers[exponent] = value;
    logarithms[value] = exponent;
    value <<= 1;
    if (value & 256) {
      value ^= 0x11d;
    }
  }
  for (let exponent = 255; exponent < powers.length; exponent++) {
    powers[exponent] = powers[exponent - 255];
  }
  return Object.freeze({
    logarithms: Object.freeze(logarithms),
    powers: Object.freeze(powers),
  });
})();

/** Multiply two QR field elements in the byte range. */
export function multiplyQRField(a: number, b: number): number {
  return a === 0 || b === 0
    ? 0
    : FIELD.powers[FIELD.logarithms[a] + FIELD.logarithms[b]];
}
