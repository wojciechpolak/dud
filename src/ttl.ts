// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

const TTL_RE = /^(\d+)\s*(s|m|h|d|w)$/i;

const UNIT_TO_MS: Record<string, number> = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

export function parseTtl(
  input: string | null,
  defaultTtlMs: number,
  maxTtlMs: number,
): number {
  if (!input) {
    return defaultTtlMs;
  }

  const trimmed = input.trim();
  const match = TTL_RE.exec(trimmed);

  if (!match) {
    throw new Error('TTL must look like 15m, 24h, or 7d.');
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  const ttlMs = value * UNIT_TO_MS[unit];

  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error('TTL must be a positive duration.');
  }

  if (ttlMs > maxTtlMs) {
    throw new Error('TTL exceeds the maximum allowed duration.');
  }

  return ttlMs;
}
