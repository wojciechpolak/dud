// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export function generateOpaqueId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}

export function normalizeOpaqueId(id: string): string {
  return id.replaceAll('-', '');
}

export function isOpaqueId(id: string): boolean {
  return /^[0-9a-f]{32}$/.test(id);
}

export function parseOpaqueId(id: string): string | null {
  const normalized = normalizeOpaqueId(id);
  return isOpaqueId(normalized) ? normalized : null;
}

export function formatOpaqueId(id: string): string {
  if (!isOpaqueId(id)) {
    return id;
  }

  return id.match(/.{1,4}/g)?.join('-') ?? id;
}
