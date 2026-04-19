// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export function generateOpaqueId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  );
}
