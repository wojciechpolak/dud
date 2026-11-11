// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export const MAX_SCAN_DIMENSION = 960;

export interface ScanRegion {
  sourceX: number;
  sourceY: number;
  sourceSize: number;
  scanSize: number;
}

// The camera preview uses object-fit: cover inside a square guide. Scanning the
// matching center square avoids pixels the operator cannot see in that guide.
export function scanRegion(width: number, height: number): ScanRegion {
  if (
    !Number.isInteger(width) ||
    !Number.isInteger(height) ||
    width < 1 ||
    height < 1
  ) {
    throw new RangeError('camera dimensions must be positive integers');
  }
  const sourceSize = Math.min(width, height);
  return {
    sourceX: Math.floor((width - sourceSize) / 2),
    sourceY: Math.floor((height - sourceSize) / 2),
    sourceSize,
    scanSize: Math.min(sourceSize, MAX_SCAN_DIMENSION),
  };
}
