// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export type QRScanMode = 'full-frame' | 'tracked-four';

export interface CaptureProfile {
  id: string;
  framesPerSecond: number;
  scanMode: QRScanMode;
}

const CAPTURE_PROFILES: readonly CaptureProfile[] = [
  { id: 'tracked-60', framesPerSecond: 60, scanMode: 'tracked-four' },
  { id: 'balanced', framesPerSecond: 30, scanMode: 'full-frame' },
];

export const DEFAULT_CAPTURE_PROFILE = CAPTURE_PROFILES[0];

export function captureProfile(id: string): CaptureProfile {
  return (
    CAPTURE_PROFILES.find((candidate) => candidate.id === id) ??
    DEFAULT_CAPTURE_PROFILE
  );
}
