// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export const CAMERA_SCAN_FPS = 30;

const EARLY_TOLERANCE_MILLISECONDS = 1;

export class ScanCadence {
  private readonly intervalMilliseconds: number;
  private nextScanAt: number | undefined;

  constructor(framesPerSecond = CAMERA_SCAN_FPS) {
    if (!Number.isFinite(framesPerSecond) || framesPerSecond <= 0) {
      throw new RangeError('Scan frame rate must be positive');
    }
    this.intervalMilliseconds = 1000 / framesPerSecond;
  }

  shouldScan(timestampMilliseconds: number): boolean {
    if (!Number.isFinite(timestampMilliseconds) || timestampMilliseconds < 0) {
      throw new RangeError('Scan timestamp must be a non-negative number');
    }
    if (this.nextScanAt === undefined) {
      this.nextScanAt = timestampMilliseconds + this.intervalMilliseconds;
      return true;
    }
    if (
      timestampMilliseconds + EARLY_TOLERANCE_MILLISECONDS <
      this.nextScanAt
    ) {
      return false;
    }

    const intervalsBehind = Math.max(
      0,
      Math.floor(
        (timestampMilliseconds - this.nextScanAt) / this.intervalMilliseconds,
      ),
    );
    this.nextScanAt += (intervalsBehind + 1) * this.intervalMilliseconds;
    return true;
  }
}
