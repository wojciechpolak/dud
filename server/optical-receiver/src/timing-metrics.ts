// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export const STALL_THRESHOLD_MILLISECONDS = 250;

export interface ReceiverTimingSnapshot {
  cameraCallbacks: number;
  cameraGapsOverThreshold: number;
  maximumCameraGapMilliseconds: number;
  usefulGapsOverThreshold: number;
  maximumUsefulGapMilliseconds: number;
  frameHandlersOverThreshold: number;
  maximumFrameHandlerMilliseconds: number;
}

// These counters separate gaps in camera callbacks and useful progress from
// synchronous frame handling. They carry no frame bytes or persistent state.
export class ReceiverTimingMeter {
  private lastCameraCallbackAt: number | undefined;
  private lastUsefulFrameAt: number | undefined;
  private usefulFrames = 0;
  private counters: ReceiverTimingSnapshot = {
    cameraCallbacks: 0,
    cameraGapsOverThreshold: 0,
    maximumCameraGapMilliseconds: 0,
    usefulGapsOverThreshold: 0,
    maximumUsefulGapMilliseconds: 0,
    frameHandlersOverThreshold: 0,
    maximumFrameHandlerMilliseconds: 0,
  };

  cameraCallback(atMilliseconds: number): void {
    if (!Number.isFinite(atMilliseconds) || atMilliseconds < 0) {
      throw new RangeError(
        'camera callback time must be finite and nonnegative',
      );
    }
    if (this.lastCameraCallbackAt !== undefined) {
      const gap = atMilliseconds - this.lastCameraCallbackAt;
      if (gap >= 0) {
        this.counters.maximumCameraGapMilliseconds = Math.max(
          this.counters.maximumCameraGapMilliseconds,
          gap,
        );
        if (gap > STALL_THRESHOLD_MILLISECONDS) {
          this.counters.cameraGapsOverThreshold++;
        }
      }
    }
    this.lastCameraCallbackAt = atMilliseconds;
    this.counters.cameraCallbacks++;
  }

  usefulProgress(atMilliseconds: number, usefulFrames: number): void {
    if (
      !Number.isFinite(atMilliseconds) ||
      atMilliseconds < 0 ||
      !Number.isInteger(usefulFrames) ||
      usefulFrames < 0
    ) {
      throw new RangeError('useful progress requires a valid time and count');
    }
    if (usefulFrames <= this.usefulFrames) {
      return;
    }
    if (this.lastUsefulFrameAt !== undefined) {
      const gap = atMilliseconds - this.lastUsefulFrameAt;
      if (gap >= 0) {
        this.counters.maximumUsefulGapMilliseconds = Math.max(
          this.counters.maximumUsefulGapMilliseconds,
          gap,
        );
        if (gap > STALL_THRESHOLD_MILLISECONDS) {
          this.counters.usefulGapsOverThreshold++;
        }
      }
    }
    this.lastUsefulFrameAt = atMilliseconds;
    this.usefulFrames = usefulFrames;
  }

  frameHandler(durationMilliseconds: number): void {
    if (!Number.isFinite(durationMilliseconds) || durationMilliseconds < 0) {
      throw new RangeError('frame handler time must be finite and nonnegative');
    }
    this.counters.maximumFrameHandlerMilliseconds = Math.max(
      this.counters.maximumFrameHandlerMilliseconds,
      durationMilliseconds,
    );
    if (durationMilliseconds > STALL_THRESHOLD_MILLISECONDS) {
      this.counters.frameHandlersOverThreshold++;
    }
  }

  snapshot(): ReceiverTimingSnapshot {
    return { ...this.counters };
  }

  // A deliberate camera pause separates observation intervals without erasing counts.
  breakInterval(): void {
    this.lastCameraCallbackAt = undefined;
    this.lastUsefulFrameAt = undefined;
  }

  reset(): void {
    this.lastCameraCallbackAt = undefined;
    this.lastUsefulFrameAt = undefined;
    this.usefulFrames = 0;
    this.counters = {
      cameraCallbacks: 0,
      cameraGapsOverThreshold: 0,
      maximumCameraGapMilliseconds: 0,
      usefulGapsOverThreshold: 0,
      maximumUsefulGapMilliseconds: 0,
      frameHandlersOverThreshold: 0,
      maximumFrameHandlerMilliseconds: 0,
    };
  }
}
