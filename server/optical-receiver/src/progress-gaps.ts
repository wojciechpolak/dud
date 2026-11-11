// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { FrameDisposition } from './pipeline.js';
import { STALL_THRESHOLD_MILLISECONDS } from './timing-metrics.js';
import type { DecodedImageObservation } from './worker-pool.js';

export const MAX_RECORDED_PROGRESS_GAPS = 32;

export interface GapActivity {
  cameraCallbacks: number;
  submittedImages: number;
  busyDrops: number;
  cadenceSkips: number;
  bitmapFailures: number;
  decodedImages: number;
  emptyImages: number;
  qrSymbols: number;
  useful: number;
  repeated: number;
  dependent: number;
  'completed-stripe': number;
  rejected: number;
  unsupported: number;
  'other-session': number;
  ignored: number;
  maximumBitmapMilliseconds: number;
  maximumWorkerRoundTripMilliseconds: number;
  maximumQRDecodeMilliseconds: number;
}

export interface ProgressGap {
  startOffsetMilliseconds: number;
  durationMilliseconds: number;
  activity: GapActivity;
}

export interface ProgressGapSnapshot {
  thresholdMilliseconds: number;
  recordLimit: number;
  usefulFrames: number;
  completedGapsOverThreshold: number;
  omittedGaps: number;
  totals: GapActivity;
  gaps: ProgressGap[];
  ongoingGap?: ProgressGap;
}

function activity(): GapActivity {
  return {
    cameraCallbacks: 0,
    submittedImages: 0,
    busyDrops: 0,
    cadenceSkips: 0,
    bitmapFailures: 0,
    decodedImages: 0,
    emptyImages: 0,
    qrSymbols: 0,
    useful: 0,
    repeated: 0,
    dependent: 0,
    'completed-stripe': 0,
    rejected: 0,
    unsupported: 0,
    'other-session': 0,
    ignored: 0,
    maximumBitmapMilliseconds: 0,
    maximumWorkerRoundTripMilliseconds: 0,
    maximumQRDecodeMilliseconds: 0,
  };
}

// Each interval ends at an independent-frame increase. Keep the longest gaps
// and scalar observations only, so neither capture length nor ciphertext size
// increases diagnostic storage.
export class ProgressGapMeter {
  private totals = activity();
  private interval = activity();
  private firstUsefulAt: number | undefined;
  private lastUsefulAt: number | undefined;
  private usefulFrames = 0;
  private completedGapsOverThreshold = 0;
  private gaps: ProgressGap[] = [];

  count(
    name:
      | 'cameraCallbacks'
      | 'submittedImages'
      | 'busyDrops'
      | 'cadenceSkips'
      | 'bitmapFailures'
      | FrameDisposition,
    amount = 1,
  ): void {
    this.totals[name] += amount;
    if (this.lastUsefulAt !== undefined) {
      this.interval[name] += amount;
    }
  }

  bitmap(durationMilliseconds: number): void {
    this.maximum('maximumBitmapMilliseconds', durationMilliseconds);
  }

  image(value: DecodedImageObservation): void {
    for (const target of this.targets()) {
      target.decodedImages++;
      target.emptyImages += Number(value.symbolCount === 0);
      target.qrSymbols += value.symbolCount;
    }
    this.maximum('maximumQRDecodeMilliseconds', value.decodeMilliseconds);
    this.maximum(
      'maximumWorkerRoundTripMilliseconds',
      value.roundTripMilliseconds,
    );
  }

  usefulProgress(atMilliseconds: number, usefulFrames: number): void {
    if (usefulFrames <= this.usefulFrames) {
      return;
    }
    if (this.lastUsefulAt !== undefined) {
      const gap = this.gap(atMilliseconds);
      if (gap.durationMilliseconds > STALL_THRESHOLD_MILLISECONDS) {
        this.completedGapsOverThreshold++;
        this.gaps.push(gap);
        this.gaps.sort(
          (left, right) =>
            right.durationMilliseconds - left.durationMilliseconds,
        );
        this.gaps.length = Math.min(
          this.gaps.length,
          MAX_RECORDED_PROGRESS_GAPS,
        );
      }
    }
    this.firstUsefulAt ??= atMilliseconds;
    this.lastUsefulAt = atMilliseconds;
    this.usefulFrames = usefulFrames;
    this.interval = activity();
  }

  finish(): void {
    this.lastUsefulAt = undefined;
  }

  snapshot(atMilliseconds: number): ProgressGapSnapshot {
    return {
      thresholdMilliseconds: STALL_THRESHOLD_MILLISECONDS,
      recordLimit: MAX_RECORDED_PROGRESS_GAPS,
      usefulFrames: this.usefulFrames,
      completedGapsOverThreshold: this.completedGapsOverThreshold,
      omittedGaps: this.completedGapsOverThreshold - this.gaps.length,
      totals: { ...this.totals },
      gaps: this.gaps
        .map((gap) => ({ ...gap, activity: { ...gap.activity } }))
        .sort(
          (left, right) =>
            left.startOffsetMilliseconds - right.startOffsetMilliseconds,
        ),
      ...(this.lastUsefulAt === undefined
        ? {}
        : { ongoingGap: this.gap(atMilliseconds) }),
    };
  }

  reset(): void {
    this.totals = activity();
    this.interval = activity();
    this.firstUsefulAt = undefined;
    this.lastUsefulAt = undefined;
    this.usefulFrames = 0;
    this.completedGapsOverThreshold = 0;
    this.gaps = [];
  }

  private gap(atMilliseconds: number): ProgressGap {
    return {
      startOffsetMilliseconds: this.lastUsefulAt! - this.firstUsefulAt!,
      durationMilliseconds: Math.max(0, atMilliseconds - this.lastUsefulAt!),
      activity: { ...this.interval },
    };
  }

  private targets(): GapActivity[] {
    return this.lastUsefulAt === undefined
      ? [this.totals]
      : [this.totals, this.interval];
  }

  private maximum(
    name:
      | 'maximumBitmapMilliseconds'
      | 'maximumWorkerRoundTripMilliseconds'
      | 'maximumQRDecodeMilliseconds',
    value: number,
  ): void {
    for (const target of this.targets()) {
      target[name] = Math.max(target[name], value);
    }
  }
}

export function formatProgressGaps(snapshot: ProgressGapSnapshot): string {
  const candidates = [
    ...snapshot.gaps,
    ...(snapshot.ongoingGap ? [snapshot.ongoingGap] : []),
  ];
  const longest = candidates.reduce<ProgressGap | undefined>(
    (result, gap) =>
      !result || gap.durationMilliseconds > result.durationMilliseconds
        ? gap
        : result,
    undefined,
  );
  const current = snapshot.ongoingGap?.durationMilliseconds ?? 0;
  if (!longest) {
    return 'No progress gaps recorded.';
  }
  const value = longest.activity;
  return `Current gap ${(current / 1000).toFixed(1)} s. Longest observed gap ${(longest.durationMilliseconds / 1000).toFixed(1)} s: ${value.decodedImages} decoded images, ${value.emptyImages} empty images, ${value.qrSymbols} QR symbols, ${value.repeated} repeated frames, ${value.dependent} dependent equations, ${value['completed-stripe']} completed-stripe frames, ${value.rejected + value.unsupported + value['other-session']} rejected or other-stream frames. Maximum bitmap ${value.maximumBitmapMilliseconds.toFixed(0)} ms, worker round trip ${value.maximumWorkerRoundTripMilliseconds.toFixed(0)} ms, QR decode ${value.maximumQRDecodeMilliseconds.toFixed(0)} ms.`;
}
