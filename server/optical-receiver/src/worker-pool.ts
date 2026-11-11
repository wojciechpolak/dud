// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { CaptureLifecycle } from './lifecycle.js';
import type { QRScanMode } from './capture-profile.js';
import { STALL_THRESHOLD_MILLISECONDS } from './timing-metrics.js';

interface WorkerSlot {
  worker: Worker;
  ready: boolean;
  busy: boolean;
  submittedAt?: number;
}

interface DecoderWorkerMessage {
  type: 'ready' | 'result' | 'error';
  frames?: ArrayBuffer[];
  message?: string;
  decodeMilliseconds?: number;
  scanDimension?: number;
  fullScans?: number;
  trackedScans?: number;
  trackedSymbols?: number;
  scanDiagnostics?: QRScanDiagnostics;
}

export interface QRScanDiagnostics {
  finderChecks: number;
  finderCandidates: number;
  alignmentChecks: number;
  matrixAttempts: number;
  exhaustedScans: number;
}

export interface WorkerPoolStats {
  submitted: number;
  dropped: number;
  decodedImages: number;
  decodedFrames: number;
  multiSymbolImages: number;
  maximumSymbolsPerImage: number;
  decodeMilliseconds: number;
  maximumDecodeMilliseconds: number;
  decodesOverThreshold: number;
  scanDimension: number;
  fullScans: number;
  trackedScans: number;
  trackedSymbols: number;
  scanDiagnostics?: QRScanDiagnostics;
}

export interface DecoderDiagnostics {
  fullScans: number;
  trackedScans: number;
  trackedSymbols: number;
  scanDiagnostics?: QRScanDiagnostics;
}

export function recordDecodedImage(
  stats: WorkerPoolStats,
  symbolCount: number,
  decodeMilliseconds: number,
  scanDimension: number,
  diagnostics: DecoderDiagnostics = {
    fullScans: 0,
    trackedScans: 0,
    trackedSymbols: 0,
  },
): WorkerPoolStats {
  if (!Number.isInteger(symbolCount) || symbolCount < 0) {
    throw new RangeError(
      'decoded QR symbol count must be a non-negative integer',
    );
  }
  if (!Number.isFinite(decodeMilliseconds) || decodeMilliseconds < 0) {
    throw new RangeError('QR decode time must be finite and nonnegative');
  }
  return {
    ...stats,
    decodedImages: stats.decodedImages + 1,
    decodedFrames: stats.decodedFrames + symbolCount,
    multiSymbolImages: stats.multiSymbolImages + (symbolCount > 1 ? 1 : 0),
    maximumSymbolsPerImage: Math.max(stats.maximumSymbolsPerImage, symbolCount),
    decodeMilliseconds: stats.decodeMilliseconds + decodeMilliseconds,
    maximumDecodeMilliseconds: Math.max(
      stats.maximumDecodeMilliseconds,
      decodeMilliseconds,
    ),
    decodesOverThreshold:
      stats.decodesOverThreshold +
      Number(decodeMilliseconds > STALL_THRESHOLD_MILLISECONDS),
    scanDimension,
    fullScans: stats.fullScans + diagnostics.fullScans,
    trackedScans: stats.trackedScans + diagnostics.trackedScans,
    trackedSymbols: stats.trackedSymbols + diagnostics.trackedSymbols,
    ...(diagnostics.scanDiagnostics
      ? {
          scanDiagnostics: {
            finderChecks:
              (stats.scanDiagnostics?.finderChecks ?? 0) +
              diagnostics.scanDiagnostics.finderChecks,
            finderCandidates:
              (stats.scanDiagnostics?.finderCandidates ?? 0) +
              diagnostics.scanDiagnostics.finderCandidates,
            alignmentChecks:
              (stats.scanDiagnostics?.alignmentChecks ?? 0) +
              diagnostics.scanDiagnostics.alignmentChecks,
            matrixAttempts:
              (stats.scanDiagnostics?.matrixAttempts ?? 0) +
              diagnostics.scanDiagnostics.matrixAttempts,
            exhaustedScans:
              (stats.scanDiagnostics?.exhaustedScans ?? 0) +
              diagnostics.scanDiagnostics.exhaustedScans,
          },
        }
      : {}),
  };
}

export interface WorkerPoolCallbacks {
  onImage?(image: DecodedImageObservation): void;
  onFrame(frame: Uint8Array): void;
  onStats(stats: WorkerPoolStats): void;
  onError(message: string): void;
}

export interface DecodedImageObservation {
  symbolCount: number;
  decodeMilliseconds: number;
  roundTripMilliseconds: number;
}

export function recommendedQRWorkerCount(hardwareConcurrency: number): number {
  if (!Number.isFinite(hardwareConcurrency) || hardwareConcurrency < 1) {
    return 2;
  }
  return Math.min(4, Math.max(2, Math.floor(hardwareConcurrency)));
}

export class QRWorkerPool {
  private readonly slots: WorkerSlot[];
  readonly ready: Promise<void>;
  private markReady: (() => void) | undefined;
  private stats: WorkerPoolStats = {
    submitted: 0,
    dropped: 0,
    decodedImages: 0,
    decodedFrames: 0,
    multiSymbolImages: 0,
    maximumSymbolsPerImage: 0,
    decodeMilliseconds: 0,
    maximumDecodeMilliseconds: 0,
    decodesOverThreshold: 0,
    scanDimension: 0,
    fullScans: 0,
    trackedScans: 0,
    trackedSymbols: 0,
  };

  constructor(
    size: number,
    lifecycle: CaptureLifecycle,
    private readonly callbacks: WorkerPoolCallbacks,
    private readonly scanMode: QRScanMode = 'full-frame',
    private readonly now: () => number = () => performance.now(),
  ) {
    if (!Number.isInteger(size) || size < 1 || size > 4) {
      throw new RangeError('QR worker count must be between 1 and 4');
    }
    this.ready = new Promise((resolve) => {
      this.markReady = resolve;
    });
    lifecycle.addCleanup(() => {
      this.markReady?.();
      this.markReady = undefined;
    });
    this.slots = Array.from({ length: size }, () => {
      const workerURL = new URL('./decoder-worker.js', import.meta.url);
      workerURL.search = new URL(import.meta.url).search;
      const worker = new Worker(workerURL, { type: 'module' });
      const slot: WorkerSlot = { worker, ready: false, busy: false };
      lifecycle.addWorker(worker);
      worker.addEventListener(
        'message',
        (event: MessageEvent<DecoderWorkerMessage>) => {
          this.receive(slot, event.data);
        },
      );
      worker.addEventListener('error', () => {
        slot.busy = false;
        this.markReady?.();
        this.markReady = undefined;
        this.callbacks.onError('QR decoder worker stopped');
      });
      worker.postMessage({ type: 'warmup' });
      return slot;
    });
  }

  get canAccept(): boolean {
    return this.slots.some((slot) => slot.ready && !slot.busy);
  }

  drop(): void {
    this.stats.dropped++;
    this.emitStats();
  }

  submit(bitmap: ImageBitmap): boolean {
    const slot = this.slots.find(
      (candidate) => candidate.ready && !candidate.busy,
    );
    if (!slot) {
      bitmap.close();
      this.drop();
      return false;
    }
    slot.busy = true;
    slot.submittedAt = this.now();
    this.stats.submitted++;
    slot.worker.postMessage(
      { type: 'decode', bitmap, scanMode: this.scanMode },
      [bitmap],
    );
    this.emitStats();
    return true;
  }

  private receive(slot: WorkerSlot, message: DecoderWorkerMessage): void {
    if (message.type === 'ready') {
      slot.ready = true;
      this.markReady?.();
      this.markReady = undefined;
      return;
    }
    slot.busy = false;
    if (message.type === 'error') {
      this.markReady?.();
      this.markReady = undefined;
      this.callbacks.onError(message.message ?? 'QR decoder failed');
      return;
    }
    this.callbacks.onImage?.({
      symbolCount: message.frames?.length ?? 0,
      decodeMilliseconds: message.decodeMilliseconds ?? 0,
      roundTripMilliseconds: Math.max(
        0,
        this.now() - (slot.submittedAt ?? this.now()),
      ),
    });
    slot.submittedAt = undefined;
    this.stats = recordDecodedImage(
      this.stats,
      message.frames?.length ?? 0,
      message.decodeMilliseconds ?? 0,
      message.scanDimension ?? this.stats.scanDimension,
      {
        fullScans: message.fullScans ?? 0,
        trackedScans: message.trackedScans ?? 0,
        trackedSymbols: message.trackedSymbols ?? 0,
        scanDiagnostics: message.scanDiagnostics,
      },
    );
    this.emitStats();
    for (const frame of message.frames ?? []) {
      this.callbacks.onFrame(new Uint8Array(frame));
    }
  }

  private emitStats(): void {
    this.callbacks.onStats({ ...this.stats });
  }
}
