// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { OpticalCodecError, OpticalDecoder } from './codec.js';

export interface PipelineProgress {
  percent: number;
  stripeIndex: number;
  stripeCount: number;
  independentRows: number;
  sourceCount: number;
  usefulFrames: number;
  requiredFrames: number;
  rejectedFrames: number;
}

export interface PipelineCompletion {
  capsule: Uint8Array;
  byteLength: number;
  usefulFrames: number;
  rejectedFrames: number;
  elapsedMilliseconds: number;
}

export interface PipelineCallbacks {
  onFrameDisposition?(disposition: FrameDisposition): void;
  onProgress(progress: PipelineProgress): void;
  onComplete(completion: PipelineCompletion): void;
  onSessionChange(): void;
  onUnsupported(message: string): void;
  onRejected(code: string): void;
  onFatal(message: string): void;
}

export type FrameDisposition =
  | 'useful'
  | 'repeated'
  | 'dependent'
  | 'completed-stripe'
  | 'rejected'
  | 'unsupported'
  | 'other-session'
  | 'ignored';

const UNSUPPORTED_CODES = new Set(['magic', 'version', 'features']);
const FATAL_CODES = new Set([
  'active-stripes',
  'contradiction',
  'decoder-work',
  'digest',
  'distinct-frames',
  'retained-equations',
]);

export const MAX_PIPELINE_FRAMES = 216_000;
export const MAX_TRANSFER_MILLISECONDS = 15 * 60 * 1000;

export interface PipelineLimits {
  maxFrames: number;
  maxTransferMilliseconds: number;
}

const DEFAULT_PIPELINE_LIMITS: Readonly<PipelineLimits> = {
  maxFrames: MAX_PIPELINE_FRAMES,
  maxTransferMilliseconds: MAX_TRANSFER_MILLISECONDS,
};

// OpticalFramePipeline is the single frame-to-capsule path used by camera and
// synthetic-video input. Its completion callback takes ownership of verified
// ciphertext so the receiver can save it without parsing it.
export class OpticalFramePipeline {
  private decoder = new OpticalDecoder();
  private finishing = false;
  private usefulFrames = 0;
  private rejectedFrames = 0;
  private independentFrameCount = 0;
  private distinctFrameCount = 0;
  private frameCount = 0;
  private startedAtMilliseconds: number | undefined;
  private generation = 0;

  constructor(
    private readonly callbacks: PipelineCallbacks,
    private readonly now: () => number = () => performance.now(),
    private readonly limits: Readonly<PipelineLimits> = DEFAULT_PIPELINE_LIMITS,
  ) {}

  accept(frame: Uint8Array): void {
    if (this.finishing) {
      this.callbacks.onFrameDisposition?.('ignored');
      return;
    }
    const receivedAt = this.now();
    this.frameCount++;
    if (this.frameCount > this.limits.maxFrames) {
      this.stopAtBound(
        `Frame processing limit ${this.limits.maxFrames} reached. Restart the receiver and use one sender stream.`,
      );
      return;
    }
    if (
      this.startedAtMilliseconds !== undefined &&
      receivedAt - this.startedAtMilliseconds >
        this.limits.maxTransferMilliseconds
    ) {
      this.stopAtBound(
        `Transfer time limit ${formatMinutes(this.limits.maxTransferMilliseconds)} reached. Restart the receiver and sender.`,
      );
      return;
    }
    try {
      const progress = this.decoder.add(frame);
      const startedAt = this.recordProgress(progress, receivedAt);
      if (this.decoder.complete) {
        this.finish(this.generation, Math.max(0, receivedAt - startedAt));
      }
    } catch (error) {
      this.callbacks.onFrameDisposition?.(
        error instanceof OpticalCodecError && error.code === 'session'
          ? 'other-session'
          : error instanceof OpticalCodecError &&
              UNSUPPORTED_CODES.has(error.code)
            ? 'unsupported'
            : 'rejected',
      );
      this.handleError(error);
    }
  }

  private recordProgress(
    progress: ReturnType<OpticalDecoder['add']>,
    receivedAt: number,
  ): number {
    const useful = progress.independentFrameCount > this.independentFrameCount;
    // The decoder's bounded ID set distinguishes seen stripe/sequence pairs
    // from new equations that add no rank; no diagnostic payload copy is needed.
    const repeated = progress.distinctFrameCount === this.distinctFrameCount;
    this.distinctFrameCount = progress.distinctFrameCount;
    this.callbacks.onFrameDisposition?.(
      useful
        ? 'useful'
        : repeated
          ? 'repeated'
          : progress.independentRows === progress.sourceCount
            ? 'completed-stripe'
            : 'dependent',
    );
    this.startedAtMilliseconds ??= receivedAt;
    if (progress.independentFrameCount > this.independentFrameCount) {
      this.usefulFrames +=
        progress.independentFrameCount - this.independentFrameCount;
      this.independentFrameCount = progress.independentFrameCount;
    }
    this.callbacks.onProgress({
      percent: Math.min(
        99.9,
        (progress.independentFrameCount / progress.requiredFrameCount) * 100,
      ),
      stripeIndex: progress.stripeIndex,
      stripeCount: progress.stripeCount,
      independentRows: progress.independentRows,
      sourceCount: progress.sourceCount,
      usefulFrames: this.usefulFrames,
      requiredFrames: progress.requiredFrameCount,
      rejectedFrames: this.rejectedFrames,
    });
    return this.startedAtMilliseconds;
  }

  // fallow-ignore-next-line unused-class-member -- Compiled receiver tests exercise reset during pending completion.
  reset(): void {
    this.generation++;
    this.decoder.clear();
    this.decoder = new OpticalDecoder();
    this.finishing = false;
    this.usefulFrames = 0;
    this.rejectedFrames = 0;
    this.independentFrameCount = 0;
    this.distinctFrameCount = 0;
    this.frameCount = 0;
    this.startedAtMilliseconds = undefined;
  }

  private async finish(
    generation: number,
    elapsedMilliseconds: number,
  ): Promise<void> {
    this.finishing = true;
    try {
      const result = await this.decoder.result();
      if (generation !== this.generation) {
        result.fill(0);
        return;
      }
      const completion = {
        capsule: result,
        byteLength: result.byteLength,
        usefulFrames: this.usefulFrames,
        rejectedFrames: this.rejectedFrames,
        elapsedMilliseconds,
      };
      this.callbacks.onComplete(completion);
    } catch (error) {
      if (generation === this.generation) {
        this.handleError(error);
      }
    }
  }

  private handleError(error: unknown): void {
    this.rejectedFrames++;
    if (!(error instanceof OpticalCodecError)) {
      this.finishing = true;
      this.callbacks.onFatal(
        'Receiver stopped within its memory or runtime budget.',
      );
      return;
    }
    if (error.code === 'session') {
      this.callbacks.onSessionChange();
      return;
    }
    if (UNSUPPORTED_CODES.has(error.code)) {
      this.callbacks.onUnsupported(error.message);
      return;
    }
    if (FATAL_CODES.has(error.code)) {
      this.finishing = true;
      this.callbacks.onFatal(error.message);
      return;
    }
    this.callbacks.onRejected(error.code);
  }

  private stopAtBound(message: string): void {
    this.callbacks.onFrameDisposition?.('rejected');
    this.finishing = true;
    this.callbacks.onFatal(message);
  }
}

function formatMinutes(milliseconds: number): string {
  if (milliseconds < 60_000) {
    const seconds = milliseconds / 1000;
    return `${seconds} second${seconds === 1 ? '' : 's'}`;
  }
  const minutes = milliseconds / 60_000;
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}
