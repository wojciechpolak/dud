// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { MAX_PIPELINE_FRAMES, type PipelineCallbacks } from './pipeline.js';
import {
  FOUNTAIN_CAPTURE_HEADROOM,
  MAX_FOUNTAIN_FRAME_BYTES,
  MAX_FOUNTAIN_PENDING_FRAMES,
  type FountainResponse,
} from './fountain-messages.js';

export interface FountainStats {
  submittedFrames: number;
  processedFrames: number;
  pendingFrames: number;
  maximumPendingFrames: number;
  processingMilliseconds: number;
  maximumProcessingMilliseconds: number;
  maximumRoundTripMilliseconds: number;
}

function emptyStats(): FountainStats {
  return {
    submittedFrames: 0,
    processedFrames: 0,
    pendingFrames: 0,
    maximumPendingFrames: 0,
    processingMilliseconds: 0,
    maximumProcessingMilliseconds: 0,
    maximumRoundTripMilliseconds: 0,
  };
}

// One worker owns the bounded fountain session. Only acknowledgement metadata
// stays on the UI thread; reset terminates both retained and queued ciphertext.
export class FountainFramePipeline {
  private worker: Worker | undefined;
  private readonly pending = new Map<number, number>();
  private stats = emptyStats();
  private stopped = false;

  constructor(
    private readonly callbacks: PipelineCallbacks,
    private readonly createWorker: (url: URL) => Worker = (url) =>
      new Worker(url, { type: 'module' }),
    private readonly now: () => number = () => performance.now(),
  ) {}

  get canAccept(): boolean {
    return (
      !this.stopped &&
      this.pending.size <=
        MAX_FOUNTAIN_PENDING_FRAMES - FOUNTAIN_CAPTURE_HEADROOM
    );
  }

  snapshot(): FountainStats {
    return { ...this.stats, pendingFrames: this.pending.size };
  }

  accept(frame: Uint8Array): void {
    if (this.stopped) {
      return;
    }
    if (
      !(frame instanceof Uint8Array) ||
      frame.byteLength > MAX_FOUNTAIN_FRAME_BYTES ||
      this.pending.size >= MAX_FOUNTAIN_PENDING_FRAMES ||
      this.stats.submittedFrames >= MAX_PIPELINE_FRAMES
    ) {
      this.fail(
        'Fountain frame queue or input limit reached. Restart the receiver and sender.',
      );
      return;
    }
    try {
      const worker = this.worker ?? this.startWorker();
      const id = this.stats.submittedFrames++;
      const receivedAt = this.now();
      const bytes =
        frame.buffer instanceof ArrayBuffer &&
        frame.byteOffset === 0 &&
        frame.byteLength === frame.buffer.byteLength
          ? frame
          : frame.slice();
      this.pending.set(id, receivedAt);
      this.stats.maximumPendingFrames = Math.max(
        this.stats.maximumPendingFrames,
        this.pending.size,
      );
      worker.postMessage({ id, receivedAt, frame: bytes.buffer }, [
        bytes.buffer,
      ]);
    } catch {
      this.fail('Fountain processing could not start. Restart the receiver.');
    }
  }

  reset(): void {
    this.worker?.terminate();
    this.worker = undefined;
    this.pending.clear();
    this.stats = emptyStats();
    this.stopped = false;
  }

  private startWorker(): Worker {
    const url = new URL('./fountain-worker.js', import.meta.url);
    url.search = new URL(import.meta.url).search;
    const worker = this.createWorker(url);
    this.worker = worker;
    worker.addEventListener(
      'message',
      (event: MessageEvent<FountainResponse>) => {
        if (this.worker === worker && !this.stopped) {
          this.receive(event.data);
        } else if (event.data.type === 'complete') {
          new Uint8Array(event.data.capsule).fill(0);
        }
      },
    );
    worker.addEventListener('error', () => {
      if (this.worker === worker) {
        this.fail('Fountain worker stopped. Restart the receiver.');
      }
    });
    return worker;
  }

  private receive(message: FountainResponse): void {
    if (message.type === 'failed') {
      this.fail(message.message);
      return;
    }
    if (message.type === 'complete') {
      this.stopped = true;
      this.worker?.terminate();
      this.worker = undefined;
      this.pending.clear();
      this.callbacks.onComplete({
        ...message.completion,
        capsule: new Uint8Array(message.capsule),
      });
      return;
    }
    const started = this.pending.get(message.id);
    if (started === undefined) {
      return;
    }
    this.pending.delete(message.id);
    this.stats.processedFrames++;
    this.stats.processingMilliseconds += message.processingMilliseconds;
    this.stats.maximumProcessingMilliseconds = Math.max(
      this.stats.maximumProcessingMilliseconds,
      message.processingMilliseconds,
    );
    this.stats.maximumRoundTripMilliseconds = Math.max(
      this.stats.maximumRoundTripMilliseconds,
      Math.max(0, this.now() - started),
    );
    if (message.disposition !== undefined) {
      this.callbacks.onFrameDisposition?.(message.disposition);
    }
    if (message.progress) {
      this.callbacks.onProgress(message.progress);
    }
    if (message.issue) {
      switch (message.issue.type) {
        case 'session':
          this.callbacks.onSessionChange();
          break;
        case 'unsupported':
          this.callbacks.onUnsupported(message.issue.value);
          break;
        case 'rejected':
          this.callbacks.onRejected(message.issue.value);
          break;
        case 'fatal':
          this.fail(message.issue.value);
          break;
      }
    }
  }

  private fail(message: string): void {
    this.stopped = true;
    this.worker?.terminate();
    this.worker = undefined;
    this.pending.clear();
    this.callbacks.onFatal(message);
  }
}
