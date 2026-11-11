// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export interface SyntheticFrameSink<T> {
  submit(frame: T): boolean;
  discard?(frame: T): void;
}

export type FrameWait = (signal: AbortSignal) => Promise<void>;

const waitForAnimationFrame: FrameWait = (signal) =>
  new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const callback = requestAnimationFrame(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    });
    const abort = (): void => {
      cancelAnimationFrame(callback);
      resolve();
    };
    signal.addEventListener('abort', abort, { once: true });
  });

// PlaySyntheticVideo submits recorded frames to the camera worker pool. Busy
// workers drop a frame under the same rule as live capture.
export async function playSyntheticVideo<T>(
  frames: AsyncIterable<T>,
  sink: SyntheticFrameSink<T>,
  signal: AbortSignal,
  wait: FrameWait = waitForAnimationFrame,
): Promise<{ submitted: number; dropped: number }> {
  let submitted = 0;
  let dropped = 0;
  for await (const frame of frames) {
    if (signal.aborted) {
      sink.discard?.(frame);
      break;
    }
    if (sink.submit(frame)) {
      submitted++;
    } else {
      dropped++;
    }
    await wait(signal);
  }
  return { submitted, dropped };
}
