// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Decoder callbacks can arrive faster than the page can render useful changes.
// Keep the latest state for each display key while preserving every decoded frame.
export class PresentationCadence<T> {
  private lastRenderedAt = Number.NEGATIVE_INFINITY;
  private readonly pending = new Map<unknown, T>();

  constructor(
    private readonly intervalMilliseconds: number,
    private readonly render: (value: T) => void,
    private readonly key: (value: T) => unknown = () => undefined,
  ) {
    if (!Number.isFinite(intervalMilliseconds) || intervalMilliseconds <= 0) {
      throw new RangeError('display interval must be finite and positive');
    }
  }

  offer(value: T, atMilliseconds: number): void {
    if (!Number.isFinite(atMilliseconds) || atMilliseconds < 0) {
      throw new RangeError('display time must be finite and nonnegative');
    }
    const key = this.key(value);
    // Render the most recent update last so aggregate counters cannot regress
    // when updates for several independent rows share one display interval.
    this.pending.delete(key);
    this.pending.set(key, value);
    if (atMilliseconds - this.lastRenderedAt >= this.intervalMilliseconds) {
      this.flush();
      this.lastRenderedAt = atMilliseconds;
    }
  }

  flush(): void {
    const values = [...this.pending.values()];
    this.pending.clear();
    for (const value of values) {
      if (value !== undefined) {
        this.render(value);
      }
    }
  }

  reset(): void {
    this.pending.clear();
    this.lastRenderedAt = Number.NEGATIVE_INFINITY;
  }
}
