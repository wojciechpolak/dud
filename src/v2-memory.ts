// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { emptyV2State, type V2StoredState, type V2Store } from './v2-types.js';

function cloneState(state: V2StoredState): V2StoredState {
  return structuredClone(state);
}

export class MemoryV2Store implements V2Store {
  readonly quotaEnforcement = 'atomic' as const;
  readonly wholeState = true;
  private state = emptyV2State();
  private readonly nonces = new Map<string, number>();
  private queue: Promise<void> = Promise.resolve();

  async initialize(): Promise<void> {}

  async readState(): Promise<V2StoredState> {
    await this.queue;
    return cloneState(this.state);
  }

  async transaction<T>(
    operation: (state: V2StoredState) => T | Promise<T>,
  ): Promise<T> {
    let resolveResult!: (result: T) => void;
    let rejectResult!: (reason: unknown) => void;
    const result = new Promise<T>((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });
    this.queue = this.queue.then(async () => {
      const candidate = cloneState(this.state);
      try {
        const value = await operation(candidate);
        this.state = candidate;
        resolveResult(value);
      } catch (error) {
        rejectResult(error);
      }
    });
    await this.queue;
    return result;
  }

  async claimNonce(
    key: string,
    expiresAt: number,
    now: number,
  ): Promise<boolean> {
    return this.transaction(() => {
      const previous = this.nonces.get(key);
      if (previous !== undefined && previous >= now) {
        return false;
      }
      this.nonces.set(key, expiresAt);
      return true;
    });
  }

  async deleteExpiredNonces(now: number, limit: number): Promise<number> {
    let deleted = 0;
    for (const [key, expiresAt] of Array.from(this.nonces.entries()).sort()) {
      if (deleted >= limit) {
        break;
      }
      if (expiresAt < now) {
        this.nonces.delete(key);
        deleted += 1;
      }
    }
    return deleted;
  }
}
