// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { V2Store, V2StoredState } from './v2-types.js';

/**
 * Worker-side `V2Store` that refuses every whole-state operation. Granular D1
 * repositories own all V2 Worker storage, so a caller that reaches this fails
 * closed instead of creating state.json-like metadata.
 */
export class WorkerV2Store implements V2Store {
  readonly quotaEnforcement = 'atomic' as const;
  readonly wholeState = false;

  async initialize(): Promise<void> {}

  private unavailable(): never {
    throw new Error('The legacy V2 state store is unavailable in Workers.');
  }

  async readState(): Promise<V2StoredState> {
    return this.unavailable();
  }

  async transaction<T>(
    _operation: (state: V2StoredState) => T | Promise<T>,
  ): Promise<T> {
    return this.unavailable();
  }

  async claimNonce(
    _key: string,
    _expiresAt: number,
    _now: number,
  ): Promise<boolean> {
    return this.unavailable();
  }

  async deleteExpiredNonces(_now: number, _limit: number): Promise<number> {
    return this.unavailable();
  }
}
