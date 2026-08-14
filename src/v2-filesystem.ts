// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import {
  open,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
} from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { emptyV2State, type V2StoredState, type V2Store } from './v2-types.js';

const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 5_000;

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function errorCode(error: unknown): string | undefined {
  return (error as { code?: string }).code;
}

function validateState(value: unknown): V2StoredState {
  const state = value as Partial<V2StoredState>;
  if (
    state?.version !== 2 ||
    !state.capabilities ||
    !state.reservations ||
    !state.revocations ||
    !state.rateWindows
  ) {
    throw new Error('Filesystem v2 state is invalid.');
  }
  // Later state collections are empty by default, so older state files migrate
  // in memory and are persisted on the next transaction.
  state.invitations ??= {};
  state.relationships ??= {};
  state.legacyObjects ??= {};
  state.legacyCommittedBytes ??= 0;
  if (
    !Number.isSafeInteger(state.legacyCommittedBytes) ||
    state.legacyCommittedBytes < 0
  ) {
    throw new Error('Filesystem v2 legacy accounting state is invalid.');
  }
  return state as V2StoredState;
}

export class FilesystemV2Store implements V2Store {
  readonly quotaEnforcement = 'atomic' as const;
  readonly wholeState = true;
  private readonly v2Dir: string;
  private readonly statePath: string;
  private readonly lockPath: string;
  private readonly nonceDir: string;

  constructor(rootDir: string) {
    this.v2Dir = join(rootDir, 'v2');
    this.statePath = join(this.v2Dir, 'state.json');
    this.lockPath = join(this.v2Dir, 'state.lock');
    this.nonceDir = join(this.v2Dir, 'nonces');
  }

  async initialize(): Promise<void> {
    await mkdir(this.nonceDir, { recursive: true, mode: 0o700 });
    await this.removeStaleArtifacts();
    try {
      await stat(this.statePath);
    } catch (error) {
      if (errorCode(error) !== 'ENOENT') {
        throw error;
      }
      await this.withLock(async () => {
        try {
          await stat(this.statePath);
        } catch (nestedError) {
          if (errorCode(nestedError) !== 'ENOENT') {
            throw nestedError;
          }
          await this.writeState(emptyV2State());
        }
      });
    }
  }

  async readState(): Promise<V2StoredState> {
    const raw = await readFile(this.statePath, 'utf8');
    return structuredClone(validateState(JSON.parse(raw)));
  }

  async transaction<T>(
    operation: (state: V2StoredState) => T | Promise<T>,
  ): Promise<T> {
    return this.withLock(async () => {
      const state = await this.readState();
      const result = await operation(state);
      await this.writeState(state);
      return result;
    });
  }

  async claimNonce(
    key: string,
    expiresAt: number,
    _now: number,
  ): Promise<boolean> {
    if (!/^[a-f0-9]{64}$/.test(key)) {
      throw new Error('Invalid v2 nonce storage key.');
    }
    const path = join(this.nonceDir, `${key}.json`);
    try {
      const handle = await open(path, 'wx', 0o600);
      try {
        await handle.writeFile(JSON.stringify({ expiresAt }), 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      return true;
    } catch (error) {
      if (errorCode(error) === 'EEXIST') {
        return false;
      }
      throw error;
    }
  }

  async deleteExpiredNonces(now: number, limit: number): Promise<number> {
    let deleted = 0;
    const entries = (await readdir(this.nonceDir)).sort();
    for (const entry of entries) {
      if (deleted >= limit || !/^[a-f0-9]{64}\.json$/.test(entry)) {
        continue;
      }
      const path = join(this.nonceDir, entry);
      try {
        const value = JSON.parse(await readFile(path, 'utf8')) as {
          expiresAt?: number;
        };
        if (Number(value.expiresAt) < now) {
          await rm(path, { force: true });
          deleted += 1;
        }
      } catch {
        // Preserve malformed records so replay protection fails closed.
      }
    }
    return deleted;
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    const deadline = Date.now() + LOCK_WAIT_MS;
    let handle: any;
    while (!handle) {
      try {
        handle = await open(this.lockPath, 'wx', 0o600);
        await handle.writeFile(String(Date.now()), 'utf8');
        await handle.sync();
      } catch (error) {
        if (errorCode(error) !== 'EEXIST') {
          throw error;
        }
        try {
          const lockStat = await stat(this.lockPath);
          if (Date.now() - lockStat.mtimeMs > LOCK_STALE_MS) {
            await rm(this.lockPath, { force: true });
            continue;
          }
        } catch (statError) {
          if (errorCode(statError) === 'ENOENT') {
            continue;
          }
          throw statError;
        }
        if (Date.now() >= deadline) {
          throw new Error(
            'Timed out waiting for the v2 filesystem state lock.',
          );
        }
        await sleep(10);
      }
    }

    const heartbeat = setInterval(
      () => {
        void handle.utimes(new Date(), new Date()).catch(() => undefined);
      },
      Math.floor(LOCK_STALE_MS / 3),
    );
    try {
      return await operation();
    } finally {
      clearInterval(heartbeat);
      await handle.close().catch(() => undefined);
      await rm(this.lockPath, { force: true });
    }
  }

  private async writeState(state: V2StoredState): Promise<void> {
    validateState(state);
    const suffix = `${Date.now()}-${crypto.randomUUID()}`;
    const temporaryPath = `${this.statePath}.tmp-${suffix}`;
    await mkdir(dirname(this.statePath), { recursive: true, mode: 0o700 });
    const handle = await open(temporaryPath, 'wx', 0o600);
    try {
      await handle.writeFile(JSON.stringify(state), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporaryPath, this.statePath);
    const directory = await open(dirname(this.statePath), 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }

  private async removeStaleArtifacts(): Promise<void> {
    const entries = await readdir(this.v2Dir).catch(() => []);
    for (const entry of entries) {
      if (!entry.startsWith('state.json.tmp-') && entry !== 'state.lock') {
        continue;
      }
      const path = join(this.v2Dir, entry);
      try {
        const fileStat = await stat(path);
        if (Date.now() - fileStat.mtimeMs > LOCK_STALE_MS) {
          await rm(path, { force: true });
        }
      } catch {
        // A concurrent cleanup or initialization already handled it.
      }
    }
  }
}
