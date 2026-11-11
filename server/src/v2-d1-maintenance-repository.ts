// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { D1DatabaseLike, D1RunResultLike } from './types.js';

/** D1-backed lease acquisition for bounded Worker maintenance passes. */
export class D1V2MaintenanceRepository {
  constructor(private readonly database: D1DatabaseLike) {}

  async acquireLease(
    name: string,
    expiresAt: number,
    now: number,
  ): Promise<boolean> {
    if (!/^[a-z0-9-]{1,64}$/.test(name)) {
      throw new Error('D1 maintenance lease name is invalid.');
    }
    if (
      !Number.isSafeInteger(expiresAt) ||
      !Number.isSafeInteger(now) ||
      expiresAt <= now
    ) {
      throw new Error('D1 maintenance lease expiry is invalid.');
    }
    const result = await this.database
      .prepare(
        'INSERT INTO maintenance_leases(name, expires_at) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET expires_at = excluded.expires_at WHERE maintenance_leases.expires_at <= ?',
      )
      .bind(name, expiresAt, now)
      .run<D1RunResultLike>();
    return result.meta?.changes === 1;
  }
}
