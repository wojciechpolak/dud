// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { R2BlobStore } from './cloudflare.js';
import { DEFAULT_CONFIG } from './config.js';
import { formatEventLog } from './log.js';
import { createDudService } from './service.js';
import type { Env, ExecutionContextLike } from './types.js';
import { D1V2Repository } from './v2-d1-repository.js';
import { D1V2PairingRepository } from './v2-d1-pairing-repository.js';
import { D1V2MaintenanceRepository } from './v2-d1-maintenance-repository.js';
import { runV2MaintenancePass } from './v2-maintenance.js';
import type { V2BodyStore, V2Repository } from './v2-repository.js';
import { R2V2BodyStore } from './v2-r2.js';
import { WorkerV2Store } from './v2-worker-store.js';
import type { V2TimingObserver } from './v2-timing.js';

const WORKER_MAINTENANCE_LEASE = 'v2-maintenance';
const WORKER_MAINTENANCE_INTERVAL_SECONDS = 5 * 60;
const WORKER_MAINTENANCE_BATCH_SIZE = 128;
/** Batch budget per lease window; the next window resumes where this stopped. */
const WORKER_MAINTENANCE_MAX_BATCHES = 4;

function envBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') {
    return fallback;
  }
  if (value === 'true' || value === '1') {
    return true;
  }
  if (value === 'false' || value === '0') {
    return false;
  }
  throw new Error('Boolean environment value is invalid.');
}

function buildService(env: Env, observeV2Timing?: V2TimingObserver) {
  const storageConfigured = Boolean(env.FILES);
  const v2Enabled = envBoolean(env.DUD_PEER_ENABLED, DEFAULT_CONFIG.v2Enabled);
  if (v2Enabled && !env.DB) {
    throw new Error('D1 DB binding is required when the v2 Worker is enabled.');
  }

  return createDudService({
    blobStore: new R2BlobStore(env.FILES!),
    v2Store: env.DB && env.FILES ? new WorkerV2Store() : undefined,
    v2Repository: env.DB ? new D1V2Repository(env.DB) : undefined,
    v2PairingRepository: env.DB ? new D1V2PairingRepository(env.DB) : undefined,
    v2BodyStore: env.FILES ? new R2V2BodyStore(env.FILES) : undefined,
    observeV2Timing,
    // Refusals are uniform on the wire by design, so the reason only ever
    // reaches the operator, here through the Worker's own log stream.
    observeV2Rejection: ({ route, reason }) => {
      console.error(
        formatEventLog(
          'json',
          'error',
          'v2_rejected',
          `V2 request refused on ${route}: ${reason}`,
        ),
      );
    },
    config: {
      version: env.APP_VERSION ?? DEFAULT_CONFIG.version,
      secretToken: env.DUD_DROP_SECRET,
      v1Enabled: envBoolean(env.DUD_DROP_ENABLED, DEFAULT_CONFIG.v1Enabled),
      v2AdminSecret: env.DUD_PEER_ADMIN_SECRET,
      v2DeploymentKey: env.DUD_PEER_DEPLOYMENT_KEY,
      v2Enabled,
      v2Secret: env.DUD_PEER_SECRET,
      v2OpenEnrollment: envBoolean(env.DUD_PEER_OPEN_ENROLLMENT, false),
      v2AcceptWeakEnrollmentKdf: envBoolean(
        env.DUD_PEER_ACCEPT_WEAK_ENROLLMENT_KDF,
        false,
      ),
      storageConfigured,
      storageNotConfiguredMessage:
        'Storage is not configured. Bind R2 as FILES.',
    },
  });
}

/**
 * In-isolate view of the five-minute maintenance window. The D1 lease is the
 * authority across isolates; this gate keeps the concurrent requests of one
 * isolate from each issuing a lease write and from each awaiting a duplicate
 * pass, so requests that arrive during a running pass skip the work entirely.
 */
export interface WorkerMaintenanceGate {
  nextAttemptSeconds: number;
  running: Promise<void> | undefined;
}

export function createWorkerMaintenanceGate(): WorkerMaintenanceGate {
  return { nextAttemptSeconds: 0, running: undefined };
}

const workerMaintenanceGate = createWorkerMaintenanceGate();

/**
 * Schedule at most one bounded granular-maintenance pass in each five-minute
 * lease window. The pass runs restartable batches until D1 reports no expired
 * records remain or its batch budget is spent, and the body keys it deletes
 * originate only from metadata D1 selected; request handling never lists R2.
 */
export function scheduleWorkerV2Maintenance(
  ctx: ExecutionContextLike,
  database: NonNullable<Env['DB']>,
  repository: V2Repository,
  bodyStore: V2BodyStore,
  now = () => Date.now(),
  gate: WorkerMaintenanceGate = workerMaintenanceGate,
): void {
  const current = Math.floor(now() / 1000);
  if (gate.running || current < gate.nextAttemptSeconds) {
    return;
  }
  gate.nextAttemptSeconds = current + WORKER_MAINTENANCE_INTERVAL_SECONDS;
  const running = (async () => {
    const lease = new D1V2MaintenanceRepository(database);
    if (
      !(await lease.acquireLease(
        WORKER_MAINTENANCE_LEASE,
        current + WORKER_MAINTENANCE_INTERVAL_SECONDS,
        current,
      ))
    ) {
      return;
    }
    await runV2MaintenancePass(
      repository,
      bodyStore,
      current,
      WORKER_MAINTENANCE_BATCH_SIZE,
      WORKER_MAINTENANCE_MAX_BATCHES,
    );
  })();
  gate.running = running;
  ctx.waitUntil(
    running.finally(() => {
      gate.running = undefined;
    }),
  );
}

export function createWorker(env: Env) {
  const service = buildService(env);
  const v2Enabled = envBoolean(env.DUD_PEER_ENABLED, DEFAULT_CONFIG.v2Enabled);
  const repository = env.DB ? new D1V2Repository(env.DB) : undefined;
  const bodyStore = env.FILES ? new R2V2BodyStore(env.FILES) : undefined;

  return {
    async fetch(
      request: Request,
      ctx: ExecutionContextLike,
    ): Promise<Response> {
      if (v2Enabled && repository && bodyStore && env.DB) {
        scheduleWorkerV2Maintenance(ctx, env.DB, repository, bodyStore);
      }
      return service.fetch(
        request,
        ctx,
        request.headers.get('cf-connecting-ip') ?? 'unknown',
      );
    },
  };
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContextLike,
  ): Promise<Response> {
    return createWorker(env).fetch(request, ctx);
  },
};
