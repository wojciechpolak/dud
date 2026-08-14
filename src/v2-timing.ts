// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

/**
 * Server-side phase timing for V2 requests.
 *
 * A timing record carries a fixed route label, the HTTP status, and four
 * durations. It never carries a capability, lookup, slot, epoch, delivery,
 * relationship, operation, or peer value, so a deployment can report it at any
 * verbosity without turning its own performance data into a metadata oracle.
 *
 * The three phases are disjoint and cover the work a V2 route can spend time
 * in: proving the caller may act (`authorization`), the transactional metadata
 * write or read (`metadata`), and moving payload bytes (`body`). `totalMs`
 * spans the whole route, so the difference between it and the three phases is
 * framing, decoding, and response construction.
 */
export type V2TimingPhase = 'authorization' | 'metadata' | 'body';

/** The V2 route classes that report timings, as fixed labels. */
export const V2_TIMED_OPERATIONS = [
  'capabilities',
  'capability-reissue',
  'pairing',
  'delivery-publish',
  'delivery-inbox',
  'delivery-complete',
  'control-event',
  'admin',
  'unknown',
] as const;

export type V2TimedOperation = (typeof V2_TIMED_OPERATIONS)[number];

export interface V2OperationTiming {
  operation: V2TimedOperation;
  status: number;
  authorizationMs: number;
  metadataMs: number;
  bodyMs: number;
  totalMs: number;
}

export type V2TimingObserver = (timing: V2OperationTiming) => void;

export interface V2TimingRecorder {
  /** Runs `work` and adds its elapsed time to one phase. */
  measure<T>(phase: V2TimingPhase, work: () => Promise<T>): Promise<T>;
  /** Reports the record once; later calls are ignored. */
  finish(status: number): void;
}

/** A recorder that costs nothing when no deployment is observing. */
const IDLE_RECORDER: V2TimingRecorder = {
  measure: (_phase, work) => work(),
  finish: () => undefined,
};

function defaultMonotonicMs(): number {
  return performance.now();
}

/**
 * Durations are reported at microsecond resolution. That is precise enough for
 * a release gate and coarse enough that the record stays a stable, comparable
 * number rather than a raw clock reading.
 */
function round(milliseconds: number): number {
  return Math.round(milliseconds * 1000) / 1000;
}

export function startV2Timing(
  operation: V2TimedOperation,
  observe?: V2TimingObserver,
  monotonicMs: () => number = defaultMonotonicMs,
): V2TimingRecorder {
  if (!observe) {
    return IDLE_RECORDER;
  }
  const startedAt = monotonicMs();
  const totals: Record<V2TimingPhase, number> = {
    authorization: 0,
    metadata: 0,
    body: 0,
  };
  let reported = false;
  return {
    async measure(phase, work) {
      const phaseStartedAt = monotonicMs();
      try {
        return await work();
      } finally {
        totals[phase] += monotonicMs() - phaseStartedAt;
      }
    },
    finish(status) {
      if (reported) {
        return;
      }
      reported = true;
      observe({
        operation,
        status,
        authorizationMs: round(totals.authorization),
        metadataMs: round(totals.metadata),
        bodyMs: round(totals.body),
        totalMs: round(monotonicMs() - startedAt),
      });
    },
  };
}

const COMPLETION_PATH = /^\/v2\/deliveries\/[a-f0-9]{32}\/complete$/;

/**
 * Maps a request to its timing label. The label set is fixed and public, so it
 * classifies a request without describing it.
 */
export function classifyV2Operation(
  method: string,
  pathname: string,
): V2TimedOperation {
  if (method === 'GET' && pathname === '/v2/capabilities') {
    return 'capabilities';
  }
  if (method === 'POST') {
    switch (pathname) {
      case '/v2/capabilities/reissue':
        return 'capability-reissue';
      case '/v2/deliveries':
        return 'delivery-publish';
      case '/v2/inbox':
        return 'delivery-inbox';
      case '/v2/control-events':
        return 'control-event';
    }
    if (COMPLETION_PATH.test(pathname)) {
      return 'delivery-complete';
    }
  }
  if (pathname.startsWith('/v2/pairing')) {
    return 'pairing';
  }
  if (pathname.startsWith('/v2/admin/')) {
    return 'admin';
  }
  return 'unknown';
}
