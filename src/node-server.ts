// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { readFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { Readable } from 'node:stream';

import { DEFAULT_CONFIG } from './config.js';
import { FilesystemBlobStore } from './filesystem.js';
import { errorResponse } from './http.js';
import { createDudService } from './service.js';
import { parseTtl } from './ttl.js';
import type { BlobStore, DudConfig, ExecutionContextLike } from './types.js';
import { FilesystemV2Store } from './v2-filesystem.js';
import { FilesystemV2BodyStore } from './v2-filesystem-body-store.js';
import { runV2MaintenancePass } from './v2-maintenance.js';
import { SQLiteV2Repository } from './v2-sqlite-repository.js';
import type { V2BodyStore, V2Repository } from './v2-repository.js';
import type { V2Store } from './v2-types.js';
import type { V2OperationTiming, V2TimingObserver } from './v2-timing.js';
import {
  formatAccessLog,
  formatEventLog,
  parseLogFormat,
  type DudLogFormat,
} from './log.js';

export interface NodeServerConfig extends Partial<DudConfig> {
  dataDir: string;
  listenHost?: string;
  listenPort?: number;
  logMode?: 'normal' | 'minimal' | 'silent';
  logFormat?: DudLogFormat;
  publicBaseUrl?: string;
  tlsCertFile?: string;
  tlsKeyFile?: string;
}

export type NodeRequestHook = (
  request: Request,
) => Response | null | void | Promise<Response | null | void>;

export interface NodeServerOptions {
  beforeRequest?: NodeRequestHook;
  blobStore?: BlobStore;
  createId?: () => string;
  logger?: {
    error(...args: unknown[]): void;
    log(...args: unknown[]): void;
  };
  now?: () => number;
  randomBytes?: (length: number) => Uint8Array;
  v2Store?: V2Store;
  v2Repository?: V2Repository;
  v2BodyStore?: V2BodyStore;
  /** Receives one redacted phase-timing record per v2 request. */
  observeV2Timing?: V2TimingObserver;
}

const V2_MAINTENANCE_INTERVAL_MS = 5 * 60 * 1000;

/**
 * Run bounded, restartable granular-metadata cleanup batches until the
 * repository reports nothing expired remains, and remove only the bodies those
 * batches named. An interrupted pass loses no work: the next tick resumes from
 * the records that are still expired.
 */
export async function runNodeV2Maintenance(
  repository: V2Repository,
  bodyStore: V2BodyStore,
  now: () => number,
  limit: number,
): Promise<void> {
  await runV2MaintenancePass(
    repository,
    bodyStore,
    Math.floor(now() / 1000),
    limit,
  );
}

/**
 * Schedules bounded granular V2 maintenance without keeping the Node process
 * alive. Concurrent timer ticks share the current pass instead of starting a
 * second metadata transaction.
 */
export function scheduleNodeV2Maintenance(
  repository: V2Repository,
  bodyStore: V2BodyStore,
  now: () => number,
  limit: number,
  logger: NodeServerOptions['logger'],
): () => void {
  let running: Promise<void> | undefined;
  const run = () => {
    if (running) {
      return;
    }
    running = runNodeV2Maintenance(repository, bodyStore, now, limit)
      .catch((error: unknown) => {
        logger?.error?.('V2 maintenance failed:', error);
      })
      .finally(() => {
        running = undefined;
      });
  };
  run();
  const timer = setInterval(run, V2_MAINTENANCE_INTERVAL_MS);
  (timer as unknown as { unref(): void }).unref();
  return () => clearInterval(timer);
}

function parseLogMode(
  raw: string | undefined,
): 'normal' | 'minimal' | 'silent' {
  if (raw === undefined || raw === 'normal') {
    return 'normal';
  }
  if (raw === 'minimal') {
    return 'minimal';
  }
  if (raw === 'silent') {
    return 'silent';
  }

  throw new Error('DUD_LOG_MODE must be one of: normal, minimal, silent.');
}

function clientAddress(req: any): string {
  const forwardedFor = normalizeForwardedValue(
    req.headers['x-forwarded-for'] ?? null,
  );
  if (forwardedFor) {
    return forwardedFor;
  }

  return req.socket?.remoteAddress ?? '-';
}

export function redactAccessPath(pathname: string): string {
  if (!pathname.startsWith('/v2/')) {
    return pathname;
  }
  return pathname
    .replace(/\/deliveries\/[a-f0-9]{32}(?=\/|$)/g, '/deliveries/<redacted>')
    .replace(
      /\/pairing\/rendezvous\/[a-f0-9]{64}(?=\/|$)/g,
      '/pairing/rendezvous/<redacted>',
    );
}

function logAccess(
  config: NodeServerConfig,
  logger: NodeServerOptions['logger'],
  req: any,
  request: Request,
  response: Response,
  startedAtMs: number,
  timing?: V2OperationTiming,
): void {
  if (config.logMode === 'silent') {
    return;
  }

  const url = new URL(request.url);
  logger?.log?.(
    formatAccessLog(config.logFormat ?? 'text', {
      method: request.method,
      path: redactAccessPath(url.pathname),
      status: response.status,
      durationMs: Date.now() - startedAtMs,
      ...(config.logMode === 'minimal' ? {} : { client: clientAddress(req) }),
      ...(timing ? { timing } : {}),
    }),
  );
}

function parseIntegerEnv(
  name: string,
  fallback: number,
  env: Record<string, string | undefined>,
): number {
  const raw = env[name];
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer.`);
  }

  return parsed;
}

function parseBooleanEnv(
  name: string,
  fallback: boolean,
  env: Record<string, string | undefined>,
): boolean {
  const raw = env[name];
  if (raw === undefined || raw === '') {
    return fallback;
  }
  if (raw === 'true' || raw === '1') {
    return true;
  }
  if (raw === 'false' || raw === '0') {
    return false;
  }
  throw new Error(`${name} must be true, false, 1, or 0.`);
}

function normalizeForwardedValue(value: string | null): string | null {
  if (!value) {
    return null;
  }

  return value.split(',')[0]?.trim() ?? null;
}

function buildRequestUrl(
  req: any,
  config: NodeServerConfig,
  isTls: boolean,
): string {
  const forwardedProto = normalizeForwardedValue(
    req.headers['x-forwarded-proto'] ?? null,
  );
  const forwardedHost = normalizeForwardedValue(
    req.headers['x-forwarded-host'] ?? null,
  );
  const requestPath = req.url ?? '/';

  if (config.publicBaseUrl) {
    return new URL(requestPath, config.publicBaseUrl).toString();
  }

  if (forwardedProto && forwardedHost) {
    return `${forwardedProto}://${forwardedHost}${requestPath}`;
  }

  const hostHeader =
    req.headers.host ??
    `${config.listenHost ?? '127.0.0.1'}:${config.listenPort ?? 8787}`;
  return `${isTls ? 'https' : 'http'}://${hostHeader}${requestPath}`;
}

function buildHeaders(req: any): Headers {
  const headers = new Headers();
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    headers.append(req.rawHeaders[i], req.rawHeaders[i + 1]);
  }
  return headers;
}

function buildRequest(
  req: any,
  config: NodeServerConfig,
  isTls: boolean,
): Request {
  const url = buildRequestUrl(req, config, isTls);
  const method = req.method ?? 'GET';
  const headers = buildHeaders(req);

  if (method === 'GET' || method === 'HEAD') {
    return new Request(url, { method, headers });
  }

  return new Request(url, {
    method,
    headers,
    body: Readable.toWeb(req) as ReadableStream<Uint8Array>,
    duplex: 'half',
  } as RequestInit & { duplex: 'half' });
}

async function sendResponse(res: any, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => {
    res.setHeader(key, value);
  });

  if (!response.body) {
    res.end();
    return;
  }

  const nodeBody = Readable.fromWeb(response.body);
  res.on('close', () => {
    if (!res.writableEnded && response.body) {
      void response.body.cancel().catch(() => undefined);
    }
  });

  await new Promise<void>((resolve, reject) => {
    nodeBody.on('error', reject);
    res.on('error', reject);
    res.on('finish', () => resolve());
    nodeBody.pipe(res);
  });
}

function createContext(
  logger: NodeServerOptions['logger'],
): ExecutionContextLike {
  return {
    waitUntil(promise) {
      void Promise.resolve(promise).catch((error) => {
        logger?.error?.('Background task failed:', error);
      });
    },
  };
}

function buildServiceConfig(config: NodeServerConfig): DudConfig {
  return {
    ...DEFAULT_CONFIG,
    ...config,
    listenHost: undefined,
    listenPort: undefined,
    publicBaseUrl: undefined,
    tlsCertFile: undefined,
    tlsKeyFile: undefined,
    storageConfigured: true,
  } as DudConfig;
}

function validateNodeV2Origin(config: NodeServerConfig): void {
  if (!config.v2Enabled) {
    return;
  }
  if (!config.publicBaseUrl) {
    throw new Error(
      'DUD_PUBLIC_BASE_URL is required when the Node v2 service is enabled.',
    );
  }
  const publicUrl = new URL(config.publicBaseUrl);
  if (
    publicUrl.protocol !== 'https:' ||
    publicUrl.username ||
    publicUrl.password ||
    publicUrl.pathname !== '/' ||
    publicUrl.search ||
    publicUrl.hash
  ) {
    throw new Error(
      'DUD_PUBLIC_BASE_URL must be a canonical HTTPS origin for v2.',
    );
  }
}

export function createNodeRequestHandler(
  config: NodeServerConfig,
  options: NodeServerOptions = {},
): (req: unknown, res: unknown) => Promise<void> {
  validateNodeV2Origin(config);
  const blobStore =
    options.blobStore ?? new FilesystemBlobStore(config.dataDir);
  const serviceConfig = buildServiceConfig(config);
  const v2Store =
    options.v2Store ??
    (serviceConfig.v2Enabled
      ? new FilesystemV2Store(config.dataDir)
      : undefined);
  const v2Repository =
    options.v2Repository ??
    (serviceConfig.v2Enabled
      ? new SQLiteV2Repository(config.dataDir)
      : undefined);
  const v2BodyStore =
    options.v2BodyStore ??
    (serviceConfig.v2Enabled
      ? new FilesystemV2BodyStore(config.dataDir)
      : undefined);
  const logger = options.logger ?? console;
  const service = createDudService({
    blobStore,
    config: serviceConfig,
    now: options.now,
    createId: options.createId,
    randomBytes: options.randomBytes,
    v2Store,
    v2Repository,
    ...(v2Repository instanceof SQLiteV2Repository
      ? { v2PairingRepository: v2Repository }
      : {}),
    v2BodyStore,
    observeV2Timing: options.observeV2Timing,
    // The refusal the caller sees is deliberately uniform, which leaves an
    // operator unable to tell a quota problem from a stale replay. The reason
    // goes to the log instead, through the same redaction every other event
    // gets.
    observeV2Rejection: ({ route, reason }) => {
      if (config.logMode === 'silent') {
        return;
      }
      logger.error(
        formatEventLog(
          config.logFormat ?? 'text',
          'error',
          'v2_rejected',
          `V2 request refused on ${route}: ${reason}`,
        ),
      );
    },
  });
  const isTls = Boolean(config.tlsCertFile && config.tlsKeyFile);

  return async function handleNodeRequest(req: any, res: any): Promise<void> {
    const startedAtMs = Date.now();
    try {
      const request = buildRequest(req, config, isTls);

      if (options.beforeRequest) {
        const intercepted = await options.beforeRequest(request);
        if (intercepted) {
          logAccess(config, logger, req, request, intercepted, startedAtMs);
          await sendResponse(res, intercepted);
          return;
        }
      }

      // The observer is per request, so the phase timings land in this
      // request's own access record even under concurrency.
      let timing: V2OperationTiming | undefined;
      const response = await service.fetch(
        request,
        createContext(logger),
        req.socket?.remoteAddress ?? 'unknown',
        (record) => {
          timing = record;
        },
      );
      logAccess(config, logger, req, request, response, startedAtMs, timing);
      await sendResponse(res, response);
    } catch (error) {
      logger.error(
        formatEventLog(
          config.logFormat ?? 'text',
          'error',
          'request_failed',
          `Node server request failed: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
      await sendResponse(res, errorResponse(500, 'Internal server error.'));
    }
  };
}

async function listen(server: any, host: string, port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

export async function startNodeServer(
  config: NodeServerConfig,
  options: NodeServerOptions = {},
): Promise<any> {
  const logger = options.logger ?? console;
  const serviceConfig = buildServiceConfig(config);
  const repository =
    options.v2Repository ??
    (serviceConfig.v2Enabled
      ? new SQLiteV2Repository(config.dataDir)
      : undefined);
  const bodyStore =
    options.v2BodyStore ??
    (serviceConfig.v2Enabled
      ? new FilesystemV2BodyStore(config.dataDir)
      : undefined);
  if (repository && bodyStore) {
    await repository.initialize();
  }
  const handler = createNodeRequestHandler(config, {
    ...options,
    ...(repository ? { v2Repository: repository } : {}),
    ...(bodyStore ? { v2BodyStore: bodyStore } : {}),
  });

  const server =
    config.tlsCertFile && config.tlsKeyFile
      ? createHttpsServer(
          {
            cert: await readFile(config.tlsCertFile),
            key: await readFile(config.tlsKeyFile),
            minVersion: 'TLSv1.3',
          },
          handler,
        )
      : createHttpServer(handler);

  const host = config.listenHost ?? '127.0.0.1';
  const port = config.listenPort ?? 8787;
  await listen(server, host, port);

  const stopMaintenance =
    repository && bodyStore
      ? scheduleNodeV2Maintenance(
          repository,
          bodyStore,
          options.now ?? (() => Date.now()),
          serviceConfig.cleanupBatchSize,
          logger,
        )
      : undefined;
  server.once('close', () => stopMaintenance?.());

  const address = server.address();
  const actualPort =
    typeof address === 'object' && address ? Number(address.port) : port;
  const origin = `${config.tlsCertFile && config.tlsKeyFile ? 'https' : 'http'}://${host}:${actualPort}`;
  if (config.logMode !== 'silent') {
    logger.log(
      formatEventLog(
        config.logFormat ?? 'text',
        'info',
        'listening',
        `DUD node server listening on ${origin}`,
      ),
    );
  }
  return server;
}

export function loadNodeServerConfig(
  env: Record<string, string | undefined> = process.env as Record<
    string,
    string | undefined
  >,
): NodeServerConfig {
  const maxTtlMs = parseTtl(
    env.DUD_MAX_TTL ?? null,
    DEFAULT_CONFIG.maxTtlMs,
    DEFAULT_CONFIG.maxTtlMs,
  );
  const defaultTtlMs = parseTtl(
    env.DUD_DEFAULT_TTL ?? null,
    DEFAULT_CONFIG.defaultTtlMs,
    maxTtlMs,
  );

  if (Boolean(env.DUD_TLS_CERT_FILE) !== Boolean(env.DUD_TLS_KEY_FILE)) {
    throw new Error(
      'DUD_TLS_CERT_FILE and DUD_TLS_KEY_FILE must be set together.',
    );
  }

  return {
    dataDir: env.DUD_DATA_DIR || './dud-data',
    listenHost: env.DUD_LISTEN_HOST || '127.0.0.1',
    listenPort: parseIntegerEnv('DUD_LISTEN_PORT', 8787, env),
    logMode: parseLogMode(env.DUD_LOG_MODE),
    logFormat: parseLogFormat(env.DUD_LOG_FORMAT),
    publicBaseUrl: env.DUD_PUBLIC_BASE_URL,
    tlsCertFile: env.DUD_TLS_CERT_FILE,
    tlsKeyFile: env.DUD_TLS_KEY_FILE,
    serviceName: env.DUD_SERVICE_NAME || DEFAULT_CONFIG.serviceName,
    version: env.APP_VERSION || DEFAULT_CONFIG.version,
    secretToken: env.DUD_DROP_SECRET,
    v1Enabled: parseBooleanEnv(
      'DUD_DROP_ENABLED',
      DEFAULT_CONFIG.v1Enabled,
      env,
    ),
    v2AdminSecret: env.DUD_PEER_ADMIN_SECRET,
    v2DeploymentKey: env.DUD_PEER_DEPLOYMENT_KEY,
    v2Enabled: parseBooleanEnv(
      'DUD_PEER_ENABLED',
      DEFAULT_CONFIG.v2Enabled,
      env,
    ),
    v2Secret: env.DUD_PEER_SECRET,
    v2OpenEnrollment: parseBooleanEnv('DUD_PEER_OPEN_ENROLLMENT', false, env),
    v2AcceptWeakEnrollmentKdf: parseBooleanEnv(
      'DUD_PEER_ACCEPT_WEAK_ENROLLMENT_KDF',
      false,
      env,
    ),
    defaultTtlMs,
    maxTtlMs,
    maxUploadBytes: parseIntegerEnv(
      'DUD_MAX_UPLOAD_BYTES',
      DEFAULT_CONFIG.maxUploadBytes,
      env,
    ),
    cleanupBatchSize: parseIntegerEnv(
      'DUD_CLEANUP_BATCH_SIZE',
      DEFAULT_CONFIG.cleanupBatchSize,
      env,
    ),
    flushMaxIterations: parseIntegerEnv(
      'DUD_FLUSH_MAX_ITERATIONS',
      DEFAULT_CONFIG.flushMaxIterations,
      env,
    ),
    v2Limits: {
      maxObjectBytes: parseIntegerEnv(
        'DUD_PEER_MAX_OBJECT_BYTES',
        DEFAULT_CONFIG.v2Limits.maxObjectBytes,
        env,
      ),
      maxDescriptorBytes: parseIntegerEnv(
        'DUD_PEER_MAX_DESCRIPTOR_BYTES',
        DEFAULT_CONFIG.v2Limits.maxDescriptorBytes,
        env,
      ),
      maxTtlSeconds: parseIntegerEnv(
        'DUD_PEER_MAX_TTL_SECONDS',
        DEFAULT_CONFIG.v2Limits.maxTtlSeconds,
        env,
      ),
      maxPendingDeliveries: parseIntegerEnv(
        'DUD_PEER_MAX_PENDING_DELIVERIES',
        DEFAULT_CONFIG.v2Limits.maxPendingDeliveries,
        env,
      ),
      maxObjectsPerCapability: parseIntegerEnv(
        'DUD_PEER_MAX_OBJECTS_PER_CAPABILITY',
        DEFAULT_CONFIG.v2Limits.maxObjectsPerCapability,
        env,
      ),
      maxConcurrentUploads: parseIntegerEnv(
        'DUD_PEER_MAX_CONCURRENT_UPLOADS',
        DEFAULT_CONFIG.v2Limits.maxConcurrentUploads,
        env,
      ),
      maxRequestsPerMinute: parseIntegerEnv(
        'DUD_PEER_MAX_REQUESTS_PER_MINUTE',
        DEFAULT_CONFIG.v2Limits.maxRequestsPerMinute,
        env,
      ),
      maxStagedBytes: parseIntegerEnv(
        'DUD_PEER_MAX_STAGED_BYTES',
        DEFAULT_CONFIG.v2Limits.maxStagedBytes,
        env,
      ),
      maxPairingEnvelopeBytes: parseIntegerEnv(
        'DUD_PEER_MAX_PAIRING_ENVELOPE_BYTES',
        DEFAULT_CONFIG.v2Limits.maxPairingEnvelopeBytes,
        env,
      ),
      maxPairingTtlSeconds: parseIntegerEnv(
        'DUD_PEER_MAX_PAIRING_TTL_SECONDS',
        DEFAULT_CONFIG.v2Limits.maxPairingTtlSeconds,
        env,
      ),
      maxPairingCreatesPerMinute: parseIntegerEnv(
        'DUD_PEER_MAX_PAIRING_CREATES_PER_MINUTE',
        DEFAULT_CONFIG.v2Limits.maxPairingCreatesPerMinute,
        env,
      ),
      maxPendingPairings: parseIntegerEnv(
        'DUD_PEER_MAX_PENDING_PAIRINGS',
        DEFAULT_CONFIG.v2Limits.maxPendingPairings,
        env,
      ),
      maxTotalBytes: parseIntegerEnv(
        'DUD_PEER_MAX_TOTAL_BYTES',
        DEFAULT_CONFIG.v2Limits.maxTotalBytes,
        env,
      ),
    },
  };
}

if (
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1]}`).toString()
) {
  process.umask(0o077);
  startNodeServer(loadNodeServerConfig()).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
