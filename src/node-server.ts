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

export interface NodeServerConfig extends Partial<DudConfig> {
  dataDir: string;
  listenHost?: string;
  listenPort?: number;
  logMode?: 'normal' | 'minimal' | 'silent';
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

function logAccess(
  config: NodeServerConfig,
  logger: NodeServerOptions['logger'],
  req: any,
  request: Request,
  response: Response,
  startedAtMs: number,
): void {
  if (config.logMode === 'silent') {
    return;
  }

  const durationMs = Date.now() - startedAtMs;
  const url = new URL(request.url);
  const prefix = config.logMode === 'minimal' ? '' : `${clientAddress(req)} `;
  logger?.log?.(
    `${prefix}${request.method} ${url.pathname} -> ${response.status} ${durationMs}ms`,
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

  if (forwardedProto && forwardedHost) {
    return `${forwardedProto}://${forwardedHost}${requestPath}`;
  }

  if (config.publicBaseUrl) {
    return new URL(requestPath, config.publicBaseUrl).toString();
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

export function createNodeRequestHandler(
  config: NodeServerConfig,
  options: NodeServerOptions = {},
): (req: unknown, res: unknown) => Promise<void> {
  const blobStore =
    options.blobStore ?? new FilesystemBlobStore(config.dataDir);
  const service = createDudService({
    blobStore,
    config: buildServiceConfig(config),
    now: options.now,
    createId: options.createId,
  });
  const logger = options.logger ?? console;
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

      const response = await service.fetch(request, createContext(logger));
      logAccess(config, logger, req, request, response, startedAtMs);
      await sendResponse(res, response);
    } catch (error) {
      logger.error('Node server request failed:', error);
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
  const handler = createNodeRequestHandler(config, options);
  const logger = options.logger ?? console;

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

  const address = server.address();
  const actualPort =
    typeof address === 'object' && address ? Number(address.port) : port;
  const origin = `${config.tlsCertFile && config.tlsKeyFile ? 'https' : 'http'}://${host}:${actualPort}`;
  if (config.logMode !== 'silent') {
    logger.log(`DUD node server listening on ${origin}`);
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
    publicBaseUrl: env.DUD_PUBLIC_BASE_URL,
    tlsCertFile: env.DUD_TLS_CERT_FILE,
    tlsKeyFile: env.DUD_TLS_KEY_FILE,
    serviceName: env.DUD_SERVICE_NAME || DEFAULT_CONFIG.serviceName,
    version: env.APP_VERSION || DEFAULT_CONFIG.version,
    secretToken: env.DUD_SECRET_TOKEN,
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
  };
}

if (
  process.argv[1] &&
  import.meta.url === new URL(`file://${process.argv[1]}`).toString()
) {
  startNodeServer(loadNodeServerConfig()).catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
