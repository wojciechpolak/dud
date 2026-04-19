// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { R2BlobStore } from './cloudflare.js';
import { DEFAULT_CONFIG } from './config.js';
import { createDudService } from './service.js';
import type { Env, ExecutionContextLike } from './types.js';

function buildService(env: Env) {
  const storageConfigured = Boolean(env.FILES);

  return createDudService({
    blobStore: new R2BlobStore(env.FILES!),
    config: {
      version: env.APP_VERSION ?? DEFAULT_CONFIG.version,
      secretToken: env.DUD_SECRET_TOKEN,
      storageConfigured,
    },
  });
}

export function createWorker(env: Env) {
  const service = buildService(env);

  return {
    async fetch(
      request: Request,
      ctx: ExecutionContextLike,
    ): Promise<Response> {
      return service.fetch(request, ctx);
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
