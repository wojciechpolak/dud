// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { DudConfig } from './types.js';

export const DEFAULT_CONFIG: DudConfig = {
  serviceName: 'dud',
  version: '1.0.0',
  defaultTtlMs: 24 * 60 * 60 * 1000,
  maxTtlMs: 30 * 24 * 60 * 60 * 1000,
  maxUploadBytes: 100 * 1024 * 1024,
  cleanupBatchSize: 100,
  flushMaxIterations: 20,
  storageConfigured: true,
};
