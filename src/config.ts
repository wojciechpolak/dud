// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { DudConfig } from './types.js';

export const DEFAULT_CONFIG: DudConfig = {
  serviceName: 'dud',
  version: '2.1.0',
  defaultTtlMs: 24 * 60 * 60 * 1000,
  maxTtlMs: 30 * 24 * 60 * 60 * 1000,
  maxUploadBytes: 100 * 1024 * 1024,
  cleanupBatchSize: 100,
  flushMaxIterations: 20,
  storageNotConfiguredMessage: 'Storage is not configured.',
  storageConfigured: true,
  v1Enabled: true,
  v2Enabled: false,
  v2Limits: {
    maxObjectBytes: 100 * 1024 * 1024,
    maxDescriptorBytes: 256 * 1024,
    maxTtlSeconds: 30 * 24 * 60 * 60,
    maxPendingDeliveries: 64,
    maxObjectsPerCapability: 256,
    maxConcurrentUploads: 4,
    maxRequestsPerMinute: 60,
    maxStagedBytes: 200 * 1024 * 1024,
    maxPairingEnvelopeBytes: 4096,
    maxPairingTtlSeconds: 60 * 60,
    maxPairingCreatesPerMinute: 10,
    maxPendingPairings: 256,
    maxTotalBytes: 10 * 1024 * 1024 * 1024,
  },
};
