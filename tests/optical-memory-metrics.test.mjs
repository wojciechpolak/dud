// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  chromeProcessTree,
  summarizeMemory,
} from '../server/optical-receiver/memory-metrics.mjs';

test('browser RSS includes descendant processes without another Chrome or the native sender', () => {
  const processes = chromeProcessTree(
    `
    40 1 100 native-sender
    10 1 200 Google Chrome
    30 20 300 Chrome Helper --type=renderer
    20 10 400 Google Chrome Helper
    50 1 500 Google Chrome
    60 10 600 Chrome Helper --type=gpu-process
  `,
    10,
  );
  assert.deepEqual(
    processes.map(({ pid }) => pid),
    [10, 20, 30, 60],
  );
  assert.deepEqual(
    processes.map(({ role }) => role),
    ['browser', 'utility', 'renderer', 'gpu'],
  );
  assert.equal(
    processes.reduce((sum, process) => sum + process.rssBytes, 0),
    1500 * 1024,
  );
  assert.throws(() => chromeProcessTree('10 1 200 Chrome', 50), /absent/);
  assert.throws(
    () => chromeProcessTree('unexpected ps format', 10),
    /ps did not/,
  );
});

test('memory summary keeps absolute RSS, phase peaks, and sampling gaps distinct', () => {
  const samples = [
    {
      offsetMilliseconds: 0,
      phase: 'installed',
      totalRSSBytes: 1000,
      processes: [{ role: 'browser', rssBytes: 1000 }],
    },
    {
      offsetMilliseconds: 200,
      phase: 'receiving',
      totalRSSBytes: 5000,
      processes: [
        { role: 'browser', rssBytes: 1000 },
        { role: 'renderer', rssBytes: 4000 },
      ],
    },
    {
      offsetMilliseconds: 550,
      phase: 'saving',
      totalRSSBytes: 4500,
      processes: [
        { role: 'browser', rssBytes: 1500 },
        { role: 'renderer', rssBytes: 3000 },
      ],
    },
  ];
  assert.deepEqual(summarizeMemory(samples), {
    sampleCount: 3,
    peakRSSBytes: 5000,
    peakOffsetMilliseconds: 200,
    peakPhase: 'receiving',
    peaksByPhase: { installed: 1000, receiving: 5000, saving: 4500 },
    peaksByRole: { browser: 1500, renderer: 4000 },
    maximumGapMilliseconds: 350,
    baselines: {
      installed: {
        sampleCount: 1,
        minimumRSSBytes: 1000,
        medianRSSBytes: 1000,
        maximumRSSBytes: 1000,
      },
      'warm-camera': null,
    },
  });
  assert.throws(() => summarizeMemory([]), /requires/);
  assert.deepEqual(
    summarizeMemory([
      { ...samples[0], totalRSSBytes: 4000 },
      { ...samples[0], offsetMilliseconds: 200, totalRSSBytes: 1000 },
      { ...samples[0], offsetMilliseconds: 400, totalRSSBytes: 3000 },
      { ...samples[0], offsetMilliseconds: 600, totalRSSBytes: 2000 },
    ]).baselines.installed,
    {
      sampleCount: 4,
      minimumRSSBytes: 1000,
      medianRSSBytes: 2500,
      maximumRSSBytes: 4000,
    },
  );
});
