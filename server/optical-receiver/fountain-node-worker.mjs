// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { readFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';

// Run the shipped browser bundle through real message ports and transfer lists.
// This adapter is confined to local tests and Node profiling.
export function createFountainNodeWorker() {
  const directory = new URL('./.work/pwa/', import.meta.url);
  const manifest = JSON.parse(
    readFileSync(new URL('build-manifest.json', directory)),
  );
  const asset = manifest.assets.find((a) =>
    a.path.startsWith('fountain-worker.'),
  );
  const worker = new Worker(
    `
    const {parentPort,workerData}=require('node:worker_threads');
    global.self={postMessage(message,options){parentPort.postMessage(message,options?.transfer);}};
    import(workerData).then(()=>parentPort.on('message',data=>self.onmessage({data})));
  `,
    { eval: true, workerData: new URL(asset.path, directory).href },
  );
  return {
    addEventListener(type, callback) {
      worker.on(type, (value) =>
        callback(type === 'message' ? { data: value } : value),
      );
    },
    postMessage(message, transfer) {
      worker.postMessage(message, transfer);
    },
    terminate() {
      void worker.terminate();
    },
  };
}
