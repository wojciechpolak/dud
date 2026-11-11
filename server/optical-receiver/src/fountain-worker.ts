// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { OpticalFramePipeline } from './pipeline.js';
import {
  MAX_FOUNTAIN_FRAME_BYTES,
  type FountainRequest,
  type FountainResponse,
} from './fountain-messages.js';

let receivedAt = 0;
let processing = false;
let response: Extract<FountainResponse, { type: 'processed' }>;
function issue(
  type: 'session' | 'unsupported' | 'rejected' | 'fatal',
  value: string,
): void {
  if (processing) {
    response.issue = { type, value };
  } else {
    self.postMessage({ type: 'failed', message: value });
  }
}
const pipeline = new OpticalFramePipeline(
  {
    onFrameDisposition: (disposition) => {
      response.disposition = disposition;
    },
    onProgress: (progress) => {
      response.progress = progress;
    },
    onComplete: ({ capsule, ...completion }) => {
      self.postMessage(
        { type: 'complete', completion, capsule: capsule.buffer },
        { transfer: [capsule.buffer] },
      );
    },
    onSessionChange: () => issue('session', ''),
    onUnsupported: (value) => issue('unsupported', value),
    onRejected: (value) => issue('rejected', value),
    onFatal: (value) => issue('fatal', value),
  },
  () => receivedAt,
);

self.onmessage = (event: MessageEvent<FountainRequest>): void => {
  const request = event.data;
  if (
    !Number.isInteger(request.id) ||
    request.id < 0 ||
    !Number.isFinite(request.receivedAt) ||
    request.receivedAt < 0 ||
    !(request.frame instanceof ArrayBuffer) ||
    request.frame.byteLength > MAX_FOUNTAIN_FRAME_BYTES
  ) {
    self.postMessage({
      type: 'failed',
      message: 'Fountain worker received an invalid frame envelope',
    });
    return;
  }
  receivedAt = request.receivedAt;
  response = {
    type: 'processed',
    id: request.id,
    processingMilliseconds: 0,
  };
  const started = performance.now();
  processing = true;
  pipeline.accept(new Uint8Array(request.frame));
  processing = false;
  response.processingMilliseconds = performance.now() - started;
  self.postMessage(response);
};
