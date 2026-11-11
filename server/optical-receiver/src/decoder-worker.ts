// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { QRScanMode } from './capture-profile.js';
import { scanQRImage, type QRImageSymbol } from './qr-image.js';
import { scanRegion } from './scan-region.js';
import type { QRScanDiagnostics } from './worker-pool.js';
import {
  mergeTrackedRegions,
  trackedRegion,
  type TrackedRegion,
  translatedPoints,
} from './tracked-regions.js';

interface DecodeMessage {
  type: 'warmup' | 'decode';
  bitmap?: ImageBitmap;
  scanMode?: QRScanMode;
}

const TRACK_REFRESH_INTERVAL = 15;
let trackedRegions: TrackedRegion[] = [];
let decodedImages = 0;

async function warmup(): Promise<void> {
  self.postMessage({ type: 'ready' });
}

function scanImageData(
  image: ImageData,
  diagnostics: QRScanDiagnostics,
  maximumSymbols = 4,
): QRImageSymbol[] {
  const result = scanQRImage(
    image.data,
    image.width,
    image.height,
    maximumSymbols,
  );
  diagnostics.finderChecks += result.work.finderChecks;
  diagnostics.finderCandidates += result.work.candidates;
  diagnostics.alignmentChecks += result.work.alignmentChecks;
  diagnostics.matrixAttempts += result.work.matrixAttempts;
  diagnostics.exhaustedScans += Number(result.exhausted);
  return result.symbols;
}

function frameKey(symbol: QRImageSymbol): string {
  const data = new Uint8Array(symbol.data);
  return `${data.byteLength}:${Array.from(data.subarray(0, 56)).join(',')}`;
}

function uniqueSymbols(symbols: QRImageSymbol[]): QRImageSymbol[] {
  const unique = new Map<string, QRImageSymbol>();
  for (const symbol of symbols) {
    unique.set(frameKey(symbol), symbol);
  }
  return [...unique.values()];
}

function regionsForSymbols(
  symbols: QRImageSymbol[],
  width: number,
  height: number,
): TrackedRegion[] {
  const regions = symbols
    .map((symbol) => trackedRegion(symbol.points, width, height))
    .filter((region): region is TrackedRegion => region !== undefined);
  return mergeTrackedRegions([], regions, width, height);
}

async function scanTrackedRegions(
  context: OffscreenCanvasRenderingContext2D,
  diagnostics: QRScanDiagnostics,
): Promise<QRImageSymbol[]> {
  const symbols: QRImageSymbol[] = [];
  const nextRegions = [...trackedRegions];
  for (const [index, region] of trackedRegions.entries()) {
    const found = scanImageData(
      context.getImageData(region.x, region.y, region.width, region.height),
      diagnostics,
      1,
    );
    symbols.push(...found);
    const replacement = found
      .map((symbol) =>
        trackedRegion(
          translatedPoints(symbol.points, region),
          context.canvas.width,
          context.canvas.height,
        ),
      )
      .find((candidate) => candidate !== undefined);
    if (replacement) {
      nextRegions[index] = replacement;
    }
  }
  trackedRegions = nextRegions;
  return uniqueSymbols(symbols);
}

async function decode(
  bitmap: ImageBitmap,
  scanMode: QRScanMode,
): Promise<void> {
  const started = performance.now();
  try {
    const region = scanRegion(bitmap.width, bitmap.height);
    const canvas = new OffscreenCanvas(region.scanSize, region.scanSize);
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) {
      throw new Error('2D canvas is unavailable');
    }
    context.drawImage(
      bitmap,
      region.sourceX,
      region.sourceY,
      region.sourceSize,
      region.sourceSize,
      0,
      0,
      region.scanSize,
      region.scanSize,
    );
    decodedImages++;
    const refreshTracking =
      trackedRegions.length !== 4 ||
      decodedImages % TRACK_REFRESH_INTERVAL === 1;
    let fullScans = 0;
    let trackedScans = 0;
    const scanDiagnostics: QRScanDiagnostics = {
      finderChecks: 0,
      finderCandidates: 0,
      alignmentChecks: 0,
      matrixAttempts: 0,
      exhaustedScans: 0,
    };
    let symbols: QRImageSymbol[];
    if (scanMode === 'tracked-four' && !refreshTracking) {
      symbols = await scanTrackedRegions(context, scanDiagnostics);
      trackedScans = trackedRegions.length;
    } else {
      symbols = scanImageData(
        context.getImageData(0, 0, region.scanSize, region.scanSize),
        scanDiagnostics,
      );
      fullScans = 1;
      if (scanMode === 'tracked-four') {
        trackedRegions = mergeTrackedRegions(
          trackedRegions,
          regionsForSymbols(symbols, region.scanSize, region.scanSize),
          region.scanSize,
          region.scanSize,
        );
      }
    }
    const frames = uniqueSymbols(symbols).map(
      (symbol) => new Uint8Array(symbol.data).buffer,
    );
    self.postMessage(
      {
        type: 'result',
        frames,
        decodeMilliseconds: performance.now() - started,
        scanDimension: region.scanSize,
        fullScans,
        trackedScans,
        trackedSymbols: trackedScans === 0 ? 0 : frames.length,
        scanDiagnostics,
      },
      { transfer: frames },
    );
  } finally {
    bitmap.close();
  }
}

self.addEventListener('message', (event: MessageEvent<DecodeMessage>) => {
  if (event.data.type === 'warmup') {
    warmup().catch(() => {
      self.postMessage({
        type: 'error',
        message: 'QR initialization failed',
      });
    });
    return;
  }
  if (!event.data.bitmap) {
    self.postMessage({ type: 'error', message: 'Decoder received no image' });
    return;
  }
  decode(event.data.bitmap, event.data.scanMode ?? 'full-frame').catch(() => {
    self.postMessage({
      type: 'error',
      message: 'QR decode failed',
    });
  });
});
