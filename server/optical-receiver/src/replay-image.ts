// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { scanRegion } from './scan-region.js';

const PNG_HEADER_BYTES = 24;
const PNG_SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];
const IHDR_TYPE = [73, 72, 68, 82];

export const MAX_REPLAY_PNG_BYTES = 64 * 1024 * 1024;
// A four-symbol version-40 sender frame at quiet-zone 16 and scale 16 is
// 2 * (177 + 2 * 16) * 16 pixels on each side.
export const MAX_REPLAY_IMAGE_SIDE = 6688;
export const MAX_REPLAY_IMAGE_PIXELS =
  MAX_REPLAY_IMAGE_SIDE * MAX_REPLAY_IMAGE_SIDE;

type ReplayBitmapDecoder = (
  source: Blob,
  sourceX: number,
  sourceY: number,
  sourceWidth: number,
  sourceHeight: number,
  options: ImageBitmapOptions,
) => Promise<ImageBitmap>;

export function validateReplayPNGHeader(
  header: Uint8Array,
  encodedBytes: number,
): { width: number; height: number } {
  if (
    !Number.isSafeInteger(encodedBytes) ||
    encodedBytes < PNG_HEADER_BYTES ||
    encodedBytes > MAX_REPLAY_PNG_BYTES
  ) {
    throw new RangeError('Recorded PNG exceeds its encoded byte limit.');
  }
  if (
    header.length < PNG_HEADER_BYTES ||
    !PNG_SIGNATURE.every((value, index) => header[index] === value)
  ) {
    throw new Error('Recorded frame is not a PNG.');
  }
  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength,
  );
  if (
    view.getUint32(8) !== 13 ||
    !IHDR_TYPE.every((value, index) => header[12 + index] === value)
  ) {
    throw new Error('Recorded PNG does not begin with IHDR.');
  }
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (width === 0 || height === 0) {
    throw new RangeError('Recorded PNG dimensions must be positive.');
  }
  if (
    width > MAX_REPLAY_IMAGE_SIDE ||
    height > MAX_REPLAY_IMAGE_SIDE ||
    width > Math.floor(MAX_REPLAY_IMAGE_PIXELS / height)
  ) {
    throw new RangeError('Recorded PNG exceeds its decoded pixel limit.');
  }
  return { width, height };
}

export async function decodeReplayPNG(
  file: Blob,
  decode: ReplayBitmapDecoder = (source, x, y, width, height, options) =>
    createImageBitmap(source, x, y, width, height, options),
): Promise<ImageBitmap> {
  if (file.size > MAX_REPLAY_PNG_BYTES) {
    throw new RangeError('Recorded PNG exceeds its encoded byte limit.');
  }
  const header = new Uint8Array(
    await file.slice(0, PNG_HEADER_BYTES).arrayBuffer(),
  );
  const dimensions = validateReplayPNGHeader(header, file.size);
  const region = scanRegion(dimensions.width, dimensions.height);
  const bitmap = await decode(
    file,
    region.sourceX,
    region.sourceY,
    region.sourceSize,
    region.sourceSize,
    {
      resizeWidth: region.scanSize,
      resizeHeight: region.scanSize,
      resizeQuality: 'low',
    },
  );
  if (
    bitmap.width < 1 ||
    bitmap.height < 1 ||
    bitmap.width > region.scanSize ||
    bitmap.height > region.scanSize
  ) {
    bitmap.close();
    throw new RangeError('Recorded PNG decoder exceeded its pixel limit.');
  }
  return bitmap;
}
