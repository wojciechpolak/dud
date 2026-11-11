// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export interface ScanPoint {
  x: number;
  y: number;
}

export interface TrackedRegion {
  x: number;
  y: number;
  width: number;
  height: number;
}

const MINIMUM_PADDING = 16;
const PADDING_RATIO = 0.16;

export function trackedRegion(
  points: readonly ScanPoint[],
  imageWidth: number,
  imageHeight: number,
): TrackedRegion | undefined {
  if (points.length < 3 || imageWidth < 1 || imageHeight < 1) {
    return undefined;
  }
  const left = Math.min(...points.map((point) => point.x));
  const top = Math.min(...points.map((point) => point.y));
  const right = Math.max(...points.map((point) => point.x));
  const bottom = Math.max(...points.map((point) => point.y));
  if (![left, top, right, bottom].every(Number.isFinite)) {
    return undefined;
  }
  const width = right - left;
  const height = bottom - top;
  if (width < 1 || height < 1) {
    return undefined;
  }
  const padding = Math.max(
    MINIMUM_PADDING,
    Math.ceil(Math.max(width, height) * PADDING_RATIO),
  );
  const x = Math.max(0, Math.floor(left - padding));
  const y = Math.max(0, Math.floor(top - padding));
  const boundedRight = Math.min(imageWidth, Math.ceil(right + padding));
  const boundedBottom = Math.min(imageHeight, Math.ceil(bottom + padding));
  return {
    x,
    y,
    width: boundedRight - x,
    height: boundedBottom - y,
  };
}

export function translatedPoints(
  points: readonly ScanPoint[],
  region: TrackedRegion,
): ScanPoint[] {
  return points.map((point) => ({
    x: point.x + region.x,
    y: point.y + region.y,
  }));
}

function quadrant(
  region: TrackedRegion,
  imageWidth: number,
  imageHeight: number,
): number {
  const centerX = region.x + region.width / 2;
  const centerY = region.y + region.height / 2;
  return (
    (centerY < imageHeight / 2 ? 0 : 2) + (centerX < imageWidth / 2 ? 0 : 1)
  );
}

function validRegion(
  region: TrackedRegion,
  imageWidth: number,
  imageHeight: number,
): boolean {
  return (
    Number.isFinite(region.x) &&
    Number.isFinite(region.y) &&
    Number.isFinite(region.width) &&
    Number.isFinite(region.height) &&
    region.x >= 0 &&
    region.y >= 0 &&
    region.width > 0 &&
    region.height > 0 &&
    region.x + region.width <= imageWidth &&
    region.y + region.height <= imageHeight
  );
}

export function mergeTrackedRegions(
  previous: readonly TrackedRegion[],
  observed: readonly TrackedRegion[],
  imageWidth: number,
  imageHeight: number,
): TrackedRegion[] {
  if (imageWidth < 1 || imageHeight < 1) {
    return [];
  }
  const byQuadrant = new Map<number, TrackedRegion>();
  for (const region of [...previous, ...observed]) {
    if (validRegion(region, imageWidth, imageHeight)) {
      byQuadrant.set(quadrant(region, imageWidth, imageHeight), region);
    }
  }
  return [0, 1, 2, 3]
    .map((index) => byQuadrant.get(index))
    .filter((region): region is TrackedRegion => region !== undefined);
}
