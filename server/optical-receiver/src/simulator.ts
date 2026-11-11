// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export interface LossPlan {
  removeEvery?: number;
  burstStart?: number;
  burstLength?: number;
  duplicateEvery?: number;
  truncateEvery?: number;
  corruptEvery?: number;
  reorderWindow?: number;
}

function selected(index: number, every: number | undefined): boolean {
  return every !== undefined && every > 0 && (index + 1) % every === 0;
}

function inBurst(index: number, plan: LossPlan): boolean {
  return (
    plan.burstStart !== undefined &&
    plan.burstLength !== undefined &&
    index >= plan.burstStart &&
    index < plan.burstStart + plan.burstLength
  );
}

function copyWithLoss(
  frame: Uint8Array,
  index: number,
  plan: LossPlan,
): Uint8Array {
  let copy = new Uint8Array(frame);
  if (selected(index, plan.truncateEvery)) {
    copy = copy.subarray(0, copy.length - 1);
  }
  if (selected(index, plan.corruptEvery) && copy.length > 100) {
    copy[100] ^= 0x80;
  }
  return copy;
}

function reorderWindows(output: Uint8Array[], window: number): void {
  if (window <= 1) {
    return;
  }
  for (let start = 0; start < output.length; start += window) {
    output.splice(
      start,
      window,
      ...output.slice(start, start + window).reverse(),
    );
  }
}

// SimulateLoss applies deterministic camera failures to a frame stream. It
// copies every retained frame so tests cannot mutate encoder-owned data.
export function simulateLoss(
  frames: readonly Uint8Array[],
  plan: LossPlan,
): Uint8Array[] {
  const output: Uint8Array[] = [];
  for (let index = 0; index < frames.length; index++) {
    if (selected(index, plan.removeEvery)) {
      continue;
    }
    if (inBurst(index, plan)) {
      continue;
    }
    const frame = copyWithLoss(frames[index], index, plan);
    output.push(frame);
    if (selected(index, plan.duplicateEvery)) {
      output.push(new Uint8Array(frame));
    }
  }
  reorderWindows(output, plan.reorderWindow ?? 1);
  return output;
}
