// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export function chromeProcessTree(output, rootPID) {
  const processes = output
    .trim()
    .split('\n')
    .map((line) => {
      const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/.exec(line);
      if (!match) {
        throw new Error('ps did not return PID, parent PID, RSS, and command');
      }
      const [, pid, parentPID, rssKiB, command] = match;
      return {
        pid: Number(pid),
        parentPID: Number(parentPID),
        rssBytes: Number(rssKiB) * 1024,
        role:
          Number(pid) === rootPID
            ? 'browser'
            : command.includes('(Renderer)') ||
                command.includes('--type=renderer')
              ? 'renderer'
              : command.includes('(GPU)') ||
                  command.includes('--type=gpu-process')
                ? 'gpu'
                : 'utility',
      };
    });
  if (!processes.some((process) => process.pid === rootPID)) {
    throw new Error('the isolated Chrome process is absent from ps');
  }
  const descendants = new Set([rootPID]);
  let added;
  do {
    added = false;
    for (const process of processes) {
      if (descendants.has(process.parentPID) && !descendants.has(process.pid)) {
        descendants.add(process.pid);
        added = true;
      }
    }
  } while (added);
  return processes
    .filter((process) => descendants.has(process.pid))
    .sort((a, b) => a.pid - b.pid);
}

export function summarizeMemory(samples) {
  if (samples.length === 0) {
    throw new Error('a memory report requires process samples');
  }
  const peaksByPhase = {};
  const peaksByRole = {};
  let peak = samples[0];
  let maximumGapMilliseconds = 0;
  for (let index = 0; index < samples.length; index++) {
    const sample = samples[index];
    if (sample.totalRSSBytes > peak.totalRSSBytes) {
      peak = sample;
    }
    peaksByPhase[sample.phase] = Math.max(
      peaksByPhase[sample.phase] ?? 0,
      sample.totalRSSBytes,
    );
    const totals = {};
    for (const process of sample.processes) {
      totals[process.role] = (totals[process.role] ?? 0) + process.rssBytes;
    }
    for (const [role, total] of Object.entries(totals)) {
      peaksByRole[role] = Math.max(peaksByRole[role] ?? 0, total);
    }
    if (index > 0) {
      maximumGapMilliseconds = Math.max(
        maximumGapMilliseconds,
        sample.offsetMilliseconds - samples[index - 1].offsetMilliseconds,
      );
    }
  }
  return {
    sampleCount: samples.length,
    peakRSSBytes: peak.totalRSSBytes,
    peakOffsetMilliseconds: peak.offsetMilliseconds,
    peakPhase: peak.phase,
    peaksByPhase,
    peaksByRole,
    maximumGapMilliseconds,
    baselines: Object.fromEntries(
      ['installed', 'warm-camera'].map((phase) => {
        const values = samples
          .filter((sample) => sample.phase === phase)
          .map((sample) => sample.totalRSSBytes)
          .sort((a, b) => a - b);
        return [
          phase,
          values.length
            ? {
                sampleCount: values.length,
                minimumRSSBytes: values[0],
                medianRSSBytes:
                  (values[Math.floor((values.length - 1) / 2)] +
                    values[Math.floor(values.length / 2)]) /
                  2,
                maximumRSSBytes: values.at(-1),
              }
            : null,
        ];
      }),
    ),
  };
}
