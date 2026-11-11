// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { type CaptureLifecycle, type ObservableResource } from './lifecycle.js';

export type CaptureInterruption =
  | 'background'
  | 'camera-change'
  | 'camera-ended'
  | 'camera-muted'
  | 'memory-pressure'
  | 'page-exit'
  | 'renderer-loss'
  | 'rotation'
  | 'service-worker-change'
  | 'suspension';

interface VisibilityResource extends ObservableResource {
  readonly visibilityState: string;
}

interface ServiceWorkerResource extends ObservableResource {
  readonly controller: object | null;
}

interface CaptureTrack extends ObservableResource {
  readonly readyState: string;
}

export interface CaptureInterruptionSources {
  page: ObservableResource;
  document: VisibilityResource;
  orientation?: ObservableResource;
  mediaDevices?: ObservableResource;
  serviceWorker?: ServiceWorkerResource;
}

export function watchCaptureInterruptions(
  lifecycle: CaptureLifecycle,
  sources: CaptureInterruptionSources,
  onInterrupt: (reason: CaptureInterruption) => void,
): (tracks: readonly CaptureTrack[]) => void {
  let interrupted = false;
  let activeTracks: readonly CaptureTrack[] = [];
  const interrupt = (reason: CaptureInterruption): void => {
    if (interrupted) {
      return;
    }
    interrupted = true;
    onInterrupt(reason);
  };
  const watch = (
    source: ObservableResource | undefined,
    type: string,
    reason: CaptureInterruption,
  ): void => {
    if (source) {
      lifecycle.watch(source, type, () => interrupt(reason));
    }
  };

  lifecycle.watch(sources.document, 'visibilitychange', () => {
    if (sources.document.visibilityState !== 'visible') {
      interrupt('background');
    }
  });
  watch(sources.page, 'freeze', 'suspension');
  watch(sources.page, 'pagehide', 'page-exit');
  watch(sources.page, 'error', 'renderer-loss');
  watch(sources.page, 'unhandledrejection', 'renderer-loss');
  watch(sources.page, 'memorypressure', 'memory-pressure');
  watch(sources.orientation, 'change', 'rotation');
  if (sources.mediaDevices) {
    lifecycle.watch(sources.mediaDevices, 'devicechange', () => {
      if (activeTracks.some((track) => track.readyState !== 'live')) {
        interrupt('camera-change');
      }
    });
  }
  if (sources.serviceWorker) {
    const serviceWorker = sources.serviceWorker;
    let controller = serviceWorker.controller;
    lifecycle.watch(serviceWorker, 'controllerchange', () => {
      const next = serviceWorker.controller;
      // The first claim controls an already loaded page without replacing its code.
      if (controller !== null && controller !== next) {
        interrupt('service-worker-change');
      }
      controller = next;
    });
  }
  return (tracks) => {
    activeTracks = tracks;
    for (const track of tracks) {
      watch(track, 'ended', 'camera-ended');
      watch(track, 'mute', 'camera-muted');
    }
  };
}
