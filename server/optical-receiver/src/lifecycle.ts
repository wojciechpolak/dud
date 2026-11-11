// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export interface StoppableTrack {
  stop(): void;
}

export interface TerminableWorker {
  terminate(): void;
}

export interface ObservableResource {
  addEventListener(type: string, listener: EventListener): void;
  removeEventListener(type: string, listener: EventListener): void;
}

// CaptureLifecycle owns every resource that can outlive one receiver run.
export class CaptureLifecycle {
  private readonly tracks = new Set<StoppableTrack>();
  private readonly workers = new Set<TerminableWorker>();
  private readonly cleanups = new Set<() => void>();

  addTrack(track: StoppableTrack): void {
    this.tracks.add(track);
  }

  addWorker(worker: TerminableWorker): void {
    this.workers.add(worker);
  }

  addCleanup(cleanup: () => void): void {
    this.cleanups.add(cleanup);
  }

  watch(
    source: ObservableResource,
    type: string,
    listener: EventListener,
  ): void {
    source.addEventListener(type, listener);
    this.addCleanup(() => source.removeEventListener(type, listener));
  }

  stop(): void {
    const tracks = [...this.tracks];
    const workers = [...this.workers];
    const cleanups = [...this.cleanups];
    this.tracks.clear();
    this.workers.clear();
    this.cleanups.clear();
    for (const release of [
      ...cleanups,
      ...tracks.map((track) => () => track.stop()),
      ...workers.map((worker) => () => worker.terminate()),
    ]) {
      try {
        release();
      } catch {
        // Every remaining resource still needs its release attempt.
      }
    }
  }
}
