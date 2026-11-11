// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export interface ReceiverBuild {
  buildID: string;
  entrypoint: string;
}

export function readReceiverBuild(
  worker: ServiceWorker,
  timeoutMilliseconds = 2000,
): Promise<ReceiverBuild> {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const cleanup = (): void => {
      clearTimeout(timeout);
      channel.port1.close();
      channel.port2.close();
    };
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Receiver build response timed out'));
    }, timeoutMilliseconds);
    channel.port1.onmessage = (event: MessageEvent<ReceiverBuild>) => {
      cleanup();
      const value = event.data;
      if (
        !value ||
        typeof value.buildID !== 'string' ||
        !/^[a-f0-9]{12}$/.test(value.buildID) ||
        value.entrypoint !== `./index.${value.buildID}.html`
      ) {
        reject(new Error('Receiver build response is invalid'));
        return;
      }
      resolve({ buildID: value.buildID, entrypoint: value.entrypoint });
    };
    try {
      worker.postMessage({ type: 'receiver-build' }, [channel.port2]);
    } catch (error) {
      cleanup();
      reject(error);
    }
  });
}

function activated(worker: ServiceWorker): Promise<void> {
  return new Promise((resolve, reject) => {
    const finish = (): void => {
      if (worker.state !== 'activated' && worker.state !== 'redundant') {
        return;
      }
      cleanup();
      if (worker.state === 'activated') {
        resolve();
      } else {
        reject(new Error('Receiver update installation failed'));
      }
    };
    const cleanup = (): void => {
      clearTimeout(timeout);
      worker.removeEventListener('statechange', finish);
    };
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Receiver update activation timed out'));
    }, 15_000);
    worker.addEventListener('statechange', finish);
    finish();
  });
}

// Build metadata travels through a local message port. Installation and explicit
// update checks run with capture disabled; receipt needs no host connection.
export class ReceiverUpdates {
  private registration: Promise<ServiceWorkerRegistration> | undefined;

  constructor(
    private readonly container: ServiceWorkerContainer,
    private readonly pageBuildID: string,
    private readonly onAvailable: (build: ReceiverBuild, scope: string) => void,
  ) {
    container.addEventListener('controllerchange', () => {
      void this.inspect().catch(() => {});
    });
  }

  async install(): Promise<void> {
    await this.ensureRegistration();
    await this.inspect();
  }

  private async ensureRegistration(): Promise<ServiceWorkerRegistration> {
    this.registration ??= this.container
      .register('./sw.js', { scope: './', updateViaCache: 'none' })
      .then(async (registration) => {
        const worker = registration.installing ?? registration.waiting;
        if (worker) {
          await activated(worker);
        }
        return registration;
      })
      .catch((error: unknown) => {
        this.registration = undefined;
        throw error;
      });
    return this.registration;
  }

  async check(): Promise<ReceiverBuild> {
    const registration = await this.ensureRegistration();
    await registration.update();
    const worker = registration.installing ?? registration.waiting;
    if (worker) {
      await activated(worker);
    }
    return this.inspect();
  }

  private async inspect(): Promise<ReceiverBuild> {
    const registration = await this.registration;
    const worker = registration?.active ?? this.container.controller;
    if (!registration || !worker) {
      throw new Error('Receiver service worker is unavailable');
    }
    const build = await readReceiverBuild(worker);
    if (build.buildID !== this.pageBuildID) {
      this.onAvailable(build, registration.scope);
    }
    return build;
  }
}
