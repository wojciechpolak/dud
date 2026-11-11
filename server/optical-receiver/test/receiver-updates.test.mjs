// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  readReceiverBuild,
  ReceiverUpdates,
} from '../.work/receiver/receiver-updates.js';

const first = 'aaaaaaaaaaaa';
const second = 'bbbbbbbbbbbb';
const scope = 'https://dud.example/optical/';

class Worker extends EventTarget {
  constructor(buildID, state = 'activated') {
    super();
    this.buildID = buildID;
    this.state = state;
  }
  postMessage(message, [port]) {
    assert.deepEqual(message, { type: 'receiver-build' });
    port.postMessage({
      buildID: this.buildID,
      entrypoint: `./index.${this.buildID}.html`,
    });
    port.close();
  }
}

function harness(update = async () => {}) {
  const container = new EventTarget();
  const registration = { scope, active: new Worker(first), update };
  container.register = async (script, options) => {
    assert.equal(script, './sw.js');
    assert.deepEqual(options, { scope: './', updateViaCache: 'none' });
    return registration;
  };
  const offers = [];
  const updates = new ReceiverUpdates(container, first, (build, value) => {
    offers.push({ ...build, scope: value });
  });
  return { container, registration, offers, updates };
}

test('receiver build messages accept only their fingerprinted local entrypoint', async () => {
  assert.deepEqual(await readReceiverBuild(new Worker(first)), {
    buildID: first,
    entrypoint: `./index.${first}.html`,
  });
  await assert.rejects(
    readReceiverBuild({
      postMessage(_message, [port]) {
        port.postMessage({
          buildID: first,
          entrypoint: 'https://other.example/',
        });
        port.close();
      },
    }),
    /invalid/,
  );
  await assert.rejects(
    readReceiverBuild({ postMessage() {} }, 10),
    /timed out/,
  );
});

test('update checks wait for activation and offer the installed build', async () => {
  const value = harness(async () => {
    const worker = new Worker(second, 'installing');
    value.registration.installing = worker;
    setTimeout(() => {
      worker.state = 'activated';
      value.registration.active = worker;
      value.registration.installing = undefined;
      worker.dispatchEvent(new Event('statechange'));
    }, 5);
  });
  await value.updates.install();
  assert.deepEqual(value.offers, []);
  assert.equal((await value.updates.check()).buildID, second);
  assert.deepEqual(value.offers, [
    {
      buildID: second,
      entrypoint: `./index.${second}.html`,
      scope,
    },
  ]);
});

test('a failed initial registration permits an explicit retry', async () => {
  const value = harness();
  const register = value.container.register;
  value.container.register = async () => {
    throw new Error('offline');
  };
  await assert.rejects(value.updates.install(), /offline/);
  value.container.register = register;
  assert.equal((await value.updates.check()).buildID, first);
});

test('an installed worker without build messages can still be updated', async () => {
  const value = harness(async () => {
    value.registration.active = new Worker(second);
  });
  value.registration.active.postMessage = () => {
    assert.fail('the replaced worker must not block the update request');
  };
  assert.equal((await value.updates.check()).buildID, second);
});

test('a failed update retains the installed registration for another check', async () => {
  const value = harness(async () => {
    throw new Error('offline');
  });
  await value.updates.install();
  await assert.rejects(value.updates.check(), /offline/);
  assert.equal(value.registration.active.buildID, first);
  assert.deepEqual(value.offers, []);
  value.registration.update = async () => {};
  assert.equal((await value.updates.check()).buildID, first);
});
