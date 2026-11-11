// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runIsolatedMemory } from '../server/optical-receiver/bench-isolated-memory.mjs';
import {
  chromeExecutable,
  ffmpegExecutable,
  renderFakeCameraVideo,
  deterministicCapsule,
  startOpticalServer,
  startOfflineProxy,
  DevToolsClient,
  evaluate,
  waitForPage,
  waitForTrafficToSettle,
  launchChrome,
  stopChrome,
  closeServer,
  receiveFromFakeCamera,
  saveCapsule,
  capsuleFilename,
} from '../server/optical-receiver/browser-runtime.mjs';

const repository = path.resolve(import.meta.dirname, '..');
const quote = (value) => `'${value.replaceAll("'", "'\"'\"'")}'`;

test(
  'native optical transfer commands recover production browser ciphertext for every input and encryption choice',
  { timeout: 300_000 },
  async (t) => {
    const chrome = chromeExecutable();
    const ffmpeg = ffmpegExecutable();
    if (!chrome || !ffmpeg) {
      t.skip('Chrome and ffmpeg are required for synthetic camera receipt');
      return;
    }
    try {
      execFileSync('age-keygen', ['-h'], { stdio: 'pipe' });
    } catch {
      t.skip('age-keygen is required for native recipient fixtures');
      return;
    }
    const root = mkdtempSync(path.join(tmpdir(), 'dud-native-browser-'));
    t.after(() =>
      rmSync(root, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 100,
      }),
    );
    const dud = path.join(root, 'dud');
    const testAge = path.join(root, 'age-test');
    const age = path.join(root, 'age');
    const helper = path.join(root, 'dud-optical-window');
    const buildOptions = {
      cwd: path.join(repository, 'client'),
      env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
      stdio: 'pipe',
    };
    execFileSync(
      'go',
      ['build', '-tags', 'nativewindow', '-o', dud, './cmd/dud'],
      buildOptions,
    );
    execFileSync(
      'go',
      ['test', '-c', '-o', testAge, './cmd/dud'],
      buildOptions,
    );
    writeFileSync(
      age,
      `#!/bin/sh\nexec ${quote(testAge)} -test.run=^TestOpticalAgeProcess$ -- "$@"\n`,
      { mode: 0o700 },
    );
    writeFileSync(
      helper,
      '#!/bin/sh\nprintf "DUD-OPTICAL-WINDOW-READY-1\\n"\nread ciphertext || exit 1\ncp "$ciphertext" "$OPTICAL_CAPTURE"\n',
      { mode: 0o700 },
    );
    const identities = [];
    for (const flags of [[], ['-pq'], []]) {
      const identity = path.join(root, `identity-${identities.length}.txt`);
      execFileSync('age-keygen', [...flags, '-o', identity], { stdio: 'pipe' });
      const recipient = execFileSync('age-keygen', ['-y', identity], {
        encoding: 'utf8',
      }).trim();
      identities.push({ identity, recipient });
    }
    const recipients = path.join(root, 'recipients.txt');
    writeFileSync(recipients, `${identities[0].recipient}\n`);
    const choices = [
      { name: 'passphrase', flags: ['--passphrase'] },
      {
        name: 'X25519',
        flags: ['-r', identities[0].recipient],
        identity: identities[0].identity,
      },
      {
        name: 'hybrid',
        flags: ['-r', identities[1].recipient],
        identity: identities[1].identity,
      },
      {
        name: 'recipient-file',
        flags: ['-R', recipients],
        identity: identities[0].identity,
      },
      {
        name: 'repeated-recipients',
        flags: ['-r', identities[0].recipient, '-r', identities[2].recipient],
        identity: identities[2].identity,
      },
    ];
    const message = Buffer.from('Native optical dead drop zażółć\n');
    const payload = deterministicCapsule(2401);
    const source = path.join(root, 'source.bin');
    writeFileSync(source, payload);
    const collection = path.join(root, 'private-directory');
    mkdirSync(collection);
    writeFileSync(path.join(collection, 'one.bin'), payload);
    writeFileSync(path.join(collection, 'two.txt'), message);
    const inputs = [
      { name: 'message', flags: ['-m', message.toString()], expected: message },
      { name: 'stdin', flags: [], input: payload, expected: payload },
      { name: 'file', flags: ['--file', source], expected: payload },
      { name: 'collection', flags: ['--file', collection] },
    ];
    function command(args, work, input) {
      const env = {
        ...process.env,
        TMPDIR: work,
        DISPLAY: ':0',
        DUD_AGE_BIN: age,
        DUD_TEST_OPTICAL_AGE_PROCESS: '1',
        OPTICAL_CAPTURE: path.join(work, 'sender.age'),
        DUD_DROP_SECRET: '',
        DUD_DROP_BASE_URL: 'invalid origin',
        DUD_DOH_URL: 'invalid resolver',
        DUD_ECH_MODE: 'invalid mode',
        DUD_CA_BUNDLE: '/missing',
      };
      const result = execFileSync(dud, args, {
        env,
        input,
        encoding: 'utf8',
        timeout: 30000,
      });
      assert.deepEqual(
        readdirSync(work).filter((name) =>
          /^dud-(?:optical-|upload-recipients-)/.test(name),
        ),
        [],
      );
      return JSON.parse(result);
    }
    for (const choice of choices) {
      for (const input of inputs) {
        await t.test(
          `${input.name} with ${choice.name} survives synthetic camera receipt and native recovery`,
          async () => {
            const work = path.join(root, `${choice.name}-${input.name}`);
            mkdirSync(work);
            const sender = command(
              [
                'upload',
                '--optical',
                '--json',
                '--optical-profile',
                'balanced',
                ...input.flags,
                ...choice.flags,
              ],
              work,
              input.input,
            );
            const ciphertext = readFileSync(path.join(work, 'sender.age'));
            assert.equal(sender.ciphertextBytes, ciphertext.length);
            assert.equal(sender.mode, 'optical');
            assert.equal(sender.format, 'dud/optical/1');
            assert.equal(Object.hasOwn(sender, 'carrier'), false);
            const { video } = renderFakeCameraVideo(work, ffmpeg, ciphertext);
            const downloads = path.join(work, 'downloads');
            mkdirSync(downloads);
            const hosted = await startOpticalServer(work);
            const proxy = await startOfflineProxy(hosted.origin);
            let launched, browser, page;
            try {
              launched = await launchChrome(
                chrome,
                path.join(work, 'chrome'),
                video,
                true,
                proxy.origin,
              );
              browser = await DevToolsClient.connect(launched.browserURL);
              await browser.send('Browser.setDownloadBehavior', {
                behavior: 'allow',
                downloadPath: downloads,
              });
              const target = await fetch(
                `${launched.debugOrigin}/json/new?about:blank`,
                { method: 'PUT' },
              ).then((r) => r.json());
              page = await DevToolsClient.connect(target.webSocketDebuggerUrl);
              await page.send('Runtime.enable');
              await page.send('Network.enable');
              await page.send('Page.navigate', {
                url: `${hosted.origin}/optical/`,
              });
              await waitForPage(page);
              await waitForTrafficToSettle(hosted.traffic);
              proxy.disconnect();
              hosted.traffic.length = 0;
              assert.equal(
                await evaluate(
                  page,
                  `(async () => {
                    const registration = await navigator.serviceWorker.getRegistration();
                    if (!registration) throw new Error('Receiver is not installed');
                    try {
                      await registration.update();
                      return false;
                    } catch {
                      return true;
                    }
                  })()`,
                  true,
                ),
                true,
                'service worker updates must fail while the host is disconnected',
              );
              assert.ok(proxy.blocked.length > 0);
              await receiveFromFakeCamera(page);
              const saved = path.join(downloads, capsuleFilename);
              await saveCapsule(page, saved);
              assert.deepEqual(readFileSync(saved), ciphertext);
              assert.deepEqual(hosted.traffic, []);
              for (const request of proxy.blocked) {
                assert.deepEqual(request, {
                  method: 'GET',
                  path: '/optical/sw.js',
                });
              }
              await evaluate(
                page,
                "document.querySelector('#stop').click(); true",
              );
              const destination = path.join(work, 'recovered');
              const flags =
                input.name === 'collection'
                  ? ['--extract', '--out-dir', destination]
                  : ['--out', destination];
              const result = command(
                [
                  'optical',
                  'decrypt',
                  '--json',
                  '--file',
                  saved,
                  ...flags,
                  ...(choice.identity ? ['--identity', choice.identity] : []),
                ],
                work,
              );
              assert.equal(result.status, 'recovered');
              assert.equal(result.mode, 'optical');
              assert.equal(result.format, 'dud/optical/1');
              assert.equal(Object.hasOwn(result, 'carrier'), false);
              if (input.expected) {
                assert.deepEqual(readFileSync(destination), input.expected);
              } else {
                assert.deepEqual(
                  readFileSync(
                    path.join(destination, 'private-directory/one.bin'),
                  ),
                  payload,
                );
                assert.deepEqual(
                  readFileSync(
                    path.join(destination, 'private-directory/two.txt'),
                  ),
                  message,
                );
              }
            } finally {
              page?.close();
              browser?.close();
              if (launched) {
                await stopChrome(launched.processHandle);
              }
              await closeServer(hosted.server);
              await closeServer(proxy.server);
            }
          },
        );
      }
    }
    await t.test(
      '16 MiB native source recovers through isolated production browser workers',
      async () => {
        const work = path.join(root, 'large');
        mkdirSync(work);
        const source = path.join(work, 'source.bin');
        const payload = deterministicCapsule(16 * 1024 * 1024);
        writeFileSync(source, payload);
        command(
          [
            'upload',
            '--optical',
            '--json',
            '--file',
            source,
            '-r',
            identities[0].recipient,
          ],
          work,
        );
        const sender = path.join(work, 'sender.age');
        const measurement = await runIsolatedMemory({
          input: sender,
          downloadDirectory: work,
        });
        assert.equal(measurement.result.bytes, readFileSync(sender).length);
        const saved = path.join(work, 'isolated-received.age');
        assert.deepEqual(readFileSync(saved), readFileSync(sender));
        const destination = path.join(work, 'recovered.bin');
        command(
          [
            'optical',
            'decrypt',
            '--json',
            '--file',
            saved,
            '--out',
            destination,
            '--identity',
            identities[0].identity,
          ],
          work,
        );
        assert.deepEqual(readFileSync(destination), payload);
      },
    );
    await t.test(
      'real encryption accepts exactly 64 MiB ciphertext and rejects the next plaintext byte',
      async () => {
        const work = path.join(root, 'boundary');
        mkdirSync(work);
        const source = path.join(work, 'boundary.bin');
        const flags = [
          'upload',
          '--optical',
          '--json',
          '--file',
          source,
          '-r',
          identities[0].recipient,
        ];
        writeFileSync(source, Buffer.alloc(1));
        command(flags, work);
        // Binary age adds a 16-byte tag per 64 KiB chunk. The native X25519
        // header and private file metadata have fixed lengths for this fixture.
        const overhead = readFileSync(path.join(work, 'sender.age')).length - 1;
        const maximumSource = 64 * 1024 * 1024 - overhead - 16 * (1024 - 1);
        writeFileSync(source, Buffer.alloc(maximumSource));
        assert.equal(command(flags, work).ciphertextBytes, 64 * 1024 * 1024);
        assert.equal(
          readFileSync(path.join(work, 'sender.age')).length,
          64 * 1024 * 1024,
        );
        rmSync(path.join(work, 'sender.age'));
        writeFileSync(source, Buffer.alloc(maximumSource + 1));
        assert.throws(
          () => command(flags, work),
          (error) => {
            assert.equal(
              JSON.parse(error.stdout).error.code,
              'ciphertext-limit',
            );
            return true;
          },
        );
        assert.equal(existsSync(path.join(work, 'sender.age')), false);
        assert.deepEqual(
          readdirSync(work).filter((name) => name.startsWith('dud-optical-')),
          [],
        );
      },
    );
  },
);
