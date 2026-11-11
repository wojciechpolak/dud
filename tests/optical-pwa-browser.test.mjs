// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
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
import {
  clientModule,
  pwa,
  capsuleFilename,
  chromeExecutable,
  ffmpegExecutable,
  deterministicCapsule,
  renderFakeCameraVideo,
  encodeCameraVideo,
  alternateReceiver,
  startOpticalServer,
  startOfflineProxy,
  DevToolsClient,
  waitFor,
  evaluate,
  waitForPage,
  waitForTrafficToSettle,
  launchChrome,
  stopChrome,
  closeServer,
  assertOnlyOpticalTraffic,
  assertNoExternalRequests,
  assertCachedSecurityHeaders,
  receiveFromFakeCamera,
  startFakeCamera,
  waitForReceipt,
  saveCapsule,
} from '../server/optical-receiver/browser-runtime.mjs';

const observeCameraResources = `(() => {
  const tracks = [];
  const workers = new Set();
  const urls = new Set();
  let cameraRequests = 0;
  let createdWorkers = 0;
  let receiptDeadlinesCreated = 0;
  const deadlines = new Map();
  const setTimer = window.setTimeout.bind(window);
  const clearTimer = window.clearTimeout.bind(window);
  window.setTimeout = (callback, delay, ...args) => {
    if (delay !== 900000 || typeof callback !== 'function') {
      return setTimer(callback, delay, ...args);
    }
    receiptDeadlinesCreated++;
    const id = setTimer(() => {
      deadlines.delete(id);
      callback(...args);
    }, delay);
    deadlines.set(id, callback);
    return id;
  };
  window.clearTimeout = (id) => {
    deadlines.delete(id);
    return clearTimer(id);
  };
  window.expireOpticalReceipt = () => {
    const callback = deadlines.values().next().value;
    if (!callback) throw new Error('No receipt deadline');
    callback();
  };
  const getUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  navigator.mediaDevices.getUserMedia = async (...args) => {
    cameraRequests++;
    const stream = await getUserMedia(...args);
    tracks.push(...stream.getTracks());
    return stream;
  };
  const NativeWorker = Worker;
  window.Worker = class extends NativeWorker {
    constructor(...args) {
      super(...args);
      createdWorkers++;
      workers.add(this);
    }
    terminate() {
      workers.delete(this);
      return super.terminate();
    }
  };
  const createURL = URL.createObjectURL.bind(URL);
  const revokeURL = URL.revokeObjectURL.bind(URL);
  URL.createObjectURL = (...args) => {
    const url = createURL(...args);
    urls.add(url);
    return url;
  };
  URL.revokeObjectURL = (url) => {
    urls.delete(url);
    return revokeURL(url);
  };
  window.opticalResourceSnapshot = () => ({
    receiptDeadlinesCreated,
    receiptDeadlinesActive: deadlines.size,
    cameraRequests,
    tracks: tracks.length,
    liveTracks: tracks.filter((track) => track.readyState === 'live').length,
    createdWorkers,
    liveWorkers: workers.size,
    objectURLs: urls.size,
  });
})()`;

async function receiverState(page) {
  return evaluate(
    page,
    `({
    status: document.querySelector('#status').value,
    detail: document.querySelector('#status-detail').value,
    progress: document.querySelector('#progress').value,
    progressLabel: document.querySelector('#progress-label').value,
    statistics: document.querySelector('#statistics').value,
    stripeCount: document.querySelector('#stripe-rows').children.length,
    saveDisabled: document.querySelector('#save-capsule').disabled,
    startDisabled: document.querySelector('#start').disabled,
    stopDisabled: document.querySelector('#stop').disabled,
    pauseDisabled: document.querySelector('#pause').disabled,
    startLabel: document.querySelector('#start').textContent,
    videoDetached: document.querySelector('#camera-view').srcObject === null,
    videoHidden: document.querySelector('#camera-view').hidden,
    ...window.opticalResourceSnapshot(),
  })`,
  );
}

async function assertReleasedCamera(page) {
  await waitFor(async () => {
    const state = await receiverState(page);
    return (
      state.liveTracks === 0 &&
      state.liveWorkers === 0 &&
      state.objectURLs === 0
    );
  }, 'camera, QR workers, and download URLs to be released');
  const state = await receiverState(page);
  assert.equal(state.videoDetached, true);
  assert.equal(state.videoHidden, true);
  assert.equal(state.startDisabled, false);
  assert.equal(state.pauseDisabled, true);
  assert.equal(state.receiptDeadlinesActive, 0);
  return state;
}

async function assertClearedReceiver(page) {
  const state = await assertReleasedCamera(page);
  assert.equal(state.progress, 0);
  assert.equal(state.progressLabel, '0%');
  assert.equal(state.stripeCount, 0);
  assert.equal(state.saveDisabled, true);
  assert.equal(state.statistics, 'No frames received.');
  return state;
}

function contrastRatio(foreground, background) {
  const luminance = (color) => {
    const components = color.startsWith('#')
      ? color
          .slice(1)
          .match(/../g)
          .map((value) => parseInt(value, 16))
      : color
          .match(/[\d.]+/g)
          .slice(0, 3)
          .map(Number);
    const linear = components.map((value) => {
      const channel = value / 255;
      return channel <= 0.04045
        ? channel / 12.92
        : ((channel + 0.055) / 1.055) ** 2.4;
    });
    return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
  };
  const values = [luminance(foreground), luminance(background)];
  return (Math.max(...values) + 0.05) / (Math.min(...values) + 0.05);
}

async function assertSystemTheme(page, theme) {
  await page.send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-color-scheme', value: theme }],
  });
  const colors = await evaluate(
    page,
    `(() => {
      const style = getComputedStyle(document.documentElement);
      const token = name => style.getPropertyValue(name).trim();
      const paper = token('--paper');
      return {
        scheme: style.colorScheme,
        paper,
        theme: [...document.querySelectorAll('meta[name="theme-color"]')]
          .find(meta => matchMedia(meta.media).matches)?.content,
        pairs: [
          ['receipt status', getComputedStyle(document.querySelector('#status')).color, paper],
          ...['--ink', '--muted', '--cobalt-dark', '--amber', '--red', '--complete']
            .map(name => [name, token(name), paper]),
          ['camera text', token('--muted'), token('--camera-field')],
          ['control text', token('--ink'), token('--field')],
          ['primary button', token('--button-text'), token('--cobalt')],
        ],
      };
    })()`,
  );
  assert.equal(colors.scheme, theme);
  assert.equal(colors.paper, theme === 'dark' ? '#111827' : '#f4f8ff');
  assert.equal(colors.theme, theme === 'dark' ? '#111827' : '#eef4ff');
  for (const [name, foreground, background] of colors.pairs) {
    assert.ok(
      contrastRatio(foreground, background) >= 4.5,
      `${theme} ${name} contrast is below 4.5:1`,
    );
  }
}

async function assertCompactReceiver(page) {
  const layout = await evaluate(
    page,
    `(() => {
      const preview = document.querySelector('.camera-field').getBoundingClientRect();
      const controls = document.querySelector('.controls').getBoundingClientRect();
      return {
        width: innerWidth,
        height: innerHeight,
        pageWidth: document.documentElement.scrollWidth,
        preview: { width: preview.width, height: preview.height, top: preview.top },
        controlsBottom: controls.bottom,
        buttons: [...document.querySelectorAll('.controls button')].map(button => {
          const rect = button.getBoundingClientRect();
          return { left: rect.left, right: rect.right, height: rect.height };
        }),
        panelsClosed: [...document.querySelectorAll('.panel')].every(panel => !panel.open),
        diagnosticsHidden: ['statistics', 'stripe-rows', 'save-diagnostics', 'replay-files']
          .every(id => !document.getElementById(id).checkVisibility()),
        updateInFooter: !!document.querySelector('.receiver-footer #receiver-update'),
        detail: document.querySelector('#status-detail').value,
      };
    })()`,
  );
  assert.ok(
    layout.pageWidth <= layout.width,
    'receiver overflows horizontally',
  );
  assert.ok(layout.preview.top >= 0);
  assert.ok(Math.abs(layout.preview.width - layout.preview.height) < 1);
  assert.ok(layout.preview.width <= Math.min(layout.height * 0.42, 420) + 1);
  assert.ok(
    layout.controlsBottom <= layout.height,
    `controls end at ${layout.controlsBottom} in a ${layout.height}px viewport`,
  );
  for (const button of layout.buttons) {
    assert.ok(button.left >= 0 && button.right <= layout.width);
    assert.ok(button.height >= 44);
  }
  assert.equal(layout.panelsClosed, true);
  assert.equal(layout.diagnosticsHidden, true);
  assert.equal(layout.updateInFooter, true);
  assert.doesNotMatch(layout.detail, /stripe|independent frames|\bCRC\b/i);
  return layout.controlsBottom;
}

async function togglePanelWithKeyboard(page, id) {
  await evaluate(
    page,
    `document.querySelector('#${id} summary').focus(); true`,
  );
  await page.send('Input.dispatchKeyEvent', {
    type: 'keyDown',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
    text: '\r',
    unmodifiedText: '\r',
  });
  await page.send('Input.dispatchKeyEvent', {
    type: 'keyUp',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
  });
}

test(
  'camera failures, cancellation, unsupported format, and distinct sessions recover through the receiver interface',
  { timeout: 180_000 },
  async (t) => {
    const chrome = chromeExecutable();
    const ffmpeg = ffmpegExecutable();
    if (!chrome || !ffmpeg) {
      t.skip('Chrome and ffmpeg are required for browser recovery flows');
      return;
    }
    const work = mkdtempSync(
      path.join(tmpdir(), 'dud-optical-recovery-browser-'),
    );
    const fixture = (name, capsule, limit) => {
      const directory = path.join(work, name);
      mkdirSync(directory);
      return renderFakeCameraVideo(directory, ffmpeg, capsule, limit);
    };
    const first = fixture('first', deterministicCapsule(2401));
    const second = fixture('second', deterministicCapsule(3201));
    const partial = fixture('partial', deterministicCapsule(14001), 1);
    const stripeFixtures = [6, 11].map((count) => ({
      count,
      ...fixture(
        `stripes-${count}`,
        deterministicCapsule((count - 1) * 1600 * 1024 + 1),
        1,
      ),
    }));
    const pauseFixture = fixture('pause', deterministicCapsule(14001));
    const pauseVideos = [];
    for (const [name, frameIndices] of [
      ['pause-first', [0]],
      ['pause-rest', [1, 2]],
    ]) {
      const directory = path.join(work, name);
      mkdirSync(directory);
      for (const [index, frame] of frameIndices.entries()) {
        cpSync(
          path.join(
            pauseFixture.frames,
            `frame-${String(frame).padStart(8, '0')}.png`,
          ),
          path.join(directory, `frame-${String(index).padStart(8, '0')}.png`),
        );
      }
      const video = path.join(work, `${name}.y4m`);
      encodeCameraVideo(directory, video, ffmpeg);
      pauseVideos.push(video);
    }
    const hostile = path.join(work, 'hostile');
    mkdirSync(hostile);
    const hostileFrames = path.join(hostile, 'frames');
    mkdirSync(hostileFrames);
    const vectors = JSON.parse(
      readFileSync(
        path.join(
          clientModule,
          'optical-sender/testdata/format1/go-vectors.json',
        ),
        'utf8',
      ),
    );
    const unsupportedFrame = path.join(hostile, 'unsupported.bin');
    writeFileSync(
      unsupportedFrame,
      Buffer.from(
        vectors.invalid.find((frame) => frame.name === 'version').bytes,
        'hex',
      ),
    );
    execFileSync(
      'go',
      [
        'run',
        './optical-sender/testtools/qr-frame',
        unsupportedFrame,
        path.join(hostileFrames, 'frame-00000000.png'),
      ],
      {
        cwd: clientModule,
        env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
        stdio: 'pipe',
      },
    );
    for (const index of [1, 2]) {
      cpSync(
        path.join(hostileFrames, 'frame-00000000.png'),
        path.join(hostileFrames, `frame-0000000${index}.png`),
      );
    }
    cpSync(
      path.join(first.frames, 'frame-00000000.png'),
      path.join(hostileFrames, 'frame-00000003.png'),
    );
    const hostileVideo = path.join(hostile, 'camera.y4m');
    encodeCameraVideo(hostileFrames, hostileVideo, ffmpeg);

    const activeVideo = path.join(work, 'active-camera.y4m');
    cpSync(first.video, activeVideo);
    const profile = path.join(work, 'chrome-profile');
    const downloads = path.join(work, 'downloads');
    mkdirSync(profile);
    mkdirSync(downloads);
    const hosted = await startOpticalServer(work);
    const proxy = await startOfflineProxy(hosted.origin);
    let launched;
    let browser;
    let page;
    t.after(async () => {
      page?.close();
      browser?.close();
      if (launched) {
        await stopChrome(launched.processHandle);
      }
      await closeServer(hosted.server);
      await closeServer(proxy.server);
      rmSync(work, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 100,
      });
    });
    launched = await launchChrome(
      chrome,
      profile,
      activeVideo,
      false,
      proxy.origin,
    );
    const requests = [];
    const connectReceiver = async () => {
      browser = await DevToolsClient.connect(launched.browserURL);
      await browser.send('Browser.setDownloadBehavior', {
        behavior: 'allow',
        downloadPath: downloads,
      });
      const target = await fetch(
        `${launched.debugOrigin}/json/new?about:blank`,
        {
          method: 'PUT',
        },
      ).then((response) => response.json());
      page = await DevToolsClient.connect(target.webSocketDebuggerUrl);
      await Promise.all([
        page.send('Page.enable'),
        page.send('Runtime.enable'),
        page.send('Network.enable'),
      ]);
      await page.send('Page.addScriptToEvaluateOnNewDocument', {
        source: observeCameraResources,
      });
      page.on('Network.requestWillBeSent', (event) => requests.push(event));
    };
    await connectReceiver();
    await page.send('Page.navigate', { url: `${hosted.origin}/optical/` });
    await waitForPage(page);
    await waitForTrafficToSettle(hosted.traffic);
    assertOnlyOpticalTraffic(hosted.traffic);
    assertNoExternalRequests(requests, hosted.origin);
    // Browser-initiated worker update checks bypass page-level offline emulation.
    // The proxy disconnects the installed receiver from the host at transport level.
    proxy.disconnect();
    await t.test(
      'installed receiver starts after a browser restart with its host disconnected',
      async () => {
        await page.send('Page.navigate', { url: 'about:blank' });
        page.close();
        browser.close();
        await stopChrome(launched.processHandle);
        launched = await launchChrome(
          chrome,
          profile,
          activeVideo,
          false,
          proxy.origin,
        );
        await connectReceiver();
        await page.send('Network.emulateNetworkConditions', {
          offline: true,
          latency: 0,
          downloadThroughput: 0,
          uploadThroughput: 0,
        });
        hosted.traffic.length = 0;
        await page.send('Page.navigate', {
          url: `${hosted.origin}/optical/index.html`,
        });
        await waitForPage(page);
        assert.equal(await evaluate(page, 'location.pathname'), '/optical/');
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#receiver-update-status').value",
          ),
          'Receiver is available offline.',
        );
        assert.deepEqual(hosted.traffic, []);
        assert.equal((await receiverState(page)).status, 'Ready');
      },
    );
    hosted.traffic.length = 0;
    requests.length = 0;
    const pageIdentity = await evaluate(page, 'performance.timeOrigin');
    const download = path.join(downloads, capsuleFilename);
    const assertNoReceiptRequests = async () => {
      await waitForTrafficToSettle(hosted.traffic);
      assert.deepEqual(hosted.traffic, []);
      for (const request of proxy.blocked) {
        assert.deepEqual(request, { method: 'GET', path: '/optical/sw.js' });
      }
      assertNoExternalRequests(requests, hosted.origin);
      assert.equal(
        await evaluate(page, 'performance.timeOrigin'),
        pageIdentity,
      );
    };
    const receiveAndCompare = async (fixture) => {
      cpSync(fixture.video, activeVideo);
      await receiveFromFakeCamera(page);
      await saveCapsule(page, download);
      assert.deepEqual(readFileSync(download), fixture.capsule);
      const state = await assertReleasedCamera(page);
      assert.ok(state.tracks > 0 && state.createdWorkers > 0);
      await assertNoReceiptRequests();
    };

    await t.test(
      'offline update failure leaves camera receipt available after a cold start',
      async () => {
        await evaluate(
          page,
          "document.querySelector('#receiver-update').click(); true",
        );
        await waitFor(
          () =>
            evaluate(
              page,
              "document.querySelector('#receiver-update-status').value.includes('Could not check') && !document.querySelector('#start').disabled",
            ),
          'offline update failure to release camera controls',
        );
        const state = await assertReleasedCamera(page);
        assert.equal(state.status, 'Ready');
        assert.equal(state.progress, 0);
        assert.equal(state.stripeCount, 0);
        assert.equal(state.saveDisabled, true);
        assert.equal(state.cameraRequests, 0);
        await assertNoReceiptRequests();
      },
    );

    await t.test(
      'system themes keep mobile controls visible while stripe diagnostics stay collapsed',
      async (t) => {
        t.after(async () => {
          await page.send('Emulation.clearDeviceMetricsOverride');
          await page.send('Emulation.setEmulatedMedia', { features: [] });
        });
        for (const [width, height] of [
          [390, 844],
          [320, 568],
        ]) {
          await page.send('Emulation.setDeviceMetricsOverride', {
            width,
            height,
            deviceScaleFactor: 1,
            mobile: false,
          });
          for (const theme of ['light', 'dark']) {
            await assertSystemTheme(page, theme);
            await assertCompactReceiver(page);
          }
        }
        await browser.send('Browser.setPermission', {
          permission: { name: 'camera' },
          setting: 'granted',
          origin: hosted.origin,
        });
        let receivingBottom;
        for (const fixture of stripeFixtures) {
          cpSync(fixture.video, activeVideo);
          await startFakeCamera(page);
          await waitFor(
            async () => (await receiverState(page)).progress > 0,
            'multi-stripe partial receipt',
          );
          const before = await receiverState(page);
          assert.equal(before.stripeCount, fixture.count);
          for (const theme of ['dark', 'light']) {
            await assertSystemTheme(page, theme);
            const bottom = await assertCompactReceiver(page);
            if (receivingBottom !== undefined) {
              assert.equal(bottom, receivingBottom);
            }
            receivingBottom = bottom;
            const state = await receiverState(page);
            assert.equal(state.cameraRequests, before.cameraRequests);
            assert.equal(state.createdWorkers, before.createdWorkers);
            assert.equal(state.liveTracks, before.liveTracks);
            assert.ok(state.progress >= before.progress);
          }
          await evaluate(
            page,
            "document.querySelector('#pause').click(); true",
          );
          await waitFor(
            async () => (await receiverState(page)).status === 'Receipt paused',
            'paused receipt',
          );
          for (const theme of ['light', 'dark']) {
            await assertSystemTheme(page, theme);
            await assertCompactReceiver(page);
          }
          await evaluate(
            page,
            "document.querySelector('#receiver-diagnostics summary').click(); true",
          );
          assert.equal(
            await evaluate(
              page,
              `(() => {
            const rows = [...document.querySelectorAll('#stripe-rows [role="listitem"]')];
            return rows.length === ${fixture.count} && rows.every(row => row.checkVisibility()) &&
              rows.some(row => row.querySelector('progress').value > 0) &&
              document.querySelector('#save-diagnostics').checkVisibility() &&
              !document.querySelector('#replay-files').checkVisibility();
          })()`,
            ),
            true,
          );
          await evaluate(
            page,
            "document.querySelector('#receiver-diagnostics summary').click(); document.querySelector('#stop').click(); true",
          );
          await assertClearedReceiver(page);
        }
        await assertNoReceiptRequests();
      },
    );

    await t.test(
      'camera denial offers permission recovery and leaves no savable receipt',
      async (t) => {
        const beforeDenial = await receiverState(page);
        t.after(() =>
          browser.send('Browser.setPermission', {
            permission: { name: 'camera' },
            setting: 'granted',
            origin: hosted.origin,
          }),
        );
        await browser.send('Browser.setPermission', {
          permission: { name: 'camera' },
          setting: 'denied',
          origin: hosted.origin,
        });
        await startFakeCamera(page);
        await waitFor(
          async () =>
            (await receiverState(page)).status === 'Camera did not start',
          'camera denial message',
        );
        const state = await assertClearedReceiver(page);
        assert.match(state.detail, /Allow camera access.*Start camera/);
        for (const theme of ['light', 'dark']) {
          await assertSystemTheme(page, theme);
        }
        assert.equal(state.tracks, beforeDenial.tracks);
        assert.equal(state.createdWorkers, beforeDenial.createdWorkers);
        await assertNoReceiptRequests();
        await browser.send('Browser.setPermission', {
          permission: { name: 'camera' },
          setting: 'granted',
          origin: hosted.origin,
        });
        await receiveAndCompare(first);
        for (const [width, height] of [
          [390, 844],
          [320, 568],
        ]) {
          await page.send('Emulation.setDeviceMetricsOverride', {
            width,
            height,
            deviceScaleFactor: 1,
            mobile: false,
          });
          for (const theme of ['light', 'dark']) {
            await assertSystemTheme(page, theme);
            await assertCompactReceiver(page);
          }
        }
        await page.send('Emulation.clearDeviceMetricsOverride');
      },
    );

    await t.test(
      'a second sender session saves distinct bytes without reloading',
      async () => {
        await receiveAndCompare(second);
        assert.notDeepEqual(readFileSync(download), first.capsule);
      },
    );

    await t.test(
      'Stop / reset clears an incomplete receipt and releases resources before retry',
      async () => {
        cpSync(partial.video, activeVideo);
        rmSync(download, { force: true });
        await startFakeCamera(page);
        await waitFor(async () => {
          const state = await receiverState(page);
          return (
            state.progress > 0 &&
            state.progress < 100 &&
            state.liveTracks > 0 &&
            state.liveWorkers > 0
          );
        }, 'incomplete camera receipt');
        assert.equal((await receiverState(page)).saveDisabled, true);
        const expectedScan = await evaluate(
          page,
          `(async () => {
          const video = document.querySelector('#camera-view');
          const sourceSize = Math.min(video.videoWidth, video.videoHeight);
          const scanSize = Math.min(sourceSize, 960);
          const canvas = new OffscreenCanvas(scanSize, scanSize);
          const context = canvas.getContext('2d');
          context.drawImage(video, Math.floor((video.videoWidth - sourceSize) / 2),
            Math.floor((video.videoHeight - sourceSize) / 2), sourceSize, sourceSize,
            0, 0, scanSize, scanSize);
          const digest = await crypto.subtle.digest('SHA-256',
            context.getImageData(0, 0, scanSize, scanSize).data);
          return { scanSize, build: document.body.dataset.build,
            sha256: [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('') };
        })()`,
          true,
        );
        const scanDownload = path.join(
          downloads,
          `dud-optical-scan-${expectedScan.build}.png`,
        );
        assert.equal(existsSync(scanDownload), false);
        await evaluate(
          page,
          "document.querySelector('#receiver-diagnostics summary').click(); true",
        );
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#save-scan-image').disabled",
          ),
          false,
        );
        await evaluate(
          page,
          "document.querySelector('#save-scan-image').click(); true",
        );
        await waitFor(
          () =>
            existsSync(scanDownload) &&
            !existsSync(`${scanDownload}.crdownload`),
          'explicit local camera scan image download',
        );
        const png = readFileSync(scanDownload);
        assert.equal(png.readUInt32BE(16), expectedScan.scanSize);
        assert.equal(png.readUInt32BE(20), expectedScan.scanSize);
        await evaluate(
          page,
          "document.querySelector('#receiver-diagnostics summary').click(); true",
        );
        const pixels = execFileSync(
          ffmpeg,
          [
            '-loglevel',
            'error',
            '-i',
            scanDownload,
            '-f',
            'rawvideo',
            '-pix_fmt',
            'rgba',
            '-',
          ],
          { maxBuffer: 8 * 1024 * 1024 },
        );
        assert.equal(
          createHash('sha256').update(pixels).digest('hex'),
          expectedScan.sha256,
        );
        await evaluate(page, "document.querySelector('#stop').click(); true");
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#save-scan-image').disabled",
          ),
          true,
        );
        const state = await assertClearedReceiver(page);
        assert.equal(state.status, 'Receiver reset');
        assert.equal(state.stopDisabled, true);
        assert.match(state.detail, /cleared.*Start camera/);
        await evaluate(
          page,
          "document.querySelector('#save-capsule').click(); true",
        );
        assert.equal(existsSync(download), false);
        await assertNoReceiptRequests();
        await receiveAndCompare(second);
      },
    );

    await t.test(
      'pause releases the camera and resumes retained equations through permission recovery',
      async (t) => {
        t.after(async () => {
          await page.send('Emulation.clearDeviceMetricsOverride');
          await browser.send('Browser.setPermission', {
            permission: { name: 'camera' },
            setting: 'granted',
            origin: hosted.origin,
          });
        });
        await page.send('Emulation.setDeviceMetricsOverride', {
          width: 390,
          height: 844,
          deviceScaleFactor: 1,
          mobile: false,
        });
        cpSync(pauseVideos[0], activeVideo);
        rmSync(download, { force: true });
        await startFakeCamera(page);
        await waitFor(
          async () => (await receiverState(page)).progress > 0,
          'partial receipt before pause',
        );
        await evaluate(page, "document.querySelector('#pause').click(); true");
        await waitFor(async () => {
          const state = await receiverState(page);
          return (
            state.status === 'Receipt paused' &&
            state.liveTracks === 0 &&
            state.videoDetached
          );
        }, 'camera release on pause');
        const before = await receiverState(page);
        assert.equal(before.startLabel, 'Resume camera');
        assert.equal(before.startDisabled, false);
        assert.equal(before.pauseDisabled, true);
        assert.equal(before.stopDisabled, false);
        assert.equal(before.saveDisabled, true);
        assert.ok(
          before.progress > 0 &&
            before.progress < 100 &&
            before.liveWorkers > 0,
        );
        assert.equal(before.receiptDeadlinesActive, 1);
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#receiver-update').disabled && document.querySelector('#capture-profile').disabled && document.querySelector('#camera').disabled",
          ),
          true,
        );
        const submitted = await evaluate(
          page,
          "document.querySelector('#statistics').value.match(/^\\d+ submitted/)[0]",
        );
        await new Promise((resolve) => setTimeout(resolve, 500));
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#statistics').value.match(/^\\d+ submitted/)[0]",
          ),
          submitted,
        );
        assert.equal((await receiverState(page)).progress, before.progress);

        assert.equal(
          await evaluate(
            page,
            "[...document.querySelectorAll('.receipt-actions button')].every(button => { const rect = button.getBoundingClientRect(); return rect.width > 0 && rect.left >= 0 && rect.right <= innerWidth && rect.height >= 44; })",
          ),
          true,
        );
        await evaluate(
          page,
          "document.querySelector('#receiver-settings summary').click(); true",
        );
        assert.equal(
          await evaluate(
            page,
            "['camera', 'capture-profile'].every(id => { const rect = document.getElementById(id).getBoundingClientRect(); const settings = document.querySelector('.settings-fields').getBoundingClientRect(); return rect.width >= settings.width - 1; })",
          ),
          true,
        );
        await evaluate(
          page,
          "document.querySelector('#receiver-settings summary').click(); true",
        );

        await browser.send('Browser.setPermission', {
          permission: { name: 'camera' },
          setting: 'denied',
          origin: hosted.origin,
        });
        await startFakeCamera(page);
        await waitFor(
          async () =>
            (await receiverState(page)).status === 'Camera did not resume',
          'resume permission failure',
        );
        const denied = await receiverState(page);
        assert.equal(denied.progress, before.progress);
        assert.equal(denied.liveTracks, 0);
        assert.equal(denied.startLabel, 'Resume camera');
        assert.equal(
          denied.receiptDeadlinesCreated,
          before.receiptDeadlinesCreated,
        );
        await browser.send('Browser.setPermission', {
          permission: { name: 'camera' },
          setting: 'granted',
          origin: hosted.origin,
        });

        const diagnostics = path.join(
          downloads,
          'dud-optical-diagnostics.json',
        );
        rmSync(diagnostics, { force: true });
        await evaluate(
          page,
          "document.querySelector('#save-diagnostics').click(); true",
        );
        await waitFor(
          () =>
            existsSync(diagnostics) && !existsSync(`${diagnostics}.crdownload`),
          'paused diagnostics download',
        );
        const report = JSON.parse(readFileSync(diagnostics, 'utf8'));
        assert.equal(report.pauses.count, 2);
        assert.ok(report.pauses.milliseconds >= 500);
        assert.ok(report.workers.submitted > 0);

        cpSync(pauseVideos[1], activeVideo);
        await startFakeCamera(page);
        await waitForReceipt(page);
        await saveCapsule(page, download);
        assert.deepEqual(readFileSync(download), pauseFixture.capsule);
        const completed = await assertReleasedCamera(page);
        assert.equal(
          completed.receiptDeadlinesCreated,
          before.receiptDeadlinesCreated,
        );
        assert.equal(completed.stopDisabled, false);
        assert.match(completed.statistics, /Camera paused for/);
        await evaluate(page, "document.querySelector('#stop').click(); true");
        await assertClearedReceiver(page);
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#save-diagnostics').disabled",
          ),
          true,
        );
        await assertNoReceiptRequests();
        await receiveAndCompare(second);
      },
    );

    await t.test(
      'reset and the receipt deadline discard paused state and allow another sender',
      async () => {
        for (const action of ['reset', 'deadline']) {
          cpSync(pauseVideos[0], activeVideo);
          await startFakeCamera(page);
          await waitFor(
            async () => (await receiverState(page)).progress > 0,
            'partial receipt',
          );
          await evaluate(
            page,
            "document.querySelector('#pause').click(); true",
          );
          await waitFor(
            async () => (await receiverState(page)).status === 'Receipt paused',
            'paused receipt',
          );
          await evaluate(
            page,
            action === 'reset'
              ? "document.querySelector('#stop').click(); true"
              : 'window.expireOpticalReceipt(); true',
          );
          const state = await assertClearedReceiver(page);
          assert.equal(
            state.status,
            action === 'reset' ? 'Receiver reset' : 'Transfer stopped',
          );
          if (action === 'deadline') {
            assert.match(state.detail, /15 minutes/);
          }
          await assertNoReceiptRequests();
          await receiveAndCompare(first);
        }
      },
    );

    await t.test(
      'unsupported QR format stays unsavable and recovers when valid frames appear',
      async () => {
        cpSync(hostileVideo, activeVideo);
        rmSync(download, { force: true });
        await startFakeCamera(page);
        await waitFor(
          async () =>
            (await receiverState(page)).status === 'Unsupported optical format',
          'unsupported QR format warning',
        );
        const state = await receiverState(page);
        assert.match(state.detail, /Point the camera.*dud\/optical\/1/);
        assert.equal(state.progress, 0);
        assert.equal(state.stripeCount, 0);
        assert.equal(state.saveDisabled, true);
        assert.ok(state.liveTracks > 0 && state.liveWorkers > 0);
        await evaluate(
          page,
          "document.querySelector('#save-capsule').click(); true",
        );
        assert.equal(existsSync(download), false);
        await waitForReceipt(page);
        await saveCapsule(page, download);
        assert.deepEqual(readFileSync(download), first.capsule);
        await assertReleasedCamera(page);
        await assertNoReceiptRequests();
      },
    );

    await t.test(
      'keyboard disclosures expose settings, help, and local recorded-frame replay',
      async () => {
        for (const id of ['receiver-settings', 'receiver-help']) {
          await togglePanelWithKeyboard(page, id);
          assert.equal(
            await evaluate(page, `document.querySelector('#${id}').open`),
            true,
          );
          await togglePanelWithKeyboard(page, id);
          assert.equal(
            await evaluate(page, `document.querySelector('#${id}').open`),
            false,
          );
        }
        await togglePanelWithKeyboard(page, 'receiver-diagnostics');
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#receiver-diagnostics').open && document.querySelector('#save-diagnostics').checkVisibility()",
          ),
          true,
        );
        await togglePanelWithKeyboard(page, 'recorded-replay');
        assert.equal(
          await evaluate(
            page,
            "document.querySelector('#replay-files').checkVisibility()",
          ),
          true,
        );
        const { root } = await page.send('DOM.getDocument');
        const { nodeId } = await page.send('DOM.querySelector', {
          nodeId: root.nodeId,
          selector: '#replay-files',
        });
        await page.send('DOM.setFileInputFiles', {
          nodeId,
          files: readdirSync(first.frames)
            .filter((name) => name.endsWith('.png'))
            .map((name) => path.join(first.frames, name)),
        });
        assert.equal(
          await evaluate(page, "document.querySelector('#replay').disabled"),
          false,
        );
        rmSync(download, { force: true });
        await evaluate(page, "document.querySelector('#replay').click(); true");
        await waitForReceipt(page);
        await saveCapsule(page, download);
        assert.deepEqual(readFileSync(download), first.capsule);
        await assertReleasedCamera(page);
        await assertNoReceiptRequests();
        await togglePanelWithKeyboard(page, 'recorded-replay');
        const diagnostics = path.join(
          downloads,
          'dud-optical-diagnostics.json',
        );
        await evaluate(
          page,
          "document.querySelector('#save-diagnostics').click(); true",
        );
        await waitFor(
          () =>
            existsSync(diagnostics) && !existsSync(`${diagnostics}.crdownload`),
          'offline diagnostics download after browser restart',
        );
        const report = JSON.parse(readFileSync(diagnostics, 'utf8'));
        assert.equal(report.schemaVersion, 1);
        assert.equal(
          report.receiverBuild,
          await evaluate(page, 'document.body.dataset.build'),
        );
        await assertNoReceiptRequests();
        await togglePanelWithKeyboard(page, 'receiver-diagnostics');
      },
    );
  },
);

test(
  'encrypted optical transfer browser downloads decrypt on the native host',
  { timeout: 180_000 },
  async (t) => {
    const chrome = chromeExecutable();
    const ffmpeg = ffmpegExecutable();
    if (!chrome || !ffmpeg) {
      t.skip(
        'Chrome and ffmpeg are required for the encrypted browser receipt test',
      );
      return;
    }

    const root = mkdtempSync(
      path.join(tmpdir(), 'dud-optical-encrypted-browser-'),
    );
    t.after(() =>
      rmSync(root, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 100,
      }),
    );
    const nativeHandoff = path.join(root, 'capsule-handoff');
    execFileSync(
      'go',
      [
        'build',
        '-o',
        nativeHandoff,
        './optical-sender/testtools/capsule-handoff',
      ],
      {
        cwd: clientModule,
        env: { ...process.env, GOCACHE: '/tmp/dud-go-build-cache' },
        stdio: 'pipe',
      },
    );

    for (const mode of ['passphrase', 'X25519', 'hybrid']) {
      await t.test(
        `${mode} ciphertext survives camera receipt and native decryption`,
        { timeout: 60_000 },
        async (t) => {
          const work = path.join(root, mode);
          const profile = path.join(work, 'chrome-profile');
          const downloads = path.join(work, 'downloads');
          mkdirSync(profile, { recursive: true });
          mkdirSync(downloads);

          const source = path.join(work, `private-${mode}-zażółć.bin`);
          const payload = deterministicCapsule(2401);
          payload.set(
            Buffer.from(
              `Private optical dead drop ${mode}: zażółć gęślą jaźń\n`,
            ),
          );
          writeFileSync(source, payload, { mode: 0o600 });
          const senderCiphertext = path.join(work, 'sender.age');
          const secret = path.join(work, 'native-secret');
          execFileSync(
            nativeHandoff,
            ['encrypt', mode, source, senderCiphertext, secret],
            { stdio: 'pipe' },
          );
          const ciphertext = readFileSync(senderCiphertext);
          assert.equal(ciphertext.includes(payload), false);
          assert.equal(
            ciphertext.includes(Buffer.from(path.basename(source))),
            false,
          );
          const { video } = renderFakeCameraVideo(work, ffmpeg, ciphertext);

          const hosted = await startOpticalServer(work);
          let launched;
          let browser;
          let page;
          t.after(async () => {
            page?.close();
            browser?.close();
            if (launched) {
              await stopChrome(launched.processHandle);
            }
            await closeServer(hosted.server);
          });
          launched = await launchChrome(chrome, profile, video);
          browser = await DevToolsClient.connect(launched.browserURL);
          await browser.send('Browser.setDownloadBehavior', {
            behavior: 'allow',
            downloadPath: downloads,
          });
          const target = await fetch(
            `${launched.debugOrigin}/json/new?about:blank`,
            { method: 'PUT' },
          ).then((response) => response.json());
          page = await DevToolsClient.connect(target.webSocketDebuggerUrl);
          await Promise.all([
            page.send('Page.enable'),
            page.send('Runtime.enable'),
            page.send('Network.enable'),
          ]);
          const browserRequests = [];
          page.on('Network.requestWillBeSent', (event) =>
            browserRequests.push(event),
          );
          await page.send('Page.navigate', {
            url: `${hosted.origin}/optical/`,
          });
          await waitForPage(page);
          await waitForTrafficToSettle(hosted.traffic);
          assertOnlyOpticalTraffic(hosted.traffic);
          assertNoExternalRequests(browserRequests, hosted.origin);

          await page.send('Network.emulateNetworkConditions', {
            offline: true,
            latency: 0,
            downloadThroughput: 0,
            uploadThroughput: 0,
          });
          hosted.traffic.length = 0;
          browserRequests.length = 0;
          await receiveFromFakeCamera(page);
          const download = path.join(downloads, capsuleFilename);
          await saveCapsule(page, download);
          await waitForTrafficToSettle(hosted.traffic);
          assert.deepEqual(readFileSync(download), ciphertext);
          assert.deepEqual(hosted.traffic, []);
          assertNoExternalRequests(browserRequests, hosted.origin);

          // Only the native process receives the original secret and saved file.
          const recovered = path.join(work, 'recovered-payload.bin');
          const metadata = JSON.parse(
            execFileSync(
              nativeHandoff,
              ['decrypt', mode, download, secret, recovered],
              { encoding: 'utf8', stdio: 'pipe' },
            ),
          );
          assert.deepEqual(readFileSync(recovered), payload);
          assert.deepEqual(metadata, {
            type: 3,
            displayName: path.basename(source),
            archiveFormat: 0,
            plaintextSize: payload.length,
            plaintextSHA256: createHash('sha256').update(payload).digest('hex'),
          });
          assert.deepEqual(hosted.traffic, []);
        },
      );
    }
  },
);

test(
  'installed receiver saves offline receipts and updates explicitly between builds',
  { timeout: 120_000 },
  async (t) => {
    const chrome = chromeExecutable();
    const ffmpeg = ffmpegExecutable();
    if (!chrome || !ffmpeg) {
      t.skip('Chrome and ffmpeg are required for the browser receipt test');
      return;
    }

    const work = mkdtempSync(path.join(tmpdir(), 'dud-optical-browser-'));
    const profile = path.join(work, 'chrome-profile');
    const downloads = path.join(work, 'downloads');
    mkdirSync(profile);
    mkdirSync(downloads);
    const { capsule, video } = renderFakeCameraVideo(work, ffmpeg);
    const manifest = JSON.parse(
      readFileSync(path.join(pwa, 'build-manifest.json'), 'utf8'),
    );
    const alternate = await alternateReceiver(work);
    assert.notEqual(alternate.manifest.buildId, manifest.buildId);
    const hosted = await startOpticalServer(work);
    let launched;
    let browser;
    let page;
    t.after(async () => {
      page?.close();
      browser?.close();
      if (launched) {
        await stopChrome(launched.processHandle);
      }
      await closeServer(hosted.server);
      rmSync(work, {
        recursive: true,
        force: true,
        maxRetries: 10,
        retryDelay: 100,
      });
    });
    launched = await launchChrome(chrome, profile, video);

    browser = await DevToolsClient.connect(launched.browserURL);
    await browser.send('Browser.setDownloadBehavior', {
      behavior: 'allow',
      downloadPath: downloads,
      eventsEnabled: true,
    });
    const target = await fetch(`${launched.debugOrigin}/json/new?about:blank`, {
      method: 'PUT',
    }).then((response) => response.json());
    page = await DevToolsClient.connect(target.webSocketDebuggerUrl);
    await Promise.all([
      page.send('Page.enable'),
      page.send('Runtime.enable'),
      page.send('Network.enable'),
      page.send('Log.enable'),
    ]);
    const browserRequests = [];
    const browserResponses = new Map();
    const browserErrors = [];
    page.on('Network.requestWillBeSent', (event) => {
      browserRequests.push(event);
    });
    page.on('Network.responseReceived', (event) => {
      browserResponses.set(event.requestId, event.response);
    });
    page.on('Runtime.exceptionThrown', (event) => {
      browserErrors.push(event.exceptionDetails?.exception?.description);
    });
    page.on('Log.entryAdded', (event) => {
      if (event.entry?.level === 'error') {
        browserErrors.push(event.entry.text);
      }
    });

    const receiverURL = `${hosted.origin}/optical/`;
    await page.send('Page.navigate', { url: receiverURL });
    try {
      await waitForPage(page);
    } catch (error) {
      throw new Error(
        `${error.message}; host traffic=${JSON.stringify(hosted.traffic)}; browser errors=${JSON.stringify(browserErrors)}`,
      );
    }
    await waitForTrafficToSettle(hosted.traffic);
    assertOnlyOpticalTraffic(hosted.traffic);
    assert.ok(
      hosted.traffic.some(({ url }) => url === '/optical/sw.js'),
      'service worker was not installed',
    );
    assertNoExternalRequests(browserRequests, hosted.origin);

    const appManifest = await page.send('Page.getAppManifest');
    assert.equal(
      appManifest.url,
      `${hosted.origin}/optical/manifest.webmanifest`,
    );
    const installation = JSON.parse(appManifest.data);
    assert.equal(installation.id, '/optical/');
    assert.equal(
      new URL(installation.start_url, appManifest.url).href,
      receiverURL,
    );
    assert.equal(
      await evaluate(
        page,
        "document.querySelector('#receiver-update-status').value",
      ),
      'Receiver is available offline.',
    );

    const cacheState = await evaluate(
      page,
      `(async () => {
        const names = await caches.keys();
        const entries = [];
        for (const name of names) {
          const cache = await caches.open(name);
          entries.push(...(await cache.keys()).map((request) => request.url));
        }
        return { names, entries: entries.sort() };
      })()`,
      true,
    );
    assert.deepEqual(cacheState.names, [`dud-optical-${manifest.buildId}`]);
    assert.deepEqual(
      cacheState.entries,
      manifest.assets
        .filter((asset) => asset.immutable)
        .map((asset) => `${hosted.origin}/optical/${asset.path}`)
        .sort(),
    );

    hosted.traffic.length = 0;
    browserRequests.length = 0;
    browserResponses.clear();
    await page.send('Page.reload');
    await waitForPage(page);
    await waitForTrafficToSettle(hosted.traffic);
    assertOnlyOpticalTraffic(hosted.traffic, false);
    assertNoExternalRequests(browserRequests, hosted.origin);
    assert.equal(
      await evaluate(page, 'navigator.serviceWorker.controller !== null'),
      true,
    );
    const reloadDocument = browserRequests.find(
      (event) => event.type === 'Document' && event.request.url === receiverURL,
    );
    assert.ok(reloadDocument, 'reload document request was not observed');
    const reloadResponse = browserResponses.get(reloadDocument.requestId);
    assert.equal(
      reloadResponse?.fromServiceWorker,
      true,
      'reload did not use the installed service worker',
    );
    assertCachedSecurityHeaders(reloadResponse);

    hosted.traffic.length = 0;
    browserRequests.length = 0;
    browserResponses.clear();
    await receiveFromFakeCamera(page);
    await waitForTrafficToSettle(hosted.traffic);
    assert.deepEqual(hosted.traffic, []);
    assertNoExternalRequests(browserRequests, hosted.origin);
    const download = path.join(downloads, capsuleFilename);
    await saveCapsule(page, download);
    assert.deepEqual(readFileSync(download), capsule);
    assert.deepEqual(hosted.traffic, []);

    browserRequests.length = 0;
    await receiveFromFakeCamera(page);
    await waitForTrafficToSettle(hosted.traffic);
    assert.deepEqual(hosted.traffic, []);
    assertNoExternalRequests(browserRequests, hosted.origin);
    await saveCapsule(page, download);
    assert.deepEqual(readFileSync(download), capsule);
    assert.deepEqual(hosted.traffic, []);

    await page.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0,
    });
    hosted.traffic.length = 0;
    browserRequests.length = 0;
    browserResponses.clear();
    await page.send('Page.reload');
    await waitForPage(page);
    assert.deepEqual(hosted.traffic, []);
    assert.equal(
      await evaluate(page, 'navigator.serviceWorker.controller !== null'),
      true,
    );
    const offlineDocument = browserRequests.find(
      (event) => event.type === 'Document' && event.request.url === receiverURL,
    );
    assert.ok(offlineDocument, 'offline document request was not observed');
    const offlineResponse = browserResponses.get(offlineDocument.requestId);
    assert.equal(
      offlineResponse?.fromServiceWorker,
      true,
      'offline reload did not use the installed service worker',
    );
    assertCachedSecurityHeaders(offlineResponse);

    hosted.traffic.length = 0;
    browserRequests.length = 0;
    browserResponses.clear();
    await receiveFromFakeCamera(page);
    await waitForTrafficToSettle(hosted.traffic);
    assert.deepEqual(hosted.traffic, []);
    assertNoExternalRequests(browserRequests, hosted.origin);
    // Page offline emulation does not disable the service-worker update loader.
    // A host failure also exercises that loader's failure path.
    hosted.rejectUpdates(true);
    await evaluate(
      page,
      "document.querySelector('#receiver-update').click(); true",
    );
    await waitFor(
      () =>
        evaluate(
          page,
          "document.querySelector('#receiver-update-status').value.includes('Could not check') && !document.querySelector('#start').disabled",
        ),
      'offline update failure with camera recovery',
    );
    assert.equal(
      await evaluate(page, 'document.body.dataset.build'),
      manifest.buildId,
    );
    assert.equal(
      await evaluate(page, "document.querySelector('#save-capsule').disabled"),
      false,
    );

    hosted.useBuild(alternate.serve);
    hosted.rejectUpdates(false);
    await page.send('Network.emulateNetworkConditions', {
      offline: false,
      latency: 0,
      downloadThroughput: -1,
      uploadThroughput: -1,
    });
    await evaluate(
      page,
      "document.querySelector('#receiver-update').click(); true",
    );
    await waitFor(
      () =>
        evaluate(
          page,
          `document.querySelector('#receiver-update-status').value.includes('${alternate.manifest.buildId}') && !document.querySelector('#receiver-update').disabled`,
        ),
      'a different installed build to be offered',
    );
    assert.equal(
      await evaluate(page, 'document.body.dataset.build'),
      manifest.buildId,
    );
    await evaluate(
      page,
      "document.querySelector('#receiver-update').click(); true",
    );
    assert.equal(
      await evaluate(
        page,
        "document.querySelector('#receiver-update-status').value",
      ),
      'Save encrypted capsule before loading the update.',
    );
    assert.equal(
      await evaluate(page, 'document.body.dataset.build'),
      manifest.buildId,
    );
    await saveCapsule(page, download);
    assert.deepEqual(readFileSync(download), capsule);
    await evaluate(
      page,
      "document.querySelector('#receiver-update').click(); true",
    );
    await waitFor(
      () =>
        evaluate(
          page,
          `document.body.dataset.build === '${alternate.manifest.buildId}'`,
        ),
      'explicit navigation to the installed receiver build',
    );
    await waitForPage(page);
    assert.equal(await evaluate(page, 'location.search'), '');
    assert.equal(await evaluate(page, 'location.href'), receiverURL);
    assert.deepEqual(await evaluate(page, 'caches.keys()', true), [
      `dud-optical-${alternate.manifest.buildId}`,
    ]);
    for (const offline of [false, true]) {
      await page.send('Network.emulateNetworkConditions', {
        offline,
        latency: 0,
        downloadThroughput: offline ? 0 : -1,
        uploadThroughput: offline ? 0 : -1,
      });
      for (const address of [
        `${hosted.origin}/optical/${manifest.entrypoint}`,
        `${hosted.origin}/optical/index.html`,
        new URL(installation.start_url, appManifest.url).href,
      ]) {
        hosted.traffic.length = 0;
        await page.send('Page.navigate', { url: address });
        await waitForPage(page);
        assert.equal(
          await evaluate(page, 'document.body.dataset.build'),
          alternate.manifest.buildId,
        );
        assert.equal(await evaluate(page, 'location.href'), receiverURL);
        assert.deepEqual(hosted.traffic, []);
      }
    }
    await page.send('Network.emulateNetworkConditions', {
      offline: true,
      latency: 0,
      downloadThroughput: 0,
      uploadThroughput: 0,
    });
    hosted.traffic.length = 0;
    browserRequests.length = 0;
    await page.send('Page.reload');
    await waitForPage(page);
    assert.equal(
      await evaluate(page, 'document.body.dataset.build'),
      alternate.manifest.buildId,
    );
    assert.deepEqual(hosted.traffic, []);
    await receiveFromFakeCamera(page);
    await saveCapsule(page, download);
    assert.deepEqual(readFileSync(download), capsule);
    assert.deepEqual(hosted.traffic, []);
    assertNoExternalRequests(browserRequests, hosted.origin);
    const diagnosticsPath = path.join(
      downloads,
      'dud-optical-diagnostics.json',
    );
    await evaluate(
      page,
      "document.querySelector('#save-diagnostics').click(); true",
    );
    await waitFor(
      () =>
        existsSync(diagnosticsPath) &&
        !existsSync(`${diagnosticsPath}.crdownload`),
      'local diagnostics download',
    );
    const report = JSON.parse(readFileSync(diagnosticsPath, 'utf8'));
    assert.deepEqual(Object.keys(report).sort(), [
      'cameraFramesPerSecond',
      'fountain',
      'observations',
      'pauses',
      'receiverBuild',
      'receiverProfile',
      'schemaVersion',
      'timing',
      'workers',
    ]);
    assert.equal(report.schemaVersion, 1);
    assert.deepEqual(report.pauses, { count: 0, milliseconds: 0 });
    assert.equal(report.receiverBuild, alternate.manifest.buildId);
    assert.deepEqual(report.receiverProfile, {
      id: 'tracked-60',
      framesPerSecond: 60,
      scanMode: 'tracked-four',
    });
    assert.equal(report.observations.usefulFrames, 2);
    assert.ok(report.fountain.processedFrames >= 2);
    assert.equal(report.fountain.pendingFrames, 0);
    assert.ok(report.fountain.maximumPendingFrames <= 32);
    assert.equal(report.observations.totals.useful, 2);
    assert.ok(report.observations.totals.decodedImages > 0);
    assert.equal(
      report.observations.totals.decodedImages,
      report.workers.decodedImages,
    );
    assert.equal(
      report.observations.totals.qrSymbols,
      report.workers.decodedFrames,
    );
    assert.equal(
      report.observations.totals.cameraCallbacks,
      report.timing.cameraCallbacks,
    );
    assert.ok(
      Object.values(report.observations.totals).every((value) =>
        Number.isFinite(value),
      ),
    );
    assert.ok(report.observations.gaps.length <= 32);
    assert.equal(report.observations.ongoingGap, undefined);
    assert.deepEqual(hosted.traffic, []);
  },
);
