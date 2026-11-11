// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { CaptureLifecycle } from './lifecycle.js';
import {
  type CaptureInterruption,
  watchCaptureInterruptions,
} from './capture-interruptions.js';
import {
  captureProfile,
  DEFAULT_CAPTURE_PROFILE,
  type CaptureProfile,
} from './capture-profile.js';
import {
  MAX_TRANSFER_MILLISECONDS,
  type PipelineCompletion,
  type PipelineProgress,
} from './pipeline.js';
import {
  FountainFramePipeline,
  type FountainStats,
} from './fountain-client.js';
import {
  CapsuleReceipt,
  ENCRYPTED_CAPSULE_FILENAME,
} from './capsule-receipt.js';
import { decodeReplayPNG } from './replay-image.js';
import { ScanCadence } from './scan-cadence.js';
import { scanRegion } from './scan-region.js';
import { PresentationCadence } from './presentation-cadence.js';
import { playSyntheticVideo } from './synthetic-video.js';
import {
  ReceiverTimingMeter,
  type ReceiverTimingSnapshot,
} from './timing-metrics.js';
import {
  ProgressGapMeter,
  formatProgressGaps,
  type ProgressGapSnapshot,
} from './progress-gaps.js';
import { ReceiverUpdates, type ReceiverBuild } from './receiver-updates.js';
import {
  QRWorkerPool,
  recommendedQRWorkerCount,
  type WorkerPoolStats,
} from './worker-pool.js';

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) {
    throw new Error(`Missing receiver element ${id}`);
  }
  return found as T;
}

const receiverURL = new URL(location.href);
if (
  !receiverURL.search &&
  /^index(?:\.[a-f0-9]{12})?\.html$/.test(
    receiverURL.pathname.slice(receiverURL.pathname.lastIndexOf('/') + 1),
  )
) {
  const publicURL = new URL('./', receiverURL);
  publicURL.hash = receiverURL.hash;
  history.replaceState(history.state, '', publicURL.href);
}

const camera = element<HTMLSelectElement>('camera');
const profile = element<HTMLSelectElement>('capture-profile');
const startButton = element<HTMLButtonElement>('start');
const pauseButton = element<HTMLButtonElement>('pause');
const stopButton = element<HTMLButtonElement>('stop');
const saveButton = element<HTMLButtonElement>('save-capsule');
const replayButton = element<HTMLButtonElement>('replay');
const replayFiles = element<HTMLInputElement>('replay-files');
const video = element<HTMLVideoElement>('camera-view');
const idleField = element<HTMLDivElement>('idle-field');
const progress = element<HTMLProgressElement>('progress');
const progressLabel = element<HTMLOutputElement>('progress-label');
const stripeProgress = element<HTMLElement>('stripe-progress');
const stripeRows = element<HTMLDivElement>('stripe-rows');
const status = element<HTMLOutputElement>('status');
const detail = element<HTMLOutputElement>('status-detail');
const statistics = element<HTMLOutputElement>('statistics');
const buildID = document.body.dataset.build ?? 'unknown';
const updateButton = element<HTMLButtonElement>('receiver-update');
const updateStatus = element<HTMLOutputElement>('receiver-update-status');
const gapDetails = element<HTMLOutputElement>('progress-gaps');
const diagnosticsButton = element<HTMLButtonElement>('save-diagnostics');
const scanImageButton = element<HTMLButtonElement>('save-scan-image');

let lifecycle = new CaptureLifecycle();
let workerLifecycle = new CaptureLifecycle();
let pool: QRWorkerPool | undefined;
let running = false;
let paused = false;
let pausedAt: number | undefined;
let pauseCount = 0;
let pausedMilliseconds = 0;
let receiptDeadlineStarted = false;
let capturePending = false;
let cameraFramesPerSecond: number | undefined;
let latestWorkerStats: WorkerPoolStats | undefined;
let stripeRowElements: StripeRowElements[] = [];
let cadenceSkips = 0;
let runGeneration = 0;
let captureGeneration = 0;
let receiptBusy = false;
let checkingUpdate = false;
let unsavedReceipt = false;
let availableUpdateURL: string | undefined;
let receiverUpdates: ReceiverUpdates | undefined;
let activeCaptureProfile: CaptureProfile = DEFAULT_CAPTURE_PROFILE;
const receipt = new CapsuleReceipt();
const timingMeter = new ReceiverTimingMeter();
const gapMeter = new ProgressGapMeter();
interface ReceiverDiagnostics {
  schemaVersion: number;
  receiverBuild: string;
  receiverProfile: CaptureProfile;
  cameraFramesPerSecond?: number;
  observations: ProgressGapSnapshot;
  timing: ReceiverTimingSnapshot;
  workers?: WorkerPoolStats;
  fountain?: FountainStats;
  pauses: { count: number; milliseconds: number };
}
let retainedDiagnostics: ReceiverDiagnostics | undefined;
const progressPresentation = new PresentationCadence<PipelineProgress>(
  100,
  renderProgress,
  (value) => value.stripeIndex,
);
const statisticsPresentation = new PresentationCadence<WorkerPoolStats>(
  100,
  renderStatistics,
);

interface StripeRowElements {
  row: HTMLDivElement;
  count: HTMLOutputElement;
  percent: HTMLOutputElement;
  meter: HTMLProgressElement;
}

const pipeline = new FountainFramePipeline({
  onFrameDisposition: (value) => gapMeter.count(value),
  onProgress: showProgress,
  onComplete: complete,
  onSessionChange: () => {
    if (paused) {
      return;
    }
    setStatus(
      'Another stream is in view',
      'Return to the original sender or press Stop / reset to receive the new stream.',
      'warning',
    );
  },
  onUnsupported: () => {
    if (paused) {
      return;
    }
    setStatus(
      'Unsupported optical format',
      'Point the camera at a DUD optical transfer sender using dud/optical/1.',
      'warning',
    );
  },
  onRejected: () => {
    // Frame dispositions count rejections without interrupting receipt status.
  },
  onFatal: (message) => {
    stopRun();
    setStatus('Transfer stopped', message, 'error');
  },
});

startButton.addEventListener('click', () => {
  startCamera().catch((error: unknown) => {
    stopRun();
    setStatus(
      'Camera did not start',
      error instanceof Error && error.name === 'NotAllowedError'
        ? 'Allow camera access in this browser, then press Start camera again.'
        : `${error instanceof Error ? error.message : 'Camera input could not be opened.'} Check the camera and press Start camera again.`,
      'error',
    );
  });
});
pauseButton.addEventListener('click', pauseCamera);
stopButton.addEventListener('click', () => {
  stopRun();
  resetGapDiagnostics();
  replayFiles.value = '';
  replayButton.disabled = true;
  stopButton.disabled = true;
  setStatus(
    'Receiver reset',
    'Progress cleared. Press Start camera to begin.',
    'idle',
  );
});
saveButton.addEventListener('click', () => {
  if (!receipt.available) {
    return;
  }
  const url = URL.createObjectURL(receipt.blob());
  const download = document.createElement('a');
  download.href = url;
  download.download = ENCRYPTED_CAPSULE_FILENAME;
  download.hidden = true;
  document.body.append(download);
  download.click();
  download.remove();
  unsavedReceipt = false;
  setTimeout(() => URL.revokeObjectURL(url), 0);
});
updateButton.addEventListener('click', () => {
  void checkReceiverUpdate();
});
diagnosticsButton.addEventListener('click', () => {
  if (paused) {
    retainDiagnostics();
  }
  if ((receiptBusy && !paused) || !retainedDiagnostics) {
    return;
  }
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(retainedDiagnostics, null, 2)], {
      type: 'application/json',
    }),
  );
  const download = document.createElement('a');
  download.href = url;
  download.download = 'dud-optical-diagnostics.json';
  download.hidden = true;
  document.body.append(download);
  download.click();
  download.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
});
scanImageButton.addEventListener('click', () => {
  void saveScanImage();
});

async function saveScanImage(): Promise<void> {
  if (!running || !video.srcObject || scanImageButton.disabled) {
    return;
  }
  const generation = captureGeneration;
  scanImageButton.disabled = true;
  let bitmap: ImageBitmap | undefined;
  try {
    bitmap = await createImageBitmap(video);
    if (generation !== captureGeneration) {
      return;
    }
    const region = scanRegion(bitmap.width, bitmap.height);
    const canvas = new OffscreenCanvas(region.scanSize, region.scanSize);
    const context = canvas.getContext('2d');
    if (!context) {
      throw new Error('2D canvas is unavailable');
    }
    context.drawImage(
      bitmap,
      region.sourceX,
      region.sourceY,
      region.sourceSize,
      region.sourceSize,
      0,
      0,
      region.scanSize,
      region.scanSize,
    );
    const blob = await canvas.convertToBlob({ type: 'image/png' });
    if (generation !== captureGeneration) {
      return;
    }
    const url = URL.createObjectURL(blob);
    const download = document.createElement('a');
    download.href = url;
    download.download = `dud-optical-scan-${buildID}.png`;
    download.hidden = true;
    document.body.append(download);
    download.click();
    download.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  } catch {
    if (generation === captureGeneration) {
      detail.value =
        'Scan image could not be saved. Keep the camera running and try again.';
    }
  } finally {
    bitmap?.close();
    if (generation === captureGeneration) {
      scanImageButton.disabled = !running || !video.srcObject;
    }
  }
}
replayButton.addEventListener('click', () => {
  replayRecordedFrames().catch((error: unknown) => {
    stopRun();
    setStatus(
      'Replay stopped',
      error instanceof Error
        ? error.message
        : 'Recorded frames could not be read.',
      'error',
    );
  });
});
replayFiles.addEventListener('change', () => {
  replayButton.disabled =
    checkingUpdate || receiptBusy || (replayFiles.files?.length ?? 0) === 0;
});

async function startCamera(): Promise<void> {
  if (checkingUpdate || (receiptBusy && !paused)) {
    return;
  }
  const resuming = paused;
  if (resuming) {
    finishPause();
    releaseCapture();
    timingMeter.breakInterval();
    gapMeter.finish();
  } else {
    stopRun();
    resetGapDiagnostics();
    activeCaptureProfile = captureProfile(profile.value);
  }
  receiptBusy = true;
  updateButton.disabled = true;
  const generation = captureGeneration;
  startButton.disabled = true;
  pauseButton.disabled = true;
  stopButton.disabled = false;
  replayButton.disabled = true;
  diagnosticsButton.disabled = true;
  camera.disabled = true;
  profile.disabled = true;
  setStatus('Starting camera', 'Waiting for camera permission.', 'active');
  const watchTracks = beginInterruptionGuards(true);
  try {
    await startCameraRun(generation, watchTracks);
  } catch (error) {
    if (generation === captureGeneration) {
      if (resuming) {
        pauseCamera();
        setStatus(
          'Camera did not resume',
          'Progress is kept. Check camera permission and press Resume camera, or press Stop / reset to clear the transfer.',
          'error',
        );
        return;
      }
      throw error;
    }
  }
}

async function startCameraRun(
  generation: number,
  watchTracks: (tracks: readonly MediaStreamTrack[]) => void,
): Promise<void> {
  const selected = camera.value;
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: selected
      ? {
          deviceId: { exact: selected },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: activeCaptureProfile.framesPerSecond },
        }
      : {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: activeCaptureProfile.framesPerSecond },
        },
  });
  if (generation !== captureGeneration) {
    for (const track of stream.getTracks()) {
      track.stop();
    }
    return;
  }
  for (const track of stream.getTracks()) {
    lifecycle.addTrack(track);
  }
  watchTracks(stream.getTracks());
  video.srcObject = stream;
  await video.play();
  if (generation !== captureGeneration) {
    return;
  }
  const cameraSettings = stream.getVideoTracks()[0]?.getSettings();
  cameraFramesPerSecond = cameraSettings?.frameRate;
  const activeDeviceID = cameraSettings?.deviceId ?? selected;
  await refreshCameras(activeDeviceID, generation);
  if (generation !== captureGeneration) {
    return;
  }
  if (!pool) {
    beginWorkers();
  }
  running = true;
  idleField.hidden = true;
  scanImageButton.disabled = false;
  video.hidden = false;
  startButton.disabled = true;
  startButton.textContent = 'Start camera';
  pauseButton.disabled = false;
  stopButton.disabled = false;
  replayButton.disabled = true;
  profile.disabled = true;
  camera.disabled = true;
  setStatus(
    'Looking for frames',
    "Keep the sender's QR display inside the guide.",
    'active',
  );
  if (!receiptDeadlineStarted) {
    startReceiptDeadline();
  }
  startCaptureLoop();
}

function pauseCamera(): void {
  if (!receiptBusy || paused) {
    return;
  }
  paused = true;
  pausedAt = performance.now();
  pauseCount++;
  releaseCapture();
  beginInterruptionGuards(false);
  progressPresentation.flush();
  statisticsPresentation.flush();
  timingMeter.breakInterval();
  gapMeter.finish();
  retainDiagnostics();
  startButton.textContent = 'Resume camera';
  startButton.disabled = false;
  pauseButton.disabled = true;
  showPausedStatus();
}

function showPausedStatus(): void {
  setStatus(
    'Receipt paused',
    'Progress is kept. Press Resume camera to continue.',
    'idle',
  );
}

function finishPause(): void {
  if (pausedAt !== undefined) {
    pausedMilliseconds += Math.max(0, performance.now() - pausedAt);
  }
  pausedAt = undefined;
  paused = false;
}

const interruptionMessages: Readonly<Record<CaptureInterruption, string>> = {
  background: 'The receiver moved to the background.',
  'camera-change': 'The available cameras changed.',
  'camera-ended': 'Camera permission or input ended.',
  'camera-muted': 'The camera stopped delivering frames.',
  'memory-pressure': 'The browser reported low memory.',
  'page-exit': 'The receiver page is closing.',
  'renderer-loss': 'The browser renderer stopped.',
  rotation: 'The device orientation changed.',
  'service-worker-change': 'A different receiver build became active.',
  suspension: 'The receiver tab was suspended.',
};

function beginInterruptionGuards(
  watchCameras: boolean,
): (tracks: readonly MediaStreamTrack[]) => void {
  return watchCaptureInterruptions(
    lifecycle,
    {
      page: window,
      document,
      orientation: screen.orientation,
      mediaDevices: watchCameras ? navigator.mediaDevices : undefined,
      serviceWorker:
        'serviceWorker' in navigator ? navigator.serviceWorker : undefined,
    },
    (reason) => {
      stopRun();
      setStatus(
        'Transfer stopped',
        `${interruptionMessages[reason]} Incomplete encrypted bytes were cleared. Restart the receiver and sender.`,
        'error',
      );
    },
  );
}

function startReceiptDeadline(): void {
  receiptDeadlineStarted = true;
  const deadline = window.setTimeout(() => {
    stopRun();
    setStatus(
      'Transfer stopped',
      'Camera time limit 15 minutes reached. Restart the receiver and sender.',
      'error',
    );
  }, MAX_TRANSFER_MILLISECONDS);
  workerLifecycle.addCleanup(() => window.clearTimeout(deadline));
}

function beginWorkers(): void {
  const generation = runGeneration;
  pool = new QRWorkerPool(
    recommendedQRWorkerCount(navigator.hardwareConcurrency),
    workerLifecycle,
    {
      onImage: (image) => {
        if (generation === runGeneration) {
          gapMeter.image(image);
        }
      },
      onFrame: (frame) => {
        if (generation === runGeneration) {
          const started = performance.now();
          pipeline.accept(frame);
          if (generation === runGeneration) {
            timingMeter.frameHandler(performance.now() - started);
          }
        }
      },
      onStats: (stats) => {
        if (generation !== runGeneration) {
          return;
        }
        gapMeter.count(
          'submittedImages',
          stats.submitted - (latestWorkerStats?.submitted ?? 0),
        );
        gapMeter.count(
          'busyDrops',
          stats.dropped - (latestWorkerStats?.dropped ?? 0),
        );
        latestWorkerStats = stats;
        showStatistics(stats);
      },
      onError: (message) => {
        if (generation !== runGeneration) {
          return;
        }
        stopRun();
        setStatus('QR decoder stopped', message, 'error');
      },
    },
    activeCaptureProfile.scanMode,
  );
}

function startCaptureLoop(): void {
  const generation = captureGeneration;
  const cadence = new ScanCadence(activeCaptureProfile.framesPerSecond);
  let callbackId = 0;
  let videoCallback = false;
  const capture = (timestamp: number): void => {
    if (!running || generation !== captureGeneration) {
      return;
    }
    timingMeter.cameraCallback(timestamp);
    gapMeter.count('cameraCallbacks');
    if (cadence.shouldScan(timestamp)) {
      captureCameraFrame();
    } else {
      cadenceSkips++;
      gapMeter.count('cadenceSkips');
    }
    schedule();
  };
  const schedule = (): void => {
    if (!running || generation !== captureGeneration) {
      return;
    }
    videoCallback = 'requestVideoFrameCallback' in video;
    callbackId = videoCallback
      ? video.requestVideoFrameCallback((timestamp) => capture(timestamp))
      : requestAnimationFrame(capture);
  };
  lifecycle.addCleanup(() => {
    if (videoCallback) {
      video.cancelVideoFrameCallback(callbackId);
    } else {
      cancelAnimationFrame(callbackId);
    }
  });
  schedule();
}

function captureCameraFrame(): void {
  if (!pool || capturePending) {
    pool?.drop();
    return;
  }
  if (!pool.canAccept || !pipeline.canAccept) {
    pool.drop();
    return;
  }
  capturePending = true;
  const generation = captureGeneration;
  const activePool = pool;
  const captureStarted = performance.now();
  createImageBitmap(video)
    .then((bitmap) => {
      if (generation !== captureGeneration) {
        bitmap.close();
        return;
      }
      gapMeter.bitmap(performance.now() - captureStarted);
      if (!pipeline.canAccept) {
        bitmap.close();
        activePool.drop();
        return;
      }
      activePool.submit(bitmap);
    })
    .catch(() => {
      if (generation === captureGeneration) {
        gapMeter.bitmap(performance.now() - captureStarted);
        gapMeter.count('bitmapFailures');
        setStatus(
          'Camera frame unavailable',
          'Keep the receiver visible and try repositioning the phone.',
          'warning',
        );
      }
    })
    .finally(() => {
      if (generation === captureGeneration) {
        capturePending = false;
      }
    });
}

async function refreshCameras(
  selected: string,
  generation: number,
): Promise<void> {
  const devices = (await navigator.mediaDevices.enumerateDevices()).filter(
    (device) => device.kind === 'videoinput',
  );
  if (generation !== captureGeneration) {
    return;
  }
  camera.replaceChildren();
  for (const [index, device] of devices.entries()) {
    const option = document.createElement('option');
    option.value = device.deviceId;
    option.textContent = device.label || `Camera ${index + 1}`;
    option.selected = device.deviceId === selected;
    camera.append(option);
  }
  camera.disabled = devices.length < 2;
}

async function replayRecordedFrames(): Promise<void> {
  if (checkingUpdate) {
    return;
  }
  const files = Array.from(replayFiles.files ?? []).sort((left, right) =>
    left.name.localeCompare(right.name),
  );
  if (files.length === 0) {
    throw new Error('Choose PNG frames first.');
  }
  stopRun();
  resetGapDiagnostics();
  receiptBusy = true;
  updateButton.disabled = true;
  const generation = runGeneration;
  try {
    await replayRun(files, generation);
  } catch (error) {
    if (generation === runGeneration) {
      throw error;
    }
  }
}

async function replayRun(files: File[], generation: number): Promise<void> {
  pipeline.reset();
  activeCaptureProfile = captureProfile(profile.value);
  beginInterruptionGuards(false);
  startButton.disabled = true;
  stopButton.disabled = false;
  replayButton.disabled = true;
  profile.disabled = true;
  setStatus('Preparing replay', 'Starting the QR decoder.', 'active');
  startReceiptDeadline();
  beginWorkers();
  await pool?.ready;
  if (generation !== runGeneration) {
    return;
  }
  running = true;
  setStatus(
    'Replaying recorded frames',
    `${files.length} images use the live QR decoder path.`,
    'active',
  );
  const controller = new AbortController();
  lifecycle.addCleanup(() => controller.abort());
  await playSyntheticVideo(
    recordedBitmaps(files, controller.signal),
    {
      submit: (bitmap) => {
        if (!pipeline.canAccept) {
          bitmap.close();
          pool?.drop();
          return false;
        }
        return (pool as QRWorkerPool).submit(bitmap);
      },
      discard: (bitmap) => bitmap.close(),
    },
    controller.signal,
  );
  if (running) {
    detail.value =
      'Replay input ended. The receiver is waiting for in-flight decoder work.';
  }
}

async function* recordedBitmaps(
  files: File[],
  signal: AbortSignal,
): AsyncIterable<ImageBitmap> {
  for (const file of files) {
    if (signal.aborted) {
      return;
    }
    const bitmap = await decodeReplayPNG(file);
    if (signal.aborted) {
      bitmap.close();
      return;
    }
    yield bitmap;
  }
}

function showProgress(value: PipelineProgress): void {
  timingMeter.usefulProgress(performance.now(), value.usefulFrames);
  gapMeter.usefulProgress(performance.now(), value.usefulFrames);
  if (value.usefulFrames === value.requiredFrames) {
    gapMeter.finish();
  }
  progressPresentation.offer(value, performance.now());
}

function renderProgress(value: PipelineProgress): void {
  progress.value = Math.min(100, value.percent);
  progressLabel.value = `${value.percent.toFixed(1)}%`;
  showStripeProgress(value);
  if (paused) {
    timingMeter.breakInterval();
    gapMeter.finish();
    showPausedStatus();
    return;
  }
  setStatus(
    'Receiving encrypted bytes',
    "Keep the sender's QR display inside the guide.",
    'active',
  );
}

function showStripeProgress(value: PipelineProgress): void {
  ensureStripeRows(value.stripeCount);
  const elements = stripeRowElements[value.stripeIndex];
  if (!elements) {
    return;
  }
  const percent = Math.min(
    100,
    (value.independentRows / value.sourceCount) * 100,
  );
  elements.count.value = `${value.independentRows} / ${value.sourceCount}`;
  elements.percent.value = `${percent.toFixed(1)}%`;
  elements.meter.max = value.sourceCount;
  elements.meter.value = value.independentRows;
  elements.meter.setAttribute(
    'aria-label',
    `Stripe ${value.stripeIndex + 1}: ${value.independentRows} of ${value.sourceCount} independent frames`,
  );
  elements.row.dataset.complete = String(
    value.independentRows === value.sourceCount,
  );
}

function ensureStripeRows(count: number): void {
  if (stripeRowElements.length === count) {
    return;
  }
  stripeRowElements = Array.from({ length: count }, (_, index) => {
    const row = document.createElement('div');
    row.className = 'stripe-row';
    row.dataset.complete = 'false';
    row.setAttribute('role', 'listitem');

    const name = document.createElement('span');
    name.className = 'stripe-name';
    name.textContent = `Stripe ${index + 1}`;

    const rowCount = document.createElement('output');
    rowCount.className = 'stripe-count';
    rowCount.value = 'Waiting';

    const percent = document.createElement('output');
    percent.className = 'stripe-percent';
    percent.value = '0.0%';

    const meter = document.createElement('progress');
    meter.className = 'stripe-meter';
    meter.max = 1;
    meter.value = 0;
    meter.setAttribute(
      'aria-label',
      `Stripe ${index + 1}: waiting for a frame`,
    );

    row.append(name, rowCount, percent, meter);
    return { row, count: rowCount, percent, meter };
  });
  stripeRows.replaceChildren(...stripeRowElements.map(({ row }) => row));
  stripeProgress.hidden = false;
}

function clearStripeProgress(): void {
  stripeRowElements = [];
  stripeRows.replaceChildren();
  stripeProgress.hidden = true;
}

function complete(value: PipelineCompletion): void {
  progressPresentation.flush();
  const workerStats = latestWorkerStats;
  const skipped = cadenceSkips;
  const rate = cameraRate();
  const timing = timingStatistics(workerStats);
  finishPause();
  const pauseTime = pausedMilliseconds;
  stopRun(true);
  receipt.accept(value.capsule);
  unsavedReceipt = true;
  saveButton.disabled = false;
  stopButton.disabled = false;
  progress.value = 100;
  progressLabel.value = '100%';
  const elapsed = formatDuration(value.elapsedMilliseconds);
  setStatus(
    'Optical receipt complete',
    `${formatBytes(value.byteLength)} verified in ${elapsed}. Save the encrypted capsule.`,
    'complete',
  );
  const decoder = workerStats
    ? `, ${workerStats.submitted} submitted, ${workerStats.dropped} busy drops, ${workerStats.decodedImages} scanned images, ${workerStats.decodedFrames} QR symbols, ${workerStats.multiSymbolImages} multi-symbol images, ${workerStats.maximumSymbolsPerImage} max symbols/image, ${meanDecodeMilliseconds(workerStats).toFixed(1)} ms mean decode${trackingStatistics(workerStats)}`
    : '';
  statistics.value = `${value.usefulFrames} useful frames, ${value.rejectedFrames} rejected frames, ${formatRate(value.byteLength, value.elapsedMilliseconds)} average${decoder}${rate}, ${skipped} cadence skips${timing}${pauseTime > 0 ? `, Camera paused for ${formatDuration(pauseTime)}` : ''}, build ${buildID}`;
}

function showStatistics(value: WorkerPoolStats): void {
  statisticsPresentation.offer(value, performance.now());
}

function renderStatistics(value: WorkerPoolStats): void {
  gapDetails.value = formatProgressGaps(gapMeter.snapshot(performance.now()));
  const mean = meanDecodeMilliseconds(value);
  const scan =
    value.scanDimension === 0 ? '' : `, ${value.scanDimension} px scan`;
  statistics.value = `${value.submitted} submitted, ${value.dropped} busy drops, ${value.decodedImages} scanned images, ${value.decodedFrames} QR symbols, ${value.multiSymbolImages} multi-symbol images, ${value.maximumSymbolsPerImage} max symbols/image, ${mean.toFixed(1)} ms mean decode${scan}${trackingStatistics(value)}${cameraRate()}, ${cadenceSkips} cadence skips${timingStatistics(value)}, build ${buildID}`;
}

function timingStatistics(value: WorkerPoolStats | undefined): string {
  const timing = timingMeter.snapshot();
  if (timing.cameraCallbacks === 0 && (value?.decodedImages ?? 0) === 0) {
    return '';
  }
  const qrMaximum = value?.maximumDecodeMilliseconds ?? 0;
  const slowQR = value?.decodesOverThreshold ?? 0;
  const fountain = pipeline.snapshot();
  const scan = value?.scanDiagnostics;
  return `, max progress gap ${timing.maximumUsefulGapMilliseconds.toFixed(0)} ms (${timing.usefulGapsOverThreshold} >250 ms), max camera gap ${timing.maximumCameraGapMilliseconds.toFixed(0)} ms (${timing.cameraGapsOverThreshold} >250 ms), max QR decode ${qrMaximum.toFixed(0)} ms (${slowQR} >250 ms), max frame handler ${timing.maximumFrameHandlerMilliseconds.toFixed(0)} ms (${timing.frameHandlersOverThreshold} >250 ms), max fountain work ${fountain.maximumProcessingMilliseconds.toFixed(1)} ms, max fountain round trip ${fountain.maximumRoundTripMilliseconds.toFixed(1)} ms, ${scan?.finderCandidates ?? 0} finder candidates, ${scan?.matrixAttempts ?? 0} matrix attempts, ${scan?.exhaustedScans ?? 0} exhausted scans`;
}

function trackingStatistics(value: WorkerPoolStats): string {
  return value.trackedScans === 0
    ? ''
    : `, ${value.fullScans} full scans, ${value.trackedScans} tracked regions, ${value.trackedSymbols} tracked symbols`;
}

function cameraRate(): string {
  const negotiated =
    cameraFramesPerSecond === undefined
      ? ''
      : `, ${cameraFramesPerSecond.toFixed(1)} camera FPS`;
  return `${negotiated}, ${activeCaptureProfile.framesPerSecond} FPS cap`;
}

function meanDecodeMilliseconds(value: WorkerPoolStats): number {
  return value.decodedImages === 0
    ? 0
    : value.decodeMilliseconds / value.decodedImages;
}

function retainDiagnostics(): void {
  retainedDiagnostics = {
    schemaVersion: 1,
    receiverBuild: buildID,
    receiverProfile: { ...activeCaptureProfile },
    cameraFramesPerSecond,
    observations: gapMeter.snapshot(performance.now()),
    timing: timingMeter.snapshot(),
    workers: latestWorkerStats ? { ...latestWorkerStats } : undefined,
    fountain: pipeline.snapshot(),
    pauses: {
      count: pauseCount,
      milliseconds:
        pausedMilliseconds +
        (pausedAt === undefined
          ? 0
          : Math.max(0, performance.now() - pausedAt)),
    },
  };
  gapDetails.value = formatProgressGaps(retainedDiagnostics.observations);
  diagnosticsButton.disabled = false;
}

function releaseCapture(): void {
  captureGeneration++;
  running = false;
  capturePending = false;
  scanImageButton.disabled = true;
  lifecycle.stop();
  lifecycle = new CaptureLifecycle();
  video.pause();
  video.srcObject = null;
  video.hidden = true;
  idleField.hidden = false;
}

function stopRun(preserveStripeProgress = false): void {
  if (receiptBusy) {
    retainDiagnostics();
  }
  finishPause();
  runGeneration++;
  releaseCapture();
  receiptBusy = false;
  updateButton.disabled = checkingUpdate || !receiverUpdates;
  unsavedReceipt = false;
  cameraFramesPerSecond = undefined;
  workerLifecycle.stop();
  workerLifecycle = new CaptureLifecycle();
  receiptDeadlineStarted = false;
  pool = undefined;
  startButton.disabled = checkingUpdate;
  startButton.textContent = 'Start camera';
  pauseButton.disabled = true;
  stopButton.disabled = retainedDiagnostics === undefined;
  replayButton.disabled =
    checkingUpdate || (replayFiles.files?.length ?? 0) === 0;
  profile.disabled = false;
  camera.disabled = camera.options.length < 2;
  pipeline.reset();
  latestWorkerStats = undefined;
  cadenceSkips = 0;
  pauseCount = 0;
  pausedMilliseconds = 0;
  timingMeter.reset();
  gapMeter.reset();
  progressPresentation.reset();
  statisticsPresentation.reset();
  receipt.clear();
  saveButton.disabled = true;
  if (!preserveStripeProgress) {
    clearStripeProgress();
    progress.value = 0;
    progressLabel.value = '0%';
    statistics.value = 'No frames received.';
  }
}

function resetGapDiagnostics(): void {
  retainedDiagnostics = undefined;
  gapDetails.value = 'No progress gaps recorded.';
  diagnosticsButton.disabled = true;
  gapMeter.reset();
}

function setStatus(
  message: string,
  explanation: string,
  state: 'idle' | 'active' | 'warning' | 'error' | 'complete',
): void {
  status.value = message;
  detail.value = explanation;
  document.body.dataset.state = state;
}

function formatBytes(value: number): string {
  if (value >= 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
  }
  if (value >= 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }
  return `${value} bytes`;
}

function formatDuration(milliseconds: number): string {
  const seconds = milliseconds / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)} seconds`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes} min ${(seconds - minutes * 60).toFixed(1)} sec`;
}

function formatRate(bytes: number, milliseconds: number): string {
  if (milliseconds <= 0) {
    return 'rate unavailable';
  }
  return `${((bytes * 1000) / milliseconds / 1024).toFixed(1)} KiB/s`;
}

function offerReceiverUpdate(build: ReceiverBuild, scope: string): void {
  availableUpdateURL = new URL(build.entrypoint, scope).href;
  updateButton.textContent = 'Load receiver update';
  updateStatus.value = `Receiver ${build.buildID} is ready. Save any completed capsule before loading the update.`;
}

async function checkReceiverUpdate(): Promise<void> {
  if (receiptBusy || checkingUpdate || !receiverUpdates) {
    return;
  }
  if (availableUpdateURL) {
    if (unsavedReceipt) {
      updateStatus.value = 'Save encrypted capsule before loading the update.';
      return;
    }
    location.assign(availableUpdateURL);
    return;
  }
  checkingUpdate = true;
  updateButton.disabled = true;
  startButton.disabled = true;
  replayButton.disabled = true;
  updateStatus.value = 'Checking for a receiver update.';
  try {
    const build = await receiverUpdates.check();
    if (build.buildID === buildID) {
      updateStatus.value = `Receiver ${buildID} is up to date.`;
    }
  } catch {
    updateStatus.value =
      'Could not check for updates. Connect to the receiver host and try again with the camera off.';
  } finally {
    checkingUpdate = false;
    updateButton.disabled = receiptBusy;
    startButton.disabled = receiptBusy;
    replayButton.disabled =
      receiptBusy || (replayFiles.files?.length ?? 0) === 0;
  }
}

if ('serviceWorker' in navigator) {
  receiverUpdates = new ReceiverUpdates(
    navigator.serviceWorker,
    buildID,
    offerReceiverUpdate,
  );
  checkingUpdate = true;
  startButton.disabled = true;
  window.addEventListener('load', () => {
    receiverUpdates!
      .install()
      .then(() => {
        if (!updateStatus.value) {
          updateStatus.value = 'Receiver is available offline.';
        }
      })
      .catch(() => {
        updateStatus.value =
          'Offline installation failed. Camera receipt still works on this page.';
      })
      .finally(() => {
        checkingUpdate = false;
        updateButton.disabled = receiptBusy;
        startButton.disabled = receiptBusy;
        replayButton.disabled =
          receiptBusy || (replayFiles.files?.length ?? 0) === 0;
      });
  });
} else {
  updateStatus.value = 'Receiver updates require service-worker support.';
}

setStatus('Ready', 'Press Start camera to begin.', 'idle');
showStatistics(
  latestWorkerStats ?? {
    submitted: 0,
    dropped: 0,
    decodedImages: 0,
    decodedFrames: 0,
    multiSymbolImages: 0,
    maximumSymbolsPerImage: 0,
    decodeMilliseconds: 0,
    maximumDecodeMilliseconds: 0,
    decodesOverThreshold: 0,
    scanDimension: 0,
    fullScans: 0,
    trackedScans: 0,
    trackedSymbols: 0,
  },
);
