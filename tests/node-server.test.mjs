// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile, chmod } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import test from 'node:test';

import { startNodeServer } from '../dist/src/node-server.js';
import { TEST_CERT_PEM, TEST_KEY_PEM } from './helpers.mjs';

const CLIENT_BIN = path.resolve('client/bin/dud');

function runCommand(command, args, env = {}, options = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      {
        env: {
          ...process.env,
          ...env,
        },
        maxBuffer: 10 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (error && error.code === undefined) {
          reject(error);
          return;
        }

        resolve({
          code: error?.code ?? 0,
          stdout,
          stderr,
        });
      },
    );

    if (options.input !== undefined) {
      child.stdin.end(options.input);
    }
  });
}

async function makeExecutable(filePath, content) {
  await writeFile(filePath, content, 'utf8');
  await chmod(filePath, 0o755);
}

async function closeServer(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function createCapturingLogger(messages) {
  return {
    error() {},
    log(...args) {
      messages.push(args.join(' '));
    },
  };
}

async function startTestServer(config = {}, options = {}) {
  const dataDir =
    config.dataDir ?? (await mkdtemp(path.join(os.tmpdir(), 'dud-node-data-')));
  const quietLogger = {
    error() {},
    log() {},
  };

  const server = await startNodeServer(
    {
      dataDir,
      listenHost: '127.0.0.1',
      listenPort: 0,
      secretToken: 'top-secret',
      ...config,
    },
    {
      logger: quietLogger,
      ...options,
    },
  );

  const address = server.address();
  const protocol = config.tlsCertFile && config.tlsKeyFile ? 'https' : 'http';
  const baseUrl = `${protocol}://127.0.0.1:${address.port}`;
  return { baseUrl, dataDir, server };
}

async function startLoggedTestServer(config = {}) {
  const messages = [];
  const serverState = await startTestServer(config, {
    logger: createCapturingLogger(messages),
  });

  return {
    ...serverState,
    messages,
  };
}

async function fetchTestEndpoint(baseUrl) {
  const response = await fetch(`${baseUrl}/v1/test`);
  assert.equal(response.status, 200);
  return response;
}

test('node server can upload and download ciphertext through the shared API', async () => {
  const { baseUrl, server } = await startTestServer();

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 201);
    const uploadBody = await upload.json();

    const download = await fetch(`${baseUrl}/v1/files/${uploadBody.id}`);
    assert.equal(download.status, 200);
    assert.equal(await download.text(), 'ciphertext');
  } finally {
    await closeServer(server);
  }
});

test('node server enforces delete-after-read', async () => {
  const { baseUrl, server } = await startTestServer();

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-delete-after-read': 'true',
      },
      body: 'ciphertext',
    });

    const { id } = await upload.json();
    const first = await fetch(`${baseUrl}/v1/files/${id}`);
    assert.equal(first.status, 200);
    assert.equal(await first.text(), 'ciphertext');

    await sleep(25);

    const second = await fetch(`${baseUrl}/v1/files/${id}`);
    assert.equal(second.status, 410);
  } finally {
    await closeServer(server);
  }
});

test('node server handles expiry with the shared service logic', async () => {
  let currentTime = 1_700_000_000_000;
  const { baseUrl, server } = await startTestServer(
    {},
    {
      now: () => currentTime,
      createId: () => '4'.repeat(32),
    },
  );

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '1s',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 201);
    currentTime += 2_000;

    const download = await fetch(`${baseUrl}/v1/files/${'4'.repeat(32)}`);
    assert.equal(download.status, 410);
  } finally {
    await closeServer(server);
  }
});

test('node server rejects invalid secret tokens', async () => {
  const { baseUrl, server } = await startTestServer();

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'wrong',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 403);
  } finally {
    await closeServer(server);
  }
});

test('node server applies max upload size limits', async () => {
  const { baseUrl, server } = await startTestServer({
    maxUploadBytes: 4,
  });

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: 'hello world',
    });

    assert.equal(upload.status, 413);
  } finally {
    await closeServer(server);
  }
});

test('node server flush removes expired objects', async () => {
  let currentTime = 1_700_000_000_000;
  const { baseUrl, server } = await startTestServer(
    {},
    {
      now: () => currentTime,
      createId: () => '5'.repeat(32),
    },
  );

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
        'x-dud-ttl': '1s',
      },
      body: 'ciphertext',
    });
    assert.equal(upload.status, 201);

    currentTime += 2_000;

    const flush = await fetch(`${baseUrl}/v1/admin/flush`, {
      method: 'POST',
      headers: {
        'x-dud-secret-token': 'top-secret',
      },
    });
    assert.equal(flush.status, 200);

    const body = await flush.json();
    assert.equal(body.ok, true);
    assert.equal(body.deletedCount >= 1, true);
  } finally {
    await closeServer(server);
  }
});

test('node server exposes a middleware point for operator policy', async () => {
  const { baseUrl, server } = await startTestServer(
    {},
    {
      beforeRequest(request) {
        if (new URL(request.url).pathname === '/v1/files') {
          return new Response('rate limited', { status: 429 });
        }
        return null;
      },
    },
  );

  try {
    const upload = await fetch(`${baseUrl}/v1/files`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-dud-secret-token': 'top-secret',
      },
      body: 'ciphertext',
    });

    assert.equal(upload.status, 429);
    assert.equal(await upload.text(), 'rate limited');
  } finally {
    await closeServer(server);
  }
});

test('node server logs request summaries', async () => {
  const { baseUrl, messages, server } = await startLoggedTestServer();

  try {
    await fetchTestEndpoint(baseUrl);
    assert.equal(messages.length >= 1, true);
    assert.equal(
      messages.some((message) =>
        /127\.0\.0\.1 GET \/v1\/test -> 200 \d+ms/.test(message),
      ),
      true,
    );
  } finally {
    await closeServer(server);
  }
});

test('node server supports minimal request logging without client IPs', async () => {
  const { baseUrl, messages, server } = await startLoggedTestServer({
    logMode: 'minimal',
  });

  try {
    await fetchTestEndpoint(baseUrl);
    assert.equal(
      messages.some((message) => /GET \/v1\/test -> 200 \d+ms/.test(message)),
      true,
    );
    assert.equal(
      messages.some((message) =>
        /127\.0\.0\.1 GET \/v1\/test -> 200 \d+ms/.test(message),
      ),
      false,
    );
  } finally {
    await closeServer(server);
  }
});

test('node server silent log mode suppresses startup and access logs', async () => {
  const { baseUrl, messages, server } = await startLoggedTestServer({
    logMode: 'silent',
  });

  try {
    await fetchTestEndpoint(baseUrl);
    assert.deepEqual(messages, []);
  } finally {
    await closeServer(server);
  }
});

test('client binary can upload and download through the node server over HTTPS', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-node-client-'));
  const certPath = path.join(tmpDir, 'cert.pem');
  const keyPath = path.join(tmpDir, 'key.pem');
  const inputPath = path.join(tmpDir, 'plain.bin');
  const outputPath = path.join(tmpDir, 'out.bin');
  const curlWrapper = path.join(tmpDir, 'curl-wrapper.mjs');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await writeFile(certPath, TEST_CERT_PEM, 'utf8');
  await writeFile(keyPath, TEST_KEY_PEM, 'utf8');
  await writeFile(inputPath, 'plaintext', 'utf8');

  await makeExecutable(
    curlWrapper,
    `#!/usr/bin/env node
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const args = process.argv.slice(2);
let method = 'GET';
let output = '';
let bodySpec = '';
const headers = new Headers();
let url = '';

for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === '--silent' || arg === '--show-error' || arg === '--fail' || arg === '--tlsv1.3') {
    continue;
  }
  if (arg === '--proto' || arg === '--tls-max' || arg === '--ech' || arg === '--doh-url') {
    i += 1;
    continue;
  }
  if (arg === '-X') {
    method = args[++i];
    continue;
  }
  if (arg === '-H') {
    const header = args[++i];
    const idx = header.indexOf(':');
    headers.append(header.slice(0, idx), header.slice(idx + 1).trim());
    continue;
  }
  if (arg === '--data-binary') {
    bodySpec = args[++i];
    continue;
  }
  if (arg === '--output' || arg === '-o') {
    output = args[++i];
    continue;
  }
  url = arg;
}

const body = bodySpec
  ? await import('node:fs/promises').then(({ readFile }) =>
      bodySpec.startsWith('@') ? readFile(bodySpec.slice(1)) : readFile(bodySpec),
    )
  : undefined;

const response = await fetch(url, { method, headers, body });
if (!response.ok) {
  process.exit(22);
}

const bytes = new Uint8Array(await response.arrayBuffer());
if (output) {
  const { writeFile } = await import('node:fs/promises');
  await writeFile(output, bytes);
} else {
  process.stdout.write(Buffer.from(bytes));
}
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
set -eu
input=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    -R|-i)
      shift 2
      ;;
    --encrypt|--decrypt|--passphrase)
      shift 1
      ;;
    -*)
      shift 1
      ;;
    *)
      input="$1"
      shift 1
      ;;
  esac
done
cp "$input" "$output"
`,
  );

  const { baseUrl, server } = await startTestServer({
    tlsCertFile: certPath,
    tlsKeyFile: keyPath,
  });

  try {
    const upload = await runCommand(
      CLIENT_BIN,
      ['upload', '--file', inputPath, '--json', '--url', baseUrl],
      {
        DUD_SECRET_TOKEN: 'top-secret',
        DUD_CURL_BIN: curlWrapper,
        DUD_AGE_BIN: ageMock,
      },
    );

    assert.equal(upload.code, 0);
    const uploadBody = JSON.parse(upload.stdout);

    const download = await runCommand(
      CLIENT_BIN,
      [
        'download',
        '--id',
        uploadBody.id,
        '--out',
        outputPath,
        '--url',
        baseUrl,
      ],
      {
        DUD_CURL_BIN: curlWrapper,
        DUD_AGE_BIN: ageMock,
      },
    );

    assert.equal(download.code, 0);
    assert.equal(await readFile(outputPath, 'utf8'), 'plaintext');
  } finally {
    await closeServer(server);
  }
});
