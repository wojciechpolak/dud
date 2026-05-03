// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, chmod, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';

const CLIENT_SCRIPT = path.resolve('client/entrypoint.sh');

function runCommand(command, args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: {
        ...process.env,
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function makeExecutable(filePath, content) {
  await writeFile(filePath, content, 'utf8');
  await chmod(filePath, 0o755);
}

test('test command enforces secure curl flags', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-test-'));
  const logFile = path.join(tmpDir, 'curl.log');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey' >&2
printf '%s\n' '* ECH: result: status is succeeded, inner is dud.example.com, outer is cloudflare-ech.com' >&2
printf '%s\n' '* ALPN: server accepted http/1.1' >&2
printf '{"ok":true}\n' > "$output"
`,
  );

  const result = await runCommand('sh', [CLIENT_SCRIPT, 'test'], {
    DUD_CURL_BIN: curlMock,
  });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Transport:/);
  assert.match(result.stdout, /Response:\n{"ok":true}/);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--verbose/);
  assert.match(args, /--ech/);
  assert.match(args, /hard/);
  assert.match(args, /--doh-url/);
  assert.match(args, /cloudflare-dns.com/);
  assert.match(args, /--tlsv1.3/);
});

test('test command allows DUD_ECH_MODE=grease', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-grease-'));
  const logFile = path.join(tmpDir, 'curl.log');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey' >&2
printf '%s\n' '* ECH: result: status is succeeded, inner is dud.example.com, outer is cloudflare-ech.com' >&2
printf '%s\n' '* ALPN: server accepted http/1.1' >&2
printf '{"ok":true}\n' > "$output"
`,
  );

  const result = await runCommand('sh', [CLIENT_SCRIPT, 'test'], {
    DUD_CURL_BIN: curlMock,
    DUD_ECH_MODE: 'grease',
  });

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--ech/);
  assert.match(args, /grease/);
});

test('test command can print TLS and ECH details', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-details-'));
  const logFile = path.join(tmpDir, 'curl.log');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ecPublicKey' >&2
printf '%s\n' '* ECH: result: status is succeeded, inner is dud.example.com, outer is cloudflare-ech.com' >&2
printf '%s\n' '* ALPN: server accepted http/1.1' >&2
printf '{"ok":true}\n' > "$output"
`,
  );

  const result = await runCommand('sh', [CLIENT_SCRIPT, 'test'], {
    DUD_CURL_BIN: curlMock,
  });

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Transport:/);
  assert.match(
    result.stdout,
    /doh resolver: https:\/\/cloudflare-dns.com\/dns-query/,
  );
  assert.match(result.stdout, /ech mode: hard/);
  assert.match(
    result.stdout,
    /tls: TLSv1.3 \/ TLS_AES_256_GCM_SHA384 \/ X25519MLKEM768 \/ id-ecPublicKey/,
  );
  assert.match(result.stdout, /alpn: http\/1.1/);
  assert.match(result.stdout, /ech: succeeded/);
  assert.match(result.stdout, /inner sni: dud.example.com/);
  assert.match(result.stdout, /outer sni: cloudflare-ech.com/);
  assert.match(result.stdout, /Response:\n{"ok":true}/);

  const args = await readFile(logFile, 'utf8');
  assert.match(args, /--verbose/);
});

test('upload command encrypts locally and posts the encrypted file', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-upload-'));
  const filePath = path.join(tmpDir, 'plain.bin');
  const ageLog = path.join(tmpDir, 'age.log');
  const curlLog = path.join(tmpDir, 'curl.log');
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(filePath, 'plaintext', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${ageLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--data-binary" ]; then
    payload="$2"
    shift 2
    continue
  fi
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
cp "\${payload#@}" "${curlPayload}"
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":true}' > "$output"
`,
  );

  const result = await runCommand(
    'sh',
    [
      CLIENT_SCRIPT,
      'upload',
      '--file',
      filePath,
      '--ttl',
      '48h',
      '--delete-after-read',
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^Upload complete$/m);
  assert.match(result.stdout, /^ID: 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe$/m);
  assert.match(result.stdout, /^Expires: 2026-04-20T12:00:00.000Z$/m);
  assert.match(result.stdout, /^Delete after read: yes$/m);
  assert.match(await readFile(ageLog, 'utf8'), /--passphrase/);
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, /x-dud-ttl: 48h/);
  assert.match(curlArgs, /x-dud-delete-after-read: true/);
  assert.match(curlArgs, /x-dud-secret-token: top-secret/);
  assert.equal(await readFile(curlPayload, 'utf8'), 'plaintext');
});

test('upload command can print raw JSON with --json', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-json-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(filePath, 'plaintext', 'utf8');

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  await makeExecutable(
    curlMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    'sh',
    [CLIENT_SCRIPT, 'upload', '--file', filePath, '--json'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.equal(
    result.stdout,
    '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}\n',
  );
});

test('download command passes dashed IDs through to the API', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-download-'));
  const outDir = path.join(tmpDir, 'work');
  const outputPath = path.join(outDir, 'output.bin');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlLog = path.join(tmpDir, 'curl.log');

  await mkdir(outDir);

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const result = await runCommand(
    'sh',
    [
      CLIENT_SCRIPT,
      'download',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '--out',
      outputPath,
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(outputPath, 'utf8'), 'ciphertext');
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(
    curlArgs,
    /\/v1\/files\/3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe/,
  );
});

test('download command still accepts raw IDs unchanged', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-download-raw-'),
  );
  const outDir = path.join(tmpDir, 'work');
  const outputPath = path.join(outDir, 'output.bin');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlLog = path.join(tmpDir, 'curl.log');

  await mkdir(outDir);

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${curlLog}"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf 'ciphertext' > "$output"
`,
  );

  await makeExecutable(
    ageMock,
    `#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    output="$2"
    shift 2
    continue
  fi
  input="$1"
  shift
done
cp "$input" "$output"
`,
  );

  const rawId = '3df75d5c0c3b4f53ac1b8eeb23704fbe';
  const result = await runCommand(
    'sh',
    [CLIENT_SCRIPT, 'download', '--id', rawId, '--out', outputPath],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(outputPath, 'utf8'), 'ciphertext');
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, new RegExp(`/v1/files/${rawId}`));
});

test('flush command posts the secret token header', async () => {
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), 'dud-client-flush-'));
  const logFile = path.join(tmpDir, 'curl.log');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
printf '{"ok":true,"deletedCount":2}\n'
`,
  );

  const result = await runCommand('sh', [CLIENT_SCRIPT, 'flush'], {
    DUD_CURL_BIN: curlMock,
    DUD_SECRET_TOKEN: 'top-secret',
  });

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /x-dud-secret-token: top-secret/);
  assert.match(result.stdout, /deletedCount/);
});
