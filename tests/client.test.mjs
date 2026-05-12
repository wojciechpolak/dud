// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, chmod, mkdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';

const CLIENT_SCRIPT = path.resolve('client/entrypoint.sh');

function runCommand(command, args, env = {}, options = {}) {
  return new Promise((resolve, reject) => {
    const stdinMode = options.input === undefined ? 'ignore' : 'pipe';
    const child = spawn(command, args, {
      env: {
        ...process.env,
        ...env,
      },
      stdio: [stdinMode, 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    if (options.input !== undefined) {
      child.stdin.end(options.input);
    }

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
  const qrLog = path.join(tmpDir, 'qr.log');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');

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

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${qrLog}"
printf '[qr]\\n'
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
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^Upload complete$/m);
  assert.match(result.stdout, /^ID: 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe$/m);
  assert.match(result.stdout, /^Expires: 2026-04-20T12:00:00.000Z$/m);
  assert.match(result.stdout, /^Delete after read: yes$/m);
  assert.match(result.stdout, /\nQR Code:\n\[qr\]\n?$/);
  assert.match(await readFile(ageLog, 'utf8'), /--passphrase/);
  const curlArgs = await readFile(curlLog, 'utf8');
  assert.match(curlArgs, /x-dud-ttl: 48h/);
  assert.match(curlArgs, /x-dud-delete-after-read: true/);
  assert.match(curlArgs, /x-dud-secret-token: top-secret/);
  assert.equal(await readFile(curlPayload, 'utf8'), 'plaintext');
  assert.match(
    await readFile(qrLog, 'utf8'),
    /-t\nansiutf8\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe/,
  );
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

test('upload command can upload a literal message with -m', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-message-'),
  );
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

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
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    'sh',
    [CLIENT_SCRIPT, 'upload', '-m', 'hello from dud', '--json'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'hello from dud');
});

test('upload command can read plaintext from stdin', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-stdin-'),
  );
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

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
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  const result = await runCommand(
    'sh',
    [CLIENT_SCRIPT, 'upload', '--json'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    { input: 'stdin plaintext' },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'stdin plaintext');
});

test('upload command rejects conflicting source options', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-conflict-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');

  await writeFile(filePath, 'plaintext', 'utf8');

  const result = await runCommand(
    'sh',
    [CLIENT_SCRIPT, 'upload', '--file', filePath, '-m', 'hello'],
    {
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.notEqual(result.code, 0);
  assert.match(result.stderr, /upload accepts only one source/);
});

test('upload command can suppress QR output with --no-qr', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-upload-no-qr-'),
  );
  const filePath = path.join(tmpDir, 'plain.bin');
  const qrLog = path.join(tmpDir, 'qr.log');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');

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
  if [ "$1" = "--data-binary" ]; then
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
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${qrLog}"
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    'sh',
    [CLIENT_SCRIPT, 'upload', '--file', filePath, '--no-qr'],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^Upload complete$/m);
  assert.match(result.stdout, /^ID: 3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe$/m);
  assert.match(result.stdout, /^Delete after read: no$/m);
  assert.doesNotMatch(result.stdout, /QR Code:/);
  await assert.rejects(readFile(qrLog, 'utf8'));
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

test('download command can write decrypted plaintext to stdout', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-download-stdout-'),
  );
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await makeExecutable(
    curlMock,
    `#!/bin/sh
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
printf 'plain stdout' > "$output"
`,
  );

  const result = await runCommand(
    'sh',
    [
      CLIENT_SCRIPT,
      'download',
      '--id',
      '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
      '--stdout',
    ],
    {
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
  );

  assert.equal(result.code, 0);
  assert.equal(result.stdout, 'plain stdout');
});

test('download command validates stdout and file output options', async () => {
  const bothResult = await runCommand('sh', [
    CLIENT_SCRIPT,
    'download',
    '--id',
    '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
    '--out',
    '/tmp/out.bin',
    '--stdout',
  ]);

  assert.notEqual(bothResult.code, 0);
  assert.match(bothResult.stderr, /only one output target/);

  const missingResult = await runCommand('sh', [
    CLIENT_SCRIPT,
    'download',
    '--id',
    '3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe',
  ]);

  assert.notEqual(missingResult.code, 0);
  assert.match(missingResult.stderr, /requires either --out or --stdout/);
});

test('interactive upload can collect typed text and upload it', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-upload-'),
  );
  const interactiveScript = path.join(tmpDir, 'entrypoint.sh');
  const curlPayload = path.join(tmpDir, 'payload.bin');
  const qrMock = path.join(tmpDir, 'qr-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');

  await writeFile(interactiveScript, await readFile(CLIENT_SCRIPT, 'utf8'));
  await chmod(interactiveScript, 0o755);

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
printf '%s' '{"id":"3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe","expiresAt":"2026-04-20T12:00:00.000Z","deleteAfterRead":false}' > "$output"
`,
  );

  await makeExecutable(
    qrMock,
    `#!/bin/sh
printf '[qr]\\n'
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
      DUD_QRENCODE_BIN: qrMock,
      DUD_SECRET_TOKEN: 'top-secret',
    },
    { input: '2\n2\n\n\n\nmenu payload' },
  );

  assert.equal(result.code, 0);
  assert.equal(await readFile(curlPayload, 'utf8'), 'menu payload');
  assert.match(result.stdout, /Upload source:/);
  assert.equal(
    (
      result.stderr.match(
        /Enter plaintext, then press Ctrl-D when finished\./g,
      ) ?? []
    ).length,
    1,
  );
});

test('interactive download can write decrypted output to stdout', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-interactive-download-'),
  );
  const interactiveScript = path.join(tmpDir, 'entrypoint.sh');
  const curlMock = path.join(tmpDir, 'curl-mock.sh');
  const ageMock = path.join(tmpDir, 'age-mock.sh');

  await writeFile(interactiveScript, await readFile(CLIENT_SCRIPT, 'utf8'));
  await chmod(interactiveScript, 0o755);

  await makeExecutable(
    curlMock,
    `#!/bin/sh
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
printf 'interactive stdout' > "$output"
`,
  );

  const result = await runCommand(
    interactiveScript,
    [],
    {
      DUD_TEST_STDIN_TTY: '1',
      DUD_CURL_BIN: curlMock,
      DUD_AGE_BIN: ageMock,
    },
    { input: '3\n3df7-5d5c-0c3b-4f53-ac1b-8eeb-2370-4fbe\n2\n\n' },
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /Download output:/);
  assert.match(result.stdout, /interactive stdout$/);
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

test('install command prints a TTY-aware wrapper', async () => {
  const result = await runCommand('sh', [CLIENT_SCRIPT, 'install']);

  assert.equal(result.code, 0);
  assert.match(result.stdout, /dud_docker_env_args\(\)/);
  assert.match(result.stdout, /if \[ -r \.env \]; then/);
  assert.match(result.stdout, /--env-file/);
  assert.match(
    result.stdout,
    /DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN/,
  );
  assert.match(result.stdout, /dud_shell_quote -e/);
  assert.match(result.stdout, /if \[ -t 0 \] && \[ -t 1 \]; then/);
  assert.match(result.stdout, /docker run --rm -it/);
  assert.match(result.stdout, /docker run --rm -i/);
});

test('shell-init command prints a TTY-aware shell function', async () => {
  const result = await runCommand('sh', [CLIENT_SCRIPT, 'shell-init']);

  assert.equal(result.code, 0);
  assert.match(result.stdout, /^_dud_shell_quote\(\) \{/m);
  assert.match(result.stdout, /^dud\(\) \{/m);
  assert.match(result.stdout, /if \[ -r \.env \]; then/);
  assert.match(result.stdout, /--env-file/);
  assert.match(
    result.stdout,
    /DUD_BASE_URL DUD_DOH_URL DUD_ECH_MODE DUD_SECRET_TOKEN/,
  );
  assert.match(result.stdout, /_dud_shell_quote -e/);
  assert.match(result.stdout, /docker run --rm -it/);
  assert.match(result.stdout, /docker run --rm -i/);
});

test('shell-init output can be evaled and used in the current shell', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    ['-c', 'eval "$(sh client/entrypoint.sh shell-init)"; dud test'],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
      DUD_SECRET_TOKEN: 'top-secret',
    },
  );

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /run/);
  assert.match(args, /--rm/);
  assert.match(args, /ghcr\.io\/wojciechpolak\/dud\/dud-client:latest/);
  assert.match(args, /test/);
  assert.match(args, /-e\nDUD_SECRET_TOKEN=top-secret/);
});

test('shell-init output does not pass an empty command argument', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-empty-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
`,
  );

  const result = await runCommand(
    'bash',
    ['-c', 'eval "$(sh client/entrypoint.sh shell-init)"; dud'],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
    },
  );

  assert.equal(result.code, 0);
  const args = (await readFile(logFile, 'utf8')).trimEnd().split('\n');
  assert.equal(args.at(-1), 'ghcr.io/wojciechpolak/dud/dud-client:latest');
  assert.notEqual(args.at(-1), '');
});

test('shell-init stages piped upload stdin so age can still use a tty', async () => {
  const tmpDir = await mkdtemp(
    path.join(os.tmpdir(), 'dud-client-shell-init-pipe-'),
  );
  const logFile = path.join(tmpDir, 'docker.log');
  const payloadFile = path.join(tmpDir, 'payload.bin');
  const dockerMock = path.join(tmpDir, 'docker');

  await makeExecutable(
    dockerMock,
    `#!/bin/sh
printf '%s\n' "$@" > "${logFile}"
stdin_mount=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-v" ]; then
    case "$2" in
      *:/tmp/dud-stdin:ro) stdin_mount="$2" ;;
    esac
    shift 2
    continue
  fi
  shift
done
host_path="\${stdin_mount%%:/tmp/dud-stdin:ro}"
cat "$host_path" > "${payloadFile}"
`,
  );

  const result = await runCommand(
    'bash',
    [
      '-c',
      'eval "$(sh client/entrypoint.sh shell-init)"; printf streamed-payload | dud upload',
    ],
    {
      PATH: `${tmpDir}:${process.env.PATH ?? ''}`,
      DUD_SECRET_TOKEN: 'top-secret',
      DUD_TEST_HOST_TTY: '1',
      DUD_TEST_STDOUT_TTY: '1',
      DUD_TEST_TTY_INPUT_PATH: '/dev/null',
    },
  );

  assert.equal(result.code, 0);
  const args = await readFile(logFile, 'utf8');
  assert.match(args, /run/);
  assert.match(args, /-it/);
  assert.match(args, /\/tmp\/dud-stdin:ro/);
  assert.match(args, /--file\n\/tmp\/dud-stdin/);
  assert.equal(await readFile(payloadFile, 'utf8'), 'streamed-payload');
});
