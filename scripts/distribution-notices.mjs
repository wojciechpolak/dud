// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';

export const sha256 = (bytes) =>
  createHash('sha256').update(bytes).digest('hex');

function readGoToolchainNotice(directory, name) {
  let file = path.join(directory, name);
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (error) {
    // Homebrew places Go's license beside libexec; PATENTS stays in GOROOT.
    if (
      error.code !== 'ENOENT' ||
      name !== 'LICENSE' ||
      path.basename(directory) !== 'libexec'
    ) {
      throw error;
    }
    file = path.join(path.dirname(directory), name);
    bytes = readFileSync(file);
  }
  return { file, bytes };
}

export function goToolchainNoticeRecords(goRoot) {
  const directory = realpathSync(goRoot);
  return ['LICENSE', 'PATENTS'].map((name) => {
    const { file, bytes } = readGoToolchainNotice(directory, name);
    return {
      path: path.relative(directory, file),
      kind: 'license-file',
      sha256: sha256(bytes),
      text: bytes.toString('utf8'),
    };
  });
}

export function parseGoObjects(output) {
  return JSON.parse(`[${output.trim().replace(/}\s*\n{/g, '},{')}]`);
}

function filesBelow(directory) {
  return readdirSync(directory, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name, 'en'))
    .flatMap((entry) =>
      entry.isDirectory()
        ? filesBelow(path.join(directory, entry.name)).map(
            (name) => `${entry.name}/${name}`,
          )
        : entry.isFile()
          ? [entry.name]
          : [],
    );
}

function leadingNotice(source) {
  const prefix =
    source
      .replace(/^\uFEFF/, '')
      .match(/^(?:(?:\s*\/\/[^\n]*(?:\n|$))|(?:\s*\/\*[\s\S]*?\*\/))+/)?.[0] ??
    '';
  return /copyright|SPDX-License-Identifier|permission is granted|licensed under/i.test(
    prefix,
  )
    ? prefix.trimEnd()
    : '';
}

export function noticeInventory(directory, selectedFiles) {
  const all = filesBelow(directory);
  const licenses = all.filter((name) =>
    /^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT|PATENTS)(?:[._-].*)?$/i.test(
      path.basename(name),
    ),
  );
  const records = licenses.map((name) => {
    const bytes = readFileSync(path.join(directory, name));
    return {
      path: name,
      kind: 'license-file',
      bytes: bytes.length,
      sha256: sha256(bytes),
      text: bytes.toString('utf8'),
    };
  });
  for (const name of [...new Set(selectedFiles)].sort()) {
    const text = leadingNotice(
      readFileSync(path.join(directory, name), 'utf8'),
    );
    if (text) {
      records.push({
        path: name,
        kind: 'source-header',
        bytes: Buffer.byteLength(text),
        sha256: sha256(text),
        text,
      });
    }
  }
  return {
    scannedFiles: all.length,
    rootLicensePresent: licenses.some(
      (name) => !name.includes('/') && /^LICEN[CS]E(?:[._-].*)?$/i.test(name),
    ),
    records,
  };
}

function groupNotices(records) {
  const groups = new Map();
  for (const record of records) {
    const group = groups.get(record.sha256) ?? {
      text: record.text,
      sources: [],
    };
    group.sources.push(`${record.kind}: ${record.path}`);
    groups.set(record.sha256, group);
  }
  return groups;
}

export function noticeBundle(entities) {
  const blocks = [
    'DUD optical transfer native dependency-notice inventory\n\nThis inventory preserves collected license files and selected source headers.\nIt does not grant permission for entries with missing or unresolved licenses.\n',
  ];
  for (const entity of entities) {
    blocks.push(`\n=== ${entity.name} ===\n`);
    if (!entity.rootLicensePresent) {
      blocks.push(
        'MISSING ROOT LICENSE FILE: distribution requires resolution.\n',
      );
    }
    const groups = groupNotices(entity.records);
    for (const [digest, group] of groups) {
      blocks.push(
        `\nSources:\n${group.sources.join('\n')}\nSHA-256: ${digest}\n\n${group.text}\n`,
      );
    }
  }
  return blocks.join('');
}
