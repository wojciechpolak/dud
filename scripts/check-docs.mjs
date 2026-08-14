#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
//
// Documentation gate. Verifies that the documents a release is required to ship
// exist, that every relative link between Markdown files resolves, and that the
// V2 transport terminology stays consistent.
//
// Reads files only; no network.

import fs from 'node:fs';
import path from 'node:path';

/** Documents a release cannot ship without. */
const REQUIRED = [
  'README.md',
  'SECURITY.md',
  'CHANGELOG.md',
  'LICENSE',
  'docs/README.md',
  'docs/protocol-v2.md',
  'docs/threat-model-v2.md',
  'docs/peer-setup.md',
  'docs/dead-drops-v1.md',
  'docs/client.md',
  'docs/server-v2.md',
  'docs/migration-v1-v2.md',
  'docs/recovery-v2.md',
  'docs/git-sync-v2.md',
  'docs/supported-versions.md',
];

/**
 * ECH has exactly two modes and they are named `hard` and `off` everywhere. Any
 * other word for them in prose is a documentation bug, because an operator who
 * reads "strict" or "best-effort" will look for a mode that does not exist. The
 * patterns below name the wrong words explicitly rather than trying to guess,
 * so ordinary prose about ECH support keeps reading naturally.
 */
const FORBIDDEN_TRANSPORT_WORDS = [
  /\bECH\s+mode\s+(?:strict|enabled|disabled|optional|relaxed|lenient|auto|best[- ]effort)\b/i,
  /\b(?:strict|best[- ]effort)\s+ECH\b/i,
  /\bECH\s+(?:strict|best[- ]effort)\b/i,
  /DUD_ECH_MODE=(?!hard\b|off\b|\$)/,
];

/**
 * The two transfer modes are named, not numbered: a **dead drop** is addressed
 * by an opaque ID shared out of band, and a **peer** transfer is addressed by
 * the local alias of a paired device. Both ship permanently, so naming either
 * one "legacy" tells the reader to migrate off a feature that is not going
 * anywhere. "one-shot" is worse than vague, it is false: `--delete-after-read`
 * is opt-in, so a drop stays fetchable until its TTL expires. Those words
 * belong to that flag alone. As above, the patterns name the wrong words
 * explicitly instead of guessing, so ordinary prose keeps reading naturally.
 */
const FORBIDDEN_MODE_WORDS = [
  /\bone-shot\s+link\b/i,
  /\bone-(?:shot|time)\s+(?:drop|transfer|sharing|upload|download)\b/i,
  /\blegacy\s+(?:commands?|modes?|paths?|upload|download|one-shot|drops?|v1)\b/i,
  /\bV[12]\s+modes?\b/i,
];

/**
 * "drop" alone is generic enough to read as a product name someone else owns,
 * or as the everyday verb, which would let it swallow peer transfers too. Every
 * document therefore establishes the full idiom before it uses the shorthand.
 * Only noun forms count: "drops that requirement" and `--cap-drop` are ordinary
 * prose and stay allowed anywhere.
 */
const DROP_NOUN =
  /\b(?:a|the|each|every|any)\s+drops?\b|\bdrops?[\s-](?:transfers?|IDs?|commands?|modes?|uploads?|downloads?|files?|objects?|entry|entries|based)\b/i;
const DEAD_DROP = /\bdead[\s-]drops?\b/i;

const failures = [];

function fail(message) {
  failures.push(message);
}

function markdownFiles() {
  const files = ['README.md', 'SECURITY.md', 'CHANGELOG.md'];
  for (const entry of fs.readdirSync('docs')) {
    if (entry.endsWith('.md')) {
      files.push(path.join('docs', entry));
    }
  }
  return files.filter((file) => fs.existsSync(file));
}

for (const file of REQUIRED) {
  if (!fs.existsSync(file)) {
    fail(`required document ${file} is missing`);
  }
}

for (const file of markdownFiles()) {
  const text = fs.readFileSync(file, 'utf8');
  const directory = path.dirname(file);

  for (const match of text.matchAll(/\[[^\]]*\]\(([^)\s]+)\)/g)) {
    const target = match[1];
    if (/^[a-z]+:/i.test(target) || target.startsWith('#')) {
      continue;
    }
    const [relative] = target.split('#');
    if (!relative) {
      continue;
    }
    const resolved = path.normalize(path.join(directory, relative));
    if (!fs.existsSync(resolved)) {
      fail(`${file}: link to ${target} does not resolve to ${resolved}`);
    }
  }

  // Skip the changelog, which quotes historical wording verbatim.
  if (file === 'CHANGELOG.md') {
    continue;
  }
  for (const pattern of FORBIDDEN_TRANSPORT_WORDS) {
    const found = pattern.exec(text);
    if (found) {
      fail(
        `${file}: uses "${found[0].trim()}" for a transport mode; the modes are hard and off`,
      );
    }
  }

  // The guidance files state the naming rule, so they have to spell out the
  // words the rule rejects.
  if (file === 'AGENTS.md' || file === 'CLAUDE.md') {
    continue;
  }
  for (const pattern of FORBIDDEN_MODE_WORDS) {
    const found = pattern.exec(text);
    if (found) {
      fail(
        `${file}: uses "${found[0].trim()}" for a transfer mode; the modes are dead drops and peers`,
      );
    }
  }

  const shorthand = DROP_NOUN.exec(text);
  if (shorthand) {
    const full = DEAD_DROP.exec(text);
    if (!full || full.index > shorthand.index) {
      fail(
        `${file}: uses the shorthand "${shorthand[0].trim()}" before naming a dead drop`,
      );
    }
  }
}

if (failures.length !== 0) {
  console.error(`documentation gate failed:\n${failures.join('\n')}`);
  process.exit(1);
}
console.log(
  `docs: ${REQUIRED.length} required document(s) present, every relative link resolves`,
);
