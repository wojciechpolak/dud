#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const coverageRoot = path.join(root, 'coverage');
const requestedTarget = process.argv[2];
const targets = requestedTarget ? [requestedTarget] : ['server', 'client'];

if (targets.some((target) => target !== 'server' && target !== 'client')) {
  console.error('usage: npm run test:coverage [-- server|client]');
  process.exit(2);
}

function summarizeGoTestFailure(stdoutText, stderrText, reportPath) {
  const failedTests = new Set();
  const diagnosticOutput = [];

  for (const line of stdoutText.split('\n')) {
    if (!line) {
      continue;
    }
    try {
      const event = JSON.parse(line);
      if (event.Action === 'fail' && event.Test) {
        failedTests.add(event.Test);
      }
      if (
        event.Action === 'output' &&
        typeof event.Output === 'string' &&
        /(?:--- FAIL:|panic:|fatal error:)/.test(event.Output)
      ) {
        diagnosticOutput.push(event.Output.trimEnd());
      }
    } catch {
      // Go test's JSON output may contain non-JSON diagnostics; the saved
      // report remains the source of truth for those cases.
    }
  }

  const summary = [];
  if (failedTests.size > 0) {
    summary.push(`Failed tests: ${[...failedTests].join(', ')}`);
  }
  if (diagnosticOutput.length > 0) {
    summary.push(diagnosticOutput.join('\n'));
  }
  if (stderrText.trim()) {
    summary.push(stderrText.trim());
  }
  summary.push(`Full Go test report: ${reportPath}`);
  return summary.join('\n');
}

function run(command, args, options = {}) {
  const { cwd = root, env, stdoutFile, failureSummary } = options;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', async (code, signal) => {
      const stdoutText = Buffer.concat(stdout).toString('utf8');
      const stderrText = Buffer.concat(stderr).toString('utf8');
      if (stdoutFile) {
        await fs.writeFile(stdoutFile, stdoutText);
      }
      if (code !== 0) {
        const reason = signal ? `signal ${signal}` : `exit code ${code}`;
        const output = `${stdoutText}${stderrText}`.trim();
        const outputTail = failureSummary
          ? failureSummary(stdoutText, stderrText, stdoutFile)
          : output.length > 12_000
            ? `[diagnostics truncated; full stdout is in ${stdoutFile ?? 'the coverage test report'}]\n${output.slice(-12_000)}`
            : output;
        reject(
          new Error(
            `${command} ${args.join(' ')} failed with ${reason}${outputTail ? `\n${outputTail}` : ''}`,
          ),
        );
        return;
      }
      resolve({ stdout: stdoutText, stderr: stderrText });
    });
  });
}

function parseGoProfile(profile) {
  const files = new Map();
  let totalStatements = 0;
  let coveredStatements = 0;

  for (const line of profile.trim().split('\n').slice(1)) {
    const match = /^(.*?):(\d+)\.(\d+),(\d+)\.(\d+)\s+(\d+)\s+(\d+)$/.exec(
      line,
    );
    if (!match) {
      throw new Error(`cannot parse Go coverage profile line: ${line}`);
    }
    const [
      ,
      rawFile,
      startLine,
      startColumn,
      endLine,
      endColumn,
      countText,
      hitsText,
    ] = match;
    const file = rawFile.includes('/client/')
      ? `client/${rawFile.split('/client/')[1]}`
      : rawFile;
    const statements = Number(countText);
    const hits = Number(hitsText);
    const entry = files.get(file) ?? {
      statements: 0,
      coveredStatements: 0,
      uncoveredBlocks: [],
    };
    entry.statements += statements;
    totalStatements += statements;
    if (hits > 0) {
      entry.coveredStatements += statements;
      coveredStatements += statements;
    } else {
      entry.uncoveredBlocks.push({
        start: { line: Number(startLine), column: Number(startColumn) },
        end: { line: Number(endLine), column: Number(endColumn) },
        statements,
      });
    }
    files.set(file, entry);
  }

  const percentage = (covered, total) =>
    total === 0 ? 100 : Number(((covered / total) * 100).toFixed(1));
  const fileEntries = [...files.entries()]
    .map(([file, entry]) => ({
      file,
      statements: {
        covered: entry.coveredStatements,
        total: entry.statements,
        percent: percentage(entry.coveredStatements, entry.statements),
      },
      uncoveredBlocks: entry.uncoveredBlocks,
    }))
    .sort(
      (left, right) =>
        left.statements.percent - right.statements.percent ||
        left.file.localeCompare(right.file),
    );

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    total: {
      statements: {
        covered: coveredStatements,
        total: totalStatements,
        percent: percentage(coveredStatements, totalStatements),
      },
    },
    files: fileEntries,
  };
}

async function runServerCoverage() {
  const reportDir = path.join(coverageRoot, 'server');
  const tempDir = path.join(reportDir, 'tmp');
  const testFiles = (await fs.readdir(path.join(root, 'tests')))
    .filter((file) => file.endsWith('.test.mjs'))
    .sort()
    .map((file) => path.join('tests', file));
  await fs.rm(reportDir, { recursive: true, force: true });
  await fs.mkdir(reportDir, { recursive: true });

  await run('npm', ['run', 'build:server']);
  await run(path.join(root, 'node_modules', '.bin', 'c8'), [
    '--all',
    '--src=src',
    '--include=src/**/*.ts',
    '--exclude=src/**/*.d.ts',
    '--exclude=src/types.ts',
    '--exclude-after-remap',
    `--temp-directory=${tempDir}`,
    `--reports-dir=${reportDir}`,
    '--reporter=json',
    '--reporter=json-summary',
    '--reporter=lcovonly',
    'node',
    '--import',
    './tests/clean-env.mjs',
    '--test',
    '--test-concurrency=1',
    '--test-reporter=spec',
    `--test-reporter-destination=${path.join(reportDir, 'test-results.txt')}`,
    ...testFiles,
  ]);

  const detailed = await run(path.join(root, 'node_modules', '.bin', 'c8'), [
    'report',
    `--temp-directory=${tempDir}`,
    `--reports-dir=${reportDir}`,
    '--all',
    '--src=src',
    '--include=src/**/*.ts',
    '--exclude=src/**/*.d.ts',
    '--exclude=src/types.ts',
    '--exclude-after-remap',
    '--reporter=text',
  ]);
  await fs.writeFile(path.join(reportDir, 'details.txt'), detailed.stdout);
  await fs.rm(tempDir, { recursive: true, force: true });

  const summary = JSON.parse(
    await fs.readFile(path.join(reportDir, 'coverage-summary.json'), 'utf8'),
  );
  const total = summary.total;
  console.log('Server coverage');
  console.log(`  Statements: ${total.statements.pct}%`);
  console.log(`  Branches:   ${total.branches.pct}%`);
  console.log(`  Functions:  ${total.functions.pct}%`);
  console.log(`  Lines:      ${total.lines.pct}%`);
  return total;
}

async function runClientCoverage() {
  const reportDir = path.join(coverageRoot, 'client');
  const profilePath = path.join(reportDir, 'coverage.out');
  await fs.rm(reportDir, { recursive: true, force: true });
  await fs.mkdir(reportDir, { recursive: true });

  await run(
    'go',
    [
      'test',
      '-json',
      '-covermode=atomic',
      `-coverprofile=${profilePath}`,
      './...',
    ],
    {
      cwd: path.join(root, 'client'),
      env: { GOCACHE: '/tmp/dud-go-build-cache' },
      stdoutFile: path.join(reportDir, 'test-results.jsonl'),
      failureSummary: summarizeGoTestFailure,
    },
  );

  const functions = await run('go', ['tool', 'cover', `-func=${profilePath}`], {
    cwd: path.join(root, 'client'),
  });
  await fs.writeFile(path.join(reportDir, 'functions.txt'), functions.stdout);
  const summary = parseGoProfile(await fs.readFile(profilePath, 'utf8'));
  await fs.writeFile(
    path.join(reportDir, 'coverage-summary.json'),
    `${JSON.stringify(summary, null, 2)}\n`,
  );

  console.log('Client coverage');
  console.log(`  Statements: ${summary.total.statements.percent}%`);
  return summary.total;
}

try {
  await fs.mkdir(coverageRoot, { recursive: true });
  const summaries = {};
  for (const target of targets) {
    if (target === 'server') {
      summaries.server = await runServerCoverage();
    } else {
      summaries.client = await runClientCoverage();
    }
  }
  if (summaries.server && summaries.client) {
    const covered =
      summaries.server.statements.covered + summaries.client.statements.covered;
    const total =
      summaries.server.statements.total + summaries.client.statements.total;
    const percent = Number(((covered / total) * 100).toFixed(1));
    const summary = {
      schemaVersion: 1,
      statements: { covered, total, percent },
      minimumStatements: 80,
    };
    await fs.writeFile(
      path.join(coverageRoot, 'coverage-summary.json'),
      `${JSON.stringify(summary, null, 2)}\n`,
    );
    console.log('Combined coverage');
    console.log(`  Statements: ${percent}% (${covered}/${total})`);
    if (percent < summary.minimumStatements) {
      throw new Error(
        `combined statement coverage ${percent}% is below the ${summary.minimumStatements}% minimum`,
      );
    }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
}
