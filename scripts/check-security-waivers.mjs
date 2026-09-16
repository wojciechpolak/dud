#!/usr/bin/env node
import fs from 'node:fs';

const [scanner, reportPath, waiverPath = '.github/security-waivers.json'] =
  process.argv.slice(2);
if (!scanner || !reportPath) {
  throw new Error(
    'usage: check-security-waivers.mjs <npm|govulncheck|trivy> <report> [waivers]',
  );
}
const reportText = fs.readFileSync(reportPath, 'utf8');
const waivers = JSON.parse(fs.readFileSync(waiverPath, 'utf8')).waivers ?? [];
const findings = new Map();
function requireObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(message);
  }
  return value;
}
function addFinding(id, details = {}) {
  findings.set(id, { id, ...details });
}
/** Index of the quote closing the JSON string that opens at `start`. */
function stringEnd(text, start) {
  for (let index = start + 1; index < text.length; index += 1) {
    if (text[index] === '\\') {
      index += 1;
    } else if (text[index] === '"') {
      return index;
    }
  }
  return text.length;
}
/** Index of the brace closing the JSON object that opens at `start`, or -1. */
function objectEnd(text, start) {
  let depth = 0;
  for (let index = start; index < text.length; index += 1) {
    const character = text[index];
    if (character === '"') {
      index = stringEnd(text, index);
    } else if (character === '{') {
      depth += 1;
    } else if (character === '}') {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}
function parseJsonObjectStream(text, message) {
  const entries = [];
  let index = 0;
  while (index < text.length) {
    if (/\s/.test(text[index])) {
      index += 1;
      continue;
    }
    const end = text[index] === '{' ? objectEnd(text, index) : -1;
    if (end === -1) {
      throw new Error(message);
    }
    entries.push(JSON.parse(text.slice(index, end + 1)));
    index = end + 1;
  }
  if (entries.length === 0) {
    throw new Error(message);
  }
  return entries;
}
if (scanner === 'npm') {
  const report = requireObject(
    JSON.parse(reportText),
    'npm audit report must be a JSON object',
  );
  if (report.error) {
    throw new Error(`npm audit failed: ${JSON.stringify(report.error)}`);
  }
  requireObject(
    report.vulnerabilities,
    'npm audit report has no vulnerabilities',
  );
  for (const [name, vulnerability] of Object.entries(report.vulnerabilities)) {
    for (const advisory of vulnerability.via ?? []) {
      if (typeof advisory !== 'object' || advisory === null) {
        continue;
      }
      addFinding(`npm:${name}:${advisory.source}`, {
        package: name,
        range: advisory.range,
      });
    }
  }
} else if (scanner === 'govulncheck') {
  let sawProgress = false;
  for (const entry of parseJsonObjectStream(
    reportText,
    'govulncheck report must be a stream of JSON objects',
  )) {
    const report = requireObject(
      entry,
      'govulncheck report entry must be a JSON object',
    );
    if (report.config || report.progress) {
      sawProgress = true;
    }
    if (report.error) {
      throw new Error(`govulncheck failed: ${JSON.stringify(report.error)}`);
    }
    const id = report.finding?.osv;
    if (id) {
      addFinding(`govulncheck:${id}`);
    }
  }
  if (!sawProgress) {
    throw new Error('govulncheck report has no successful scan records');
  }
} else if (scanner === 'trivy') {
  const report = requireObject(
    JSON.parse(reportText),
    'trivy report must be a JSON object',
  );
  if (report.Error) {
    throw new Error(`trivy failed: ${report.Error}`);
  }
  if (!Array.isArray(report.Results)) {
    throw new Error('trivy report has no Results array');
  }
  for (const result of report.Results) {
    for (const item of result.Vulnerabilities ?? []) {
      addFinding(`trivy:${item.VulnerabilityID}`);
    }
    for (const item of result.Secrets ?? []) {
      addFinding(`trivy:${item.RuleID}`);
    }
    for (const item of result.Misconfigurations ?? []) {
      addFinding(`trivy:${item.ID}`);
    }
  }
} else {
  throw new Error(`unsupported scanner: ${scanner}`);
}
const now = new Date();
/**
 * A finding is waived only by an unexpired, justified waiver for the same
 * scanner and ID, and for a package finding, the same package and range.
 */
function isWaived(finding) {
  const waiver = waivers.find(
    (item) => item.scanner === scanner && item.id === finding.id,
  );
  return (
    waiver !== undefined &&
    Boolean(waiver.reason?.trim()) &&
    !Number.isNaN(Date.parse(waiver.expires)) &&
    new Date(waiver.expires) > now &&
    (finding.package === undefined ||
      (waiver.package === finding.package && waiver.range === finding.range))
  );
}
const rejected = [...findings.values()].filter((finding) => !isWaived(finding));
if (rejected.length) {
  throw new Error(
    `unwaived or expired security findings:\n${rejected
      .map((finding) => finding.id)
      .sort()
      .join('\n')}`,
  );
}
console.log(
  `${scanner}: ${findings.size} finding(s), all clear or covered by current reviewed waivers`,
);
