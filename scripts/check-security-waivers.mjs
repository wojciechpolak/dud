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
function parseJsonObjectStream(text, message) {
  const entries = [];
  let start = -1;
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (start === -1) {
      if (/\s/.test(character)) {
        continue;
      }
      if (character !== '{') {
        throw new Error(message);
      }
      start = index;
      depth = 1;
      continue;
    }

    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
    } else if (character === '{') {
      depth += 1;
    } else if (character === '}') {
      depth -= 1;
      if (depth === 0) {
        entries.push(JSON.parse(text.slice(start, index + 1)));
        start = -1;
      }
    }
  }

  if (start !== -1 || entries.length === 0) {
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
const rejected = [...findings.values()].filter((finding) => {
  const waiver = waivers.find(
    (item) => item.scanner === scanner && item.id === finding.id,
  );
  return (
    !waiver ||
    !waiver.reason?.trim() ||
    Number.isNaN(Date.parse(waiver.expires)) ||
    new Date(waiver.expires) <= now ||
    (finding.package !== undefined &&
      (waiver.package !== finding.package || waiver.range !== finding.range))
  );
});
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
