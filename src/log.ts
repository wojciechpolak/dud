// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type { V2OperationTiming } from './v2-timing.js';

/**
 * Server log formatting.
 *
 * `text` is a single-line access log; `json` emits one object per line for a
 * log pipeline. Both carry the same facts, and both are redacted the
 * same way: the record names a route, not the object, delivery, capability, or
 * peer the request touched.
 */
export type DudLogFormat = 'text' | 'json';

export type DudLogMode = 'normal' | 'minimal' | 'silent';

export interface DudAccessLogInput {
  method: string;
  /** Already passed through the path redactor. */
  path: string;
  status: number;
  durationMs: number;
  /** Omitted in `minimal` mode, where the client address is not recorded. */
  client?: string;
  timing?: V2OperationTiming;
}

/**
 * Anything that looks like an identifier is replaced before it reaches a log
 * sink. The two shapes that matter are hex object, delivery, and rendezvous
 * identifiers and base64url capability or token material.
 */
const HEX_IDENTIFIER = /[a-f0-9]{32,}/gi;
const BASE64URL_IDENTIFIER = /[A-Za-z0-9_-]{40,}/g;

export function redactLogText(value: string): string {
  return value
    .replace(HEX_IDENTIFIER, '<redacted>')
    .replace(BASE64URL_IDENTIFIER, '<redacted>');
}

export function parseLogFormat(raw: string | undefined): DudLogFormat {
  if (raw === undefined || raw === '' || raw === 'text') {
    return 'text';
  }
  if (raw === 'json') {
    return 'json';
  }
  throw new Error('DUD_LOG_FORMAT must be one of: text, json.');
}

/** The text line the Node server has always written. */
function accessTextLine(input: DudAccessLogInput): string {
  const prefix = input.client ? `${input.client} ` : '';
  return `${prefix}${input.method} ${input.path} -> ${input.status} ${input.durationMs}ms`;
}

function accessJsonLine(input: DudAccessLogInput, at: Date): string {
  const record: Record<string, string | number> = {
    ts: at.toISOString(),
    level: 'info',
    event: 'request',
    method: input.method,
    path: input.path,
    status: input.status,
    duration_ms: input.durationMs,
  };
  if (input.client) {
    record.client = input.client;
  }
  if (input.timing) {
    record.operation = input.timing.operation;
    record.authorization_ms = input.timing.authorizationMs;
    record.metadata_ms = input.timing.metadataMs;
    record.body_ms = input.timing.bodyMs;
    record.handler_ms = input.timing.totalMs;
  }
  return JSON.stringify(record);
}

export function formatAccessLog(
  format: DudLogFormat,
  input: DudAccessLogInput,
  at: Date = new Date(),
): string {
  return format === 'json' ? accessJsonLine(input, at) : accessTextLine(input);
}

export function formatEventLog(
  format: DudLogFormat,
  level: 'info' | 'error',
  event: string,
  message: string,
  at: Date = new Date(),
): string {
  const redacted = redactLogText(message);
  if (format !== 'json') {
    return redacted;
  }
  return JSON.stringify({
    ts: at.toISOString(),
    level,
    event,
    message: redacted,
  });
}
