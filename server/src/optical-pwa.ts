// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { OPTICAL_PWA_BUILD } from './optical-pwa-assets.generated.js';

const OPTICAL_PREFIX = '/optical/';
const IMMUTABLE_CACHE = 'public, max-age=31536000, immutable';
const MUTABLE_CACHE = 'no-store';
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "connect-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' blob:",
  "media-src 'self' blob:",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const decodedAssets = new Map<string, Uint8Array>();

function decodeAsset(name: string, value: string): Uint8Array {
  const existing = decodedAssets.get(name);
  if (existing) {
    return existing;
  }
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  decodedAssets.set(name, bytes);
  return bytes;
}

function opticalHeaders(): Headers {
  return new Headers({
    'content-security-policy': CONTENT_SECURITY_POLICY,
    'permissions-policy': 'camera=(self), geolocation=(), microphone=()',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  });
}

function errorResponse(
  status: number,
  message: string,
  head: boolean,
  headers?: Record<string, string>,
): Response {
  const responseHeaders = opticalHeaders();
  responseHeaders.set('cache-control', MUTABLE_CACHE);
  responseHeaders.set('content-type', 'text/plain; charset=utf-8');
  for (const [name, value] of Object.entries(headers ?? {})) {
    responseHeaders.set(name, value);
  }
  return new Response(head ? null : `${message}\n`, {
    status,
    headers: responseHeaders,
  });
}

function isOpticalPath(pathname: string): boolean {
  return pathname === '/optical' || pathname.startsWith(OPTICAL_PREFIX);
}

function resolveOpticalAsset(pathname: string) {
  const relativePath = pathname.slice(OPTICAL_PREFIX.length);
  let name = relativePath === '' ? 'index.html' : relativePath;
  const staleIndex =
    !Object.hasOwn(OPTICAL_PWA_BUILD.assets, name) &&
    /^index\.[a-f0-9]{12}\.html$/.test(name);
  if (staleIndex) {
    name = 'index.html';
  }
  const asset = Object.hasOwn(OPTICAL_PWA_BUILD.assets, name)
    ? OPTICAL_PWA_BUILD.assets[name]
    : undefined;
  return asset ? { name, asset, staleIndex } : undefined;
}

/**
 * Returns a response only for the optical route family. The embedded byte map
 * is the complete dependency of this path, so requests cannot reach payload
 * storage, API secrets, or body readers.
 */
export function serveOpticalPwa(
  request: Request,
  enabled: boolean,
): Response | undefined {
  const url = new URL(request.url);
  if (!isOpticalPath(url.pathname)) {
    return undefined;
  }
  if (!enabled) {
    return errorResponse(404, 'Not found.', request.method === 'HEAD');
  }
  if (url.pathname === '/optical' || url.search) {
    return errorResponse(404, 'Not found.', request.method === 'HEAD');
  }

  const resolved = resolveOpticalAsset(url.pathname);
  if (!resolved) {
    return errorResponse(404, 'Not found.', request.method === 'HEAD');
  }
  const { name, asset, staleIndex } = resolved;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return errorResponse(405, 'Method not allowed.', false, {
      allow: 'GET, HEAD',
    });
  }

  const bytes = decodeAsset(name, asset.bytes);
  if (request.headers.has('range')) {
    return errorResponse(
      416,
      'Range requests are not supported.',
      request.method === 'HEAD',
      {
        'accept-ranges': 'none',
        'content-range': `bytes */${bytes.byteLength}`,
      },
    );
  }

  const headers = opticalHeaders();
  if (staleIndex) {
    headers.set('cache-control', MUTABLE_CACHE);
    headers.set('location', OPTICAL_PREFIX);
    return new Response(null, { status: 302, headers });
  }
  headers.set(
    'cache-control',
    asset.immutable ? IMMUTABLE_CACHE : MUTABLE_CACHE,
  );
  headers.set('content-length', String(bytes.byteLength));
  headers.set('content-type', asset.contentType);
  headers.set('accept-ranges', 'none');
  if (name === 'sw.js') {
    headers.set('service-worker-allowed', OPTICAL_PREFIX);
  }

  const body = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  return new Response(request.method === 'HEAD' ? null : body, {
    status: 200,
    headers,
  });
}

export { OPTICAL_PWA_BUILD };
