// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

export function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('cache-control', 'no-store');
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-frame-options', 'DENY');

  return new Response(JSON.stringify(body), {
    ...init,
    headers,
  });
}

export function errorResponse(status: number, error: string): Response {
  return jsonResponse({ error }, { status });
}
