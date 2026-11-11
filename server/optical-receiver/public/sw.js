// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

const CACHE_PREFIX = 'dud-optical-';
const CACHE = `${CACHE_PREFIX}__DUD_OPTICAL_BUILD__`;
const INDEX = '__DUD_OPTICAL_INDEX__';
const MANIFEST = '__DUD_OPTICAL_MANIFEST__';
const CACHE_ENTRIES = __DUD_OPTICAL_CACHE_ENTRIES__;
const ASSETS = CACHE_ENTRIES.map((entry) => entry.url);

self.addEventListener('message', (event) => {
  if (event.data?.type === 'receiver-build') {
    event.ports[0]?.postMessage({
      buildID: '__DUD_OPTICAL_BUILD__',
      entrypoint: INDEX,
    });
  }
});
const SECURITY_HEADERS = {
  'content-security-policy':
    "default-src 'self'; connect-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; media-src 'self' blob:; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'permissions-policy': 'camera=(self), geolocation=(), microphone=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
};

function decodeBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) =>
        Promise.all(
          CACHE_ENTRIES.map((entry) => {
            const bytes = decodeBase64(entry.bytes);
            return cache.put(
              new URL(entry.url, self.registration.scope).href,
              new Response(bytes, {
                headers: {
                  ...SECURITY_HEADERS,
                  'accept-ranges': 'none',
                  'cache-control': 'public, max-age=31536000, immutable',
                  'content-length': String(bytes.byteLength),
                  'content-type': entry.contentType,
                },
              }),
            );
          }),
        ),
      )
      .then(() => self.skipWaiting())
      .catch(async (error) => {
        await caches.delete(CACHE);
        throw error;
      }),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key.startsWith(CACHE_PREFIX) && key !== CACHE)
            .map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    return;
  }
  const requestURL = new URL(event.request.url);
  if (requestURL.origin !== self.location.origin || requestURL.search) {
    return;
  }

  const scopeURL = new URL(self.registration.scope);
  const relativePath = requestURL.pathname.startsWith(scopeURL.pathname)
    ? requestURL.pathname.slice(scopeURL.pathname.length)
    : undefined;
  const indexAlias = relativePath === '' || relativePath === 'index.html';
  const manifestAlias = relativePath === 'manifest.webmanifest';
  const directAsset = ASSETS.find(
    (candidate) =>
      new URL(candidate, self.registration.scope).pathname ===
      requestURL.pathname,
  );
  const staleIndex =
    !directAsset &&
    relativePath !== undefined &&
    /^index\.[a-f0-9]{12}\.html$/.test(relativePath) &&
    event.request.mode === 'navigate';
  const asset =
    indexAlias || staleIndex ? INDEX : manifestAlias ? MANIFEST : directAsset;
  if (!asset) {
    return;
  }
  const entry = CACHE_ENTRIES.find((candidate) => candidate.url === asset);
  if (!entry) {
    return;
  }
  if (event.request.headers.has('range')) {
    event.respondWith(
      Promise.resolve(
        new Response(null, {
          status: 416,
          headers: {
            ...SECURITY_HEADERS,
            'cache-control': 'no-store',
            'accept-ranges': 'none',
            'content-range': `bytes */${entry.byteLength}`,
          },
        }),
      ),
    );
    return;
  }
  if (staleIndex) {
    event.respondWith(
      Promise.resolve(
        new Response(null, {
          status: 302,
          headers: {
            ...SECURITY_HEADERS,
            'cache-control': 'no-store',
            location: scopeURL.href,
          },
        }),
      ),
    );
    return;
  }
  event.respondWith(
    caches
      .open(CACHE)
      .then((cache) =>
        cache.match(new URL(asset, self.registration.scope).href),
      )
      .then((response) => {
        if (!response) {
          return Response.error();
        }
        if (!indexAlias && !manifestAlias) {
          return response;
        }
        const headers = new Headers(response.headers);
        headers.set('cache-control', 'no-store');
        return new Response(response.clone().body, {
          status: response.status,
          headers,
        });
      }),
  );
});
