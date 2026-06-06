// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak
// fallow-ignore-file unused-class-member

export function textStream(text) {
  const bytes = new TextEncoder().encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

export function makeContext() {
  const promises = [];
  return {
    waitUntil(promise) {
      promises.push(Promise.resolve(promise));
    },
    async flush() {
      await Promise.allSettled(promises);
    },
  };
}

export class MemoryBlobStore {
  constructor() {
    this.objects = new Map();
    this.deletedKeys = [];
    this.failPut = false;
  }

  async put(key, body, metadata) {
    if (this.failPut) {
      throw new Error('put failed');
    }

    const bytes = new Uint8Array(await new Response(body).arrayBuffer());
    this.objects.set(key, {
      bytes,
      contentType: metadata.contentType,
      customMetadata: { ...(metadata.customMetadata ?? {}) },
    });
  }

  async get(key) {
    const entry = this.objects.get(key);
    if (!entry) {
      return null;
    }

    return {
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(entry.bytes);
          controller.close();
        },
      }),
      size: entry.bytes.byteLength,
      customMetadata: { ...entry.customMetadata },
    };
  }

  async head(key) {
    const entry = this.objects.get(key);
    if (!entry) {
      return null;
    }

    return {
      size: entry.bytes.byteLength,
      customMetadata: { ...entry.customMetadata },
    };
  }

  async list(prefix, limit) {
    return Array.from(this.objects.keys())
      .filter((key) => key.startsWith(prefix))
      .sort()
      .slice(0, limit)
      .map((key) => ({ key }));
  }

  async delete(key) {
    this.deletedKeys.push(key);
    this.objects.delete(key);
  }
}

export const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUINoxOVy/byQVD+3zsuNMlhmxO3QwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDUyNTExMzQ0OVoXDTI3MDUy
NTExMzQ0OVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEApVtI3LCHOpeITYqKvSvSwNG0EDgiB8/rxV4vPL047kwG
d/gxeFXu1iPLG7qfaCLKGDpC2y0xyPiLdrlRYBCjeAVPwuszY6HkCZQhrHuYLaHZ
DXg4F+fPRMf5gou6sVoblWKhMnBDV6PGPJKYVJ1byWsFgxjyt05GnQcoLOGdotY6
L8S7sywPoio8m7cZAe3KZL03arixqZIOaqMyjjn//3l/q4+XpMoCOXzwW+K8O1Nq
UZ/yzJZJ5QpgR76nacwn5Beb4D30hf2inIVs06xbKYA11Cwe8S3tppdgkgclv64i
MSj0r+VNoDGiUlswxBp/Zc9Xzdhx4h+vHM8Ut48QMQIDAQABo2kwZzAdBgNVHQ4E
FgQULjw1zQTMuYzjRiUA/flQaYwSRpgwHwYDVR0jBBgwFoAULjw1zQTMuYzjRiUA
/flQaYwSRpgwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3Qw
DQYJKoZIhvcNAQELBQADggEBADu/KpP/Vep/2UxKDxNZchIZhayQ9XWIsXhi6g+q
dkhwytvJ4eItq2TEZ6kGwlkoonGXKRJ4jIeInGaYzhYYkh+Nf9u3FINl46qFyXEh
yKcYXZwiJHypodl/z7qv9NYMZZbbSBias8RidOHtOb6hdIF605Rnt8UWPyP7dUuh
BaRsya3lr+WUPlRPMMl00WSS6mRHOIEEVZ+xwp4kRgs+1t5Es2gx/9NrwIph5Ksr
1s+h5JhwGx9NlTQrBvqmqfg6pcHPpIintiR8AYqsrlwbC8TZQVlfbKvld3XsoGqA
I1AQ9H+hdGXhpPQGtPdsCIHIb9ZvuHGT/DWtPyg6iWvo2pE=
-----END CERTIFICATE-----
`;

export const TEST_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQClW0jcsIc6l4hN
ioq9K9LA0bQQOCIHz+vFXi88vTjuTAZ3+DF4Ve7WI8sbup9oIsoYOkLbLTHI+It2
uVFgEKN4BU/C6zNjoeQJlCGse5gtodkNeDgX589Ex/mCi7qxWhuVYqEycENXo8Y8
kphUnVvJawWDGPK3TkadBygs4Z2i1jovxLuzLA+iKjybtxkB7cpkvTdquLGpkg5q
ozKOOf//eX+rj5ekygI5fPBb4rw7U2pRn/LMlknlCmBHvqdpzCfkF5vgPfSF/aKc
hWzTrFspgDXULB7xLe2ml2CSByW/riIxKPSv5U2gMaJSWzDEGn9lz1fN2HHiH68c
zxS3jxAxAgMBAAECgf8Cedtyx9yT2VuxIuHw8zcKAW8wzvuzd5Q64FjUuqtKO4Pd
SATK8ykgYRN+1syMQqPEDnCcgjtnRvwk9aFs+X15I/CNz/fKW3eOrSkpQVswqREW
9+CJ0G7KGN8jlUlhCSMLREQlp94E8e7bTqv5QwyczNLITmypUgK8rIltd/NkUiAH
wNH6MOC+NfggJX7wXNpJjWhudO8NR8XdU8Lm1Vaau9vAAxtHf9amZ/BUIH6R2+S4
ecaNzXz8te6C98XMLd+1pvOwCPTRVWOIyH88lWkg9FlokWPhLFKVVwC4sv5U6hk1
rvDecyQMypNoUEmZe21qupnIcDrasYA4VtiRLysCgYEA4TexjbJE1Ur9GoaxTvXx
c2A094GSGpiSZYfXt9NQxS/UrFE/juE5XITUG1GC9xynFe/cAd72AxymO88eTpCC
4ya9yYzRwKHi43YWYu3+0b71oTmdUSuUizftDpysuKGrIVwrhDFqvsbwMYmsYN1Y
mUqxWdPse3wqQYhAmK2dV+8CgYEAu/USCFkzrg54AHyZgY/dvE2nu2ye5Gbe1twc
HYgQ2srT1G4W0+kDN44SNKzxJ0nbTxF2R/6ol5m3ec0/c6TZpTYMQTLoJ3ez6V26
3AzQOHOMDQ9kmZ/7L+lhyEwJSam5wOOPNVlCQPQMhOZT4NTAGV6XP/dPRwbo14j5
YOaI+d8CgYB1HaEXLjzdLcGwqZpKlVqZxM3GZ3qymeSHJ7zlut2lrNnLQfTrN/O8
SNaD3j9cgWnh3nlp/6eutpc7QtlfwYZO2TaYOMJaidSStDWv/FMmf0b8MBm+vAri
2pJLpu2qlWeIUYXPmGMKEimVmSIqvO/1xwGy1KGFFWxj55avzpijwQKBgGSPJnmu
99ZcyVlBUIOf6/sN9Ppyj8QVQY3kr2ohXRshvxl9WNtBZEY5zYW/LTpe6mWwKv8z
wRFy3VXeON9vSD563y2Wxdwvz+LAEfQfKtu4/ioSnTkP/bzReU5HWATAOLB5Tyo0
uhy0NWp5LFEyoiAwmm1PrGuMx9Bg6UMttAUzAoGAXZ0b+ukSCBdHU/nG1D4RbmET
iq7l84e69zkRxS+mchohay3Jr56JQVKnhO8o/JKzXsZH2B6u8dIqXB8hIxHX7chS
DtQ0IA5Mb50Sn7MtnJLk9DPtHmP6xQUKWoyKxNde7nlxDC142B9DHefQc+uFhnW1
9SYjQcIgH1I8KdOnRfo=
-----END PRIVATE KEY-----
`;
