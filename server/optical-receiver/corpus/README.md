# Optical transfer test corpus

`manifest.json` pins the names, sizes and SHA-256 hashes of 12 deterministic
fixtures. `generate.mjs` checks every generated entry against that manifest.
Fixtures cover UTF-8, binary files, safe and hostile tar collections, and random
and compressible payloads at 1 KiB, 1 MiB, 16 MiB and 64 MiB.

From the repository root:

```sh
node server/optical-receiver/corpus/generate.mjs
node server/optical-receiver/corpus/generate.mjs OUTPUT_DIRECTORY
npm run test:optical:corpus
```

The default output is `server/optical-receiver/.work/corpus/`, which is ignored
by Git. `bench-memory.mjs` reads these fixtures and the manifest. The corpus
integration test generates files in its own temporary directory and invokes the
client Go helper to verify exact optical reconstruction. Missing, truncated or
corrupt fixtures fail; they are never skipped. These tests measure codec
correctness, not camera throughput or phone memory.
