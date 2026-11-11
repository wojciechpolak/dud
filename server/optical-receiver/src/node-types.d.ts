// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

declare module 'node:fs' {
  export function writeFileSync(path: string, data: string): void;
}

declare const process: {
  argv: string[];
};
