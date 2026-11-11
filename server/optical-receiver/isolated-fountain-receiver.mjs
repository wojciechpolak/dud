// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// fallow-ignore-next-line unresolved-import -- The isolated benchmark serves compiled receiver modules beside this script.
import './fountain-worker.js';
self.postMessage({ benchmarkReady: true });
