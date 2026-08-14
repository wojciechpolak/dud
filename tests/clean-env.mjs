// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

// Test behavior must not depend on a developer's active DUD configuration.
// Individual tests can still provide the variables they need to child processes.
for (const name of Object.keys(process.env)) {
  if (name.startsWith('DUD_')) {
    delete process.env[name];
  }
}
