// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * D1 hands BLOB columns back as `Array<number>` where `node:sqlite` returns a
 * `Uint8Array`, so rows are converted to the representation the Worker receives.
 */
function d1Row(row) {
  if (!row) {
    return row;
  }
  for (const [column, value] of Object.entries(row)) {
    if (value instanceof Uint8Array) {
      row[column] = Array.from(value);
    }
  }
  return row;
}

class Statement {
  constructor(database, query, values = []) {
    this.database = database;
    this.query = query;
    this.values = values;
  }

  bind(...values) {
    return new Statement(this.database, this.query, values);
  }

  async run() {
    const result = this.database.prepare(this.query).run(...this.values);
    return { meta: { changes: Number(result.changes) } };
  }

  async first() {
    return d1Row(this.database.prepare(this.query).get(...this.values) ?? null);
  }

  async all() {
    return {
      results: this.database
        .prepare(this.query)
        .all(...this.values)
        .map(d1Row),
    };
  }
}

export class LocalD1Database {
  constructor(path) {
    this.path = path;
    this.database = new DatabaseSync(path);
  }

  prepare(query) {
    return new Statement(this.database, query);
  }

  async batch(statements) {
    this.database.exec('BEGIN IMMEDIATE');
    try {
      const results = [];
      for (const statement of statements) {
        results.push(await statement.run());
      }
      this.database.exec('COMMIT');
      return results;
    } catch (error) {
      this.database.exec('ROLLBACK');
      throw error;
    }
  }

  close() {
    this.database.close();
  }
}

/** Reads every checked-in D1 migration in the order Wrangler applies them. */
export async function readD1Migrations() {
  const directory = new URL('../migrations/d1/', import.meta.url);
  const names = (await readdir(directory))
    .filter((name) => name.endsWith('.sql'))
    .sort();
  return Promise.all(
    names.map((name) => readFile(new URL(name, directory), 'utf8')),
  );
}

export async function createMigratedLocalD1(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dud-v2-d1-'));
  const database = new LocalD1Database(join(directory, 'd1.sqlite'));
  for (const migration of await readD1Migrations()) {
    database.database.exec(migration);
  }
  t.after(async () => {
    database.close();
    await rm(directory, { recursive: true, force: true });
  });
  return database;
}
