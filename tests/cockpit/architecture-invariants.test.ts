import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as cockpit from '../../src/cockpit/index.js';

/**
 * D1 architecture invariants, bounded to the Cockpit layer only.
 *
 * The Cockpit read-model contract must stay pure: no filesystem, no
 * subprocess, no HTTP or network client, no Git or GitHub access, and no
 * import outside the domain kernel it derives from. These tests inspect only
 * `src/cockpit/`, not unrelated repository layers.
 */

const cockpitDir = fileURLToPath(new URL('../../src/cockpit/', import.meta.url));

function cockpitSources(): readonly { readonly file: string; readonly text: string }[] {
  return readdirSync(cockpitDir)
    .filter((name) => name.endsWith('.ts'))
    .map((name) => ({ file: name, text: readFileSync(join(cockpitDir, name), 'utf8') }));
}

describe('D1 source purity', () => {
  it('contains no I/O, subprocess, network, or process-execution reference', () => {
    const forbidden: readonly RegExp[] = [
      /node:fs/,
      /child_process/,
      /node:child_process/,
      /node:http/,
      /node:https/,
      /node:net/,
      /node:tls/,
      /node:dgram/,
      /node:worker_threads/,
      /\bfetch\s*\(/,
      /XMLHttpRequest/,
      /WebSocket/,
      /EventSource/,
      /\brequire\s*\(/,
      /\bprocess\.\w/,
      /\bexecSync\b/,
      /\bspawn(?:Sync)?\s*\(/,
      /\bexecFile\b/,
      /simple-git/,
      /octokit/i,
      /\bgit\s+(?:push|commit|merge|rebase|checkout)\b/,
    ];
    for (const { file, text } of cockpitSources()) {
      for (const pattern of forbidden) {
        expect(pattern.test(text), `${file} must not match ${String(pattern)}`).toBe(false);
      }
    }
  });

  it('imports only from within src/, and only the domain kernel or itself', () => {
    const importSpecifiers = /from\s+'([^']+)'/g;
    for (const { file, text } of cockpitSources()) {
      for (const match of text.matchAll(importSpecifiers)) {
        const specifier = match[1] ?? '';
        const allowed = specifier.startsWith('./') || specifier.startsWith('../domain/');
        expect(allowed, `${file} imports forbidden specifier: ${specifier}`).toBe(true);
      }
    }
  });
});

describe('D1 exported surface grants no authority', () => {
  it('exports only readers and frozen vocabulary — no authority-shaped operation', () => {
    for (const [name, value] of Object.entries(cockpit)) {
      if (typeof value === 'function') {
        // Every exported function is a pure reader by naming convention and by
        // contract; nothing exported authorizes, executes, persists, or grants.
        expect(name.startsWith('read'), `unexpected non-reader export: ${name}`).toBe(true);
      } else if (typeof value === 'object') {
        expect(Object.isFrozen(value), `unfrozen exported constant: ${name}`).toBe(true);
      }
      expect(/^(authorize|execute|persist|grant|permit|apply|merge|push)/i.test(name)).toBe(
        false,
      );
    }
  });

  it('a reader result carries no authority-shaped field', () => {
    const result = cockpit.readCockpitSnapshot({});
    const forbiddenKeys = [
      'decision',
      'permit',
      'mayExecuteOnce',
      'approved',
      'approvalState',
      'authority',
    ];
    for (const key of forbiddenKeys) {
      expect(Object.hasOwn(result, key)).toBe(false);
    }
  });
});
