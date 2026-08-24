import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * Cockpit D3 host purity, bounded to `src/cockpit-host/`.
 *
 * The host is allowed the I/O the pure D1/D2 layer forbids — it is an HTTP
 * server — but it must remain read-only and dependency-narrow: no subprocess,
 * no environment/secret access, no Git, and no import of any adapter, transport,
 * or authority module. It may reach domain truth only through the Cockpit
 * boundary (`../cockpit/`), never by importing the domain kernel directly.
 */

const hostDir = fileURLToPath(new URL('../../src/cockpit-host/', import.meta.url));

function hostSources(): readonly { readonly file: string; readonly text: string }[] {
  return readdirSync(hostDir, { recursive: true })
    .map((entry) => String(entry))
    .filter((name) => name.endsWith('.ts'))
    .map((name) => ({ file: name, text: readFileSync(join(hostDir, name), 'utf8') }));
}

describe('D3 host has no mutation, subprocess, secret, or Git capability', () => {
  it('references no subprocess, environment, or Git operation', () => {
    const forbidden: readonly RegExp[] = [
      /child_process/,
      /node:child_process/,
      /process\.env/,
      /\bexecSync\b/,
      /\bspawn(?:Sync)?\s*\(/,
      /\bexecFile\b/,
      /octokit/i,
      /simple-git/,
      /\bgit\s+(?:push|commit|merge|rebase|checkout)\b/,
    ];
    for (const { file, text } of hostSources()) {
      for (const pattern of forbidden) {
        expect(pattern.test(text), `${file} must not match ${String(pattern)}`).toBe(false);
      }
    }
  });
});

describe('D3 host import discipline', () => {
  const importSpecifiers = /from\s+'([^']+)'/g;

  it('imports only node builtins, itself, or the Cockpit boundary', () => {
    for (const { file, text } of hostSources()) {
      for (const match of text.matchAll(importSpecifiers)) {
        const specifier = match[1] ?? '';
        const allowed =
          specifier.startsWith('node:') ||
          specifier.startsWith('./') ||
          specifier.startsWith('../cockpit/');
        expect(allowed, `${file} imports forbidden specifier: ${specifier}`).toBe(true);
      }
    }
  });

  it('never imports an adapter, transport, or authority module (nor the domain kernel directly)', () => {
    for (const { file, text } of hostSources()) {
      for (const match of text.matchAll(importSpecifiers)) {
        const specifier = match[1] ?? '';
        expect(
          /adapter|transport|authorization|repair-job|permit|\.\.\/domain\//i.test(specifier),
          `${file} imports forbidden module: ${specifier}`,
        ).toBe(false);
      }
    }
  });
});
