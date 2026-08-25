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

/**
 * Extract every module specifier from TypeScript/NodeNext ESM source.
 *
 * The import-discipline checks below judge *specifiers*, so a specifier this
 * helper fails to surface is silently exempt from the boundary. It therefore
 * covers all the static-graph import forms this project can use, in either
 * quote style, so no forbidden dependency can hide behind syntax:
 *
 *   - static:       `import x from '...'` / `import x from "..."`
 *                   (including multi-line `import type { ... } from '...'`)
 *   - side-effect:  `import '...'` / `import "..."`
 *   - dynamic:      `import('...')` / `import("...")`, with or without a second
 *                   options argument (`import('...', { with: { type: 'json' } })`)
 *   - re-export:    `export { x } from '...'` / `export * from "..."`
 *
 * A block comment between tokens does not hide the specifier — not even a block
 * comment that itself contains quote characters (a quoted-comment token
 * separator between `import` and `from`, or a comment just inside `import(`).
 * The token region between keywords consumes a whole block comment as a single
 * unit instead of stopping at the first quote inside it. (Ordinary unquoted
 * comment separators were already handled and remain so.)
 *
 * `import.meta.url` is deliberately not matched: the `import` keyword must be
 * followed by whitespace (static/side-effect) or `(` (dynamic), and `.` is
 * neither. This is a bounded lexical scan, not a parser — no AST dependency is
 * introduced.
 */
function extractModuleSpecifiers(source: string): readonly string[] {
  // A run of source between two keywords that may legally hold whole block
  // comments (which can contain quote characters) or any other non-quote text.
  // Consuming a `/* ... */` as one unit is what lets a quoted comment sit
  // between `import` and `from` without the scanner mistaking the comment's
  // quote for the specifier delimiter.
  const patterns: readonly RegExp[] = [
    // static (`import x from 'S'`) and side-effect (`import 'S'`) imports.
    /\bimport\s+(?:(?:\/\*[\s\S]*?\*\/|[^'"])*?\bfrom\s+)?['"]([^'"]+)['"]/g,
    // dynamic imports: `import('S')`, an optional leading block comment, and an
    // optional second options argument (closing `)` or a comma introduces it).
    /\bimport\s*\(\s*(?:\/\*[\s\S]*?\*\/\s*)?['"]([^'"]+)['"]\s*[,)]/g,
    // re-export bindings: `export { x } from 'S'`, `export * from 'S'`.
    /\bexport\b(?:\/\*[\s\S]*?\*\/|[^'"])*?\bfrom\s+['"]([^'"]+)['"]/g,
  ];
  const specifiers: string[] = [];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier !== undefined) {
        specifiers.push(specifier);
      }
    }
  }
  return specifiers;
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
  it('imports only node builtins, itself, or the Cockpit boundary', () => {
    for (const { file, text } of hostSources()) {
      for (const specifier of extractModuleSpecifiers(text)) {
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
      for (const specifier of extractModuleSpecifiers(text)) {
        expect(
          /adapter|transport|authorization|repair-job|permit|\.\.\/domain\//i.test(specifier),
          `${file} imports forbidden module: ${specifier}`,
        ).toBe(false);
      }
    }
  });
});

describe('D3 host import scanner recognizes every supported ESM form (D3-CR-F1)', () => {
  // A forbidden domain/adapter import must be surfaced no matter which valid
  // import syntax hides it — otherwise the discipline checks above are blind to
  // it. Each fixture below is a single valid TypeScript/NodeNext ESM statement.
  const forbiddenForms: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'single-quoted static from', source: `import x from '../domain/foo.js';` },
    { form: 'double-quoted static from', source: `import x from "../domain/foo.js";` },
    { form: 'single-quoted side-effect', source: `import '../adapters/foo.js';` },
    { form: 'double-quoted side-effect', source: `import "../adapters/foo.js";` },
    { form: 'single-quoted dynamic', source: `const m = import('../domain/foo.js');` },
    { form: 'double-quoted dynamic', source: `const m = import("../domain/foo.js");` },
    { form: 're-export from', source: `export { y } from "../domain/foo.js";` },
  ];

  for (const { form, source } of forbiddenForms) {
    it(`extracts the forbidden specifier from a ${form} import`, () => {
      const specifiers = extractModuleSpecifiers(source);
      const forbidden = specifiers.filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));
      expect(forbidden.length, `no specifier extracted from: ${source}`).toBeGreaterThan(0);
    });
  }

  it('extracts allowed node builtin, local, and Cockpit-boundary specifiers', () => {
    expect(extractModuleSpecifiers(`import http from 'node:http';`)).toContain('node:http');
    expect(extractModuleSpecifiers(`import { a } from "./local.js";`)).toContain('./local.js');
    expect(
      extractModuleSpecifiers(`import { readCockpitSnapshot } from '../cockpit/index.js';`),
    ).toContain('../cockpit/index.js');
  });

  it('extracts a multi-line `import type { ... } from` specifier', () => {
    const source = [
      'import type {',
      '  CockpitSnapshot,',
      '  CockpitFindingReadModel,',
      "} from '../cockpit/index.js';",
    ].join('\n');
    expect(extractModuleSpecifiers(source)).toContain('../cockpit/index.js');
  });

  it('does not treat `import.meta.url` as a module specifier', () => {
    const source = `const isEntry = import.meta.url === pathToFileURL(entry).href;`;
    expect(extractModuleSpecifiers(source)).toEqual([]);
  });
});

describe('D3 host import scanner covers dynamic-options and block-comment forms (D3-CR-F2/F3)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // D3-CR-F2: a dynamic import that carries a second options argument still
  // surfaces its specifier. Before this fix the scanner required `)` right after
  // the closing quote, so the comma-led options form extracted nothing and the
  // forbidden dependency slipped past both discipline checks.
  it('extracts the specifier from a dynamic import with an import-attributes options object', () => {
    expect(forbiddenIn(`import('../domain/foo.js', { with: { type: 'json' } })`).length).toBeGreaterThan(0);
  });

  it('extracts the specifier from a dynamic import with a bundler-style options object', () => {
    expect(forbiddenIn(`import('../domain/foo.js', { webpackChunkName: 'foo' })`).length).toBeGreaterThan(0);
  });

  // D3-CR-F3 (narrow, independently reproduced cases only).
  it('extracts the specifier when a block comment sits inside the dynamic import', () => {
    expect(forbiddenIn(`import(/* note */ '../domain/foo.js')`).length).toBeGreaterThan(0);
  });

  it('extracts the specifier across a quoted-comment token separator', () => {
    // The block comment contains a quote character; the scanner must consume the
    // whole comment as a unit rather than treating that inner quote as the
    // specifier delimiter.
    expect(forbiddenIn(`import /* 'note' */ x from '../domain/foo.js';`).length).toBeGreaterThan(0);
  });

  // Preservation: the ordinary unquoted comment separator was never broken and
  // must keep working (guards against over-narrowing the fix). The broad claim
  // that ordinary comment separators evade the scanner was NOT REPRODUCIBLE.
  it('still extracts across an ordinary unquoted comment separator', () => {
    expect(forbiddenIn(`import /* note */ x from '../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`export /* note */ { x } from '../domain/foo.js';`).length).toBeGreaterThan(0);
  });

  // Preservation: a single-argument dynamic import and allowed specifiers are
  // unaffected, and import.meta.url is still ignored.
  it('preserves single-argument dynamic, allowed, and import.meta behaviour', () => {
    expect(extractModuleSpecifiers(`import('../domain/foo.js');`)).toContain('../domain/foo.js');
    expect(extractModuleSpecifiers(`import http from 'node:http';`)).toContain('node:http');
    expect(extractModuleSpecifiers(`import { a } from "./local.js";`)).toContain('./local.js');
    expect(extractModuleSpecifiers(`import { r } from '../cockpit/index.js';`)).toContain(
      '../cockpit/index.js',
    );
    expect(extractModuleSpecifiers(`const isEntry = import.meta.url === x;`)).toEqual([]);
  });
});
