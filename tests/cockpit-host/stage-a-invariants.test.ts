/**
 * Cockpit D3 — Stage-A source invariants (frozen-source pin).
 *
 * This is a DELIBERATELY TRIVIAL direct-source check, not an analyzer. It reads
 * the exact text of the frozen `src/cockpit-host/**` files and asserts a small,
 * finite set of facts with plain string / single-regex matching. It performs:
 *   - no AST parsing, no TypeScript compiler, no module resolver;
 *   - no alias / value-flow / data-flow / receiver tracking;
 *   - no fixpoint, no export-fact propagation, no generic JS semantic analysis.
 *
 * It pins facts about the *current authored source* only, so that a future edit
 * that reintroduces (say) `process.env` or a second server has to be a
 * deliberate, visible change. It makes NO claim about runtime behavior: literal
 * / runtime no-egress is out of scope and belongs to a future runtime / process
 * / OS isolation boundary, never to a source check.
 */
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

/** Frozen Stage-A host source. Every executable host file is listed explicitly. */
const HOST_FILES = ['escape.ts', 'render.ts', 'server.ts', 'styles.ts', 'fixtures/stage-a.ts'] as const;

const HOST_URL = new URL('../../src/cockpit-host/', import.meta.url);

const SOURCES = HOST_FILES.map((file) => ({
  file,
  text: readFileSync(new URL(file, HOST_URL), 'utf8'),
}));

/**
 * Trivial specifier extraction: the quoted module string in a static
 * `… from '…'`, a bare side-effect `import '…'`, or a `import('…')`. This is a
 * direct regex over frozen text, not a parser or resolver — it does no module
 * resolution and models no scope.
 */
function specifiersOf(text: string): string[] {
  const out: string[] = [];
  const re =
    /\bfrom\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s+['"]([^'"]+)['"]/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    out.push((match[1] ?? match[2] ?? match[3]) as string);
  }
  return out;
}

/**
 * The exact, frozen set of literal runtime import specifiers the five Stage-A
 * host source files use — derived from the current real source, NOT a prefix
 * rule. Any specifier outside this set (e.g. `./network.js`, `../cockpit/other.js`,
 * `node:fs`) fails the pin until this frozen Stage-A invariant is deliberately
 * updated here. This is exact literal set membership — no closure walking, no
 * file resolution, no AST.
 */
const FROZEN_SPECIFIERS: ReadonlySet<string> = new Set([
  'node:http',
  'node:url',
  '../cockpit/index.js',
  './escape.js',
  './fixtures/stage-a.js',
  './render.js',
  './styles.js',
]);

function isFrozenSpecifier(specifier: string): boolean {
  return FROZEN_SPECIFIERS.has(specifier);
}

describe('Cockpit D3 Stage-A source invariants (frozen-source pin, not an analyzer)', () => {
  it('reads no process environment (`process.env`)', () => {
    for (const { file, text } of SOURCES) {
      expect(text.includes('process.env'), `${file} must not read process.env`).toBe(false);
    }
  });

  it('executes no subprocess and runs no Git', () => {
    const forbidden = ['child_process', 'execSync', 'execFileSync', 'spawnSync', 'spawn(', 'simple-git'];
    for (const { file, text } of SOURCES) {
      for (const token of forbidden) {
        expect(text.includes(token), `${file} must not reference ${token}`).toBe(false);
      }
    }
  });

  it('imports exactly the frozen Stage-A specifier set (no broad prefix acceptance)', () => {
    const actual = new Set<string>();
    for (const { text } of SOURCES) {
      for (const specifier of specifiersOf(text)) {
        actual.add(specifier);
      }
    }
    expect([...actual].sort()).toEqual([...FROZEN_SPECIFIERS].sort());
  });

  it('limits Node builtin imports to exactly {node:http, node:url}', () => {
    const builtins = new Set<string>();
    for (const { text } of SOURCES) {
      for (const specifier of specifiersOf(text)) {
        if (specifier.startsWith('node:')) {
          builtins.add(specifier);
        }
      }
    }
    expect([...builtins].sort()).toEqual(['node:http', 'node:url']);
  });

  it('contains exactly one authored http.createServer(...) site', () => {
    const total = SOURCES.reduce(
      (count, { text }) => count + (text.match(/createServer\s*\(/g)?.length ?? 0),
      0,
    );
    expect(total).toBe(1);
  });

  it('binds the literal loopback address and never a routable one', () => {
    const server = SOURCES.find((entry) => entry.file === 'server.ts');
    expect(server).toBeDefined();
    const text = server?.text ?? '';
    expect(text.includes("'127.0.0.1'")).toBe(true);
    expect(text.includes("'0.0.0.0'")).toBe(false);
    expect(text.includes("'::'")).toBe(false);
  });
});

describe('specifier extraction — literal ESM forms (regression)', () => {
  it('extracts bare static side-effect imports', () => {
    expect(specifiersOf('import "node:fs";')).toEqual(['node:fs']);
    expect(specifiersOf("import 'node:https';")).toEqual(['node:https']);
  });

  it('still extracts static named/default imports (single match, no double count)', () => {
    expect(specifiersOf("import x from '../cockpit/index.js';")).toEqual(['../cockpit/index.js']);
    expect(specifiersOf('import { a, b } from "node:http";')).toEqual(['node:http']);
    expect(specifiersOf("import y from 'node:url';")).toEqual(['node:url']);
  });

  it('still extracts dynamic imports', () => {
    expect(specifiersOf("const m = import('./render.js');")).toEqual(['./render.js']);
  });
});

describe('frozen specifier set — exact membership (regression)', () => {
  it('accepts every current real Stage-A specifier', () => {
    for (const specifier of [
      'node:http',
      'node:url',
      '../cockpit/index.js',
      './escape.js',
      './fixtures/stage-a.js',
      './render.js',
      './styles.js',
    ]) {
      expect(isFrozenSpecifier(specifier), `${specifier} should be frozen-accepted`).toBe(true);
    }
  });

  it('rejects a specifier outside the frozen set, extracted from any literal ESM form', () => {
    const cases: readonly [string, string][] = [
      ["import './network.js';", './network.js'],
      ["import x from '../cockpit/other.js';", '../cockpit/other.js'],
      ["import 'node:fs';", 'node:fs'],
    ];
    for (const [source, expected] of cases) {
      expect(specifiersOf(source)).toEqual([expected]);
      expect(isFrozenSpecifier(expected), `${expected} must not be frozen-accepted`).toBe(false);
    }
  });
});
