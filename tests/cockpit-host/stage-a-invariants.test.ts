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
 * `… from '…'` or a `import('…')`. This is a direct regex over frozen text, not
 * a parser or resolver — it does no module resolution and models no scope.
 */
function specifiersOf(text: string): string[] {
  const out: string[] = [];
  const re = /\bfrom\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    out.push((match[1] ?? match[2]) as string);
  }
  return out;
}

/** The only specifiers the read-only host is allowed to import. */
function isAllowedSpecifier(specifier: string): boolean {
  return (
    specifier === 'node:http' ||
    specifier === 'node:url' ||
    specifier.startsWith('./') ||
    specifier.startsWith('../cockpit/')
  );
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

  it('imports only node:http, node:url, itself, or ../cockpit/ (no GitHub/agent/permit authority)', () => {
    for (const { file, text } of SOURCES) {
      for (const specifier of specifiersOf(text)) {
        expect(isAllowedSpecifier(specifier), `${file} imports disallowed specifier ${specifier}`).toBe(true);
      }
    }
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
