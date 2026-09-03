import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  ALLOWED_NODE_BUILTINS,
  collectRuntimeReferences,
  computeExecutableClosure,
  EXPECTED_CLOSURE,
  findHttpCreateServerSites,
  findListenCalls,
  REPO_ROOT,
  resolveRelativeSpecifier,
} from './executable-closure.js';

/**
 * Cockpit D3 — finite reviewed-source policy guard.
 *
 * This suite proves one bounded invariant about the *written source* of the
 * read-only dashboard host, expressed only as rules A–D:
 *
 *   A. Executable closure — the runtime ESM dependency closure of
 *      `src/cockpit-host/`, resolved through the TypeScript AST and normal
 *      relative-module resolution, is exactly a pinned set of files. Only
 *      runtime edges count; type-only imports/exports are erased.
 *   B. ESM only — a bare runtime `require(...)` (and `import x = require(...)`)
 *      is forbidden; CommonJS `.cts`/`.cjs` execution is not supported.
 *   C. Runtime imports — a runtime import may be only a relative specifier that
 *      resolves to a member of the pinned closure, or one of the exact Node
 *      builtins the current host actually requires. A computed / unverifiable
 *      dynamic `import(...)` fails closed.
 *   D. Authored server structure — the authored closure contains exactly one
 *      direct `http.createServer(...)` site (the real host), and its authored
 *      `listen(...)` binds the loopback host `127.0.0.1`, with the legitimate
 *      port constant preserved where statically resolvable.
 *
 * Runtime-isolation separation (recorded deliberately): this is a *source*
 * guard. It does NOT prove that arbitrary hostile runtime JavaScript cannot
 * perform network egress or otherwise escape. It intentionally implements no
 * provenance map, value/fact propagation, alias or receiver tracking, reflective
 * (Proxy / descriptor / Reflect) analysis, runtime code-generation route
 * scanning, or hidden-builtin value-flow. Strong runtime confinement is a
 * separate future process/OS isolation control and is out of scope here.
 */

/** Read a real closure source by its repo-relative path. */
function readSource(repoRelative: string): string {
  return readFileSync(join(REPO_ROOT, repoRelative), 'utf8');
}

/** Real path of a closure source, for importer-relative resolution. */
function realSourcePath(repoRelative: string): string {
  return realpathSync.native(join(REPO_ROOT, repoRelative));
}

const SERVER = 'src/cockpit-host/server.ts';

describe('A — runtime executable closure is pinned', () => {
  it('the real executable closure equals the pinned expected file set', () => {
    const closure = computeExecutableClosure();
    expect(closure.files).toEqual([...EXPECTED_CLOSURE]);
  });

  it('the real host source passes the finite guard with no violations (PR #55 unchanged)', () => {
    const closure = computeExecutableClosure();
    expect(closure.violations).toEqual([]);
  });

  it('every runtime relative dependency resolves to a pinned closure member', () => {
    const closure = computeExecutableClosure();
    const pinned = new Set(EXPECTED_CLOSURE);
    expect(closure.edges.length).toBeGreaterThan(0);
    for (const edge of closure.edges) {
      expect(pinned.has(edge.from)).toBe(true);
      expect(pinned.has(edge.to)).toBe(true);
    }
  });
});

describe('A — only executed modules become runtime edges', () => {
  it('a type-only import and a type-only export create no runtime edge', () => {
    const refs = collectRuntimeReferences(
      'fixture.ts',
      ["import type { A } from './a.js';", "export type { B } from './b.js';"].join('\n'),
    );
    expect(refs.staticImports).toEqual([]);
  });

  it('an all-`type` inline named import is erased, creating no runtime edge', () => {
    const refs = collectRuntimeReferences('fixture.ts', "import { type A, type B } from './a.js';");
    expect(refs.staticImports).toEqual([]);
  });

  it('a mixed value+type import still creates a runtime edge', () => {
    const refs = collectRuntimeReferences('fixture.ts', "import { value, type T } from './a.js';");
    expect(refs.staticImports).toEqual(['./a.js']);
  });

  it("the real render.ts imports the Cockpit boundary only as types — not a runtime edge", () => {
    const refs = collectRuntimeReferences(SERVER, readSource('src/cockpit-host/render.ts'));
    expect(refs.staticImports).toEqual(['./escape.js']);
    expect(refs.staticImports).not.toContain('../cockpit/index.js');
  });

  it('the real read-model.ts keeps its mixed value+type domain import as a runtime edge', () => {
    const refs = collectRuntimeReferences(SERVER, readSource('src/cockpit/read-model.ts'));
    expect(refs.staticImports).toContain('../domain/evidence.js');
  });
});

describe('B — ESM only, runtime require is forbidden', () => {
  it('surfaces a bare require(...) call', () => {
    const refs = collectRuntimeReferences('fixture.ts', "const fs = require('node:fs');");
    expect(refs.requireCalls).toEqual([{ specifier: 'node:fs' }]);
  });

  it('surfaces an `import x = require(...)` CommonJS interop form', () => {
    const refs = collectRuntimeReferences('fixture.ts', "import fs = require('node:fs');");
    expect(refs.requireCalls).toEqual([{ specifier: 'node:fs' }]);
  });

  it('the real closure contains no require call', () => {
    const closure = computeExecutableClosure();
    expect(closure.violations.filter((v) => v.startsWith('require('))).toEqual([]);
    for (const file of EXPECTED_CLOSURE) {
      expect(collectRuntimeReferences(file, readSource(file)).requireCalls).toEqual([]);
    }
  });
});

describe('C — runtime import allowlist', () => {
  it('a relative specifier resolves to its .ts source inside the closure', () => {
    const resolution = resolveRelativeSpecifier(realSourcePath(SERVER), './render.js');
    expect(resolution.ok).toBe(true);
    expect(resolution.target).toBe(realSourcePath('src/cockpit-host/render.ts'));
  });

  it('a static dynamic import is a supported, resolvable runtime edge', () => {
    const refs = collectRuntimeReferences('fixture.ts', "await import('./render.js');");
    expect(refs.staticDynamicImports).toEqual(['./render.js']);
    expect(refs.computedDynamicImports).toBe(0);
    const resolution = resolveRelativeSpecifier(realSourcePath(SERVER), './render.js');
    expect(resolution.ok).toBe(true);
  });

  it('the real host uses no dynamic import at all', () => {
    for (const file of EXPECTED_CLOSURE) {
      const refs = collectRuntimeReferences(file, readSource(file));
      expect(refs.staticDynamicImports).toEqual([]);
      expect(refs.computedDynamicImports).toBe(0);
    }
  });

  it('a computed / unverifiable dynamic import fails closed', () => {
    const identifier = collectRuntimeReferences('fixture.ts', 'await import(name);');
    const concat = collectRuntimeReferences('fixture.ts', "await import('../domain/' + name);");
    const template = collectRuntimeReferences('fixture.ts', 'await import(`../domain/${name}.js`);');
    expect(identifier.computedDynamicImports).toBe(1);
    expect(concat.computedDynamicImports).toBe(1);
    expect(template.computedDynamicImports).toBe(1);
    for (const refs of [identifier, concat, template]) {
      expect(refs.staticDynamicImports).toEqual([]);
    }
  });

  it('only the exact required Node builtins are used and accepted', () => {
    const closure = computeExecutableClosure();
    expect(closure.usedBuiltins).toEqual(['node:http', 'node:url']);
    expect(closure.usedBuiltins).toEqual([...ALLOWED_NODE_BUILTINS].sort((a, b) => (a < b ? -1 : 1)));
    expect(closure.violations.filter((v) => v.startsWith('disallowed builtin'))).toEqual([]);
  });

  it('another Node builtin is rejected (not on the allowlist)', () => {
    const refs = collectRuntimeReferences('fixture.ts', "import fs from 'node:fs';");
    expect(refs.staticImports).toEqual(['node:fs']);
    expect(ALLOWED_NODE_BUILTINS.has('node:fs')).toBe(false);
  });

  it('a bare, non-relative, non-node specifier is neither builtin nor in-tree', () => {
    const refs = collectRuntimeReferences('fixture.ts', "import { x } from 'express';");
    expect(refs.staticImports).toEqual(['express']);
    const specifier = refs.staticImports[0] ?? '';
    expect(specifier.startsWith('.')).toBe(false);
    expect(specifier.startsWith('node:')).toBe(false);
  });
});

describe('D — authored server structure', () => {
  it('exactly one direct http.createServer site exists across the authored closure', () => {
    const sites = EXPECTED_CLOSURE.flatMap((file) =>
      findHttpCreateServerSites(join(REPO_ROOT, file), readSource(file)),
    );
    expect(sites.length).toBe(1);
    expect(sites[0]?.file).toBe(SERVER);
  });

  it('the authored listen call binds the loopback host 127.0.0.1', () => {
    const calls = findListenCalls(join(REPO_ROOT, SERVER), readSource(SERVER));
    expect(calls.length).toBe(1);
    expect(calls[0]?.host).toEqual({ kind: 'string', value: '127.0.0.1' });
  });

  it('the legitimate port constant structure is preserved (statically resolvable)', () => {
    const calls = findListenCalls(join(REPO_ROOT, SERVER), readSource(SERVER));
    expect(calls[0]?.port).toEqual({ kind: 'number', value: 4317 });
  });
});
