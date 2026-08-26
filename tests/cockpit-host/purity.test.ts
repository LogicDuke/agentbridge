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
 * A single ESM lexical token. Comments and whitespace are trivia and are never
 * emitted; strings (including template literals) are emitted whole so their
 * contents can never be mistaken for code. `num`/`regex` carry no value — they
 * exist only so a following `/` is disambiguated between division and a regex
 * literal, and so a quote inside a regex body is never read as a string.
 */
type EsmToken =
  | { readonly t: 'str'; readonly v: string; readonly template: boolean }
  | { readonly t: 'id'; readonly v: string }
  | { readonly t: 'punct'; readonly v: string }
  | { readonly t: 'num' }
  | { readonly t: 'regex' };

const isIdentifierStart = (c: string): boolean => /[A-Za-z_$]/.test(c);
const isIdentifierPart = (c: string): boolean => /[A-Za-z0-9_$]/.test(c);

// Keywords after which a `/` begins a regex literal rather than division. Any
// other identifier (a value, including `from`/`fromValues`) means division.
const REGEX_CONTEXT_KEYWORDS: ReadonlySet<string> = new Set([
  'return',
  'typeof',
  'instanceof',
  'in',
  'of',
  'new',
  'delete',
  'void',
  'do',
  'else',
  'case',
  'yield',
  'await',
  'throw',
]);

/**
 * Tokenize TypeScript/NodeNext ESM source with a single linear, comment- and
 * string-aware pass — a tiny state machine over four conceptual states (CODE,
 * LINE_COMMENT, BLOCK_COMMENT, STRING). Each character is consumed exactly once
 * and every inner scan advances monotonically, so the pass is O(n): there is no
 * regex backtracking and therefore no catastrophic (ReDoS) blow-up on
 * comment-heavy input.
 *
 * Trivia (whitespace, line comments, and block comments) is dropped while
 * statement structure is preserved. A `//` or a block-comment opener occurring
 * *inside* a string or a regex literal is ordinary text, never a comment. Because comments
 * are gone before any specifier is read, no comment-contained `from` can ever
 * fabricate a dependency (D3-CX-F8), and no comment position can hide a real one
 * (D3-CR-F4/F5/F6/F7 and line comments inside a re-export clause).
 */
function tokenizeEsm(source: string): readonly EsmToken[] {
  const tokens: EsmToken[] = [];
  const length = source.length;
  let index = 0;
  let previous: EsmToken | null = null;

  const regexCanFollow = (): boolean => {
    if (previous === null) return true;
    switch (previous.t) {
      case 'id':
        return REGEX_CONTEXT_KEYWORDS.has(previous.v);
      case 'num':
      case 'str':
      case 'regex':
        return false;
      case 'punct':
        return previous.v !== ')' && previous.v !== ']';
    }
  };
  const emit = (token: EsmToken): void => {
    tokens.push(token);
    previous = token;
  };

  while (index < length) {
    const c = source.charAt(index);

    // insignificant whitespace
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      index += 1;
      continue;
    }
    // line comment — trivia, consumed to end of line (the newline stays)
    if (c === '/' && source.charAt(index + 1) === '/') {
      index += 2;
      while (index < length && source.charAt(index) !== '\n') index += 1;
      continue;
    }
    // block comment — trivia, consumed whole as one unit (may span lines)
    if (c === '/' && source.charAt(index + 1) === '*') {
      index += 2;
      while (index < length && !(source.charAt(index) === '*' && source.charAt(index + 1) === '/')) {
        index += 1;
      }
      index += 2;
      continue;
    }
    // single- or double-quoted string — one atomic token; `//`, `/*`, and the
    // word `from` inside it are ordinary text and cannot start a comment or a
    // re-export clause.
    if (c === "'" || c === '"') {
      const quote = c;
      let cursor = index + 1;
      let value = '';
      while (cursor < length) {
        const d = source.charAt(cursor);
        if (d === '\\') {
          value += source.charAt(cursor + 1);
          cursor += 2;
          continue;
        }
        if (d === quote) {
          cursor += 1;
          break;
        }
        if (d === '\n') break; // an unterminated single/double string ends at the line
        value += d;
        cursor += 1;
      }
      emit({ t: 'str', v: value, template: false });
      index = cursor;
      continue;
    }
    // template literal — also an atomic string token, but flagged: only a plain
    // `'`/`"` string is a literal module specifier, so a template (`import(`...`)`
    // with substitutions) is never surfaced, exactly as before.
    if (c === '`') {
      let cursor = index + 1;
      let value = '';
      while (cursor < length) {
        const d = source.charAt(cursor);
        if (d === '\\') {
          value += source.charAt(cursor + 1);
          cursor += 2;
          continue;
        }
        if (d === '`') {
          cursor += 1;
          break;
        }
        value += d;
        cursor += 1;
      }
      emit({ t: 'str', v: value, template: true });
      index = cursor;
      continue;
    }
    // regex literal — only where a regex may legally begin, so `a / b` division
    // is not mistaken for one. Its body (which may hold quotes, `//`, or `from`)
    // is opaque and yields no specifier.
    if (c === '/' && regexCanFollow()) {
      let cursor = index + 1;
      let inClass = false;
      let closed = false;
      while (cursor < length) {
        const d = source.charAt(cursor);
        if (d === '\\') {
          cursor += 2;
          continue;
        }
        if (d === '\n') break;
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) {
          cursor += 1;
          closed = true;
          break;
        }
        cursor += 1;
      }
      if (closed) {
        while (cursor < length && isIdentifierPart(source.charAt(cursor))) cursor += 1; // flags
        emit({ t: 'regex' });
        index = cursor;
        continue;
      }
      // not a terminated regex — fall through and treat `/` as punctuation
    }
    // identifier / keyword
    if (isIdentifierStart(c)) {
      let cursor = index + 1;
      while (cursor < length && isIdentifierPart(source.charAt(cursor))) cursor += 1;
      emit({ t: 'id', v: source.slice(index, cursor) });
      index = cursor;
      continue;
    }
    // numeric literal (coarse — only needs to block a following `/` regex)
    if (c >= '0' && c <= '9') {
      let cursor = index + 1;
      while (cursor < length && /[0-9a-fA-FxXbBoOeE._]/.test(source.charAt(cursor))) cursor += 1;
      emit({ t: 'num' });
      index = cursor;
      continue;
    }
    // any other single character is punctuation / operator
    emit({ t: 'punct', v: c });
    index += 1;
  }
  return tokens;
}

/**
 * Extract every module specifier from TypeScript/NodeNext ESM source.
 *
 * The import-discipline checks below judge *specifiers*, so a specifier this
 * helper fails to surface is silently exempt from the boundary, and any string
 * it wrongly surfaces would fabricate a phantom dependency. It therefore covers
 * every static-graph import/re-export form this project can use, in either quote
 * style, with comments and quoted export names treated as trivia:
 *
 *   - static:       `import x from '...'` / `import x from "..."`
 *                   (including multi-line `import type { ... } from '...'`)
 *   - side-effect:  `import '...'` / `import "..."`
 *   - dynamic:      `import('...')` / `import("...")`, with or without a second
 *                   options argument (`import('...', { with: { type: 'json' } })`)
 *   - re-export:    `export { x } from '...'` / `export * from "..."`,
 *                   including quoted export names (`export { "x" as y } from …`)
 *
 * It runs over the token stream from {@link tokenizeEsm}, not the raw text, so
 * comments in any position are already gone and strings are atomic. That single
 * mechanism replaces the earlier trio of hand-tuned regexes and closes the whole
 * scanner family at once: block/line comments as trivia (D3-CR-F4..F7), quoted
 * export names, no comment-contained `from` fabricating a dependency (D3-CX-F8),
 * no cross-statement capture, no duplicate extraction, and linear-time scanning
 * with no catastrophic backtracking.
 *
 * The specifier of a static import or a re-export is the string that follows the
 * `from` keyword (so a quoted export name before `from` is skipped); a
 * side-effect import has no `from`, so its specifier is its first string. A
 * scan is bounded by the statement (`;`, or the next `import`/`export`), so a
 * following statement can never be captured. `import.meta.*` is excluded: the
 * `import` keyword there is followed by `.`, which starts neither a static
 * import nor a `(` dynamic import. This is a bounded lexical scan, not a
 * parser — no AST dependency is introduced.
 */
function extractModuleSpecifiers(source: string): readonly string[] {
  const tokens = tokenizeEsm(source);
  const specifiers: string[] = [];
  const isStatementBoundary = (tok: EsmToken): boolean =>
    (tok.t === 'punct' && tok.v === ';') ||
    (tok.t === 'id' && (tok.v === 'import' || tok.v === 'export'));

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === undefined || token.t !== 'id') continue;

    if (token.v === 'import') {
      const next = tokens[i + 1];
      // `import.meta.*` — not a module specifier.
      if (next?.t === 'punct' && next.v === '.') continue;
      // dynamic `import( 'S' … )` — the specifier, if a literal, is the first
      // token inside the parens.
      if (next?.t === 'punct' && next.v === '(') {
        const arg = tokens[i + 2];
        if (arg?.t === 'str' && !arg.template) specifiers.push(arg.v);
        continue;
      }
      // static (`import … from 'S'`) or side-effect (`import 'S'`).
      let fromSpecifier: string | null = null;
      let firstString: string | null = null;
      for (let j = i + 1; j < tokens.length; j += 1) {
        const scan = tokens[j];
        if (scan === undefined) break;
        if (j > i + 1 && isStatementBoundary(scan)) break;
        if (scan.t === 'str' && !scan.template && firstString === null) firstString = scan.v;
        const after = tokens[j + 1];
        if (scan.t === 'id' && scan.v === 'from' && after?.t === 'str' && !after.template) {
          fromSpecifier = after.v;
          break;
        }
      }
      const specifier = fromSpecifier ?? firstString;
      if (specifier !== null) specifiers.push(specifier);
      continue;
    }

    if (token.v === 'export') {
      // re-export: the specifier is the string immediately after the `from`
      // keyword. Requiring a string right after `from` distinguishes the clause
      // keyword from an identifier that merely starts with `from`, and from a
      // `from` used as an exported binding name. The scan stops at `;` or the
      // next statement, so no following statement is captured.
      for (let j = i + 1; j < tokens.length; j += 1) {
        const scan = tokens[j];
        if (scan === undefined) break;
        if (scan.t === 'punct' && scan.v === ';') break;
        if (scan.t === 'id' && (scan.v === 'import' || scan.v === 'export')) break;
        const after = tokens[j + 1];
        if (scan.t === 'id' && scan.v === 'from' && after?.t === 'str' && !after.template) {
          specifiers.push(after.v);
          break;
        }
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

describe('D3 host import scanner covers boundary block-comment positions (D3-CR-F4/F5)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // D3-CR-F4: a bare side-effect import has no `from`, so a block comment
  // between `import` and the specifier previously fell through every branch and
  // the forbidden dependency was not surfaced.
  it('extracts a side-effect specifier preceded by an unquoted block comment', () => {
    expect(forbiddenIn(`import /* note */ '../domain/foo.js';`).length).toBeGreaterThan(0);
  });

  it('extracts a side-effect specifier preceded by a quoted block comment', () => {
    expect(forbiddenIn(`import /* "note" */ '../domain/foo.js';`).length).toBeGreaterThan(0);
  });

  it('extracts a double-quoted side-effect specifier preceded by a block comment', () => {
    expect(forbiddenIn(`import /* note */ "../adapters/foo.js";`).length).toBeGreaterThan(0);
  });

  // D3-CR-F5: a block comment after the dynamic-import specifier, before the
  // options comma or the closing paren, previously blocked the match because
  // only whitespace was allowed in that position.
  it('extracts a dynamic specifier with a trailing block comment before the options object', () => {
    expect(
      forbiddenIn(`import('../domain/foo.js' /* note */, { with: { type: 'json' } })`).length,
    ).toBeGreaterThan(0);
  });

  it('extracts a double-quoted dynamic specifier with a trailing block comment before options', () => {
    expect(
      forbiddenIn(`import("../domain/foo.js" /* note */, { with: { type: "json" } })`).length,
    ).toBeGreaterThan(0);
  });

  it('extracts a dynamic specifier with a trailing block comment before the closing paren', () => {
    expect(forbiddenIn(`import('../domain/foo.js' /* note */)`).length).toBeGreaterThan(0);
  });

  // Preservation: the earlier boundary-comment forms and allowed/import.meta
  // behaviour are unaffected by widening these two positions.
  it('preserves prior comment forms, allowed imports, and import.meta exclusion', () => {
    expect(forbiddenIn(`import(/* note */ '../domain/foo.js')`).length).toBeGreaterThan(0);
    expect(
      forbiddenIn(`import('../domain/foo.js', { with: { type: 'json' } })`).length,
    ).toBeGreaterThan(0);
    expect(forbiddenIn(`import /* 'note' */ x from '../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(extractModuleSpecifiers(`import http from 'node:http';`)).toContain('node:http');
    expect(extractModuleSpecifiers(`import { r } from '../cockpit/index.js';`)).toContain(
      '../cockpit/index.js',
    );
    expect(extractModuleSpecifiers(`const isEntry = import.meta.url === x;`)).toEqual([]);
  });
});

describe('D3 host import scanner covers post-`from` re-export comments (D3-CR-F6)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // D3-CR-F6: a block comment between a re-export's `from` and its module string
  // blocked the match, because the pattern required the quote right after
  // `from`. The static-import pattern already tolerated that position, so only
  // the re-export form was blind and the forbidden dependency slipped past both
  // discipline checks.
  it('extracts a re-export specifier preceded by an unquoted block comment', () => {
    expect(forbiddenIn(`export { x } from /* note */ '../domain/foo.js';`).length).toBeGreaterThan(
      0,
    );
  });

  it('extracts a re-export specifier preceded by a quoted block comment', () => {
    // The comment holds a quote character, so it must be consumed as a whole
    // unit rather than mistaken for the specifier delimiter.
    expect(
      forbiddenIn(`export { x } from /* "note" */ '../domain/foo.js';`).length,
    ).toBeGreaterThan(0);
  });

  it('extracts a double-quoted re-export specifier preceded by a block comment', () => {
    expect(forbiddenIn(`export { x } from /* note */ "../domain/foo.js";`).length).toBeGreaterThan(
      0,
    );
  });

  it('extracts an export-star specifier preceded by a block comment', () => {
    expect(forbiddenIn(`export * from /* note */ '../domain/foo.js';`).length).toBeGreaterThan(0);
  });

  it('extracts a double-quoted export-star specifier preceded by a block comment', () => {
    expect(forbiddenIn(`export * from /* note */ "../adapters/foo.js";`).length).toBeGreaterThan(0);
  });

  it('extracts an `export type` specifier preceded by a block comment', () => {
    expect(
      forbiddenIn(`export type { T } from /* note */ '../domain/foo.js';`).length,
    ).toBeGreaterThan(0);
  });

  it('extracts a re-export specifier across a multi-line block comment', () => {
    const source = ['export { x } from /* multi', " line note */ '../domain/foo.js';"].join('\n');
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  // Preservation: the comment-free re-export, every earlier comment position,
  // allowed specifiers, and the import.meta.url exclusion are unaffected by
  // widening this one position.
  it('preserves prior re-export, import, dynamic, allowed, and import.meta behaviour', () => {
    expect(forbiddenIn(`export { y } from "../domain/foo.js";`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`export /* note */ { x } from '../domain/foo.js';`).length).toBeGreaterThan(
      0,
    );
    expect(forbiddenIn(`import /* note */ '../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`import /* 'note' */ x from '../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`import(/* note */ '../domain/foo.js')`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`import('../domain/foo.js' /* note */)`).length).toBeGreaterThan(0);
    expect(
      forbiddenIn(`import('../domain/foo.js', { with: { type: 'json' } })`).length,
    ).toBeGreaterThan(0);
    expect(extractModuleSpecifiers(`import http from 'node:http';`)).toContain('node:http');
    expect(extractModuleSpecifiers(`import { a } from "./local.js";`)).toContain('./local.js');
    expect(extractModuleSpecifiers(`import { r } from '../cockpit/index.js';`)).toContain(
      '../cockpit/index.js',
    );
    expect(extractModuleSpecifiers(`const isEntry = import.meta.url === x;`)).toEqual([]);
  });

  // The widened position must not double-count a specifier, and one match must
  // not swallow the statement that follows it.
  it('extracts each re-export specifier once, without capturing across statements', () => {
    const source = [
      "export { a } from /* note */ './local.js';",
      "export { b } from '../cockpit/index.js';",
    ].join('\n');
    expect(extractModuleSpecifiers(source)).toEqual(['./local.js', '../cockpit/index.js']);
  });
});

describe('D3 host import scanner is comment/string-aware across the whole family (D3-CR-F7/D3-CX-F8 consolidated)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // --- Comment adjacent to / abutting `from` (D3-CR-F7) ---
  it('extracts a named re-export with a block comment abutting `from`', () => {
    expect(forbiddenIn(`export { x } from/* note */'../domain/foo.js';`).length).toBeGreaterThan(0);
  });

  it('extracts star/type/double-quoted re-exports with a comment abutting `from`', () => {
    expect(forbiddenIn(`export * from/* note */'../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(
      forbiddenIn(`export type { T } from/* note */'../domain/foo.js';`).length,
    ).toBeGreaterThan(0);
    expect(forbiddenIn(`export * from/* note */"../adapters/foo.js";`).length).toBeGreaterThan(0);
  });

  it('extracts a specifier across a multi-line block comment abutting `from`', () => {
    const source = ['export { x } from/* multi', " line note */'../domain/foo.js';"].join('\n');
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  it('tolerates multiple consecutive comments after `from`', () => {
    expect(forbiddenIn(`export { x } from/* a *//* b */'../domain/foo.js';`).length).toBeGreaterThan(
      0,
    );
  });

  // --- Previously-open holes now closed ---
  // A: a line comment INSIDE a real re-export clause (before the real `from`).
  it('extracts a re-export whose clause contains a line comment (hole A)', () => {
    const source = ['export {', '  x, // note', '  y', "} from '../domain/foo.js';"].join('\n');
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  // B: a line comment between the export clause and the real `from`.
  it('extracts a re-export with a line comment before `from` (hole B)', () => {
    const source = ["export { x } // note", "from '../domain/foo.js';"].join('\n');
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  // C: a valid string ModuleExportName in the clause must not be read as the
  // specifier, and must not block reaching the real specifier after `from`.
  it('extracts a re-export with a quoted export name, not the quoted name (hole C)', () => {
    expect(extractModuleSpecifiers(`export { "foo" as bar } from '../domain/foo.js';`)).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers(`export { x as "foo" } from "../adapters/foo.js";`)).toEqual([
      '../adapters/foo.js',
    ]);
  });

  it('extracts a static import that uses a quoted import name', () => {
    expect(extractModuleSpecifiers(`import { "foo" as bar } from '../domain/foo.js';`)).toEqual([
      '../domain/foo.js',
    ]);
  });

  it('extracts a re-export whose binding is literally named `from`', () => {
    expect(extractModuleSpecifiers(`export { from } from '../domain/foo.js';`)).toEqual([
      '../domain/foo.js',
    ]);
  });

  // --- Comment-contained `from` must NOT fabricate a dependency (D3-CX-F8) ---
  const falsePositiveFixtures: readonly { readonly form: string; readonly source: string }[] = [
    {
      form: 'line comment, `from` abutting the quote',
      source: `export const safe = true; // docs: from'../domain/example.js'`,
    },
    {
      form: 'line comment, whitespace before the quote',
      source: `export const safe = true; // docs: from '../domain/example.js'`,
    },
    {
      form: 'block comment, `from` abutting the quote',
      source: `export const safe = true; /* docs: from'../domain/example.js' */`,
    },
    {
      form: 'multi-line block comment',
      source: ['export const safe = true;', '/* docs:', "   from'../domain/example.js'", '*/'].join(
        '\n',
      ),
    },
    {
      form: 'ASI (no semicolon), trailing block comment',
      source: `export const x = true /* docs: from'../domain/example.js' */`,
    },
    {
      form: 'ASI (no semicolon), trailing line comment',
      source: ['export const x = true', "// docs: from'../domain/example.js'"].join('\n'),
    },
    {
      form: 'a `from`-bearing string value, not a re-export',
      source: `export const doc = "from '../domain/example.js'";`,
    },
  ];

  for (const { form, source } of falsePositiveFixtures) {
    it(`does not extract a comment- or string-contained module (${form})`, () => {
      expect(extractModuleSpecifiers(source)).not.toContain('../domain/example.js');
      expect(forbiddenIn(source)).toEqual([]);
    });
  }

  it('still consumes a prefix comment holding quotes or the word `from` as trivia', () => {
    expect(extractModuleSpecifiers(`export /* 'note' */ { x } from '../domain/foo.js';`)).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers(`export /* from 'x' */ { a } from '../domain/foo.js';`)).toEqual([
      '../domain/foo.js',
    ]);
  });

  // --- Identifier safety: only the exact `from` keyword introduces a clause ---
  it('does not treat an identifier beginning with `from` as the clause keyword', () => {
    expect(extractModuleSpecifiers(`export const fromValues = 1;`)).toEqual([]);
    expect(extractModuleSpecifiers(`export const from_foo = true;`)).toEqual([]);
    expect(extractModuleSpecifiers(`export { y } fromX '../domain/foo.js';`)).toEqual([]);
    expect(extractModuleSpecifiers(`export { y } from1 '../domain/foo.js';`)).toEqual([]);
    expect(extractModuleSpecifiers(`const a = Array.from(xs);`)).toEqual([]);
    expect(extractModuleSpecifiers(`const b = Object.fromEntries(e);`)).toEqual([]);
  });

  // --- Boundaries: no cross-statement capture, no duplicates ---
  it('extracts each specifier once across mixed comment-heavy statements', () => {
    const source = [
      "export { a } from/* note */'./local.js';",
      "export const doc = true; // from'../domain/example.js'",
      "export { b } from '../cockpit/index.js';",
    ].join('\n');
    expect(extractModuleSpecifiers(source)).toEqual(['./local.js', '../cockpit/index.js']);
  });

  it('extracts mixed import and re-export forms in order, once each', () => {
    const source = [
      `import http from 'node:http';`,
      `export { a } from './local.js';`,
      `const d = import('../domain/foo.js');`,
    ].join('\n');
    expect(extractModuleSpecifiers(source)).toEqual([
      'node:http',
      './local.js',
      '../domain/foo.js',
    ]);
  });

  // --- Slash / token cases: division, regex literals, comment markers in strings ---
  it('is not confused by division, regex literals, or comment markers inside strings', () => {
    expect(extractModuleSpecifiers(`const q = a / b; const r = 1 / 2;`)).toEqual([]);
    expect(extractModuleSpecifiers(`const re = /['"]/g; const s = text.replace(/from/g, 'x');`)).toEqual(
      [],
    );
    expect(extractModuleSpecifiers(`const u = 'node:http//x'; const v = "a//b";`)).toEqual([]);
    expect(extractModuleSpecifiers(`const u = 'a/*b*/c';`)).toEqual([]);
    expect(extractModuleSpecifiers(`const u = 'https://example.com/from/x';`)).toEqual([]);
  });

  it('does not read a specifier out of a template literal', () => {
    const template = ['const t = `', `import x from '../domain/x.js'`, '`;'].join('');
    expect(extractModuleSpecifiers(template)).toEqual([]);
  });

  // --- Preservation of every earlier form under the new mechanism ---
  it('preserves static, side-effect, dynamic, allowed, and import.meta behaviour', () => {
    expect(forbiddenIn(`import /* note */ '../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`import /* 'note' */ x from '../domain/foo.js';`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`import(/* note */ '../domain/foo.js')`).length).toBeGreaterThan(0);
    expect(forbiddenIn(`import('../domain/foo.js' /* note */)`).length).toBeGreaterThan(0);
    expect(
      extractModuleSpecifiers(`import('../domain/foo.js', { with: { type: 'json' } })`),
    ).toContain('../domain/foo.js');
    expect(extractModuleSpecifiers(`import http from 'node:http';`)).toContain('node:http');
    expect(extractModuleSpecifiers(`import { a } from "./local.js";`)).toContain('./local.js');
    expect(extractModuleSpecifiers(`import { r } from '../cockpit/index.js';`)).toContain(
      '../cockpit/index.js',
    );
    expect(extractModuleSpecifiers(`const isEntry = import.meta.url === x;`)).toEqual([]);
  });

  // --- Liveness: comment-heavy legal input scans in linear time ---
  // The prior regex family exhibited catastrophic backtracking here (seconds for
  // ~20 comments). The tokenizer is single-pass, so a much larger input resolves
  // instantly; a regression to backtracking would blow vitest's per-test timeout.
  it('scans comment-heavy legal input in bounded, linear time', () => {
    const heavyImport = `import ${'/* c */'.repeat(400)} '../domain/foo.js';`;
    const heavyClause = `export {\n${'  a, // note\n'.repeat(400)}} from '../domain/foo.js';`;
    const start = performance.now();
    expect(extractModuleSpecifiers(heavyImport)).toEqual(['../domain/foo.js']);
    expect(extractModuleSpecifiers(heavyClause)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});
