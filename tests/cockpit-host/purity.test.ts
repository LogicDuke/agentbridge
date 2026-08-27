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
 * emitted; a `'`/`"` string is emitted whole so its contents can never be
 * mistaken for code. A template literal's text is likewise opaque, but its
 * `${ ... }` substitutions are executable code and are tokenized inline, so an
 * `import` hidden in a substitution is still seen. `template` marks a string that
 * came from backticks; `hasSubstitution` marks a template that carried a `${ }`
 * (so it is a computed value, not a fixed module specifier). `num`/`regex` carry
 * no value — they exist only so a following `/` is disambiguated between division
 * and a regex literal, and so a quote inside a regex body is never read as a
 * string.
 */
type EsmToken =
  | { readonly t: 'str'; readonly v: string; readonly template: boolean; readonly hasSubstitution: boolean }
  | { readonly t: 'id'; readonly v: string }
  | { readonly t: 'punct'; readonly v: string; readonly controlHeader?: boolean }
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

// Keywords whose parenthesised head is a *control-flow header* — `if (…)`,
// `while (…)`, `for (…)`, `with (…)`. The `)` that closes such a header is
// followed by a statement, whose first token may legally be a regex literal
// (`if (ok) /re/.test(x);`). This is unlike a value-producing `)` (`fn()`,
// `(x)`), after which a `/` is division. The distinction is carried on the
// closing `)` token via `controlHeader` so `regexCanFollow()` classifies the
// next `/` correctly (D3-CR-B); it is orthogonal to the object-literal `}`
// division case (C2), which is deliberately left unchanged.
const CONTROL_HEADER_KEYWORDS: ReadonlySet<string> = new Set([
  'if',
  'while',
  'for',
  'with',
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

  // Brace-depth stack for the currently open `${ ... }` template substitutions.
  // Empty means ordinary code; a top value of 0 means the next unmatched `}`
  // closes the current substitution and resumes the enclosing template's text.
  const substitutionStack: number[] = [];

  // Parenthesis-context stack: each open `(` pushes whether it began a
  // control-flow header (`if`/`while`/`for`/`with`). The matching `)` pops it and
  // records the flag on the emitted token, so a `/` right after the `)` is
  // classified as a regex (control header) or division (value paren).
  const parenStack: boolean[] = [];

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
        // A `)` closing a control-flow header (`if (…)`) may be followed by a
        // regex; a value-producing `)` (`fn()`, `(x)`) means division. `]` is
        // always a value (index/array), so a following `/` is division.
        if (previous.v === ')') return previous.controlHeader === true;
        return previous.v !== ']';
    }
  };
  // Whether the token before an opening `(` is a control-flow keyword — read
  // inside this helper (not inline in the main loop) so `previous` keeps its
  // declared `EsmToken | null` type and narrows over the full token union, as in
  // `regexCanFollow`.
  const previousOpensControlHeader = (): boolean => {
    if (previous === null || previous.t !== 'id' || !CONTROL_HEADER_KEYWORDS.has(previous.v)) {
      return false;
    }
    // A control keyword spelled as a *member name* — `obj.for(…)`, `Symbol.for(…)`,
    // `obj.if(…)` — is a value-producing method call, not a control-flow header:
    // its closing `)` must stay a value paren so a following `/` is division, not
    // a regex (which would swallow a later real import — D3-CR-B2). The keyword
    // heads a control statement only when it is *bare*, i.e. not immediately
    // preceded by a `.` member-access punctuator. `previous` is the just-emitted
    // keyword (`tokens[len-1]`), so `tokens[len-2]` is the token before it; a
    // leading `.` (including the `.` of `?.`) marks member access. Computed access
    // (`obj['for'](…)`) already fails the `previous.t === 'id'` check above, since
    // the token before `(` is then `]`.
    const beforePrevious = tokens[tokens.length - 2];
    if (beforePrevious?.t === 'punct' && beforePrevious.v === '.') return false;
    return true;
  };
  const emit = (token: EsmToken): void => {
    tokens.push(token);
    previous = token;
  };

  // Scan a template literal's *text* run starting at `from` (the character just
  // past an opening backtick or past a substitution's closing `}`). Returns
  // where scanning stopped, whether a `${` substitution was opened there, and
  // the literal text consumed. `\`` and `\${` escapes are honoured so they never
  // open a substitution or end the template. Each character is read once, so the
  // scan is linear.
  const scanTemplateText = (
    from: number,
  ): { readonly end: number; readonly opened: boolean; readonly literal: string } => {
    let cursor = from;
    let literal = '';
    while (cursor < length) {
      const d = source.charAt(cursor);
      if (d === '\\') {
        literal += source.charAt(cursor + 1);
        cursor += 2;
        continue;
      }
      if (d === '`') {
        return { end: cursor + 1, opened: false, literal };
      }
      if (d === '$' && source.charAt(cursor + 1) === '{') {
        return { end: cursor + 2, opened: true, literal };
      }
      literal += d;
      cursor += 1;
    }
    return { end: cursor, opened: false, literal };
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
      emit({ t: 'str', v: value, template: false, hasSubstitution: false });
      index = cursor;
      continue;
    }
    // template literal — its text is opaque, but any `${ ... }` substitution is
    // executable code and is tokenized inline (via the main loop, guarded by the
    // substitution-brace stack), so a dynamic import hidden inside a substitution
    // is still surfaced (D3-CR-C1). A substitution-free template is a valid fixed
    // dynamic-import specifier (D3-CR-R1); a template that *has* substitutions is
    // flagged so it is never taken as a fixed specifier.
    if (c === '`') {
      const run = scanTemplateText(index + 1);
      index = run.end;
      if (run.opened) {
        emit({ t: 'str', v: run.literal, template: true, hasSubstitution: true });
        substitutionStack.push(0);
        // A `${ ... }` substitution begins a fresh JavaScript expression, so its
        // first executable token is at expression-start: a leading `/` is a regex
        // literal, not division. `emit` above set `previous` to the template
        // prefix `str`, which would wrongly make regexCanFollow() report a value
        // context; clear it so expression-start (regex allowed) holds (D3-CR-S1).
        previous = null;
      } else {
        emit({ t: 'str', v: run.literal, template: true, hasSubstitution: false });
      }
      continue;
    }
    // `{` / `}` inside an active substitution: track depth so a `}` that closes
    // the `${ ... }` resumes the enclosing template's text instead of being read
    // as code. Braces that belong to nested objects/blocks within the
    // substitution stay ordinary punctuation.
    if (substitutionStack.length > 0 && c === '{') {
      const top = substitutionStack.length - 1;
      substitutionStack[top] = (substitutionStack[top] ?? 0) + 1;
      emit({ t: 'punct', v: '{' });
      index += 1;
      continue;
    }
    if (substitutionStack.length > 0 && c === '}') {
      const top = substitutionStack.length - 1;
      const depth = substitutionStack[top] ?? 0;
      if (depth === 0) {
        substitutionStack.pop();
        const run = scanTemplateText(index + 1);
        index = run.end;
        if (run.opened) {
          substitutionStack.push(0);
          // another substitution opens immediately (`} … ${`); it too begins a
          // fresh expression, so restore expression-start rather than inheriting
          // the just-closed substitution's last token (D3-CR-S1).
          previous = null;
        } else {
          // the enclosing template is now fully closed and is a value, so a
          // following `/` is division, not the start of a regex.
          previous = { t: 'str', v: '', template: true, hasSubstitution: false };
        }
        continue;
      }
      substitutionStack[top] = depth - 1;
      emit({ t: 'punct', v: '}' });
      index += 1;
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
    // `(` / `)` — tracked so a control-flow header's closing `)` is distinguished
    // from a value-producing `)` when the next `/` is classified. Any `(`/`)`
    // reaching here is genuine code punctuation: those inside strings, comments,
    // regex bodies, and template text were already consumed above.
    if (c === '(') {
      parenStack.push(previousOpensControlHeader());
      emit({ t: 'punct', v: '(' });
      index += 1;
      continue;
    }
    if (c === ')') {
      const controlHeader = parenStack.pop() ?? false;
      emit({ t: 'punct', v: ')', controlHeader });
      index += 1;
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
      const prev = tokens[i - 1];
      const next = tokens[i + 1];
      // `obj.import` / `obj.import(...)` — a member access, not an ESM import.
      if (prev?.t === 'punct' && prev.v === '.') continue;
      // `import.meta.*` — not a module specifier.
      if (next?.t === 'punct' && next.v === '.') continue;
      // A member named `import` — `{ import: ... }` (object property keyed
      // `import`) or `class C { import = … }` (a class field whose name is the
      // reserved word `import`). Neither is an ESM import: `:` introduces the
      // property value and `=` the field initializer, so the following string is
      // data, not a module specifier (D3-CR-C3/A). A real import is never
      // immediately followed by `:` or `=` (`import x = require(…)` puts an
      // identifier after `import`, not `=`).
      if (next?.t === 'punct' && (next.v === ':' || next.v === '=')) continue;
      // dynamic `import( 'S' … )` — the specifier, if a literal, is the first
      // token inside the parens. A plain string or a substitution-free template
      // is a fixed specifier; a template that carries `${ }` substitutions is a
      // computed value and is not surfaced.
      if (next?.t === 'punct' && next.v === '(') {
        const arg = tokens[i + 2];
        if (arg?.t === 'str' && !arg.hasSubstitution) specifiers.push(arg.v);
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

describe('D3 host import scanner handles template literals and import context (D3-CR-C1/C3/R1)', () => {
  // A backtick built without a template literal, so the source fixtures below can
  // embed real backticks and `${ }` sequences as plain text.
  const BT = '`';
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // --- C1: executable code inside a `${ }` substitution is still scanned ---
  it('surfaces a dynamic import hidden inside a template substitution (C1)', () => {
    const source = 'const text = ' + BT + "${import('../domain/foo.js')}" + BT + ';';
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  it('surfaces a dynamic import inside a nested template substitution (C1)', () => {
    const source = 'const t = ' + BT + '${ f(' + BT + '${import("../domain/foo.js")}' + BT + ') }' + BT + ';';
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  it('does not fabricate a specifier from a substitution that holds no import (C1 safety)', () => {
    const source = 'const t = ' + BT + '${ compute(x) + y }' + BT + ';';
    expect(extractModuleSpecifiers(source)).toEqual([]);
  });

  // --- R1: a substitution-free template is a valid fixed dynamic specifier ---
  it('surfaces a substitution-free template dynamic import specifier (R1)', () => {
    const source = 'import(' + BT + '../domain/foo.js' + BT + ');';
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  it('surfaces a substitution-free template dynamic import with options (R1)', () => {
    const source = 'import(' + BT + '../domain/foo.js' + BT + ", { with: { type: 'json' } });";
    expect(extractModuleSpecifiers(source)).toContain('../domain/foo.js');
  });

  it('does NOT surface a template dynamic import that carries a substitution (R1 negative)', () => {
    const source = 'import(' + BT + '../domain/${name}.js' + BT + ');';
    expect(extractModuleSpecifiers(source)).toEqual([]);
  });

  it('does NOT accept a template after `from` or as a bare specifier (syntax-invalid forms)', () => {
    // `import x from ` template ` ` and `import ` template ` ` are not legal ESM;
    // the scanner must not surface them.
    expect(extractModuleSpecifiers('import x from ' + BT + '../domain/foo.js' + BT + ';')).toEqual([]);
    expect(extractModuleSpecifiers('import ' + BT + '../domain/foo.js' + BT + ';')).toEqual([]);
  });

  // --- C3: `import` only counts in a genuine import context ---
  it('does not treat a property keyed `import` as an import (C3)', () => {
    expect(extractModuleSpecifiers("const config = { import: '../domain/foo.js' };")).toEqual([]);
    expect(extractModuleSpecifiers("const config = { import : '../domain/foo.js' };")).toEqual([]);
  });

  it('does not treat a method named `import` as an import (C3)', () => {
    expect(extractModuleSpecifiers('const obj = { import() { return 1; } };')).toEqual([]);
    expect(
      extractModuleSpecifiers("const obj = { import() { return '../domain/foo.js'; } };"),
    ).toEqual([]);
  });

  it('does not treat member access `obj.import(...)` as a dynamic import (C3)', () => {
    expect(extractModuleSpecifiers("obj.import('../domain/foo.js');")).toEqual([]);
    expect(extractModuleSpecifiers('const x = obj.import;')).toEqual([]);
  });

  it('does not treat a quoted `"import"` key or `import`-prefixed identifier as an import (C3)', () => {
    expect(extractModuleSpecifiers('const o = { "import": \'../domain/foo.js\' };')).toEqual([]);
    expect(extractModuleSpecifiers("const importX = '../domain/foo.js';")).toEqual([]);
    expect(extractModuleSpecifiers("const reimport = '../domain/foo.js';")).toEqual([]);
  });

  // --- Adversarial template tokenizer state ---
  it('keeps tokenizer state correct across template escapes, comments, strings, and regex', () => {
    const F = '../domain/foo.js';
    const cases: readonly string[] = [
      'const t = ' + BT + 'a\\' + BT + 'b' + BT + "; import '" + F + "';", // escaped backtick
      'const t = ' + BT + '\\${import("x")}' + BT + "; import '" + F + "';", // escaped ${ is text
      'const t = ' + BT + '${ {a:1} }' + BT + "; import '" + F + "';", // object braces in subst
      'const t = ' + BT + '${ "}" + import(\'' + F + '\') }' + BT + ';', // string holding } in subst
      'const t = ' + BT + '${ /* } */ import(\'' + F + '\') }' + BT + ';', // comment holding } in subst
      'const t = ' + BT + '${ /[}]/g.test(x) }' + BT + "; import '" + F + "';", // regex holding } in subst
    ];
    // Every case links exactly one real forbidden import (the trailing/inner one).
    for (const source of cases) {
      expect(forbiddenIn(source).length).toBeGreaterThan(0);
    }
    // Escaped-`${` and object-brace cases must not themselves fabricate a module.
    expect(extractModuleSpecifiers('const t = ' + BT + '\\${import("../domain/x.js")}' + BT + ';')).toEqual(
      [],
    );
  });

  it('scans substitution-heavy and deeply-nested templates in bounded, linear time', () => {
    const many = 'const t = ' + BT + '${x}'.repeat(600) + BT + "; import '../domain/foo.js';";
    let nested = "import('../domain/foo.js')";
    for (let k = 0; k < 600; k += 1) nested = BT + '${' + nested + '}' + BT;
    const nestedSource = 'const t = ' + nested + ';';
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(extractModuleSpecifiers(nestedSource)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

describe('D3 host import scanner treats a `${` substitution as expression-start (D3-CR-S1)', () => {
  // A `${ ... }` substitution begins a fresh JavaScript expression. The prior
  // template-substitution tokenizer left `previous` pointing at the template
  // prefix `str`, so regexCanFollow() reported a *value* context and a leading
  // `/` inside the substitution was mis-tokenized as division. A quote in the
  // resulting "regex-as-division" text then opened a spurious string that either
  // swallowed a following real import (false negative) or exposed a fake one
  // buried in the regex body (false positive). The fix resets `previous` to
  // expression-start whenever a substitution opens (both `\`${` and `}…${`).
  const BT = '`';
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // --- S1-A: a regex whose class holds a quote must not swallow a later import.
  // Single-line form is load-bearing: with the defect the spurious string runs
  // to the real import's quote and the specifier is lost (returns []).
  it('surfaces a real import after a `${ /[\']/ }` regex on the same line (S1-A)', () => {
    const source = 'const t = ' + BT + "${ /[']/.test(x) }" + BT + "; import '../domain/secret.js';";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/secret.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  it('surfaces a real import after a `${ /[\']/ }` regex on the next line (S1-A)', () => {
    const source = ['const t = ' + BT + "${ /[']/.test(x) }" + BT + ';', "import '../domain/secret.js';"].join(
      '\n',
    );
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/secret.js']);
  });

  // --- S1-B: a fake `import('...')` buried inside a regex body must NOT surface.
  it('does not fabricate a module from an import call inside a `${ /.../ }` regex body (S1-B)', () => {
    const source = 'const t = ' + BT + "${ /import('../domain/evil.js')/ }" + BT + ';';
    expect(extractModuleSpecifiers(source)).toEqual([]);
    expect(forbiddenIn(source)).toEqual([]);
  });

  // --- S1-C: a leading regex followed by a ternary must not hide a later import.
  it('surfaces a real import after a `${ /\\s+/ ? .. : .. }` ternary regex (S1-C)', () => {
    const source = 'const t = ' + BT + '${ /\\s+/.test(x) ? "a" : "b" }' + BT + "; import '../domain/z.js';";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/z.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  // --- Regex-vs-division context matrix. Each `${` independently begins an
  // expression, so a leading `/` is a regex; after a value-producing token a `/`
  // is division. A trailing real import proves no spurious string swallowed it.
  it('reads a `/` at expression-start inside `${` as a regex literal', () => {
    const withImport = (subst: string): string =>
      'const t = ' + BT + subst + BT + "; import '../domain/z.js';";
    // leading / parenthesised / unary / ternary / logical / assignment regex
    expect(extractModuleSpecifiers(withImport('${ /abc/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ /a\\/b/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ /[\'"]/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ (/abc/).test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ !/abc/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ x ? /a/ : /b/ }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ x && /a/.test(y) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ (r = /a/) }'))).toEqual(['../domain/z.js']);
  });

  it('reads a `/` after a value-producing token inside `${` as division', () => {
    // No import is present, so a mis-read regex (which would eat to the next `/`)
    // could only ADD a phantom; each of these must stay empty.
    expect(extractModuleSpecifiers('const t = ' + BT + '${ x / 2 }' + BT + ';')).toEqual([]);
    expect(extractModuleSpecifiers('const t = ' + BT + '${ 4 / 2 }' + BT + ';')).toEqual([]);
    expect(extractModuleSpecifiers('const t = ' + BT + '${ fn() / 2 }' + BT + ';')).toEqual([]);
    expect(extractModuleSpecifiers('const t = ' + BT + '${ arr[0] / 2 }' + BT + ';')).toEqual([]);
    expect(extractModuleSpecifiers('const t = ' + BT + '${ ({ x: 1 }).x / 2 }' + BT + ';')).toEqual([]);
  });

  // --- Each `${` in a multi-substitution template independently resets context.
  it('gives every substitution its own expression-start (regex then division)', () => {
    const a = 'const t = ' + BT + '${ /a/.test(x) }-${ /b/.test(y) }' + BT + "; import '../domain/z.js';";
    expect(extractModuleSpecifiers(a)).toEqual(['../domain/z.js']);
    // second substitution is a division context and must not fabricate a module
    const b = 'const t = ' + BT + '${ /a/.test(x) }-${ y / 2 }' + BT + ';';
    expect(extractModuleSpecifiers(b)).toEqual([]);
  });

  // --- A nested template restores expression-start for its own substitution and
  // then correctly resumes division in the outer expression on return.
  it('resets and restores context correctly across nested template substitutions', () => {
    const source =
      'const t = ' + BT + '${ ' + BT + 'x ${ /a/.test(p) }' + BT + ' + q / 2 }' + BT + "; import '../domain/z.js';";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/z.js']);
  });

  // --- A regex body may hold quotes, `//`, `}`, or a `${` sequence without
  // desyncing the substitution depth or fabricating a fake dependency.
  it('keeps substitution depth intact when a regex body holds quotes, comments, or `${`', () => {
    const withImport = (subst: string): string =>
      'const t = ' + BT + subst + BT + "; import '../domain/z.js';";
    expect(extractModuleSpecifiers(withImport('${ /a"b/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport("${ /a'b/.test(x) }"))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ /a\\/\\/b/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ /a${b}/.test(x) }'))).toEqual(['../domain/z.js']);
    expect(extractModuleSpecifiers(withImport('${ /[}]/g.test(x) }'))).toEqual(['../domain/z.js']);
    // fake import/export text living inside a regex body must never surface
    expect(
      extractModuleSpecifiers('const t = ' + BT + "${ /from '..\\/domain\\/evil.js'/.test(x) }" + BT + ';'),
    ).toEqual([]);
    expect(
      extractModuleSpecifiers(
        'const t = ' + BT + "${ /export y from '..\\/domain\\/e.js'/.test(x) }" + BT + ';',
      ),
    ).toEqual([]);
  });

  // --- Preservation: C1/C3/R1 remain fixed under the expression-start change.
  it('preserves C1 substitution imports, R1 template specifiers, and C3 non-imports', () => {
    expect(extractModuleSpecifiers('const text = ' + BT + "${import('../domain/foo.js')}" + BT + ';')).toEqual([
      '../domain/foo.js',
    ]);
    expect(
      extractModuleSpecifiers('const t = ' + BT + '${ f(' + BT + '${import("../domain/foo.js")}' + BT + ') }' + BT + ';'),
    ).toEqual(['../domain/foo.js']);
    expect(extractModuleSpecifiers('import(' + BT + '../domain/foo.js' + BT + ');')).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers('import(' + BT + '../domain/${name}.js' + BT + ');')).toEqual([]);
    expect(extractModuleSpecifiers("const config = { import: '../domain/foo.js' };")).toEqual([]);
  });

  // --- Liveness: many regex-leading substitutions and nested templates scan in
  // bounded linear time; a regression to rescanning would blow the timeout.
  it('scans many regex-leading substitutions in bounded, linear time', () => {
    const many =
      'const t = ' + BT + '${ /a/.test(x) }'.repeat(600) + BT + "; import '../domain/foo.js';";
    let nested = "import('../domain/foo.js')";
    for (let k = 0; k < 600; k += 1) nested = BT + '${ /q/.test(z) || ' + nested + ' }' + BT;
    const nestedSource = 'const t = ' + nested + ';';
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(extractModuleSpecifiers(nestedSource)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

describe('D3 host import scanner rejects a class field named `import` (D3-CR-A)', () => {
  // `import` is a reserved word, but reserved words are legal member names, so a
  // class field may be named `import`. Its `=` initializer is data, not a module
  // specifier — the scanner must not fabricate a dependency from it. Reported
  // independently by both Codex and CodeRabbit as the same false positive.
  it('does not treat a one-line class field `import = …` as an import', () => {
    expect(extractModuleSpecifiers("class Config { import = '../domain/foo.js'; }")).toEqual([]);
  });

  it('does not treat a multi-line class field `import = …` as an import', () => {
    const source = ['class Config {', "  import = '../domain/foo.js';", '}'].join('\n');
    expect(extractModuleSpecifiers(source)).toEqual([]);
  });

  it('does not treat an `import` field beside other fields as an import', () => {
    const source = ['class Config {', "  import = '../domain/foo.js';", '  other = 1;', '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(source)).toEqual([]);
  });

  it('does not treat a typed or static class field named `import` as an import', () => {
    // `import: string = …` is caught by the `:` guard; `static import = …` still
    // lands on the `=` guard, since the field-name token is `import`.
    expect(extractModuleSpecifiers("class C { import: string = '../domain/foo.js'; }")).toEqual([]);
    expect(extractModuleSpecifiers("class C { static import = '../domain/foo.js'; }")).toEqual([]);
  });

  // Preservation: the `=` guard must not blind the scanner to genuine imports,
  // which never place `=` immediately after the `import` keyword.
  it('still surfaces every genuine import form under the `=` guard', () => {
    expect(extractModuleSpecifiers("import '../domain/foo.js';")).toEqual(['../domain/foo.js']);
    expect(extractModuleSpecifiers("import x from '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("import { x } from '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("import type { T } from '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("import('../domain/foo.js');")).toEqual(['../domain/foo.js']);
    expect(
      extractModuleSpecifiers("import('../domain/foo.js', { with: { type: 'json' } });"),
    ).toContain('../domain/foo.js');
  });

  // Preservation: the other `import`-member exclusions are unaffected.
  it('keeps excluding property/method/member/prefixed `import` forms', () => {
    expect(extractModuleSpecifiers("const o = { import: '../domain/foo.js' };")).toEqual([]);
    expect(
      extractModuleSpecifiers("const o = { import() { return '../domain/foo.js'; } };"),
    ).toEqual([]);
    expect(extractModuleSpecifiers("obj.import('../domain/foo.js');")).toEqual([]);
    expect(extractModuleSpecifiers('const o = { "import": ' + "'../domain/foo.js' };")).toEqual([]);
    expect(extractModuleSpecifiers("const importX = '../domain/foo.js';")).toEqual([]);
    expect(extractModuleSpecifiers('const isEntry = import.meta.url === x;')).toEqual([]);
  });
});

describe('D3 host import scanner classifies `/` after a control-flow header as a regex (D3-CR-B)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // The `)` that closes `if (…)` / `while (…)` / `for (…)` / `with (…)` is a
  // control-flow header, whose statement body may start with a regex literal
  // (`if (ok) /re/.test(x);`). Before this fix that `)` was read as a
  // value-producing close, so `regexCanFollow()` returned false and the `/` was
  // treated as division. A quote inside the regex could then open a spurious
  // string (swallowing a following real import — false negative), and an
  // `import('…')` inside the regex body could be tokenized as code (fabricating
  // a dependency — false positive). This is distinct from the object-literal
  // `}` division case (C2), which is left unchanged.

  // False negative: a regex whose class holds a quote must not swallow a later
  // import (single-line form is load-bearing).
  it('surfaces a real import after a control-flow-header regex on the same line (B false negative)', () => {
    const source = "if (ok) /[']/.test(value); import '../domain/foo.js';";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  it('surfaces a real import after a control-flow-header regex on the next line (B false negative)', () => {
    const source = ["if (ok) /[']/.test(value);", "import '../domain/foo.js';"].join('\n');
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  // False positive: an `import('…')` buried in a regex body after a control
  // header must NOT surface.
  it('does not fabricate a module from an import call inside a control-flow-header regex (B false positive)', () => {
    expect(extractModuleSpecifiers("if (ok) /import('../domain/evil.js')/.test(value);")).toEqual(
      [],
    );
    expect(extractModuleSpecifiers("if (ok) /import('evil')/.test(value);")).toEqual([]);
  });

  // Context matrix: a regex is recognised after every control-flow header, so a
  // trailing real import is always surfaced (proving no spurious string ran on).
  it('recognizes a regex after if/while/for/with headers and preserves the trailing import', () => {
    const withImport = (stmt: string): string => stmt + " import '../domain/z.js';";
    for (const stmt of [
      "if (ok) /abc/.test(x);",
      "if (ok) /[']/.test(x);",
      'if (ok) /["]/.test(x);',
      "while (ok) /[']/.test(x);",
      "for (; ok;) /[']/.test(x);",
      "for (let i = 0; i < n; i += 1) /[']/.test(x);",
      "if (a && b) /[']/.test(x);",
      "if (f(x)) /[']/.test(x);", // nested value paren inside the control header
      "if ((a)) /[']/.test(x);",
    ]) {
      expect(extractModuleSpecifiers(withImport(stmt))).toEqual(['../domain/z.js']);
      expect(extractModuleSpecifiers(stmt + "\nimport '../domain/z.js';")).toEqual([
        '../domain/z.js',
      ]);
    }
  });

  // Preservation: a `/` after a value-producing `)` or `]` stays division, so no
  // phantom module is fabricated and a following real import is still surfaced.
  it('keeps division after value-producing parens and brackets', () => {
    expect(extractModuleSpecifiers('const r = fn() / 2;')).toEqual([]);
    expect(extractModuleSpecifiers('const r = (x) / 2;')).toEqual([]);
    expect(extractModuleSpecifiers('const r = arr[0] / 2;')).toEqual([]);
    expect(extractModuleSpecifiers('const r = (a + b) / c;')).toEqual([]);
    expect(extractModuleSpecifiers('function f() { return (x) / 2; }')).toEqual([]);
    expect(extractModuleSpecifiers("const r = fn() / 2;\nimport '../domain/z.js';")).toEqual([
      '../domain/z.js',
    ]);
  });

  // The object-literal `}` division case (C2) is deliberately untouched: the
  // same-line form still swallows and the next-line form still surfaces, exactly
  // as before this fix.
  it('leaves the object-literal `}` division case (C2) unchanged', () => {
    expect(extractModuleSpecifiers("const ratio = {} / value; import '../domain/foo.js';")).toEqual(
      [],
    );
    expect(
      extractModuleSpecifiers("const ratio = {} / value;\nimport '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
  });

  // Member-guard (D3-CR-B2): a control keyword spelled as a member/property name
  // (`Symbol.for(…)`, `obj.if(…)`) opens a value-producing call, not a control
  // header, so its `)` stays a value paren and a following `/` is division. Before
  // this guard, such a `)` was stamped `controlHeader`, the `/` began a regex, and
  // the regex swallowed the later real import (false negative — dependency skipped).
  it('does not treat a control keyword used as a member name as a control header', () => {
    for (const call of [
      "Symbol.for('x')",
      'obj.for(x)',
      'obj.if(x)',
      'a.while(y)',
      'a.with(y)',
      'foo.bar.for(x)',
      'ns.Symbol.for(x)',
    ]) {
      const source = call + " / 2; import '../domain/foo.js';";
      expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
      // next-line form too — the trailing import must survive regardless of layout
      expect(extractModuleSpecifiers(call + " / 2;\nimport '../domain/foo.js';")).toEqual([
        '../domain/foo.js',
      ]);
    }
  });

  // Member-guard, computed / optional / prefixed forms must likewise never be
  // read as control headers (none should even reach the keyword-member check, but
  // pin the behaviour so a future tokenizer change can't silently regress it).
  it('keeps division after computed, optional, and control-word-prefixed member calls', () => {
    for (const call of [
      "obj['for'](x)",
      'obj["if"](x)',
      'obj?.for(x)',
      'obj?.if(x)',
      'beforeThing(x)',
      'format(x)',
      'different(x)',
      'whileX(x)',
      'ifX(x)',
    ]) {
      expect(extractModuleSpecifiers(call + " / 2; import '../domain/foo.js';")).toEqual([
        '../domain/foo.js',
      ]);
    }
  });

  // Preservation of the genuine fix: a *bare* control-flow header still allows a
  // following regex, so the false-positive and false-negative B cases stay fixed.
  it('still treats a bare control-flow header regex correctly after the member guard', () => {
    expect(extractModuleSpecifiers("if (ok) /import('../domain/evil.js')/.test(value);")).toEqual(
      [],
    );
    expect(
      extractModuleSpecifiers("if (ok) /[']/.test(value); import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
    expect(
      extractModuleSpecifiers("while (ok) /[']/.test(value); import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
    expect(
      extractModuleSpecifiers("for (; ok;) /[']/.test(value); import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
  });

  // No stale marker leak: a member call named like a control keyword nested inside
  // a genuine control header must not corrupt the header's own `)` classification.
  it('keeps a genuine header regex working when it wraps a control-word member call', () => {
    expect(
      extractModuleSpecifiers("if (Symbol.for('x')) /[']/.test(value); import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
    // …and a member call after the header body still divides, not regexes.
    expect(
      extractModuleSpecifiers("if (ok) { obj.for(x) / 2; } import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
  });

  // Liveness: many control-flow-header regex statements scan in bounded linear
  // time; a regression to rescanning would blow vitest's per-test timeout.
  it('scans many control-flow-header regex statements in bounded, linear time', () => {
    const many = "if (ok) /[']/.test(x);\n".repeat(2000) + "import '../domain/foo.js';";
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});
