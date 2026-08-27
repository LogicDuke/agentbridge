import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';
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
 * Relative-import confinement for the host boundary (D3-CX-POLICY-1).
 *
 * The import-discipline check below used to accept any specifier beginning `./`
 * (`specifier.startsWith('./')`). A redundant escaping form such as
 * `./../index.js` begins `./` yet, resolved from a file under
 * `src/cockpit-host/`, lands on `src/index.ts` — a re-export of the domain
 * kernel — and the literal forbidden-term check missed it because the specifier
 * text contains no `../domain/`. A relative specifier is therefore judged here by
 * its *resolved* destination relative to the importing host file, and accepted
 * only when that destination stays inside the host tree or enters the explicit
 * sibling Cockpit boundary (`src/cockpit/`).
 *
 * The resolution must model the ESM loader, not literal string arithmetic
 * (D3-CX-POLICY-F1). An earlier revision joined/normalized the specifier *text*
 * with `posix.join`/`posix.normalize`, which treats a percent-encoded dot
 * segment such as `%2e%2e` as an ordinary directory name and so accepted
 * `./%2e%2e/index.js` as in-host — yet WHATWG/Node resolution decodes `%2e%2e`
 * to `..` and lands that specifier on `src/index.js`, the domain re-export
 * barrel. Every specifier is therefore resolved exactly as Node's ESM loader
 * resolves it — `new URL(specifier, importerFileUrl)` then a Node-compatible
 * file-URL→path conversion — before the segment-aware containment rule runs.
 */
// Windows `fileURLToPath` output uses '\\'; folding a resolved path to
// '/'-separated form lets a `file:`-URL pathname compare like-for-like with the
// URL-derived boundaries below. Retained for the percent-filename assertion in the
// F1 suite; the confinement engine itself now compares `file:` URLs directly.
const toPosix = (value: string): string => value.replace(/\\/g, '/');

// The real host root and its sibling Cockpit boundary are derived from the *very*
// `hostDir` the sources are enumerated from — a single source of truth, so the
// guard's containment and the source reader agree by construction (D3-CX-POLICY-1).
// There is no synthetic root: a specifier is judged against where the host
// actually lives, so a path that exits the real repository and then re-enters a
// directory literally named like an allowed one (the `agentbridge-virtual/src/
// cockpit-host/…` re-entry, or a `<repo>-sibling/src/cockpit-host/…` prefix
// collision) can never be read as in-host. `hostDir` ends with a separator (it
// came from a trailing-slash URL), so `pathToFileURL` yields a directory URL
// ending in '/', and the Cockpit boundary is its real sibling `src/cockpit/`.
const HOST_ROOT_URL = pathToFileURL(hostDir);
const COCKPIT_BOUNDARY_URL = new URL('../cockpit/', HOST_ROOT_URL);

// Segment-aware containment on the resolved `file:` URL: an exact match, or a
// genuine sub-path guarded by the boundary's trailing '/', so a sibling such as
// `src/cockpit-host-evil/` is never read as inside `src/cockpit-host`, and a host
// path is never read as inside `src/cockpit`. `file:` URL hrefs carry a stable
// percent-encoding, so the comparison is identical on POSIX and Windows.
const isWithin = (candidate: URL, boundary: URL): boolean =>
  candidate.href === boundary.href || candidate.href.startsWith(boundary.href);

// `fileURLToPath` rejects `%2f` on every platform but `%5c` only on Win32; on a
// POSIX runner a `%5c` would otherwise decode to a literal backslash and fold
// back into an in-host segment. Reject both, case-insensitively, on both
// platforms so an encoded separator can never be read as in-host — matching how
// Node (which folds neither into a path separator) fails closed on Windows.
const ENCODED_SEPARATOR = /%2f|%5c/i;

/**
 * Resolve a *relative* module specifier against its importing host file — using
 * the *real* host location, exactly as Node's ESM loader would — and report
 * whether the resolved destination remains within the host tree or the Cockpit
 * boundary.
 *
 * The importer URL is built with native path→file-URL semantics
 * (`pathToFileURL(join(hostDir, importerRelPath))`); the importer relative path is
 * NOT folded through `toPosix` first, so a literal backslash in a POSIX filename
 * (`a\b.ts`, a single legal filename there) stays one segment and is percent-
 * encoded (`%5C`) rather than smuggled in as a directory separator — the earlier
 * `toPosix(importerRelPath)` fold deepened the importer's directory by a level and
 * let `../index.js` reach `src/index.js`, the domain re-export barrel, while the
 * guard reported in-host (D3-CX-POLICY-B). On Windows `join` keeps native
 * separators, so a real Windows path resolves natively. The specifier is then
 * resolved with `new URL(specifier, importerFileUrl)` (WHATWG resolution: it folds
 * `.`/`..` *and* their case-insensitive `%2e`-encoded forms, keeps an encoded
 * `/`/`\` intact within a segment, treats a literal backslash as a separator for
 * the special `file:` scheme, and drops any query/fragment from the path). This is
 * pure URL/path arithmetic — no file-system access — so synthetic fixture
 * (importer, specifier) pairs resolve identically to real ones. It fails closed
 * (returns `false`) on any resolution failure: an encoded separator, or a
 * malformed percent escape that makes the `fileURLToPath` decode throw (that
 * round-trip is performed for its throwing side effect, so a bad escape is
 * rejected exactly as before).
 */
const relativeImportStaysInBoundary = (importerRelPath: string, specifier: string): boolean => {
  let resolvedUrl: URL;
  try {
    const importerFileUrl = pathToFileURL(join(hostDir, importerRelPath));
    resolvedUrl = new URL(specifier, importerFileUrl);
    if (ENCODED_SEPARATOR.test(resolvedUrl.pathname)) return false;
    // Round-trip through `fileURLToPath` so a malformed percent escape (`%2`,
    // `%zz`) throws and fails closed, matching the real loader; the decoded path
    // is not otherwise needed because containment compares `file:` URLs.
    fileURLToPath(resolvedUrl);
  } catch {
    return false;
  }
  return isWithin(resolvedUrl, HOST_ROOT_URL) || isWithin(resolvedUrl, COCKPIT_BOUNDARY_URL);
};

// The host's production `node:*` needs are exactly these two (verified across
// `src/cockpit-host/**`); every other builtin — `node:fs`, `node:child_process`,
// `node:os`, `node:process`, `node:fs/promises`, … — is refused, so a "read-only"
// host cannot reach filesystem-mutation or process authority through a builtin
// (D3-CX-POLICY-3). This replaces the former blanket `specifier.startsWith('node:')`.
const ALLOWED_NODE_BUILTINS: ReadonlySet<string> = new Set(['node:http', 'node:url']);
const isAllowedNodeBuiltin = (specifier: string): boolean => ALLOWED_NODE_BUILTINS.has(specifier);

/**
 * Extract every static-graph module specifier from TypeScript/NodeNext ESM
 * source, using the TypeScript compiler's own parser as the single source of
 * truth.
 *
 * The import-discipline checks below judge *specifiers*, so a specifier this
 * helper fails to surface is silently exempt from the boundary, and any string it
 * wrongly surfaces would fabricate a phantom dependency. Earlier revisions
 * hand-rolled a lexer to decide, per `/`, whether it opened a regex or was
 * division, plus ASI, member-keyword, postfix, non-null, and control-header
 * special cases. That heuristic family regenerated a new corner case on almost
 * every review round, so it is replaced here by structural parsing: the same
 * `typescript` package the build already depends on parses the source once into
 * an AST, and a single walk collects specifiers only from the structural
 * import/export forms. Regex-vs-division, ASI, keyword-named members, non-null
 * assertions, and template context are then decided by the compiler's grammar,
 * not by us — so a `/` in `obj.return / 2`, a `debugger`/`break`/`continue`
 * statement boundary, or an `x!!` chain can never be misread, and an `import('…')`
 * sitting inside a regex or template *text* is opaque data, never a call node.
 * Because this is the parser the host is type-checked with, the scanner's notion
 * of "an import" is definitionally the one that actually loads a module.
 *
 * Collected forms (each only when the specifier is a *static* string):
 *   - `import … from 'S'` / side-effect `import 'S'` / `import type … from 'S'`
 *     — an `ts.ImportDeclaration`;
 *   - `export … from 'S'` / `export * from 'S'` / `export type … from 'S'`,
 *     including quoted export names — an `ts.ExportDeclaration` (a local
 *     `export { x }` with no `from` has no moduleSpecifier and is skipped);
 *   - `import x = require('S')` — an `ts.ImportEqualsDeclaration` whose reference
 *     is an external-module reference (`import x = ns.y` is an alias and skipped);
 *   - dynamic `import('S')` / `import('S', { … })` — a call whose callee is the
 *     `import` keyword; its first argument surfaces only as a `StringLiteral` or a
 *     substitution-free `NoSubstitutionTemplateLiteral`, never a substituted
 *     `TemplateExpression` (a computed specifier).
 *
 * Excluded structurally, with no special-casing: `import.meta` (a meta-property,
 * not a call), `obj.import(…)` (a property call), a plain `require(…)`, and a
 * member/property/class-field named `import` (`{ import: 'S' }`,
 * `class C { import = 'S' }`) — none of which is an import node. Specifiers are
 * returned in source order (a pre-order walk); repeats are kept, since each
 * import site is a distinct occurrence. This is a pure syntactic parse — no
 * binder, type-checker, module resolution, or file-system access.
 */
function extractModuleSpecifiers(source: string): readonly string[] {
  const sourceFile = ts.createSourceFile(
    'module.ts',
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ false,
    ts.ScriptKind.TS,
  );
  const specifiers: string[] = [];
  // The module specifier of a *static* import/export/`require` is grammatically a
  // `StringLiteral` — never a template. `import x from ` + backtick or
  // `import ` + backtick is a syntax error, and the parser's error recovery must
  // not let such a template be surfaced as a dependency, so require a real
  // `StringLiteral` here (`ts.isStringLiteral`, not `isStringLiteralLike`).
  const stringLiteralText = (node: ts.Node | undefined): string | null =>
    node !== undefined && ts.isStringLiteral(node) ? node.text : null;

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const specifier = stringLiteralText(node.moduleSpecifier);
      if (specifier !== null) specifiers.push(specifier);
    } else if (ts.isImportEqualsDeclaration(node)) {
      // `import x = require('S')` — an external-module reference.
      if (ts.isExternalModuleReference(node.moduleReference)) {
        const specifier = stringLiteralText(node.moduleReference.expression);
        if (specifier !== null) specifiers.push(specifier);
      }
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      // Dynamic `import('S' … )`: the specifier is the first argument, surfaced
      // only when static — a `StringLiteral` or a substitution-free
      // `NoSubstitutionTemplateLiteral` (both are `isStringLiteralLike`), never a
      // substituted `TemplateExpression` (a computed value). A second options
      // argument is ignored; `import.meta` is a MetaProperty, not a call, so it
      // never reaches this branch.
      const arg = node.arguments[0];
      if (arg !== undefined && ts.isStringLiteralLike(arg)) specifiers.push(arg.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return specifiers;
}

/**
 * Report whether the source contains a dynamic `import(...)` whose target is not a
 * statically verifiable string (D3-CX-POLICY-2). A computed argument — an
 * identifier, a concatenation, or a substituted template — cannot be confined by
 * `relativeImportStaysInBoundary`, so the import-discipline check must fail closed
 * on it rather than (as `extractModuleSpecifiers` structurally must) silently omit
 * it. Enforcing the rule here, in the discipline layer, keeps the extractor's
 * established contract — surface only static specifiers — unchanged.
 *
 * This uses the identical node discrimination as the extractor's dynamic-import
 * branch (a call whose callee is the `import` keyword), so it never fires on
 * `import.meta` (a meta-property, not a call), `obj.import(…)` (a property call),
 * or a member/property/class field named `import` — none of which is an import
 * call. A static `import('S')` or a substitution-free `` import(`S`) `` (both
 * `isStringLiteralLike`) is verifiable and does not trip it.
 */
const hasUnverifiableDynamicImport = (source: string): boolean => {
  const sourceFile = ts.createSourceFile(
    'module.ts',
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ false,
    ts.ScriptKind.TS,
  );
  let found = false;
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const arg = node.arguments[0];
      if (arg === undefined || !ts.isStringLiteralLike(arg)) found = true;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return found;
};

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
  it('imports only allow-listed node builtins, itself, or the Cockpit boundary', () => {
    for (const { file, text } of hostSources()) {
      // Fail closed: a dynamic `import(...)` whose target is not a static string
      // cannot be confined, so the host must contain none (D3-CX-POLICY-2). The
      // extractor necessarily omits such a computed specifier, so this is the
      // layer that must reject it.
      expect(
        hasUnverifiableDynamicImport(text),
        `${file} contains an unverifiable (computed) dynamic import`,
      ).toBe(false);
      for (const specifier of extractModuleSpecifiers(text)) {
        // A relative specifier is accepted only when its resolved destination is
        // confined to the host tree or the Cockpit boundary (D3-CX-POLICY-1); a
        // raw `./`/`../cockpit/` string prefix let a redundant escape like
        // `./../index.js` reach `src/index.ts` (the domain re-export barrel). A
        // `node:*` builtin is accepted only when on the exact production allowlist
        // (D3-CX-POLICY-3), not by a blanket `node:` prefix.
        const isRelative = specifier.startsWith('./') || specifier.startsWith('../');
        const allowed =
          isAllowedNodeBuiltin(specifier) ||
          (isRelative && relativeImportStaysInBoundary(file, specifier));
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

describe('D3 host relative-import confinement rejects boundary escapes (D3-CX-POLICY-1)', () => {
  // Mirror of the check-#1 acceptance predicate, exercised directly on synthetic
  // (importer, specifier) pairs. No production file is created; the bounded policy
  // helper is pure path arithmetic, so fixture paths resolve exactly as real ones.
  const accepts = (importer: string, specifier: string): boolean => {
    const isRelative = specifier.startsWith('./') || specifier.startsWith('../');
    return (
      isAllowedNodeBuiltin(specifier) ||
      (isRelative && relativeImportStaysInBoundary(importer, specifier))
    );
  };

  // --- Rejections: every relative path whose resolved destination leaves the host ---
  it('rejects the redundant `./`-prefixed parent escape to the barrel', () => {
    expect(accepts('server.ts', './../index.js')).toBe(false);
  });

  it('rejects a redundant `./`-prefixed escape straight into the domain kernel', () => {
    expect(accepts('server.ts', './../domain/index.js')).toBe(false);
  });

  it('rejects a deeper `../../src/index.js` traversal escape', () => {
    expect(accepts('server.ts', './../../src/index.js')).toBe(false);
    expect(accepts('server.ts', '../../src/index.js')).toBe(false);
  });

  it('rejects redundant dot segments that normalize outside the host', () => {
    expect(accepts('server.ts', './cockpit/../../index.js')).toBe(false);
    expect(accepts('server.ts', './././../adapters/foo.js')).toBe(false);
  });

  it('rejects an escape from a nested host file', () => {
    expect(accepts('fixtures/stage-a.ts', '../../index.js')).toBe(false);
    expect(accepts('fixtures/stage-a.ts', './../../domain/index.js')).toBe(false);
  });

  it('rejects a sibling directory whose name merely begins with the host dir name', () => {
    // `src/cockpit-host/../cockpit-host-evil/x.js` -> `src/cockpit-host-evil/x.js`
    expect(accepts('server.ts', '../cockpit-host-evil/x.js')).toBe(false);
  });

  it('rejects a sibling `cockpit-*` directory that is not the Cockpit boundary', () => {
    // `src/cockpit-host/../cockpit-secrets/x.js` -> `src/cockpit-secrets/x.js`;
    // must not be read as inside `src/cockpit`.
    expect(accepts('server.ts', '../cockpit-secrets/x.js')).toBe(false);
  });

  it('rejects a path with misleading allowed text before escaping', () => {
    // Threads through `cockpit/` yet resolves to `src/index.js`.
    expect(accepts('server.ts', './cockpit/../../index.js')).toBe(false);
    // Re-enters a `cockpit-host/`-named segment yet escapes above `src`.
    expect(accepts('server.ts', '../../cockpit-host/../index.js')).toBe(false);
  });

  it('rejects a backslash-smuggled escape, folded to `/` (POSIX/Windows-consistent)', () => {
    expect(accepts('server.ts', '.\\..\\index.js')).toBe(false);
    expect(accepts('server.ts', './..\\domain\\index.js')).toBe(false);
  });

  it('rejects a bare or plain-parent specifier that is not node: and not confined', () => {
    expect(accepts('server.ts', '../index.js')).toBe(false); // plain parent to the barrel
    expect(accepts('server.ts', '../domain/index.js')).toBe(false);
    expect(accepts('server.ts', 'typescript')).toBe(false);
  });

  // --- Preservations: every legitimate host / Cockpit import still accepted ---
  it('accepts a same-directory local import from a top-level host file', () => {
    expect(accepts('server.ts', './local.js')).toBe(true);
    expect(accepts('render.ts', './escape.js')).toBe(true);
  });

  it('accepts a nested local import', () => {
    expect(accepts('server.ts', './nested/local.js')).toBe(true);
    expect(accepts('server.ts', './fixtures/stage-a.js')).toBe(true);
  });

  it('accepts legitimate parent navigation that stays inside the host', () => {
    expect(accepts('fixtures/stage-a.ts', '../local.js')).toBe(true);
    expect(accepts('fixtures/stage-a.ts', '../render.js')).toBe(true);
  });

  it('accepts the explicit sibling Cockpit boundary from a top-level host file', () => {
    expect(accepts('server.ts', '../cockpit/index.js')).toBe(true);
  });

  it('accepts a legitimate Cockpit import from a nested host file', () => {
    expect(accepts('fixtures/stage-a.ts', '../../cockpit/index.js')).toBe(true);
  });

  it('restricts node: builtins to the exact production allowlist (POLICY-3)', () => {
    expect(accepts('server.ts', 'node:http')).toBe(true);
    expect(accepts('server.ts', 'node:url')).toBe(true);
    // Every non-allowlisted builtin is now refused (previously the blanket `node:`
    // prefix accepted them all): a "read-only" host cannot reach filesystem-
    // mutation or process authority through `node:*`.
    expect(accepts('server.ts', 'node:fs')).toBe(false);
  });

  // Integration: check #1 now catches the escape, and the forbidden-module check
  // (check #2) remains an independent defense whose behavior is unchanged.
  it('check #1 rejects `./../index.js` while the forbidden-module defense stays independent', () => {
    const spec = './../index.js';
    expect(accepts('server.ts', spec)).toBe(false); // now caught by check #1
    // check #2 independently does NOT match this specifier text, proving check #1
    // is the load-bearing defense here and check #2 is untouched by this repair.
    expect(/adapter|transport|authorization|repair-job|permit|\.\.\/domain\//i.test(spec)).toBe(
      false,
    );
  });

  // The real host sources still satisfy check #1 under the confinement predicate.
  it('accepts every specifier the real host sources actually import', () => {
    for (const { file, text } of hostSources()) {
      for (const specifier of extractModuleSpecifiers(text)) {
        expect(accepts(file, specifier), `${file} -> ${specifier}`).toBe(true);
      }
    }
  });
});

describe('D3 host confinement resolves percent-encoded URL dot-segments like Node (D3-CX-POLICY-F1)', () => {
  // The confinement helper used to join/normalize the specifier *text*, so a
  // percent-encoded dot segment (`%2e%2e`) was read as an ordinary directory name
  // and `import('./%2e%2e/index.js')` was accepted as in-host — while WHATWG/Node
  // ESM resolution decodes `%2e%2e` to `..` and lands it on `src/index.js`, the
  // domain re-export barrel. The helper now resolves every specifier through
  // `new URL` + `fileURLToPath` before the containment rule, so its verdict tracks
  // the real loader. These fixtures are synthetic; no production file is created
  // and no module is loaded — the helper performs pure URL/path arithmetic.
  const accepts = (importer: string, specifier: string): boolean => {
    const isRelative = specifier.startsWith('./') || specifier.startsWith('../');
    return (
      isAllowedNodeBuiltin(specifier) ||
      (isRelative && relativeImportStaysInBoundary(importer, specifier))
    );
  };

  // --- The exact original bypass, proven against the INTEGRATED policy path ---
  // Not a mirrored helper in isolation: the real scanner surfaces the specifier
  // from a real `import(...)` statement, and the exact check-#1 discipline
  // predicate then rejects it — parser through confinement, end to end.
  it('the integrated import-discipline path rejects the original `./%2e%2e/index.js` bypass', () => {
    const source = `import('./%2e%2e/index.js');`;
    const specifiers = extractModuleSpecifiers(source);
    expect(specifiers).toContain('./%2e%2e/index.js'); // the scanner surfaces it verbatim
    for (const specifier of specifiers) {
      // Identical to check #1 in `D3 host import discipline`.
      const isRelative = specifier.startsWith('./') || specifier.startsWith('../');
      const allowed =
        isAllowedNodeBuiltin(specifier) ||
        (isRelative && relativeImportStaysInBoundary('server.ts', specifier));
      expect(allowed, `integrated path must reject: ${specifier}`).toBe(false);
    }
    // check #2 (forbidden-term text match) does NOT catch this specifier, proving
    // check #1's URL-aware confinement is the load-bearing defense here.
    expect(
      /adapter|transport|authorization|repair-job|permit|\.\.\/domain\//i.test('./%2e%2e/index.js'),
    ).toBe(false);
  });

  // --- Cross-check against the runtime resolution model (WHATWG URL) ---
  // Independent of the helper's internals: `new URL` is the same algorithm Node's
  // ESM loader resolves specifiers with, so pinning the resolved pathname proves
  // the policy verdict cannot silently drift from real resolution.
  it('tracks Node URL resolution: encoded double-dot escapes onto the src barrel', () => {
    const spec = './%2e%2e/index.js';
    expect(new URL(spec, 'file:///r/src/cockpit-host/server.ts').pathname).toBe('/r/src/index.js');
    expect(accepts('server.ts', spec)).toBe(false);
  });

  it('tracks Node URL resolution: encoded double-dot then legitimate re-entry stays in host', () => {
    const spec = './%2e%2e/cockpit-host/index.js';
    expect(new URL(spec, 'file:///r/src/cockpit-host/server.ts').pathname).toBe(
      '/r/src/cockpit-host/index.js',
    );
    expect(accepts('server.ts', spec)).toBe(true);
  });

  it('tracks Node URL resolution: a query holding `%2e%2e` never changes the file path', () => {
    const spec = './local.js?x=%2e%2e';
    const resolved = new URL(spec, 'file:///r/src/cockpit-host/server.ts');
    expect(resolved.pathname).toBe('/r/src/cockpit-host/local.js');
    expect(resolved.search).toBe('?x=%2e%2e');
    expect(accepts('server.ts', spec)).toBe(true);
  });

  it('fileURLToPath decodes a legitimate percent filename exactly once', () => {
    // Drive-lettered URL so `fileURLToPath` accepts it on Windows and POSIX alike.
    // `%2525` decodes ONCE to `%25`, never twice to `%`, preserving the filename.
    const resolved = fileURLToPath(new URL('./file%2525.js', 'file:///C:/r/src/cockpit-host/a.ts'));
    expect(toPosix(resolved).endsWith('/src/cockpit-host/file%25.js')).toBe(true);
    expect(accepts('server.ts', './file%2525.js')).toBe(true);
  });

  // --- Rejection: the full encoded-dot-segment matrix (every ASCII case form) ---
  const rejectedEncodedTraversal: readonly { readonly importer: string; readonly spec: string }[] = [
    { importer: 'server.ts', spec: './%2e%2e/index.js' }, // lower
    { importer: 'server.ts', spec: './%2E%2E/index.js' }, // upper
    { importer: 'server.ts', spec: './%2e%2E/index.js' }, // mixed
    { importer: 'server.ts', spec: './%2E%2e/index.js' }, // mixed (other order)
    { importer: 'server.ts', spec: './%2e./index.js' }, // encoded + literal dot
    { importer: 'server.ts', spec: './.%2e/index.js' }, // literal + encoded dot
    { importer: 'server.ts', spec: './%2e%2e//index.js' }, // trailing empty segment
    { importer: 'server.ts', spec: './%2e%2e/%2e%2e/index.js' }, // two encoded hops
    // Encoded traversal from a NESTED importing file (fixtures/ -> src/index.js).
    { importer: 'fixtures/stage-a.ts', spec: './%2e%2e/%2e%2e/index.js' },
    // Encoded traversal followed by a misleading sibling-PREFIX destination:
    // resolves to `src/cockpit-host-evil/x.js`, which merely begins with the host
    // dir name and must not be read as inside it.
    { importer: 'server.ts', spec: './%2e%2e/cockpit-host-evil/x.js' },
    // Encoded traversal straight into the domain kernel.
    { importer: 'server.ts', spec: './%2e%2e/domain/index.js' },
  ];
  for (const { importer, spec } of rejectedEncodedTraversal) {
    it(`rejects encoded traversal ${JSON.stringify(spec)} from ${importer}`, () => {
      expect(accepts(importer, spec)).toBe(false);
    });
  }

  // --- Rejection: encoded separators and malformed escapes fail closed ---
  const rejectedInvalid: readonly string[] = [
    './%2f/x.js', // encoded '/'
    './..%2f/x.js', // literal `..` fused to an encoded '/'
    './%2F/x.js', // encoded '/' (upper)
    './%5c/x.js', // encoded '\'
    './%5C/x.js', // encoded '\' (upper)
    './%2e%2e%2fx.js', // encoded '/' after an encoded double-dot
    './%2/x.js', // truncated percent escape
    './%zz/x.js', // non-hex percent escape
    './%gg%2e/x.js', // non-hex escape beside an encoded dot
  ];
  for (const spec of rejectedInvalid) {
    it(`fails closed on ${JSON.stringify(spec)}`, () => {
      expect(accepts('server.ts', spec)).toBe(false);
    });
  }

  // --- Preservation: correct verdicts that must NOT regress ---
  const preserved: readonly {
    readonly importer: string;
    readonly spec: string;
    readonly verdict: boolean;
  }[] = [
    { importer: 'server.ts', spec: './%2e/index.js', verdict: true }, // single encoded dot == ./index.js
    { importer: 'server.ts', spec: './%2E/local.js', verdict: true }, // single encoded dot (upper)
    { importer: 'server.ts', spec: './%2e%2e/cockpit-host/index.js', verdict: true }, // traversal + re-entry
    { importer: 'server.ts', spec: './%252e%252e/index.js', verdict: true }, // double-encoded: literal `%2e%2e` dir
    { importer: 'server.ts', spec: './file%20name.js', verdict: true }, // legitimate percent (space) filename
    { importer: 'server.ts', spec: './file%2525.js', verdict: true }, // decode-once percent filename -> file%25.js
    { importer: 'server.ts', spec: './local.js?x=%2e%2e', verdict: true }, // query with %2e%2e is ignored
    { importer: 'server.ts', spec: './local.js#%2e%2e', verdict: true }, // fragment with %2e%2e is ignored
    { importer: 'server.ts', spec: './local.js', verdict: true }, // plain unencoded local import
    { importer: 'fixtures/stage-a.ts', spec: '../local.js', verdict: true }, // nested parent nav stays in host
    // Top-level and nested encoded imports into the Cockpit boundary.
    { importer: 'server.ts', spec: './%2e%2e/cockpit/index.js', verdict: true },
    { importer: 'fixtures/stage-a.ts', spec: './%2e%2e/%2e%2e/cockpit/index.js', verdict: true },
  ];
  for (const { importer, spec, verdict } of preserved) {
    it(`preserves the ${verdict ? 'accept' : 'reject'} verdict for ${JSON.stringify(spec)} from ${importer}`, () => {
      expect(accepts(importer, spec)).toBe(verdict);
    });
  }

  // --- No silent drift: the policy verdict equals an independent runtime oracle ---
  // The oracle re-derives containment from `new URL` + `fileURLToPath` under a
  // DIFFERENT synthetic root and DIFFERENT containment string logic than the
  // helper, so a change that decoupled the policy from real resolution would make
  // these disagree and fail the test.
  const runtimeOracleStaysInBoundary = (importer: string, specifier: string): boolean => {
    const importerUrl = new URL(
      `src/cockpit-host/${importer.replace(/\\/g, '/')}`,
      'file:///D:/oracle-root/',
    );
    try {
      const u = new URL(specifier, importerUrl);
      if (/%2f|%5c/i.test(u.pathname)) return false;
      // fileURLToPath emits a drive-prefixed `D:\…` on Windows and `/D:/…` on
      // POSIX; anchor on the unique synthetic-root marker and match the segments
      // *below* it, so the comparison is independent of platform path formatting.
      const full = fileURLToPath(u)
        .replace(/\\/g, '/')
        .replace(/\/{2,}/g, '/');
      const marker = '/oracle-root/';
      const at = full.indexOf(marker);
      if (at < 0) return false; // resolved above the synthetic repo root entirely
      const rel = full.slice(at + marker.length);
      const inside = (base: string): boolean => rel === base || rel.startsWith(`${base}/`);
      return inside('src/cockpit-host') || inside('src/cockpit');
    } catch {
      return false;
    }
  };

  it('agrees with an independent `new URL` + `fileURLToPath` oracle across the matrix', () => {
    const specimens: readonly { readonly importer: string; readonly spec: string }[] = [
      ...rejectedEncodedTraversal,
      ...rejectedInvalid.map((spec) => ({ importer: 'server.ts', spec })),
      ...preserved.map(({ importer, spec }) => ({ importer, spec })),
      { importer: 'server.ts', spec: './../index.js' }, // unencoded escape still rejected
      { importer: 'server.ts', spec: '../cockpit/index.js' }, // unencoded cockpit still accepted
    ];
    for (const { importer, spec } of specimens) {
      expect(accepts(importer, spec), `policy vs oracle drift: ${importer} -> ${spec}`).toBe(
        runtimeOracleStaysInBoundary(importer, spec),
      );
    }
  });

  // --- Preservation: the unencoded POLICY-1 behavior is unchanged ---
  it('preserves the original unencoded confinement verdicts', () => {
    expect(accepts('server.ts', './../index.js')).toBe(false);
    expect(accepts('server.ts', './../domain/index.js')).toBe(false);
    expect(accepts('server.ts', '../cockpit-host-evil/x.js')).toBe(false);
    expect(accepts('server.ts', '.\\..\\index.js')).toBe(false); // backslash-smuggled escape
    expect(accepts('server.ts', './local.js')).toBe(true);
    expect(accepts('server.ts', '../cockpit/index.js')).toBe(true);
    expect(accepts('server.ts', 'node:http')).toBe(true);
  });

  // --- Preservation: real host sources still satisfy the URL-aware confinement ---
  it('accepts every specifier the real host sources actually import', () => {
    for (const { file, text } of hostSources()) {
      for (const specifier of extractModuleSpecifiers(text)) {
        expect(accepts(file, specifier), `${file} -> ${specifier}`).toBe(true);
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
    // The extractor omits a computed specifier by contract (it surfaces only
    // static ones). Security is not "silent omission": the import-discipline check
    // treats such an unverifiable dynamic import as a rejection via
    // `hasUnverifiableDynamicImport` — see the D3-CX-POLICY-2 regression block.
    const source = 'import(' + BT + '../domain/${name}.js' + BT + ');';
    expect(extractModuleSpecifiers(source)).toEqual([]);
    expect(hasUnverifiableDynamicImport(source)).toBe(true);
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

  // C2 reconciliation: `const ratio = {} / value;` is object-literal division in
  // expression position, so a following `import '…'` is a real dependency in
  // *both* the same-line and next-line forms. The removed hand-lexer classified a
  // `/` after `}` as a regex opener and let the same-line fake regex swallow the
  // import — a false negative it deliberately preserved. The structural parser
  // reads the division correctly, so the specifier now surfaces on both forms.
  it('surfaces the import across an object-literal `}` division (C2)', () => {
    expect(extractModuleSpecifiers("const ratio = {} / value; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
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

describe('D3 host import scanner classifies `/` after a postfix operator as division (D3-CR postfix)', () => {
  // `x++` / `x--` / TS non-null `x!` end a value, so the following `/` is
  // division. Before this fix the tokenizer saw the bare trailing operator and
  // `regexCanFollow()` opened a regex; a quote inside that fake regex ran on and
  // swallowed a later real import (false negative). `++`/`--` are now emitted as
  // one maximal-munch token, and `!` is disambiguated from logical-not by the
  // token it follows.
  it('surfaces a real import after `++`/`--`/`!` postfix division', () => {
    expect(extractModuleSpecifiers("let x = 0; const r = x++ / 2; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("let x = 0; const r = x-- / 2; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("const r = x! / 2; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
  });

  it('surfaces a real import after postfix on member/index/call targets', () => {
    for (const lhs of ['arr[i]++', 'obj.value--', 'fn()!', 'arr[i]!']) {
      expect(extractModuleSpecifiers(`const r = ${lhs} / 2;\nimport '../domain/foo.js';`)).toEqual([
        '../domain/foo.js',
      ]);
    }
  });

  it('never fabricates a module from the fake regex a postfix `/` used to open', () => {
    expect(extractModuleSpecifiers("let x = 0; const r = x++ / 2;")).toEqual([]);
    expect(extractModuleSpecifiers("const r = x! / 2;")).toEqual([]);
  });

  // Preservation: a *prefix* `++x`/`--x` puts the operand (not the operator)
  // immediately before the `/`, so division is already correct there; and a
  // genuine regex after a real prefix operator / operator position must still be
  // recognised (logical-not `!/re/`, binary `+ /re/`, `return /re/`).
  it('keeps prefix increment as division and prefix/operator regex as regex', () => {
    expect(extractModuleSpecifiers("let x = 0; const r = ++x / 2;\nimport '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("let x = 0; const r = --x / 2;\nimport '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("if (!/[']/.test(v)) {} import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("const r = a + /[']/.source; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers("function f() { return /[']/.test(v); } import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
  });

  it('scans many postfix-division statements in bounded, linear time', () => {
    const many = "let x = 0; const r = x++ / 2;\n".repeat(2000) + "import '../domain/foo.js';";
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

describe('D3 host import scanner recognizes `for await (…)` as a control header (D3-CR for-await)', () => {
  // `for await (…)` is the async-iteration header: the token before `(` is
  // `await`, not `for`, so the base control-header check missed it and its `)`
  // was read as a value paren — a following regex became division, its quote ran
  // on, and a later real import was swallowed (false negative); an `import('…')`
  // inside that regex body was tokenized as code (false positive). The header is
  // now recognised only for the exact bare `for` + `await` + `(` sequence.
  it('surfaces a real import after a `for await` header regex', () => {
    const source = "async function f() { for await (const y of xs) /[']/.test(y); }\nimport '../domain/foo.js';";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  it('does not fabricate a module from an import call inside a `for await` header regex', () => {
    expect(
      extractModuleSpecifiers("async function f() { for await (const y of xs) /import('../domain/evil.js')/.test(y); }"),
    ).toEqual([]);
  });

  // Preservation: `await` in any non-header position is a value/member call, not a
  // control header, so a following `/` stays division and a later import surfaces.
  it('keeps `await` value/member forms as value contexts, not headers', () => {
    expect(
      extractModuleSpecifiers("async function f() { const r = await fn() / 2; import '../domain/foo.js'; }"),
    ).toEqual(['../domain/foo.js']);
    expect(extractModuleSpecifiers("const r = obj.await(x) / 2;\nimport '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(
      extractModuleSpecifiers("async function f() { const r = await (y) / 2; import '../domain/foo.js'; }"),
    ).toEqual(['../domain/foo.js']);
  });

  // Preservation: a plain `for (…)` and the other headers keep working, and a
  // keyword-member (`obj.for`) nested in a `for await` condition still divides.
  it('keeps plain `for`/`if`/`while` headers and nested keyword-member division working', () => {
    expect(extractModuleSpecifiers("for (let i = 0; i < n; i += 1) /[']/.test(x); import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(
      extractModuleSpecifiers("async function f() { for await (const y of obj.for(x)) /[']/.test(y); }\nimport '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
  });

  it('scans many `for await` header regex statements in bounded, linear time', () => {
    const many =
      "async function f() { for await (const y of xs) /[']/.test(y); }\n".repeat(2000) +
      "import '../domain/foo.js';";
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

describe('D3 host import scanner classifies `/` after a restricted-statement keyword as a regex (D3-CR-BREAK-CONTINUE-ASI)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // `break`/`continue` are restricted productions — a `[no LineTerminator here]`
  // precedes the optional label — so a newline after the bare keyword triggers ASI
  // and the next line begins a fresh statement whose first token may be a regex
  // literal. Before this fix the keyword was read as an ordinary value-ending
  // identifier, so `regexCanFollow()` returned false and the leading `/` was treated
  // as division. A quote inside the regex then opened a spurious string that could
  // swallow a following real import (false negative), and an `import('…')` in the
  // regex body could be tokenized as code (false positive). The `/` is now a regex
  // opener after a *bare* `break`/`continue`; a `.`-member form stays division.

  // False positive: an `import('…')` buried in a regex body after a bare
  // `break`/`continue` + newline must NOT surface (this was the reproduced defect —
  // the exact newline fixtures A/B returned the right set only accidentally, because
  // a single-quoted string dies at the line end, but C/D fabricated `evil`).
  it('does not fabricate a module from an import call in a regex after `break` + newline', () => {
    const source = ['while (ok) {', '  break', "  /import('../domain/evil.js')/.test(x);", '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(source)).toEqual([]);
    expect(forbiddenIn(source)).toEqual([]);
  });

  it('does not fabricate a module from an import call in a regex after `continue` + newline', () => {
    const source = ['while (ok) {', '  continue', "  /import('../domain/evil.js')/.test(x);", '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(source)).toEqual([]);
    expect(forbiddenIn(source)).toEqual([]);
  });

  // False negative: a quote-bearing regex after the keyword must not swallow a
  // later real import. The exact Codex newline fixtures (import on its own line)
  // pass either way — the load-bearing form places the import on the regex's line,
  // where the old spurious string ran straight through it.
  it('surfaces a real import after a `break`-newline quote-bearing regex (same line)', () => {
    const source = "while (ok) { break\n/[']/.test(x); import '../domain/foo.js'; }";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  it('surfaces a real import after a `continue`-newline quote-bearing regex (same line)', () => {
    const source = "while (ok) { continue\n/[']/.test(x); import '../domain/foo.js'; }";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  // The exact Codex fixtures (A/B): import on a separate line — must stay correct.
  it('surfaces a real import on a separate line after break/continue + newline regex', () => {
    for (const kw of ['break', 'continue']) {
      const source = ['while (ok) {', `  ${kw}`, "  /[']/.test(x);", '}', "import '../domain/foo.js';"].join(
        '\n',
      );
      expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    }
  });

  // Regex-vs-division context matrix after the keyword: a leading `/` is a regex,
  // so a trailing real import always survives (no spurious string ran on).
  it('recognizes a regex after break/continue across newline, CRLF, and comment separators', () => {
    const bodies: readonly string[] = [
      'break\n/[\']/.test(x);',
      'continue\n/[\']/.test(x);',
      'break\r\n/[\']/.test(x);',
      'continue\r\n/[\']/.test(x);',
      'break /* c */\n/[\']/.test(x);',
      'continue /* c */\n/[\']/.test(x);',
      'break // c\n/[\']/.test(x);',
      'continue // c\n/[\']/.test(x);',
    ];
    for (const body of bodies) {
      const source = `while (ok) { ${body} }\nimport '../domain/foo.js';`;
      expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    }
  });

  // A regex body holding an `import('…')` must not fabricate a dependency across any
  // of those same separators.
  it('never fabricates a module from an import-bearing regex across separators', () => {
    const bodies: readonly string[] = [
      "break\n/import('../domain/evil.js')/.test(x);",
      "continue\n/import('../domain/evil.js')/.test(x);",
      "break\r\n/import('../domain/evil.js')/.test(x);",
      "continue /* c */\n/import('../domain/evil.js')/.test(x);",
      "break // c\n/import('../domain/evil.js')/.test(x);",
    ];
    for (const body of bodies) {
      expect(extractModuleSpecifiers(`while (ok) { ${body} }`)).toEqual([]);
    }
  });

  // Member guard: a control/restricted keyword spelled as a *member name* is a
  // value, so a following `/` is division, not a regex — otherwise the fake regex
  // would swallow the later real import (false negative). Covers `.` and `?.`.
  it('keeps division after a `break`/`continue` used as a member name', () => {
    for (const access of ['obj.break', 'obj.continue', 'obj?.break', 'obj?.continue']) {
      const source = `const r = ${access} / 2; import '../domain/foo.js';`;
      expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
      expect(extractModuleSpecifiers(`const r = ${access} / 2;\nimport '../domain/foo.js';`)).toEqual([
        '../domain/foo.js',
      ]);
    }
  });

  it('fabricates no module from a bare `obj.break` / `obj.continue` division', () => {
    expect(extractModuleSpecifiers('const r = obj.break / 2;')).toEqual([]);
    expect(extractModuleSpecifiers('const r = obj.continue / 2;')).toEqual([]);
  });

  // The `!` lookback must still read `obj.break!` as a non-null assertion (value),
  // so the following `/` is division — `break`/`continue` stay value-ending in
  // `endsValue`, unlike REGEX_CONTEXT_KEYWORDS.
  it('keeps division after a non-null member assertion `obj.break!`', () => {
    expect(extractModuleSpecifiers("const r = obj.break! / 2; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(extractModuleSpecifiers('const r = obj.break! / 2;')).toEqual([]);
  });

  // Preservation: a labelled `break`/`continue`, an explicit-semicolon form, and the
  // untouched `return`/`throw` restricted keywords all keep working.
  it('preserves labelled, explicit-semicolon, and return/throw forms', () => {
    expect(
      extractModuleSpecifiers("outer: while (ok) { break outer; } import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
    expect(
      extractModuleSpecifiers("outer: while (ok) { continue outer; } import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
    expect(
      extractModuleSpecifiers("while (ok) { break;\n/[']/.test(x); } import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
    expect(
      extractModuleSpecifiers("function f() { return\n/[']/.test(v); } import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
  });

  // Liveness: many restricted-statement regex lines scan in bounded linear time; a
  // regression to rescanning would blow vitest's per-test timeout.
  it('scans many `break`-newline regex statements in bounded, linear time', () => {
    const many = "while (ok) { break\n/[']/.test(x); }\n".repeat(2000) + "import '../domain/foo.js';";
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

describe('D3 host import scanner classifies `/` after a labelled restricted statement as a regex (D3-CR-BREAK-CONTINUE-LABEL-ASI)', () => {
  const forbiddenIn = (source: string): readonly string[] =>
    extractModuleSpecifiers(source).filter((s) => /\.\.\/(?:domain|adapters)\//.test(s));

  // `break outer` / `continue outer` carry the statement's optional label on the
  // *same* line as the keyword; the statement is then complete, so a `/` beginning
  // the next line is a regex opener, not division. The token immediately before that
  // `/` is the *label* id (not the keyword), so the bare-keyword guard alone missed
  // it: before this fix `regexCanFollow()` read the label as an ordinary value and
  // classified the `/` as division. An `import('…')` in the regex body then
  // fabricated a dependency (false positive) and a quote-bearing regex could swallow
  // a following same-line import (false negative). The label is now marked
  // `restrictedLabel` when it directly follows a bare `break`/`continue` with no
  // intervening LineTerminator; a newline in between is ASI, leaving the id an
  // ordinary fresh statement whose `/` stays division.

  // False positive: an `import('…')` in a regex body after `break <label>` + newline
  // must NOT surface. (This is the load-bearing case — the separate-line quote
  // fixtures below pass either way, since a spurious string dies at the line end.)
  it('does not fabricate a module from an import call in a regex after `break <label>` + newline', () => {
    const source = ['outer: while (ok) {', '  break outer', "  /import('../domain/evil.js')/.test(x);", '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(source)).toEqual([]);
    expect(forbiddenIn(source)).toEqual([]);
  });

  it('does not fabricate a module from an import call in a regex after `continue <label>` + newline', () => {
    const source = ['outer: while (ok) {', '  continue outer', "  /import('../domain/evil.js')/.test(x);", '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(source)).toEqual([]);
    expect(forbiddenIn(source)).toEqual([]);
  });

  // False negative: a quote-bearing regex after `break <label>` + newline must not
  // swallow a later real import placed on the regex's own line.
  it('surfaces a real import after a `break <label>`-newline quote-bearing regex (same line)', () => {
    const source = "outer: while (ok) { break outer\n/[']/.test(x); import '../domain/foo.js'; }";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  it('surfaces a real import after a `continue <label>`-newline quote-bearing regex (same line)', () => {
    const source = "outer: while (ok) { continue outer\n/[']/.test(x); import '../domain/foo.js'; }";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    expect(forbiddenIn(source).length).toBeGreaterThan(0);
  });

  // The exact validator fixtures (import on a separate line) — must stay correct.
  it('surfaces a real import on a separate line after `break`/`continue <label>` + newline regex', () => {
    for (const kw of ['break', 'continue']) {
      const source = ['outer: while (ok) {', `  ${kw} outer`, "  /[']/.test(x);", '}', "import '../domain/foo.js';"].join(
        '\n',
      );
      expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    }
  });

  // Regex-vs-division matrix after a labelled keyword across newline, CRLF, block and
  // line comments (the comment/newline follows the label, so the statement is already
  // complete): a leading `/` is a regex, so a trailing real import survives.
  it('recognizes a regex after a labelled break/continue across newline, CRLF, and comment separators', () => {
    const heads: readonly string[] = [
      'break outer\n',
      'continue outer\n',
      'break outer\r\n',
      'continue outer\r\n',
      'break outer /* c */\n',
      'continue outer /* c */\n',
      'break outer // c\n',
      'continue outer // c\n',
    ];
    for (const head of heads) {
      const source = `outer: while (ok) { ${head}/[']/.test(x); }\nimport '../domain/foo.js';`;
      expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
    }
  });

  it('never fabricates a module from an import-bearing regex after a labelled break/continue', () => {
    const heads: readonly string[] = [
      'break outer\n',
      'continue outer\n',
      'break outer\r\n',
      'continue outer /* c */\n',
      'break outer // c\n',
    ];
    for (const head of heads) {
      const source = `outer: while (ok) { ${head}/import('../domain/evil.js')/.test(x); }`;
      expect(extractModuleSpecifiers(source)).toEqual([]);
    }
  });

  // Nested labels: `break inner` / `continue outer` inside `outer: inner: …` are each
  // valid labelled restricted statements, so the following `/` is still a regex.
  it('handles nested labels', () => {
    const inner = ['outer: inner: while (ok) {', '  break inner', "  /import('../domain/evil.js')/.test(x);", '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(inner)).toEqual([]);
    const out = ['outer: inner: while (ok) {', '  continue outer', "  /[']/.test(x); import '../domain/foo.js';", '}'].join(
      '\n',
    );
    expect(extractModuleSpecifiers(out)).toEqual(['../domain/foo.js']);
  });

  // The label marker must NOT leak to a fresh statement: a LineTerminator between the
  // keyword and the id is ASI, so the id (`outer` here) is an ordinary statement and a
  // following `/` is division — exactly as `x \n / 2` is division. A regex
  // misclassification here would swallow the trailing real import.
  it('keeps a newline-separated id after break/continue as a fresh statement (division)', () => {
    const fresh = "while (ok) { break\nouter\n/ 2; } import '../domain/foo.js';";
    expect(extractModuleSpecifiers(fresh)).toEqual(['../domain/foo.js']);
    const fresh2 = "while (ok) { continue\nouter\n/ 2; } import '../domain/foo.js';";
    expect(extractModuleSpecifiers(fresh2)).toEqual(['../domain/foo.js']);
  });

  // Ordinary identifier / call / member division across a newline stays division — the
  // labelled repair must never turn general newline ASI into a regex context.
  it('keeps ordinary identifier, call, and member division across a newline', () => {
    for (const expr of ['x\n/ 2', 'value\n/ divisor', 'obj.value\n/ 2', 'fn()\n/ 2']) {
      expect(extractModuleSpecifiers(`const r = ${expr}; import '../domain/foo.js';`)).toEqual(['../domain/foo.js']);
    }
  });

  // A block comment carrying a LineTerminator *between* the keyword and the id is a
  // terminator too, so the id is not a label and the following `/` stays division.
  it('treats a block-comment newline between keyword and id as ASI (division), not a label', () => {
    const source = "while (ok) { break /*\n*/ outer\n/ 2; } import '../domain/foo.js';";
    expect(extractModuleSpecifiers(source)).toEqual(['../domain/foo.js']);
  });

  // Member `.break` / `.continue` are ordinary property accesses (values), so a
  // following `/` is division and a later real import still surfaces. (The prior
  // fixture used the syntactically invalid `obj.break outer / 2`, which only
  // probed an internal state of the removed hand-lexer; valid member-access
  // division is the stronger, structurally meaningful check.)
  it('treats a member `.break`/`.continue` as a value, keeping division', () => {
    expect(extractModuleSpecifiers("const r = obj.break / 2; import '../domain/foo.js';")).toEqual([
      '../domain/foo.js',
    ]);
    expect(
      extractModuleSpecifiers("const r = obj.continue / 2; import '../domain/foo.js';"),
    ).toEqual(['../domain/foo.js']);
  });

  // Liveness: many labelled-restricted regex lines scan in bounded linear time.
  it('scans many labelled `break`-newline regex statements in bounded, linear time', () => {
    const many =
      "outer: while (ok) { break outer\n/[']/.test(x); }\n".repeat(2000) + "import '../domain/foo.js';";
    const start = performance.now();
    expect(extractModuleSpecifiers(many)).toEqual(['../domain/foo.js']);
    expect(performance.now() - start).toBeLessThan(1000);
  });
});

// ---------------------------------------------------------------------------
// Consolidated purity-guard hardening — adversarial regression matrix for the
// four CURRENT findings closed on PR #61:
//   A  synthetic-root re-entry            (POLICY-1, was fail-open/soundness)
//   B  POSIX literal-backslash importer   (POLICY-F1, was fail-open, POSIX-only)
//   C  computed dynamic-import blind spot (POLICY-2, was fail-open by omission)
//   D  blanket `node:*` allowance         (POLICY-3, was fail-open)
// All resolution below is pure path/URL arithmetic against the *real* `hostDir`;
// no fixture file is created and no module is loaded.
// ---------------------------------------------------------------------------
describe('D3 host consolidated purity hardening (A/B/C/D)', () => {
  const BT = '`';

  // Mirror of the real check #1 acceptance predicate for a single specifier
  // (`node:*` allowlist OR real-root relative confinement).
  const accepts = (importer: string, specifier: string): boolean => {
    const isRelative = specifier.startsWith('./') || specifier.startsWith('../');
    return (
      isAllowedNodeBuiltin(specifier) ||
      (isRelative && relativeImportStaysInBoundary(importer, specifier))
    );
  };

  // End-to-end discipline decision over source text: fail closed on an
  // unverifiable dynamic import, else every surfaced specifier must be accepted.
  const disciplineAccepts = (source: string, importer = 'server.ts'): boolean => {
    if (hasUnverifiableDynamicImport(source)) return false;
    return extractModuleSpecifiers(source).every((specifier) => accepts(importer, specifier));
  };

  // --- A: synthetic-root re-entry -----------------------------------------
  describe('A — synthetic-root re-entry is judged against the real repository', () => {
    it('rejects the exact Codex witness `../../../agentbridge-virtual/src/cockpit-host/escape.js`', () => {
      expect(accepts('server.ts', '../../../agentbridge-virtual/src/cockpit-host/escape.js')).toBe(
        false,
      );
    });

    it('rejects a path that climbs above the real repository and repeats its real directory names', () => {
      // Derive the real repository and its parent directory name from the same
      // `hostDir` the guard resolves against: `[…, <parent>, <repo>, 'src',
      // 'cockpit-host']`. Over-climb to the filesystem root (clamped), then
      // re-enter directories that repeat those real names — the absolute prefix no
      // longer matches the real host root, so it must be rejected.
      const segments = HOST_ROOT_URL.pathname.split('/').filter((s) => s.length > 0);
      // `hostDir` is always at least `<parent>/<repo>/src/cockpit-host`.
      const repoName = segments[segments.length - 3] ?? '';
      const parentName = segments[segments.length - 4] ?? '';
      const overClimb = '../'.repeat(segments.length + 3);
      // Put the repeated names below a root-level fixture directory that cannot
      // be the checkout's first directory. Without this distinct prefix, a
      // shallow checkout such as `/workspace/agentbridge` is reconstructed
      // exactly after excessive `..` segments clamp at `/`.
      const rootDirectoryIndex = /^[A-Za-z]:$/.test(segments[0] ?? '') ? 1 : 0;
      const firstRootDirectory = segments[rootDirectoryIndex] ?? '';
      const fixturePrefix =
        firstRootDirectory === 'agentbridge-purity-outside'
          ? 'agentbridge-purity-other'
          : 'agentbridge-purity-outside';
      const reentry = `${overClimb}${fixturePrefix}/${parentName}/${repoName}/src/cockpit-host/escape.js`;
      expect(accepts('server.ts', reentry)).toBe(false);
      // A sibling that shares the real repository name as a prefix is likewise out.
      expect(accepts('server.ts', `../../../${repoName}-sibling/src/cockpit-host/escape.js`)).toBe(
        false,
      );
    });

    it('preserves the legitimate host-local and Cockpit-boundary controls', () => {
      expect(accepts('render.ts', './escape.js')).toBe(true);
      expect(accepts('server.ts', '../cockpit/index.js')).toBe(true);
    });
  });

  // --- B: POSIX literal-backslash importer --------------------------------
  describe('B — a literal backslash in a POSIX importer filename is one encoded segment', () => {
    // `a\b.ts` is a single legal POSIX filename; `readdirSync` lists it as one
    // entry. The importer URL must keep it one percent-encoded segment so
    // `../index.js` resolves to `src/index.js` (the domain barrel), OUT of host —
    // not, as the removed `toPosix(importerRelPath)` fold made it,
    // `src/cockpit-host/index.js`. On Windows `\` is a native separator, so this
    // path-arithmetic case is POSIX-gated (it cannot exist as a Windows filename).
    const itPosix = process.platform === 'win32' ? it.skip : it;
    itPosix('rejects importer `a\\b.ts` -> `../index.js` (resolves to src/index.js, out of host)', () => {
      expect(accepts('a\\b.ts', '../index.js')).toBe(false);
    });

    it('preserves the normal nested control `sub/b.ts` -> `../x.js` (stays in host)', () => {
      expect(accepts('sub/b.ts', '../x.js')).toBe(true);
    });
  });

  // --- C: computed dynamic imports fail closed ----------------------------
  describe('C — a computed dynamic import is rejected, not silently omitted', () => {
    it('rejects an identifier target `import(t)`', () => {
      const source = "const t = './../index.js';\nawait import(t);";
      expect(hasUnverifiableDynamicImport(source)).toBe(true);
      expect(disciplineAccepts(source)).toBe(false);
    });

    it('rejects a concatenated target `import(\'../domain/\' + name)`', () => {
      const source = "await import('../domain/' + name);";
      expect(hasUnverifiableDynamicImport(source)).toBe(true);
      expect(disciplineAccepts(source)).toBe(false);
    });

    it('rejects a substituted template target `import(`../domain/${name}.js`)`', () => {
      const source = 'await import(' + BT + '../domain/${name}.js' + BT + ');';
      expect(hasUnverifiableDynamicImport(source)).toBe(true);
      expect(disciplineAccepts(source)).toBe(false);
    });

    it('preserves a static string target `import(\'./local.js\')`', () => {
      const source = "await import('./local.js');";
      expect(hasUnverifiableDynamicImport(source)).toBe(false);
      expect(extractModuleSpecifiers(source)).toContain('./local.js');
      expect(disciplineAccepts(source)).toBe(true);
    });

    it('preserves a no-substitution template target `import(`../cockpit/index.js`)`', () => {
      const source = 'await import(' + BT + '../cockpit/index.js' + BT + ');';
      expect(hasUnverifiableDynamicImport(source)).toBe(false);
      expect(extractModuleSpecifiers(source)).toContain('../cockpit/index.js');
      expect(disciplineAccepts(source)).toBe(true);
    });

    it('does not fire on `import.meta`, member calls, or object/class members named `import`', () => {
      const exclusions: readonly string[] = [
        'const isEntry = import.meta.url === x;',
        "obj.import('../domain/foo.js');",
        'const y = obj.import;',
        "const config = { import: '../domain/foo.js' };",
        "const o = { \"import\": '../domain/foo.js' };",
        "const obj = { import() { return '../domain/foo.js'; } };",
        "class C { import = '../domain/foo.js'; }",
        "class C { static import = '../domain/foo.js'; }",
        "const importX = '../domain/foo.js';",
      ];
      for (const source of exclusions) {
        expect(hasUnverifiableDynamicImport(source), `must not fire on: ${source}`).toBe(false);
      }
    });
  });

  // --- D: exact node builtin allowlist ------------------------------------
  describe('D — node builtins are restricted to the exact production allowlist', () => {
    for (const spec of ['node:http', 'node:url']) {
      it(`accepts allow-listed ${spec}`, () => {
        expect(accepts('server.ts', spec)).toBe(true);
      });
    }
    for (const spec of [
      'node:fs',
      'node:fs/promises',
      'node:child_process',
      'node:os',
      'node:process',
    ]) {
      it(`rejects non-allow-listed ${spec}`, () => {
        expect(accepts('server.ts', spec)).toBe(false);
      });
    }
  });
});
