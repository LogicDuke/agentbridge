import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';
import { afterAll, describe, expect, it } from 'vitest';

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

// The sibling Cockpit boundary is a *second* allowed source root the host may
// import from (`../cockpit/`). `tsc`/`readFileSync` follow symlinks under it just
// as they do under the host root, so it must receive the same fail-closed symlink
// scan (D3-CX-POLICY-FB). Derived from the same `import.meta.url` anchor as
// `hostDir`, so the two roots agree by construction.
const cockpitDir = fileURLToPath(new URL('../../src/cockpit/', import.meta.url));

/**
 * Fail closed on any symlink entry under a host tree (D3-CX-POLICY-SYMLINK).
 *
 * `readdirSync`/`readFileSync` — and `tsc` — follow symbolic links, so a
 * committed `src/cockpit-host/domain.ts -> ../domain/actions.ts` (imported as
 * `./domain.js`) would read/emit forbidden kernel code while the lexical URL
 * containment check still sees an in-host path and the forbidden-specifier check
 * sees only a local import. `lstatSync` does NOT follow the link, so each
 * enumerated entry — file or directory, at any depth — is stat-checked and the
 * scan throws on the first symlink *before* any content is read or any
 * URL-containment verdict is formed. Node's recursive `readdirSync` does not
 * descend into a symlinked directory, so a symlinked directory surfaces as a
 * leaf entry and is rejected here the same way.
 */
function assertNoSymlinkEntries(root: string): void {
  for (const entry of readdirSync(root, { recursive: true })) {
    const name = String(entry);
    if (lstatSync(join(root, name)).isSymbolicLink()) {
      throw new Error(`D3 host purity: symlink entry is forbidden under the host tree: ${name}`);
    }
  }
}

function hostSources(): readonly { readonly file: string; readonly text: string }[] {
  // Reject symlink escapes beneath EITHER allowed source root before any read or
  // containment decision is trusted (D3-CX-POLICY-SYMLINK / -FB). A symlink under
  // `src/cockpit/` — e.g. `bridge.ts -> ../domain/actions.ts` — would let a host
  // `../cockpit/bridge.js` import reach the domain kernel while lexical URL
  // containment still passes and `tsc` emits the linked kernel into `dist/`.
  assertNoSymlinkEntries(hostDir);
  assertNoSymlinkEntries(cockpitDir);
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

// ---------------------------------------------------------------------------
// Shared structural helpers for the acquisition-site RC/HA detectors
// (D3-CX-POLICY-RC / -HA). These reason over parented AST nodes so a capability
// is caught where its name first appears — as a value reference, a member access,
// or a destructuring property — rather than only at a final call after limited
// alias tracing. Forwarding a captured value through an object, array, return, or
// argument therefore cannot hide it, because the capability had to be *named* at
// its source site, which these helpers see. No substring text matching is used;
// comments and string/template literals are not identifier or access nodes and so
// are never matched. This is a finite, conservative structural policy — not an
// interprocedural taint engine — safe here because the real host and Cockpit
// sources use none of these capability names (verified by the enforcement `it`s
// below that run every detector over the real sources).
// ---------------------------------------------------------------------------

// Global-object receiver identifiers. A member named `eval`/`Function`/`process`
// read off one of these is the real global authority; the same name read off an
// unrelated local object is not.
const GLOBAL_RECEIVER_NAMES: ReadonlySet<string> = new Set(['globalThis', 'window', 'self', 'global']);

// Unwrap the expression wrappers that do not change identity: parentheses, `as`
// casts, `!` non-null, `satisfies`, and old-style `<T>` assertions. So
// `(globalThis as any)['eval']` and `(process as any).binding` are seen through.
const unwrapExpr = (node: ts.Expression): ts.Expression => {
  let cur: ts.Expression = node;
  while (
    ts.isParenthesizedExpression(cur) ||
    ts.isAsExpression(cur) ||
    ts.isNonNullExpression(cur) ||
    ts.isSatisfiesExpression(cur) ||
    ts.isTypeAssertionExpression(cur)
  ) {
    cur = cur.expression;
  }
  return cur;
};

// Whether an initializer is a STATICALLY-RESOLVED runtime import of node:http —
// `import('node:http')` or `await import('node:http')` (parens/`as`/await unwrapped).
// A computed/dynamic specifier is not matched (it is already failed-closed by
// `hasUnverifiableDynamicImport`); only the exact allow-listed literal acquires the
// node:http namespace capability, so it gains the SAME identity as `import * as http`.
const isNodeHttpDynamicImport = (expr: ts.Expression): boolean => {
  let cur = unwrapExpr(expr);
  while (ts.isAwaitExpression(cur)) cur = unwrapExpr(cur.expression);
  if (!ts.isCallExpression(cur) || cur.expression.kind !== ts.SyntaxKind.ImportKeyword) return false;
  const arg: ts.Expression | undefined = cur.arguments[0];
  return arg !== undefined && ts.isStringLiteralLike(arg) && arg.text === 'node:http';
};

const isGlobalReceiver = (node: ts.Expression): boolean => {
  const n = unwrapExpr(node);
  return ts.isIdentifier(n) && GLOBAL_RECEIVER_NAMES.has(n.text);
};

// The statically-provable string value of an expression: a string literal or
// substitution-free template, a `+` concatenation of such, or a local `const`
// bound (conservatively, see collectStringConsts) to one — else null. This resolves
// `'ev' + 'al'` and `const m = 'getBuiltin' + 'Module'; obj[m]` to `eval` /
// `getBuiltinModule`, so a computed-but-static property name cannot launder a
// reserved capability past the member-name check.
const staticStringOf = (node: ts.Expression, constMap: ReadonlyMap<string, string>): string | null => {
  const n = unwrapExpr(node);
  if (ts.isStringLiteralLike(n)) return n.text;
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = staticStringOf(n.left, constMap);
    const right = staticStringOf(n.right, constMap);
    return left !== null && right !== null ? left + right : null;
  }
  if (ts.isIdentifier(n)) {
    const value = constMap.get(n.text);
    return value !== undefined ? value : null;
  }
  return null;
};

// Collect the identifier texts that provably denote a single immutable string
// constant, resolved conservatively and in FINITE time over the already-parsed
// AST. This replaces an earlier scope-insensitive `while (pass())` fixpoint that
// (F1) let a mutable, shadowed, or parameter binding inherit another binding's
// static value by matching on identifier text alone, and (F2) could fail to
// terminate when two scopes declared the same name with different values, each
// pass overwriting the name-only map and re-setting `changed`.
//
// Eligibility (else the text is UNKNOWN): the WHOLE SourceFile contains exactly
// one binding of that text; that sole binding is a simple `const <id> = <init>`
// declaration with an initializer; and the text is never an assignment,
// compound-assignment, increment, or decrement target. Any repeated binding —
// even same-name/same-value — any non-const or destructuring binding, any
// parameter/catch/function/class/import/type/module binding of the same text, or
// any mutation, makes it UNKNOWN. Unique immutable names with equal values stay
// independently resolvable; unique immutable `+`-concatenation chains still fold.
//
// Resolution is a memoized depth-first search with explicit per-name states
// (UNVISITED = absent from `memo`, RESOLVING, RESOLVED(string), UNKNOWN). Entering
// a name that is already RESOLVING is a dependency cycle and yields UNKNOWN. Each
// eligible name is evaluated at most once and then read from `memo`, so the search
// visits every name a bounded number of times and always terminates.
const collectStringConsts = (sourceFile: ts.SourceFile): Map<string, string> => {
  // --- Phase 1: one complete AST inventory ---------------------------------
  // How many times each identifier text is *bound* anywhere (any binding form).
  const bindingCounts = new Map<string, number>();
  const bindName = (text: string): void => {
    bindingCounts.set(text, (bindingCounts.get(text) ?? 0) + 1);
  };
  // Identifier texts that are ever an assignment/update target — not immutable.
  const mutated = new Set<string>();
  // The initializer of a simple `const <id> = <init>` declaration, by text. A text
  // with more than one binding is disqualified by `bindingCounts` below, so a later
  // overwrite here is harmless: the entry is consulted only when the text is unique.
  const constInit = new Map<string, ts.Expression>();

  const inventory = (node: ts.Node): void => {
    // Binding sites, counted by the identifier name(s) they directly introduce.
    if (ts.isVariableDeclaration(node)) {
      if (ts.isIdentifier(node.name)) {
        bindName(node.name.text);
        const list = node.parent;
        if (
          node.initializer !== undefined &&
          ts.isVariableDeclarationList(list) &&
          (list.flags & ts.NodeFlags.Const) !== 0
        ) {
          constInit.set(node.name.text, node.initializer);
        }
      }
    } else if (ts.isBindingElement(node)) {
      if (ts.isIdentifier(node.name)) bindName(node.name.text);
    } else if (ts.isParameter(node)) {
      if (ts.isIdentifier(node.name)) bindName(node.name.text);
    } else if (ts.isImportClause(node)) {
      if (node.name !== undefined) bindName(node.name.text);
    } else if (ts.isNamespaceImport(node) || ts.isImportSpecifier(node)) {
      bindName(node.name.text);
    } else if (ts.isImportEqualsDeclaration(node)) {
      bindName(node.name.text);
    } else if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isClassDeclaration(node) ||
      ts.isClassExpression(node) ||
      ts.isEnumDeclaration(node) ||
      ts.isModuleDeclaration(node) ||
      ts.isTypeAliasDeclaration(node) ||
      ts.isInterfaceDeclaration(node) ||
      ts.isTypeParameterDeclaration(node)
    ) {
      if (node.name !== undefined && ts.isIdentifier(node.name)) bindName(node.name.text);
    }

    // Mutation sites: `x = …` / `x += …` / … and `++x` / `x--`.
    if (ts.isBinaryExpression(node)) {
      const kind = node.operatorToken.kind;
      if (kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment) {
        const target = unwrapExpr(node.left);
        if (ts.isIdentifier(target)) mutated.add(target.text);
      }
    } else if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
      if (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) {
        const target = unwrapExpr(node.operand);
        if (ts.isIdentifier(target)) mutated.add(target.text);
      }
    }

    ts.forEachChild(node, inventory);
  };
  ts.forEachChild(sourceFile, inventory);

  // --- Phase 2: finite memoized resolution ---------------------------------
  type State =
    | { readonly kind: 'RESOLVING' }
    | { readonly kind: 'RESOLVED'; readonly value: string }
    | { readonly kind: 'UNKNOWN' };
  const memo = new Map<string, State>();

  const isEligible = (text: string): boolean =>
    bindingCounts.get(text) === 1 && !mutated.has(text) && constInit.has(text);

  const resolveExpr = (node: ts.Expression): string | null => {
    const n = unwrapExpr(node);
    if (ts.isStringLiteralLike(n)) return n.text;
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = resolveExpr(n.left);
      if (left === null) return null;
      const right = resolveExpr(n.right);
      if (right === null) return null;
      return left + right;
    }
    if (ts.isIdentifier(n)) return resolveName(n.text);
    return null;
  };

  function resolveName(text: string): string | null {
    const seen = memo.get(text);
    if (seen !== undefined) return seen.kind === 'RESOLVED' ? seen.value : null;
    if (!isEligible(text)) {
      memo.set(text, { kind: 'UNKNOWN' });
      return null;
    }
    memo.set(text, { kind: 'RESOLVING' }); // re-entry before completion is a cycle
    const init = constInit.get(text);
    const value = init === undefined ? null : resolveExpr(init);
    memo.set(text, value === null ? { kind: 'UNKNOWN' } : { kind: 'RESOLVED', value });
    return value;
  }

  const resolved = new Map<string, string>();
  for (const text of constInit.keys()) {
    const value = resolveName(text);
    if (value !== null) resolved.set(text, value);
  }
  return resolved;
};

// The member name of a property/element access — a property identifier, or a
// statically-resolved element key — else null.
const memberNameOf = (node: ts.Node, constMap: ReadonlyMap<string, string>): string | null => {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) return staticStringOf(node.argumentExpression, constMap);
  return null;
};

// The SOURCE property name read by a destructuring binding element: `{ x }` and
// `{ x: y }` both read property `x`. Handles a quoted key `{ 'x': y }`.
const bindingPropertyName = (node: ts.BindingElement): string | null => {
  const key = node.propertyName ?? node.name;
  if (ts.isIdentifier(key)) return key.text;
  if (ts.isStringLiteralLike(key)) return key.text;
  return null;
};

// Whether an identifier is a *value reference* (a read of the binding) rather than
// a name being declared, an object-literal key, a member name, or a type name.
// Conservative: anything not in the small excluded set of name-only positions is
// treated as a reference, so the fail-closed rules err toward rejection.
const isValueReference = (id: ts.Identifier): boolean => {
  const p = id.parent as ts.Node | undefined;
  if (p === undefined) return true;
  const named = p as { name?: ts.Node };
  if (
    (ts.isVariableDeclaration(p) ||
      ts.isParameter(p) ||
      ts.isBindingElement(p) ||
      ts.isFunctionDeclaration(p) ||
      ts.isClassDeclaration(p) ||
      ts.isMethodDeclaration(p) ||
      ts.isPropertyDeclaration(p) ||
      ts.isGetAccessorDeclaration(p) ||
      ts.isSetAccessorDeclaration(p) ||
      ts.isEnumDeclaration(p) ||
      ts.isModuleDeclaration(p) ||
      ts.isTypeAliasDeclaration(p) ||
      ts.isInterfaceDeclaration(p) ||
      ts.isTypeParameterDeclaration(p) ||
      ts.isImportClause(p) ||
      ts.isNamespaceImport(p) ||
      ts.isImportSpecifier(p) ||
      ts.isExportSpecifier(p)) &&
    named.name === id
  ) {
    return false;
  }
  if (ts.isPropertyAssignment(p) && p.name === id) return false; // object-literal key
  if (ts.isPropertyAccessExpression(p) && p.name === id) return false; // member name
  if (ts.isPropertySignature(p) && p.name === id) return false;
  if (ts.isQualifiedName(p) && p.right === id) return false;
  if (ts.isTypeReferenceNode(p)) return false;
  return true;
};

// Whether a node ultimately serves as the object being accessed by an enclosing
// member/element access (through identity-preserving wrappers). `process` in
// `process.argv[1]` and `(process as any).cwd()` serves as an access object — a
// direct operation — whereas `process` stored in `[process]` or `{ p: process }`
// does not, so the latter is caught as forwarding.
const servesAsAccessObject = (node: ts.Node): boolean => {
  let cur: ts.Node = node;
  let p = cur.parent as ts.Node | undefined;
  while (
    p !== undefined &&
    ((ts.isParenthesizedExpression(p) && p.expression === cur) ||
      (ts.isAsExpression(p) && p.expression === cur) ||
      (ts.isNonNullExpression(p) && p.expression === cur) ||
      (ts.isSatisfiesExpression(p) && p.expression === cur) ||
      (ts.isTypeAssertionExpression(p) && p.expression === cur))
  ) {
    cur = p;
    p = cur.parent as ts.Node | undefined;
  }
  if (p === undefined) return false;
  return (ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) && p.expression === cur;
};

// NET-LOCAL: whether an HTTP_NS identifier occurrence is a forbidden ESCAPE of the
// privileged node:http namespace — i.e. NOT one of the three permitted positions:
//  (1) the access-object receiver of a member/element access (a permitted createServer
//      access is then decided by the member rule);
//  (2) the initializer of an object-binding-pattern destructuring (F2 decides members);
//  (3) a type/non-runtime position — the LEFT of a type QualifiedName, a `typeof` type
//      query, an import-type, or the operand of the runtime `typeof` operator.
// Intentionally local to NET; it does NOT change the shared `isValueReference` or RC/HA.
const isHttpNamespaceEscape = (id: ts.Identifier): boolean => {
  if (servesAsAccessObject(id)) return false;
  const par = id.parent as ts.Node | undefined;
  if (
    par !== undefined &&
    ts.isVariableDeclaration(par) &&
    ts.isObjectBindingPattern(par.name) &&
    par.initializer === id
  ) {
    return false;
  }
  let cur: ts.Node = id;
  let gp = cur.parent as ts.Node | undefined;
  while (gp !== undefined && ts.isQualifiedName(gp)) {
    cur = gp;
    gp = cur.parent as ts.Node | undefined;
  }
  if (
    gp !== undefined &&
    (ts.isTypeQueryNode(gp) || ts.isTypeReferenceNode(gp) || ts.isImportTypeNode(gp) || ts.isTypeOfExpression(gp))
  ) {
    return false;
  }
  return true;
};

/**
 * RC — reject runtime code generation at its acquisition site (D3-CX-POLICY-RC v2).
 *
 * The import scanner reasons over *import AST nodes*; a string handed to a runtime
 * code-generation primitive is opaque to it, so `eval("import('../domain/x.js')")`
 * builds and Node 24 executes the hidden domain import while every specifier check
 * sees nothing. The v1 detector only recognized the final call after simple
 * `const x = eval` alias tracing, so the same primitive laundered through a
 * destructuring, an object property, an array element, or a function return
 * bypassed it. v2 rejects the capability where it is *named*, not where it is
 * called — forwarding cannot hide what was already named at its source.
 *
 * Rejected, structurally (never by substring text):
 *   - (a) any member access named `constructor` — property or statically-computed
 *     element key, any receiver — the `(async () => {}).constructor` /
 *     `(function*(){}).constructor` chain to the Async/Generator/AsyncGenerator
 *     function constructors, including extraction to a variable before invocation;
 *   - (b) any member access named `eval` / `Function` read off a global receiver
 *     (`globalThis`/`window`/`self`/`global`, through `as`/paren wrappers), e.g.
 *     `globalThis.eval`, `globalThis['ev' + 'al']`, `(globalThis as any)['eval']`;
 *   - (c) any destructuring of a property named `eval` / `Function`
 *     (`const { eval: e } = globalThis`);
 *   - (d) any *value reference* to the global `eval` / `Function` primitive — as a
 *     call callee, initializer, object-property value, array element, return
 *     value, or argument — so `[eval]`, `{ e: eval }`, `return eval` are caught at
 *     the reference site regardless of how the value is later invoked.
 *
 * A member named `eval`/`Function` read off a NON-global local object
 * (`cfg.eval`) is not the global primitive and is preserved. Class constructor
 * *declarations* and ordinary `new C()` contain no `.constructor` access and are
 * preserved. Comments, strings, and longer identifiers (`evaluate`) are never
 * matched. Fail-closed and finite; the real host sources reference none of these.
 */
const RC_PRIMITIVE_NAMES: ReadonlySet<string> = new Set(['eval', 'Function']);

const usesRuntimeCodeGeneration = (source: string): boolean => {
  const sourceFile = ts.createSourceFile(
    'module.ts',
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    ts.ScriptKind.TS,
  );
  const constMap = collectStringConsts(sourceFile);

  let found = false;
  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const member = memberNameOf(node, constMap);
      // (a) `.constructor` on any receiver — the function-constructor chain.
      if (member === 'constructor') found = true;
      // (b) `.eval` / `.Function` off a global receiver.
      else if (member !== null && RC_PRIMITIVE_NAMES.has(member) && isGlobalReceiver(node.expression)) {
        found = true;
      }
    }
    // (c) destructuring a property named eval / Function.
    if (ts.isBindingElement(node)) {
      const name = bindingPropertyName(node);
      if (name !== null && RC_PRIMITIVE_NAMES.has(name)) found = true;
    }
    // (d) a value reference to the global eval / Function primitive.
    if (ts.isIdentifier(node) && RC_PRIMITIVE_NAMES.has(node.text) && isValueReference(node)) {
      found = true;
    }
    // (e) forwarding a recognized global-authority object (`globalThis`/`global`/
    //     `window`/`self`) as a value — an initializer, object value, array element,
    //     return, or argument — i.e. any use that is NOT a direct member access on
    //     it. This is the acquisition-site closure of the global-alias route: once
    //     `const g = globalThis` is rejected, an alias `g.eval` / `g.Function` /
    //     `g.process` can never be created, so no deep flow tracing is needed. A
    //     direct `globalThis.console` / `globalThis.process.cwd()` (where the global
    //     serves as the access object, through `as`/paren wrappers) is preserved.
    if (
      ts.isIdentifier(node) &&
      GLOBAL_RECEIVER_NAMES.has(node.text) &&
      isValueReference(node) &&
      !servesAsAccessObject(node)
    ) {
      found = true;
    }
    // (f) a computed element access on a recognized global receiver whose key is not
    //     statically resolvable — a runtime-built key (`['e','v','a','l'].join('')`,
    //     `String.fromCharCode(...)`) could acquire `eval`/`Function`/`process` off
    //     the global object without ever exposing the property name to static
    //     inspection. A statically-resolved global member (`globalThis['console']`,
    //     `globalThis['ev' + 'al']`) is not caught here (the latter is caught by (b)).
    if (
      ts.isElementAccessExpression(node) &&
      isGlobalReceiver(node.expression) &&
      staticStringOf(node.argumentExpression, constMap) === null
    ) {
      found = true;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return found;
};

/**
 * HA — reject hidden Node-builtin acquisition at its acquisition site
 * (D3-CX-POLICY-HA v2).
 *
 * `process.getBuiltinModule('fs')` and the legacy `process.binding('…')` return a
 * builtin with NO module specifier, so the exact `{node:http, node:url}` import
 * allowlist never sees them and a "read-only" host can still reach
 * `fs`/`child_process` authority. The v1 detector recognized the acquisition only
 * when the receiver was a directly-traced `process` alias, so forwarding `process`
 * — or the bound method itself — through a destructuring, object, array, or return
 * bypassed it. v2 reserves the capability *names* and rejects forwarding of the
 * `process` global, catching every route at the site where the name appears.
 *
 * Rejected, structurally (never by substring text):
 *   - (a) any member access — property or statically-computed element key, on ANY
 *     receiver — named `getBuiltinModule` or `binding`. Reserving the names
 *     receiver-independently is what closes forwarding: `{ acquire:
 *     process.getBuiltinModule }` and `(process as any)['getBuiltin' + 'Module']`
 *     are both caught where `getBuiltinModule` is named. This is an intentional
 *     fail-closed reservation for this narrow host boundary — see the preservation
 *     note in the HA suite about unrelated methods that happen to share the name.
 *   - (b) any destructuring of a property named `getBuiltinModule` / `binding`
 *     (`const { getBuiltinModule } = process`, `const { binding: b } = process`);
 *   - (c) forwarding the `process` global as a value — as an initializer, object
 *     property value, array element, return value, or argument — i.e. any use that
 *     is NOT a direct `process.<op>` operation. A direct operation such as
 *     `process.argv[1]` or `process.cwd()` (where `process` is the object of the
 *     access, through `as`/paren wrappers) is preserved.
 *
 * The static import allowlist is neither weakened nor replaced — `node:http` /
 * `node:url` stay allowed, `node:fs` stays rejected — this only closes the
 * specifier-less side channel and its forwarding variants. Finite and
 * conservative; the real host and Cockpit sources use none of these names and only
 * the direct `process.argv[1]` operation, which is preserved.
 */
const HIDDEN_BUILTIN_METHODS: ReadonlySet<string> = new Set(['getBuiltinModule', 'binding']);

// A node denoting the `process` global as a value: the bare `process` identifier
// used as a reference, or `globalThis.process` / `globalThis['process']` read off a
// global receiver. A `.process` member on an unrelated local object is NOT this.
const isProcessValue = (node: ts.Node, constMap: ReadonlyMap<string, string>): boolean => {
  if (ts.isIdentifier(node)) return node.text === 'process' && isValueReference(node);
  if (ts.isPropertyAccessExpression(node)) {
    return node.name.text === 'process' && isGlobalReceiver(node.expression);
  }
  if (ts.isElementAccessExpression(node)) {
    return staticStringOf(node.argumentExpression, constMap) === 'process' && isGlobalReceiver(node.expression);
  }
  return false;
};

const acquiresHiddenBuiltin = (source: string): boolean => {
  const sourceFile = ts.createSourceFile(
    'module.ts',
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    ts.ScriptKind.TS,
  );
  const constMap = collectStringConsts(sourceFile);

  let found = false;
  const visit = (node: ts.Node): void => {
    // (a) member access named getBuiltinModule / binding — any receiver.
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const member = memberNameOf(node, constMap);
      if (member !== null && HIDDEN_BUILTIN_METHODS.has(member)) found = true;
    }
    // (b) destructuring a property named getBuiltinModule / binding.
    if (ts.isBindingElement(node)) {
      const name = bindingPropertyName(node);
      if (name !== null && HIDDEN_BUILTIN_METHODS.has(name)) found = true;
    }
    // (c) forwarding the process global as a value (not a direct process operation).
    if (isProcessValue(node, constMap) && !servesAsAccessObject(node)) found = true;
    // (d) a computed element access on the process global whose key is not statically
    //     resolvable — a runtime-built key (`(process as any)[['g','e',…].join('')]`)
    //     could name `getBuiltinModule`/`binding` without exposing it to (a). This is
    //     the same finite rule as RC (f), applied to the authority object HA governs.
    //     `process.argv[1]` is unaffected: its `[1]` receiver is `process.argv`, not
    //     the process object, so this never fires on it.
    if (
      ts.isElementAccessExpression(node) &&
      isProcessValue(unwrapExpr(node.expression), constMap) &&
      staticStringOf(node.argumentExpression, constMap) === null
    ) {
      found = true;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return found;
};

/**
 * NET — reject outbound network egress at its use/acquisition site
 * (D3-CX-POLICY-NET).
 *
 * The D3 contract forbids network egress ("no network egress"; "not a
 * collector"; Stage A is "not live"). The import allowlist already blocks
 * `node:https` / `node:net` / `node:tls` (they are not on the exact
 * `{node:http, node:url}` allowlist — D3-CX-POLICY-3), and with `node:net`/`tls`/
 * `dgram`/`http2` therefore unreachable, the COMPLETE outbound surface that survives
 * every other check is finite and closed by construction:
 *   - importless network GLOBALS — `fetch` and (on the Node target) `WebSocket` are
 *     built-in globals, so they need no import and the specifier allowlist never sees
 *     them. This is the whole importless-network-global family on the target runtime,
 *     not an open-ended blacklist: a raw socket needs `node:net`/`tls`, which the
 *     import allowlist blocks.
 *   - any NON-`createServer` value reached through the legitimately-allowed
 *     `node:http` import. The read-only host needs exactly ONE node:http VALUE export
 *     — the inbound-server constructor `createServer`; every other value member/name
 *     (`request`, `get`, `ClientRequest`, `Agent`, `Agent.createConnection`, …) is a
 *     non-server (outbound/connection) capability. So node:http is decided by a finite
 *     POSITIVE model — allow `createServer`, reject the rest — and a newly-noticed
 *     client API needs NO new special case.
 *
 * This detector closes both families, decided by LEXICAL BINDING IDENTITY —
 * the binding visible at each occurrence, never mere identifier text — so
 * shadowing neither hides a real capability nor false-positives a same-named
 * local (NET-S1/NET-S2):
 *   - a network GLOBAL (`fetch`/`WebSocket`): a `<global>.<name>` member on a global
 *     receiver name (globalThis/window/self/global, incl. a statically-resolved
 *     `<global>['fetch']`) that is itself FREE here — a lexically-shadowing local
 *     receiver (`function f(globalThis){ globalThis.fetch(...) }`) is an ordinary
 *     object and is allowed; a destructuring of the name OFF such a free global
 *     receiver; or a bare reference (`fetch(...)`, `new WebSocket(...)`) that is FREE
 *     at that occurrence (no lexical binding of the name is visible). An alias
 *     `const f = fetch` is caught at the `fetch` reference; forwarding a global
 *     receiver (`const g = globalThis`) is already rejected by RC (e).
 *   - node:http value capabilities: any member OTHER than `createServer` reached
 *     through a binding THIS module imported from `node:http` — a default or namespace
 *     binding (`http.request`, `h.get`, `new http.ClientRequest()`, `new http.Agent()`),
 *     a named import used bare (`request()`, `new ClientRequest()`, `new Agent()`), an
 *     aliased named import (`req()` from `{ request as req }`), or an import-equals
 *     binding — where the receiver/name still LEXICALLY resolves to that import.
 *     `createServer` is the sole allowed value member, so the real host server is
 *     preserved; type-only `http.Server`/`IncomingMessage`/`ServerResponse` are
 *     QualifiedName nodes (never value member accesses) and stay untouched, as do
 *     `map.get(...)` / `obj.request(...)` / an unrelated local `new ClientRequest()`
 *     on any non-node:http binding.
 *
 * Binding identity is resolved by a bounded lexical ENVIRONMENT STACK tied to the
 * AST walk: each scope (module, function/arrow/method params, block, for-header,
 * catch) pushes a frame naming its own declarations; an occurrence resolves to the
 * nearest enclosing frame that binds the name. A NAMED function expression also
 * binds its own name inside its body (so `const helper = function request(){ return
 * request(); }` resolves the inner call to that self-binding, not the import). A
 * module-declared `fetch` (`function fetch(){}`, `const fetch = …`) is legal (unlike
 * `eval`) and shadows the global where it is visible; a sibling scope's local `fetch`
 * does not, and a shadow disappears once its scope closes — while a FREE-receiver
 * `globalThis.fetch` stays a member call. Structural and finite: one parse, one
 * traversal with balanced push/pop and Set/Map lookups (no fixpoint, no re-scan, no
 * value resolution), reusing `memberNameOf` / `GLOBAL_RECEIVER_NAMES` (resolved
 * lexically here) / `isValueReference` / `unwrapExpr` / `bindingPropertyName`. This is
 * a development-time SOURCE-POLICY guard, not a
 * runtime sandbox. NOT decided (bounded gaps, not sandbox claims): alias-via-
 * assignment (`const h = http; h.request()`), method extraction (`const r =
 * http.request`), runtime reassignment, computed/dynamic forwarding, and runtime-
 * generated code (RC/HA cover codegen). `node:https`/`net`/`tls` stay out of scope
 * — the import allowlist already blocks them.
 */
// The ONLY node:http VALUE export the read-only host legitimately needs is the
// inbound-server constructor `createServer`. Every other value member/name reached
// through a node:http binding is a non-server (outbound/connection) capability and is
// rejected — a finite POSITIVE model, so a client API noticed later (Agent,
// ClientRequest, request, get, …) needs no new entry. Type-only references
// (`http.Server`/`IncomingMessage`/`ServerResponse`) are QualifiedName nodes, never
// value member accesses, so they are structurally untouched.
const HTTP_SERVER_VALUE_MEMBERS: ReadonlySet<string> = new Set(['createServer']);
// Importless network-initiating globals present on the Node target. `node:https`/
// `net`/`tls`/`dgram`/`http2` are import-blocked by the allowlist, so this is the
// COMPLETE importless-egress global surface — a bounded family, not an open blacklist.
const NETWORK_GLOBAL_NAMES: ReadonlySet<string> = new Set(['fetch', 'WebSocket']);

interface HttpBindings {
  // Local names bound to the node:http MODULE (`import http` / `import * as h` /
  // `import http = require('node:http')`), used as `binding.request(...)`.
  readonly namespaceOrDefault: ReadonlySet<string>;
  // Local names bound to a NON-`createServer` node:http named value (`import
  // { request, get as g, ClientRequest, Agent }`), used bare as `request(...)` /
  // `g(...)` / `new ClientRequest()` / `new Agent()`. A named `createServer` is
  // deliberately NOT collected — it is the one legitimate value export.
  readonly namedClient: ReadonlySet<string>;
}

// Discover, structurally, the local bindings this module introduces from
// `node:http`. Keyed on the exact specifier `node:http`, so a plain local object
// named `http` (no such import) yields no binding and is never treated as the
// network module.
const collectHttpBindings = (sourceFile: ts.SourceFile): HttpBindings => {
  const NODE_HTTP = 'node:http';
  const namespaceOrDefault = new Set<string>();
  const namedClient = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      node.moduleSpecifier.text === NODE_HTTP &&
      node.importClause !== undefined
    ) {
      const clause = node.importClause;
      // `import http from 'node:http'` — default binding.
      if (clause.name !== undefined) namespaceOrDefault.add(clause.name.text);
      const bindings = clause.namedBindings;
      if (bindings !== undefined) {
        if (ts.isNamespaceImport(bindings)) {
          // `import * as http from 'node:http'`.
          namespaceOrDefault.add(bindings.name.text);
        } else {
          // `import { createServer, request, Agent as A } from 'node:http'` — collect
          // every named import EXCEPT `createServer` (the sole allowed value export),
          // under its LOCAL name (`el.name`). The positive model treats any other
          // node:http named value as a non-server capability.
          for (const el of bindings.elements) {
            const imported = (el.propertyName ?? el.name).text;
            if (!HTTP_SERVER_VALUE_MEMBERS.has(imported)) namedClient.add(el.name.text);
          }
        }
      }
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression) &&
      node.moduleReference.expression.text === NODE_HTTP
    ) {
      // `import http = require('node:http')`.
      namespaceOrDefault.add(node.name.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return { namespaceOrDefault, namedClient };
};

// Design D — node:http capability EXPORT confinement. The privileged node:http
// namespace/capability may not cross the D3 module boundary: reject any re-export FROM
// node:http (`export * from 'node:http'`, `export { … } from 'node:http'`) and any export
// of a LOCAL binding whose lexical identity is HTTP_NS (`export { http }`,
// `export { http as h }`, `export default http`, `export = http`) — createServer included.
// Ordinary local exports and type-only exports are untouched. Inspects only THIS module's
// statements and local binding identity: no cross-module value-flow.
const exportsHttpCapability = (sourceFile: ts.SourceFile): boolean => {
  const NODE_HTTP = 'node:http';
  const httpNs = new Set<string>();
  for (const s of sourceFile.statements) {
    if (
      ts.isImportDeclaration(s) &&
      ts.isStringLiteral(s.moduleSpecifier) &&
      s.moduleSpecifier.text === NODE_HTTP &&
      s.importClause !== undefined
    ) {
      const clause = s.importClause;
      if (clause.name !== undefined) httpNs.add(clause.name.text);
      if (clause.namedBindings !== undefined && ts.isNamespaceImport(clause.namedBindings)) {
        httpNs.add(clause.namedBindings.name.text);
      }
    } else if (
      ts.isImportEqualsDeclaration(s) &&
      ts.isExternalModuleReference(s.moduleReference) &&
      ts.isStringLiteral(s.moduleReference.expression) &&
      s.moduleReference.expression.text === NODE_HTTP
    ) {
      httpNs.add(s.name.text);
    } else if (ts.isVariableStatement(s)) {
      for (const decl of s.declarationList.declarations) {
        if (ts.isIdentifier(decl.name) && decl.initializer !== undefined && isNodeHttpDynamicImport(decl.initializer)) {
          httpNs.add(decl.name.text);
        }
      }
    }
  }
  for (const s of sourceFile.statements) {
    // (a) any re-export whose specifier is node:http (`export * from` / `export { … } from`).
    if (ts.isExportDeclaration(s) && s.moduleSpecifier !== undefined && ts.isStringLiteral(s.moduleSpecifier) && s.moduleSpecifier.text === NODE_HTTP) {
      return true;
    }
    // (b) a local re-export of an HTTP_NS binding (`export { http }` / `export { http as h }`).
    if (ts.isExportDeclaration(s) && s.moduleSpecifier === undefined && s.exportClause !== undefined && ts.isNamedExports(s.exportClause)) {
      for (const el of s.exportClause.elements) {
        if (httpNs.has((el.propertyName ?? el.name).text)) return true;
      }
    }
    // (c) `export default http` / `export = http`.
    if (ts.isExportAssignment(s) && ts.isIdentifier(s.expression) && httpNs.has(s.expression.text)) return true;
  }
  return false;
};

// A lexical binding kind for the identity-sensitive detection below. `HTTP_NS` and
// `HTTP_CLIENT` mark the module-level node:http import bindings (namespace/default,
// and any named node:http value that is not `createServer` respectively); `LOCAL`
// marks any OTHER declaration
// (parameter, const/let/var, function/class, catch, or unrelated import) that
// SHADOWS an outer binding of the same name. Capability identity is therefore the
// binding VISIBLE at an occurrence, never mere identifier text (NET-S1/NET-S2).
type BindingKind = 'HTTP_NS' | 'HTTP_CLIENT' | 'LOCAL';

// Collect every identifier a binding name introduces — a plain identifier or a
// (possibly nested) destructuring pattern — into `sink`. Bounded by the finite
// binding-pattern tree; performs no value resolution.
const eachBoundName = (name: ts.BindingName, sink: (text: string) => void): void => {
  if (ts.isIdentifier(name)) {
    sink(name.text);
    return;
  }
  for (const element of name.elements) {
    if (ts.isBindingElement(element)) eachBoundName(element.name, sink);
  }
};

// The names a single statement declares DIRECTLY in its own scope — const/let/var
// declarations and function/class declaration names — with no descent into nested
// blocks or functions (those get their own frames). The required matrices exercise
// only const/let/params, so `var`'s function-hoisting is a stated bounded gap that
// cannot make a covered case wrong.
const declaredByStatement = (statement: ts.Statement, sink: (text: string) => void): void => {
  if (ts.isVariableStatement(statement)) {
    for (const decl of statement.declarationList.declarations) eachBoundName(decl.name, sink);
  } else if (
    (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
    statement.name !== undefined
  ) {
    sink(statement.name.text);
  }
};

// F1/F2 node:http capability PROPAGATION, reusing binding identity (never text):
//   F1 `const http = (await) import('node:http')` -> `http` is HTTP_NS, exactly as a
//       namespace import would be.
//   F2 `const { request, get: g, createServer: cs } = <HTTP_NS>` -> each destructured
//       member preserves the namespace capability: `createServer` (the one allowed
//       server value) stays LOCAL, every other member is HTTP_CLIENT (outbound). The
//       RHS must LEXICALLY resolve to HTTP_NS, so `const { request } = someLocalObject`
//       is untouched. Bounded: one binding-pattern level, static keys only; deeper
//       nesting and genuinely computed keys are unsupported (documented) gaps.
const propagateHttpCapability = (
  decl: ts.VariableDeclaration,
  lookup: (name: string) => BindingKind | undefined,
  sink: (name: string, kind: BindingKind) => void,
): void => {
  if (decl.initializer === undefined) return;
  if (ts.isIdentifier(decl.name)) {
    if (isNodeHttpDynamicImport(decl.initializer)) sink(decl.name.text, 'HTTP_NS');
    return;
  }
  if (ts.isObjectBindingPattern(decl.name)) {
    // The RHS is the node:http namespace when it is a lexically-HTTP_NS identifier
    // OR the dynamic import itself (`const { request } = await import('node:http')`,
    // the direct F1+F2 composition).
    const rhs = unwrapExpr(decl.initializer);
    const rhsIsHttpNs =
      isNodeHttpDynamicImport(decl.initializer) || (ts.isIdentifier(rhs) && lookup(rhs.text) === 'HTTP_NS');
    if (!rhsIsHttpNs) return;
    for (const el of decl.name.elements) {
      if (!ts.isIdentifier(el.name)) continue; // nested pattern: unsupported
      const key = el.propertyName;
      const member =
        key === undefined
          ? el.name.text
          : ts.isIdentifier(key)
            ? key.text
            : ts.isStringLiteralLike(key)
              ? key.text
              : ts.isComputedPropertyName(key) && ts.isStringLiteralLike(key.expression)
                ? key.expression.text
                : null;
      if (member === null) continue; // genuinely computed key: unsupported
      sink(el.name.text, HTTP_SERVER_VALUE_MEMBERS.has(member) ? 'LOCAL' : 'HTTP_CLIENT');
    }
  }
};

// The module (top-level) lexical frame: node:http import bindings tagged with their
// capability kind, every other top-level binding tagged LOCAL. This is the outermost
// frame for the whole file, so a genuine module-level `const fetch` shadows the
// global `fetch` module-wide (NET-S2), while `globalThis.fetch` stays a member call.
const buildModuleFrame = (sourceFile: ts.SourceFile, http: HttpBindings): Map<string, BindingKind> => {
  const frame = new Map<string, BindingKind>();
  for (const statement of sourceFile.statements) {
    declaredByStatement(statement, (text) => frame.set(text, 'LOCAL'));
    if (ts.isImportDeclaration(statement) && statement.importClause !== undefined) {
      const clause = statement.importClause;
      if (clause.name !== undefined) frame.set(clause.name.text, 'LOCAL');
      const bindings = clause.namedBindings;
      if (bindings !== undefined) {
        if (ts.isNamespaceImport(bindings)) {
          frame.set(bindings.name.text, 'LOCAL');
        } else {
          for (const el of bindings.elements) frame.set(el.name.text, 'LOCAL');
        }
      }
    } else if (ts.isImportEqualsDeclaration(statement)) {
      frame.set(statement.name.text, 'LOCAL');
    }
  }
  // Capability override: the node:http import bindings win their specific kind over
  // the generic LOCAL tag applied above.
  for (const name of http.namespaceOrDefault) frame.set(name, 'HTTP_NS');
  for (const name of http.namedClient) frame.set(name, 'HTTP_CLIENT');
  // F1/F2: dynamic-import acquisition and destructuring off HTTP_NS, in source order so
  // a capability acquired earlier is visible to a later destructuring in the same scope.
  for (const statement of sourceFile.statements) {
    if (ts.isVariableStatement(statement)) {
      for (const decl of statement.declarationList.declarations) {
        propagateHttpCapability(decl, (n) => frame.get(n), (name, kind) => frame.set(name, kind));
      }
    }
  }
  return frame;
};

const usesOutboundNetwork = (source: string): boolean => {
  const sourceFile = ts.createSourceFile(
    'module.ts',
    source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    ts.ScriptKind.TS,
  );
  const constMap = collectStringConsts(sourceFile);
  const http = collectHttpBindings(sourceFile);

  // Lexical environment: a stack of frames, innermost last. `resolve` returns the
  // kind of the NEAREST visible binding of a name, or undefined when the name is
  // FREE at that occurrence (an unshadowed global such as `fetch`). Frames are
  // pushed on scope entry and popped on scope exit, so sibling scopes are
  // independent and an inner shadow vanishes once its scope closes.
  const scopes: Map<string, BindingKind>[] = [buildModuleFrame(sourceFile, http)];
  const resolve = (name: string): BindingKind | undefined => {
    for (let i = scopes.length - 1; i >= 0; i--) {
      const kind = scopes[i]?.get(name);
      if (kind !== undefined) return kind;
    }
    return undefined;
  };

  // A receiver is the REAL global object only when its identifier is a global name
  // (globalThis/window/self/global) AND no lexical binding shadows it at this
  // occurrence — identifier text is not binding identity. So
  // `function f(globalThis) { globalThis.fetch('local'); }` resolves the receiver to
  // the LOCAL parameter and is NOT the global, while an unshadowed `globalThis.fetch`
  // (FREE receiver) stays a real global member. Uses the same scope stack as `resolve`
  // rather than the RC-shared text-only `isGlobalReceiver`, so this stays local to NET.
  const isLexicalGlobalReceiver = (expr: ts.Expression): boolean => {
    const recv = unwrapExpr(expr);
    return ts.isIdentifier(recv) && GLOBAL_RECEIVER_NAMES.has(recv.text) && resolve(recv.text) === undefined;
  };

  // The frame a scope-introducing node contributes, or null when it is not one.
  // Function-likes contribute their parameters; blocks their direct lexical
  // declarations; for-headers their loop variables; catch clauses their variable.
  const frameFor = (node: ts.Node): Map<string, BindingKind> | null => {
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isConstructorDeclaration(node) ||
      ts.isGetAccessorDeclaration(node) ||
      ts.isSetAccessorDeclaration(node)
    ) {
      const frame = new Map<string, BindingKind>();
      for (const param of node.parameters) eachBoundName(param.name, (t) => frame.set(t, 'LOCAL'));
      // A NAMED function EXPRESSION binds its own name inside its body only (unlike a
      // function DECLARATION, whose name lives in the enclosing scope and is already
      // recorded there by `declaredByStatement`). Recording the self-binding in this
      // frame lets `const helper = function request() { return request(); }` resolve
      // the inner recursive call to the LOCAL self-binding, shadowing an imported
      // `request`; the frame is popped on scope exit, so it never leaks to siblings or
      // to the enclosing scope, where the import must still be rejected.
      if (ts.isFunctionExpression(node) && node.name !== undefined) {
        frame.set(node.name.text, 'LOCAL');
      }
      return frame;
    }
    if (ts.isBlock(node) || ts.isModuleBlock(node)) {
      const frame = new Map<string, BindingKind>();
      for (const statement of node.statements) declaredByStatement(statement, (t) => frame.set(t, 'LOCAL'));
      // F1/F2 capability propagation within this block, resolving a destructuring RHS
      // against this frame first, then the enclosing scopes (outer HTTP_NS imports).
      for (const statement of node.statements) {
        if (ts.isVariableStatement(statement)) {
          for (const decl of statement.declarationList.declarations) {
            propagateHttpCapability(decl, (n) => frame.get(n) ?? resolve(n), (name, kind) => frame.set(name, kind));
          }
        }
      }
      return frame;
    }
    if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
      const frame = new Map<string, BindingKind>();
      const init = node.initializer;
      if (init !== undefined && ts.isVariableDeclarationList(init)) {
        for (const decl of init.declarations) eachBoundName(decl.name, (t) => frame.set(t, 'LOCAL'));
      }
      return frame;
    }
    if (ts.isCatchClause(node)) {
      const frame = new Map<string, BindingKind>();
      if (node.variableDeclaration !== undefined) {
        eachBoundName(node.variableDeclaration.name, (t) => frame.set(t, 'LOCAL'));
      }
      return frame;
    }
    return null;
  };

  let found = false;
  const visit = (node: ts.Node): void => {
    const frame = frameFor(node);
    if (frame !== null) scopes.push(frame);

    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const member = memberNameOf(node, constMap);
      const recv = unwrapExpr(node.expression);
      const recvIsHttpNs = ts.isIdentifier(recv) && resolve(recv.text) === 'HTTP_NS';
      // (d/3) an HTTP_NS receiver is permitted ONLY for a statically-PROVEN `createServer`
      //     member; every other known member (`.request`/`.get`/`.ClientRequest`/`.Agent`/…)
      //     AND any indeterminate/computed member (`http[dynamicKey]`, member === null) is
      //     rejected fail-closed. `createServer` is the sole allowed value member; type-only
      //     `http.ServerResponse` etc. are QualifiedName, not member accesses.
      const provenCreateServer = member !== null && HTTP_SERVER_VALUE_MEMBERS.has(member);
      if (recvIsHttpNs && !provenCreateServer) found = true;
      if (member !== null) {
        // (a) `<global>.fetch` / statically-keyed `<global>['fetch']` — only when the
        //     receiver identifier is a global name that is FREE here (no local binding
        //     shadows it). A shadowing local (param/const/…) makes it an ordinary
        //     object, so `function f(globalThis) { globalThis.fetch(...) }` is allowed.
        if (NETWORK_GLOBAL_NAMES.has(member) && isLexicalGlobalReceiver(node.expression)) found = true;
      }
    }
    // (b) destructuring `fetch` off a global receiver, i.e. `const { fetch: f } =
    //     globalThis` — but only when that receiver is the FREE global (a shadowing
    //     local `globalThis`/… makes it an ordinary object, and `const { fetch } =
    //     someLocalConfig` is untouched).
    if (ts.isBindingElement(node)) {
      const name = bindingPropertyName(node);
      const decl = node.parent.parent;
      const offGlobalReceiver =
        ts.isVariableDeclaration(decl) &&
        decl.initializer !== undefined &&
        isLexicalGlobalReceiver(decl.initializer);
      if (name !== null && NETWORK_GLOBAL_NAMES.has(name) && offGlobalReceiver) found = true;
    }
    if (ts.isIdentifier(node) && isValueReference(node)) {
      // The `key` in a destructuring `const { key: local } = …` is a binding
      // PROPERTY name, not an expression read (handled receiver-scoped by rule (b)),
      // so it must not be mistaken for a bare reference to the global.
      const isBindingPropertyKey = ts.isBindingElement(node.parent) && node.parent.propertyName === node;
      if (!isBindingPropertyKey) {
        const kind = resolve(node.text);
        // (c) a bare network-global reference (`fetch`, `WebSocket`) that is FREE here
        //     — no lexical binding of the name is visible — so it is the global. A
        //     local shadow resolves to LOCAL and is allowed; `const f = fetch` is still
        //     caught at `fetch`.
        if (NETWORK_GLOBAL_NAMES.has(node.text) && kind === undefined) found = true;
        // (e) a bare reference that lexically resolves to a NON-`createServer` node:http
        //     named import (`request(...)`, `req(...)`, `new Agent()`); a shadowing
        //     local resolves LOCAL.
        if (kind === 'HTTP_CLIENT') found = true;
        // (f) DESIGN A non-escape: an HTTP_NS value reference is permitted ONLY as an
        //     access-object receiver (rule d/3), a destructuring initializer (F2), or a
        //     NET-local type/non-runtime position; EVERY other runtime reference is a
        //     forbidden ESCAPE (`const h = http`, `foo(http)`, `return http`, `[http]`,
        //     `{ v: http }`, `{ ...http }`, `export default http`) — rejected AT the name,
        //     so no alias/value-flow tracking is needed.
        if (kind === 'HTTP_NS' && isHttpNamespaceEscape(node)) found = true;
      }
    }

    ts.forEachChild(node, visit);
    if (frame !== null) scopes.pop();
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

// ---------------------------------------------------------------------------
// Symlink-escape rejection (D3-CX-POLICY-SYMLINK).
// `readdirSync`/`readFileSync` and `tsc` follow symlinks, so a committed symlink
// under src/cockpit-host could point at forbidden code outside the host boundary
// while lexical URL containment still passes. `assertNoSymlinkEntries` fails
// closed via `lstatSync` (no follow) before any read. These tests exercise it on
// an isolated temp tree — no fixture is created under src/**.
// ---------------------------------------------------------------------------
describe('D3 host purity rejects symlink escapes (D3-CX-POLICY-SYMLINK)', () => {
  // Probe whether this platform/user can create symlinks. Windows without
  // Developer Mode/admin throws EPERM; the authoritative Linux CI always can, so
  // the symlink-rejection cases run there. Where unavailable we still assert the
  // regular-file control below and skip only the cases that require creating a
  // symlink — never weakening Linux CI coverage.
  const symlinksSupported = ((): boolean => {
    try {
      const probe = mkdtempSync(join(tmpdir(), 'd3-symlink-probe-'));
      try {
        symlinkSync('target', join(probe, 'link'));
        return true;
      } finally {
        rmSync(probe, { recursive: true, force: true });
      }
    } catch {
      return false;
    }
  })();
  const itSymlink = symlinksSupported ? it : it.skip;

  const tempRoots: string[] = [];
  const makeRoot = (): string => {
    const root = mkdtempSync(join(tmpdir(), 'd3-host-symlink-'));
    tempRoots.push(root);
    return root;
  };
  afterAll(() => {
    for (const root of tempRoots) rmSync(root, { recursive: true, force: true });
  });

  it('accepts a tree of ordinary regular files (control, all platforms)', () => {
    const root = makeRoot();
    writeFileSync(join(root, 'server.ts'), "import http from 'node:http';\n");
    writeFileSync(join(root, 'render.ts'), "import { e } from './escape.js';\n");
    expect(() => {
      assertNoSymlinkEntries(root);
    }).not.toThrow();
  });

  itSymlink('rejects a host-local-looking symlink to ../domain/actions.ts', () => {
    const root = makeRoot();
    writeFileSync(join(root, 'server.ts'), "import './domain.js';\n");
    // A host-local name whose target escapes the boundary. The target is left
    // DANGLING (never created), so if the guard followed the link it would throw
    // an ENOENT read error instead of our clean symlink rejection.
    symlinkSync(join('..', 'domain', 'actions.ts'), join(root, 'domain.ts'));
    expect(() => {
      assertNoSymlinkEntries(root);
    }).toThrow(/symlink entry is forbidden/i);
  });

  itSymlink('rejects before reading or following the symlink (no ENOENT leak)', () => {
    const root = makeRoot();
    symlinkSync(join('..', '..', 'domain', 'actions.ts'), join(root, 'domain.ts'));
    let error: unknown;
    try {
      assertNoSymlinkEntries(root);
    } catch (e) {
      error = e;
    }
    // The rejection is our lstat-based symlink error, proving no read/follow of
    // the dangling target occurred (a follow would surface ENOENT instead).
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/symlink entry is forbidden/i);
    expect((error as Error).message).not.toMatch(/ENOENT/i);
  });

  itSymlink('rejects a symlinked directory that could redirect recursive enumeration', () => {
    const root = makeRoot();
    writeFileSync(join(root, 'server.ts'), "import './escape.js';\n");
    // A symlinked directory (dangling target) surfaces as a leaf entry under the
    // non-following recursive `readdirSync` and must still be rejected.
    symlinkSync(join('..', 'domain'), join(root, 'linked-dir'));
    expect(() => {
      assertNoSymlinkEntries(root);
    }).toThrow(/symlink entry is forbidden/i);
  });

  it('leaves the real host tree passing (no symlink is present today)', () => {
    // Preservation: the production host tree contains no symlink, so the guard
    // does not throw and every existing POLICY-1/2/3 check still reads it.
    expect(() => {
      assertNoSymlinkEntries(hostDir);
    }).not.toThrow();
    expect(hostSources().length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// RC — runtime code generation is forbidden (D3-CX-POLICY-RC).
// The import scanner cannot see an import built from a string handed to a
// runtime code-generation primitive, so the host must use none.
// ---------------------------------------------------------------------------
describe('D3 host forbids runtime code generation (D3-CX-POLICY-RC)', () => {
  // Enforcement over the real host tree: no production source constructs code at
  // runtime, so the discipline is satisfied today and stays satisfied.
  it('accepts every real host source (none uses runtime code generation)', () => {
    for (const { file, text } of hostSources()) {
      expect(usesRuntimeCodeGeneration(text), `${file} uses runtime code generation`).toBe(false);
    }
  });

  // --- Rejections: each required witness constructs the hidden domain import ---
  const rejected: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'direct eval', source: `eval("import('../domain/actions.js')");` },
    {
      form: 'aliased eval',
      source: `const evaluate = eval;\nevaluate("import('../domain/actions.js')");`,
    },
    { form: 'globalThis.eval', source: `globalThis.eval("import('../domain/actions.js')");` },
    {
      form: 'globalThis["eval"] (string-keyed)',
      source: `globalThis["eval"]("import('../domain/actions.js')");`,
    },
    { form: 'Function call', source: `Function('return import("../domain/actions.js")')();` },
    { form: 'new Function', source: `new Function('return import("../domain/actions.js")');` },
    {
      form: 'async-arrow constructor chain',
      source: `(async () => {}).constructor('return import("../domain/actions.js")')();`,
    },
    {
      form: 'generator constructor chain',
      source: `(function* () {}).constructor('return import("../domain/actions.js")')();`,
    },
    {
      form: 'chained alias of eval',
      source: `const a = eval;\nconst b = a;\nb("import('../domain/actions.js')");`,
    },
  ];
  for (const { form, source } of rejected) {
    it(`rejects ${form}`, () => {
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    });
  }

  // --- False-positive controls: text that merely mentions the primitives ---
  const accepted: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'line comment mentioning eval/Function', source: `const x = 1; // eval("nope") new Function()` },
    {
      form: 'block comment mentioning the primitives',
      source: `/* do not eval(...) or new Function(...) here */\nexport const ok = true;`,
    },
    {
      form: 'string data containing the words',
      source: `const s = "eval('x')";\nconst t = 'Function';\nconst u = \`eval\`;`,
    },
    {
      form: 'identifiers whose names merely contain the substrings',
      source: `const evaluate = (a: number) => a;\nconst functionalValue = 2;\nevaluate(functionalValue);`,
    },
    {
      form: 'domain-style evaluate call (not a codegen alias)',
      source: `import { evaluateEvidenceSet } from '../cockpit/index.js';\nevaluateEvidenceSet([], {});`,
    },
    {
      form: 'a class with a constructor declaration and ordinary new',
      source: `class C { constructor() {} }\nconst c = new C();\nconst u = new URL('http://x');`,
    },
    {
      form: 'a property literally named eval that is never called',
      source: `const cfg = { eval: false, Function: 'x' };\nconst y = cfg.eval;`,
    },
  ];
  for (const { form, source } of accepted) {
    it(`does not flag ${form}`, () => {
      expect(usesRuntimeCodeGeneration(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// HA — hidden Node-builtin acquisition is forbidden (D3-CX-POLICY-HA).
// A builtin obtained without an import specifier bypasses the exact allowlist.
// ---------------------------------------------------------------------------
describe('D3 host forbids hidden builtin acquisition (D3-CX-POLICY-HA)', () => {
  // Enforcement over the real host tree: no production source acquires a builtin
  // through a specifier-less side channel.
  it('accepts every real host source (none hides a builtin acquisition)', () => {
    for (const { file, text } of hostSources()) {
      expect(acquiresHiddenBuiltin(text), `${file} hides a builtin acquisition`).toBe(false);
    }
  });

  // --- Rejections: each required specifier-less acquisition route ---
  const rejected: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'direct process.getBuiltinModule', source: `const fs = process.getBuiltinModule('fs');` },
    {
      form: 'globalThis.process.getBuiltinModule',
      source: `const cp = globalThis.process.getBuiltinModule('child_process');`,
    },
    {
      form: 'string-keyed getBuiltinModule',
      source: `const fs = process['getBuiltinModule']('fs');`,
    },
    {
      form: 'simple process alias',
      source: `const proc = process;\nconst fs = proc.getBuiltinModule('fs');`,
    },
    {
      form: 'simple method alias',
      source: `const getBuiltin = process.getBuiltinModule;\nconst fs = getBuiltin('fs');`,
    },
    { form: 'direct process.binding', source: `const fs = process.binding('fs');` },
    {
      form: 'globalThis.process.binding',
      source: `const n = globalThis.process.binding('natives');`,
    },
    {
      form: 'aliased process.binding',
      source: `const proc = process;\nconst n = proc.binding('natives');`,
    },
  ];
  for (const { form, source } of rejected) {
    it(`rejects ${form}`, () => {
      expect(acquiresHiddenBuiltin(source)).toBe(true);
    });
  }

  // --- False-positive controls: unrelated process/binding text ---
  const notHidden: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'process.env access (a different concern)', source: `const p = process.env.PORT;` },
    { form: 'process.exitCode assignment', source: `process.exitCode = 0;` },
    { form: 'process.cwd() call', source: `const d = process.cwd();` },
    { form: 'comment mentioning getBuiltinModule', source: `// process.getBuiltinModule('fs') is banned\nexport const ok = true;` },
    { form: 'string containing the method name', source: `const s = "getBuiltinModule";\nconst t = 'binding';` },
    { form: 'identifier named binding, unrelated', source: `const binding = 1;\nconst z = binding + 2;` },
    { form: 'direct process.argv[1] operation (as the real host uses)', source: `const entry = process.argv[1];\nvoid entry;` },
  ];
  for (const { form, source } of notHidden) {
    it(`does not flag ${form}`, () => {
      expect(acquiresHiddenBuiltin(source)).toBe(false);
    });
  }

  // INTENTIONAL RESERVATION (v2, documented): the v1 control that asserted an
  // unrelated object method named `getBuiltinModule`/`binding` is NOT flagged is
  // inverted here. The v2 positive contract reserves those capability names
  // receiver-independently, which is what lets it catch a forwarded acquisition
  // (`{ acquire: process.getBuiltinModule }`) at the site where the name appears.
  // The real host and Cockpit sources define no such method, so the reservation is
  // safe — see the "accepts every real host source" enforcement above.
  it('reserves getBuiltinModule / binding as capability names on any receiver', () => {
    expect(
      acquiresHiddenBuiltin(`const svc = { getBuiltinModule(x: string) { return x; } };\nsvc.getBuiltinModule('ok');`),
    ).toBe(true);
    expect(acquiresHiddenBuiltin(`const svc = { binding(x: string) { return x; } };\nsvc.binding('ok');`)).toBe(
      true,
    );
  });

  // --- Preservation: the static builtin allowlist is untouched by this repair ---
  it('keeps the exact `{node:http, node:url}` allowlist and still rejects node:fs', () => {
    expect(isAllowedNodeBuiltin('node:http')).toBe(true);
    expect(isAllowedNodeBuiltin('node:url')).toBe(true);
    expect(isAllowedNodeBuiltin('node:fs')).toBe(false);
    // A hidden acquisition is not an import specifier, so it never appears in the
    // extractor's output — the allowlist alone could not have caught it.
    expect(extractModuleSpecifiers(`const fs = process.getBuiltinModule('fs');`)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// RC v2 — forwarding closure. The v1 detector missed a code-generation primitive
// laundered through destructuring, an object, an array, or a function return; v2
// catches it at the naming site. Every witness below typechecks under the repo's
// strict NodeNext config (verified by an out-of-worktree harness) and reaches
// runtime code generation on Node 24.
// ---------------------------------------------------------------------------
describe('D3 host RC forwarding closure rejects laundered code generation (D3-CX-POLICY-RC v2)', () => {
  const rejected: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'destructured eval', source: `const { eval: e } = globalThis;\ne("import('../domain/actions.js')");` },
    { form: 'renamed destructured eval', source: `const { eval: evaluate } = globalThis;\nevaluate("import('../domain/actions.js')");` },
    { form: 'eval in an object property', source: `const o = { e: eval };\no.e("import('../domain/actions.js')");` },
    { form: 'eval in an array invoked with [0]!', source: `const a = [eval];\na[0]!("import('../domain/actions.js')");` },
    { form: 'eval returned from a function', source: `function f() { return eval; }\nf()("import('../domain/actions.js')");` },
    { form: 'eval passed through a function argument', source: `function run(fn: (s: string) => unknown) { fn("import('../domain/actions.js')"); }\nrun(eval);` },
    { form: 'destructured Function', source: `const { Function: F } = globalThis;\nF('return import("../domain/actions.js")')();` },
    { form: 'Function in an object property', source: `const o = { c: Function };\no.c('return import("../domain/actions.js")')();` },
    { form: 'Function returned from a function', source: `function f() { return Function; }\nf()('return import("../domain/actions.js")')();` },
    { form: "globalThis['ev' + 'al'] via as-any cast", source: `(globalThis as any)['ev' + 'al']("import('../domain/actions.js')");` },
    { form: "globalThis['Fun' + 'ction'] via as-any cast", source: `(globalThis as any)['Fun' + 'ction']('return import("../domain/actions.js")')();` },
    { form: 'extracted async-function constructor', source: `const F = (async () => {}).constructor;\nF('return import("../domain/actions.js")')();` },
    { form: 'extracted generator-function constructor', source: `const F = (function* () {}).constructor;\nF('return import("../domain/actions.js")')();` },
    { form: 'statically-computed constructor member access', source: `const obj = (async () => {}) as any;\nconst C = obj['con' + 'structor'];\nC('return import("../domain/actions.js")')();` },
  ];
  for (const { form, source } of rejected) {
    it(`rejects ${form}`, () => {
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    });
  }

  // Preservation: forms that name none of the primitives at a value/member site.
  it('preserves local `.eval`, class constructors, and unrelated identifiers', () => {
    expect(usesRuntimeCodeGeneration(`const cfg = { eval: false };\nconst y = cfg.eval;`)).toBe(false);
    expect(usesRuntimeCodeGeneration(`class C { constructor() {} }\nconst c = new C();\nconst u = new URL('http://x');`)).toBe(false);
    expect(usesRuntimeCodeGeneration(`const evaluate = (x: number) => x;\nconst functionalValue = 2;\nevaluate(functionalValue);`)).toBe(false);
    // v3 note: a bare `const g = globalThis` value is now REJECTED as global-object
    // forwarding (see the RC v3 suite); a DIRECT global member access stays allowed.
    expect(usesRuntimeCodeGeneration(`globalThis.console.log('x');`)).toBe(false);
    expect(usesRuntimeCodeGeneration(`globalThis.setTimeout(() => {}, 0);`)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// HA v2 — forwarding closure. The v1 detector missed a hidden acquisition
// laundered by forwarding `process` or the bound method through a destructuring,
// object, array, or return; v2 reserves the capability names and rejects process
// forwarding. Every witness typechecks under the repo config and is
// capability-relevant on Node 24.
// ---------------------------------------------------------------------------
describe('D3 host HA forwarding closure rejects laundered builtin acquisition (D3-CX-POLICY-HA v2)', () => {
  const rejected: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'destructured getBuiltinModule', source: `const { getBuiltinModule } = process;\nconst m = getBuiltinModule('fs');\nvoid m;` },
    { form: 'renamed destructured getBuiltinModule', source: `const { getBuiltinModule: acquire } = process;\nconst m = acquire('fs');\nvoid m;` },
    { form: 'process in an object property', source: `const o = { p: process };\nconst m = o.p.getBuiltinModule('fs');\nvoid m;` },
    { form: 'process in an array using [0]!', source: `const a = [process];\nconst m = a[0]!.getBuiltinModule('fs');\nvoid m;` },
    { form: 'process returned from a function', source: `function f() { return process; }\nconst m = f().getBuiltinModule('fs');\nvoid m;` },
    { form: 'process passed through a function argument', source: `function run(p: NodeJS.Process) { p.getBuiltinModule('fs'); }\nrun(process);` },
    { form: 'getBuiltinModule stored in an object', source: `const o = { acquire: process.getBuiltinModule };\nconst m = o.acquire('fs');\nvoid m;` },
    { form: 'getBuiltinModule stored in an array', source: `const a = [process.getBuiltinModule];\nconst m = a[0]!('fs');\nvoid m;` },
    { form: 'getBuiltinModule returned from a function', source: `function f() { return process.getBuiltinModule; }\nconst m = f()('fs');\nvoid m;` },
    { form: 'computed process access via as-any', source: `const m = (process as any)['getBuiltin' + 'Module']('fs');\nvoid m;` },
    { form: "statically-computed 'getBuiltin' + 'Module'", source: `const method = 'getBuiltin' + 'Module';\nconst m = (process as any)[method]('fs');\nvoid m;` },
    { form: 'direct process.binding via as-any', source: `const internal = (process as any).binding('fs');\nvoid internal;` },
    { form: 'destructured binding via as-any', source: `const { binding: acquireBinding } = process as any;\nconst internal = acquireBinding('fs');\nvoid internal;` },
  ];
  for (const { form, source } of rejected) {
    it(`rejects ${form}`, () => {
      expect(acquiresHiddenBuiltin(source)).toBe(true);
    });
  }

  // Preservation: direct process operations and unrelated text remain accepted.
  it('preserves direct process.argv[1] / process.cwd() and unrelated text', () => {
    expect(acquiresHiddenBuiltin(`const entry = process.argv[1];\nvoid entry;`)).toBe(false);
    expect(acquiresHiddenBuiltin(`const d = process.cwd();\nvoid d;`)).toBe(false);
    expect(acquiresHiddenBuiltin(`(process as any).exitCode = 0;`)).toBe(false);
    expect(acquiresHiddenBuiltin(`// process.getBuiltinModule('fs') and process.binding are banned\nexport const ok = true;`)).toBe(false);
    expect(acquiresHiddenBuiltin(`const s = 'getBuiltinModule';\nconst t = \`binding\`;\nvoid s;\nvoid t;`)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// RC v3 — global-object forwarding closure. v2 rejected `.eval`/`.Function` only
// off a *named* global receiver, so aliasing the global object to a non-reserved
// name (`const g = globalThis; g.eval(...)`) evaded it. v3 rejects forwarding a
// recognized global-authority object as a value, and rejects an unresolved
// computed access on a global receiver — so the alias can never be created and a
// runtime-built property name cannot launder the acquisition. Every witness
// typechecks under strict NodeNext (verified by an out-of-worktree harness).
// ---------------------------------------------------------------------------
describe('D3 host RC global-object forwarding closure (D3-CX-POLICY-RC v3)', () => {
  const rejected: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'direct globalThis alias then eval', source: `const g = globalThis;\ng.eval("import('../domain/actions.js')");` },
    { form: 'globalThis forwarded through an object', source: `const holder = { g: globalThis };\nholder.g.eval("import('../domain/actions.js')");` },
    { form: 'globalThis forwarded through an array', source: `const holders = [globalThis];\nholders[0]!.eval("import('../domain/actions.js')");` },
    { form: 'globalThis returned from a function', source: `function obtainGlobal() { return globalThis; }\nobtainGlobal().eval("import('../domain/actions.js')");` },
    { form: 'globalThis passed as a function argument', source: `function consume(x: typeof globalThis) { void x; }\nconsume(globalThis);` },
    { form: 'node global alias then eval', source: `const g = global;\ng.eval("import('../domain/actions.js')");` },
    { form: 'window alias then eval (type-valid synthetic)', source: `declare const window: typeof globalThis;\nconst g = window;\ng.eval("import('../domain/actions.js')");` },
    { form: 'self alias then eval (type-valid synthetic)', source: `declare const self: typeof globalThis;\nconst g = self;\ng.eval("import('../domain/actions.js')");` },
    { form: 'aliased globalThis then Function', source: `const g = globalThis;\ng.Function('return import("../domain/actions.js")')();` },
    { form: 'aliased globalThis then process.getBuiltinModule', source: `const g = globalThis;\nconst m = g.process.getBuiltinModule('fs');\nvoid m;` },
    { form: "runtime-computed global lookup via .join('')", source: `const key = ['e', 'v', 'a', 'l'].join('');\n(globalThis as any)[key]("import('../domain/actions.js')");` },
    { form: 'runtime-computed global lookup via String.fromCharCode', source: `const key = String.fromCharCode(101, 118, 97, 108);\n(globalThis as any)[key]("import('../domain/actions.js')");` },
    { form: "statically-computed global lookup ['ev' + 'al']", source: `(globalThis as any)['ev' + 'al']("import('../domain/actions.js')");` },
    // Deeper alias chains — rejected at the ORIGINAL global acquisition/forwarding
    // site, with no deep flow tracing.
    { form: 'two-hop globalThis alias chain', source: `const a = globalThis;\nconst b = a;\nb.eval("import('../domain/actions.js')");` },
    { form: 'globalThis via object then extracted', source: `const a = { global: globalThis };\nconst b = a.global;\nb.Function('return 1')();` },
  ];
  for (const { form, source } of rejected) {
    it(`rejects ${form}`, () => {
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    });
  }

  // Preservation: a global object that DIRECTLY serves as a member-access receiver
  // is a normal, harmless operation and must remain accepted.
  it('preserves direct harmless global member access', () => {
    expect(usesRuntimeCodeGeneration(`globalThis.console.log('x');`)).toBe(false);
    expect(usesRuntimeCodeGeneration(`globalThis.setTimeout(() => {}, 0);`)).toBe(false);
    expect(usesRuntimeCodeGeneration(`const d = globalThis.process.cwd();\nvoid d;`)).toBe(false);
    expect(usesRuntimeCodeGeneration(`const c = globalThis['console'];\nvoid c;`)).toBe(false); // statically resolved
    expect(usesRuntimeCodeGeneration(`const p = process.cwd();\nvoid p;`)).toBe(false);
  });

  // The aliased-globalThis-then-getBuiltinModule witness is ALSO independently
  // caught by the HA reserved-name rule — either detector rejecting the source is
  // sufficient for the enforcement `it`s that check both.
  it('HA independently rejects the aliased-global getBuiltinModule witness', () => {
    expect(acquiresHiddenBuiltin(`const g = globalThis;\nconst m = g.process.getBuiltinModule('fs');\nvoid m;`)).toBe(
      true,
    );
  });

  // The runtime-computed process lookup (HA (d)) — reserved-name laundering through
  // a non-static key on the process object — is closed too.
  it('HA rejects a runtime-computed process element access', () => {
    expect(
      acquiresHiddenBuiltin(`const key = ['g', 'e', 't'].join('');\nconst m = (process as any)[key]('fs');\nvoid m;`),
    ).toBe(true);
    // Preservation: the real host's direct `process.argv[1]` (numeric key on
    // `process.argv`, not on `process`) is unaffected.
    expect(acquiresHiddenBuiltin(`const e = process.argv[1];\nvoid e;`)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// F1/F2 — the shared static-const resolver (collectStringConsts) must be
// scope-sensitive and total. These suites drive the resolver THROUGH the RC/HA
// detectors, the way the rest of this file does, using an identifier-keyed
// `(globalThis as any)[k]` / `(process as any)[k]` as the verdict lever:
//
//   - if `k` resolves to a benign string (e.g. 'console'), the key is non-null and
//     harmless, so RC/HA ACCEPT (`false`);
//   - if `k` is UNKNOWN, the computed global/authority key is not statically
//     resolvable, so the fail-closed rule rejects (`true`).
//
// So `toBe(true)` on an F1 witness whose value would be the *harmless* string
// means the name did NOT inherit that static value from another binding — the F1
// invariant. `toBe(false)` on a genuinely unique immutable const means it still
// resolves. The F2 suite asserts every conflicting/cyclic shape simply RETURNS a
// verdict — with the old `while (pass())` fixpoint these sources looped forever.
// ---------------------------------------------------------------------------

const RC_LAUNDER = `("import('../domain/actions.js')")`;

describe('D3 host static-const resolver is scope-sensitive (D3-CX-POLICY-F1)', () => {
  // Each source resolves its key to the HARMLESS 'console' if (and only if) the
  // resolver wrongly inherits a static value across a shadow/mutation/rebinding.
  // The correct verdict is UNKNOWN -> fail-closed rejection (`true`).
  const mustReject: readonly { readonly form: string; readonly source: string }[] = [
    {
      form: 'a parameter shadows an outer const of the same name',
      source: `const key = 'console';\nfunction run(key: string) { (globalThis as any)[key]${RC_LAUNDER}; }\nrun('eval');`,
    },
    {
      form: 'a nested block const shadows an outer const',
      source: `const key = 'console';\n{\n  const key = 'eval';\n  (globalThis as any)[key]${RC_LAUNDER};\n}`,
    },
    {
      form: 'a mutable let is reassigned before use',
      source: `let key = 'console';\nkey = 'eval';\n(globalThis as any)[key]${RC_LAUNDER};`,
    },
    {
      form: 'a mutable let is compound-assigned before use',
      source: `let key = 'con';\nkey += 'sole';\n(globalThis as any)[key]${RC_LAUNDER};`,
    },
    {
      // Parse-only, deliberately type-invalid: exercises the ++/-- update-target
      // inventory. A benign const that is ever an increment/decrement target is
      // mutable and must not fold to its harmless initializer.
      form: 'a const is an increment target (update-target inventory)',
      source: `const key = 'console';\nkey++;\n(globalThis as any)[key]${RC_LAUNDER};`,
    },
    {
      form: 'a const is a decrement target (update-target inventory)',
      source: `const key = 'console';\n--key;\n(globalThis as any)[key]${RC_LAUNDER};`,
    },
    {
      form: 'a destructuring binding rebinds an outer const name',
      source: `const key = 'console';\nconst holder = { key: 'eval' } as any;\nconst { key } = holder;\n(globalThis as any)[key]${RC_LAUNDER};`,
    },
    {
      form: 'a catch binding rebinds an outer const name',
      source: `const err = 'console';\ntry {\n  doWork();\n} catch (err) {\n  (globalThis as any)[err]${RC_LAUNDER};\n}`,
    },
    {
      form: 'the same text is bound as a const in two disjoint function scopes',
      source: `function a() { const key = 'console'; return key; }\nfunction b() { (globalThis as any)[key]${RC_LAUNDER}; const key = 'eval'; }`,
    },
    {
      // Repeated same-name bindings are UNKNOWN even with identical initial values.
      form: 'the same name is const-bound twice with the identical harmless value',
      source: `const key = 'console';\n{ const key = 'console'; }\n(globalThis as any)[key]${RC_LAUNDER};`,
    },
    {
      // Parse-only: an `import key = N.value` alias inside a namespace binds the
      // text `key` a second time, so the outer immutable `const key = 'console'`
      // is no longer unique and must fold to UNKNOWN. Without counting
      // ImportEqualsDeclaration the resolver would inherit the harmless outer value
      // while the runtime alias resolves to `N.value` (`'eval'`).
      form: 'an import-equals alias rebinds an outer const name (import-equals inventory)',
      source: `const key = 'console';\nnamespace N { export const value = 'eval'; }\nnamespace M {\n  import key = N.value;\n  (globalThis as any)[key]${RC_LAUNDER};\n}`,
    },
  ];
  for (const { form, source } of mustReject) {
    it(`does not inherit a static value when ${form}`, () => {
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    });
  }

  // Preservation — genuinely unique, immutable, unmutated consts still resolve.
  it('resolves two distinct unique consts that share the same value, independently', () => {
    // Both resolve to the harmless 'console' -> accepted. If either had collapsed
    // to UNKNOWN, the fail-closed rule would have rejected.
    const source = `const a = 'console';\nconst b = 'console';\nvoid (globalThis as any)[a];\nvoid (globalThis as any)[b];`;
    expect(usesRuntimeCodeGeneration(source)).toBe(false);
  });

  it('folds a unique immutable `+`-concatenation chain to its real value', () => {
    // Benign chain resolves (accepted); dangerous chain folds to 'eval' and is
    // rejected on the RESOLVED name (not merely fail-closed).
    expect(usesRuntimeCodeGeneration(`const part = 'con';\nconst full = part + 'sole';\nvoid (globalThis as any)[full];`)).toBe(
      false,
    );
    expect(usesRuntimeCodeGeneration(`const a = 'ev';\nconst b = a + 'al';\n(globalThis as any)[b]${RC_LAUNDER};`)).toBe(true);
    // HA folds a two-token concatenation to a reserved builtin method name too.
    expect(
      acquiresHiddenBuiltin(`const method = 'getBuiltin' + 'Module';\nconst m = (process as any)[method]('fs');\nvoid m;`),
    ).toBe(true);
  });

  it('accepts unrelated harmless local member access resolved from a local const', () => {
    // A local const key on a NON-authority object is resolved and harmless.
    expect(usesRuntimeCodeGeneration(`const key = 'log';\nconst o = { log(x: string) { return x; } } as any;\no[key]('hi');`)).toBe(
      false,
    );
    // A `.eval` property read off a non-global local object is not the primitive.
    expect(usesRuntimeCodeGeneration(`const cfg = { eval: false };\nconst y = cfg.eval;\nvoid y;`)).toBe(false);
  });
});

describe('D3 host static-const resolver terminates on every finite source (D3-CX-POLICY-F2)', () => {
  // The old name-only fixpoint looped forever whenever two scopes declared the
  // same name with different values. Each case here must return a verdict; the
  // explicit per-test timeout turns any reintroduced non-termination into a fast,
  // localized failure rather than a silent CI hang.
  const TERMINATION_BUDGET_MS = 2000;

  it(
    'terminates (as UNKNOWN) on conflicting same-name declarations',
    () => {
      const source = `const x = 'a';\n{ const x = 'b'; }\n(globalThis as any)[x]${RC_LAUNDER};`;
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    },
    TERMINATION_BUDGET_MS,
  );

  it(
    'terminates (as UNKNOWN) on same-name/same-value declarations',
    () => {
      // Identical values, benign: a wrong fold would ACCEPT; the correct UNKNOWN
      // fail-closes to reject. Either way it must terminate.
      const source = `const x = 'console';\n{ const x = 'console'; }\n(globalThis as any)[x]${RC_LAUNDER};`;
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    },
    TERMINATION_BUDGET_MS,
  );

  it(
    'terminates normally when all declared names are different',
    () => {
      const source = `const x = 'console';\nconst y = 'setTimeout';\nvoid (globalThis as any)[x];\nvoid (globalThis as any)[y];`;
      expect(usesRuntimeCodeGeneration(source)).toBe(false);
    },
    TERMINATION_BUDGET_MS,
  );

  it(
    'resolves a long finite immutable dependency chain',
    () => {
      const chain =
        `const s0 = 'console';\n` +
        Array.from({ length: 40 }, (_, i) => `const s${String(i + 1)} = s${String(i)};`).join('\n') +
        `\nvoid (globalThis as any)[s40];`;
      // The 41-deep chain resolves to the harmless 'console' -> accepted.
      expect(usesRuntimeCodeGeneration(chain)).toBe(false);
    },
    TERMINATION_BUDGET_MS,
  );

  it(
    'terminates (as UNKNOWN) on a cyclic const dependency',
    () => {
      // Parse-only TDZ cycle a -> b -> a. Resolution must break the cycle, not spin.
      const source = `const a = b;\nconst b = a;\n(globalThis as any)[a]${RC_LAUNDER};`;
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    },
    TERMINATION_BUDGET_MS,
  );

  it(
    'terminates in BOTH the RC and HA consumers on a conflicting-name source',
    () => {
      const source = `const p = 'a';\n{ const p = 'b'; }\nvoid (globalThis as any)[p];\nvoid (process as any)[p];`;
      let rcVerdict: boolean | undefined;
      let haVerdict: boolean | undefined;
      expect(() => {
        rcVerdict = usesRuntimeCodeGeneration(source);
        haVerdict = acquiresHiddenBuiltin(source);
      }).not.toThrow();
      expect(typeof rcVerdict).toBe('boolean');
      expect(typeof haVerdict).toBe('boolean');
    },
    TERMINATION_BUDGET_MS,
  );
});

// ---------------------------------------------------------------------------
// FB — the symlink boundary covers BOTH allowed source roots (D3-CX-POLICY-FB).
// A symlink under src/cockpit could redirect a `../cockpit/…` host import onto
// the domain kernel; `assertNoSymlinkEntries` must guard that root too.
// ---------------------------------------------------------------------------
describe('D3 host rejects symlink escapes under the Cockpit boundary (D3-CX-POLICY-FB)', () => {
  // Symlink-capability probe, identical in spirit to the host-root suite: Windows
  // without Developer Mode/admin throws EPERM, so the symlink-creation cases are
  // capability-gated while the ordinary-file and real-tree controls always run.
  // Authoritative Linux CI always supports symlinks and runs every case.
  const symlinksSupported = ((): boolean => {
    try {
      const probe = mkdtempSync(join(tmpdir(), 'd3-fb-symlink-probe-'));
      try {
        symlinkSync('target', join(probe, 'link'));
        return true;
      } finally {
        rmSync(probe, { recursive: true, force: true });
      }
    } catch {
      return false;
    }
  })();
  const itSymlink = symlinksSupported ? it : it.skip;

  const tempRoots: string[] = [];
  const makeRoot = (): string => {
    const root = mkdtempSync(join(tmpdir(), 'd3-cockpit-symlink-'));
    tempRoots.push(root);
    return root;
  };
  afterAll(() => {
    for (const root of tempRoots) rmSync(root, { recursive: true, force: true });
  });

  it('accepts a tree of ordinary Cockpit-boundary files (control, all platforms)', () => {
    const root = makeRoot();
    writeFileSync(join(root, 'index.ts'), "export { x } from '../domain/actions.js';\n");
    writeFileSync(join(root, 'read-model.ts'), 'export const model = {};\n');
    expect(() => {
      assertNoSymlinkEntries(root);
    }).not.toThrow();
  });

  itSymlink('rejects a Cockpit-boundary file symlink to ../domain/actions.ts', () => {
    const root = makeRoot();
    writeFileSync(join(root, 'index.ts'), "export { x } from './bridge.js';\n");
    // A Cockpit-local name whose target escapes the boundary; left DANGLING so a
    // follow would surface ENOENT instead of the clean symlink rejection.
    symlinkSync(join('..', 'domain', 'actions.ts'), join(root, 'bridge.ts'));
    expect(() => {
      assertNoSymlinkEntries(root);
    }).toThrow(/symlink entry is forbidden/i);
  });

  itSymlink('rejects a symlinked directory under the Cockpit boundary', () => {
    const root = makeRoot();
    writeFileSync(join(root, 'index.ts'), 'export const ok = true;\n');
    symlinkSync(join('..', 'domain'), join(root, 'linked-dir'));
    expect(() => {
      assertNoSymlinkEntries(root);
    }).toThrow(/symlink entry is forbidden/i);
  });

  itSymlink('rejects a nested Cockpit-boundary symlink at any depth', () => {
    const root = makeRoot();
    mkdirSync(join(root, 'nested'), { recursive: true });
    writeFileSync(join(root, 'nested', 'index.ts'), 'export const ok = true;\n');
    symlinkSync(join('..', '..', 'domain', 'actions.ts'), join(root, 'nested', 'bridge.ts'));
    expect(() => {
      assertNoSymlinkEntries(root);
    }).toThrow(/symlink entry is forbidden/i);
  });

  itSymlink('rejects a dangling Cockpit-boundary symlink without leaking ENOENT', () => {
    const root = makeRoot();
    symlinkSync(join('..', 'nowhere', 'gone.ts'), join(root, 'bridge.ts'));
    let error: unknown;
    try {
      assertNoSymlinkEntries(root);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/symlink entry is forbidden/i);
    expect((error as Error).message).not.toMatch(/ENOENT/i);
  });

  it('leaves the real Cockpit boundary passing (no symlink is present today)', () => {
    expect(() => {
      assertNoSymlinkEntries(cockpitDir);
    }).not.toThrow();
  });

  it('applies the Cockpit-boundary scan through the shared hostSources() reader', () => {
    // hostSources() now scans BOTH roots before returning any source, so the guard
    // fails closed on a Cockpit-boundary symlink exactly as it does on a host one.
    expect(() => hostSources()).not.toThrow();
    expect(hostSources().length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// NET — the host must perform no outbound network egress (D3-CX-POLICY-NET).
// The routes that survive every OTHER purity check are the importless network
// globals (`fetch`/`WebSocket`) and any NON-`createServer` value reached through the
// already-allowed `node:http` module. `usesOutboundNetwork` closes both by a finite
// model — a bounded global family plus a POSITIVE node:http allow of exactly
// `createServer` — receiver-scoped, while preserving `http.createServer` and every
// unrelated `.get`/`.request`. node:https/net/tls stay covered by the import allowlist
// (D3-CX-POLICY-3), not here — see the detector's doc comment.
// ---------------------------------------------------------------------------
describe('D3 host forbids outbound network egress (D3-CX-POLICY-NET)', () => {
  it('accepts every real host source (no egress is present today)', () => {
    for (const { file, text } of hostSources()) {
      expect(usesOutboundNetwork(text), `${file} performs outbound network egress`).toBe(false);
    }
  });

  // --- MUST REJECT: global fetch, at every bounded acquisition/use site ---
  const rejectFetch: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a bare global fetch call', source: `export async function p() { await fetch('https://example.com/'); }` },
    { form: 'globalThis.fetch', source: `globalThis.fetch('https://example.com/');` },
    { form: 'a statically-keyed globalThis["fetch"]', source: `globalThis['fetch']('https://example.com/');` },
    { form: 'a window.fetch receiver', source: `window.fetch('https://example.com/');` },
    { form: 'a self.fetch receiver', source: `self.fetch('https://example.com/');` },
    { form: 'an aliased global fetch acquisition (const f = fetch)', source: `const f = fetch;\nf('https://example.com/');` },
    {
      form: 'a destructured global fetch acquisition',
      source: `const { fetch: f } = globalThis;\nf('https://example.com/');`,
    },
  ];
  for (const { form, source } of rejectFetch) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- MUST REJECT: node:http client APIs, bound specifically to node:http ---
  const rejectHttp: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a default node:http binding .request', source: `import http from 'node:http';\nhttp.request('http://example.com/');` },
    { form: 'a default node:http binding .get', source: `import http from 'node:http';\nhttp.get('http://example.com/');` },
    { form: 'a namespace node:http binding .request', source: `import * as http from 'node:http';\nhttp.request('http://example.com/');` },
    { form: 'a namespace-ALIAS binding .request', source: `import * as h from 'node:http';\nh.request('http://example.com/');` },
    { form: 'a namespace-ALIAS binding .get', source: `import * as h from 'node:http';\nh.get('http://example.com/');` },
    { form: 'a statically-keyed member on a node:http binding', source: `import * as http from 'node:http';\nhttp['request']('http://example.com/');` },
    { form: 'a named request import used bare', source: `import { request } from 'node:http';\nrequest('http://example.com/');` },
    { form: 'a named get import used bare', source: `import { get } from 'node:http';\nget('http://example.com/');` },
    { form: 'an aliased named request import', source: `import { request as req } from 'node:http';\nreq('http://example.com/');` },
    { form: 'an aliased named get import', source: `import { get as httpGet } from 'node:http';\nhttpGet('http://example.com/');` },
    { form: 'an import-equals node:http binding .request', source: `import http = require('node:http');\nhttp.request('http://example.com/');` },
    { form: 'a named ClientRequest import constructed', source: `import { ClientRequest } from 'node:http';\nnew ClientRequest('http://example.com/').end();` },
    { form: 'an aliased named ClientRequest import constructed', source: `import { ClientRequest as CR } from 'node:http';\nnew CR('http://example.com/').end();` },
    { form: 'a namespace node:http binding new .ClientRequest', source: `import * as http from 'node:http';\nnew http.ClientRequest('http://example.com/').end();` },
    { form: 'a default node:http binding new .ClientRequest', source: `import http from 'node:http';\nnew http.ClientRequest('http://example.com/').end();` },
    { form: 'an import-equals node:http binding new .ClientRequest', source: `import http = require('node:http');\nnew http.ClientRequest('http://example.com/').end();` },
    { form: 'a statically-keyed ClientRequest member on a node:http binding', source: `import * as http from 'node:http';\nnew http['ClientRequest']('http://example.com/').end();` },
    // node:http connection APIs beyond the request/get/ClientRequest names — caught by
    // the POSITIVE model (only `createServer` is allowed) with no per-name entry.
    { form: 'a namespace node:http binding new .Agent', source: `import * as http from 'node:http';\nvoid new http.Agent();` },
    { form: 'a default node:http binding new .Agent', source: `import http from 'node:http';\nvoid new http.Agent();` },
    { form: 'an import-equals node:http binding new .Agent', source: `import http = require('node:http');\nvoid new http.Agent();` },
    { form: 'an Agent.createConnection outbound chain', source: `import * as http from 'node:http';\nnew http.Agent().createConnection({ host: 'example.com', port: 80 });` },
    { form: 'a named Agent import constructed bare', source: `import { Agent } from 'node:http';\nvoid new Agent();` },
    { form: 'an aliased named Agent import constructed bare', source: `import { Agent as A } from 'node:http';\nvoid new A();` },
    { form: 'a statically-keyed Agent member on a node:http binding', source: `import * as http from 'node:http';\nvoid new http['Agent']();` },
    { form: 'a namespace node:http binding .globalAgent read', source: `import * as http from 'node:http';\nvoid http.globalAgent;` },
  ];
  for (const { form, source } of rejectHttp) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- MUST ALLOW: createServer and every unrelated member/name ---
  const allow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'http.createServer on a default binding', source: `import http from 'node:http';\nhttp.createServer(() => {});` },
    { form: 'createServer on a namespace alias', source: `import * as h from 'node:http';\nh.createServer(() => {});` },
    { form: 'a named createServer import used bare', source: `import { createServer } from 'node:http';\ncreateServer(() => {});` },
    { form: 'Map.get / map.get', source: `const m = new Map<string, number>();\nvoid m.get('k');` },
    {
      form: '.get / .request on an unrelated local object',
      source: `const api = { get(x: string) { return x; }, request(x: string) { return x; } };\nvoid api.get('a');\nvoid api.request('b');`,
    },
    {
      form: '.fetch on an ordinary local object (non-global receiver)',
      source: `const store = { fetch(x: string) { return x; } };\nvoid store.fetch('a');`,
    },
    {
      form: 'a member named request on a plain local object also named http',
      source: `const http = { request(x: string) { return x; } };\nvoid http.request('a');`,
    },
    { form: 'a local non-network function named fetch', source: `function fetch(x: string) { return x; }\nvoid fetch('a');` },
    { form: 'a local non-network const named request', source: `const request = (x: string) => x;\nvoid request('a');` },
    { form: 'a local non-network const named get', source: `const get = (x: string) => x;\nvoid get('a');` },
    { form: 'an unrelated local class named ClientRequest', source: `class ClientRequest {}\nvoid new ClientRequest();` },
    { form: 'an unrelated local const constructor named ClientRequest', source: `const LocalCtor = class {};\nconst ClientRequest = LocalCtor;\nvoid new ClientRequest();` },
    { form: 'a ClientRequest member on a plain local object (non-node:http)', source: `const LocalCtor = class {};\nconst http = { ClientRequest: LocalCtor };\nvoid new http.ClientRequest();` },
    { form: 'an unrelated local class named Agent', source: `class Agent {}\nvoid new Agent();` },
    { form: 'an Agent member on a plain local object (non-node:http)', source: `const http = { Agent: class {} };\nvoid new http.Agent();` },
    { form: 'a named Agent import shadowed by a function-local class', source: `import { Agent } from 'node:http';\nfunction f() { class Agent {} return new Agent(); }\nvoid f;` },
    { form: 'a type-only http.Agent reference alongside a real createServer', source: `import * as http from 'node:http';\nlet a: http.Agent | null = null;\nvoid a;\nhttp.createServer(() => {});` },
    { form: 'a type-only named Agent import used only in a type position', source: `import { Agent } from 'node:http';\nlet a: Agent | null = null;\nvoid a;` },
    {
      form: 'the real server.ts createServer shape (handler param named request)',
      source:
        `import http from 'node:http';\n` +
        `export function make() {\n` +
        `  return http.createServer((request: http.IncomingMessage, response: http.ServerResponse) => {\n` +
        `    const method = request.method ?? '';\n` +
        `    void method;\n` +
        `    void response;\n` +
        `  });\n` +
        `}`,
    },
  ];
  for (const { form, source } of allow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // --- FALSE-POSITIVE attack: strings / comments / regex must not fabricate egress ---
  it('does not fire on egress-looking text inside strings, comments, regex, or templates', () => {
    expect(usesOutboundNetwork(`const s = "fetch('https://x/')";\nvoid s;`)).toBe(false);
    expect(usesOutboundNetwork(`// fetch('https://x/') and http.request('http://x/')\nexport const ok = true;`)).toBe(false);
    expect(usesOutboundNetwork(`/* http.get('http://x/') */\nexport const ok = true;`)).toBe(false);
    expect(usesOutboundNetwork(`const re = /fetch\\(/;\nvoid re;`)).toBe(false);
    expect(usesOutboundNetwork(`const t = \`http.request('\${'http://x/'}')\`;\nvoid t;`)).toBe(false);
  });

  it('does not treat destructuring `fetch` off a local (non-global) object as egress', () => {
    expect(usesOutboundNetwork(`const cfg = { fetch: (x: string) => x };\nconst { fetch: f } = cfg;\nvoid f('a');`)).toBe(false);
  });

  // --- FALSE-NEGATIVE attack: the rule must not depend on the literal name `http` ---
  it('still fires when the node:http namespace binding is renamed', () => {
    expect(usesOutboundNetwork(`import * as anyName from 'node:http';\nanyName.get('http://example.com/');`)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// NET lexical-binding identity (NET-S1 / NET-S2). Capability identity is the
// binding VISIBLE at an occurrence, not identifier text: a same-named local
// (const/let/var/param/catch/destructuring, in any nested or sibling scope) shadows
// the node:http import or the global `fetch` only inside its own scope, and the
// outer binding is restored on scope exit. `usesOutboundNetwork` decides this with a
// bounded lexical environment stack over one AST traversal — see the detector's doc.
// ---------------------------------------------------------------------------
describe('D3 host network egress uses lexical binding identity, not name text (D3-CX-POLICY-NET-SHADOW)', () => {
  // NET-S1 — a local binding that shadows the node:http import is ALLOWED.
  const s1Allow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a namespace import shadowed by a function-local const', source: `import * as http from 'node:http';\nfunction f() {\n  const http = { request(v: string) { return v; } };\n  return http.request('local');\n}` },
    { form: 'a namespace import shadowed by a parameter', source: `import * as http from 'node:http';\nfunction f(http: { request(v: string): string }) {\n  return http.request('local');\n}` },
    { form: 'a named request import shadowed by a function-local const', source: `import { request } from 'node:http';\nfunction f() {\n  const request = (x: string) => x;\n  return request('local');\n}` },
    { form: 'a named request import shadowed by a parameter', source: `import { request } from 'node:http';\nfunction f(request: (x: string) => string) {\n  return request('local');\n}` },
    { form: 'a named get import shadowed by a parameter', source: `import { get } from 'node:http';\nfunction f(get: (x: string) => string) {\n  return get('local');\n}` },
    { form: 'a namespace import shadowed in a nested block, used inside that block', source: `import * as http from 'node:http';\nfunction f() {\n  {\n    const http = { request(v: string) { return v; } };\n    http.request('local');\n  }\n}` },
    { form: 'a named import shadowed by a catch binding', source: `import { get } from 'node:http';\nfunction f() {\n  try {\n    /* work */\n  } catch (get) {\n    (get as (x: string) => string)('local');\n  }\n}` },
    { form: 'a named import shadowed by a destructuring parameter', source: `import { request } from 'node:http';\nfunction f({ request }: { request: (x: string) => string }) {\n  return request('local');\n}` },
    { form: 'only the inner shadowed use (outer binding never called)', source: `import * as http from 'node:http';\nfunction local() {\n  const http = { request(v: string) { return v; } };\n  return http.request('local');\n}` },
  ];
  for (const { form, source } of s1Allow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // NET-S1 — the imported capability is still REJECTED where it is actually visible.
  const s1Reject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'the imported namespace binding after a sibling function shadows the name', source: `import * as http from 'node:http';\nfunction local() {\n  const http = { request(v: string) { return v; } };\n  http.request('local');\n}\nhttp.request('https://evil/');` },
    { form: 'the imported binding after a nested block shadows then closes', source: `import * as http from 'node:http';\nfunction f() {\n  {\n    const http = { request(v: string) { return v; } };\n    http.request('local');\n  }\n  http.request('https://evil/');\n}` },
    { form: 'a sibling function that does NOT shadow the named import', source: `import { get } from 'node:http';\nfunction outer() {\n  function inner() {\n    return get('https://evil/');\n  }\n  return inner;\n}` },
  ];
  for (const { form, source } of s1Reject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // NET-S2 — a local `fetch` shadows the global only inside its own scope.
  it('ALLOWS a function-local fetch used only within that function', () => {
    expect(usesOutboundNetwork(`function helper() {\n  const fetch = (x: string) => x;\n  return fetch('local');\n}`)).toBe(false);
  });
  it('ALLOWS a parameter-shadowed fetch used only within that function', () => {
    expect(usesOutboundNetwork(`function helper(fetch: (x: string) => string) {\n  return fetch('local');\n}`)).toBe(false);
  });
  it('ALLOWS a genuine module-level local fetch used bare across the module', () => {
    expect(usesOutboundNetwork(`const fetch = (x: string) => x;\nfetch('local');`)).toBe(false);
  });
  it('REJECTS a bare global fetch in a sibling function, despite a local fetch elsewhere', () => {
    expect(
      usesOutboundNetwork(
        `function helper() {\n  const fetch = (x: string) => x;\n  return fetch('local');\n}\nexport function leak() {\n  return fetch('https://evil.example/');\n}`,
      ),
    ).toBe(true);
  });
  it('REJECTS a bare global fetch after a parameter-shadowed scope closes', () => {
    expect(usesOutboundNetwork(`function helper(fetch: (x: string) => string) {\n  return fetch('local');\n}\nfetch('https://evil/');`)).toBe(true);
  });
  it('REJECTS globalThis.fetch even when a module-level local fetch exists', () => {
    expect(usesOutboundNetwork(`const fetch = (x: string) => x;\nvoid fetch('local');\nglobalThis.fetch('https://evil/');`)).toBe(true);
  });

  // Sibling scopes with the same binding name do not contaminate one another.
  it('keeps sibling function scopes independent (both shadow, both allowed)', () => {
    expect(usesOutboundNetwork(`import * as http from 'node:http';\nfunction a(http: { request(v: string): string }) {\n  return http.request('a');\n}\nfunction b(http: { get(v: string): string }) {\n  return http.get('b');\n}`)).toBe(false);
  });

  // NET-S3 — a GLOBAL RECEIVER name (globalThis/window/self/global) is the real global
  // only when it is FREE at the occurrence; a lexically-shadowing local makes it an
  // ordinary object. Identifier text is not binding identity for receivers either.
  const receiverAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a parameter-shadowed globalThis receiver', source: `function f(globalThis: { fetch: (v: string) => string }) {\n  return globalThis.fetch('local');\n}` },
    { form: 'a parameter-shadowed window receiver', source: `function f(window: { fetch: (v: string) => string }) {\n  return window.fetch('local');\n}` },
    { form: 'a parameter-shadowed self receiver', source: `function f(self: { fetch: (v: string) => string }) {\n  return self.fetch('local');\n}` },
    { form: 'a parameter-shadowed global receiver', source: `function f(global: { fetch: (v: string) => string }) {\n  return global.fetch('local');\n}` },
    { form: 'a block-shadowed globalThis receiver used within that block', source: `function f() {\n  {\n    const globalThis = { fetch(v: string) { return v; } };\n    globalThis.fetch('local');\n  }\n}` },
    { form: 'a destructuring of fetch off a shadowed globalThis', source: `function f(globalThis: { fetch: (v: string) => string }) {\n  const { fetch: g } = globalThis;\n  return g('local');\n}` },
  ];
  for (const { form, source } of receiverAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  const receiverReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a real globalThis.fetch receiver (unshadowed)', source: `globalThis.fetch('https://evil/');` },
    { form: 'a real window.fetch receiver (unshadowed)', source: `window.fetch('https://evil/');` },
    { form: 'a real self.fetch receiver (unshadowed)', source: `self.fetch('https://evil/');` },
    { form: 'a real globalThis.fetch after a shadowing parameter scope closes', source: `function f(globalThis: { fetch: (v: string) => string }) {\n  return globalThis.fetch('local');\n}\nglobalThis.fetch('https://evil/');` },
    { form: 'a real globalThis.fetch after a shadowing block closes', source: `function f() {\n  {\n    const globalThis = { fetch(v: string) { return v; } };\n    globalThis.fetch('local');\n  }\n  globalThis.fetch('https://evil/');\n}` },
  ];
  for (const { form, source } of receiverReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // NET-S4 — a NAMED function EXPRESSION binds its own name inside its body, shadowing
  // an outer import there, but never outside the expression.
  const fnExprAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a named function-expression request recursion shadowing the import', source: `import { request } from 'node:http';\nconst helper = function request(): unknown {\n  return request();\n};\nvoid helper;` },
    { form: 'a named function-expression matching an aliased import name', source: `import { request as req } from 'node:http';\nconst helper = function req(): unknown {\n  return req();\n};\nvoid helper;` },
    { form: 'a named function-expression get recursion shadowing the import', source: `import { get } from 'node:http';\nconst helper = function get(): unknown {\n  return get();\n};\nvoid helper;` },
    { form: 'a named function-expression fetch recursion shadowing the global', source: `const helper = function fetch(): unknown {\n  return fetch();\n};\nvoid helper;` },
  ];
  for (const { form, source } of fnExprAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  const fnExprReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'the imported request used OUTSIDE a same-named function expression', source: `import { request } from 'node:http';\nconst helper = function request(): unknown {\n  return request();\n};\nvoid helper;\nrequest('https://evil/');` },
    { form: 'the imported request in a SIBLING that does not share the fn-expr name', source: `import { request } from 'node:http';\nconst a = function request(): unknown {\n  return request();\n};\nconst b = function other(): unknown {\n  return request('https://evil/');\n};\nvoid a;\nvoid b;` },
    { form: 'the global fetch OUTSIDE a same-named function expression', source: `const helper = function fetch(): unknown {\n  return fetch();\n};\nvoid helper;\nfetch('https://evil/');` },
  ];
  for (const { form, source } of fnExprReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// NET capability-family completeness (D3-CX-POLICY-NET-CAP). The detector's outbound
// surface is closed by construction, not by an ever-growing blacklist: with the import
// allowlist blocking node:https/net/tls/dgram/http2, the only importless network route
// is a built-in network GLOBAL — `fetch` and, on the Node target, `WebSocket` — and the
// only node:http route is a NON-`createServer` value (decided by the POSITIVE model).
// These cases pin the second global, `WebSocket`, with the SAME lexical-binding identity
// used for `fetch`: a free global is rejected, a same-named local shadow is allowed.
// ---------------------------------------------------------------------------
describe('D3 host outbound-network surface is a bounded capability family (D3-CX-POLICY-NET-CAP)', () => {
  const wsReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a bare global WebSocket constructor', source: `new WebSocket('wss://example.com/');` },
    { form: 'an assigned global WebSocket', source: `const ws = new WebSocket('wss://example.com/');\nvoid ws;` },
    { form: 'a globalThis.WebSocket receiver', source: `new globalThis.WebSocket('wss://example.com/');` },
    { form: 'a window.WebSocket receiver', source: `new window.WebSocket('wss://example.com/');` },
    { form: 'a self.WebSocket receiver', source: `new self.WebSocket('wss://example.com/');` },
    { form: 'a statically-keyed globalThis["WebSocket"]', source: `new globalThis['WebSocket']('wss://example.com/');` },
    { form: 'an aliased global WebSocket acquisition (const W = WebSocket)', source: `const W = WebSocket;\nnew W('wss://example.com/');` },
    { form: 'a real global WebSocket after a shadowing scope closes', source: `function f(WebSocket: new () => unknown) {\n  return new WebSocket();\n}\nnew WebSocket('wss://example.com/');` },
  ];
  for (const { form, source } of wsReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const wsAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an unrelated local class named WebSocket', source: `class WebSocket {}\nvoid new WebSocket();` },
    { form: 'an unrelated local const constructor named WebSocket', source: `const WebSocket = class {};\nvoid new WebSocket();` },
    { form: 'a parameter-shadowed WebSocket used within that function', source: `function f(WebSocket: new () => unknown) {\n  return new WebSocket();\n}` },
    { form: 'a WebSocket member on a plain local object (non-global receiver)', source: `const rt = { WebSocket: class {} };\nvoid new rt.WebSocket();` },
    { form: 'a named function-expression WebSocket recursion shadowing the global', source: `const helper = function WebSocket(): unknown {\n  return new WebSocket();\n};\nvoid helper;` },
  ];
  for (const { form, source } of wsAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// NET capability ACQUISITION / PROPAGATION (D3-CX-POLICY-NET-ACQ). node:http is
// allow-listed, so its capability must be tracked not only through a static import
// but through the other bounded, statically-resolvable forms that acquire or
// forward that exact binding: a runtime `await import('node:http')` (F1) yields the
// same HTTP_NS identity as `import * as http`, and destructuring off an HTTP_NS
// binding (F2) preserves capability per member — `createServer` stays the one allowed
// server value, every other member is outbound. Decided by the same lexical binding
// stack (a local shadow or a non-node:http receiver is untouched); alias-via-plain-
// assignment and genuinely computed forms remain documented, bounded gaps.
// ---------------------------------------------------------------------------
describe('D3 host tracks node:http capability through dynamic import and destructuring (D3-CX-POLICY-NET-ACQ)', () => {
  // F1 — a statically-resolved `import('node:http')` acquires the namespace capability.
  const f1Reject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a dynamic-import namespace .request', source: `const http = await import('node:http');\nhttp.request('http://example.com/').end();` },
    { form: 'a dynamic-import namespace .get', source: `const http = await import('node:http');\nhttp.get('http://example.com/');` },
    { form: 'a dynamic-import namespace new .ClientRequest', source: `const http = await import('node:http');\nnew http.ClientRequest('http://example.com/');` },
    { form: 'a dynamic-import namespace new .Agent', source: `const http = await import('node:http');\nvoid new http.Agent();` },
    { form: 'a dynamic-import namespace statically-keyed member', source: `const http = await import('node:http');\nhttp['request']('http://example.com/');` },
    { form: 'a parenthesized awaited dynamic import', source: `const http = (await import('node:http'));\nhttp.get('http://example.com/');` },
  ];
  for (const { form, source } of f1Reject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const f1Allow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a dynamic-import namespace createServer', source: `const http = await import('node:http');\nhttp.createServer(() => {});` },
    { form: 'a dynamic-import http shadowed by a nested local', source: `const http = await import('node:http');\nfunction f() {\n  const http = { request(v: string) { return v; } };\n  return http.request('local');\n}\nvoid f;` },
    { form: 'an unrelated relative dynamic import', source: `const m = await import('./local.js');\nvoid m;` },
    { form: 'a node:url dynamic import used for pathToFileURL', source: `const u = await import('node:url');\nvoid u.pathToFileURL('x');` },
  ];
  for (const { form, source } of f1Allow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // F2 — destructuring a NON-createServer member off an HTTP_NS binding is outbound.
  const f2Reject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a destructured request off a namespace import', source: `import * as http from 'node:http';\nconst { request } = http;\nrequest('http://example.com/').end();` },
    { form: 'a destructured get off a namespace import', source: `import * as http from 'node:http';\nconst { get } = http;\nget('http://example.com/');` },
    { form: 'a destructured ClientRequest off a namespace import', source: `import * as http from 'node:http';\nconst { ClientRequest } = http;\nnew ClientRequest('http://example.com/');` },
    { form: 'a destructured Agent off a namespace import', source: `import * as http from 'node:http';\nconst { Agent } = http;\nvoid new Agent();` },
    { form: 'an aliased destructured request', source: `import * as http from 'node:http';\nconst { request: r } = http;\nr('http://example.com/');` },
    { form: 'a statically-computed-key destructured request', source: `import * as http from 'node:http';\nconst { ['request']: r } = http;\nr('http://example.com/');` },
    { form: 'a destructured request off a default import', source: `import http from 'node:http';\nconst { request } = http;\nrequest('http://example.com/');` },
    { form: 'a destructured request off an import-equals binding', source: `import http = require('node:http');\nconst { request } = http;\nrequest('http://example.com/');` },
    { form: 'a destructured request off a dynamic-import namespace', source: `const http = await import('node:http');\nconst { request } = http;\nrequest('http://example.com/');` },
    { form: 'a request destructured DIRECTLY off a dynamic import', source: `const { request } = await import('node:http');\nrequest('http://example.com/');` },
    { form: 'a destructured request inside a nested block', source: `import * as http from 'node:http';\nfunction f() {\n  const { request } = http;\n  return request('http://example.com/');\n}\nvoid f;` },
  ];
  for (const { form, source } of f2Reject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const f2Allow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a destructured createServer off a namespace import', source: `import * as http from 'node:http';\nconst { createServer } = http;\ncreateServer(() => {});` },
    { form: 'an aliased destructured createServer', source: `import * as http from 'node:http';\nconst { createServer: cs } = http;\ncs(() => {});` },
    { form: 'createServer destructured DIRECTLY off a dynamic import', source: `const { createServer } = await import('node:http');\ncreateServer(() => {});` },
    { form: 'a destructured request off a plain local object named http', source: `const http = { request(x: string) { return x; } };\nconst { request } = http;\nvoid request('a');` },
    { form: 'a destructured request off an unrelated local object', source: `const cfg = { request: (x: string) => x };\nconst { request } = cfg;\nvoid request('a');` },
    { form: 'a destructured capability that does not leak to a sibling scope', source: `import * as http from 'node:http';\nfunction b(request: (x: string) => string) {\n  return request('local');\n}\nvoid b;` },
  ];
  for (const { form, source } of f2Allow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // Combined: a destructured capability is rejected where visible, without tainting a
  // same-named local parameter in a sibling scope.
  it('REJECTS the destructured import use while ALLOWING a same-named sibling param', () => {
    expect(
      usesOutboundNetwork(
        `import * as http from 'node:http';\nfunction a() {\n  const { request } = http;\n  return request('http://example.com/');\n}\nfunction b(request: (x: string) => string) {\n  return request('local');\n}\nvoid a;\nvoid b;`,
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// NET namespace NON-ESCAPE (D3-CX-POLICY-NET-ESCAPE). The privileged node:http
// namespace (HTTP_NS) may appear at runtime ONLY as a createServer access, a
// destructuring that extracts createServer, or a type reference. Every other runtime
// reference — alias, argument, return, array/object element, spread, default-export —
// is a rejected ESCAPE, decided at the original occurrence (no alias/value-flow).
// An HTTP_NS member access is permitted only for a statically-proven createServer;
// an indeterminate/computed member is rejected fail-closed.
// ---------------------------------------------------------------------------
describe('D3 host forbids escape of the node:http namespace capability (D3-CX-POLICY-NET-ESCAPE)', () => {
  const escapeReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'aliasing the namespace to a const', source: `import * as http from 'node:http';\nconst h = http;\nvoid h;` },
    { form: 'passing the namespace as an argument', source: `import * as http from 'node:http';\ndeclare function foo(x: unknown): void;\nfoo(http);` },
    { form: 'returning the namespace', source: `import * as http from 'node:http';\nexport function g(): unknown { return http; }` },
    { form: 'storing the namespace in an array', source: `import * as http from 'node:http';\nconst a = [http];\nvoid a;` },
    { form: 'storing the namespace in an object property', source: `import * as http from 'node:http';\nconst o = { value: http };\nvoid o;` },
    { form: 'spreading the namespace into an object', source: `import * as http from 'node:http';\nconst o = { ...http };\nvoid o;` },
    { form: 'default-exporting the namespace', source: `import * as http from 'node:http';\nexport default http;` },
    { form: 'aliasing a dynamic-import namespace', source: `const http = await import('node:http');\nconst h = http;\nvoid h;` },
    { form: 'an indeterminate computed member on the namespace', source: `import * as http from 'node:http';\ndeclare const k: string;\nvoid http[k];` },
    { form: 'a runtime-conditional computed member on the namespace', source: `import * as http from 'node:http';\nconst k = Math.random() > 0.5 ? 'createServer' : 'request';\nvoid http[k];` },
  ];
  for (const { form, source } of escapeReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const escapeAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a createServer access on the namespace', source: `import * as http from 'node:http';\nhttp.createServer(() => {});` },
    { form: 'a statically-keyed createServer access', source: `import * as http from 'node:http';\nhttp['createServer'](() => {});` },
    { form: 'extracting createServer to a const via access', source: `import * as http from 'node:http';\nconst cs = http.createServer;\ncs(() => {});` },
    { form: 'a createServer destructuring', source: `import * as http from 'node:http';\nconst { createServer } = http;\ncreateServer(() => {});` },
    { form: 'a type reference to the namespace member', source: `import * as http from 'node:http';\nexport type S = http.Server;\nhttp.createServer(() => {});` },
    { form: 'a typeof type query of the namespace', source: `import * as http from 'node:http';\nexport type T = typeof http;\nhttp.createServer(() => {});` },
    { form: 'a runtime typeof of the namespace', source: `import * as http from 'node:http';\nconst t = typeof http;\nvoid t;\nhttp.createServer(() => {});` },
  ];
  for (const { form, source } of escapeAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// NET module-boundary export confinement (D3-CX-POLICY-NET-EXPORT). The privileged
// node:http capability may not cross the D3 module boundary: no re-export from
// node:http and no export of a local HTTP_NS binding (createServer included). Ordinary
// local exports and type-only exports are untouched. `exportsHttpCapability` inspects
// only THIS module's statements and local binding identity (no cross-module data-flow).
// ---------------------------------------------------------------------------
describe('D3 host may not export node:http capability across the module boundary (D3-CX-POLICY-NET-EXPORT)', () => {
  it('accepts every real host source (no host source exports node:http capability)', () => {
    for (const { file, text } of hostSources()) {
      const sf = ts.createSourceFile('module.ts', text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf), `${file} exports node:http capability`).toBe(false);
    }
  });

  const exportReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a star re-export from node:http', source: `export * from 'node:http';` },
    { form: 'a named re-export from node:http', source: `export { request } from 'node:http';` },
    { form: 'a createServer re-export from node:http', source: `export { createServer } from 'node:http';` },
    { form: 'a default-aliased re-export from node:http', source: `export { default as http } from 'node:http';` },
    { form: 'exporting a namespace import binding', source: `import * as http from 'node:http';\nexport { http };` },
    { form: 'exporting an aliased namespace binding', source: `import * as http from 'node:http';\nexport { http as h };` },
    { form: 'default-exporting a namespace binding', source: `import * as http from 'node:http';\nexport default http;` },
    { form: 'exporting a dynamic-import namespace binding', source: `const http = await import('node:http');\nexport { http };` },
    { form: 'export-equals of a namespace binding', source: `import http = require('node:http');\nexport = http;` },
  ];
  for (const { form, source } of exportReject) {
    it(`REJECTS ${form}`, () => {
      const sf = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf)).toBe(true);
    });
  }

  const exportAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an ordinary const export', source: `export const HOST = '127.0.0.1';` },
    { form: 'an ordinary function export that uses createServer internally', source: `import http from 'node:http';\nexport function make() { return http.createServer(() => {}); }` },
    { form: 'exporting a created server instance', source: `import http from 'node:http';\nexport const server = http.createServer(() => {});` },
    { form: 'a relative re-export', source: `export { foo } from './local.js';` },
    { form: 'a type-only export of a namespace member type', source: `import * as http from 'node:http';\nexport type S = http.Server;` },
  ];
  for (const { form, source } of exportAllow) {
    it(`ALLOWS ${form}`, () => {
      const sf = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf)).toBe(false);
    });
  }
});
