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

// A global-object SELF-REFERENCE hop: the member NAME read off a receiver when that
// receiver is a member access whose key is a statically present string
// (`globalThis.globalThis`, `window['window']`). The real global exposes itself under
// every GLOBAL_RECEIVER_NAMES key (`globalThis.globalThis === globalThis`,
// `globalThis.window === globalThis`, …), so a chain of such hops off a global base still
// denotes the real global. Returns the hop name or null; it NEVER folds a runtime-built
// key (no alias/value-flow), so a truly computed key stays outside the frozen boundary.
const selfReferenceHopName = (
  node: ts.PropertyAccessExpression | ts.ElementAccessExpression,
): string | null => {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  return ts.isStringLiteralLike(node.argumentExpression) ? node.argumentExpression.text : null;
};

// A structural global receiver: a bare global-object identifier, OR a self-reference member
// (name in GLOBAL_RECEIVER_NAMES) read off another structural global receiver — so
// `globalThis.globalThis`, `globalThis.window`, `window.window` are all recognized. Finite:
// each recursion strips one member-access layer off `node.expression`.
const isGlobalReceiver = (node: ts.Expression): boolean => {
  const n = unwrapExpr(node);
  if (ts.isIdentifier(n)) return GLOBAL_RECEIVER_NAMES.has(n.text);
  if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
    const hop = selfReferenceHopName(n);
    return hop !== null && GLOBAL_RECEIVER_NAMES.has(hop) && isGlobalReceiver(n.expression);
  }
  return false;
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

// Totality ceiling for `+`-fold resolution (TOTALITY). The longest name any consumer of
// this resolver compares against is `prependOnceListener` (19) / `getBuiltinModule` (16),
// so a fold longer than this can never be a matched capability/socket/reserved name. Capping
// the fold length keeps the resolver total: an adversarial exponentially-growing `+`-chain
// (`a1 = a0 + a0; a2 = a1 + a1; …`) resolves to UNKNOWN instead of exhausting string memory,
// exactly as the NET binder resolver already aborts such chains. No genuine name (all ≤ 19)
// is suppressed. Ascending source order + memoization keep recursion depth O(1) per name, so
// depth is already bounded; this bounds output SIZE, the only remaining growth axis.
const MAX_STATIC_FOLD_LEN = 64;

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
      // TOTALITY: never build a fold longer than any name this resolver is compared against.
      if (left.length + right.length > MAX_STATIC_FOLD_LEN) return null;
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

// A node:http runtime authority capability. `HTTP_NS` is the namespace; `HTTP_CLIENT`
// any non-createServer node:http value; `CREATE_SERVER` the one permitted capability.
type HttpCapability = 'HTTP_NS' | 'HTTP_CLIENT' | 'CREATE_SERVER' | 'NONE';

// Build a bounded, in-memory, single-file Program so the compiler BINDER supplies
// lexical binding identity (Option D). `noLib`+`noResolve`: no filesystem, no module
// resolution, no network, deterministic. The only file served is the analyzed source;
// node:http is never loaded — we read the import declaration's specifier TEXT, never its
// types — so binding identity, not module contents, is all this guard depends on.
const buildBinderProgram = (source: string): { readonly checker: ts.TypeChecker; readonly sourceFile: ts.SourceFile } => {
  const fileName = 'module.ts';
  const parsed = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const host: ts.CompilerHost = {
    getSourceFile: (name) => (name === fileName ? parsed : undefined),
    getDefaultLibFileName: () => 'lib.d.ts',
    writeFile: () => undefined,
    getCurrentDirectory: () => '/',
    getDirectories: () => [],
    getCanonicalFileName: (f) => f,
    useCaseSensitiveFileNames: () => true,
    getNewLine: () => '\n',
    fileExists: (f) => f === fileName,
    readFile: (f) => (f === fileName ? source : undefined),
  };
  const program = ts.createProgram(
    [fileName],
    { noLib: true, noResolve: true, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.Latest },
    host,
  );
  const bound = program.getSourceFile(fileName);
  return { checker: program.getTypeChecker(), sourceFile: bound ?? parsed };
};

const binderUnwrap = (node: ts.Expression): ts.Expression => {
  let cur: ts.Expression = node;
  while (
    ts.isParenthesizedExpression(cur) ||
    ts.isAsExpression(cur) ||
    ts.isSatisfiesExpression(cur) ||
    ts.isNonNullExpression(cur) ||
    ts.isTypeAssertionExpression(cur) ||
    ts.isAwaitExpression(cur)
  ) {
    cur = cur.expression;
  }
  return cur;
};

const binderMemberName = (node: ts.PropertyAccessExpression | ts.ElementAccessExpression): string | null => {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  const arg = node.argumentExpression;
  return ts.isStringLiteralLike(arg) ? arg.text : null;
};

// The specifier text of the import a declaration belongs to (or null when not an import).
const declarationImportSpecifier = (decl: ts.Declaration): string | null => {
  let p: ts.Node | undefined = decl;
  while (p !== undefined) {
    if (ts.isImportDeclaration(p)) return ts.isStringLiteral(p.moduleSpecifier) ? p.moduleSpecifier.text : null;
    if (ts.isImportEqualsDeclaration(p)) {
      const ref = p.moduleReference;
      return ts.isExternalModuleReference(ref) && ts.isStringLiteral(ref.expression) ? ref.expression.text : null;
    }
    p = p.parent as ts.Node | undefined;
  }
  return null;
};

// Whether a symbol is DIRECTLY a static node:http namespace binding (`import * as http`
// / `import http` / `import http = require('node:http')`). One-hop, non-recursive — the
// only acquisition relation `HTTP_CLIENT` destructuring is allowed to consult.
const isDirectNodeHttpNamespace = (symbol: ts.Symbol | undefined): boolean => {
  if (symbol === undefined || symbol.declarations === undefined) return false;
  return symbol.declarations.some(
    (d) =>
      (ts.isNamespaceImport(d) || (ts.isImportClause(d) && d.name !== undefined) || ts.isImportEqualsDeclaration(d)) &&
      declarationImportSpecifier(d) === 'node:http',
  );
};

// The static property KEY an object-binding element reads from its receiver: an explicit
// `propertyName` (identifier / string-literal / static computed string-literal), or, for the
// shorthand `{ name }`, the bound identifier itself. Null when the key is not statically
// identifiable — fail-closed as HTTP_CLIENT off an HTTP_NS receiver, exactly as the original
// single-hop rule did.
const bindingElementKey = (el: ts.BindingElement): string | null => {
  const key = el.propertyName;
  if (key === undefined) return ts.isIdentifier(el.name) ? el.name.text : null;
  if (ts.isIdentifier(key) || ts.isStringLiteralLike(key)) return key.text;
  if (ts.isComputedPropertyName(key) && ts.isStringLiteralLike(key.expression)) return key.expression.text;
  return null;
};

// The node:http capability a member named `key` yields off a receiver of capability `recv`,
// mirroring member-access semantics (`classifyHttpExpression`): off the namespace,
// `createServer` is the one permitted server value and every other member (a non-static key
// included) is an outbound HTTP_CLIENT; off an HTTP_CLIENT value every member stays
// HTTP_CLIENT; nothing else propagates. No new capability kind, no member blacklist.
const httpMemberCapability = (recv: HttpCapability, key: string | null): HttpCapability => {
  if (recv === 'HTTP_NS') return key !== null && HTTP_SERVER_VALUE_MEMBERS.has(key) ? 'CREATE_SERVER' : 'HTTP_CLIENT';
  if (recv === 'HTTP_CLIENT') return 'HTTP_CLIENT';
  return 'NONE';
};

// The capability a single OBJECT-destructuring binding element acquires, propagated
// RECURSIVELY through nested object binding patterns from the enclosing variable
// declaration's initializer (still the sole acquisition root, resolved ONE hop to the
// node:http namespace — no alias chains, no value-flow). A top-level element
// `{ request } = http` reduces to the original single-hop rule; a nested
// `{ globalAgent: { createConnection } } = http` propagates HTTP_NS → HTTP_CLIENT →
// HTTP_CLIENT structurally down the pattern until this element's bound name is reached.
// Only object patterns carry named members; an array binding pattern or a non-namespace
// initializer does not propagate. Finite: one step per binding-pattern nesting level.
const bindingElementHttpCapability = (el: ts.BindingElement, checker: ts.TypeChecker): HttpCapability => {
  const pattern = el.parent;
  if (!ts.isObjectBindingPattern(pattern)) return 'NONE';
  const container = pattern.parent;
  let receiver: HttpCapability;
  if (ts.isVariableDeclaration(container)) {
    const initializer = container.initializer;
    if (initializer === undefined) return 'NONE';
    const rhs = binderUnwrap(initializer);
    receiver = ts.isIdentifier(rhs) && isDirectNodeHttpNamespace(checker.getSymbolAtLocation(rhs)) ? 'HTTP_NS' : 'NONE';
  } else if (ts.isBindingElement(container)) {
    receiver = bindingElementHttpCapability(container, checker);
  } else {
    return 'NONE';
  }
  if (receiver === 'NONE') return 'NONE';
  return httpMemberCapability(receiver, bindingElementKey(el));
};

// Classify a single DECLARATION. Bounded: a node:http import, or a destructuring whose
// initializer DIRECTLY resolves to the node:http namespace (one hop, no alias chains),
// propagated through nested object binding patterns to the bound name.
const classifyHttpDeclaration = (decl: ts.Declaration, checker: ts.TypeChecker): HttpCapability => {
  if (ts.isNamespaceImport(decl)) return declarationImportSpecifier(decl) === 'node:http' ? 'HTTP_NS' : 'NONE';
  if (ts.isImportClause(decl) && decl.name !== undefined) {
    return declarationImportSpecifier(decl) === 'node:http' ? 'HTTP_NS' : 'NONE';
  }
  if (ts.isImportEqualsDeclaration(decl)) return declarationImportSpecifier(decl) === 'node:http' ? 'HTTP_NS' : 'NONE';
  if (ts.isImportSpecifier(decl)) {
    if (declarationImportSpecifier(decl) !== 'node:http') return 'NONE';
    const imported = (decl.propertyName ?? decl.name).text;
    return HTTP_SERVER_VALUE_MEMBERS.has(imported) ? 'CREATE_SERVER' : 'HTTP_CLIENT';
  }
  if (ts.isBindingElement(decl) && ts.isObjectBindingPattern(decl.parent)) {
    return bindingElementHttpCapability(decl, checker);
  }
  return 'NONE';
};

// Classify a SYMBOL by its declaration(s) — the compiler binder resolved the symbol, so
// this is nearest-visible-binding identity (shadowing/restoration/scope all included).
const classifyHttpSymbol = (symbol: ts.Symbol | undefined, checker: ts.TypeChecker): HttpCapability => {
  if (symbol === undefined || symbol.declarations === undefined) return 'NONE';
  for (const decl of symbol.declarations) {
    const cap = classifyHttpDeclaration(decl, checker);
    if (cap !== 'NONE') return cap;
  }
  return 'NONE';
};

// Classify an EXPRESSION directly: an identifier (via its symbol) or a member access off
// an HTTP_NS receiver (createServer vs other). Bounded by member-access nesting (finite);
// no binding-element recursion, so no cycles.
const classifyHttpExpression = (expr: ts.Expression, checker: ts.TypeChecker): HttpCapability => {
  const e = binderUnwrap(expr);
  if (ts.isIdentifier(e)) return classifyHttpSymbol(checker.getSymbolAtLocation(e), checker);
  if (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e)) {
    if (classifyHttpExpression(e.expression, checker) === 'HTTP_NS') {
      const m = binderMemberName(e);
      return m !== null && HTTP_SERVER_VALUE_MEMBERS.has(m) ? 'CREATE_SERVER' : 'HTTP_CLIENT';
    }
  }
  return 'NONE';
};

// Whether an identifier is a value read (not a declaration/type/member/key position).
const isBinderValueReference = (id: ts.Identifier): boolean => {
  const p = id.parent as ts.Node | undefined;
  if (p === undefined) return true;
  if (ts.isQualifiedName(p) && p.right === id) return false;
  if (ts.isTypeReferenceNode(p)) return false;
  if (ts.isPropertyAccessExpression(p) && p.name === id) return false;
  if (ts.isBindingElement(p) && (p.name === id || p.propertyName === id)) return false;
  if (ts.isVariableDeclaration(p) && p.name === id) return false;
  if (ts.isParameter(p) && p.name === id) return false;
  if (ts.isPropertyAssignment(p) && p.name === id) return false;
  if (
    (ts.isFunctionDeclaration(p) || ts.isFunctionExpression(p) || ts.isClassDeclaration(p) || ts.isMethodDeclaration(p)) &&
    p.name === id
  ) {
    return false;
  }
  if (ts.isImportSpecifier(p) || ts.isNamespaceImport(p) || ts.isImportClause(p) || ts.isExportSpecifier(p)) return false;
  return true;
};

// The permitted positions for an HTTP_NS occurrence (else it is a forbidden escape): a
// member-access receiver, an object-binding-pattern destructuring initializer, or a
// type/non-runtime position (through paren/as/await wrappers).
const isHttpNsSafePosition = (node: ts.Node): boolean => {
  let cur: ts.Node = node;
  for (;;) {
    const parent = cur.parent as ts.Node | undefined;
    if (
      parent !== undefined &&
      (ts.isParenthesizedExpression(parent) ||
        ts.isAsExpression(parent) ||
        ts.isSatisfiesExpression(parent) ||
        ts.isNonNullExpression(parent) ||
        ts.isAwaitExpression(parent))
    ) {
      cur = parent;
      continue;
    }
    break;
  }
  const p = cur.parent as ts.Node | undefined;
  if (p === undefined) return false;
  if ((ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) && p.expression === cur) return true;
  if (ts.isVariableDeclaration(p) && ts.isObjectBindingPattern(p.name) && p.initializer === cur) return true;
  if (
    ts.isTypeQueryNode(p) ||
    ts.isTypeReferenceNode(p) ||
    ts.isQualifiedName(p) ||
    ts.isTypeOfExpression(p) ||
    ts.isImportTypeNode(p)
  ) {
    return true;
  }
  return false;
};

// DDR-CREATE-SERVER-ALIAS-POLICY (Option A — positive-model restriction). The one permitted
// node:http value capability, `createServer`, may itself REMAIN only in the smallest approved
// direct-call forms: as the callee of a call (`http.createServer(...)`, `createServer(...)`,
// `mk(...)`), or in a type / non-runtime position. Every other position — a variable/const
// initializer, an assignment right-hand side, a call ARGUMENT, a return, an array/object
// element or spread value — FORWARDS or STORES the constructor capability itself and is a
// forbidden escape, decided at THIS occurrence (the same shape as `isHttpNsSafePosition`; no
// alias/value-flow tracking — a receiving binding such as `start`/`cs` is never classified).
// The returned Server object is a SEPARATE value (capability NONE), so the CALL RESULT
// (`const server = http.createServer(...)`) sits in none of these positions and is untouched.
// Unwraps only the same finite transparent wrappers (paren / as / satisfies / non-null / await).
const isCreateServerSafePosition = (node: ts.Node): boolean => {
  let cur: ts.Node = node;
  for (;;) {
    const parent = cur.parent as ts.Node | undefined;
    if (
      parent !== undefined &&
      (ts.isParenthesizedExpression(parent) ||
        ts.isAsExpression(parent) ||
        ts.isSatisfiesExpression(parent) ||
        ts.isNonNullExpression(parent) ||
        ts.isAwaitExpression(parent))
    ) {
      cur = parent;
      continue;
    }
    break;
  }
  const p = cur.parent as ts.Node | undefined;
  if (p === undefined) return false;
  if ((ts.isCallExpression(p) || ts.isNewExpression(p)) && p.expression === cur) return true;
  if (
    ts.isTypeQueryNode(p) ||
    ts.isTypeReferenceNode(p) ||
    ts.isQualifiedName(p) ||
    ts.isTypeOfExpression(p) ||
    ts.isImportTypeNode(p)
  ) {
    return true;
  }
  return false;
};

// A declaration EMITS a runtime value binding — and so can shadow a runtime global — only
// when it is neither ambient (`declare …`, which emits nothing) nor a type-only form
// (interface / type alias / type-only import). This is the minimal runtime-emission
// distinction, read from the AST and modifier flags rather than restored as a
// declaration-kind whitelist: it separates a real local shadow (`const fetch = …`,
// `function fetch`, `class`, `enum`, a value namespace, `import x = require(...)`, a runtime
// import binding) from a declaration-only binding (`declare const fetch`, a type-only import)
// that leaves the runtime global reachable at the call site.
// Whether a node sits in an ambient (`declare …`) context — itself or any enclosing
// declaration carries the `declare` modifier (covers `declare const`, `declare function`,
// and a binding nested in `declare global` / `declare namespace`). Public API only.
const isInAmbientContext = (node: ts.Node): boolean => {
  let n: ts.Node | undefined = node;
  while (n !== undefined) {
    if (ts.canHaveModifiers(n)) {
      const mods = ts.getModifiers(n);
      if (mods !== undefined && mods.some((m) => m.kind === ts.SyntaxKind.DeclareKeyword)) return true;
    }
    n = n.parent as ts.Node | undefined;
  }
  return false;
};

// Whether an import binding is type-only — the whole clause (`import type { fetch }`, whose
// clause carries the `type` phase modifier) or the inline specifier form (`import { type fetch }`).
const isTypeOnlyImportClause = (clause: ts.ImportClause): boolean => clause.phaseModifier === ts.SyntaxKind.TypeKeyword;

const declarationEmitsRuntimeValue = (d: ts.Declaration): boolean => {
  if (ts.isInterfaceDeclaration(d) || ts.isTypeAliasDeclaration(d)) return false;
  if (isInAmbientContext(d)) return false;
  if (ts.isImportClause(d) && isTypeOnlyImportClause(d)) return false;
  if (ts.isImportSpecifier(d)) {
    if (d.isTypeOnly) return false;
    const clause = d.parent.parent as ts.Node | undefined;
    if (clause !== undefined && ts.isImportClause(clause) && isTypeOnlyImportClause(clause)) return false;
  }
  return true;
};

// Whether the binder-resolved symbol has, in the analyzed file, at least one declaration that
// emits a runtime value — i.e. a genuine RUNTIME shadow of a same-named global. A symbol whose
// only in-file declarations are ambient/type-only is NOT a runtime shadow.
const hasLocalRuntimeShadow = (symbol: ts.Symbol, sourceFile: ts.SourceFile): boolean =>
  symbol.declarations !== undefined &&
  symbol.declarations.some((d) => d.getSourceFile() === sourceFile && declarationEmitsRuntimeValue(d));

// A receiver is the REAL global (globalThis/window/self/global) only when the binder resolves
// it to NO local RUNTIME binding in this file (an intrinsic globalThis has a symbol but no
// local declaration; a param/const shadow does). Identifier text is not identity.
//
// Local runtime-shadow rule (no declaration-kind whitelist): the receiver is free/global only
// when its resolved symbol carries no in-file declaration that EMITS A RUNTIME VALUE. Any
// genuine runtime binding of the name — const/let/var, parameter, binding element, function,
// class, enum, a namespace with a runtime value, import-equals, a runtime import — is a shadow,
// so the receiver is an ordinary object. Two kinds of declaration are correctly NOT shadows:
// a type-only name (`interface global` / `type global`) does not even resolve at a value
// position (the binder returns no value symbol), and an ambient `declare const global` resolves
// but emits nothing at runtime, so the real global is still reached — both leave the receiver
// free. Restoration/nesting/sibling scope are the binder's job as before.
const isFreeGlobalReceiver = (expr: ts.Expression, checker: ts.TypeChecker, sourceFile: ts.SourceFile): boolean => {
  const recv = binderUnwrap(expr);
  if (ts.isIdentifier(recv)) {
    if (!GLOBAL_RECEIVER_NAMES.has(recv.text)) return false;
    const symbol = checker.getSymbolAtLocation(recv);
    if (symbol === undefined) return true;
    return !hasLocalRuntimeShadow(symbol, sourceFile);
  }
  // Global-object self-reference hop (`globalThis.globalThis`, `window.window`, …): the member
  // name is a global-receiver name and its own receiver is (recursively) a free global. Binder/
  // shadowing authority stays at the BASE identifier above — a shadowed base
  // (`function f(globalThis){ globalThis.globalThis.fetch() }`) demotes the whole chain to an
  // ordinary object. DDR-NET-STATIC-KEY-PARITY (F1): the ELEMENT-access hop key is folded by the
  // bounded binder resolver (`netHopName`), so `globalThis['global' + 'This']`,
  // `const k = 'globalThis'; globalThis[k]`, and `` globalThis[`glob` + 'alThis'] `` are recognized
  // hops, while a genuinely runtime key resolves to null and is NOT a hop. Finite: recursion
  // descends `recv.expression`.
  if (ts.isPropertyAccessExpression(recv) || ts.isElementAccessExpression(recv)) {
    const hop = ts.isPropertyAccessExpression(recv) ? recv.name.text : netHopName(recv.argumentExpression, checker);
    return hop !== null && GLOBAL_RECEIVER_NAMES.has(hop) && isFreeGlobalReceiver(recv.expression, checker, sourceFile);
  }
  return false;
};

// Whether a call is a runtime dynamic `import('node:http')` (Option B: prohibited outright).
const isDynamicNodeHttpImport = (node: ts.Node): boolean => {
  if (!ts.isCallExpression(node) || node.expression.kind !== ts.SyntaxKind.ImportKeyword) return false;
  const specifier = node.arguments[0];
  return specifier !== undefined && ts.isStringLiteralLike(specifier) && specifier.text === 'node:http';
};

// SOCK — reject acquisition of the inbound SERVER SOCKET capability (D3-CX-POLICY-NET-SOCK).
// The permitted `createServer` path yields a listening server whose request/response objects
// and connection-family events expose the underlying duplex socket — a transitive OUTBOUND
// capability (`req.socket.connect(...)`) the createServer allowance is not meant to grant.
// This is the FINAL BOUNDED D3 source policy (commander decision, frozen): the strongest
// finite policy that stays compatible with the actual host. It is NOT a taint/alias/type/
// whole-program engine and does NOT claim literal no-egress. It is ONE global static-name
// rule (RULE A over a socket-acquisition name FAMILY) plus its req/res computed refinement
// (RULE A2), both receiver- and position-independent:
//
//   RULE A — GLOBAL static socket-ACQUISITION NAME ban, regardless of receiver identity and
//     regardless of call/read position. Two name families are rejected wherever a statically
//     identifiable property/binding KEY names them:
//       (i)  the SOCKET-VALUE names `socket`/`connection` — the duplex socket itself; and
//       (ii) the SOCKET-DELIVERY member names `on`/`once`/`addListener`/`prependListener`/
//            `prependOnceListener`/`setTimeout` — the permitted http.Server callbacks that
//            hand a socket to a handler (`connection`/`request`/`upgrade`/`connect`/
//            `clientError`/`dropRequest`/`timeout`, plus `setTimeout`'s one-shot timeout
//            socket), covered with NO event-name list.
//     The ban fires on every statically identifiable form: dotted `x.on` (optional chaining
//     included), static-computed `x['on']`/`` x[`socket`] ``, and object-destructuring
//     `{ socket }` / `{ on: h }` in any binding pattern (variable, parameter, nested,
//     callback). Because it anchors on the member NAME at ANY position — not on a call
//     callee — it closes the indirect-registrar family uniformly: `server.on(...)`,
//     `server.on.call/apply/bind(...)`, `Reflect.apply(server.on, …)`, `const m = server.on`
//     (F2), and `server.setTimeout(t, socket => …)` (F1) all contain the banned name as a
//     property access and are rejected at acquisition, with no witness-specific
//     `.call`/`.apply`/`.bind` blacklist. Receiver identity is deliberately irrelevant — an
//     unrelated `camera.socket`, `emitter.on('ready', …)`, or `obj.setTimeout(…)` is an
//     accepted, intentional policy false positive; real host/cockpit source uses none of
//     these names (it calls only `http.createServer` and `server.listen`).
//
//   RULE A2 — for the request/response PARAMETERS of a function literal passed DIRECTLY to a
//     permitted static `createServer` call (binder identity — these are the sole direct
//     entry of IncomingMessage/ServerResponse into user code), an element access whose key
//     is not a static string FAILS CLOSED (`req[key]`, `req['sock'+'et']`, `req[c?…:…]`).
//     This closes computed recovery on the direct handler param without touching legitimate
//     host indexing elsewhere (`array[index]`, `text[character]`, `object[key]` are NOT on a
//     createServer handler param, so they are unaffected). No const-folding is used. A2's
//     socket/connection semantics are preserved byte-for-byte by the RULE A name-family
//     promotion above (A2 keeps consulting `SOCKET_CAPABILITY_NAMES`, not the wider family).
//
// HONEST BOUNDARY (frozen, not a defect): a socket-delivering member acquired WITHOUT its
// name ever appearing statically — a cross-function alias combined with a runtime-computed
// key, `const r = request; r[runtimeKey]` where `runtimeKey` becomes `'socket'` at runtime
// (or a registrar/`setTimeout` reached as `server[k]` with runtime `k`) — is NOT closed;
// closing it would require alias propagation / type resolution / whole-program flow,
// deliberately excluded here. It belongs to a future runtime-isolation enforcement boundary,
// not this source policy.
// The SOCKET-VALUE names (RULE A family i) — the duplex socket itself. Still used verbatim by
// the RULE A2 req/res-bound branches below, whose socket/connection semantics are preserved.
const SOCKET_CAPABILITY_NAMES: ReadonlySet<string> = new Set(['socket', 'connection']);
// The SOCKET-DELIVERY member names (RULE A family ii) — the permitted http.Server callbacks
// that hand a socket to a handler. `setTimeout` (the one-shot 'timeout' socket — F1) sits
// beside the five event registrars; the whole family is banned by NAME at any position (F2),
// never by call shape, so `.call`/`.apply`/`.bind`/`Reflect.apply`/`const m = server.on`
// cannot launder it, and there is NO event-name list to maintain.
const SOCKET_DELIVERY_MEMBERS: ReadonlySet<string> = new Set([
  'on',
  'once',
  'addListener',
  'prependListener',
  'prependOnceListener',
  'setTimeout',
]);
// The full RULE A static name family (i ∪ ii), tested at every statically identifiable
// property/binding-key position (dotted, static-computed, destructured), receiver-independent.
const STATIC_SOCKET_ACQUISITION_NAMES: ReadonlySet<string> = new Set([
  ...SOCKET_CAPABILITY_NAMES,
  ...SOCKET_DELIVERY_MEMBERS,
]);

// The static key named by an element-access argument or a binding-element key, or null.
const staticKeyText = (key: ts.Node | undefined): string | null => {
  if (key === undefined) return null;
  if (ts.isIdentifier(key)) return key.text;
  if (ts.isStringLiteralLike(key)) return key.text;
  if (ts.isComputedPropertyName(key) && ts.isStringLiteralLike(key.expression)) return key.expression.text;
  return null;
};

const acquiresInboundServerSocket = (checker: ts.TypeChecker, sourceFile: ts.SourceFile): boolean => {
  const isCreateServerCall = (node: ts.Node): boolean =>
    ts.isCallExpression(node) && classifyHttpExpression(node.expression, checker) === 'CREATE_SERVER';

  // DDR-NET-STATIC-KEY-PARITY (SOCK): socket acquisition keys are resolved by TypeScript BINDER
  // identity via the shared bounded `netResolveKey` (see `sockResolveKey`) — the SAME resolver NET's
  // member/hop/destructuring keys use — never by the whole-file text-keyed `collectStringConsts`/
  // `staticStringOf`. A Resolved socket-acquisition NAME is rejected on any receiver
  // (`server['o' + 'n']`, `const k = 'on'; server[k]`), and a shadowing same-text `const` in an
  // unrelated scope can no longer make a binder-pinned key unresolved (the scope-insensitive
  // fail-open). An Indeterminate (genuinely runtime / resource-abort) key stays outside the proof,
  // except on a createServer req/res param where RULE A2 fails closed. One declaration-keyed memo,
  // fresh per traversal and scoped to the socket ceiling, is shared by every SOCK key resolution so a
  // const chain reused across many accesses is resolved once (bounded work); per-key `seen`/`budget`
  // stay local (cycle detection + the per-key hop ceiling).
  const sockMemo = new Map<ts.Declaration, NetKey>();

  // Pass 1 (RULE A2 support) — collect the createServer request/response parameter symbols.
  // Direct identifier params only; a destructured param `({ socket })` is a RULE A binding
  // pattern, rejected in pass 2 like any other.
  const reqResSymbols = new Set<ts.Symbol>();
  const collect = (node: ts.Node): void => {
    if (isCreateServerCall(node)) {
      for (const arg of (node as ts.CallExpression).arguments) {
        const handler = binderUnwrap(arg);
        if (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler)) {
          for (const param of handler.parameters) {
            if (ts.isIdentifier(param.name)) {
              const symbol = checker.getSymbolAtLocation(param.name);
              if (symbol !== undefined) reqResSymbols.add(symbol);
            }
          }
        }
      }
    }
    ts.forEachChild(node, collect);
  };
  ts.forEachChild(sourceFile, collect);

  const receiverIsReqRes = (expr: ts.Expression): boolean => {
    const e = binderUnwrap(expr);
    if (!ts.isIdentifier(e)) return false;
    const symbol = checker.getSymbolAtLocation(e);
    return symbol !== undefined && reqResSymbols.has(symbol);
  };

  let found = false;
  // RULE A (c, assignment parity — DELIVERY/REGISTRAR members ONLY) — the assignment-AST twin of the
  //     RULE A (c) per-binding-element key check, walked over the finite ObjectLiteralExpression
  //     destructuring TARGET of an `=`, but DELIBERATELY SCOPED to the receiver-independent
  //     delivery/registrar-member family (`SOCKET_DELIVERY_MEMBERS`: on/once/addListener/
  //     prependListener/prependOnceListener/setTimeout), NOT the full `STATIC_SOCKET_ACQUISITION_NAMES`
  //     set. `({ on: register } = server)` extracts the registrar exactly like `const { on: register }
  //     = server`, but its target is an ObjectLiteralExpression (Shorthand/PropertyAssignment), not a
  //     BindingElement, so RULE A (c) never saw it. Each target KEY is resolved by the SAME
  //     binder-aware machinery A (c) uses — a plain/quoted key is its own text (`staticKeyText`), a
  //     computed key (`{ ['o'+'n']: … }`, `{ [k]: … }`) folds off the binder (`sockResolveKey`) — and a
  //     RESOLVED delivery/registrar name REJECTS receiver-independently (the `.on` / `const { on }`
  //     registrar bans are already receiver-independent, so no server identity is tracked). The
  //     socket/connection CAPABILITY names are intentionally EXCLUDED here: their assignment-extraction
  //     policy stays the receiver-sensitive req/res-bound RULE A2 assignment branch below (the accepted
  //     D3-CX-CODEX-ASSIGN "no global broadening" invariant — `({ socket } = unrelatedObject)` and
  //     `({ socket } = server)` remain allowed). Recurses ONLY into a nested ObjectLiteralExpression
  //     VALUE — the assignment twin of a nested binding pattern (`({ a: { on } } = x)`) — terminating at
  //     the finite AST depth with NO value flow, alias following, or receiver tracking. An INDETERMINATE
  //     computed key is NOT globally failed closed here (only a Resolved delivery name rejects); the
  //     req/res A2 branch below retains its own fail-closed behavior.
  const scanSocketAssignmentTarget = (target: ts.ObjectLiteralExpression): void => {
    for (const prop of target.properties) {
      if (ts.isShorthandPropertyAssignment(prop)) {
        if (SOCKET_DELIVERY_MEMBERS.has(prop.name.text)) found = true;
      } else if (ts.isPropertyAssignment(prop)) {
        let name: string | null = null;
        if (ts.isComputedPropertyName(prop.name)) {
          const key = sockResolveKey(prop.name.expression, checker, sockMemo);
          if (key.kind === 'resolved') name = key.value;
        } else {
          name = staticKeyText(prop.name);
        }
        if (name !== null && SOCKET_DELIVERY_MEMBERS.has(name)) found = true;
        const value = binderUnwrap(prop.initializer);
        if (ts.isObjectLiteralExpression(value)) scanSocketAssignmentTarget(value);
      }
    }
  };
  const visit = (node: ts.Node): void => {
    // RULE A (a) — GLOBAL dotted socket-acquisition NAME: `.socket`/`.connection` or a delivery
    //     member `.on`/`.once`/`.addListener`/`.prependListener`/`.prependOnceListener`/
    //     `.setTimeout` (optional chaining included), any receiver, any position. This is the node
    //     that closes the indirect-registrar family (F2): the inner `server.on` inside
    //     `server.on.call(...)` / `server.on.apply(...)` / `server.on.bind(...)` /
    //     `Reflect.apply(server.on, …)` / `const m = server.on`, and the `server.setTimeout`
    //     receiver of `server.setTimeout(t, socket => …)` (F1), are each a property access
    //     visited here regardless of how (or whether) they are later invoked.
    if (ts.isPropertyAccessExpression(node) && STATIC_SOCKET_ACQUISITION_NAMES.has(node.name.text)) found = true;
    // RULE A (b) — GLOBAL static-computed socket-acquisition NAME `['socket']`/`['connection']`/
    //     `['on']`/…/`['setTimeout']` (any receiver, e.g. `server['on']('connection', …)`),
    //     resolved by BINDER identity (`sockResolveKey` → `netResolveKey`), never by identifier
    //     text. Resolved(socket name) REJECTS on any receiver; Resolved(other) and NotCapability are
    //     non-matches; Indeterminate falls to the unchanged RULE A2 fail-closed branch.
    if (ts.isElementAccessExpression(node)) {
      const arg = node.argumentExpression;
      const key = sockResolveKey(arg, checker, sockMemo);
      // RULE A extension: a binder-resolvable socket-acquisition NAME, ANY receiver
      //     (`server['o' + 'n']`, `const k='on'; server[k]`, `` server[`socket`] ``), even with an
      //     unrelated shadowing `const k` in another scope — binder identity pins the exact key.
      if (key.kind === 'resolved') {
        if (STATIC_SOCKET_ACQUISITION_NAMES.has(key.value)) found = true;
      }
      // RULE A2 (unchanged): an INDETERMINATE (runtime / resource-abort) computed key on a
      //     createServer req/res param fails closed. The trigger stays keyed on `!isStringLiteralLike`,
      //     so A2's fail-closed surface is byte-for-byte what it was — the resolver only ADDS global
      //     name rejections; a NotCapability key never reaches here.
      else if (key.kind === 'indeterminate' && !ts.isStringLiteralLike(arg) && receiverIsReqRes(node.expression)) {
        found = true;
      }
    }
    // RULE A (c) — GLOBAL socket-acquisition NAME destructuring in any object binding pattern
    //     (variable, parameter, nested, callback): `{ socket }` / `{ connection }` /
    //     `{ on }` / `{ setTimeout }`, including the renamed `{ on: h }` / `{ socket: s }` form
    //     (the static source KEY is what is banned, never the local binding name).
    if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
      const keyNode = node.propertyName ?? node.name;
      // RULE A extension: a COMPUTED destructuring key (`{ ['o'+'n']: h }`, `{ [k]: h }` with
      //     `const k='on'`) is resolved by the SAME binder-aware `sockResolveKey` used for member
      //     access — binder identity, never identifier text — so a shadowing same-text `const`
      //     elsewhere cannot flip it. A plain identifier/string key is its own literal text
      //     (`staticKeyText`, purely syntactic). The separate A2 destructuring branch below is
      //     untouched, so its fail-closed surface is preserved.
      let name: string | null = null;
      if (ts.isComputedPropertyName(keyNode)) {
        const key = sockResolveKey(keyNode.expression, checker, sockMemo);
        if (key.kind === 'resolved') name = key.value;
      } else {
        name = staticKeyText(keyNode);
      }
      if (name !== null && STATIC_SOCKET_ACQUISITION_NAMES.has(name)) found = true;
    }
    // RULE A2 (destructuring) — an INDETERMINATE computed binding key destructured DIRECTLY
    //     from a createServer request/response handler parameter fails closed (bound to the
    //     req/res initializer symbol identity, not globally). A statically resolvable key is
    //     unaffected here: a `socket`/`connection` name is already rejected by RULE A (c), a
    //     harmless name (`['method']`) is allowed. `const { ['sock'+'et']: s } = req` and
    //     `const { [key]: s } = req` are rejected; `const { [key]: s } = unrelated` is not.
    if (
      ts.isVariableDeclaration(node) &&
      ts.isObjectBindingPattern(node.name) &&
      node.initializer !== undefined &&
      receiverIsReqRes(node.initializer)
    ) {
      for (const el of node.name.elements) {
        if (
          el.propertyName !== undefined &&
          ts.isComputedPropertyName(el.propertyName) &&
          staticKeyText(el.propertyName) === null
        ) {
          found = true;
        }
      }
    }
    // RULE A2 (assignment) — an object DESTRUCTURING ASSIGNMENT `({ socket: s } = req)` reads
    //     the property off the req/res param exactly like a declaration destructuring, but the
    //     target is an ObjectLiteralExpression (PropertyAssignment / ShorthandPropertyAssignment),
    //     not a binding pattern, so RULE A (c) / RULE A2 above do not see it. This is bound to the
    //     req/res initializer symbol identity (NOT global — an unrelated `({ socket: x } = obj)`
    //     stays allowed): a `socket`/`connection` key is rejected, an indeterminate computed key
    //     fails closed, and a static harmless key (`method`/`url`) is allowed.
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      receiverIsReqRes(node.right)
    ) {
      const target = binderUnwrap(node.left);
      if (ts.isObjectLiteralExpression(target)) {
        for (const prop of target.properties) {
          if (ts.isShorthandPropertyAssignment(prop)) {
            if (SOCKET_CAPABILITY_NAMES.has(prop.name.text)) found = true;
          } else if (ts.isPropertyAssignment(prop)) {
            if (ts.isComputedPropertyName(prop.name)) {
              const key = staticKeyText(prop.name);
              if (key === null || SOCKET_CAPABILITY_NAMES.has(key)) found = true;
            } else {
              const key = staticKeyText(prop.name);
              if (key !== null && SOCKET_CAPABILITY_NAMES.has(key)) found = true;
            }
          }
        }
      }
    }
    // RULE A (c, assignment parity — DELIVERY/REGISTRAR members ONLY) — receiver-INDEPENDENT
    //     delivery/registrar-member NAME in an object DESTRUCTURING ASSIGNMENT target:
    //     `({ on: register } = server)` / `({ on } = server)` / `({ ['o'+'n']: h } = server)` / nested
    //     `({ a: { on } } = server)`. The target is an ObjectLiteralExpression (Shorthand/
    //     PropertyAssignment), NOT a BindingElement, so RULE A (c) above does not see it, and the RULE
    //     A2 assignment branch just above is bound to req/res receivers + SOCKET_CAPABILITY_NAMES only.
    //     `scanSocketAssignmentTarget` closes the verified registrar-extraction gap by applying the
    //     receiver-independent SOCKET_DELIVERY_MEMBERS ban to the assignment AST — server identity is
    //     never tracked, exactly as `.on` / `const { on }` are already receiver-independent. The
    //     socket/connection CAPABILITY names are DELIBERATELY not broadened here: their assignment
    //     extraction stays the req/res-bound RULE A2 branch above (accepted D3-CX-CODEX-ASSIGN
    //     invariant). Only a RESOLVED delivery name rejects; an indeterminate computed key is left to
    //     the req/res-bound RULE A2 branch above (NOT globally failed closed).
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const target = binderUnwrap(node.left);
      if (ts.isObjectLiteralExpression(target)) scanSocketAssignmentTarget(target);
    }
    // RULE B (PROMOTED into RULE A's name family) — the event registrars and `setTimeout` are
    //     now banned by NAME at RULE A (a)/(b)/(c) above, receiver- and position-independent, so
    //     the former call-callee-only registrar ban is fully subsumed (a called `server.on(...)`
    //     is caught by its `.on` property access, exactly like an uncalled `const m = server.on`).
    //     Anchoring on the member NAME rather than the call callee is precisely what closes the
    //     `.call`/`.apply`/`.bind`/`Reflect.apply`/method-extraction indirection (F2) and the
    //     `setTimeout` delivery surface (F1) — with NO witness-specific `.call`/`.apply`/`.bind`
    //     blacklist and NO event-name enumeration. No separate call-shaped rule remains.
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  return found;
};

// F1/P2 — recursive binder-identity resolution for the NET free-global member check
// (D3-CX-POLICY-NET-BIND). `collectStringConsts` keys a resolved constant by identifier TEXT and,
// while resolving a `const`'s initializer, folds EVERY identifier leaf by text too. For the NET
// free-global member path that is unsound at two levels: (1) the element-access key identifier
// itself may resolve to a DIFFERENT same-text binding, and (2) even a genuine same-symbol key
// (`const key = Infinity`) can carry a value that was folded from an out-of-scope
// `const Infinity = 'fetch'` INSIDE its initializer — binding identity is lost during initializer
// resolution. Identifier text equality is never binding identity; the compiler binder is authority.
//
// The NET path therefore resolves strings itself, straight off the binder, WITHOUT consulting the
// text-keyed const map: every Identifier hop — the key and every identifier reached while resolving
// a collected initializer — must resolve (via `checker.getSymbolAtLocation`) to a single
// `const <text> = <init>` declaration of matching text, and that declaration's initializer is then
// resolved under the SAME discipline. A hop that resolves to a different same-text binding, to no
// in-file binding (a free global under `noLib`), or to a non-const/duplicate binding, demotes the
// whole chain to unresolved (`null`), left to the fail-closed runtime-code guard. String literals
// and `+`-folds of literals carry no identifier and resolve as before, so a genuine same-symbol
// const chain (`const a = 'fetch'; const key = a; globalThis[key]`) still folds and is still
// rejected. `seen` bounds recursion: a const-initializer cycle terminates at `null`. Bounded to
// NET: `collectStringConsts` / `staticStringOf` / `memberNameOf` are unchanged, so the RC/HA
// text-only structural policy is not touched.

// The single `const <text> = <init>` declaration a binder-resolved identifier denotes, else null:
// the symbol has exactly one declaration, that declaration is a `const` VariableDeclaration whose
// name text matches the reference. Text equality alone never qualifies — a different-scope or
// free-global reference resolves to a different symbol (or none) and is rejected here.
const netUniqueConstDecl = (id: ts.Identifier, checker: ts.TypeChecker): ts.VariableDeclaration | null => {
  const symbol = checker.getSymbolAtLocation(id);
  if (symbol === undefined || symbol.declarations === undefined || symbol.declarations.length !== 1) {
    return null;
  }
  const decl = symbol.declarations[0];
  if (decl === undefined || !ts.isVariableDeclaration(decl) || !ts.isIdentifier(decl.name) || decl.name.text !== id.text) {
    return null;
  }
  const list = decl.parent;
  return ts.isVariableDeclarationList(list) && (list.flags & ts.NodeFlags.Const) !== 0 ? decl : null;
};

// The statically-provable string an expression denotes for the NET path, resolved entirely by the
// binder: a string literal or substitution-free template, a `+`-fold of such, or an Identifier the
// binder proves is a unique `const` whose initializer resolves the same way — recursively, with
// binder identity required at EVERY hop.
//
// Two DISTINCT bookkeeping structures, both keyed by DECLARATION identity (never identifier text),
// so a shared initializer subtree is resolved once instead of exponentially (P2 memoization):
//   - `seen`: the declarations on the CURRENT resolution path, so an initializer cycle yields
//     `null` in finite time (a declaration re-entered before it completes is a cycle).
//   - `memo`: the COMPLETED result of each declaration (a `string`, or `null` for unresolved),
//     so a second reference to the same declaration — a diamond/doubling chain such as
//     `aN = aN-1 + aN-1` — reads the cached result rather than recomputing its whole subtree.
//     `memo.has` distinguishes a cached `null` from "not yet computed", so a genuine unresolved
//     result never silently becomes a static value. The cache is per top-level key resolution and
//     keyed by the binder-proven declaration node, so a result for one declaration is NEVER reused
//     for a different same-text declaration in another scope.
//
// A per-member `budget` records the identifier hops ONE member resolution spends and CAPS them:
// memoization keeps the hop count linear in the number of const declarations, so a doubling chain
// costs O(N), never O(2^N). Because resolution is synchronous, an un-memoized regression would
// block the event loop rather than trip a test timeout — the cap converts that into a fast,
// deterministic failure. `netResolveVisits` accumulates hops across ALL member resolutions of ONE
// `usesOutboundNetwork` traversal (reset at its start), so a test can prove the CROSS-member cost
// is O(N + M) — a chain reused by M accesses is resolved once — not O(M × N). Both bounds sit far
// above anything real host/Cockpit source or any genuine const chain produces.
const NET_RESOLVE_VISIT_CAP = 200_000;

// NET member-key CLASSIFICATION (D3-CX-POLICY-NET-KEY, frozen DDR). At a binder-verified FREE
// global receiver the computed member key is resolved to one of three states, and ONLY these three
// — a member name is never demoted to a bare `null` that silently means "allow":
//
//   Resolved(string)  — the key statically denotes exactly this string (a literal, a
//                       substitution-free template, a bounded `+`-fold, or a binder-proven unique
//                       `const` chain). DENY iff the string is a NETWORK_GLOBAL_NAMES member.
//   NotCapability     — the key is PROVABLY not a capability name: a `+`-fold whose result exceeds
//                       the longest capability name. Because `+` only ADDS characters, no further
//                       concatenation can shrink it to `fetch`/`WebSocket`, so this is a sound
//                       ALLOW — and it lets the fold stop BEFORE materializing the oversized string.
//   Indeterminate     — the key cannot be statically pinned down: a runtime/ambient/mutated/
//                       duplicate/undeclared/shadowed-differently identifier, an initializer cycle,
//                       a non-string expression form, OR a RESOURCE-BOUND ABORT (depth/visit
//                       ceiling). At a free-global receiver this is DENIED fail-closed — a computed
//                       key that MIGHT be `fetch`/`WebSocket` at runtime must not slip past NET by
//                       being unresolvable. (Converting an abort to "allow" was the P1 egress hole:
//                       a deep `const shared='fetch'; nK='' + nK-1; globalThis[nN](...)` aborted and
//                       was allowed.) NET no longer relies on the runtime-code guard to catch these.
//
// The identifier-ALIAS spine (`const a = b; const b = c; …`) resolves ITERATIVELY, so a genuine
// long chain to `fetch`/`WebSocket` still classifies as Resolved (DENY), and a long benign chain as
// Resolved-non-capability (ALLOW), rather than aborting into a false positive. Only a non-identifier
// initializer (literal / `+`-fold) recurses, bounded by `NET_RESOLVE_DEPTH_CAP` (deterministic, far
// below the native stack limit and far above any real host/Cockpit source or genuine capability
// fold); the visit ceiling bounds total work. Both bounds raise `NetResolveAbort`, which maps to
// Indeterminate. Resolved and NotCapability are context-INDEPENDENT (intrinsic to a declaration's
// own initializer) and are memoized; the abort is context-DEPENDENT (it depends on the depth a
// declaration is reached from) and is thrown, so it is NEVER memoized — a declaration aborted on a
// deep path still resolves when later reached from a shallow one. (A deeply nested LITERAL `+`
// expression overflows the shared `ts.forEachChild` AST walk every detector uses, before this
// resolver is reached — a pre-existing whole-file traversal limit, out of scope here.)
const NET_RESOLVE_DEPTH_CAP = 2_000;
// The longest network-capability name (`WebSocket` = 9). Derived from the policy set so it stays
// correct if the set changes; a `+`-fold whose result exceeds it is provably NotCapability.
const MAX_NETWORK_MEMBER_LENGTH = Math.max(...[...NETWORK_GLOBAL_NAMES].map((name) => name.length));
let netResolveVisits = 0;

// The three-state key classification. `Resolved` carries the exact string; the other two are
// nullary. A member key is exactly one of these — never an ambiguous `null`.
type NetKey =
  | { readonly kind: 'resolved'; readonly value: string }
  | { readonly kind: 'notCapability' }
  | { readonly kind: 'indeterminate' };
const NET_NOT_CAPABILITY: NetKey = { kind: 'notCapability' };
const NET_INDETERMINATE: NetKey = { kind: 'indeterminate' };

// A resource-bound abort (recursion depth or visit budget). Thrown (not returned) so no partially
// resolved declaration on the aborted path is memoized, and caught at the member boundary where it
// becomes an Indeterminate key (fail-closed DENY at a free-global receiver), never a crash.
class NetResolveAbort extends Error {}

const netResolveKey = (
  node: ts.Expression,
  checker: ts.TypeChecker,
  seen: Set<ts.Declaration>,
  memo: Map<ts.Declaration, NetKey>,
  budget: { spent: number },
  depth: number,
  // The longest name any consumer of THIS resolution compares against: `MAX_NETWORK_MEMBER_LENGTH`
  // for a network member key, `MAX_GLOBAL_RECEIVER_LENGTH` for a self-reference hop key (a hop can
  // fold to `globalThis`, 10 > the 9-char network ceiling, so the ceiling must travel with the
  // call). `memo` is keyed by declaration AND is caller-scoped to a single `maxLen`, so a
  // NotCapability decided under one ceiling can never be read back under the other.
  maxLen: number,
): NetKey => {
  if (depth > NET_RESOLVE_DEPTH_CAP) throw new NetResolveAbort(); // resource bound: not memoized
  const n = unwrapExpr(node);
  if (ts.isStringLiteralLike(n)) return { kind: 'resolved', value: n.text };
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = netResolveKey(n.left, checker, seen, memo, budget, depth + 1, maxLen);
    if (left.kind === 'indeterminate') return NET_INDETERMINATE;
    if (left.kind === 'notCapability') return NET_NOT_CAPABILITY; // already too long; `+` only grows it
    const right = netResolveKey(n.right, checker, seen, memo, budget, depth + 1, maxLen);
    if (right.kind === 'indeterminate') return NET_INDETERMINATE;
    if (right.kind === 'notCapability') return NET_NOT_CAPABILITY;
    // Bound OUTPUT before allocating `left + right`: an oversized result is provably NotCapability,
    // so no exponential intermediate is ever materialized.
    if (left.value.length + right.value.length > maxLen) return NET_NOT_CAPABILITY;
    return { kind: 'resolved', value: left.value + right.value };
  }
  // A SUBSTITUTED template `` `o${'n'}` `` denotes the same static string as the `+`-fold and folds the
  // SAME way: the head text, then for every span the resolved substitution EXPRESSION followed by that
  // span's literal text — each substitution resolved through THIS resolver (string literal / `+`-fold /
  // unique-const identity), reusing the same depth/visit/length bounds. A substitution-free template is
  // a `NoSubstitutionTemplateLiteral` already handled by the `isStringLiteralLike` branch above; a
  // `TemplateExpression` always carries ≥1 span. Length is bounded BEFORE each concat (an oversized
  // result is provably NotCapability, so no oversized intermediate is materialized). If ANY substitution
  // is indeterminate (runtime / mutable / ambient / unresolvable), the whole template is Indeterminate —
  // no runtime coercion, no `toString`, no value flow.
  if (ts.isTemplateExpression(n)) {
    let value = n.head.text;
    if (value.length > maxLen) return NET_NOT_CAPABILITY;
    for (const span of n.templateSpans) {
      const part = netResolveKey(span.expression, checker, seen, memo, budget, depth + 1, maxLen);
      if (part.kind === 'indeterminate') return NET_INDETERMINATE;
      if (part.kind === 'notCapability') return NET_NOT_CAPABILITY; // already too long; concat only grows it
      if (value.length + part.value.length > maxLen) return NET_NOT_CAPABILITY;
      value += part.value;
      if (value.length + span.literal.text.length > maxLen) return NET_NOT_CAPABILITY;
      value += span.literal.text;
    }
    return { kind: 'resolved', value };
  }
  if (ts.isIdentifier(n)) {
    // Resolve an identifier-ALIAS spine (`const a = b; const b = c; …`) ITERATIVELY, so a chain of
    // any length consumes O(1) native stack. Every declaration on the spine denotes the SAME key, so
    // the completed classification is recorded for all of them at once. A hop that is not a
    // binder-proven unique `const` (runtime/ambient/mutated/duplicate/undeclared/shadowed) or a
    // cycle is Indeterminate. Only a non-identifier initializer (literal / `+`-fold) recurses.
    const spine: ts.Declaration[] = [];
    let cur: ts.Identifier = n;
    let key: NetKey = NET_INDETERMINATE;
    for (;;) {
      netResolveVisits += 1; // cumulative across the whole usesOutboundNetwork traversal (test evidence)
      budget.spent += 1; // per-member ceiling
      if (budget.spent > NET_RESOLVE_VISIT_CAP) throw new NetResolveAbort(); // resource bound: not memoized
      const decl = netUniqueConstDecl(cur, checker);
      if (decl === null || decl.initializer === undefined) {
        key = NET_INDETERMINATE; // not a binder-proven unique const → unknown key
        break;
      }
      if (memo.has(decl)) {
        key = memo.get(decl) ?? NET_INDETERMINATE; // completed classification
        break;
      }
      if (seen.has(decl)) {
        key = NET_INDETERMINATE; // re-entry before completion: cycle (do not cache)
        break;
      }
      seen.add(decl);
      spine.push(decl);
      const init = unwrapExpr(decl.initializer);
      if (ts.isIdentifier(init)) {
        cur = init; // alias hop: iterate, no recursion
        continue;
      }
      key = netResolveKey(init, checker, seen, memo, budget, depth + 1, maxLen); // literal / `+`-fold
      break;
    }
    // Reached only on a NON-abort return (a thrown NetResolveAbort unwinds past this, leaving the
    // aborted-path declarations UNcached). The completed classification is context-independent, so
    // caching it for every alias on the spine is sound.
    for (const d of spine) {
      seen.delete(d);
      memo.set(d, key);
    }
    return key;
  }
  return NET_INDETERMINATE; // any other expression form (call, number, conditional, …): unknown key
};

// Classify the member key of a property/element access for the NET path. A property name is read
// directly (always Resolved); an element-access key is resolved by `netResolveKey` (binder identity
// at every hop), never by identifier text alone. The completed-classification `memo` is SHARED
// across every member resolution of one `usesOutboundNetwork` traversal, so a const chain reused by
// many accesses is resolved once (O(N + M), not O(M × N)); a fresh `seen`/`budget` per call keeps
// active-path cycle detection and the per-member ceiling local. A resource-bound abort becomes
// Indeterminate (fail-closed at a free-global receiver).
const netMemberKey = (
  node: ts.PropertyAccessExpression | ts.ElementAccessExpression,
  checker: ts.TypeChecker,
  memo: Map<ts.Declaration, NetKey>,
): NetKey => {
  if (ts.isPropertyAccessExpression(node)) return { kind: 'resolved', value: node.name.text };
  try {
    return netResolveKey(node.argumentExpression, checker, new Set<ts.Declaration>(), memo, { spent: 0 }, 0, MAX_NETWORK_MEMBER_LENGTH);
  } catch (error) {
    if (error instanceof NetResolveAbort) return NET_INDETERMINATE;
    throw error;
  }
};

// The longest global-receiver name (`globalThis` = 10). A self-reference hop key can fold to it,
// so the hop resolver's `+`-fold ceiling must reach 10 — one above the 9-char network member
// ceiling — or `globalThis['global' + 'This']` would be pruned as NotCapability before resolving.
const MAX_GLOBAL_RECEIVER_LENGTH = Math.max(...[...GLOBAL_RECEIVER_NAMES].map((name) => name.length));

// DDR-NET-STATIC-KEY-PARITY (F1) — the self-reference HOP name an element-access key denotes,
// resolved by the SAME bounded binder resolver used for network member keys (`netResolveKey`),
// never by identifier text: a string literal / substitution-free template, a `+`-fold, or a
// binder-proven unique `const` chain, capped at `MAX_GLOBAL_RECEIVER_LENGTH`. Only a Resolved key
// yields a hop name; NotCapability, Indeterminate, and a resource-bound abort all become null (NOT
// a hop), so a genuinely runtime key (`globalThis[runtimeKey]`) is never folded into a self-hop and
// stays outside the frozen boundary. A FRESH memo isolates the wider hop ceiling from the shared
// network-member memo (a declaration classified under one ceiling is never read back under the
// other). Binder/shadowing authority over the base identifier stays with `isFreeGlobalReceiver`.
const netHopName = (node: ts.Expression, checker: ts.TypeChecker): string | null => {
  try {
    const key = netResolveKey(node, checker, new Set<ts.Declaration>(), new Map<ts.Declaration, NetKey>(), { spent: 0 }, 0, MAX_GLOBAL_RECEIVER_LENGTH);
    return key.kind === 'resolved' ? key.value : null;
  } catch (error) {
    if (error instanceof NetResolveAbort) return null;
    throw error;
  }
};

// DDR-NET-STATIC-KEY-PARITY (F2) — classify a destructuring property KEY (declaration binding
// element OR assignment ObjectLiteral property) with the SAME three-state discipline as a member
// key: a plain identifier / string-literal name is its own text (Resolved); a computed key
// (`{ ['fe' + 'tch']: f }`, `{ [k]: f }`) is resolved off the binder by `netResolveKey` at the
// network-member ceiling into Resolved / NotCapability / Indeterminate. At a proven free-global
// receiver the caller applies the frozen NET policy — Resolved(capability) and Indeterminate DENY,
// Resolved(other) / NotCapability ALLOW — so an indeterminate destructuring key fails closed
// exactly like an indeterminate member key. Any other name form (numeric/private) is Indeterminate.
const netDestructuringKey = (keyNode: ts.Node, checker: ts.TypeChecker): NetKey => {
  if (ts.isComputedPropertyName(keyNode)) {
    try {
      return netResolveKey(keyNode.expression, checker, new Set<ts.Declaration>(), new Map<ts.Declaration, NetKey>(), { spent: 0 }, 0, MAX_NETWORK_MEMBER_LENGTH);
    } catch (error) {
      if (error instanceof NetResolveAbort) return NET_INDETERMINATE;
      throw error;
    }
  }
  if (ts.isIdentifier(keyNode) || ts.isStringLiteralLike(keyNode)) return { kind: 'resolved', value: keyNode.text };
  return NET_INDETERMINATE;
};

// DDR-NET-STATIC-KEY-PARITY (SOCK, F1) — SOCK's static socket acquisition-key resolution is
// CONSOLIDATED onto the SAME bounded binder-aware `netResolveKey` the NET member/hop/destructuring
// keys use, replacing the scope-insensitive whole-file text-keyed `collectStringConsts`/
// `staticStringOf` path. Binder identity is required at the key AND at every const-initializer hop,
// so the exact occurrence is resolved by the TypeScript binder: an unrelated sibling/nested same-text
// declaration in another scope can no longer make a statically-known key unresolved — the fail-open
// that let `const k='on'; server[k](...)` escape when an unrelated `const k='noop'` existed elsewhere
// (the whole-file collector saw two `k` bindings and demoted the key to UNKNOWN even though the
// binder pins the exact `k='on'`). The socket ceiling is the longest name in
// STATIC_SOCKET_ACQUISITION_NAMES (`prependOnceListener` = 19), DERIVED from the set so a `+`-fold to
// any socket name (`'set' + 'Timeout'`) resolves rather than being pruned as NotCapability. A fresh
// `seen`/`budget` per call keeps active-path cycle detection and the per-key hop ceiling local; the
// caller's shared per-traversal `memo` (declaration-keyed, socket-ceiling-scoped) keeps a reused
// chain O(N + M); a resource-bound abort is caught and becomes Indeterminate. Mechanism
// CONSOLIDATION only — no new resolver, alias/capability/taint propagation, assignment following, or
// new policy family; NET's own resolver and the shared RC/HA text helpers are untouched.
const MAX_SOCKET_MEMBER_LENGTH = Math.max(...[...STATIC_SOCKET_ACQUISITION_NAMES].map((name) => name.length));
const sockResolveKey = (
  node: ts.Expression,
  checker: ts.TypeChecker,
  memo: Map<ts.Declaration, NetKey>,
): NetKey => {
  try {
    return netResolveKey(node, checker, new Set<ts.Declaration>(), memo, { spent: 0 }, 0, MAX_SOCKET_MEMBER_LENGTH);
  } catch (error) {
    if (error instanceof NetResolveAbort) return NET_INDETERMINATE;
    throw error;
  }
};

// DDR-NET-STATIC-KEY-PARITY (nested authority) — the self-reference HOP NAME a DESTRUCTURING key
// denotes, resolved by the SAME bounded binder resolver used for a member-access hop (`netHopName`)
// but reading a binding/object-literal KEY node instead of an element-access argument: a plain
// identifier / string-literal key is its own text, a computed key (`{ ['global' + 'This']: … }`,
// `{ [k]: … }` with `const k = 'globalThis'`) folds off the binder, capped at
// `MAX_GLOBAL_RECEIVER_LENGTH` (10 — a hop can fold to `globalThis`, one above the 9-char network
// member ceiling). Only a Resolved key yields a hop name; NotCapability, Indeterminate, and a
// resource-bound abort all become null (NOT a hop), so a genuinely runtime intermediate key never
// starts/continues authority and stays outside the frozen boundary. This is the destructuring twin
// of `netHopName`; it introduces NO new resolver — it reuses `netResolveKey` exactly like
// `netDestructuringKey`, only at the wider self-hop ceiling that `MAX_NETWORK_MEMBER_LENGTH` (9)
// would prune a 10-char self-reference name out of.
const netDestructuringHopName = (keyNode: ts.Node, checker: ts.TypeChecker): string | null => {
  if (ts.isComputedPropertyName(keyNode)) {
    try {
      const key = netResolveKey(keyNode.expression, checker, new Set<ts.Declaration>(), new Map<ts.Declaration, NetKey>(), { spent: 0 }, 0, MAX_GLOBAL_RECEIVER_LENGTH);
      return key.kind === 'resolved' ? key.value : null;
    } catch (error) {
      if (error instanceof NetResolveAbort) return null;
      throw error;
    }
  }
  if (ts.isIdentifier(keyNode) || ts.isStringLiteralLike(keyNode)) return keyNode.text;
  return null;
};

// DDR-NET-STATIC-KEY-PARITY (nested authority) — whether free-global-receiver authority REACHES an
// object binding PATTERN, resolved STRUCTURALLY over the finite binding AST (never value flow):
//   - a TOP-LEVEL pattern (its container is the variable declaration) has authority iff the
//     declaration's initializer is a binder-proven free global receiver (`isFreeGlobalReceiver`);
//   - a NESTED pattern (its container is an OUTER binding element) has authority iff (a) the outer
//     element's own pattern already has authority AND (b) the outer element's KEY resolves — through
//     the SAME binder-aware key machinery (`netDestructuringHopName`) — to a global self-reference
//     name in `GLOBAL_RECEIVER_NAMES`, exactly as `globalThis.globalThis` re-denotes the real global.
// Authority therefore CONTINUES only through a proven self-hop key; an intermediate key that is a
// non-self-hop name (`foo`), indeterminate, or a non-namespace receiver stops it (allow), mirroring
// how a shadowed/runtime hop demotes a member-access receiver. Finite: the recursion strips one
// binding-pattern nesting level per step and terminates at the variable declaration; it walks only
// binding-pattern parent links, never a value graph.
const objectPatternHasFreeGlobalAuthority = (
  pattern: ts.ObjectBindingPattern,
  checker: ts.TypeChecker,
  sourceFile: ts.SourceFile,
): boolean => {
  const container = pattern.parent;
  if (ts.isVariableDeclaration(container)) {
    return container.initializer !== undefined && isFreeGlobalReceiver(container.initializer, checker, sourceFile);
  }
  if (ts.isBindingElement(container) && ts.isObjectBindingPattern(container.parent)) {
    if (!objectPatternHasFreeGlobalAuthority(container.parent, checker, sourceFile)) return false;
    const hop = netDestructuringHopName(container.propertyName ?? container.name, checker);
    return hop !== null && GLOBAL_RECEIVER_NAMES.has(hop);
  }
  return false;
};

// DDR-NET-REFLECT-GET (F1) — whether `Reflect` is the binder-proven UNSHADOWED built-in intrinsic.
// Reflect is a DISTINCT intrinsic, deliberately NOT a member of `GLOBAL_RECEIVER_NAMES`: it is
// recognized only here, and only when the binder resolves the identifier to NO local runtime value
// binding, exactly the `isFreeGlobalReceiver` identifier rule reused verbatim. A local
// `const Reflect = { get() { … } }` (or any runtime binding of the name) is therefore an ordinary
// object and its `.get` is NOT the built-in — identifier text alone never qualifies.
const isFreeReflect = (expr: ts.Expression, checker: ts.TypeChecker, sourceFile: ts.SourceFile): boolean => {
  const e = binderUnwrap(expr);
  if (!ts.isIdentifier(e) || e.text !== 'Reflect') return false;
  const symbol = checker.getSymbolAtLocation(e);
  if (symbol === undefined) return true;
  return !hasLocalRuntimeShadow(symbol, sourceFile);
};

// DDR-NET-REFLECT-GET (F1) — whether a call callee is a DIRECT built-in `Reflect.get` member: a
// dotted `Reflect.get` or a static-string element access `Reflect['get']` / `Reflect['g' + 'et']`,
// with the `get` name resolved by the SAME `netMemberKey` machinery (never identifier text), off a
// binder-proven unshadowed `Reflect`. A runtime/aliased member key (`Reflect[k]`), an alias of
// Reflect (`const R = Reflect; R.get(…)`), or a shadowed Reflect all fail this — no alias, no
// call/apply/bind, no wrapper: one statically identifiable built-in member.
const isBuiltinReflectGetCallee = (callee: ts.Expression, checker: ts.TypeChecker, sourceFile: ts.SourceFile): boolean => {
  const c = binderUnwrap(callee);
  if (!ts.isPropertyAccessExpression(c) && !ts.isElementAccessExpression(c)) return false;
  const memberKey = netMemberKey(c, checker, new Map<ts.Declaration, NetKey>());
  if (!(memberKey.kind === 'resolved' && memberKey.value === 'get')) return false;
  return isFreeReflect(c.expression, checker, sourceFile);
};

// DDR-NET-REFLECT-GET (F1) — classify the KEY ARGUMENT of a `Reflect.get(receiver, key)` call with
// the SAME three-state discipline as a computed member key: a string literal / substitution-free
// template / `+`-fold resolves to its value; an identifier resolves through the binder-proven unique
// `const` chain (`const k = 'fetch'; Reflect.get(globalThis, k)`); a runtime/ambient/undeclared key
// (`declare const runtimeKey; Reflect.get(globalThis, runtimeKey)`) or a resource-bound abort is
// Indeterminate. The key is a VALUE expression (not a binding key), so — unlike `netDestructuringKey`
// — a bare identifier is resolved, never taken as its own text; this reuses `netResolveKey` exactly
// like `netMemberKey`'s element-access branch, at the network-member ceiling.
const netReflectGetKey = (keyArg: ts.Expression, checker: ts.TypeChecker): NetKey => {
  try {
    return netResolveKey(keyArg, checker, new Set<ts.Declaration>(), new Map<ts.Declaration, NetKey>(), { spent: 0 }, 0, MAX_NETWORK_MEMBER_LENGTH);
  } catch (error) {
    if (error instanceof NetResolveAbort) return NET_INDETERMINATE;
    throw error;
  }
};

/**
 * NET — reject outbound network egress, decided by TypeScript BINDER identity
 * (D3-CX-POLICY-NET). Lexical binding identity — nearest visible binding, shadowing,
 * restoration, for/switch/catch scope, parameter scope, named function-expression
 * self-binding, and computed-name evaluation order — is delegated to the compiler binder
 * via `checker.getSymbolAtLocation`, so this guard NEVER re-implements ECMAScript/
 * TypeScript scoping. The Program is in-memory, single-file, `noLib`+`noResolve`: no
 * filesystem, no module resolution, no network. Policy is the positive model: runtime
 * `import('node:http')` is prohibited; the node:http namespace may be used only to obtain
 * `createServer` (member access or `createServer`-only destructuring) or in type
 * positions; any other node:http value (`HTTP_CLIENT`) may not be referenced; the free
 * network globals `fetch`/`WebSocket` are rejected when truly unbound.
 */
const usesOutboundNetwork = (source: string): boolean => {
  const { checker, sourceFile } = buildBinderProgram(source);
  // Free-global network members (F1/P2/P1) are classified by `netMemberKey` straight off the binder
  // — identity required at the key AND at every initializer hop (see `netResolveKey`) — into
  // Resolved / NotCapability / Indeterminate. At a binder-verified free-global receiver:
  // Resolved(`fetch`/`WebSocket`) and Indeterminate DENY; Resolved(other) and NotCapability ALLOW.
  // NET is self-contained fail-closed here — it does NOT lean on the runtime-code guard to reject an
  // indeterminate computed key.
  //
  // ONE completed-classification memo is shared by every member resolution in THIS traversal, so a
  // const chain reused across many accesses is resolved once (O(N + M), not O(M × N)). It is keyed by
  // the binder's declaration nodes for this Program, so it cannot leak into another
  // `usesOutboundNetwork` call. `netResolveVisits` is reset here to make the hop count observable.
  const netMemo = new Map<ts.Declaration, NetKey>();
  netResolveVisits = 0;
  let found = false;
  // Branch (4) helper — walk an object-literal ASSIGNMENT target with free-global authority already
  // established for THIS object literal (the top-level call is guarded by the `= <free global>`
  // receiver; a nested call is reached only through a proven self-hop key below). This is the
  // assignment twin of branch (3)'s `objectPatternHasFreeGlobalAuthority` recursion: each property's
  // source KEY is classified for a network capability at the network ceiling, and authority CONTINUES
  // into a nested object-literal value only through a self-reference hop key (resolved at the wider
  // self-hop ceiling by `netDestructuringHopName`). Finite: it descends only nested object-literal
  // targets, one per pattern level, and terminates when no nested object literal remains.
  const scanFreeGlobalAssignmentTarget = (target: ts.ObjectLiteralExpression): void => {
    for (const prop of target.properties) {
      let keyNode: ts.Node | undefined;
      let valueNode: ts.Expression | undefined;
      if (ts.isShorthandPropertyAssignment(prop)) {
        keyNode = prop.name;
      } else if (ts.isPropertyAssignment(prop)) {
        keyNode = prop.name;
        valueNode = prop.initializer;
      } else {
        continue; // spread / accessor / method — not a destructuring target property
      }
      const key = netDestructuringKey(keyNode, checker);
      if (key.kind === 'resolved') {
        if (NETWORK_GLOBAL_NAMES.has(key.value)) found = true;
      } else if (key.kind === 'indeterminate') {
        found = true; // fail-closed at a proven free-global receiver
      }
      // Authority continues into a nested object-literal target ONLY through a self-reference hop key
      // (a GLOBAL_RECEIVER_NAMES name resolved at the self-hop ceiling), mirroring branch (3).
      if (valueNode !== undefined) {
        const nested = binderUnwrap(valueNode);
        if (ts.isObjectLiteralExpression(nested)) {
          const hop = netDestructuringHopName(keyNode, checker);
          if (hop !== null && GLOBAL_RECEIVER_NAMES.has(hop)) scanFreeGlobalAssignmentTarget(nested);
        }
      }
    }
  };
  const visit = (node: ts.Node): void => {
    // (0) a runtime dynamic `import('node:http')` is prohibited outright, in every context.
    if (isDynamicNodeHttpImport(node)) found = true;
    // (1) member/element access: an HTTP_NS receiver is permitted ONLY for `createServer`,
    //     and that `createServer` access must itself sit in a direct-call position
    //     (DDR-CREATE-SERVER-ALIAS-POLICY) — a stored/forwarded `http.createServer` escapes;
    //     a network global (`fetch`/`WebSocket`) off a FREE global receiver is rejected.
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      if (classifyHttpExpression(node.expression, checker) === 'HTTP_NS') {
        const member = binderMemberName(node);
        if (member === null || !HTTP_SERVER_VALUE_MEMBERS.has(member)) {
          found = true; // a non-createServer (outbound client) member off the namespace
        } else if (!isCreateServerSafePosition(node)) {
          found = true; // the createServer constructor forwarded/stored out of a direct call
        }
      }
      // F1/P2/P1 — classify the member key (Resolved / NotCapability / Indeterminate) off the binder
      //     and decide it ONLY at a binder-verified free-global receiver. Resolved(capability) DENY;
      //     Resolved(other) ALLOW; NotCapability (provably too long) ALLOW; Indeterminate (runtime/
      //     ambient/mutated/undeclared/cycle key, or a depth/visit resource abort) DENY fail-closed —
      //     a key that MIGHT be `fetch`/`WebSocket` at runtime must not pass by being unresolvable.
      const memberKey = netMemberKey(node, checker, netMemo);
      if (isFreeGlobalReceiver(node.expression, checker, sourceFile)) {
        if (memberKey.kind === 'resolved') {
          if (NETWORK_GLOBAL_NAMES.has(memberKey.value)) found = true;
        } else if (memberKey.kind === 'indeterminate') {
          found = true;
        }
      }
    }
    // (2) an identifier value read: HTTP_CLIENT is forbidden; HTTP_NS must sit in a safe
    //     position (else escape); a FREE network global (`fetch`/`WebSocket`) is rejected.
    if (ts.isIdentifier(node) && isBinderValueReference(node)) {
      const symbol = checker.getSymbolAtLocation(node);
      if (symbol !== undefined) {
        const cap = classifyHttpSymbol(symbol, checker);
        if (cap === 'HTTP_CLIENT') found = true;
        if (cap === 'HTTP_NS' && !isHttpNsSafePosition(node)) found = true;
        // A createServer-classified identifier (named/renamed import or directly-destructured
        // binding) is the constructor capability itself: it may be READ only in a direct-call
        // position (DDR-CREATE-SERVER-ALIAS-POLICY). A read that stores/forwards it
        // (`const start = createServer`) escapes — decided here, without tracking `start`.
        if (cap === 'CREATE_SERVER' && !isCreateServerSafePosition(node)) found = true;
        // A bare network global (`fetch`/`WebSocket`) whose only in-file declarations emit no
        // runtime value (an ambient `declare const fetch`, a type-only import) still reaches
        // the runtime global — reject it. A real local shadow (const/function/class/…) does not.
        if (NETWORK_GLOBAL_NAMES.has(node.text) && !hasLocalRuntimeShadow(symbol, sourceFile)) found = true;
      } else if (NETWORK_GLOBAL_NAMES.has(node.text)) {
        found = true;
      }
    }
    // (2b) an EXPORT specifier forwarding the createServer constructor out of the module
    //      (`export { createServer }`) is a non-call escape position for the capability
    //      (DDR-CREATE-SERVER-ALIAS-POLICY). One binder hop to the local target's own
    //      classification — no module-graph or value-flow analysis. A type-only specifier, a
    //      re-export from node:http (no local target → NONE, left to export confinement), and
    //      the exported CALL RESULT (`export const server = http.createServer(...)`, whose
    //      binding is NONE) are all untouched, so `exportsHttpCapability` stays unchanged.
    if (
      ts.isExportSpecifier(node) &&
      !node.isTypeOnly &&
      !node.parent.parent.isTypeOnly &&
      classifyHttpSymbol(checker.getExportSpecifierLocalTargetSymbol(node), checker) === 'CREATE_SERVER'
    ) {
      found = true;
    }
    // (3) DECLARATION destructuring a network global off a FREE global receiver, including
    //     RECURSIVE NESTED object binding patterns (DDR-NET-STATIC-KEY-PARITY, nested authority):
    //     `const { fetch } = globalThis`, `const { fetch: f } = globalThis.globalThis`,
    //     `const { globalThis: { fetch: f } } = globalThis.globalThis`. Free-global authority begins
    //     at the declaration initializer and CONTINUES into a nested pattern ONLY through a
    //     self-reference hop key (`objectPatternHasFreeGlobalAuthority`) — `{ globalThis: … }` off a
    //     global re-denotes the real global, exactly like `globalThis.globalThis`, while `{ foo: … }`
    //     does not. At an authoritative pattern this element's source KEY (`propertyName ?? name`) is
    //     classified with the SAME resolver as a member key: a plain/quoted key is its own text, a
    //     computed static key (`{ ['fe' + 'tch']: f }`, `{ [k]: f }`) folds off the binder.
    //     Resolved(capability) and Indeterminate DENY (an indeterminate key fails closed, just like a
    //     member key), Resolved(other)/NotCapability ALLOW. Capability is extracted here, at the
    //     destructuring; the bound name is not followed onward through value flow. Structural and
    //     finite — authority is proven by walking finite binding-pattern parents, never a value graph.
    if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
      if (objectPatternHasFreeGlobalAuthority(node.parent, checker, sourceFile)) {
        const key = netDestructuringKey(node.propertyName ?? node.name, checker);
        if (key.kind === 'resolved') {
          if (NETWORK_GLOBAL_NAMES.has(key.value)) found = true;
        } else if (key.kind === 'indeterminate') {
          found = true; // fail-closed at a proven free-global receiver
        }
      }
    }
    // (4) ASSIGNMENT destructuring a network global off a FREE global receiver, including RECURSIVE
    //     NESTED object patterns (DDR-NET-STATIC-KEY-PARITY, assignment parity):
    //     `({ fetch: f } = globalThis)`, `({ fetch } = globalThis.globalThis)`,
    //     `({ globalThis: { fetch: f } } = globalThis.globalThis)`. The target is an
    //     ObjectLiteralExpression (Shorthand/PropertyAssignment), not a binding pattern, so branch (3)
    //     does not see it. `scanFreeGlobalAssignmentTarget` mirrors branch (3)'s structural recursion
    //     for the object-literal AST: the same leaf key classification and free-global fail-closed
    //     policy, with authority continuing into a nested object-literal value ONLY through a
    //     self-reference hop key — declaration and assignment forms have equivalent finite authority
    //     semantics where their AST forms correspond. Bound to the `=` right-hand receiver, so an
    //     unrelated `({ fetch: f } = obj)` and a shadowed-global receiver stay allowed.
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && isFreeGlobalReceiver(node.right, checker, sourceFile)) {
      const target = binderUnwrap(node.left);
      if (ts.isObjectLiteralExpression(target)) scanFreeGlobalAssignmentTarget(target);
    }
    // (5) a direct built-in `Reflect.get(<free global receiver>, <key>)` acquisition of a network
    //     global (DDR-NET-REFLECT-GET, F1): `Reflect.get(globalThis.globalThis, 'fetch')(...)`.
    //     Reflect must be binder-proven UNSHADOWED (a local `const Reflect = { get() {} }` is an
    //     ordinary object — `isBuiltinReflectGetCallee`); the RECEIVER argument must be a binder-proven
    //     free global (`isFreeGlobalReceiver`); the KEY argument is classified by the SAME
    //     `netResolveKey` as a computed member key (`netReflectGetKey`) — a bare identifier is
    //     resolved through its const chain, never taken as text. Resolved(capability)/Indeterminate
    //     DENY (fail-closed), Resolved(other)/NotCapability ALLOW. One statically
    //     identifiable built-in call: NO alias of Reflect or of get, NO call/apply/bind chain, NO
    //     wrapper, NO value-flow after acquisition.
    if (ts.isCallExpression(node) && isBuiltinReflectGetCallee(node.expression, checker, sourceFile)) {
      const recvArg = node.arguments[0];
      const keyArg = node.arguments[1];
      if (recvArg !== undefined && keyArg !== undefined && isFreeGlobalReceiver(recvArg, checker, sourceFile)) {
        const key = netReflectGetKey(keyArg, checker);
        if (key.kind === 'resolved') {
          if (NETWORK_GLOBAL_NAMES.has(key.value)) found = true;
        } else if (key.kind === 'indeterminate') {
          found = true; // fail-closed at a proven free-global receiver
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sourceFile, visit);
  // Inbound server-socket acquisition (SOCK) is decided over the SAME single-file binder
  // program — one source of truth, no reparse — and is an additional rejection reason: the
  // permitted createServer path may not be used to acquire the underlying socket capability.
  if (acquiresInboundServerSocket(checker, sourceFile)) found = true;
  return found;
};

// Design D / Option-B export confinement, consuming the SAME binder-backed classification
// as `usesOutboundNetwork`: a binding classified HTTP_NS or HTTP_CLIENT (namespace, named
// client import, or a locally-destructured non-createServer member) may not cross the
// module boundary; createServer/LOCAL and type-only forms may. One source of truth.
const exportsHttpCapability = (inputSourceFile: ts.SourceFile): boolean => {
  const { checker, sourceFile } = buildBinderProgram(inputSourceFile.text);
  const carriesAuthority = (symbol: ts.Symbol | undefined): boolean => {
    const cap = classifyHttpSymbol(symbol, checker);
    return cap === 'HTTP_NS' || cap === 'HTTP_CLIENT';
  };
  for (const statement of sourceFile.statements) {
    // (a) a RUNTIME re-export from node:http (`export * from` / a non-type-only specifier).
    if (
      ts.isExportDeclaration(statement) &&
      !statement.isTypeOnly &&
      statement.moduleSpecifier !== undefined &&
      ts.isStringLiteral(statement.moduleSpecifier) &&
      statement.moduleSpecifier.text === 'node:http'
    ) {
      if (statement.exportClause === undefined) return true;
      // A runtime namespace re-export `export * as http from 'node:http'` binds the whole
      // node:http namespace under a name another host file can import and call
      // (`http.request(...)`). The `!statement.isTypeOnly` guard above already excludes the
      // type-only `export type * as http from 'node:http'`, which emits no runtime authority.
      if (ts.isNamespaceExport(statement.exportClause)) return true;
      if (ts.isNamedExports(statement.exportClause)) {
        for (const el of statement.exportClause.elements) {
          if (!el.isTypeOnly) return true;
        }
      }
    }
    // (b) a local re-export of a binding carrying node:http authority. Type-only skipped.
    if (
      ts.isExportDeclaration(statement) &&
      !statement.isTypeOnly &&
      statement.moduleSpecifier === undefined &&
      statement.exportClause !== undefined &&
      ts.isNamedExports(statement.exportClause)
    ) {
      for (const el of statement.exportClause.elements) {
        if (!el.isTypeOnly && carriesAuthority(checker.getExportSpecifierLocalTargetSymbol(el))) return true;
      }
    }
    // (c) `export default <authority>` / `export = <authority>`.
    if (ts.isExportAssignment(statement)) {
      const cap = classifyHttpExpression(statement.expression, checker);
      if (cap === 'HTTP_NS' || cap === 'HTTP_CLIENT') return true;
    }
    // (d) an EXPORTED declaration whose bound name(s) carry node:http authority.
    if (ts.isVariableStatement(statement) && ts.getModifiers(statement)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) === true) {
      const names: ts.Identifier[] = [];
      const collect = (binding: ts.BindingName): void => {
        if (ts.isIdentifier(binding)) {
          names.push(binding);
        } else {
          for (const el of binding.elements) {
            if (ts.isBindingElement(el)) collect(el.name);
          }
        }
      };
      for (const decl of statement.declarationList.declarations) collect(decl.name);
      for (const nm of names) {
        if (carriesAuthority(checker.getSymbolAtLocation(nm))) return true;
      }
    }
  }
  return false;
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
    { form: 'a dynamic-import http shadowed by a nested local', source: `const http = await import('node:http');\nfunction f() {\n  const http = { request(v: string) { return v; } };\n  return http.request('local');\n}\nvoid f;` },
    { form: 'a dynamic-import namespace createServer', source: `const http = await import('node:http');\nhttp.createServer(() => {});` },
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
    { form: 'createServer destructured DIRECTLY off a dynamic import', source: `const { createServer } = await import('node:http');\ncreateServer(() => {});` },
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

  // F2 (NESTED) — capability propagates RECURSIVELY through nested object destructuring off an
  //     HTTP_NS binding (Codex P1 witness). The inner binding element sits under an OUTER binding
  //     element rather than directly under the variable declaration, yet still acquires the
  //     outbound client member. Each level reduces to the single-hop F2 member rule (HTTP_NS →
  //     createServer is the one server value, every other member is HTTP_CLIENT; off an
  //     HTTP_CLIENT value every member stays HTTP_CLIENT). No alias chains, no value-flow: the
  //     acquisition root is still the one-hop node:http namespace initializer, walked structurally
  //     down the binding pattern. Array patterns and non-namespace initializers do not propagate.
  const nestedReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'the exact Codex witness: nested { globalAgent: { createConnection } } off a namespace import', source: `import * as http from 'node:http';\nconst {\n  globalAgent: { createConnection },\n} = http;\ncreateConnection({ host: 'example.com', port: 80 });` },
    { form: 'a nested aliased { globalAgent: { createConnection: connect } }', source: `import * as http from 'node:http';\nconst {\n  globalAgent: { createConnection: connect },\n} = http;\nconnect({ host: 'example.com', port: 80 });` },
    { form: 'a nested default { globalAgent: { createConnection: connect = fallback } }', source: `import * as http from 'node:http';\nconst fallback = (_o: { host: string; port: number }): void => {};\nconst {\n  globalAgent: { createConnection: connect = fallback },\n} = http;\nconnect({ host: 'example.com', port: 80 });` },
    { form: 'a three-level nested { globalAgent: { pool: { createConnection } } }', source: `import * as http from 'node:http';\nconst {\n  globalAgent: { pool: { createConnection } },\n} = http;\ncreateConnection({ host: 'example.com', port: 80 });` },
    { form: 'the same nesting off a default import resolving to the same HTTP_NS binding', source: `import http from 'node:http';\nconst {\n  globalAgent: { createConnection },\n} = http;\ncreateConnection({ host: 'example.com', port: 80 });` },
  ];
  for (const { form, source } of nestedReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const nestedAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a top-level { createServer } off a namespace import (unchanged)', source: `import * as http from 'node:http';\nconst { createServer } = http;\ncreateServer(() => {});` },
    { form: 'a nested { createServer } that stays the one permitted server value', source: `import * as http from 'node:http';\nconst {\n  createServer,\n} = http;\ncreateServer(() => {});` },
    { form: 'the same nested shape off an unrelated local object (not node:http)', source: `const cfg = {\n  globalAgent: { createConnection: (_o: { host: string }) => _o },\n};\nconst {\n  globalAgent: { createConnection },\n} = cfg;\nvoid createConnection({ host: 'x' });` },
    { form: 'a type-only namespace import used only in a type position (unchanged)', source: `import type * as http from 'node:http';\ntype Conn = http.Server;\nvoid 0 as unknown as Conn;` },
  ];
  for (const { form, source } of nestedAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
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
    // NOTE: 'extracting createServer to a const via access'
    // (`const cs = http.createServer; cs(() => {});`) was RECLASSIFIED out of this permissive
    // family — CREATE_SERVER constructor forwarding is outside the positive authority model
    // (DDR-CREATE-SERVER-ALIAS-POLICY). It now asserts REJECT in the createServer describe below.
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
// NET createServer constructor positive-model restriction (DDR-CREATE-SERVER-ALIAS-POLICY,
// Codex finding PRRT_kwDOTzqfcs6dkiEI / P1 "Track createServer aliases before inspecting
// handlers", Option A). The one permitted node:http value capability — the inbound-server
// constructor `createServer` — may itself REMAIN only in the smallest approved direct-call
// forms (a call callee, or a type position); any position that forwards or stores the
// constructor value (an alias, an assignment target, a call argument, a return, an array/
// object element or spread, an export of the binding) is a rejected escape, decided at THAT
// occurrence. This REDUCES accepted authority: it introduces no alias/value-flow tracking — a
// receiving binding such as `start`/`cs` is never classified, so the closure of the Codex
// witness (`const start = http.createServer; start(req => …req.socket…)`) comes from
// `http.createServer` being stored, not from following `start`. The returned Server object is
// a separate NONE value, so the CALL RESULT (`const server = http.createServer(...)`, its
// `.listen(...)`, and its export) is untouched. Binder identity remains authoritative, so an
// unrelated or shadowed local `createServer` stays an ordinary local.
// ---------------------------------------------------------------------------
describe('D3 host restricts the createServer constructor to direct-call positions (DDR-CREATE-SERVER-ALIAS-POLICY)', () => {
  const createServerReject: readonly { readonly form: string; readonly source: string }[] = [
    // 1 — const alias from http.createServer (also the reclassified NET-ESCAPE permissive case:
    //     `const cs = http.createServer; cs(() => {})` previously asserted ALLOW).
    { form: 'a const alias of http.createServer', source: `import * as http from 'node:http';\nconst start = http.createServer;\nstart(() => {});` },
    { form: 'the reclassified permissive alias-then-call case', source: `import * as http from 'node:http';\nconst cs = http.createServer;\ncs(() => {});` },
    // 2 — alias of a directly-extracted (destructured) createServer.
    { form: 'a const alias of a destructured createServer', source: `import * as http from 'node:http';\nconst { createServer } = http;\nconst start = createServer;\nstart(() => {});` },
    // 3 — post-declaration assignment of the constructor.
    { form: 'a post-declaration assignment of http.createServer', source: `import * as http from 'node:http';\nlet start;\nstart = http.createServer;\nstart(() => {});` },
    // 4 — call-argument forwarding of the constructor.
    { form: 'forwarding http.createServer as a call argument', source: `import * as http from 'node:http';\ndeclare function run(x: unknown): void;\nrun(http.createServer);` },
    // 5 — returning the constructor.
    { form: 'returning http.createServer', source: `import * as http from 'node:http';\nexport function g(): unknown {\n  return http.createServer;\n}` },
    // 6 — array storage of the constructor.
    { form: 'storing http.createServer in an array', source: `import * as http from 'node:http';\nconst x = [http.createServer];\nvoid x;` },
    // 7 — object storage of the constructor (property value and spread+property).
    { form: 'storing http.createServer in an object property', source: `import * as http from 'node:http';\nconst x = { start: http.createServer };\nvoid x;` },
    { form: 'storing http.createServer in a spread object property', source: `import * as http from 'node:http';\nconst base = {};\nconst x = { ...base, start: http.createServer };\nvoid x;` },
    // 8 — export of the constructor capability (named import re-exported; destructured re-exported).
    { form: 'exporting a named createServer import binding', source: `import { createServer } from 'node:http';\nexport { createServer };` },
    { form: 'exporting a destructured createServer binding', source: `import * as http from 'node:http';\nconst { createServer } = http;\nexport { createServer };` },
  ];
  for (const { form, source } of createServerReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // 9 — the exact Codex witness: the constructor is forwarded to `start`, then the handler
  //     reaches the underlying socket through a runtime-computed key. Rejection is because
  //     `http.createServer` is stored, NOT because `start` is tracked.
  it('REJECTS the exact Codex runtime-key handler witness', () => {
    const source = [
      `import http from 'node:http';`,
      ``,
      `const start = http.createServer;`,
      ``,
      `start(req => {`,
      `  const key = (req.url ?? '').slice(1);`,
      `  const s = (req as any)[key];`,
      ``,
      `  s.destroy();`,
      `  setTimeout(() => s.connect(80, 'example.com'), 50);`,
      `});`,
    ].join('\n');
    expect(usesOutboundNetwork(source)).toBe(true);
  });

  const createServerAllow: readonly { readonly form: string; readonly source: string }[] = [
    // 10–11 — the direct namespace call and the static-element call.
    { form: 'a direct http.createServer(...) call', source: `import http from 'node:http';\nhttp.createServer(() => {});` },
    { form: `a direct http['createServer'](...) call`, source: `import * as http from 'node:http';\nhttp['createServer'](() => {});` },
    // 12–13 — a direct named import call and a renamed named import call.
    { form: 'a direct named createServer import call', source: `import { createServer } from 'node:http';\ncreateServer(() => {});` },
    { form: 'a direct renamed named createServer import call', source: `import { createServer as mk } from 'node:http';\nmk(() => {});` },
    // 14–15 — a direct destructuring call and a renamed destructuring call.
    { form: 'a direct destructured createServer call', source: `import * as http from 'node:http';\nconst { createServer } = http;\ncreateServer(() => {});` },
    { form: 'a direct renamed destructured createServer call', source: `import * as http from 'node:http';\nconst { createServer: mk } = http;\nmk(() => {});` },
    // 16–17 — storing and exporting the CALL RESULT (the Server object, capability NONE).
    { form: 'storing the createServer call RESULT', source: `import http from 'node:http';\nconst server = http.createServer(() => {});\nvoid server;` },
    { form: 'exporting the createServer call RESULT', source: `import http from 'node:http';\nexport const server = http.createServer(() => {});` },
    // 18–19 — an unrelated local createServer, and a shadowed parameter createServer.
    { form: 'an unrelated local object method createServer', source: `const local = {\n  createServer() {},\n};\nlocal.createServer();` },
    { form: 'a shadowed parameter named createServer', source: `function f(createServer: () => void) {\n  createServer();\n}\nvoid f;` },
    // 20 — the returned Server object's own methods (e.g. listen) are unchanged.
    { form: 'the returned server.listen(...) behavior', source: `import http from 'node:http';\nconst server = http.createServer(() => {});\nserver.listen(4317);` },
  ];
  for (const { form, source } of createServerAllow) {
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

// ---------------------------------------------------------------------------
// NET direct dynamic-import receiver + runtime-export completeness
// (D3-CX-POLICY-NET-DIRECT). Finite completeness of the agreed model: a statically-
// resolved `import('node:http')` is HTTP_NS authority even as a direct expression
// receiver (no binding); a named node:http CLIENT import and an exported dynamic-import
// declaration are node:http authority crossing the module boundary. Same lexical
// binding identity, same createServer-only rule — no new mechanism.
// ---------------------------------------------------------------------------
describe('D3 host closes direct dynamic-import receivers and runtime capability exports (D3-CX-POLICY-NET-DIRECT)', () => {
  const directReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a direct dynamic-import statically-keyed createServer', source: `(await import('node:http'))['createServer'](() => {});` },
    { form: 'a direct dynamic-import createServer', source: `(await import('node:http')).createServer(() => {});` },
    { form: 'a direct dynamic-import .request', source: `(await import('node:http')).request('http://example.com/').end();` },
    { form: 'a direct dynamic-import .get', source: `(await import('node:http')).get('http://example.com/');` },
    { form: 'a direct dynamic-import new .ClientRequest', source: `new (await import('node:http')).ClientRequest('http://example.com/');` },
    { form: 'a direct dynamic-import new .Agent', source: `void new (await import('node:http')).Agent();` },
    { form: 'a direct dynamic-import indeterminate member', source: `declare const k: string;\nvoid (await import('node:http'))[k];` },
  ];
  for (const { form, source } of directReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }
  const directAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a direct dynamic import of an unrelated module', source: `void (await import('node:url')).pathToFileURL('x');` },
  ];
  for (const { form, source } of directAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  const exportReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a named request import re-exported', source: `import { request } from 'node:http';\nexport { request };` },
    { form: 'an aliased named request import re-exported', source: `import { request as req } from 'node:http';\nexport { req };` },
    { form: 'a named get import re-exported', source: `import { get } from 'node:http';\nexport { get };` },
    { form: 'a named ClientRequest import re-exported', source: `import { ClientRequest } from 'node:http';\nexport { ClientRequest };` },
    { form: 'a named Agent import re-exported', source: `import { Agent } from 'node:http';\nexport { Agent };` },
    { form: 'an exported destructured namespace client member', source: `import * as http from 'node:http';\nexport const { request } = http;` },
  ];
  for (const { form, source } of exportReject) {
    it(`REJECTS export of ${form}`, () => {
      const sf = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf)).toBe(true);
    });
  }
  const exportAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a named createServer import re-exported', source: `import { createServer } from 'node:http';\nexport { createServer };` },
    { form: 'an exported createServer-derived local', source: `import http from 'node:http';\nexport const server = http.createServer(() => {});` },
    { form: 'an exported destructured createServer', source: `import * as http from 'node:http';\nexport const { createServer } = http;` },
    { form: 'a type-only named import re-exported as type', source: `import type { IncomingMessage } from 'node:http';\nexport type { IncomingMessage };` },
    { form: 'an inline-type named import re-exported', source: `import { type IncomingMessage } from 'node:http';\nexport { type IncomingMessage };` },
    { form: 'a type-only star re-export from node:http', source: `export type * from 'node:http';` },
    { form: 'an ordinary application export', source: `export const HOST = '127.0.0.1';` },
  ];
  for (const { form, source } of exportAllow) {
    it(`ALLOWS export of ${form}`, () => {
      const sf = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// NET Option-B: runtime dynamic import of node:http is prohibited OUTRIGHT
// (D3-CX-POLICY-NET-OPTB). node:http authority may enter D3 only through STATIC imports;
// a runtime `import('node:http')` expression is rejected in every context, rooted at the
// import expression itself. Non-node:http dynamic imports and static createServer remain
// allowed. Export confinement consumes the same lexical binding classification.
// ---------------------------------------------------------------------------
describe('D3 host prohibits runtime dynamic import of node:http (D3-CX-POLICY-NET-OPTB)', () => {
  const optbReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an exported destructured dynamic-import client member', source: `export const { request } = await import('node:http');` },
    { form: 'an exported dynamic-import namespace declaration', source: `export const http = await import('node:http');` },
    { form: 'a namespace binding acquired from a dynamic import then exported', source: `const http = await import('node:http');\nexport { http };` },
    { form: 'a bare awaited dynamic import', source: `void (await import('node:http'));` },
    { form: 'a parenthesized awaited dynamic import', source: `void ((await import('node:http')));` },
    { form: 'a dynamic import passed as an argument', source: `declare function send(x: unknown): void;\nsend(await import('node:http'));` },
    { form: 'a returned dynamic import', source: `export async function g(): Promise<unknown> { return await import('node:http'); }` },
    { form: 'a dynamic import stored in an array', source: `const a = [await import('node:http')];\nvoid a;` },
    { form: 'a dynamic import stored in an object', source: `const o = { x: await import('node:http') };\nvoid o;` },
    { form: 'a dynamic import spread through an array', source: `const a = [...[await import('node:http')]];\nvoid a;` },
    { form: 'a dynamic import inside a conditional', source: `const x = true ? await import('node:http') : null;\nvoid x;` },
    { form: 'a dynamic import inside a logical expression', source: `const x = (globalThis as { f?: boolean }).f && (await import('node:http'));\nvoid x;` },
    { form: 'a for-header dynamic import binding', source: `for (const http = await import('node:http'); Math.random() > 1;) { http.request('http://example.com/'); }` },
    { form: 'a for-of over a dynamic import', source: `for (const _ of [await import('node:http')]) { void _; }` },
    { form: 'a destructuring off a dynamic import', source: `const { request } = await import('node:http');\nvoid request;` },
    { form: 'a default export of a dynamic import', source: `export default await import('node:http');` },
  ];
  for (const { form, source } of optbReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const optbAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a static default import createServer', source: `import http from 'node:http';\nhttp.createServer(() => {});` },
    { form: 'a static named createServer import', source: `import { createServer } from 'node:http';\ncreateServer(() => {});` },
    { form: 'a static createServer destructuring', source: `import * as http from 'node:http';\nconst { createServer } = http;\ncreateServer(() => {});` },
    { form: 'a dynamic import of an unrelated node builtin', source: `void (await import('node:url')).pathToFileURL('x');` },
    { form: 'a dynamic import of a relative module', source: `const m = await import('./local.js');\nvoid m;` },
    { form: 'a type-only node:http import used only in types', source: `import type { Server } from 'node:http';\nlet s: Server | null = null;\nvoid s;` },
  ];
  for (const { form, source } of optbAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // Export confinement (unified classification) closes the static destructure-then-export
  // residual and preserves type-only / ordinary exports.
  const exportReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a statically destructured request re-exported', source: `import * as http from 'node:http';\nconst { request } = http;\nexport { request };` },
    { form: 'a statically destructured aliased client re-exported', source: `import * as http from 'node:http';\nconst { get: g } = http;\nexport { g };` },
    { form: 'a namespace binding re-exported', source: `import * as http from 'node:http';\nexport { http };` },
    { form: 'a named client import re-exported', source: `import { request } from 'node:http';\nexport { request };` },
    { form: 'an export-equals of a namespace binding', source: `import http = require('node:http');\nexport = http;` },
  ];
  for (const { form, source } of exportReject) {
    it(`REJECTS export of ${form}`, () => {
      const sf = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf)).toBe(true);
    });
  }
  const exportAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an exported created server instance', source: `import http from 'node:http';\nexport const server = http.createServer(() => {});` },
    { form: 'a destructured createServer re-exported', source: `import * as http from 'node:http';\nconst { createServer } = http;\nexport { createServer };` },
    { form: 'an ordinary application export', source: `export const HOST = '127.0.0.1';` },
    { form: 'a relative re-export', source: `export { foo } from './x.js';` },
    { form: 'a type-only re-export', source: `import type { Server } from 'node:http';\nexport type { Server };` },
  ];
  for (const { form, source } of exportAllow) {
    it(`ALLOWS export of ${form}`, () => {
      const sf = ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      expect(exportsHttpCapability(sf)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// SOCK final bounded D3 socket policy (D3-CX-POLICY-NET-SOCK). Finite, purely syntactic, no
// taint/alias/type/whole-program: RULE A — a GLOBAL static ban on acquiring a socket-ACQUISITION
// NAME by any statically identifiable property/binding key, receiver- AND position-independent.
// The name family is (i) the socket-value names `socket`/`connection` and (ii) the socket-delivery
// member names `on`/`once`/`addListener`/`prependListener`/`prependOnceListener`/`setTimeout` —
// the permitted http.Server callbacks that hand over a socket, with no event-name list. Anchoring
// on the NAME (not the call callee) folds in the former registrar ban and closes the indirect
// family: `server.on(...)`, `server.on.call/apply/bind(...)`, `Reflect.apply(server.on, …)`,
// `const m = server.on` (F2), and `server.setTimeout(…, socket => …)` (F1). RULE A2 — on the
// request/response parameters of a function literal passed directly to a permitted `createServer`,
// an indeterminate computed element access fails closed (socket/connection semantics unchanged).
// Accepted, intentional false positives: an unrelated `camera.socket`, `emitter.on('ready', …)`,
// or `obj.setTimeout(…)` is rejected because real host/cockpit source uses none of these names.
// The alias + runtime-computed residual (`const r = request; r[runtimeKey]`, or `server[k]` with
// runtime `k`) is the frozen honest boundary, deliberately not closed here.
// ---------------------------------------------------------------------------
describe('D3 host enforces the final bounded socket-capability source policy (D3-CX-POLICY-NET-SOCK)', () => {
  it('accepts every real host source (no host source acquires the inbound socket)', () => {
    for (const { file, text } of hostSources()) {
      expect(usesOutboundNetwork(text), `${file} acquires the inbound server socket`).toBe(false);
    }
  });

  // The reported F1 transitive-egress reproduction: the permitted createServer path used to
  // reach `req.socket` and call `.connect(...)` outbound. Rejected now at the acquisition.
  it('rejects the reported req.socket transitive-outbound reproduction', () => {
    expect(
      usesOutboundNetwork(
        `import http from 'node:http';\n` +
          `http.createServer((req: http.IncomingMessage) => {\n` +
          `  req.socket.destroy();\n` +
          `  req.socket.connect(80, 'example.com');\n` +
          `});`,
      ),
    ).toBe(true);
  });

  const H = `import http from 'node:http';\n`;
  const handler = (body: string): string =>
    H + `http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {\n${body}\n});`;

  // --- RULE A: GLOBAL static socket/connection NAME ban (any receiver) — MUST REJECT ---
  const ruleAReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an unrelated camera.socket (accepted global false positive)', source: `const camera = { socket: 1 };\nvoid camera.socket;` },
    { form: 'an unrelated thing.connection (accepted global false positive)', source: `const thing = { connection: 'local' };\nvoid thing.connection;` },
    { form: 'a plain local named request with a .socket member', source: `const request = { socket: 1 };\nvoid request.socket;` },
    { form: 'a direct req.socket member', source: handler(`req.socket.destroy();`) },
    { form: 'a direct req.connection member', source: handler(`req.connection.destroy();`) },
    { form: 'a res.socket member', source: handler(`void res.socket;`) },
    { form: 'an optional req?.socket access', source: handler(`void req?.socket;`) },
    { form: 'an optional obj?.connection access', source: `const obj: { connection?: unknown } = {};\nvoid obj?.connection;` },
    { form: 'an alias const s = req.socket', source: handler(`const s = req.socket;\nvoid s;`) },
    { form: "a static-computed req['socket'] access", source: handler(`void req['socket'];`) },
    { form: 'a template-computed req[`socket`] access', source: handler('void req[`socket`];') },
    { form: "a static-computed obj['connection'] on any receiver", source: `const obj: Record<string, unknown> = {};\nvoid obj['connection'];` },
    { form: 'the aliased-then-.socket escape (closed by the global name ban)', source: handler(`const r = req;\nvoid r.socket;`) },
    { form: 'a cross-function x.socket (closed by the global name ban)', source: H + `function h(x: { socket: unknown }): unknown { return x.socket; }\nhttp.createServer((req: http.IncomingMessage) => {\n  void h(req);\n});` },
  ];

  // --- RULE A: destructuring `{ socket }` / `{ connection }` (any binding pattern) — REJECT ---
  const destructureReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a { socket } destructuring off req', source: handler(`const { socket } = req;\nvoid socket;`) },
    { form: 'a { connection } destructuring off an unrelated object', source: `const obj = { connection: 1 };\nconst { connection } = obj;\nvoid connection;` },
    { form: 'an aliased { socket: s } destructuring off res', source: handler(`const { socket: s } = res;\nvoid s;`) },
    { form: 'a { connection: c } destructuring off req', source: handler(`const { connection: c } = req;\nvoid c;`) },
    { form: 'an inline { socket } destructuring parameter', source: H + `http.createServer(({ socket }: http.IncomingMessage) => {\n  void socket;\n});` },
    { form: 'a second-parameter { socket } destructuring', source: H + `http.createServer((_req: http.IncomingMessage, { socket }: http.ServerResponse) => {\n  void socket;\n});` },
    { form: 'a function parameter { connection } destructuring', source: `function f({ connection }: { connection: unknown }): void {\n  void connection;\n}\nvoid f;` },
  ];

  // --- RULE A2: createServer handler param indeterminate computed access — FAIL-CLOSED ---
  const ruleA2Reject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an indeterminate req[key] on the handler param', source: handler(`const key = req.url ?? '';\nvoid req[key];`) },
    { form: 'an indeterminate res[key] on the handler param', source: handler(`const key = req.url ?? '';\nvoid res[key];`) },
    { form: "a concatenated req['sock' + 'et'] on the handler param", source: handler(`void req['sock' + 'et'];`) },
    { form: 'a conditional req[c ? "socket" : "method"] on the handler param', source: handler(`const c = req.method === 'GET';\nvoid req[c ? 'socket' : 'method'];`) },
  ];

  // --- RULE A (promoted): registrar-name ban, now by NAME at any position (direct call form) ---
  const registrarNames = ['on', 'once', 'addListener', 'prependListener', 'prependOnceListener'];
  const anyEventNames = ['request', 'connection', 'dropRequest', 'ready'];
  const wrapperHead =
    H + `function makeServer(): http.Server {\n  return http.createServer(() => {});\n}\nconst server = makeServer();\n`;
  const eventReject: { readonly form: string; readonly source: string }[] = [];
  for (const reg of registrarNames) {
    for (const evt of anyEventNames) {
      eventReject.push({
        form: `a wrapper-return server.${reg}('${evt}', …)`,
        source: wrapperHead + `server.${reg}('${evt}', () => {});`,
      });
    }
  }
  const eventRejectSpecial: readonly { readonly form: string; readonly source: string }[] = [
    { form: "a 'request' event on a direct const server binding", source: H + `const server = http.createServer(() => {});\nserver.on('request', () => {});` },
    { form: "a 'connection' event on the direct createServer return chain", source: H + `http.createServer(() => {}).on('connection', () => {});` },
    { form: "a static-key registrar server['on']('request', …)", source: wrapperHead + `server['on']('request', () => {});` },
    { form: "an unrelated declared emitter registering 'ready' (accepted false positive)", source: `declare const ee: { on(event: string, cb: () => void): void };\nee.on('ready', () => {});` },
    { form: "a synthetic LocalEmitter registering 'anything' (accepted false positive)", source: `class LocalEmitter {\n  addListener(_event: string, _cb: () => void): void {}\n}\nconst emitter = new LocalEmitter();\nemitter.addListener('anything', () => {});` },
  ];

  // --- ADVERSARIAL MATRIX (frozen DDR): F1 setTimeout surface + F2 indirect-registrar family.
  //     Each is closed by the RULE A member-NAME ban (the banned name is a property/element
  //     access somewhere in the source), with NO witness-specific `.call`/`.apply`/`.bind` list. ---
  const familyReject: readonly { readonly form: string; readonly source: string }[] = [
    // F1 — server.setTimeout delivers the connection socket to its callback.
    { form: 'F1: server.setTimeout(t, socket => socket.connect(...))', source: wrapperHead + `server.setTimeout(2000, (socket: { connect(p: number, h: string): void }) => {\n  socket.connect(80, 'example.com');\n});` },
    { form: 'F1: server.setTimeout acquired via .bind', source: wrapperHead + `const t = server.setTimeout.bind(server);\nvoid t;` },
    // F2 — the same registrar reached indirectly; the inner `server.on` name is what is banned.
    { form: 'F2: server.on.call(server, "connection", …)', source: wrapperHead + `server.on.call(server, 'connection', (socket: unknown) => {\n  void socket;\n});` },
    { form: 'F2: server.on.apply(server, [...])', source: wrapperHead + `server.on.apply(server, ['connection', (socket: unknown) => {\n  void socket;\n}]);` },
    { form: 'F2: server.on.bind(server)(...)', source: wrapperHead + `const reg = server.on.bind(server);\nreg('connection', (socket: unknown) => {\n  void socket;\n});` },
    { form: 'F2: Reflect.apply(server.on, server, [...])', source: wrapperHead + `Reflect.apply(server.on, server, ['connection', (socket: unknown) => {\n  void socket;\n}]);` },
    { form: 'F2: method-extraction const m = server.on; m.call(...)', source: wrapperHead + `const m = server.on;\nm.call(server, 'connection', (socket: unknown) => {\n  void socket;\n});` },
    { form: 'F2: static-key extraction server["on"].call(...)', source: wrapperHead + `server['on'].call(server, 'connection', () => {});` },
    { form: 'F2: const m = server.on rejected at acquisition (no call)', source: wrapperHead + `const m = server.on;\nvoid m;` },
    { form: 'F2: server.once.call(server, "upgrade", …)', source: wrapperHead + `server.once.call(server, 'upgrade', () => {});` },
    // Intentionally broad static policy — unrelated .on / .setTimeout are rejected too.
    { form: 'benign unrelated object.on (accepted broad-policy false positive)', source: `const obj = { on(_e: string, _c: () => void): void {} };\nobj.on('x', () => {});` },
    { form: 'benign unrelated object.setTimeout (accepted broad-policy false positive)', source: `const timer = { setTimeout(_m: number, _c: () => void): void {} };\ntimer.setTimeout(0, () => {});` },
  ];

  for (const { form, source } of [
    ...ruleAReject,
    ...destructureReject,
    ...ruleA2Reject,
    ...eventReject,
    ...eventRejectSpecial,
    ...familyReject,
  ]) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- MUST ALLOW: the legitimate request/response surface and unrelated non-socket shapes ---
  const sockAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'the ordinary request.method read', source: handler(`const m = req.method ?? '';\nvoid m;`) },
    { form: 'the ordinary request.url read', source: handler(`const u = req.url ?? '';\nvoid u;`) },
    { form: 'the ordinary response surface', source: handler(`res.statusCode = 200;\nres.setHeader('X', 'Y');\nres.end('ok');`) },
    { form: "a static request['method'] access on the handler param", source: handler(`void req['method'];`) },
    { form: 'a template request[`url`] access on the handler param', source: handler('void req[`url`];') },
    { form: 'an empty createServer handler', source: H + `http.createServer(() => {});` },
    { form: 'a listen call on a const server binding', source: H + `const server = http.createServer(() => {});\nserver.listen(4317, '127.0.0.1');` },
    { form: 'unrelated array[index] indexing', source: `const array: readonly number[] = [];\nconst index = 0;\nvoid array[index];` },
    { form: 'unrelated text[character] indexing', source: `const text = 'abc';\nconst character = 1;\nvoid text[character];` },
    { form: 'unrelated object[key] indexing', source: `const object: Record<string, number> = {};\nconst key = 'a';\nvoid object[key];` },
    { form: 'a non-socket ordinary member on an unrelated object', source: `const obj = { value: 1 };\nvoid obj.value;` },
    // Matrix item 17 — the frozen honest boundary stays OUTSIDE the proof; the mechanism must
    // NOT be broadened to close it (doing so would need alias/type/whole-program analysis).
    { form: 'the frozen alias + runtime-key residual on req (remains allowed)', source: handler(`const r = req;\nconst k = req.url ?? '';\nvoid r[k];`) },
    { form: 'the frozen runtime-computed server[k] residual (remains allowed)', source: wrapperHead + `const k = String(4317);\nvoid server[k];` },
  ];
  for (const { form, source } of sockAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // --- DDR-B: statically CONSTRUCTED socket-acquisition KEYS resolve via the binder-aware
  //     `sockResolveKey` (`netResolveKey`), any receiver — MUST REJECT. `server['o' + 'n']` is the
  //     reported reproduction. A genuinely runtime key is Indeterminate and stays outside. ---
  const ddrBReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: "the reported server['o' + 'n']('connection', …) reproduction", source: wrapperHead + `server['o' + 'n']('connection', (s: { destroy(): void; connect(p: number, h: string): void }) => {\n  s.destroy();\n  setTimeout(() => s.connect(80, 'example.com'), 50);\n});` },
    { form: "a literal server['on']", source: wrapperHead + `server['on']('connection', () => {});` },
    { form: "a const-bound key const k = 'on'; server[k]", source: wrapperHead + `const k = 'on';\nserver[k]('connection', () => {});` },
    { form: 'a template server[`on`]', source: wrapperHead + 'server[`on`](\'connection\', () => {});' },
    { form: "a concatenated socket value server['sock' + 'et']", source: wrapperHead + `void server['sock' + 'et'];` },
    { form: "a concatenated server['connec' + 'tion']", source: wrapperHead + `void server['connec' + 'tion'];` },
    { form: "a concatenated setTimeout server['set' + 'Timeout']", source: wrapperHead + `void server['set' + 'Timeout'];` },
    { form: "the destructuring twin const { ['o'+'n']: h } = server", source: wrapperHead + `const { ['o' + 'n']: h } = server;\nvoid h;` },
    { form: "a const-bound destructuring key const k='socket'; { [k]: s } = server", source: wrapperHead + `const k = 'socket';\nconst { [k]: s } = server;\nvoid s;` },
  ];
  for (const { form, source } of ddrBReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- DDR-B: the frozen runtime-computed boundary stays OUTSIDE the proof — MUST ALLOW.
  //     A key the binder cannot pin to a static string (a call result, an ambient runtime name) is
  //     Indeterminate; closing it would need alias/type/whole-program flow, deliberately excluded. ---
  const ddrBAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a genuinely runtime server[runtimeKey] (declared, unresolvable)', source: wrapperHead + `declare const runtimeKey: string;\nvoid server[runtimeKey];` },
    { form: 'a call-result key server[String(4317)] (unresolvable)', source: wrapperHead + `void server[String(4317)];` },
    { form: 'a harmless resolvable non-socket key server["lis" + "ten"]', source: wrapperHead + `void server['lis' + 'ten'];` },
  ];
  for (const { form, source } of ddrBAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // --- DDR-B (STATIC-TEMPLATE PARITY): a socket-acquisition KEY spelled as a SUBSTITUTED template
  //     `` server[`o${'n'}`] `` denotes the same static string as `server['on']` / `server['o'+'n']`,
  //     but its key node is a `TemplateExpression` (not `StringLiteralLike`, not a `+` BinaryExpression,
  //     not an Identifier), so the bounded static-key resolver (`netResolveKey`, via `sockResolveKey`)
  //     previously fell through to Indeterminate — and an Indeterminate key rejects only on a tracked
  //     req/res receiver, so with an http.Server receiver the registrar escaped. A `TemplateExpression`
  //     is folded EXACTLY like the `+`-fold: `head.text` + resolved(span.expression) + span.literal.text
  //     for every span, each substitution resolved through the SAME binder-aware machinery (string
  //     literal / `+`-fold / unique-const identity), reusing the SAME depth/visit/length bounds. Every
  //     substitution must be independently bounded-static; if ANY is mutable/ambient/runtime the whole
  //     template stays Indeterminate (see the allow block). The no-substitution `` server[`on`] `` is
  //     already `StringLiteralLike` and handled above. MUST REJECT. ---
  const ddrBTemplateReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'the reported server[`o${\'n\'}`](\'connection\', …) registrar extraction + reconnect', source: wrapperHead + 'server[`o${\'n\'}`](\'connection\', (s: { destroy(): void; connect(p: number, h: string): void }) => {\n  s.destroy();\n  setTimeout(() => s.connect(80, \'example.com\'), 50);\n});' },
    { form: 'a whole-key substitution server[`${\'on\'}`]', source: wrapperHead + 'server[`${\'on\'}`](\'connection\', () => {});' },
    { form: 'a const-substitution server[`${a}n`] with const a = \'o\'', source: wrapperHead + 'const a = \'o\';\nserver[`${a}n`](\'connection\', () => {});' },
    { form: 'a two-const-substitution server[`${a}${b}`] with a=\'o\', b=\'n\'', source: wrapperHead + 'const a = \'o\';\nconst b = \'n\';\nserver[`${a}${b}`](\'connection\', () => {});' },
    { form: 'a delivery member server[`set${\'Timeout\'}`]', source: wrapperHead + 'void server[`set${\'Timeout\'}`];' },
    { form: 'a capability name server[`sock${\'et\'}`]', source: wrapperHead + 'void server[`sock${\'et\'}`];' },
    { form: 'a binder-pinned const under a same-text shadow in another scope server[`${a}n`]', source: wrapperHead + 'const a = \'o\';\nfunction other(): string {\n  const a = \'zz\';\n  return a;\n}\nvoid other;\nserver[`${a}n`](\'connection\', () => {});' },
  ];
  for (const { form, source } of ddrBTemplateReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- DDR-B (STATIC-TEMPLATE PARITY): the frozen indeterminate boundary is UNCHANGED — a template
  //     with ANY non-bounded-static substitution (runtime/ambient identifier, mutable `let` binding,
  //     unresolvable call) stays Indeterminate, so on a non-req/res receiver it is NOT flagged. Only a
  //     fully binder-static template folds. MUST ALLOW. ---
  const ddrBTemplateAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a runtime-substituted server[`o${runtime}n`] (declared, unresolvable)', source: wrapperHead + 'declare const runtime: string;\nvoid server[`o${runtime}n`];' },
    { form: 'a mutable-binding server[`${a}n`] with let a = \'o\'', source: wrapperHead + 'let a = \'o\';\na = \'o\';\nvoid server[`${a}n`];' },
    { form: 'a call-result substitution server[`o${String(1)}`] (unresolvable)', source: wrapperHead + 'void server[`o${String(1)}`];' },
    { form: 'a harmless resolvable non-socket template server[`lis${\'ten\'}`]', source: wrapperHead + 'void server[`lis${\'ten\'}`];' },
  ];
  for (const { form, source } of ddrBTemplateAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // --- ASSIGNMENT-DESTRUCTURING PARITY (SOCK, DELIVERY/REGISTRAR members ONLY): `({ on: register } =
  //     server)` extracts the registrar off `server` exactly like the declaration twin
  //     `const { on: register } = server`, but the target is an ObjectLiteralExpression (Shorthand/
  //     PropertyAssignment), not a BindingElement, so RULE A (c) did not see it and the req/res-bound
  //     RULE A2 assignment branch (SOCKET_CAPABILITY names, req/res receivers) skipped a `server`
  //     receiver. The new receiver-independent branch closes ONLY the delivery/registrar-member family
  //     (`SOCKET_DELIVERY_MEMBERS`: on/once/addListener/prependListener/prependOnceListener/setTimeout),
  //     resolved by the SAME `sockResolveKey`/`staticKeyText` as RULE A (c). The socket/connection
  //     CAPABILITY names are DELIBERATELY NOT broadened (accepted D3-CX-CODEX-ASSIGN invariant); see the
  //     allow block below. MUST REJECT. ---
  const assignDestructureReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'the reported ({ on: register } = server) registrar extraction + reconnect', source: wrapperHead + `let register: (this: unknown, e: string, cb: (s: { destroy(): void; connect(p: number, h: string): void }) => void) => void;\n({ on: register } = server as unknown as { on: typeof register });\nregister.call(server, 'connection', (socket) => {\n  socket.destroy();\n  setTimeout(() => socket.connect(80, 'example.com'), 50);\n});` },
    { form: 'a shorthand ({ on } = server)', source: wrapperHead + `let on: unknown;\n({ on } = server as unknown as { on: unknown });\nvoid on;` },
    { form: "a static-computed ({ ['on']: register } = server)", source: wrapperHead + `let register: unknown;\n({ ['on']: register } = server as unknown as { on: unknown });\nvoid register;` },
    { form: "a concatenated ({ ['o' + 'n']: register } = server)", source: wrapperHead + `let register: unknown;\n({ ['o' + 'n']: register } = server as unknown as Record<string, unknown>);\nvoid register;` },
    { form: "a const-bound ({ [k]: register } = server) with const k = 'on'", source: wrapperHead + `const k = 'on';\nlet register: unknown;\n({ [k]: register } = server as unknown as Record<string, unknown>);\nvoid register;` },
    { form: 'a setTimeout member ({ setTimeout: t } = server)', source: wrapperHead + `let t: unknown;\n({ setTimeout: t } = server as unknown as { setTimeout: unknown });\nvoid t;` },
    { form: 'a once member ({ once: h } = server)', source: wrapperHead + `let h: unknown;\n({ once: h } = server as unknown as { once: unknown });\nvoid h;` },
    { form: 'a nested ({ inner: { on: register } } = wrap) parity with RULE A (c)', source: wrapperHead + `let register: unknown;\nconst wrap = { inner: server } as unknown as { inner: { on: unknown } };\n({ inner: { on: register } } = wrap);\nvoid register;` },
  ];
  for (const { form, source } of assignDestructureReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- ASSIGNMENT-DESTRUCTURING PARITY (SOCK) — the DELIBERATE asymmetry: the new receiver-independent
  //     branch is scoped to DELIVERY/REGISTRAR members only, so socket/connection CAPABILITY assignment
  //     extraction keeps its accepted req/res-sensitive semantics (the D3-CX-CODEX-ASSIGN "no global
  //     broadening" invariant) — `({ socket } = unrelatedObject)` / `({ socket } = server)` /
  //     `({ connection } = unrelatedObject)` remain ALLOWED. The delivery branch also adds NO global
  //     fail-closed on indeterminate keys and NO receiver/alias/taint tracking, so a harmless key and an
  //     indeterminate key on an unrelated object stay allowed. MUST ALLOW. ---
  const assignDestructureAllow: readonly { readonly form: string; readonly source: string }[] = [
    // The accepted D3-CX-CODEX-ASSIGN invariant, asserted adjacently here as a preservation guard.
    { form: 'the preserved ({ socket: localSocket } = unrelatedObject) capability invariant', source: `const unrelatedObject = { socket: 123 };\nlet localSocket: unknown;\n({ socket: localSocket } = unrelatedObject);\nvoid localSocket;` },
    { form: 'a capability ({ socket: s } = server) stays req/res-bound (NOT delivery-broadened)', source: wrapperHead + `let s: unknown;\n({ socket: s } = server as unknown as { socket: unknown });\nvoid s;` },
    { form: 'a capability ({ connection: c } = unrelatedObject) is NOT globally banned', source: `const unrelatedObject = { connection: 1 };\nlet c: unknown;\n({ connection: c } = unrelatedObject);\nvoid c;` },
    { form: 'a harmless ({ harmless: x } = arbitraryObject)', source: `const arbitraryObject: Record<string, unknown> = {};\nlet x: unknown;\n({ harmless: x } = arbitraryObject);\nvoid x;` },
    { form: 'a harmless shorthand ({ method } = arbitraryObject)', source: `const arbitraryObject: Record<string, unknown> = {};\nlet method: unknown;\n({ method } = arbitraryObject);\nvoid method;` },
    { form: 'an INDETERMINATE key on an unrelated object stays outside the proof', source: `declare const runtimeKey: string;\nconst arbitraryObject: Record<string, unknown> = {};\nlet x: unknown;\n({ [runtimeKey]: x } = arbitraryObject);\nvoid x;` },
  ];
  for (const { form, source } of assignDestructureAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // --- CODEX F1 BINDER-KEY MATRIX (SOCK consolidation): the socket acquisition key is now resolved
  //     by TypeScript BINDER identity (`sockResolveKey` → `netResolveKey`), so an unrelated shadowing
  //     same-text `const` in another scope NEVER makes a binder-pinned key unresolved the way the
  //     whole-file text collector did. M2/M4/M6 are the regression witnesses: under the old
  //     text-keyed `collectStringConsts`/`staticStringOf` the sibling `const` demoted the key to
  //     UNKNOWN (fail-open); the binder pins the exact declaration and REJECTS. MUST REJECT. ---
  const binderKeyReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: "M1: const k='on'; server[k]('connection', …)", source: wrapperHead + `const k = 'on';\nserver[k]('connection', () => {});` },
    { form: "M2: M1 with an unrelated shadowing const k='noop' (regression witness)", source: wrapperHead + `const k = 'on';\nserver[k]('connection', () => {});\nfunction unrelated(): void {\n  const k = 'noop';\n  void k;\n}\nvoid unrelated;` },
    { form: "M3: const key='socket'; req[key]", source: handler(`const key = 'socket';\nvoid req[key];`) },
    { form: "M4: M3 with an unrelated shadowing const key='x' (regression witness)", source: handler(`const key = 'socket';\nfunction unrelated(): void {\n  const key = 'x';\n  void key;\n}\nvoid req[key];\nvoid unrelated;`) },
    { form: "M5: const k='on'; const { [k]: h } = server", source: wrapperHead + `const k = 'on';\nconst { [k]: h } = server;\nvoid h;` },
    { form: "M6: M5 with an unrelated shadowing const k='noop' (regression witness)", source: wrapperHead + `const k = 'on';\nfunction unrelated(): void {\n  const k = 'noop';\n  void k;\n}\nconst { [k]: h } = server;\nvoid h;\nvoid unrelated;` },
    { form: "M7: server['o' + 'n']('connection', …)", source: wrapperHead + `server['o' + 'n']('connection', () => {});` },
    { form: "M8: const k='connection'; server[k]", source: wrapperHead + `const k = 'connection';\nvoid server[k];` },
    { form: "M9: const k='setTimeout'; server[k](…)", source: wrapperHead + `const k = 'setTimeout';\nserver[k](0, () => {});` },
    { form: "M10: direct literal server['on']('connection', …)", source: wrapperHead + `server['on']('connection', () => {});` },
    // M13 — the RULE A2 fail-closed floor is preserved: a genuinely runtime key on a createServer
    //     req/res param is DENIED (Indeterminate + receiverIsReqRes).
    { form: "M13: req[runtimeKey] stays RULE A2 fail-closed on the handler param", source: handler(`declare const runtimeKey: string;\nvoid req[runtimeKey];`) },
  ];
  for (const { form, source } of binderKeyReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- CODEX F1 BINDER-KEY MATRIX (preserve): a runtime key on an unrelated receiver stays OUTSIDE
  //     the frozen proof, a provably-harmless key is allowed, and — resolved by the SAME binder
  //     identity — a harmless key is NEVER flipped by a shadowing socket-named sibling const
  //     (M16 exercises binder identity in the ALLOW direction). MUST ALLOW. ---
  const binderKeyAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: "M11: server[runtimeKey] on an unrelated receiver stays outside the proof", source: wrapperHead + `declare const runtimeKey: string;\nvoid server[runtimeKey];` },
    { form: "M12: server[String(4317)] stays outside the static proof", source: wrapperHead + `void server[String(4317)];` },
    { form: "M14: req['method'] stays allowed", source: handler(`void req['method'];`) },
    { form: "M15: harmless static server['listen'] stays allowed", source: wrapperHead + `void server['listen'];` },
    { form: "M16: a harmless key is not flipped by a shadowing socket-named sibling const", source: wrapperHead + `const k = 'listen';\nfunction unrelated(): void {\n  const k = 'on';\n  void k;\n}\nvoid server[k];\nvoid unrelated;` },
  ];
  for (const { form, source } of binderKeyAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// DDR-A — a global-object SELF-REFERENCE chain (`globalThis.globalThis`, `window.window`,
// `globalThis.global`, …) denotes the real global, so a network member read off it is egress.
// Recognition is structural and finite (each hop is a member name in GLOBAL_RECEIVER_NAMES off
// a recursively-global receiver); binder/shadowing authority stays at the BASE identifier, so a
// shadowed base is an ordinary object and the `const g = globalThis.globalThis; g.fetch()` alias
// residual stays OUTSIDE the frozen boundary (no alias/value-flow).
// ---------------------------------------------------------------------------
describe('D3 host recognizes global-object self-reference chains as global receivers (DDR-A)', () => {
  const selfRefReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'globalThis.fetch (base case)', source: `globalThis.fetch('https://evil.example/');` },
    { form: 'globalThis.globalThis.fetch', source: `globalThis.globalThis.fetch('https://evil.example/');` },
    { form: 'globalThis.global.fetch', source: `globalThis.global.fetch('https://evil.example/');` },
    { form: 'globalThis.window.fetch (fail-closed)', source: `globalThis.window.fetch('https://evil.example/');` },
    { form: 'window.window.fetch', source: `window.window.fetch('https://evil.example/');` },
    { form: 'self.self.fetch', source: `self.self.fetch('https://evil.example/');` },
    { form: 'multi-hop globalThis.globalThis.globalThis.fetch', source: `globalThis.globalThis.globalThis.fetch('https://evil.example/');` },
    { form: "string-literal hop globalThis['globalThis'].fetch", source: `globalThis['globalThis'].fetch('https://evil.example/');` },
    { form: 'a self-reference chain to the second global new globalThis.globalThis.WebSocket(...)', source: `void new globalThis.globalThis.WebSocket('wss://evil.example/');` },
    { form: 'destructuring fetch off a self-reference chain', source: `const { fetch } = globalThis.globalThis;\nvoid fetch('https://evil.example/');` },
  ];
  for (const { form, source } of selfRefReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const selfRefAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a shadowed base parameter globalThis (ordinary local object)', source: `function f(globalThis: { globalThis: { fetch(x: string): void } }): void {\n  globalThis.globalThis.fetch('https://evil.example/');\n}\nvoid f;` },
    { form: 'an unrelated obj.globalThis.fetch (base not a global receiver)', source: `const obj = { globalThis: { fetch: (x: string) => x } };\nvoid obj.globalThis.fetch('x');` },
    { form: 'the frozen alias residual const g = globalThis.globalThis; g.fetch() (remains allowed)', source: `const g = globalThis.globalThis;\nvoid g.fetch('https://evil.example/');` },
    { form: 'a non-network member off a self-reference chain globalThis.globalThis.crypto', source: `void globalThis.globalThis.crypto;` },
  ];
  for (const { form, source } of selfRefAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // RC twin — the SAME self-reference recursion in the structural `isGlobalReceiver` closes
  //     `globalThis.globalThis.eval(...)` in the runtime-code-generation policy.
  const rcTwinReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'globalThis.globalThis.eval(...)', source: `globalThis.globalThis.eval("import('../domain/actions.js')");` },
    { form: 'window.window.Function(...)', source: `window.window.Function('return import("../domain/actions.js")')();` },
    { form: "string-literal hop globalThis['globalThis'].eval(...)", source: `globalThis['globalThis']['eval']("import('../domain/actions.js')");` },
  ];
  for (const { form, source } of rcTwinReject) {
    it(`rejects (RC twin) ${form}`, () => {
      expect(usesRuntimeCodeGeneration(source)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// DDR-NET-STATIC-KEY-PARITY — one bounded static-key abstraction across the NET free-global
// surface. F1: a global-object SELF-REFERENCE hop whose element-access key is statically provable
// (`globalThis['global' + 'This']`, `const k = 'globalThis'; globalThis[k]`,
// `` globalThis[`glob` + 'alThis'] ``) denotes the real global, exactly like the already-recognized
// dotted / string-literal hop, so a network member read off it is egress. F2: a network global
// extracted by DESTRUCTURING ASSIGNMENT (`({ fetch: f } = globalThis)`) — an ObjectLiteral target,
// not a binding pattern — is caught at the same free-global receiver as the declaration form, and a
// computed static destructuring key folds while an indeterminate one fails closed. The hop key, the
// member key, the declaration destructuring key, and the assignment destructuring key all resolve
// through the SAME binder resolver (`netResolveKey`); binder/shadowing authority stays with the base
// identifier, and a genuinely runtime key stays outside the frozen boundary. Capability is rejected
// at extraction — `f` is not followed onward through value flow.
// ---------------------------------------------------------------------------
describe('D3 host folds static keys in self-reference hops and destructuring assignments (DDR-NET-STATIC-KEY-PARITY)', () => {
  // ---- F1: self-reference hop static-key folding — DENY --------------------------------------
  const f1Reject: readonly { readonly form: string; readonly source: string }[] = [
    { form: '1. a dotted self-hop globalThis.globalThis.fetch', source: `globalThis.globalThis.fetch('https://evil.example/');` },
    { form: "2. a literal-element self-hop globalThis['globalThis'].fetch", source: `globalThis['globalThis'].fetch('https://evil.example/');` },
    { form: "3. a concatenated self-hop globalThis['global' + 'This'].fetch", source: `globalThis['global' + 'This'].fetch('https://evil.example/');` },
    { form: '4. a const-key self-hop globalThis[k].fetch', source: `const k = 'globalThis';\nglobalThis[k].fetch('https://evil.example/');` },
    { form: '5. a template/static self-hop globalThis[`glob` + `alThis`].fetch', source: 'globalThis[`glob` + `alThis`].fetch("https://evil.example/");' },
    { form: "6. a mixed multi-hop globalThis['global' + 'This'].globalThis.fetch", source: `globalThis['global' + 'This'].globalThis.fetch('https://evil.example/');` },
  ];
  for (const { form, source } of f1Reject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // ---- F1: self-reference hop static-key folding — ALLOW (preserve) --------------------------
  // 7. a genuinely runtime hop key resolves to null (NOT a hop), so the receiver is never folded
  //    into a self-reference global. `globalThis[runtimeKey]` off a bare free global is denied by
  //    the FROZEN indeterminate-member-key policy (unchanged); the hop-resolver contract is shown
  //    here off a non-global receiver, where an unresolved key is correctly not treated as a hop.
  const f1Allow: readonly { readonly form: string; readonly source: string }[] = [
    { form: '7. a genuinely runtime hop key (not folded, receiver not a self-global)', source: `declare const holder: any;\ndeclare const runtimeKey: string;\nvoid holder[runtimeKey].fetch('https://evil.example/');` },
    { form: '8. a shadowed globalThis base (binder says local)', source: `function f(globalThis: { globalThis: { fetch(x: string): void } }): void {\n  globalThis['global' + 'This'].fetch('https://evil.example/');\n}\nvoid f;` },
    { form: "9. an unrelated object base unrelated['global' + 'This'].fetch", source: `const unrelated = { globalThis: { fetch: (x: string) => x } };\nvoid unrelated['global' + 'This'].fetch('x');` },
    { form: "10. a folded NON-self-reference hop key globalThis['craf' + 'ty'].fetch", source: `globalThis['craf' + 'ty'].fetch('https://evil.example/');` },
  ];
  for (const { form, source } of f1Allow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // ---- F2: destructuring (declaration + assignment) parity — DENY ----------------------------
  const f2Reject: readonly { readonly form: string; readonly source: string }[] = [
    { form: '11. a declaration shorthand const { fetch } = globalThis', source: `const { fetch } = globalThis;\nvoid fetch('https://evil.example/');` },
    { form: '12. a declaration alias const { fetch: f } = globalThis', source: `const { fetch: f } = globalThis;\nvoid f('https://evil.example/');` },
    { form: '13. an assignment alias ({ fetch: f } = globalThis)', source: `let f: (u: string) => unknown;\n({ fetch: f } = globalThis);\nvoid f;` },
    { form: '14. an assignment shorthand through a self-hop ({ fetch } = globalThis.globalThis)', source: `let fetch: (u: string) => unknown;\n({ fetch } = globalThis.globalThis);\nvoid fetch;` },
    { form: "15. a computed static assignment key ({ ['fe' + 'tch']: f } = globalThis)", source: `let f: (u: string) => unknown;\n({ ['fe' + 'tch']: f } = globalThis);\nvoid f;` },
    { form: "16. a computed static declaration key const { ['fe' + 'tch']: f } = globalThis", source: `const { ['fe' + 'tch']: f } = globalThis;\nvoid f('https://evil.example/');` },
    { form: '17. an indeterminate destructuring key on a proven free-global (fail-closed)', source: `declare const runtimeKey: string;\nconst { [runtimeKey]: f } = globalThis;\nvoid f;` },
  ];
  for (const { form, source } of f2Reject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // ---- F2: destructuring (declaration + assignment) parity — ALLOW (preserve) ----------------
  const f2Allow: readonly { readonly form: string; readonly source: string }[] = [
    { form: '18. an unrelated receiver assignment ({ fetch: f } = cfg)', source: `const cfg: { fetch?: (u: string) => unknown } = {};\nlet f: ((u: string) => unknown) | undefined;\n({ fetch: f } = cfg);\nvoid f;` },
    { form: '19. a shadowed global receiver const { fetch } = globalThis (local param)', source: `function f(globalThis: { fetch: (u: string) => unknown }): void {\n  const { fetch } = globalThis;\n  void fetch('local');\n}\nvoid f;` },
  ];
  for (const { form, source } of f2Allow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // Indeterminate fail-closed disposition is preserved for the ASSIGNMENT form too (F2 #17 twin).
  it('rejects an indeterminate assignment key on a proven free-global fail-closed', () => {
    expect(
      usesOutboundNetwork(`declare const runtimeKey: string;\nlet f: unknown;\n({ [runtimeKey]: f } = globalThis);\nvoid f;`),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// NET bounded P1 mechanism repair (PR #64): reflective built-in acquisition and NESTED
// destructuring authority (DDR-NET-REFLECT-GET / DDR-NET-STATIC-KEY-PARITY nested authority).
// The frozen invariant — a statically identifiable network-global capability may not be acquired
// from a binder-proven free-global receiver through a SUPPORTED FINITE ACQUISITION FORM, decided AT
// THE ACQUISITION SITE — is extended by exactly three finite forms, without any taint / alias /
// value-flow expansion:
//   F1 — a direct built-in `Reflect.get(<free global>, <key>)` (Reflect a distinct intrinsic,
//        binder-proven unshadowed; the key a binder-resolved static string; fail-closed on an
//        indeterminate key). No alias of Reflect/get, no call/apply/bind, no wrapper.
//   F2 — recursive NESTED DECLARATION binding patterns, authority continuing into a nested pattern
//        ONLY through a self-reference hop key (`{ globalThis: { fetch } }` off a global), never
//        through a non-self-hop key (`{ foo: { fetch } }`).
//   assignment parity — the same recursive authority for object-DESTRUCTURING ASSIGNMENT targets,
//        where their AST forms correspond to the declaration form.
// Authority propagation is STRUCTURAL within the finite binding/destructuring AST only: once the
// binding pattern (or the object-literal target) ends, propagation ends. The scanner still makes NO
// literal-runtime-no-egress claim (aliased Reflect.get, alias chains, wrappers, Proxy/getter
// semantics, cross-module flow all remain honest, unsupported gaps).
// ---------------------------------------------------------------------------
describe('D3 host closes reflective and nested-destructuring free-global acquisition (PR #64 bounded P1)', () => {
  // ---- F1: direct built-in Reflect.get — DENY -----------------------------------------------
  const reflectReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: '1. the exact witness Reflect.get(globalThis.globalThis, "fetch")(...)', source: `Reflect.get(globalThis.globalThis, 'fetch')('https://example.com/');` },
    { form: '2. a const-key Reflect.get(globalThis, k) folding to fetch', source: `const k = 'fetch';\nReflect.get(globalThis, k)('https://example.com/');` },
    { form: '3. a concatenated key Reflect.get(globalThis, "fe" + "tch")', source: `Reflect.get(globalThis, 'fe' + 'tch')('https://example.com/');` },
    { form: '4. Reflect.get(globalThis, "WebSocket") acquiring the second global', source: `void new (Reflect.get(globalThis, 'WebSocket'))('wss://example.com/');` },
    { form: '5. a static-element callee Reflect["get"](globalThis, "fetch")', source: `Reflect['get'](globalThis, 'fetch')('https://example.com/');` },
    { form: '6. a plain globalThis receiver Reflect.get(globalThis, "fetch")', source: `Reflect.get(globalThis, 'fetch')('https://example.com/');` },
  ];
  for (const { form, source } of reflectReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // Indeterminate Reflect.get key on a proven free global fails CLOSED.
  it('rejects Reflect.get(globalThis, runtimeKey) fail-closed on an indeterminate key', () => {
    expect(
      usesOutboundNetwork(`declare const runtimeKey: string;\nReflect.get(globalThis, runtimeKey);`),
    ).toBe(true);
  });

  // ---- F1: direct built-in Reflect.get — ALLOW (preserve) -----------------------------------
  const reflectAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: '7. Reflect.get on an ordinary local object (non-global receiver)', source: `const local = { fetch() {} };\nReflect.get(local, 'fetch')();` },
    { form: '8. a user-shadowed Reflect (non-built-in reflection)', source: `const Reflect = {\n  get() {\n    return () => undefined;\n  },\n};\nReflect.get(globalThis, 'fetch')();` },
    { form: '9. Reflect.get acquiring a NON-network member off a free global', source: `void Reflect.get(globalThis, 'crypto');` },
    { form: '10. a Reflect.get ALIAS is an unsupported honest gap (not this mechanism)', source: `const rget = Reflect.get;\nrget(globalThis, 'fetch')('https://example.com/');` },
    { form: '11. an aliased receiver Reflect.get(g, "fetch") where g = globalThis (unsupported gap)', source: `const g = globalThis;\nReflect.get(g, 'fetch')('https://example.com/');` },
  ];
  for (const { form, source } of reflectAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // ---- F2: recursive NESTED DECLARATION destructuring — DENY --------------------------------
  const nestedDeclReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: '12. the exact witness const { globalThis: { fetch: f } } = globalThis.globalThis', source: `const {\n  globalThis: { fetch: f },\n} = globalThis.globalThis;\nf('https://example.com/');` },
    { form: '13. a nested pattern off a bare global const { globalThis: { fetch } } = globalThis', source: `const {\n  globalThis: { fetch },\n} = globalThis;\nvoid fetch('https://example.com/');` },
    { form: '14. a three-level self-hop nest const { globalThis: { window: { fetch } } } = globalThis', source: `const {\n  globalThis: { window: { fetch } },\n} = globalThis;\nvoid fetch('https://example.com/');` },
    { form: '15. the second global nested const { globalThis: { WebSocket: W } } = globalThis', source: `const {\n  globalThis: { WebSocket: W },\n} = globalThis;\nvoid new W('wss://example.com/');` },
    { form: '16. a computed self-hop intermediate const { ["global" + "This"]: { fetch: f } } = globalThis', source: `const {\n  ['global' + 'This']: { fetch: f },\n} = globalThis;\nf('https://example.com/');` },
    { form: '17. a nested indeterminate leaf key fails closed', source: `declare const runtimeKey: string;\nconst {\n  globalThis: { [runtimeKey]: f },\n} = globalThis;\nvoid f;` },
    { form: '18. an indeterminate INTERMEDIATE key fails closed at the free global', source: `declare const runtimeKey: string;\nconst {\n  [runtimeKey]: { fetch: f },\n} = globalThis;\nvoid f;` },
  ];
  for (const { form, source } of nestedDeclReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // ---- F2: recursive NESTED DECLARATION destructuring — ALLOW (preserve) --------------------
  const nestedDeclAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: '19. a NON-self-hop intermediate const { foo: { fetch: f } } = globalThis', source: `const {\n  foo: { fetch: f },\n} = globalThis as unknown as { foo: { fetch: (u: string) => unknown } };\nvoid f;` },
    { form: '20. a nested pattern off a non-global receiver const { globalThis: { harmless } } = localObject', source: `const localObject = { globalThis: { harmless: 1 } };\nconst {\n  globalThis: { harmless },\n} = localObject;\nvoid harmless;` },
    { form: '21. a nested self-hop to a NON-network leaf const { globalThis: { crypto } } = globalThis', source: `const {\n  globalThis: { crypto },\n} = globalThis;\nvoid crypto;` },
    { form: '22. a self-hop nest under a SHADOWED global base (binder says local)', source: `function f(globalThis: { globalThis: { fetch: (u: string) => unknown } }): void {\n  const {\n    globalThis: { fetch: g },\n  } = globalThis;\n  void g('local');\n}\nvoid f;` },
  ];
  for (const { form, source } of nestedDeclAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // ---- assignment parity: recursive NESTED ASSIGNMENT destructuring — DENY -------------------
  const nestedAssignReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: '23. the exact witness ({ globalThis: { fetch: f } } = globalThis.globalThis)', source: `let f: (u: string) => unknown;\n({\n  globalThis: { fetch: f },\n} = globalThis.globalThis);\nvoid f;` },
    { form: '24. a nested assignment off a bare global ({ globalThis: { fetch } } = globalThis)', source: `let fetch: (u: string) => unknown;\n({\n  globalThis: { fetch },\n} = globalThis);\nvoid fetch;` },
    { form: '25. a computed self-hop intermediate ({ ["global" + "This"]: { fetch: f } } = globalThis)', source: `let f: (u: string) => unknown;\n({\n  ['global' + 'This']: { fetch: f },\n} = globalThis);\nvoid f;` },
    { form: '26. a nested indeterminate leaf key assignment fails closed', source: `declare const runtimeKey: string;\nlet f: unknown;\n({\n  globalThis: { [runtimeKey]: f },\n} = globalThis);\nvoid f;` },
  ];
  for (const { form, source } of nestedAssignReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // ---- assignment parity: recursive NESTED ASSIGNMENT destructuring — ALLOW (preserve) -------
  const nestedAssignAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: '27. a NON-self-hop intermediate ({ foo: { fetch: f } } = globalThis)', source: `let f: (u: string) => unknown;\n({\n  foo: { fetch: f },\n} = globalThis as unknown as { foo: { fetch: (u: string) => unknown } });\nvoid f;` },
    { form: '28. a nested assignment off an unrelated receiver ({ globalThis: { fetch: f } } = obj)', source: `const obj = { globalThis: { fetch: (u: string) => u } };\nlet f: (u: string) => unknown;\n({\n  globalThis: { fetch: f },\n} = obj);\nvoid f;` },
  ];
  for (const { form, source } of nestedAssignAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// NET free-global receiver is a LOCAL-VALUE-SHADOW question, not a declaration-kind list
// (D3-CX-POLICY-NET-SHADOW-LOCAL). A global-receiver name (globalThis/window/self/global)
// is the real free global only when the binder resolves it to NO declaration in this file.
// ANY genuine local runtime VALUE binding of the name shadows the global — including enum,
// a value namespace, and import-equals, which a prior declaration-kind whitelist missed and
// wrongly flagged as egress. The value/type split is the binder's: at a value-position
// receiver a type-only-only name (`interface`/`type`) does not resolve, so it stays the
// free global and its network member is still rejected.
// ---------------------------------------------------------------------------
describe('D3 host free-global receiver is a local-value-shadow decision (D3-CX-POLICY-NET-SHADOW-LOCAL)', () => {
  // A genuine local runtime VALUE binding of the receiver name is a shadow → ALLOWED.
  const localShadowAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an enum global shadow', source: `enum global { fetch }\nvoid global.fetch;` },
    { form: 'a value-namespace global shadow', source: `namespace global {\n  export const fetch = (x: string) => x;\n}\nvoid global.fetch('a');` },
    { form: 'an import-equals global shadow', source: `import global = require('x');\nvoid global.fetch;` },
    { form: 'a const global shadow', source: `const global = { fetch: (x: string) => x };\nvoid global.fetch('a');` },
    { form: 'a binding-element global shadow', source: `const { global } = { global: { fetch: (x: string) => x } };\nvoid global.fetch('a');` },
    { form: 'a class global shadow', source: `class global {\n  static fetch = (x: string) => x;\n}\nvoid global.fetch('a');` },
    { form: 'a function global shadow (WebSocket member)', source: `function global() {}\nvoid (global as unknown as { WebSocket: unknown }).WebSocket;` },
    { form: 'an enum window shadow', source: `enum window { fetch }\nvoid window.fetch;` },
    { form: 'a value-namespace self shadow', source: `namespace self {\n  export const WebSocket = class {};\n}\nvoid new self.WebSocket();` },
    { form: 'a parameter global shadow', source: `function f(global: { fetch: (v: string) => string }) {\n  return global.fetch('local');\n}` },
  ];
  for (const { form, source } of localShadowAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }

  // A name whose ONLY local declaration is type-only is NOT a runtime shadow: the receiver
  // stays the free global and the network member is REJECTED. Real free globals too.
  const stillFreeReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an interface-only global (still the free global)', source: `interface global { fetch: (v: string) => string }\nglobal.fetch('https://evil/');` },
    { form: 'a type-alias-only global (still the free global)', source: `type global = { fetch: (v: string) => string };\nglobal.fetch('https://evil/');` },
    { form: 'a real free globalThis.fetch', source: `globalThis.fetch('https://evil/');` },
    { form: 'a real free window.fetch', source: `window.fetch('https://evil/');` },
    { form: 'a real free self.WebSocket', source: `new self.WebSocket('wss://evil/');` },
  ];
  for (const { form, source } of stillFreeReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// Exact-head Codex findings (D3-CX-CODEX). F1: an ambient `declare` (or type-only) binding
// emits no runtime value, so it does NOT shadow a runtime network global — the real global is
// still reached and must be rejected, while a genuine runtime shadow stays allowed. F2: a
// computed object-binding key that does not statically resolve, destructured directly from a
// createServer request/response handler parameter, fails closed. F3: a runtime namespace
// re-export of node:http (`export * as http`) carries authority and is rejected, while the
// type-only form is preserved.
// ---------------------------------------------------------------------------
describe('D3 host rejects ambient/non-emitting shadows of runtime network globals (D3-CX-CODEX-F1)', () => {
  // REJECT — a declaration-only binding leaves the runtime global reachable.
  const ambientReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an ambient declare const fetch used bare', source: `declare const fetch: (url: string) => Promise<unknown>;\nvoid fetch('https://example.com');` },
    { form: 'an ambient declare const WebSocket constructed', source: `declare const WebSocket: new (url: string) => unknown;\nvoid new WebSocket('wss://example.com/');` },
    { form: 'an ambient declare function fetch used bare', source: `declare function fetch(url: string): Promise<unknown>;\nvoid fetch('https://example.com');` },
    { form: 'a type-only import of fetch used at a value position', source: `import type { fetch } from './x.js';\nvoid fetch('https://example.com');` },
    { form: 'an ambient declare const global receiver', source: `declare const global: { fetch: (v: string) => void };\nglobal.fetch('https://example.com');` },
  ];
  for (const { form, source } of ambientReject) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // ALLOW — a genuine runtime binding of the name is a real shadow.
  const runtimeShadowAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a const runtime shadow of fetch', source: `const fetch = (u: string): string => u;\nvoid fetch('local');` },
    { form: 'a function runtime shadow of fetch', source: `function fetch(): void {}\nvoid fetch();` },
    { form: 'a class runtime shadow of WebSocket', source: `class WebSocket {}\nvoid new WebSocket();` },
    { form: 'an enum global runtime shadow', source: `enum global { fetch }\nvoid global.fetch;` },
    { form: 'a value-namespace global runtime shadow', source: `namespace global {\n  export const fetch = (x: string): string => x;\n}\nvoid global.fetch('a');` },
    { form: 'an import-equals value runtime shadow', source: `import global = require('x');\nvoid global.fetch;` },
  ];
  for (const { form, source } of runtimeShadowAllow) {
    it(`ALLOWS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

describe('D3 host fails closed on computed req/res destructuring keys (D3-CX-CODEX-F2)', () => {
  const H = `import http from 'node:http';\n`;
  const handler = (body: string): string =>
    H + `http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {\n${body}\n});`;
  // REJECT — an indeterminate computed binding key off a handler parameter.
  const computedReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: "the reported const { ['sock' + 'et']: s } = req reproducer", source: handler(`const { ['sock' + 'et']: s } = req;\nvoid s;`) },
    { form: 'a const { [key]: x } = req with an indeterminate key', source: handler(`const key = req.url ?? '';\nconst { [key]: x } = req;\nvoid x;`) },
    { form: 'a conditional computed key off req', source: handler(`const c = req.method === 'GET';\nconst { [c ? 'socket' : 'method']: x } = req;\nvoid x;`) },
    { form: 'an indeterminate computed key off res', source: handler(`const key = req.url ?? '';\nconst { [key]: x } = res;\nvoid x;`) },
  ];
  for (const { form, source } of computedReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }
  // ALLOW — a static harmless key off a handler param, and unrelated computed destructuring.
  const computedAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: "a static harmless const { ['method']: m } = req", source: handler(`const { ['method']: m } = req;\nvoid m;`) },
    { form: 'an unrelated computed destructuring (not a handler param)', source: `const obj: Record<string, unknown> = {};\nconst key = 'x';\nconst { [key]: v } = obj;\nvoid v;` },
    { form: 'an ordinary static request field destructuring', source: handler(`const { method, url } = req;\nvoid method;\nvoid url;`) },
  ];
  for (const { form, source } of computedAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

describe('D3 host rejects namespace re-export of node:http authority (D3-CX-CODEX-F3)', () => {
  const sf = (source: string): ts.SourceFile =>
    ts.createSourceFile('module.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  it('REJECTS a runtime `export * as http from node:http`', () => {
    expect(exportsHttpCapability(sf(`export * as http from 'node:http';`))).toBe(true);
  });
  it('REJECTS a runtime `export * as anyName from node:http`', () => {
    expect(exportsHttpCapability(sf(`export * as h from 'node:http';`))).toBe(true);
  });
  it('PRESERVES a type-only `export type * as http from node:http`', () => {
    expect(exportsHttpCapability(sf(`export type * as http from 'node:http';`))).toBe(false);
  });
  it('PRESERVES an unrelated namespace re-export', () => {
    expect(exportsHttpCapability(sf(`export * as local from './local.js';`))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Codex P1: object DESTRUCTURING ASSIGNMENT socket acquisition (D3-CX-CODEX-ASSIGN). The
// permitted createServer path can extract the inbound socket through an assignment-target
// object pattern — `({ socket: s } = req)` — whose AST is a BinaryExpression over an
// ObjectLiteralExpression, not the BindingElement/VariableDeclaration forms RULE A(c)/A2
// recognize. RULE A2 (assignment) closes it, scoped to the req/res initializer symbol identity:
// a socket/connection key is rejected, an indeterminate computed key fails closed, a static
// harmless key and any key off an unrelated object stay allowed (no global broadening).
// ---------------------------------------------------------------------------
describe('D3 host inspects destructuring assignments for socket acquisition (D3-CX-CODEX-ASSIGN)', () => {
  const H = `import http from 'node:http';\n`;
  const handler = (body: string): string =>
    H + `http.createServer((req: any, res: any): void => {\n${body}\n});`;

  it('rejects the reported ({ socket: s } = req) assignment reproducer', () => {
    expect(
      usesOutboundNetwork(
        handler(`let s: any;\n({ socket: s } = req);\ns.destroy();\nsetTimeout(() => s.connect(80, 'example.com'), 50);`),
      ),
    ).toBe(true);
  });

  const assignReject: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a ({ socket: s } = req) assignment', source: handler(`let s: any;\n({ socket: s } = req);\nvoid s;`) },
    { form: 'a ({ connection: c } = req) assignment', source: handler(`let c: any;\n({ connection: c } = req);\nvoid c;`) },
    { form: 'a ({ socket: s } = res) assignment', source: handler(`let s: any;\n({ socket: s } = res);\nvoid s;`) },
    { form: 'a ({ connection: c } = res) assignment', source: handler(`let c: any;\n({ connection: c } = res);\nvoid c;`) },
    { form: 'a shorthand ({ socket } = req) assignment', source: handler(`let socket: any;\n({ socket } = req);\nvoid socket;`) },
    { form: "a static-computed ({ ['socket']: s } = req)", source: handler(`let s: any;\n({ ['socket']: s } = req);\nvoid s;`) },
    { form: 'a template-computed ({ [`connection`]: c } = req)', source: handler('let c: any;\n({ [`connection`]: c } = req);\nvoid c;') },
    { form: 'an indeterminate ({ [key]: x } = req)', source: handler(`let x: any;\nconst key = req.url ?? '';\n({ [key]: x } = req);\nvoid x;`) },
    { form: "a concatenated ({ ['sock' + 'et']: x } = req)", source: handler(`let x: any;\n({ ['sock' + 'et']: x } = req);\nvoid x;`) },
    { form: 'a conditional ({ [c ? "socket" : "method"]: x } = res)', source: handler(`let x: any;\nconst c = req.method === 'GET';\n({ [c ? 'socket' : 'method']: x } = res);\nvoid x;`) },
  ];
  for (const { form, source } of assignReject) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  const assignAllow: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a static harmless ({ method: m } = req)', source: handler(`let m: any;\n({ method: m } = req);\nvoid m;`) },
    { form: 'a static harmless ({ url: u } = req)', source: handler(`let u: any;\n({ url: u } = req);\nvoid u;`) },
    { form: "a static-computed harmless ({ ['method']: m } = req)", source: handler(`let m: any;\n({ ['method']: m } = req);\nvoid m;`) },
    { form: 'an unrelated ({ [key]: x } = obj)', source: `const obj: Record<string, unknown> = {};\nconst key = 'x';\nlet x: unknown;\n({ [key]: x } = obj);\nvoid x;` },
    { form: 'an unrelated ({ value: x } = obj)', source: `const obj = { value: 1 };\nlet x: unknown;\n({ value: x } = obj);\nvoid x;` },
    { form: 'an unrelated ({ socket: localSocket } = unrelatedObject)', source: `const unrelatedObject = { socket: 1 };\nlet localSocket: unknown;\n({ socket: localSocket } = unrelatedObject);\nvoid localSocket;` },
  ];
  for (const { form, source } of assignAllow) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// Codex P1: statically-COMPUTED free-global network members (D3-CX-CODEX-F1-COMPUTED). The
// free-global network-member check resolved the member with the literal-only `binderMemberName`,
// so a key that folds to a literal (`globalThis['fe' + 'tch']`, `const key = 'fetch'; globalThis[key]`)
// escaped `usesOutboundNetwork` while never being a runtime-code-generation capability either.
// The check now resolves the member through the existing `collectStringConsts` / `memberNameOf`
// static-string machinery (no new evaluator), so the whole NETWORK_GLOBAL_NAMES family is caught
// for direct, `+`-folded, and unique-immutable-const keys. A genuinely indeterminate key is not
// resolved here and is DENIED fail-closed by NET at a free-global receiver.
// ---------------------------------------------------------------------------
describe('D3 host rejects statically-computed free-global network members (D3-CX-CODEX-F1-COMPUTED)', () => {
  const rejectComputed: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a dotted globalThis.fetch', source: `globalThis.fetch('https://example.com/');` },
    { form: 'an optional globalThis?.fetch', source: `globalThis?.fetch('https://example.com/');` },
    { form: "a literal globalThis['fetch']", source: `globalThis['fetch']('https://example.com/');` },
    { form: 'a template globalThis[`fetch`]', source: 'globalThis[`fetch`]("https://example.com/");' },
    { form: "a concatenated globalThis['fe' + 'tch']", source: `globalThis['fe' + 'tch']('https://example.com/');` },
    { form: 'a const-key globalThis[key]', source: `const key = 'fetch';\nglobalThis[key]('https://example.com/');` },
    { form: "a const-prefix globalThis[prefix + 'tch']", source: `const prefix = 'fe';\nglobalThis[prefix + 'tch']('https://example.com/');` },
    { form: 'a bare new WebSocket', source: `void new WebSocket('wss://example.com/');` },
    { form: 'a dotted new globalThis.WebSocket', source: `void new globalThis.WebSocket('wss://example.com/');` },
    { form: "a literal new globalThis['WebSocket']", source: `void new globalThis['WebSocket']('wss://example.com/');` },
    { form: "a concatenated new globalThis['Web' + 'Socket']", source: `void new globalThis['Web' + 'Socket']('wss://example.com/');` },
    { form: 'a const-key new globalThis[w]', source: `const w = 'WebSocket';\nvoid new globalThis[w]('wss://example.com/');` },
    { form: "a window['fe' + 'tch'] receiver", source: `window['fe' + 'tch']('https://example.com/');` },
    { form: "a self['We' + 'bSocket'] receiver", source: `void new self['We' + 'bSocket']('wss://example.com/');` },
  ];
  for (const { form, source } of rejectComputed) {
    it(`rejects ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // A genuinely indeterminate free-global member key (a runtime `declare const` key) cannot be
  // statically pinned down, so at a free-global receiver NET DENIES it fail-closed (frozen key
  // policy) — a key that might be `fetch`/`WebSocket` at runtime must not pass by being unresolvable.
  const indeterminate: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a runtime-key globalThis[k] call', source: `declare const k: string;\nglobalThis[k]('https://example.com/');` },
    { form: 'a runtime-key new globalThis[k]', source: `declare const k: string;\nvoid new globalThis[k]('wss://example.com/');` },
  ];
  for (const { form, source } of indeterminate) {
    it(`rejects ${form} fail-closed`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // ALLOW / PRESERVE — a computed member that does not fold to a protected network global, and a
  // local runtime shadow of the receiver, stay allowed.
  const allowComputed: readonly { readonly form: string; readonly source: string }[] = [
    { form: "a non-network globalThis['ordinaryLocalMember']", source: `void globalThis['ordinaryLocalMember'];` },
    { form: "a non-network concatenated globalThis['con' + 'sole']", source: `void globalThis['con' + 'sole'];` },
    { form: 'a receiver-shadowed globalThis with a computed member', source: `function f(globalThis: { fetch: (v: string) => string }): string {\n  return globalThis['fe' + 'tch']('local');\n}\nvoid f;` },
    { form: 'a computed member off an unrelated local object', source: `const rt = { fetch: (v: string) => v };\nvoid rt['fe' + 'tch']('local');` },
  ];
  for (const { form, source } of allowComputed) {
    it(`allows ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// P2: the free-global network-member check resolves a computed key through a collected string
// constant by identifier TEXT (D3-CX-POLICY-NET-BIND). `collectStringConsts` keys a value by
// text under whole-file uniqueness, so a single out-of-scope `const Infinity = 'fetch'` made
// `globalThis[Infinity]` — whose `Infinity` reference does NOT resolve to that const — fold to
// a PHANTOM `'fetch'` member and reject as egress, a false positive that acquires no runtime
// fetch/WebSocket capability. The member is now resolved with `netMemberNameOf`, which
// substitutes a collected constant for an Identifier key ONLY when the compiler binder proves
// the reference denotes that same unique `const` declaration; identifier text equality is not
// binding identity. Literals and `+`-folds are unchanged, a genuine same-binding const key is
// still rejected, and a key that cannot be bound is Indeterminate and is DENIED fail-closed by NET
// itself at a free-global receiver. RC/HA text-only policy is untouched.
// ---------------------------------------------------------------------------
describe('D3 host resolves computed network-member keys by binder identity (D3-CX-POLICY-NET-BIND)', () => {
  // Under the frozen fail-closed key policy the outer `globalThis[Infinity]` key is Indeterminate
  // (it does not resolve to a unique in-file `const`), so NET DENIES it — a computed free-global key
  // that cannot be statically pinned down is not allowed. Binder identity is still authoritative for
  // genuine same-symbol chains (which stay REJECT below) and for Resolved non-capability keys.
  it('rejects the indeterminate reproducer (out-of-scope const Infinity) fail-closed', () => {
    const reproducer = `function f() {\n  const Infinity = 'fetch';\n  void Infinity;\n}\nvoid (globalThis as any)[Infinity];`;
    expect(usesOutboundNetwork(reproducer)).toBe(true);
  });

  // DENY fail-closed — the element-access key does NOT lexically resolve to a unique in-file `const`
  // (a different/inner/sibling scope, a parameter or import shadow, or a free global), so it is
  // Indeterminate and, at a free-global receiver, denied. None is a proven capability chain, but
  // none is provably NOT one either, so fail-closed is the sound verdict.
  const indeterminateKeys: readonly { readonly form: string; readonly source: string }[] = [
    {
      form: 'a function-scoped const Infinity with an outer key reference',
      source: `function f() {\n  const Infinity = 'fetch';\n  void Infinity;\n}\nvoid (globalThis as any)[Infinity];`,
    },
    {
      form: 'a block-scoped const Infinity with an outer key reference',
      source: `{\n  const Infinity = 'fetch';\n}\nvoid globalThis[Infinity];`,
    },
    {
      form: 'a sibling-scope const key that the second scope does not see',
      source: `function a() {\n  const key = 'fetch';\n  void key;\n}\nfunction b() {\n  void globalThis[key];\n}\nvoid a;\nvoid b;`,
    },
    {
      form: 'an inner-declared const with an outer WebSocket key reference (constructor)',
      source: `function outer() {\n  function inner() {\n    const wsName = 'WebSocket';\n    void wsName;\n  }\n  void inner;\n  return new globalThis[wsName]('wss://example.com/');\n}\nvoid outer;`,
    },
    {
      form: 'a parameter shadow of the collected const name',
      source: `const routeName = 'fetch';\nfunction f(routeName: string) {\n  return globalThis[routeName];\n}\nvoid f;`,
    },
    {
      form: 'an imported-name / inner-const same-text key resolving to the import',
      source: `import { helper } from './x.js';\nfunction f() {\n  const helper = 'fetch';\n  void helper;\n}\nvoid helper;\nvoid globalThis[helper];`,
    },
  ];
  for (const { form, source } of indeterminateKeys) {
    it(`rejects ${form} fail-closed`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // REJECT — genuine egress: literals, `+`-folds, and const keys whose reference the binder DOES
  // prove denotes the collected const (same-symbol), for both fetch and WebSocket.
  const rejectGenuine: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a same-binding const key globalThis[key]', source: `const key = 'fetch';\nglobalThis[key]('https://example.com/');` },
    { form: 'a same-binding const key new globalThis[ws]', source: `const ws = 'WebSocket';\nvoid new globalThis[ws]('wss://example.com/');` },
    { form: "a same-binding const-prefix globalThis[prefix + 'tch']", source: `const prefix = 'fe';\nglobalThis[prefix + 'tch']('https://example.com/');` },
    { form: "a literal concatenation globalThis['fe' + 'tch']", source: `globalThis['fe' + 'tch']('https://example.com/');` },
    { form: 'a dotted globalThis.fetch', source: `globalThis.fetch('https://example.com/');` },
    { form: 'a dotted new globalThis.WebSocket', source: `void new globalThis.WebSocket('wss://example.com/');` },
    { form: 'a same-scope const key inside a function (same symbol)', source: `function f() {\n  const key = 'fetch';\n  return globalThis[key]('https://example.com/');\n}\nvoid f;` },
  ];
  for (const { form, source } of rejectGenuine) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // FAIL-CLOSED — a key the NET branch cannot bind (ambient, mutated, or undeclared) is
  // Indeterminate and is DENIED by NET itself at a free-global receiver (no longer deferred to the
  // runtime-code guard), so binder-identity gating narrows NET WITHOUT opening an egress bypass.
  const failClosed: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an ambient declare const key globalThis[k]', source: `declare const k: string;\nglobalThis[k]('https://example.com/');` },
    { form: 'a mutated let key globalThis[k]', source: `let k = 'fetch';\nk = 'other';\nglobalThis[k]('https://example.com/');` },
    { form: 'an undeclared free-global key globalThis[neverDeclared]', source: `void globalThis[neverDeclared];` },
  ];
  for (const { form, source } of failClosed) {
    it(`rejects ${form} fail-closed by NET`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// P2 (follow-up): binder identity must hold through the ENTIRE initializer-resolution chain, not
// only at the final element-access key (D3-CX-POLICY-NET-BIND-INIT). Gating just the key left a
// second hole: `const key = Infinity` is itself a genuine same-symbol const reference, but its
// initializer `Infinity` was resolved by text-only const collection and folded to a phantom
// `'fetch'` from an out-of-scope `const Infinity = 'fetch'`. The NET path now resolves strings
// straight off the binder (`netResolveString`): every identifier hop — the key and every
// identifier reached while resolving a collected initializer — must resolve to the unique `const`
// declaration whose value is being substituted, recursively, bounded against initializer cycles.
// A genuine multi-hop same-symbol chain still folds and is still rejected; a chain poisoned at any
// hop is Indeterminate and is DENIED fail-closed by NET itself at a free-global receiver.
// ---------------------------------------------------------------------------
describe('D3 host binds identifiers inside collected constant initializers (D3-CX-POLICY-NET-BIND-INIT)', () => {
  // Under the frozen fail-closed key policy: `const key = Infinity` where `Infinity` does not
  // resolve to a unique in-file `const` leaves the key Indeterminate, so NET DENIES it. (Binder
  // identity still folds a genuine same-symbol multi-hop chain to Resolved(capability) — REJECT.)
  it('rejects the poisoned-initializer reproducer (const key = Infinity) fail-closed', () => {
    const reproducer = `function f() {\n  const Infinity = 'fetch';\n}\nconst key = Infinity;\nvoid globalThis[key];`;
    expect(usesOutboundNetwork(reproducer)).toBe(true);
  });

  // DENY fail-closed — the key is a unique const, but an identifier INSIDE its initializer chain
  // does not resolve to a unique in-file const, so the chain is Indeterminate (not binder-proven).
  const indeterminateInit: readonly { readonly form: string; readonly source: string }[] = [
    {
      form: 'a function-scoped const Infinity folded into a module const initializer',
      source: `function f() {\n  const Infinity = 'fetch';\n}\nconst key = Infinity;\nvoid globalThis[key];`,
    },
    {
      form: 'a block-scoped const Infinity folded into a module const initializer',
      source: `{\n  const Infinity = 'fetch';\n}\nconst key = Infinity;\nvoid globalThis[key];`,
    },
    {
      form: 'a sibling-scope const marker folded into a module const initializer',
      source: `function f() {\n  const marker = 'fetch';\n}\nconst key = marker;\nvoid globalThis[key];`,
    },
    {
      form: 'a concatenation initializer where one segment resolves to a different binding',
      source: `function f() {\n  const seg = 'tch';\n}\nconst a = 'fe';\nconst key = a + seg;\nvoid globalThis[key];`,
    },
    {
      form: 'a parameter-shadow initializer',
      source: `const label = 'fetch';\nfunction f(label: string) {\n  const key = label;\n  return globalThis[key];\n}\nvoid f;`,
    },
    {
      form: 'an import-shadow initializer',
      source: `import { thing } from './x.js';\nconst key = thing;\nvoid globalThis[key];`,
    },
    {
      form: 'a free-global identifier initializer under noLib',
      source: `const key = Infinity;\nvoid globalThis[key];`,
    },
    {
      form: 'a same-text sibling-scope const referenced from another function initializer',
      source: `function a() {\n  const Infinity = 'fetch';\n  void Infinity;\n}\nfunction b() {\n  const key = Infinity;\n  void globalThis[key];\n}\nvoid a;\nvoid b;`,
    },
  ];
  for (const { form, source } of indeterminateInit) {
    it(`rejects ${form} fail-closed`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // REJECT — genuine multi-hop same-symbol chains: every identifier resolves to the collected
  // declaration, for both fetch and WebSocket, call and constructor, incl. an optional key.
  const rejectGenuineChain: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a one-hop const key = a', source: `const a = 'fetch';\nconst key = a;\nglobalThis[key]('https://example.com/');` },
    { form: "a concat const key = a + 'tch'", source: `const a = 'fe';\nconst key = a + 'tch';\nglobalThis[key]('https://example.com/');` },
    { form: 'a two-hop const key = b = a chain', source: `const a = 'fe';\nconst b = a + 'tch';\nconst key = b;\nglobalThis[key]('https://example.com/');` },
    { form: 'a WebSocket const ws = a', source: `const a = 'WebSocket';\nconst ws = a;\nvoid new globalThis[ws]('wss://example.com/');` },
    { form: "a WebSocket concat const ws = a + 'Socket'", source: `const a = 'Web';\nconst ws = a + 'Socket';\nvoid new globalThis[ws]('wss://example.com/');` },
    { form: 'an optional-computed same-symbol key', source: `const key = 'fetch';\nglobalThis?.[key]('https://example.com/');` },
    { form: 'a direct literal element key', source: `globalThis['fetch']('https://example.com/');` },
  ];
  for (const { form, source } of rejectGenuineChain) {
    it(`REJECTS ${form}`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // FAIL-CLOSED — a chain the NET path cannot binder-prove (ambient initializer, or a cycle) is
  // Indeterminate and is DENIED by NET itself, and cycle resolution still TERMINATES. No bypass.
  const failClosedChain: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an ambient-declare initializer const key = k', source: `declare const k: string;\nconst key = k;\nglobalThis[key]('https://example.com/');` },
    { form: 'a two-const initializer cycle a = b, b = a', source: `const a = b;\nconst b = a;\nvoid globalThis[a];` },
    { form: 'a self-referential initializer const a = a', source: `const a = a;\nvoid globalThis[a];` },
  ];
  for (const { form, source } of failClosedChain) {
    it(`rejects ${form} fail-closed by NET (terminates)`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// P2 (second-order): NET recursive resolution must MEMOIZE by declaration identity, not merely
// detect cycles path-locally (D3-CX-POLICY-NET-BIND-MEMO). Without a completed-result cache a
// shared initializer subtree is recomputed on every reference, so a doubling chain
// `aN = aN-1 + aN-1` costs 2^N resolutions (~22.5 s at N=22 on ~500 bytes). `netResolveString`
// now caches each declaration's completed result (string or null) keyed by the binder-proven
// declaration node — distinct from the cycle set — so every declaration's initializer is resolved
// at most once. Binder identity stays authoritative at every hop, the cache never crosses scopes
// (it is keyed by declaration, never text), a cached null never becomes a static value, and cycles
// still terminate fail-closed.
// ---------------------------------------------------------------------------
describe('D3 host memoizes NET constant resolution by declaration identity (D3-CX-POLICY-NET-BIND-MEMO)', () => {
  const doubling = (n: number, base: string): string => {
    const lines = [`const a0 = '${base}';`];
    for (let i = 1; i <= n; i++) lines.push(`const a${String(i)} = a${String(i - 1)} + a${String(i - 1)};`);
    lines.push(`void globalThis[a${String(n)}];`);
    return lines.join('\n');
  };
  const linear = (n: number, base: string): string => {
    const lines = [`const a0 = '${base}';`];
    for (let i = 1; i <= n; i++) lines.push(`const a${String(i)} = a${String(i - 1)};`);
    lines.push(`globalThis[a${String(n)}]('https://example.com/');`);
    return lines.join('\n');
  };

  // Shared-subtree (doubling) chain. With an empty base the resolved value is O(1) while the
  // recomputation tree is 2^N without memo. `netResolveVisits` is the number of identifier hops the
  // resolver actually spent across this single-access traversal: declaration-keyed memoization keeps
  // it LINEAR in the declaration count (~2N), so a small bound here is deterministic structural
  // evidence of memoization. An un-memoized resolver would spend 2^60 hops — impossible — and trip
  // the visit cap at once (a fast throw, not a hang). The empty key is not a network global.
  it('resolves a shared-subtree doubling chain N=60 in a linear number of hops (memoized)', () => {
    expect(usesOutboundNetwork(doubling(60, ''))).toBe(false);
    expect(netResolveVisits).toBeGreaterThan(0);
    expect(netResolveVisits).toBeLessThan(1000);
  });

  // The exact reported adversarial family (a0 = 'fe'), well beyond the prior N=22 failure point:
  // the hop count is likewise linear, and the once-built value is not a network global.
  it('resolves the reported doubling family N=24 (a0 = fe) in a linear number of hops', () => {
    expect(usesOutboundNetwork(doubling(24, 'fe'))).toBe(false);
    expect(netResolveVisits).toBeGreaterThan(0);
    expect(netResolveVisits).toBeLessThan(1000);
  });

  // A long linear chain still resolves and rejects the genuine capability, fast.
  it('rejects a long linear const chain resolving to fetch (N=40)', () => {
    expect(usesOutboundNetwork(linear(40, 'fetch'))).toBe(true);
  }, 4000);

  // Cycles: memo + cycle interaction terminates and is DENIED fail-closed by NET (Indeterminate).
  const cycles: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a self cycle const a = a', source: `const a = a;\nglobalThis[a]('https://example.com/');` },
    { form: 'a 2-node cycle a = b, b = a', source: `const a = b;\nconst b = a;\nglobalThis[a]('https://example.com/');` },
    { form: 'a 3-node cycle a = b, b = c, c = a', source: `const a = b;\nconst b = c;\nconst c = a;\nglobalThis[a]('https://example.com/');` },
  ];
  for (const { form, source } of cycles) {
    it(`rejects ${form} fail-closed by NET (terminates)`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    }, 4000);
  }

  // Declaration-identity cache must not leak between same-text declarations in different scopes.
  it('rejects globalThis[s] where s resolves to a function-local const fetch', () => {
    expect(
      usesOutboundNetwork(`function f() {\n  const s = 'fetch';\n  return globalThis[s]('https://example.com/');\n}\nvoid f;`),
    ).toBe(true);
  });
  it('allows globalThis[s] where a same-text s resolves to a benign function-local const', () => {
    expect(usesOutboundNetwork(`function g() {\n  const s = 'safe';\n  return globalThis[s];\n}\nvoid g;`)).toBe(false);
  });
  it('does not reuse a module const fetch value for a shadowing function-local const', () => {
    expect(
      usesOutboundNetwork(`const a = 'fetch';\nfunction f() {\n  const a = 'safe';\n  return globalThis[a];\n}\nvoid f;\nvoid a;`),
    ).toBe(false);
  });

  // Two distinct declarations sharing initializer text each resolve independently (no conflation).
  it('rejects the genuine one of two distinct decls sharing initializer text', () => {
    expect(
      usesOutboundNetwork(`const m1 = 'fetch';\nconst m2 = 'fetch';\nvoid m1;\nglobalThis[m2]('https://example.com/');`),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// P2 (cross-member): the completed-result memo must be SHARED across every member resolution in one
// `usesOutboundNetwork` traversal (D3-CX-POLICY-NET-BIND-XMEMO). Previously `netMemberNameOf` built
// a fresh memo per access, so an N-declaration chain reused by M member accesses was resolved M
// times — Θ(M × N) cumulative, unbounded by the per-member cap. One memo hoisted into the traversal
// makes the cumulative cost O(N + M): each declaration is resolved once and reused. The memo stays
// keyed by exact declaration identity and is created fresh per traversal, so it never leaks between
// sources; per-member `seen`/budget stay local, preserving cycle detection and the cap.
// ---------------------------------------------------------------------------
describe('D3 host shares the NET declaration memo across member resolutions (D3-CX-POLICY-NET-BIND-XMEMO)', () => {
  const chain = (n: number, base: string): string[] => {
    const lines = [`const a0 = '${base}';`];
    for (let i = 1; i <= n; i++) lines.push(`const a${String(i)} = a${String(i - 1)} + a${String(i - 1)};`);
    return lines;
  };

  // 1. Same key repeated M times — cumulative work grows ADDITIVELY with M, not multiplicatively.
  it('resolves a repeated key chain in additive (O(N+M)), not multiplicative (O(N*M)), work', () => {
    const src = (n: number, m: number): string => {
      const lines = chain(n, '');
      for (let j = 0; j < m; j++) lines.push(`void globalThis[a${String(n)}];`);
      return lines.join('\n');
    };
    expect(usesOutboundNetwork(src(50, 1))).toBe(false);
    const c1 = netResolveVisits;
    expect(usesOutboundNetwork(src(50, 100))).toBe(false);
    const c100 = netResolveVisits;
    // Shared memo: the 50-chain is resolved once; each extra access is a single memoized hop, so
    // 100 accesses cost the 1-access cost plus ~M. Un-shared memo would give c100 ≈ 100 × c1.
    expect(c1).toBeGreaterThan(0);
    expect(c100).toBeLessThan(c1 + 400);
  });

  // 2. One chain referenced by many DISTINCT key declarations — resolved once, shared by all.
  it('shares one chain across many distinct key declarations', () => {
    const lines = chain(50, '');
    const m = 100;
    for (let j = 0; j < m; j++) lines.push(`const k${String(j)} = a50;`);
    for (let j = 0; j < m; j++) lines.push(`void globalThis[k${String(j)}];`);
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(false);
    // a0..a50 resolved ONCE and shared; each of 100 keys adds O(1). Un-shared → ~100× more hops.
    expect(netResolveVisits).toBeLessThan(1000);
  });

  // 3. Same chain read through many UNRELATED (non-global) receivers — resolution still shared.
  it('shares chain resolution across unrelated non-global receivers', () => {
    const lines = chain(50, '');
    lines.push('const obj: Record<string, unknown> = {};');
    lines.push('const key = a50;');
    const m = 100;
    for (let j = 0; j < m; j++) lines.push('void obj[key];');
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(false); // obj is not a global receiver
    expect(netResolveVisits).toBeLessThan(1000);
  });

  // 4. Independent chains are cached separately (no cross-chain contamination); WebSocket rejected.
  it('caches independent chains separately', () => {
    const src = [
      `const a0 = 'fe';`,
      `const a1 = a0 + a0;`,
      `const b0 = 'WebSocket';`,
      `const bk = b0;`,
      `void globalThis[a1];`, // 'fefe' — not a network global → allowed
      `new globalThis[bk]('wss://example.com/');`, // WebSocket → rejected
    ].join('\n');
    expect(usesOutboundNetwork(src)).toBe(true);
  });

  // Cache lifetime: the memo must NOT leak between separate usesOutboundNetwork calls (fresh memo,
  // declaration-keyed for each Program), in either order.
  it('does not leak the memo between separate usesOutboundNetwork calls', () => {
    expect(usesOutboundNetwork(`const key = 'safe';\nvoid globalThis[key];`)).toBe(false);
    expect(usesOutboundNetwork(`const key = 'fetch';\nglobalThis[key]('https://example.com/');`)).toBe(true);
    expect(usesOutboundNetwork(`const key = 'fetch';\nglobalThis[key]('https://example.com/');`)).toBe(true);
    expect(usesOutboundNetwork(`const key = 'safe';\nvoid globalThis[key];`)).toBe(false);
  });

  // An Indeterminate (poisoned) chain and a genuine chain coexist in the shared memo without
  // contaminating one another: both are denied at a free-global receiver, so the overall verdict is
  // deny (both orders exercised by the two accesses).
  it('keeps a poisoned (Indeterminate) and a genuine chain independent within one source', () => {
    const src = [
      `function f() { const p = 'fetch'; void p; }`,
      `const bad = p;`, // out-of-scope p → Indeterminate → denied fail-closed
      `const good = 'fetch';`,
      `void globalThis[bad];`,
      `globalThis[good]('https://example.com/');`, // genuine → rejected
    ].join('\n');
    expect(usesOutboundNetwork(src)).toBe(true);
  });

  // A cached Indeterminate classification is reused for a repeated poisoned key (no per-access
  // recomputation); it is DENIED fail-closed at the free-global receiver.
  it('reuses a cached Indeterminate result for a repeated poisoned key (denied)', () => {
    const lines = [`function f() { const marker = 'fetch'; void marker; }`, `const key = marker;`];
    for (let j = 0; j < 50; j++) lines.push('void globalThis[key];');
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(true);
    expect(netResolveVisits).toBeLessThan(1000);
  });

  // Cycles still terminate and are DENIED fail-closed by NET with the shared memo (in-progress
  // state is never cached).
  const cycles: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'self cycle', source: `const a = a;\nglobalThis[a]('https://example.com/');\nvoid globalThis[a];` },
    { form: '2-node cycle', source: `const a = b;\nconst b = a;\nglobalThis[a]('https://example.com/');\nvoid globalThis[b];` },
    { form: '3-node cycle', source: `const a = b;\nconst b = c;\nconst c = a;\nglobalThis[a]('https://example.com/');\nvoid globalThis[c];` },
  ];
  for (const { form, source } of cycles) {
    it(`terminates a ${form} and is denied fail-closed with a shared memo`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // Under the shared memo an Indeterminate poisoned key is DENIED fail-closed, and a genuine chain
  // is still rejected.
  it('denies a poisoned-initializer key under the shared memo', () => {
    expect(usesOutboundNetwork(`function f() {\n  const Infinity = 'fetch';\n}\nvoid globalThis[Infinity];`)).toBe(true);
    expect(usesOutboundNetwork(`function f() {\n  const Infinity = 'fetch';\n}\nconst key = Infinity;\nvoid globalThis[key];`)).toBe(true);
  });
  it('preserves the genuine-chain REJECT under the shared memo', () => {
    expect(usesOutboundNetwork(`const a = 'fetch';\nconst b = a;\nconst key = b;\nglobalThis[key]('https://example.com/');`)).toBe(true);
    expect(usesOutboundNetwork(`const a = 'Web';\nconst ws = a + 'Socket';\nvoid new globalThis[ws]('wss://example.com/');`)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// P2/P1 (resolver totality + fail-closed abort) — the NET member-key classifier must return a
// BOUNDED verdict, never crash or allocate an unbounded intermediate, and an abort must fail CLOSED
// (D3-CX-POLICY-NET-BIND-TOTALITY / D3-CX-POLICY-NET-KEY). Three verified Codex findings, same
// resolver boundary:
//   A (P2). `left + right` materialized a folded string of exponential size (`aN = aN-1 + aN-1`)
//      while only ~2N visits were charged, so the visit cap never fired. A fold whose result
//      exceeds the longest capability name is now classified NotCapability BEFORE allocating the
//      oversized string, and NotCapability ALLOWS (it can never equal `fetch`/`WebSocket`).
//   B (P2). A long chain recursed once per hop, so Node's call stack threw an uncaught RangeError
//      (~7.8k frames) far below the visit cap. The identifier-alias spine now resolves ITERATIVELY
//      (O(1) native stack; genuine long chains still classify Resolved and reject, benign ones
//      Resolved-non-capability and allow), and a deterministic recursion-depth cap bounds the
//      remaining `+`-fold recursion.
//   C (P1). Converting a resource abort to "allow" let a genuine deep fetch chain slip past NET
//      (`const shared='fetch'; nK='' + nK-1; globalThis[nN](...)`). A resource abort now maps to
//      Indeterminate, and Indeterminate at a free-global receiver is DENIED fail-closed — NET no
//      longer relies on the runtime-code guard to catch an unresolvable computed key.
// Neither bound weakens genuine `fetch`/`WebSocket` detection.
// ---------------------------------------------------------------------------
describe('D3 host bounds NET resolver output growth and recursion depth (D3-CX-POLICY-NET-BIND-TOTALITY)', () => {
  const doublingKey = (n: number, base: string): string => {
    const lines = [`const a0 = '${base}';`];
    for (let i = 1; i <= n; i++) lines.push(`const a${String(i)} = a${String(i - 1)} + a${String(i - 1)};`);
    return lines.join('\n');
  };
  const linearKey = (n: number, base: string): string => {
    const lines = [`const a0 = '${base}';`];
    for (let i = 1; i <= n; i++) lines.push(`const a${String(i)} = a${String(i - 1)};`);
    return lines.join('\n');
  };

  // --- FINDING A — output-length bound ---------------------------------------------------------
  // A shallow doubling chain whose resolved length is exponential in N: the repaired resolver does
  // BOUNDED work (no OOM, no hang) and never materializes the 2^N string. Under the OLD resolver
  // this N=30 source built a >1 GB string on ~60 visits. `netResolveVisits` staying tiny is the
  // structural proof that resolution stopped early rather than folding the whole tree.
  it('does bounded work on an exponentially-growing doubling chain (no huge allocation)', () => {
    const src = `${doublingKey(30, 'x')}\nvoid globalThis[a30];`;
    expect(usesOutboundNetwork(src)).toBe(false); // the resolved value is not a network member
    expect(netResolveVisits).toBeGreaterThan(0);
    expect(netResolveVisits).toBeLessThan(1000); // linear in N, not 2^N
  }, 4000);

  it('does bounded work on the reported doubling family N=40 (a0 = fe)', () => {
    const src = `${doublingKey(40, 'fe')}\nvoid globalThis[a40];`;
    expect(usesOutboundNetwork(src)).toBe(false);
    expect(netResolveVisits).toBeLessThan(1000);
  }, 4000);

  // The length bound stops tracking a value that can no longer equal a capability name, but never
  // rejects a genuine short fold: every `fetch` / `WebSocket` fold (and every prefix of one) is
  // within MAX_NETWORK_MEMBER_LENGTH, for direct, multi-part, and const-chain forms.
  const genuineFolds: readonly { readonly form: string; readonly source: string }[] = [
    { form: "a two-part 'fe' + 'tch'", source: `globalThis['fe' + 'tch']('https://example.com/');` },
    { form: "a five-part 'f'+'e'+'t'+'c'+'h'", source: `globalThis['f' + 'e' + 't' + 'c' + 'h']('https://example.com/');` },
    { form: "a two-part 'Web' + 'Socket'", source: `void new globalThis['Web' + 'Socket']('wss://example.com/');` },
    { form: "a nine-part W+e+b+S+o+c+k+e+t", source: `void new globalThis['W' + 'e' + 'b' + 'S' + 'o' + 'c' + 'k' + 'e' + 't']('wss://example.com/');` },
    { form: 'a genuine three-hop const chain', source: `const a = 'fetch';\nconst b = a;\nconst key = b;\nglobalThis[key]('https://example.com/');` },
  ];
  for (const { form, source } of genuineFolds) {
    it(`still REJECTS ${form} under the length bound`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // A benign computed member that exceeds the capability-name length is still allowed (a static
  // literal key is read directly, not folded, so it is unaffected by the fold-length bound).
  it('still ALLOWS a benign over-length computed member', () => {
    expect(usesOutboundNetwork(`void globalThis['ordinaryLocalMember'];`)).toBe(false);
    expect(usesOutboundNetwork(`void globalThis['con' + 'sole'];`)).toBe(false); // 'console' ≤ 9
  });

  // --- FINDING B — recursion-depth / stack totality -------------------------------------------
  // A long linear identifier chain to a genuine capability resolves ITERATIVELY: it is still
  // REJECTED (not demoted to null, not a RangeError) at depths that crashed the old resolver.
  for (const N of [500, 2000, 10000]) {
    it(`still REJECTS a genuine linear fetch chain N=${String(N)} (iterative, no stack overflow)`, () => {
      expect(usesOutboundNetwork(`${linearKey(N, 'fetch')}\nglobalThis[a${String(N)}]('https://example.com/');`)).toBe(true);
    }, 8000);
    it(`still REJECTS a genuine linear WebSocket chain N=${String(N)}`, () => {
      expect(usesOutboundNetwork(`${linearKey(N, 'WebSocket')}\nvoid new globalThis[a${String(N)}]('wss://example.com/');`)).toBe(true);
    }, 8000);
  }

  // A long linear chain to a benign value is allowed without crashing.
  it('ALLOWS a long linear chain to a benign value without a stack overflow', () => {
    expect(usesOutboundNetwork(`${linearKey(10000, 'safe')}\nvoid globalThis[a10000];`)).toBe(false);
  }, 8000);

  // A chain deep enough to exceed the recursion-depth cap yields a BOUNDED verdict (no RangeError,
  // no hang) — Indeterminate, which at a free-global receiver is DENIED fail-closed (the key could
  // be a capability at runtime). The identifier-indirected empty-base doubling reaches the `+`-fold
  // recursion cap and aborts.
  for (const N of [1200, 2000, 4000]) {
    it(`denies fail-closed past the depth cap (empty-base doubling N=${String(N)})`, () => {
      expect(usesOutboundNetwork(`${doublingKey(N, '')}\nvoid globalThis[a${String(N)}];`)).toBe(true);
    }, 8000);
  }

  // --- VISIT-BUDGET throw audit ---------------------------------------------------------------
  // The visit-budget ceiling now ABORTS to Indeterminate (caught at the member boundary; denied
  // fail-closed) instead of throwing an uncaught Error; a resolution within budget is unaffected.
  it('resolves within the visit budget without throwing', () => {
    expect(() => usesOutboundNetwork(`${linearKey(4000, 'fetch')}\nglobalThis[a4000]('https://example.com/');`)).not.toThrow();
  }, 8000);

  // --- INTERACTION MATRIX (both bounds compose) -----------------------------------------------
  it('1. shallow but exponentially-growing string → bounded, allowed', () => {
    expect(usesOutboundNetwork(`${doublingKey(30, 'x')}\nvoid globalThis[a30];`)).toBe(false);
  }, 4000);
  it('2. deep but constant-size string → bounded, allowed', () => {
    expect(usesOutboundNetwork(`${linearKey(8000, 'safe')}\nvoid globalThis[a8000];`)).toBe(false);
  }, 8000);
  it('3. deep AND growing string → bounded, denied fail-closed (depth abort)', () => {
    // Resolving a4000 recurses down to a0 (~2N depth) BEFORE the length bound can fire, so it hits
    // the depth cap and aborts → Indeterminate → DENY. Bounded (no RangeError), fail-closed.
    expect(usesOutboundNetwork(`${doublingKey(4000, 'x')}\nvoid globalThis[a4000];`)).toBe(true);
  }, 8000);
  it('4. depth-limit path after a cached valid result (genuine still rejected)', () => {
    // genuine short chain first (caches a valid result), then a deep chain in the same source.
    const src = `const good = 'fetch';\n${doublingKey(2000, '')}\nglobalThis[good]('https://example.com/');\nvoid globalThis[a2000];`;
    expect(usesOutboundNetwork(src)).toBe(true); // genuine 'good' detected; deep chain aborts → denied
  }, 8000);
  it('5. length-limit path after a cached valid result (genuine still rejected)', () => {
    const src = `const good = 'fetch';\n${doublingKey(30, 'x')}\nvoid globalThis[a30];\nglobalThis[good]('https://example.com/');`;
    expect(usesOutboundNetwork(src)).toBe(true);
  }, 4000);
  it('6. valid fetch after an earlier null (separate calls, shared nothing)', () => {
    expect(usesOutboundNetwork(`${doublingKey(30, 'x')}\nvoid globalThis[a30];`)).toBe(false);
    expect(usesOutboundNetwork(`globalThis['fetch']('https://example.com/');`)).toBe(true);
  }, 4000);
  it('7. valid WebSocket after an earlier null', () => {
    expect(usesOutboundNetwork(`${linearKey(5000, 'safe')}\nvoid globalThis[a5000];`)).toBe(false);
    expect(usesOutboundNetwork(`void new globalThis['Web' + 'Socket']('wss://example.com/');`)).toBe(true);
  }, 8000);
  it('8. null after a valid chain (both in one source, genuine rejected)', () => {
    const src = `const key = 'fetch';\n${doublingKey(30, 'x')}\nglobalThis[key]('https://example.com/');\nvoid globalThis[a30];`;
    expect(usesOutboundNetwork(src)).toBe(true);
  }, 4000);
  it('9. repeated NotCapability key reuse stays bounded and allowed', () => {
    const lines = [doublingKey(30, 'x')];
    for (let j = 0; j < 50; j++) lines.push(`void globalThis[a30];`);
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(false);
    expect(netResolveVisits).toBeLessThan(1000); // shared memo: the NotCapability chain resolved once
  }, 4000);
  it('10. shared traversal memo after a NotCapability result does not poison a genuine key', () => {
    const src = `${doublingKey(30, 'x')}\nconst good = 'fetch';\nvoid globalThis[a30];\nglobalThis[good]('https://example.com/');`;
    expect(usesOutboundNetwork(src)).toBe(true);
  }, 4000);

  // --- P1 — a resource abort DENIES fail-closed (D3-CX-POLICY-NET-KEY) -------------------------
  // The exact reported reproducer: a genuine `fetch` chain that the resolver ABORTS on (its `+`-fold
  // recursion exceeds the depth cap) must be DENIED, not allowed. Under the old "abort → null →
  // allow" mapping this was a genuine egress false negative.
  it('denies the reported depth-abort fetch chain fail-closed (P1)', () => {
    const lines = [`const shared = 'fetch';`, `const n0 = shared;`];
    for (let i = 1; i <= 2500; i++) lines.push(`const n${String(i)} = '' + n${String(i - 1)};`);
    lines.push(`globalThis[n2500]('https://example.com/');`);
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(true);
  }, 8000);
  it('denies a depth-abort WebSocket chain fail-closed (P1)', () => {
    const lines = [`const shared = 'WebSocket';`, `const n0 = shared;`];
    for (let i = 1; i <= 2500; i++) lines.push(`const n${String(i)} = '' + n${String(i - 1)};`);
    lines.push(`void new globalThis[n2500]('wss://example.com/');`);
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(true);
  }, 8000);

  // --- MEMO SAFETY — a resource-bound abort is NOT cached (context-dependent) ------------------
  // Mandatory adversarial shape: a declaration reached once past the depth cap (aborted, not
  // cached) must still classify correctly when reached directly from a shallow path in the SAME
  // traversal. A genuine `good = 'fetch'` sits alongside a depth-exceeding chain; both DENY, and
  // `good` is detected directly (the abort did not poison the shared memo).
  it('does not cache a depth-bound abort for a shared declaration', () => {
    const src = [
      doublingKey(2500, ''), // exceeds the depth cap → NetResolveAbort → not memoized → denied
      `const good = 'fetch';`,
      `void globalThis[a2500];`, // aborts → Indeterminate → denied fail-closed
      `globalThis[good]('https://example.com/');`, // genuine, resolved directly → rejected
    ].join('\n');
    expect(usesOutboundNetwork(src)).toBe(true);
  }, 8000);

  // The exact prescribed adversarial shape: a genuine `shared = 'fetch'` reached PAST the depth
  // cap on a deep `+`-nested path (`nK = '' + nK-1`, which aborts and is NOT memoized) must still
  // be detected when reached DIRECTLY from a shallow path in the SAME traversal (shared memo).
  it('resolves a shared genuine decl directly after a deep-path abort left it uncached', () => {
    const lines = [`const shared = 'fetch';`, `const n0 = shared;`];
    for (let i = 1; i <= 1500; i++) lines.push(`const n${String(i)} = '' + n${String(i - 1)};`);
    lines.push(`void globalThis[n1500];`); // deep path → NetResolveAbort → bounded null, not cached
    lines.push(`globalThis[shared]('https://example.com/');`); // shallow direct → 'fetch' → rejected
    expect(usesOutboundNetwork(lines.join('\n'))).toBe(true);
  }, 8000);

  // Two distinct declarations sharing a NotCapability shape each resolve independently; a genuine
  // one alongside a NotCapability one is still rejected (no cross-contamination via the shared memo).
  it('keeps a NotCapability chain and a genuine chain independent within one source', () => {
    const src = `${doublingKey(30, 'x')}\nconst g = 'Web';\nconst ws = g + 'Socket';\nvoid globalThis[a30];\nvoid new globalThis[ws]('wss://example.com/');`;
    expect(usesOutboundNetwork(src)).toBe(true);
  }, 4000);

  // --- FAIL-CLOSED (NET self-contained) -------------------------------------------------------
  // A computed free-global key the NET path cannot pin down is Indeterminate and is DENIED by NET
  // itself: ambient, mutated, and undeclared keys.
  const failClosed: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'an ambient declare const key', source: `declare const k: string;\nglobalThis[k]('https://example.com/');` },
    { form: 'a mutated let key', source: `let k = 'fetch';\nk = 'other';\nglobalThis[k]('https://example.com/');` },
    { form: 'an undeclared free-global key', source: `void globalThis[neverDeclared];` },
  ];
  for (const { form, source } of failClosed) {
    it(`rejects ${form} fail-closed by NET`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- CYCLE termination under the new spine/bounds (denied fail-closed) ----------------------
  const cycles: readonly { readonly form: string; readonly source: string }[] = [
    { form: 'a self cycle const a = a', source: `const a = a;\nglobalThis[a]('https://example.com/');` },
    { form: 'a 2-node cycle a = b, b = a', source: `const a = b;\nconst b = a;\nglobalThis[a]('https://example.com/');` },
    { form: 'a 3-node cycle a = b, b = c, c = a', source: `const a = b;\nconst b = c;\nconst c = a;\nglobalThis[a]('https://example.com/');` },
  ];
  for (const { form, source } of cycles) {
    it(`terminates ${form} and is denied fail-closed by NET`, () => {
      expect(usesOutboundNetwork(source)).toBe(true);
    });
  }

  // --- POISONED-BINDING now DENIED fail-closed (frozen key policy supersedes the earlier allow) -
  // An out-of-scope `const Infinity = 'fetch'` leaves `globalThis[Infinity]` Indeterminate, so it is
  // denied — the analyzer cannot prove the runtime key is not a capability, and fail-closed wins.
  it('denies the poisoned-binding cases fail-closed', () => {
    expect(usesOutboundNetwork(`function f() {\n  const Infinity = 'fetch';\n}\nvoid globalThis[Infinity];`)).toBe(true);
    expect(usesOutboundNetwork(`function f() {\n  const Infinity = 'fetch';\n}\nconst key = Infinity;\nvoid globalThis[key];`)).toBe(true);
  });
});
