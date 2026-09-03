/**
 * Finite executable-closure helper for the Cockpit D3 host source guard.
 *
 * This module answers exactly one question about the *written source*: starting
 * from every `.ts` file beneath `src/cockpit-host/`, which runtime ESM module
 * files execute, and through which specifiers? It is deliberately small and
 * finite. It is NOT a
 * runtime sandbox, taint analyzer, value/provenance tracker, alias tracker, or
 * abstract interpreter, and it makes no claim about what arbitrary hostile
 * JavaScript could do at run time — that guarantee belongs to a separate future
 * process/OS isolation control, not to this source-policy check.
 *
 * The single source of truth for "what is an import" is the TypeScript
 * compiler's own parser (`typescript`, the package the build already uses), so
 * regex-vs-division, ASI, template context, and keyword-named members are
 * decided by the real grammar, never by a hand-rolled lexer. Only *runtime*
 * edges are followed: a type-only `import type … from` / `export type … from`,
 * and inline `type` specifiers, are erased and create no edge.
 */

import { readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import ts from 'typescript';

/** Repository root, canonicalized (real path) so symlinked entries compare honestly. */
export const REPO_ROOT = realpathSync.native(fileURLToPath(new URL('../../', import.meta.url)));

/** The host source root; every `.ts` beneath it is a closure root (rule A). */
export const HOST_DIR = realpathSync.native(fileURLToPath(new URL('../../src/cockpit-host/', import.meta.url)));

/**
 * The exact Node builtins the current host genuinely imports at runtime, derived
 * from `src/cockpit-host/**` (`node:http` for the server, `node:url` for the
 * entry-point check). No larger allowlist is inferred (rule C); every other
 * builtin — `node:fs`, `node:child_process`, `node:process`, … — is rejected.
 */
export const ALLOWED_NODE_BUILTINS: ReadonlySet<string> = new Set(['node:http', 'node:url']);

/**
 * The pinned runtime executable closure, as repository-relative POSIX paths.
 * Rule A requires this be explicit and pinned by test: {@link computeExecutableClosure}
 * must reproduce exactly this set. Any new runtime edge that reaches a file not
 * listed here — or the removal of one that is — fails the closure-equality test.
 */
export const EXPECTED_CLOSURE: readonly string[] = [
  'src/cockpit-host/escape.ts',
  'src/cockpit-host/fixtures/stage-a.ts',
  'src/cockpit-host/render.ts',
  'src/cockpit-host/server.ts',
  'src/cockpit-host/styles.ts',
  'src/cockpit/evidence-freshness-projection.ts',
  'src/cockpit/index.ts',
  'src/cockpit/read-model.ts',
  'src/domain/evidence-freshness.ts',
  'src/domain/evidence.ts',
  'src/domain/repair-job.ts',
  'src/domain/review.ts',
];

/** Deterministic UTF-16 code-unit ordering, so `cockpit-host/` precedes `cockpit/`. */
const byCodeUnit = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Parse one source's text into an AST with parent links (for line lookups). */
function parse(fileName: string, text: string): ts.SourceFile {
  return ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

/** A `require(...)` occurrence: `specifier` is the static string, or `null` when computed. */
export interface RequireCall {
  readonly specifier: string | null;
}

/** The runtime module references a single source file carries. */
export interface RuntimeReferences {
  /** `import … from 'S'` / side-effect `import 'S'` / `export … from 'S'`, runtime only. */
  readonly staticImports: readonly string[];
  /** `import('S')` with a statically known string specifier (a supported runtime edge). */
  readonly staticDynamicImports: readonly string[];
  /** `import(x)` / `import('a' + b)` / `import(`…${x}…`)` — count of unverifiable dynamic imports. */
  readonly computedDynamicImports: number;
  /** Every `require(...)` and `import x = require(...)` occurrence (forbidden by rule B). */
  readonly requireCalls: readonly RequireCall[];
}

/** True when a named import/export clause contains at least one non-`type` (value) member. */
function hasValueMember(
  elements: readonly ts.ImportSpecifier[] | readonly ts.ExportSpecifier[],
): boolean {
  return elements.some((element) => !element.isTypeOnly);
}

/** True when an `import … from` declaration keeps a runtime edge (not fully erased). */
function importIsRuntime(clause: ts.ImportClause): boolean {
  // `import type …` (phase modifier `type`) is erased; a `defer` phase still loads.
  if (clause.phaseModifier === ts.SyntaxKind.TypeKeyword) return false;
  if (clause.name !== undefined) return true; // default value binding
  const named = clause.namedBindings;
  if (named === undefined) return false;
  if (ts.isNamespaceImport(named)) return true;
  return hasValueMember(named.elements);
}

/** True when an `export … from` declaration keeps a runtime edge (not fully erased). */
function exportIsRuntime(node: ts.ExportDeclaration): boolean {
  if (node.isTypeOnly) return false;
  const clause = node.exportClause;
  if (clause === undefined) return true; // export * from 'S'
  if (ts.isNamespaceExport(clause)) return true; // export * as ns from 'S'
  return hasValueMember(clause.elements);
}

/**
 * Collect the runtime module references from one source file, using the
 * TypeScript AST. Type-only import/export declarations and inline `type`
 * specifiers are treated as erased and contribute no edge (rule A).
 */
export function collectRuntimeReferences(fileName: string, text: string): RuntimeReferences {
  const sourceFile = parse(fileName, text);
  const staticImports: string[] = [];
  const staticDynamicImports: string[] = [];
  const requireCalls: RequireCall[] = [];
  let computedDynamicImports = 0;

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const clause = node.importClause;
      if (clause === undefined || importIsRuntime(clause)) {
        // No clause => side-effect import (always a runtime edge).
        staticImports.push(node.moduleSpecifier.text);
      }
    } else if (
      ts.isExportDeclaration(node) &&
      node.moduleSpecifier !== undefined &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      if (exportIsRuntime(node)) staticImports.push(node.moduleSpecifier.text);
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      // `import x = require('S')` — CommonJS interop, forbidden as a runtime require.
      const arg = node.moduleReference.expression;
      requireCalls.push({ specifier: ts.isStringLiteralLike(arg) ? arg.text : null });
    } else if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        if (arg !== undefined && ts.isStringLiteralLike(arg)) staticDynamicImports.push(arg.text);
        else computedDynamicImports += 1;
      } else if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
        const arg = node.arguments[0];
        requireCalls.push({ specifier: arg !== undefined && ts.isStringLiteralLike(arg) ? arg.text : null });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  return { staticImports, staticDynamicImports, computedDynamicImports, requireCalls };
}

/** The result of resolving one relative specifier against its importer. */
export interface Resolution {
  readonly ok: boolean;
  /** Canonical (real-path) target when `ok`. */
  readonly target?: string;
  /** Why resolution failed, when not `ok`. */
  readonly reason?: string;
}

/** An encoded path separator can never be read as an in-tree segment; fail closed. */
const ENCODED_SEPARATOR = /%2f|%5c/i;

/**
 * Resolve a *relative* specifier exactly as Node's ESM loader would — WHATWG
 * `new URL(specifier, importerFileUrl)`, so `.`/`..` and their percent-encoded
 * forms fold correctly — then map the `.js` request onto its `.ts` source and
 * canonicalize with `realpathSync` so a symlinked file resolves to its real
 * location (and thus fails closure membership if it escapes the pinned set).
 * Fails closed on an encoded separator, a malformed escape, or a missing file.
 */
export function resolveRelativeSpecifier(importerRealPath: string, specifier: string): Resolution {
  let resolvedPath: string;
  try {
    const importerUrl = pathToFileURL(importerRealPath);
    const resolvedUrl = new URL(specifier, importerUrl);
    if (ENCODED_SEPARATOR.test(resolvedUrl.pathname)) return { ok: false, reason: 'encoded-separator' };
    resolvedPath = fileURLToPath(resolvedUrl);
  } catch {
    return { ok: false, reason: 'malformed-specifier' };
  }
  const candidates = specifier.endsWith('.js')
    ? [resolvedPath.replace(/\.js$/, '.ts'), resolvedPath]
    : [resolvedPath, `${resolvedPath}.ts`];
  for (const candidate of candidates) {
    try {
      if (statSync(candidate).isFile()) return { ok: true, target: realpathSync.native(candidate) };
    } catch {
      // try the next candidate
    }
  }
  return { ok: false, reason: 'unresolved' };
}

/** Repo-relative POSIX form of an absolute path. */
export function toRepoRelative(absolutePath: string): string {
  return relative(REPO_ROOT, absolutePath).replace(/\\/g, '/');
}

/** One followed runtime edge in the closure walk. */
export interface ClosureEdge {
  readonly from: string; // repo-relative
  readonly specifier: string;
  readonly to: string; // repo-relative
  readonly kind: 'import' | 'dynamic';
}

/** The computed runtime executable closure and any policy violations found while walking. */
export interface ClosureResult {
  readonly files: readonly string[]; // repo-relative POSIX, sorted
  readonly edges: readonly ClosureEdge[];
  readonly usedBuiltins: readonly string[]; // sorted
  readonly violations: readonly string[];
}

/** Every `.ts` file beneath the host root, canonicalized — the closure roots (rule A). */
function hostRoots(): string[] {
  return readdirSync(HOST_DIR, { recursive: true })
    .map((entry) => String(entry))
    .filter((name) => name.endsWith('.ts'))
    .map((name) => realpathSync.native(join(HOST_DIR, name)));
}

/**
 * Walk the runtime executable closure from the host roots. Follows only runtime
 * edges; classifies each specifier as an allowed builtin, an in-tree relative
 * target, or a violation (bare specifier, disallowed builtin, `require`,
 * computed dynamic import, or unresolved relative target). Every static dynamic
 * import that resolves is followed as an ordinary edge.
 */
export function computeExecutableClosure(): ClosureResult {
  const closure = new Set<string>(hostRoots());
  const queue: string[] = [...closure];
  const edges: ClosureEdge[] = [];
  const builtins = new Set<string>();
  const violations: string[] = [];

  while (queue.length > 0) {
    const file = queue.shift();
    if (file === undefined) break;
    const fromRel = toRepoRelative(file);
    const references = collectRuntimeReferences(file, readFileSync(file, 'utf8'));

    for (const call of references.requireCalls) {
      violations.push(`require(${call.specifier ?? '<computed>'}) in ${fromRel}`);
    }
    if (references.computedDynamicImports > 0) {
      violations.push(`${String(references.computedDynamicImports)} computed dynamic import(s) in ${fromRel}`);
    }

    const relativeEdges: { specifier: string; kind: 'import' | 'dynamic' }[] = [
      ...references.staticImports.map((specifier) => ({ specifier, kind: 'import' as const })),
      ...references.staticDynamicImports.map((specifier) => ({ specifier, kind: 'dynamic' as const })),
    ];

    for (const { specifier, kind } of relativeEdges) {
      if (specifier.startsWith('node:')) {
        builtins.add(specifier);
        if (!ALLOWED_NODE_BUILTINS.has(specifier)) {
          violations.push(`disallowed builtin '${specifier}' in ${fromRel}`);
        }
        continue;
      }
      if (!specifier.startsWith('.')) {
        violations.push(`bare specifier '${specifier}' in ${fromRel}`);
        continue;
      }
      const resolution = resolveRelativeSpecifier(file, specifier);
      if (!resolution.ok || resolution.target === undefined) {
        violations.push(`unresolved '${specifier}' in ${fromRel}`);
        continue;
      }
      const target = resolution.target;
      edges.push({ from: fromRel, specifier, to: toRepoRelative(target), kind });
      if (!closure.has(target)) {
        closure.add(target);
        queue.push(target);
      }
    }
  }

  return {
    files: [...closure].map(toRepoRelative).sort(byCodeUnit),
    edges,
    usedBuiltins: [...builtins].sort(byCodeUnit),
    violations,
  };
}

/** A resolved `createServer`/`listen` argument (literal, or a same-file `const` literal). */
export type ResolvedArg =
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'number'; readonly value: number }
  | { readonly kind: 'unresolved' };

/**
 * Resolve one same-file top-level `const <name> = <literal>` to its literal
 * value. Bounded and single-file by construction — the only "resolution" rule D
 * sanctions ("if statically resolvable"). It is not value-flow: no cross-module
 * tracking, no aliasing, no reassignment following, only a lexical `const`
 * whose initializer is a string or numeric literal.
 */
function resolveConstLiteral(sourceFile: ts.SourceFile, name: string): ResolvedArg {
  for (const statement of sourceFile.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    if ((statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
      const init = declaration.initializer;
      if (init !== undefined && ts.isStringLiteral(init)) return { kind: 'string', value: init.text };
      if (init !== undefined && ts.isNumericLiteral(init)) return { kind: 'number', value: Number(init.text) };
    }
  }
  return { kind: 'unresolved' };
}

/** Resolve a call argument to a literal (string/number) or a same-file `const` literal. */
function resolveArg(sourceFile: ts.SourceFile, arg: ts.Expression | undefined): ResolvedArg {
  if (arg === undefined) return { kind: 'unresolved' };
  if (ts.isStringLiteral(arg)) return { kind: 'string', value: arg.text };
  if (ts.isNumericLiteral(arg)) return { kind: 'number', value: Number(arg.text) };
  if (ts.isIdentifier(arg)) return resolveConstLiteral(sourceFile, arg.text);
  return { kind: 'unresolved' };
}

/** The binding names that refer to the `node:http` module inside one source file. */
function httpBindings(sourceFile: ts.SourceFile): { defaultOrNamespace: Set<string>; named: Set<string> } {
  const defaultOrNamespace = new Set<string>();
  const named = new Set<string>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    if (statement.moduleSpecifier.text !== 'node:http') continue;
    const clause = statement.importClause;
    if (clause === undefined) continue;
    if (clause.name !== undefined) defaultOrNamespace.add(clause.name.text);
    const bindings = clause.namedBindings;
    if (bindings === undefined) continue;
    if (ts.isNamespaceImport(bindings)) defaultOrNamespace.add(bindings.name.text);
    else for (const element of bindings.elements) {
      if (element.propertyName?.text === 'createServer' || element.name.text === 'createServer') {
        named.add(element.name.text);
      }
    }
  }
  return { defaultOrNamespace, named };
}

/** A direct `http.createServer(...)` authored AST site. */
export interface CreateServerSite {
  readonly file: string; // repo-relative
  readonly line: number; // 1-based
}

/**
 * Find direct `createServer(...)` sites that target the `node:http` import in
 * this file: either `<httpDefault>.createServer(...)` or a bare `createServer(...)`
 * bound from `import { createServer } from 'node:http'`. This is a statement
 * about the written source structure only; it does not follow `createServer`
 * through variables, returns, or aliases (rule D).
 */
export function findHttpCreateServerSites(fileName: string, text: string): CreateServerSite[] {
  const sourceFile = parse(fileName, text);
  const { defaultOrNamespace, named } = httpBindings(sourceFile);
  const relFile = toRepoRelative(realpathSync.native(fileName));
  const sites: CreateServerSite[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const isMemberSite =
        ts.isPropertyAccessExpression(callee) &&
        callee.name.text === 'createServer' &&
        ts.isIdentifier(callee.expression) &&
        defaultOrNamespace.has(callee.expression.text);
      const isNamedSite = ts.isIdentifier(callee) && named.has(callee.text);
      if (isMemberSite || isNamedSite) {
        const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
        sites.push({ file: relFile, line: line + 1 });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return sites;
}

/** A `.listen(...)` call with its resolved port and host arguments. */
export interface ListenCall {
  readonly line: number; // 1-based
  readonly port: ResolvedArg;
  readonly host: ResolvedArg;
}

/**
 * Find `.listen(port, host, …)` call sites and resolve their first two
 * positional arguments to literals or same-file `const` literals (rule D). The
 * host binding must be the loopback literal `127.0.0.1`; the port constant
 * structure is preserved when statically resolvable.
 */
export function findListenCalls(fileName: string, text: string): ListenCall[] {
  const sourceFile = parse(fileName, text);
  const calls: ListenCall[] = [];

  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'listen'
    ) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      calls.push({
        line: line + 1,
        port: resolveArg(sourceFile, node.arguments[0]),
        host: resolveArg(sourceFile, node.arguments[1]),
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return calls;
}
