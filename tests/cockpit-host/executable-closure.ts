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

/** True when a binding name (identifier or destructuring pattern) binds `name`. */
function bindingBinds(binding: ts.BindingName, name: string): boolean {
  if (ts.isIdentifier(binding)) return binding.text === name;
  for (const element of binding.elements) {
    if (ts.isOmittedExpression(element)) continue;
    if (bindingBinds(element.name, name)) return true;
  }
  return false;
}

/** The parameter list of a function-like node, or undefined for anything else. */
function functionLikeParameters(node: ts.Node): readonly ts.ParameterDeclaration[] | undefined {
  if (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  ) {
    return node.parameters;
  }
  return undefined;
}

/** The statement list of a scope-bearing node (source file, block, module block). */
function scopeStatements(node: ts.Node): readonly ts.Statement[] | undefined {
  if (ts.isSourceFile(node) || ts.isBlock(node) || ts.isModuleBlock(node)) return node.statements;
  return undefined;
}

/** True when a for-loop or catch clause introduces its own (shadowing) binding of `name`. */
function introducesBinding(node: ts.Node, name: string): boolean {
  if (ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
    const initializer = node.initializer;
    return (
      initializer !== undefined &&
      ts.isVariableDeclarationList(initializer) &&
      initializer.declarations.some((declaration) => bindingBinds(declaration.name, name))
    );
  }
  if (ts.isCatchClause(node)) {
    return node.variableDeclaration !== undefined && bindingBinds(node.variableDeclaration.name, name);
  }
  return false;
}

/**
 * Classify the nearest declaration of `name` in one scope's statements:
 * an immutable `const <name> = <string|number literal>` yields that literal;
 * a `let`/`var`, a `const` with a non-literal or computed initializer, or a
 * destructured binding is a real shadow that fails closed (`unresolved`);
 * `undefined` means this scope does not declare `name` (keep looking outward).
 */
function classifyInStatements(statements: readonly ts.Statement[], name: string): ResolvedArg | undefined {
  for (const statement of statements) {
    if (!ts.isVariableStatement(statement)) continue;
    const isConst = (statement.declarationList.flags & ts.NodeFlags.Const) !== 0;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name)) {
        if (declaration.name.text !== name) continue;
        if (!isConst) return { kind: 'unresolved' };
        const init = declaration.initializer;
        if (init !== undefined && ts.isStringLiteral(init)) return { kind: 'string', value: init.text };
        if (init !== undefined && ts.isNumericLiteral(init)) return { kind: 'number', value: Number(init.text) };
        return { kind: 'unresolved' };
      }
      if (bindingBinds(declaration.name, name)) return { kind: 'unresolved' };
    }
  }
  return undefined;
}

/**
 * Resolve an identifier used as a `listen` argument to the immutable literal
 * actually visible at its use site (rule D, "if statically resolvable").
 *
 * The parse carries parent links, so this walks enclosing scopes innermost-first
 * — the body block, then any function parameters, then outward to the module —
 * and returns the FIRST scope that declares the name. A nearer lexical `const`
 * literal therefore shadows the top-level one; a nearer `let`/`var`, parameter,
 * destructured, or non-literal `const` binding fails closed. It is not a
 * data-flow or alias engine: it follows no assignment, no aliasing, and never
 * leaves this file; it only reads which lexical declaration is in scope.
 */
function resolveIdentifierLexically(useSite: ts.Node, name: string): ResolvedArg {
  let scope: ts.Node = useSite;
  for (;;) {
    if (introducesBinding(scope, name)) return { kind: 'unresolved' };
    const parameters = functionLikeParameters(scope);
    if (parameters !== undefined && parameters.some((parameter) => bindingBinds(parameter.name, name))) {
      return { kind: 'unresolved' };
    }
    const statements = scopeStatements(scope);
    if (statements !== undefined) {
      const found = classifyInStatements(statements, name);
      if (found !== undefined) return found;
    }
    if (ts.isSourceFile(scope)) return { kind: 'unresolved' };
    scope = scope.parent;
  }
}

/** Resolve a call argument to a literal (string/number) or a lexically-visible `const` literal. */
function resolveArg(arg: ts.Expression | undefined): ResolvedArg {
  if (arg === undefined) return { kind: 'unresolved' };
  if (ts.isStringLiteral(arg)) return { kind: 'string', value: arg.text };
  if (ts.isNumericLiteral(arg)) return { kind: 'number', value: Number(arg.text) };
  if (ts.isIdentifier(arg)) return resolveIdentifierLexically(arg, arg.text);
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

/** Strip transparent parenthesization: `((expr))` -> `expr`. Purely syntactic. */
function unwrapParens(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current)) current = current.expression;
  return current;
}

/** True when a receiver expression is (a parenthesized form of) an http-binding identifier. */
function receiverIsHttpBinding(expression: ts.Expression, httpBindings: ReadonlySet<string>): boolean {
  const receiver = unwrapParens(expression);
  return ts.isIdentifier(receiver) && httpBindings.has(receiver.text);
}

/**
 * True when a call's callee is a *direct* `createServer` access on the imported
 * `node:http` binding, recognized up to transparent syntax only:
 *   `http.createServer`, `(http).createServer`, `http['createServer']`,
 *   and a bare `createServer` bound from `import { createServer } from 'node:http'`.
 * The member name / static index string must be exactly `createServer`, and the
 * receiver must be the http binding identifier. A computed index, or any other
 * name, is not this authored-site class. No alias, value, receiver, or provenance
 * is followed — only the written syntax is normalized (rule D).
 */
function isHttpCreateServerCallee(
  callee: ts.Expression,
  defaultOrNamespace: ReadonlySet<string>,
  named: ReadonlySet<string>,
): boolean {
  const unwrapped = unwrapParens(callee);
  if (ts.isPropertyAccessExpression(unwrapped) && unwrapped.name.text === 'createServer') {
    return receiverIsHttpBinding(unwrapped.expression, defaultOrNamespace);
  }
  if (
    ts.isElementAccessExpression(unwrapped) &&
    ts.isStringLiteralLike(unwrapped.argumentExpression) &&
    unwrapped.argumentExpression.text === 'createServer'
  ) {
    return receiverIsHttpBinding(unwrapped.expression, defaultOrNamespace);
  }
  return ts.isIdentifier(unwrapped) && named.has(unwrapped.text);
}

/**
 * Find direct `createServer(...)` sites that target the `node:http` import in
 * this file, recognizing the transparent-syntax variants documented on
 * {@link isHttpCreateServerCallee}. This is a statement about the written source
 * structure only; it does not follow `createServer` through variables, returns,
 * factories, callbacks, exports, or aliases (rule D).
 */
export function findHttpCreateServerSites(fileName: string, text: string): CreateServerSite[] {
  const sourceFile = parse(fileName, text);
  const { defaultOrNamespace, named } = httpBindings(sourceFile);
  const relFile = toRepoRelative(realpathSync.native(fileName));
  const sites: CreateServerSite[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && isHttpCreateServerCallee(node.expression, defaultOrNamespace, named)) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      sites.push({ file: relFile, line: line + 1 });
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
        port: resolveArg(node.arguments[0]),
        host: resolveArg(node.arguments[1]),
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return calls;
}
