/**
 * Cockpit D3 — network policy for the read-only dashboard host (Stage A).
 *
 * A static, development-time source policy over ONE TypeScript file at a time.
 * It is not a runtime sandbox. The source may contain one server instantiation
 * site, loopback-bound, and must not obtain outbound network capability, socket
 * capability, hidden mutable server capability, or privileged request/response
 * authority beyond the explicitly allow-listed operations. Nothing about
 * runtime server cardinality is claimed: the bound is a static source-site
 * invariant plus a statically proven `127.0.0.1` listen binding.
 *
 * Core structural invariant:
 *
 *     PROVEN_PRIVILEGED_TARGET + NON_ALLOWLISTED_OPERATION = DENY
 *
 * Declared analysis boundary (nothing else is used):
 *   - TypeScript binder identity over a `noLib`/`noResolve` single-file Program
 *   - AST position
 *   - unique `const` bindings and unique bodied local `FunctionDeclaration`s
 *   - finite local propagation through a bounded monotone fixpoint
 *   - finite static-key folding
 *   - the host module graph, only through `analyzeNetworkPolicyTree`: proven
 *     exports of sibling host files (server factories, string constants and
 *     string-returning functions) seeded into their importers
 *
 * One concept, one implementation: `valueSymbolOf` is the only symbol
 * resolution path; `resolveStaticKey` is the only key resolver;
 * `resolvePropagationParameter` is the only parameter-propagation predicate;
 * `expressionFacts` is the only expression-authority lookup;
 * `Context.facts` is the only provenance map; `runFixpoint` is the only fixpoint.
 */

import ts from 'typescript';

// ---------------------------------------------------------------------------
// Public result model
// ---------------------------------------------------------------------------

export type Verdict = 'ALLOW' | 'DENY';
export type AuthorityClass = 'SERVER' | 'REQUEST' | 'RESPONSE';
export type AuthorityOrigin = 'ROOT' | 'ALIAS' | 'PARAM';
export type FixpointState = 'CONVERGED' | 'EXHAUSTED';

type UseViolation =
  | 'ESCAPE'
  | 'MEMBER'
  | 'WRITE'
  | 'DESTRUCTURING'
  | 'EXPORT'
  | 'MUTABLE_BINDING'
  | 'UNCONFINED_RETURN';

export type TargetReason = `${AuthorityClass}_${UseViolation}`;

export type ReasonCode =
  | TargetReason
  | 'ARGUMENTS_USE'
  | 'THIS_EXPRESSION'
  | 'FIXPOINT_EXHAUSTED'
  | 'FREE_GLOBAL_NETWORK'
  | 'GLOBAL_RECEIVER_NETWORK_MEMBER'
  | 'GLOBAL_RECEIVER_RUNTIME_KEY'
  | 'GLOBAL_RECEIVER_ESCAPE'
  | 'GLOBAL_RECEIVER_DESTRUCTURING'
  | 'GLOBAL_RECEIVER_WRITE'
  | 'GLOBAL_RECEIVER_CALL'
  | 'PROCESS_GLOBAL_USE'
  | 'HTTP_CLIENT_CAPABILITY'
  | 'HTTP_IMPORT_EQUALS'
  | 'HTTP_DYNAMIC_IMPORT'
  | 'HTTP_REEXPORT'
  | 'HTTP_NAMESPACE_ESCAPE'
  | 'HTTP_NAMESPACE_RUNTIME_KEY'
  | 'CREATE_SERVER_ESCAPE'
  | 'CREATE_SERVER_NEW'
  | 'CREATE_SERVER_NOT_CALLED'
  | 'CREATE_SERVER_ARITY'
  | 'CREATE_SERVER_MULTIPLE'
  | 'SERVER_LISTEN_BINDING'
  | 'SERVER_CLOSE_CALLBACK'
  | 'RESPONSE_END_ARGUMENT'
  | 'SERVER_FACTORY_ESCAPE'
  | 'LISTENER_NOT_FUNCTION'
  | 'LISTENER_PARAMETER_PATTERN'
  | 'LISTENER_THIS_PARAMETER';

export interface Finding {
  readonly reason: ReasonCode;
  readonly line: number;
  readonly column: number;
  readonly text: string;
}

export interface FixpointReport {
  readonly state: FixpointState;
  readonly iterations: number;
  readonly bound: number;
}

export interface NetworkPolicyResult {
  readonly verdict: Verdict;
  readonly reasons: readonly ReasonCode[];
  readonly findings: readonly Finding[];
  readonly fixpoint: FixpointReport;
}

/** Proven exports of one sibling host file, as seen by an importer (host module graph, tree entry). */
export interface HostModuleExports {
  /** Export names that are confined server factories in the exporting file. */
  readonly factories: ReadonlySet<string>;
  /** The subset of `factories` whose own body instantiates a server (directly or through another instantiating confined factory), as opposed to returning an alias. */
  readonly instantiatingFactories: ReadonlySet<string>;
  /** Export names whose value is a proven string. */
  readonly strings: ReadonlySet<string>;
  /** Export names that are local functions returning only proven strings. */
  readonly stringFunctions: ReadonlySet<string>;
}

export interface NetworkPolicyOptions {
  /** Absolute safety ceiling on fixpoint iterations (test hook; default `DEFAULT_FIXPOINT_CEILING`). */
  readonly fixpointCeiling?: number;
  /** Proven exports of sibling host files, keyed by the exact module specifier text used in this file (set by `analyzeNetworkPolicyTree`). */
  readonly hostImports?: ReadonlyMap<string, HostModuleExports>;
  /** Server-instantiation sites already counted in earlier files of the same host tree (set by `analyzeNetworkPolicyTree`). */
  readonly priorInstantiationSites?: number;
  /** Directory separator the `HostSource.file` names use (test hook; default: the running platform's, as `readdirSync` emits it). */
  readonly separator?: '/' | '\\';
}

export type StaticKey =
  | { readonly kind: 'RESOLVED'; readonly value: string }
  | { readonly kind: 'NOT_CAPABILITY' }
  | { readonly kind: 'INDETERMINATE' };

// ---------------------------------------------------------------------------
// Frozen policy tables
// ---------------------------------------------------------------------------

export const HTTP_MODULE_SPECIFIERS: ReadonlySet<string> = new Set(['node:http', 'http']);
/** Global outbound-network capabilities of the supported Node runtime: HTTP, WebSocket and server-sent events. */
export const NETWORK_GLOBAL_NAMES: ReadonlySet<string> = new Set(['fetch', 'WebSocket', 'EventSource']);
export const GLOBAL_RECEIVER_NAMES: ReadonlySet<string> = new Set(['globalThis', 'window', 'self', 'global']);
/**
 * The free `process` global is a Node authority object (handle introspection,
 * builtin acquisition, environment, signals, exit). Its one permitted runtime
 * use is the real host's entry guard, reading `process.argv[<index>]`.
 */
export const PROCESS_GLOBAL = 'process';
export const PROCESS_ARGV = 'argv';
const CREATE_SERVER = 'createServer';
const SERVER_LISTEN = 'listen';
const SERVER_CLOSE = 'close';
export const SERVER_METHODS: ReadonlySet<string> = new Set([SERVER_LISTEN, SERVER_CLOSE]);
/** The only host a proven SERVER target may listen on (positive policy; compared through the static-key resolver). */
export const LOOPBACK_HOST = '127.0.0.1';
/** Largest decimal port a proven SERVER target may listen on. */
export const PORT_MAX = 65535;
export const REQUEST_READS: ReadonlySet<string> = new Set(['method', 'url']);
const RESPONSE_END = 'end';
export const RESPONSE_METHODS: ReadonlySet<string> = new Set(['setHeader', RESPONSE_END]);
const RESPONSE_STATUS = 'statusCode';

/** Every key the policy ever compares a static string against. */
export const POLICY_KEY_NAMES: readonly string[] = [
  ...HTTP_MODULE_SPECIFIERS,
  ...NETWORK_GLOBAL_NAMES,
  ...GLOBAL_RECEIVER_NAMES,
  PROCESS_GLOBAL,
  PROCESS_ARGV,
  CREATE_SERVER,
  ...SERVER_METHODS,
  ...REQUEST_READS,
  ...RESPONSE_METHODS,
  RESPONSE_STATUS,
  LOOPBACK_HOST,
];

/** A folded string longer than this can never be a policy key: NOT_CAPABILITY. */
export const STATIC_KEY_CEILING: number = POLICY_KEY_NAMES.reduce((max, name) => Math.max(max, name.length), 0);

export const STATIC_KEY_DEPTH_LIMIT = 64;
export const STATIC_KEY_WORK_LIMIT = 10_000;
export const LISTENER_HOP_LIMIT = 32;
export const DEFAULT_FIXPOINT_CEILING = 10_000;

const RESOLVED = (value: string): StaticKey => ({ kind: 'RESOLVED', value });
const NOT_CAPABILITY: StaticKey = { kind: 'NOT_CAPABILITY' };
const INDETERMINATE: StaticKey = { kind: 'INDETERMINATE' };

const isResolvedTo = (key: StaticKey, names: ReadonlySet<string> | string): boolean =>
  key.kind === 'RESOLVED' && (typeof names === 'string' ? key.value === names : names.has(key.value));

// ---------------------------------------------------------------------------
// Analysis context
// ---------------------------------------------------------------------------

type FunctionLike = ts.ArrowFunction | ts.FunctionExpression | ts.FunctionDeclaration;

interface Context {
  readonly sourceFile: ts.SourceFile;
  readonly checker: ts.TypeChecker;
  readonly findings: Finding[];
  /** Every runtime value read, grouped by binder symbol (`valueSymbolOf`). */
  readonly valueReads: Map<ts.Symbol, ts.Identifier[]>;
  /** Runtime value reads that bind to no in-file symbol (free globals under noLib). */
  readonly unboundValueReads: ts.Identifier[];
  /** Symbols introduced by any declaration name in the file (fixpoint bound). */
  readonly declaredSymbols: Set<ts.Symbol>;
  /** Binder-resolved writes per symbol (assignment, compound, update, destructuring, for-in/of). */
  readonly writeCounts: Map<ts.Symbol, number>;
  readonly httpNamespaces: Set<ts.Symbol>;
  readonly createServerBindings: Set<ts.Symbol>;
  readonly calls: ts.CallExpression[];
  readonly variableDeclarations: ts.VariableDeclaration[];
  /** Symbols bound to a local function (FunctionDeclaration or const arrow/function expression). */
  readonly functionBindings: Set<ts.Symbol>;
  readonly thisExpressions: ts.Node[];
  /** THE provenance map: symbol -> set of `${class}:${origin}` facts. */
  readonly facts: Map<ts.Symbol, Set<string>>;
  readonly confinedFactories: Set<ts.Symbol>;
  readonly keyMemo: Map<ts.Declaration, StaticKey>;
  keyWork: number;
  /** Number of `expressionFacts` evaluations (complexity witness for the inspection API). */
  expressionFactsEvaluations: number;
  readonly fixpointCeiling: number;
  /** Proven exports of sibling host files by specifier text (tree entry; empty for a standalone file). */
  readonly hostImports: ReadonlyMap<string, HostModuleExports>;
  /** Server-instantiation sites counted in earlier files of the same tree. */
  readonly priorInstantiationSites: number;
  /** Import bindings seeded as confined server factories from sibling host files. */
  readonly externalFactories: Set<ts.Symbol>;
  /** The subset of `externalFactories` the exporting file proved to instantiate a server. */
  readonly externalInstantiatingFactories: Set<ts.Symbol>;
  /** Confined factories (local or seeded) that instantiate a server (recorded by `checkInstantiationSites`). */
  readonly instantiatingFactories: Set<ts.Symbol>;
  /** Import bindings seeded as proven strings / string-returning functions from sibling host files. */
  readonly externalStrings: Set<ts.Symbol>;
  readonly externalStringFunctions: Set<ts.Symbol>;
  /** Server-instantiation sites found in this file (recorded by `checkInstantiationSites`). */
  instantiationSites: number;
}

const FILE_NAME = 'host.ts';

function createProgram(source: string): { sourceFile: ts.SourceFile; checker: ts.TypeChecker } {
  const parsed = ts.createSourceFile(FILE_NAME, source, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS);
  const host: ts.CompilerHost = {
    getSourceFile: (fileName) => (fileName === FILE_NAME ? parsed : undefined),
    getDefaultLibFileName: () => 'lib.d.ts',
    writeFile: () => undefined,
    getCurrentDirectory: () => '',
    getCanonicalFileName: (fileName) => fileName,
    useCaseSensitiveFileNames: () => true,
    getNewLine: () => '\n',
    fileExists: (fileName) => fileName === FILE_NAME,
    readFile: () => undefined,
    directoryExists: () => false,
    getDirectories: () => [],
  };
  const program = ts.createProgram(
    [FILE_NAME],
    { noLib: true, noResolve: true, types: [], target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext },
    host,
  );
  const sourceFile = program.getSourceFile(FILE_NAME);
  if (sourceFile === undefined) {
    throw new Error('D3 network policy: single-file program did not retain its source file');
  }
  return { sourceFile, checker: program.getTypeChecker() };
}

function deny(ctx: Context, reason: ReasonCode, node: ts.Node): void {
  const { line, character } = ctx.sourceFile.getLineAndCharacterOfPosition(node.getStart(ctx.sourceFile));
  const raw = node.getText(ctx.sourceFile);
  const text = raw.length > 80 ? `${raw.slice(0, 77)}...` : raw;
  ctx.findings.push({ reason, line: line + 1, column: character + 1, text });
}

// ---------------------------------------------------------------------------
// Transparent wrappers and AST position helpers
// ---------------------------------------------------------------------------

type Wrapper =
  | ts.ParenthesizedExpression
  | ts.AsExpression
  | ts.SatisfiesExpression
  | ts.NonNullExpression
  | ts.TypeAssertion;

const isWrapper = (node: ts.Node): node is Wrapper =>
  ts.isParenthesizedExpression(node) ||
  ts.isAsExpression(node) ||
  ts.isSatisfiesExpression(node) ||
  ts.isNonNullExpression(node) ||
  ts.isTypeAssertionExpression(node);

/** Strip identity-preserving wrappers downward. */
export function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (isWrapper(current)) current = current.expression;
  return current;
}

/** Climb identity-preserving wrappers upward; returns the outermost wrapped node and its parent. */
function climb(node: ts.Node): { readonly node: ts.Node; readonly parent: ts.Node } {
  let current = node;
  let parent = current.parent;
  while (isWrapper(parent) && parent.expression === current) {
    current = parent;
    parent = current.parent;
  }
  return { node: current, parent };
}

const isAssignmentOperator = (kind: ts.SyntaxKind): boolean =>
  kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;

const isUpdateExpression = (node: ts.Node): boolean =>
  (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
  (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken);

/**
 * Whether `node` (an identifier or member access) is written: `=`, compound
 * assignment, `++`/`--`, `delete`, a for-in/for-of target, or any position inside
 * a destructuring-assignment pattern that is itself such a target. Wrappers
 * around the target are transparent.
 */
export function isWriteTarget(node: ts.Node): boolean {
  let current = climb(node).node;
  for (;;) {
    const parent = current.parent;
    if (ts.isBinaryExpression(parent) && isAssignmentOperator(parent.operatorToken.kind) && parent.left === current) {
      return true;
    }
    if (isUpdateExpression(parent) || ts.isDeleteExpression(parent)) return true;
    if ((ts.isForInStatement(parent) || ts.isForOfStatement(parent)) && parent.initializer === current) return true;
    if (ts.isArrayLiteralExpression(parent)) {
      current = climb(parent).node;
      continue;
    }
    if (ts.isSpreadElement(parent) || ts.isSpreadAssignment(parent)) {
      current = parent;
      continue;
    }
    if (ts.isPropertyAssignment(parent) && parent.initializer === current) {
      current = climb(parent.parent).node;
      continue;
    }
    if (ts.isShorthandPropertyAssignment(parent)) {
      current = climb(parent.parent).node;
      continue;
    }
    return false;
  }
}

const isDeclarationNameOf = (parent: ts.Node, id: ts.Identifier): boolean =>
  (ts.isVariableDeclaration(parent) ||
    ts.isParameter(parent) ||
    ts.isBindingElement(parent) ||
    ts.isFunctionDeclaration(parent) ||
    ts.isFunctionExpression(parent) ||
    ts.isClassDeclaration(parent) ||
    ts.isClassExpression(parent) ||
    ts.isMethodDeclaration(parent) ||
    ts.isPropertyDeclaration(parent) ||
    ts.isGetAccessorDeclaration(parent) ||
    ts.isSetAccessorDeclaration(parent) ||
    ts.isEnumDeclaration(parent) ||
    ts.isEnumMember(parent) ||
    ts.isModuleDeclaration(parent) ||
    ts.isTypeAliasDeclaration(parent) ||
    ts.isInterfaceDeclaration(parent) ||
    ts.isTypeParameterDeclaration(parent) ||
    ts.isImportClause(parent) ||
    ts.isNamespaceImport(parent) ||
    ts.isNamespaceExport(parent) ||
    ts.isImportEqualsDeclaration(parent) ||
    ts.isPropertySignature(parent) ||
    ts.isMethodSignature(parent) ||
    ts.isPropertyAssignment(parent)) &&
  parent.name === id;

/** Whether an identifier sits inside a type position (never a runtime read). */
function isInTypePosition(node: ts.Node): boolean {
  let current = node;
  let parent = current.parent;
  while (!ts.isSourceFile(parent)) {
    if (ts.isExpressionWithTypeArguments(parent)) {
      const clause = parent.parent;
      const isClassExtends =
        ts.isHeritageClause(clause) && clause.token === ts.SyntaxKind.ExtendsKeyword && ts.isClassLike(clause.parent);
      return !isClassExtends;
    }
    if (ts.isTypeNode(parent)) return true;
    if (ts.isStatement(parent) || ts.isExpression(parent)) return false;
    current = parent;
    parent = current.parent;
  }
  return false;
}

/**
 * THE value-read predicate: is this identifier a runtime read of a binding?
 * Declaration names, property keys, member names, labels, import forms and every
 * type position are not. An `ExportSpecifier` local name is an explicit value
 * use (resolved by `valueSymbolOf`). A shorthand property value is a value use.
 */
export function isValueRead(id: ts.Identifier): boolean {
  const parent = id.parent;
  if (ts.isShorthandPropertyAssignment(parent)) return parent.name === id;
  if (ts.isExportSpecifier(parent)) {
    const declaration = parent.parent.parent;
    if (declaration.moduleSpecifier !== undefined || declaration.isTypeOnly || parent.isTypeOnly) return false;
    return (parent.propertyName ?? parent.name) === id;
  }
  if (ts.isImportSpecifier(parent)) return false;
  if (isDeclarationNameOf(parent, id)) return false;
  if (ts.isBindingElement(parent) && parent.propertyName === id) return false;
  if (ts.isPropertyAccessExpression(parent) && parent.name === id) return false;
  if (ts.isLabeledStatement(parent) || ts.isBreakOrContinueStatement(parent)) return false;
  if (ts.isMetaProperty(parent)) return false;
  if (ts.isQualifiedName(parent)) {
    let root: ts.Node = parent;
    while (ts.isQualifiedName(root.parent)) root = root.parent;
    return ts.isImportEqualsDeclaration(root.parent) && root.parent.moduleReference === root;
  }
  if (ts.isImportEqualsDeclaration(parent)) return parent.moduleReference === id;
  return !isInTypePosition(id);
}

/** THE symbol-resolution helper. Every producer and consumer uses this and nothing else. */
export function valueSymbolOf(checker: ts.TypeChecker, node: ts.Node): ts.Symbol | undefined {
  if (ts.isIdentifier(node) && ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node) {
    return checker.getShorthandAssignmentValueSymbol(node.parent);
  }
  if (ts.isExportSpecifier(node)) return checker.getExportSpecifierLocalTargetSymbol(node);
  if (ts.isIdentifier(node) && ts.isExportSpecifier(node.parent)) {
    return checker.getExportSpecifierLocalTargetSymbol(node.parent);
  }
  return checker.getSymbolAtLocation(node);
}

/** Whether a node is ambient: it or an enclosing declaration carries `declare`. */
function isAmbient(node: ts.Node): boolean {
  let current: ts.Node = node;
  while (!ts.isSourceFile(current)) {
    if (ts.canHaveModifiers(current) && (ts.getCombinedModifierFlags(current as ts.Declaration) & ts.ModifierFlags.Ambient) !== 0) {
      return true;
    }
    current = current.parent;
  }
  return false;
}

const isTypeOnlyImportClause = (clause: ts.ImportClause): boolean =>
  clause.phaseModifier === ts.SyntaxKind.TypeKeyword;

const isExported = (node: ts.Declaration): boolean =>
  (ts.getCombinedModifierFlags(node) & ts.ModifierFlags.Export) !== 0;

const isPlainConst = (declaration: ts.VariableDeclaration): boolean => {
  const scoped: number = ts.getCombinedNodeFlags(declaration) & ts.NodeFlags.BlockScoped;
  const plainConst: number = ts.NodeFlags.Const;
  return scoped === plainConst;
};

/** A declaration that produces a runtime binding (shadows a global at runtime). */
function isRuntimeDeclaration(checker: ts.TypeChecker, declaration: ts.Declaration, visiting: Set<ts.Symbol>): boolean {
  if (isAmbient(declaration)) return false;
  if (ts.isVariableDeclaration(declaration) || ts.isBindingElement(declaration) || ts.isParameter(declaration)) {
    return true;
  }
  if (ts.isFunctionDeclaration(declaration)) return declaration.body !== undefined;
  // A named function expression binds its name inside its own body at runtime.
  if (ts.isFunctionExpression(declaration)) return true;
  if (ts.isClassDeclaration(declaration) || ts.isClassExpression(declaration)) return true;
  if (ts.isImportClause(declaration)) return !isTypeOnlyImportClause(declaration);
  if (ts.isNamespaceImport(declaration)) return !isTypeOnlyImportClause(declaration.parent);
  if (ts.isImportSpecifier(declaration)) {
    return !declaration.isTypeOnly && !isTypeOnlyImportClause(declaration.parent.parent);
  }
  if (ts.isEnumDeclaration(declaration)) {
    return (ts.getCombinedModifierFlags(declaration) & ts.ModifierFlags.Const) === 0;
  }
  if (ts.isModuleDeclaration(declaration)) return isInstantiatedNamespace(checker, declaration, visiting);
  if (ts.isImportEqualsDeclaration(declaration)) return isRuntimeImportEquals(checker, declaration, visiting);
  return false;
}

/**
 * THE runtime import-equals predicate. A non-type-only `import x = ...` is a
 * runtime alias when it references an external module (`require(...)`), is
 * exported — the binder's own rule for what instantiates an enclosing namespace
 * (`export import get = Local.get` emits `fetch.get = Local.get`) — or is a
 * private entity alias whose target is a value: an entity that resolves to a
 * runtime declaration, or one this single-file program cannot resolve at all
 * (an unresolved target is emitted as a value, exactly as `tsc` does). A
 * type-only alias, or a private alias of a type-only entity, is erased.
 */
function isRuntimeImportEquals(
  checker: ts.TypeChecker,
  declaration: ts.ImportEqualsDeclaration,
  visiting: Set<ts.Symbol>,
): boolean {
  if (declaration.isTypeOnly) return false;
  if (ts.isExternalModuleReference(declaration.moduleReference) || isExported(declaration)) return true;
  const target = valueSymbolOf(checker, declaration.moduleReference);
  if (target?.declarations === undefined || target.declarations.length === 0) return true;
  return isRuntimeShadowed(checker, target, visiting);
}

/**
 * A non-ambient `namespace` produces a runtime binding only when it is
 * instantiated: its body (or a nested namespace body) declares a value —
 * a variable, a bodied function, a class, or a runtime enum. A namespace that
 * holds only types is erased and shadows nothing at runtime.
 */
function isInstantiatedNamespace(checker: ts.TypeChecker, declaration: ts.ModuleDeclaration, visiting: Set<ts.Symbol>): boolean {
  if (!ts.isIdentifier(declaration.name) || declaration.body === undefined) return false;
  if (ts.isModuleDeclaration(declaration.body)) return isInstantiatedNamespace(checker, declaration.body, visiting);
  if (!ts.isModuleBlock(declaration.body)) return false;
  return declaration.body.statements.some((statement) => {
    if (isAmbient(statement)) return false;
    if (ts.isVariableStatement(statement) || ts.isClassDeclaration(statement)) return true;
    if (ts.isFunctionDeclaration(statement)) return statement.body !== undefined;
    if (ts.isEnumDeclaration(statement)) return (ts.getCombinedModifierFlags(statement) & ts.ModifierFlags.Const) === 0;
    if (ts.isModuleDeclaration(statement)) return isInstantiatedNamespace(checker, statement, visiting);
    if (ts.isImportEqualsDeclaration(statement)) return isRuntimeImportEquals(checker, statement, visiting);
    return false;
  });
}

/** Whether a symbol has any runtime declaration; `visiting` bounds alias cycles (a cyclic alias is erased). */
function isRuntimeShadowed(checker: ts.TypeChecker, symbol: ts.Symbol, visiting: Set<ts.Symbol> = new Set()): boolean {
  if (visiting.has(symbol)) return false;
  visiting.add(symbol);
  return (symbol.declarations ?? []).some((declaration) => isRuntimeDeclaration(checker, declaration, visiting));
}

const writeCount = (ctx: Context, symbol: ts.Symbol): number => ctx.writeCounts.get(symbol) ?? 0;

const hasThisParameter = (fn: ts.SignatureDeclaration): boolean =>
  fn.parameters.some((parameter) => ts.isIdentifier(parameter.name) && parameter.name.text === 'this');

const soleDeclaration = (symbol: ts.Symbol | undefined): ts.Declaration | undefined => {
  const declarations = symbol?.declarations ?? [];
  return declarations.length === 1 ? declarations[0] : undefined;
};

/**
 * The unique, immutable `const <identifier> = <initializer>` declaration behind a
 * symbol, or null: exactly one declaration, plain `const`, plain identifier name,
 * non-ambient, initialized, zero binder-resolved writes.
 */
function uniqueConstDeclaration(ctx: Context, symbol: ts.Symbol | undefined): ts.VariableDeclaration | null {
  const declaration = soleDeclaration(symbol);
  if (symbol === undefined || declaration === undefined) return null;
  if (!ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name)) return null;
  if (!isPlainConst(declaration) || isAmbient(declaration) || declaration.initializer === undefined) return null;
  if (writeCount(ctx, symbol) !== 0) return null;
  return declaration;
}

/** The unique, immutable, bodied, non-ambient FunctionDeclaration behind a symbol, or null. */
function uniqueFunctionDeclaration(ctx: Context, symbol: ts.Symbol | undefined): ts.FunctionDeclaration | null {
  const declaration = soleDeclaration(symbol);
  if (symbol === undefined || declaration === undefined || !ts.isFunctionDeclaration(declaration)) return null;
  if (declaration.body === undefined || isAmbient(declaration) || writeCount(ctx, symbol) !== 0) return null;
  return declaration;
}

/** A privileged const alias must additionally not be exported. */
const isConfinedAliasDeclaration = (ctx: Context, declaration: ts.VariableDeclaration): boolean =>
  ts.isIdentifier(declaration.name) &&
  uniqueConstDeclaration(ctx, valueSymbolOf(ctx.checker, declaration.name)) === declaration &&
  !isExported(declaration);

// ---------------------------------------------------------------------------
// THE static-key resolver
// ---------------------------------------------------------------------------

const foldKey = (text: string): StaticKey => (text.length > STATIC_KEY_CEILING ? NOT_CAPABILITY : RESOLVED(text));

const concatKeys = (left: StaticKey, right: StaticKey): StaticKey => {
  if (left.kind === 'INDETERMINATE' || right.kind === 'INDETERMINATE') return INDETERMINATE;
  if (left.kind === 'NOT_CAPABILITY' || right.kind === 'NOT_CAPABILITY') return NOT_CAPABILITY;
  return foldKey(left.value + right.value);
};

function resolveKeyInner(
  ctx: Context,
  expression: ts.Expression,
  depth: number,
  visiting: Set<ts.Declaration>,
): StaticKey {
  ctx.keyWork += 1;
  if (depth > STATIC_KEY_DEPTH_LIMIT || ctx.keyWork > STATIC_KEY_WORK_LIMIT) return INDETERMINATE;
  const node = unwrap(expression);
  if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return foldKey(node.text);
  if (ts.isTemplateExpression(node)) {
    let key = foldKey(node.head.text);
    for (const span of node.templateSpans) {
      key = concatKeys(key, resolveKeyInner(ctx, span.expression, depth + 1, visiting));
      key = concatKeys(key, foldKey(span.literal.text));
    }
    return key;
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return concatKeys(
      resolveKeyInner(ctx, node.left, depth + 1, visiting),
      resolveKeyInner(ctx, node.right, depth + 1, visiting),
    );
  }
  if (ts.isIdentifier(node)) {
    const declaration = uniqueConstDeclaration(ctx, valueSymbolOf(ctx.checker, node));
    if (declaration?.initializer === undefined) return INDETERMINATE;
    const memo = ctx.keyMemo.get(declaration);
    if (memo !== undefined) return memo;
    if (visiting.has(declaration)) return INDETERMINATE;
    visiting.add(declaration);
    const key = resolveKeyInner(ctx, declaration.initializer, depth + 1, visiting);
    visiting.delete(declaration);
    ctx.keyMemo.set(declaration, key);
    return key;
  }
  return INDETERMINATE;
}

/** THE static-key resolver: RESOLVED(value) | NOT_CAPABILITY | INDETERMINATE. */
const resolveStaticKey = (ctx: Context, expression: ts.Expression): StaticKey =>
  resolveKeyInner(ctx, expression, 0, new Set());

/** Key of a property name in a pattern/object literal, through the same resolver. */
function resolvePropertyName(ctx: Context, name: ts.PropertyName): StaticKey {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) return foldKey(name.text);
  if (ts.isComputedPropertyName(name)) return resolveStaticKey(ctx, name.expression);
  return INDETERMINATE;
}

type MemberAccess = ts.PropertyAccessExpression | ts.ElementAccessExpression;

/** Key of a member access, through the same resolver. */
function memberKey(ctx: Context, access: MemberAccess): StaticKey {
  if (ts.isPropertyAccessExpression(access)) {
    return ts.isIdentifier(access.name) ? foldKey(access.name.text) : INDETERMINATE;
  }
  return resolveStaticKey(ctx, access.argumentExpression);
}

const isMemberAccess = (node: ts.Node): node is MemberAccess =>
  ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node);

const isBindingPattern = (node: ts.Node): node is ts.BindingPattern =>
  ts.isObjectBindingPattern(node) || ts.isArrayBindingPattern(node);

// ---------------------------------------------------------------------------
// Collection pass
// ---------------------------------------------------------------------------

function collect(ctx: Context, node: ts.Node): void {
  if (node.kind === ts.SyntaxKind.ThisKeyword) ctx.thisExpressions.push(node);
  if (ts.isIdentifier(node)) {
    if (isDeclarationNameOf(node.parent, node) || (ts.isImportSpecifier(node.parent) && node.parent.name === node)) {
      const declared = valueSymbolOf(ctx.checker, node);
      if (declared !== undefined) ctx.declaredSymbols.add(declared);
    }
    if (isValueRead(node)) {
      const symbol = valueSymbolOf(ctx.checker, node);
      if (symbol === undefined) ctx.unboundValueReads.push(node);
      else {
        const reads = ctx.valueReads.get(symbol);
        if (reads === undefined) ctx.valueReads.set(symbol, [node]);
        else reads.push(node);
      }
    }
  }
  if (ts.isCallExpression(node)) ctx.calls.push(node);
  if (ts.isVariableDeclaration(node)) {
    ctx.variableDeclarations.push(node);
    if (ts.isIdentifier(node.name) && node.initializer !== undefined) {
      const initializer = unwrap(node.initializer);
      if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
        const symbol = valueSymbolOf(ctx.checker, node.name);
        if (symbol !== undefined) ctx.functionBindings.add(symbol);
      }
    }
  }
  if (ts.isFunctionDeclaration(node) && node.name !== undefined) {
    const symbol = valueSymbolOf(ctx.checker, node.name);
    if (symbol !== undefined) ctx.functionBindings.add(symbol);
  }
  ts.forEachChild(node, (child) => {
    collect(ctx, child);
  });
}

function buildWriteInventory(ctx: Context): void {
  for (const [symbol, reads] of ctx.valueReads) {
    const writes = reads.filter((read) => isWriteTarget(read)).length;
    if (writes > 0) ctx.writeCounts.set(symbol, writes);
  }
}

function isHttpSpecifier(expression: ts.Expression | undefined): boolean {
  return expression !== undefined && ts.isStringLiteralLike(expression) && HTTP_MODULE_SPECIFIERS.has(expression.text);
}

/** Recognize supported node:http import forms; deny every other node:http runtime capability route. */
function collectHttpImports(ctx: Context): void {
  for (const statement of ctx.sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && isHttpSpecifier(statement.moduleSpecifier)) {
      const clause = statement.importClause;
      if (clause === undefined || isTypeOnlyImportClause(clause)) continue;
      if (clause.name !== undefined) {
        const symbol = valueSymbolOf(ctx.checker, clause.name);
        if (symbol !== undefined) ctx.httpNamespaces.add(symbol);
      }
      const bindings = clause.namedBindings;
      if (bindings === undefined) continue;
      if (ts.isNamespaceImport(bindings)) {
        const symbol = valueSymbolOf(ctx.checker, bindings.name);
        if (symbol !== undefined) ctx.httpNamespaces.add(symbol);
        continue;
      }
      for (const element of bindings.elements) {
        if (element.isTypeOnly) continue;
        const imported = (element.propertyName ?? element.name).text;
        const symbol = valueSymbolOf(ctx.checker, element.name);
        if (imported === CREATE_SERVER && symbol !== undefined) ctx.createServerBindings.add(symbol);
        else deny(ctx, 'HTTP_CLIENT_CAPABILITY', element);
      }
    }
    if (
      ts.isImportEqualsDeclaration(statement) &&
      ts.isExternalModuleReference(statement.moduleReference) &&
      isHttpSpecifier(statement.moduleReference.expression)
    ) {
      deny(ctx, 'HTTP_IMPORT_EQUALS', statement);
    }
    if (ts.isExportDeclaration(statement) && isHttpSpecifier(statement.moduleSpecifier) && !statement.isTypeOnly) {
      const clause = statement.exportClause;
      const reexportsValue =
        clause === undefined || ts.isNamespaceExport(clause) || clause.elements.some((element) => !element.isTypeOnly);
      if (reexportsValue) deny(ctx, 'HTTP_REEXPORT', statement);
    }
  }
  for (const call of ctx.calls) {
    if (call.expression.kind !== ts.SyntaxKind.ImportKeyword) continue;
    const [specifier] = call.arguments;
    const key = specifier === undefined ? INDETERMINATE : resolveStaticKey(ctx, specifier);
    if (key.kind === 'INDETERMINATE' || isResolvedTo(key, HTTP_MODULE_SPECIFIERS)) deny(ctx, 'HTTP_DYNAMIC_IMPORT', call);
  }
}

/**
 * Host module graph (tree entry only): seed bindings imported from sibling host
 * files with the authority proven there — a confined server factory stays a
 * confined factory in its importer, a proven string stays a proven string —
 * and deny every import form through which a factory could leave the graph
 * unseen (namespace import/re-export, `require`, dynamic import).
 */
function collectHostImports(ctx: Context): void {
  if (ctx.hostImports.size === 0) return;
  const exportsOf = (specifier: ts.Expression | undefined): HostModuleExports | undefined =>
    specifier !== undefined && ts.isStringLiteralLike(specifier) ? ctx.hostImports.get(specifier.text) : undefined;
  for (const statement of ctx.sourceFile.statements) {
    if (ts.isImportDeclaration(statement)) {
      const source = exportsOf(statement.moduleSpecifier);
      const clause = statement.importClause;
      if (source === undefined || clause === undefined || isTypeOnlyImportClause(clause)) continue;
      const seed = (name: ts.Identifier, imported: string): void => {
        const symbol = valueSymbolOf(ctx.checker, name);
        if (symbol === undefined) return;
        if (source.factories.has(imported)) {
          ctx.confinedFactories.add(symbol);
          ctx.externalFactories.add(symbol);
        }
        if (source.instantiatingFactories.has(imported)) ctx.externalInstantiatingFactories.add(symbol);
        if (source.strings.has(imported)) ctx.externalStrings.add(symbol);
        if (source.stringFunctions.has(imported)) ctx.externalStringFunctions.add(symbol);
      };
      if (clause.name !== undefined) seed(clause.name, 'default');
      const bindings = clause.namedBindings;
      if (bindings === undefined) continue;
      if (ts.isNamespaceImport(bindings)) {
        if (source.factories.size > 0) deny(ctx, 'SERVER_FACTORY_ESCAPE', bindings);
        continue;
      }
      for (const element of bindings.elements) {
        if (!element.isTypeOnly) seed(element.name, (element.propertyName ?? element.name).text);
      }
    }
    if (ts.isExportDeclaration(statement) && !statement.isTypeOnly) {
      const source = exportsOf(statement.moduleSpecifier);
      const clause = statement.exportClause;
      if (source !== undefined && source.factories.size > 0 && clause !== undefined && ts.isNamespaceExport(clause)) {
        deny(ctx, 'SERVER_FACTORY_ESCAPE', clause);
      }
    }
    if (ts.isImportEqualsDeclaration(statement) && !statement.isTypeOnly && ts.isExternalModuleReference(statement.moduleReference)) {
      const source = exportsOf(statement.moduleReference.expression);
      if (source !== undefined && source.factories.size > 0) deny(ctx, 'SERVER_FACTORY_ESCAPE', statement);
    }
  }
  for (const call of ctx.calls) {
    if (call.expression.kind !== ts.SyntaxKind.ImportKeyword) continue;
    const [specifier] = call.arguments;
    if (specifier === undefined) continue;
    const literal = unwrap(specifier);
    const key = resolveStaticKey(ctx, specifier);
    const text = ts.isStringLiteralLike(literal) ? literal.text : key.kind === 'RESOLVED' ? key.value : undefined;
    if (text !== undefined && (ctx.hostImports.get(text)?.factories.size ?? 0) > 0) deny(ctx, 'SERVER_FACTORY_ESCAPE', call);
  }
}

// ---------------------------------------------------------------------------
// createServer recognition and listener normalization
// ---------------------------------------------------------------------------

/** A direct, non-optional call whose callee is a proven createServer binding form. */
function isProvenCreateServerCall(ctx: Context, node: ts.Node): node is ts.CallExpression {
  if (!ts.isCallExpression(node) || node.questionDotToken !== undefined) return false;
  const callee = unwrap(node.expression);
  if (ts.isIdentifier(callee)) {
    const symbol = valueSymbolOf(ctx.checker, callee);
    return symbol !== undefined && ctx.createServerBindings.has(symbol);
  }
  if (isMemberAccess(callee) && callee.questionDotToken === undefined) {
    const receiver = unwrap(callee.expression);
    if (!ts.isIdentifier(receiver)) return false;
    const symbol = valueSymbolOf(ctx.checker, receiver);
    return symbol !== undefined && ctx.httpNamespaces.has(symbol) && isResolvedTo(memberKey(ctx, callee), CREATE_SERVER);
  }
  return false;
}

/** A direct, non-optional call of a confined factory binding. */
function isConfinedFactoryCall(ctx: Context, node: ts.Node): node is ts.CallExpression {
  if (!ts.isCallExpression(node) || node.questionDotToken !== undefined) return false;
  const callee = unwrap(node.expression);
  if (!ts.isIdentifier(callee)) return false;
  const symbol = valueSymbolOf(ctx.checker, callee);
  return symbol !== undefined && ctx.confinedFactories.has(symbol);
}

/**
 * The local function a symbol names, when it may receive privileged propagation:
 * (A) a unique const arrow/function expression, or (B) a unique bodied non-ambient
 * FunctionDeclaration with zero binder-resolved writes. Never a `this`-parameter function.
 */
function eligibleCallee(ctx: Context, symbol: ts.Symbol | undefined): FunctionLike | null {
  let fn: FunctionLike | null = uniqueFunctionDeclaration(ctx, symbol);
  if (fn === null) {
    const constDeclaration = uniqueConstDeclaration(ctx, symbol);
    const initializer = constDeclaration?.initializer === undefined ? undefined : unwrap(constDeclaration.initializer);
    if (initializer !== undefined && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))) {
      fn = initializer;
    }
  }
  if (fn === null || hasThisParameter(fn)) return null;
  return fn;
}

/**
 * THE parameter-propagation predicate: the parameter symbol that receives a
 * privileged argument at `argumentIndex` of `call`, or null when the argument
 * may not be propagated (ineligible callee, spread, rest/pattern/missing parameter).
 * Governs both fact propagation and call-site escape permission.
 */
function resolvePropagationParameter(ctx: Context, call: ts.CallExpression, argumentIndex: number): ts.Symbol | null {
  if (call.questionDotToken !== undefined) return null;
  const callee = unwrap(call.expression);
  if (!ts.isIdentifier(callee)) return null;
  const fn = eligibleCallee(ctx, valueSymbolOf(ctx.checker, callee));
  if (fn === null) return null;
  if (call.arguments.slice(0, argumentIndex + 1).some((argument) => ts.isSpreadElement(argument))) return null;
  const parameter = fn.parameters[argumentIndex];
  if (parameter === undefined || parameter.dotDotDotToken !== undefined || !ts.isIdentifier(parameter.name)) return null;
  return valueSymbolOf(ctx.checker, parameter.name) ?? null;
}

/** Normalize the sole createServer argument to a listener function, or null. */
function normalizeListener(ctx: Context, argument: ts.Expression): FunctionLike | null {
  if (ts.isSpreadElement(argument)) return null;
  const visited = new Set<ts.Symbol>();
  let current = unwrap(argument);
  for (let hop = 0; hop <= LISTENER_HOP_LIMIT; hop += 1) {
    if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) return current;
    if (!ts.isIdentifier(current)) return null;
    const symbol = valueSymbolOf(ctx.checker, current);
    if (symbol === undefined || visited.has(symbol)) return null;
    visited.add(symbol);
    const constDeclaration = uniqueConstDeclaration(ctx, symbol);
    if (constDeclaration?.initializer !== undefined) {
      current = unwrap(constDeclaration.initializer);
      continue;
    }
    return uniqueFunctionDeclaration(ctx, symbol);
  }
  return null;
}

const listenerOf = (ctx: Context, call: ts.CallExpression): FunctionLike | null => {
  const [argument] = call.arguments;
  return call.arguments.length === 1 && argument !== undefined ? normalizeListener(ctx, argument) : null;
};

// ---------------------------------------------------------------------------
// THE provenance fixpoint
// ---------------------------------------------------------------------------

interface Fact {
  readonly authority: AuthorityClass;
  readonly origin: AuthorityOrigin;
}

const factKey = (fact: Fact): string => `${fact.authority}:${fact.origin}`;

function addFact(ctx: Context, symbol: ts.Symbol, fact: Fact): boolean {
  const key = factKey(fact);
  const facts = ctx.facts.get(symbol);
  if (facts === undefined) {
    ctx.facts.set(symbol, new Set([key]));
    return true;
  }
  if (facts.has(key)) return false;
  facts.add(key);
  return true;
}

function factsOf(ctx: Context, symbol: ts.Symbol | undefined): readonly Fact[] {
  if (symbol === undefined) return [];
  return [...(ctx.facts.get(symbol) ?? [])].map((key) => {
    const [authority, origin] = key.split(':') as [AuthorityClass, AuthorityOrigin];
    return { authority, origin };
  });
}

/**
 * THE expression-authority lookup: the facts an expression carries — SERVER:ROOT
 * for a proven createServer or confined factory result, a proven identifier's
 * facts, or, through receiver-call result authority inheritance, the facts of
 * the inheriting receiver as computed once by `inheritingReceiverOf`.
 */
function expressionFacts(ctx: Context, expression: ts.Expression): readonly Fact[] {
  ctx.expressionFactsEvaluations += 1;
  const node = unwrap(expression);
  if (isProvenCreateServerCall(ctx, node) || isConfinedFactoryCall(ctx, node)) return [{ authority: 'SERVER', origin: 'ROOT' }];
  if (ts.isIdentifier(node)) return factsOf(ctx, valueSymbolOf(ctx.checker, node));
  return inheritingReceiverOf(ctx, node) ?? [];
}

/**
 * Receiver-call result authority inheritance: the facts of the receiver whose
 * authority a call result conservatively retains, or null when the result
 * inherits nothing. `node` must be a direct, non-optional call whose callee is
 * a member access on an authority-carrying receiver that passes the positive
 * member policy of every class the receiver carries. Nothing about the
 * member's runtime semantics is proven by its name; the result is simply never
 * allowed to become an unrestricted value.
 *
 * The receiver's facts are evaluated exactly once here and handed back to
 * `expressionFacts` as the call result's facts, so a receiver-call chain costs
 * one evaluation per level rather than re-evaluating the receiver per level.
 */
function inheritingReceiverOf(ctx: Context, node: ts.Node): readonly Fact[] | null {
  if (!ts.isCallExpression(node) || node.questionDotToken !== undefined) return null;
  const callee = unwrap(node.expression);
  if (!isMemberAccess(callee)) return null;
  const facts = expressionFacts(ctx, callee.expression);
  if (facts.length === 0) return null;
  const classes = new Set(facts.map((fact) => fact.authority));
  return [...classes].every((authority) => memberAllowed(ctx, authority, callee)) ? facts : null;
}

/** Authority classes carried by an expression, through `expressionFacts`. */
function classesOf(ctx: Context, expression: ts.Expression): ReadonlySet<AuthorityClass> {
  return new Set(expressionFacts(ctx, expression).map((fact) => fact.authority));
}

/** Whether a symbol is SERVER through a non-PARAM origin (root result or alias of one). */
const hasRootedServer = (ctx: Context, symbol: ts.Symbol | undefined): boolean =>
  factsOf(ctx, symbol).some((fact) => fact.authority === 'SERVER' && fact.origin !== 'PARAM');

/** Own-body return expressions of a function (not crossing nested function boundaries). */
function ownReturnExpressions(fn: FunctionLike): readonly (ts.Expression | null)[] {
  if (fn.body === undefined) return [];
  if (!ts.isBlock(fn.body)) return [fn.body];
  const returns: (ts.Expression | null)[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isFunctionLike(node) || ts.isClassLike(node)) return;
    if (ts.isReturnStatement(node)) returns.push(node.expression ?? null);
    ts.forEachChild(node, visit);
  };
  visit(fn.body);
  return returns;
}

function isConfinedReference(id: ts.Identifier): boolean {
  const { node, parent } = climb(id);
  if (ts.isCallExpression(parent) && parent.expression === node && parent.questionDotToken === undefined) return true;
  if (ts.isTypeOfExpression(parent)) return true;
  if (ts.isExportSpecifier(parent)) return true;
  if (ts.isExportAssignment(parent) && !parent.isExportEquals) return true;
  return false;
}

/**
 * Factory confinement: an eligible immutable local callee whose every own-body
 * return is SERVER from a proven createServer call, a confined factory call, or a
 * confined const SERVER alias not derived from PARAM, and whose binding never
 * escapes (declaration, direct identifier-callee call, typeof, export of itself).
 */
function isConfinedFactory(ctx: Context, symbol: ts.Symbol): boolean {
  const fn = eligibleCallee(ctx, symbol);
  if (fn === null || fn.asteriskToken !== undefined) return false;
  if ((ts.getCombinedModifierFlags(fn) & ts.ModifierFlags.Async) !== 0) return false;
  const returns = ownReturnExpressions(fn);
  if (returns.length === 0) return false;
  for (const returned of returns) {
    if (returned === null) return false;
    const value = unwrap(returned);
    if (isProvenCreateServerCall(ctx, value) || isConfinedFactoryCall(ctx, value)) continue;
    if (ts.isIdentifier(value)) {
      const aliasSymbol = valueSymbolOf(ctx.checker, value);
      const declaration = uniqueConstDeclaration(ctx, aliasSymbol);
      if (declaration !== null && isConfinedAliasDeclaration(ctx, declaration) && hasRootedServer(ctx, aliasSymbol)) {
        continue;
      }
    }
    return false;
  }
  return (ctx.valueReads.get(symbol) ?? []).every(isConfinedReference);
}

function fixpointBound(ctx: Context): number {
  const derived = ctx.declaredSymbols.size * 9 + ctx.functionBindings.size + 1;
  return Math.min(derived, ctx.fixpointCeiling);
}

const LISTENER_ROOTS: readonly AuthorityClass[] = ['REQUEST', 'RESPONSE'];

function runFixpoint(ctx: Context): FixpointReport {
  const bound = fixpointBound(ctx);
  const createServerCalls = ctx.calls.filter((call) => isProvenCreateServerCall(ctx, call));
  for (let iteration = 1; iteration <= bound; iteration += 1) {
    let changed = false;
    // 1. listener roots
    for (const call of createServerCalls) {
      const listener = listenerOf(ctx, call);
      if (listener === null || hasThisParameter(listener)) continue;
      LISTENER_ROOTS.forEach((authority, index) => {
        const parameter = listener.parameters[index];
        if (parameter === undefined || parameter.dotDotDotToken !== undefined || !ts.isIdentifier(parameter.name)) return;
        const symbol = valueSymbolOf(ctx.checker, parameter.name);
        if (symbol !== undefined && addFact(ctx, symbol, { authority, origin: 'ROOT' })) changed = true;
      });
    }
    // 2. const aliases
    for (const declaration of ctx.variableDeclarations) {
      if (declaration.initializer === undefined || !ts.isIdentifier(declaration.name)) continue;
      if (!isConfinedAliasDeclaration(ctx, declaration)) continue;
      const symbol = valueSymbolOf(ctx.checker, declaration.name);
      if (symbol === undefined) continue;
      const initializer = unwrap(declaration.initializer);
      if (isProvenCreateServerCall(ctx, initializer) || isConfinedFactoryCall(ctx, initializer)) {
        if (addFact(ctx, symbol, { authority: 'SERVER', origin: 'ROOT' })) changed = true;
      } else {
        for (const fact of expressionFacts(ctx, initializer)) {
          const origin: AuthorityOrigin = fact.origin === 'PARAM' ? 'PARAM' : 'ALIAS';
          if (addFact(ctx, symbol, { authority: fact.authority, origin })) changed = true;
        }
      }
    }
    // 3. factory confinement
    for (const symbol of ctx.functionBindings) {
      if (ctx.confinedFactories.has(symbol) || !isConfinedFactory(ctx, symbol)) continue;
      ctx.confinedFactories.add(symbol);
      changed = true;
    }
    // 4. local parameter propagation
    for (const call of ctx.calls) {
      call.arguments.forEach((argument, index) => {
        const classes = classesOf(ctx, argument);
        if (classes.size === 0) return;
        const target = resolvePropagationParameter(ctx, call, index);
        if (target === null) return;
        for (const authority of classes) {
          if (addFact(ctx, target, { authority, origin: 'PARAM' })) changed = true;
        }
      });
    }
    if (!changed) return { state: 'CONVERGED', iterations: iteration, bound };
  }
  return { state: 'EXHAUSTED', iterations: bound, bound };
}

// ---------------------------------------------------------------------------
// Phase B: classification against the positive policies
// ---------------------------------------------------------------------------

/** The direct, non-optional call whose callee is `access` (through wrappers), or null. */
const directCallOf = (access: ts.Expression): ts.CallExpression | null => {
  const { node, parent } = climb(access);
  return ts.isCallExpression(parent) && parent.expression === node && parent.questionDotToken === undefined ? parent : null;
};

const isDirectCallee = (access: ts.Expression): boolean => directCallOf(access) !== null;

/**
 * The invocation — call (optional or not), construct, or tagged template —
 * whose callee is `access` (through wrappers), or null. Global-receiver path
 * only: every such invocation of a permitted global member is denied.
 */
const memberCallOf = (access: ts.Expression): ts.CallExpression | ts.NewExpression | ts.TaggedTemplateExpression | null => {
  const { node, parent } = climb(access);
  if ((ts.isCallExpression(parent) || ts.isNewExpression(parent)) && parent.expression === node) return parent;
  return ts.isTaggedTemplateExpression(parent) && parent.tag === node ? parent : null;
};

const isNumericLiteralAssignment = (access: ts.Expression): boolean => {
  const { node, parent } = climb(access);
  return (
    ts.isBinaryExpression(parent) &&
    parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    parent.left === node &&
    ts.isNumericLiteral(unwrap(parent.right))
  );
};

/** Class-specific member policy for a proven target used as the receiver of `access`. */
function memberAllowed(ctx: Context, authority: AuthorityClass, access: MemberAccess): boolean {
  if (access.questionDotToken !== undefined) return false;
  const key = memberKey(ctx, access);
  switch (authority) {
    case 'SERVER':
      return isResolvedTo(key, SERVER_METHODS) && isDirectCallee(access);
    case 'REQUEST':
      return isResolvedTo(key, REQUEST_READS) && !isWriteTarget(access);
    case 'RESPONSE':
      return (
        (isResolvedTo(key, RESPONSE_METHODS) && isDirectCallee(access)) ||
        (isResolvedTo(key, RESPONSE_STATUS) && isNumericLiteralAssignment(access))
      );
  }
}

/**
 * Loopback listen binding (positive policy, B1): a proven SERVER target may
 * listen only as `listen(<port>, '127.0.0.1'[, <callback>])` — argument 0 a
 * static decimal port, argument 1 the loopback host literal, both through THE
 * static-key resolver; an optional argument 2 that normalizes to a local
 * function through the listener normalizer; no spread and no further argument.
 * Every other listen shape is denied. No host or port is named as dangerous.
 */
function isLoopbackListen(ctx: Context, call: ts.CallExpression): boolean {
  const [port, host, callback] = call.arguments;
  if (call.arguments.length > 3 || port === undefined || host === undefined) return false;
  if (call.arguments.some((argument) => ts.isSpreadElement(argument))) return false;
  const portKey = resolveStaticKey(ctx, port);
  if (portKey.kind !== 'RESOLVED' || !/^\d+$/.test(portKey.value) || Number(portKey.value) > PORT_MAX) return false;
  if (!isResolvedTo(resolveStaticKey(ctx, host), LOOPBACK_HOST)) return false;
  return callback === undefined || normalizeListener(ctx, callback) !== null;
}

/**
 * Proven string (positive policy): an expression that can only evaluate to a
 * primitive string — a string or template literal (any spans), `+` with a
 * proven-string side, a conditional of proven strings, a unique const
 * initialized by one, a call of a local non-async eligible callee whose every
 * own return is one, or a binding seeded from a sibling host file's proven
 * exports. No ambient global call is proven: a global binding can be replaced
 * through routes this analysis does not track, so nothing else is proven and
 * no callable value (a Proxy, a function) can reach a Node callback position.
 */
function isProvenString(ctx: Context, expression: ts.Expression, visiting: Set<ts.Symbol>): boolean {
  const node = unwrap(expression);
  if (ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) return true;
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return isProvenString(ctx, node.left, visiting) || isProvenString(ctx, node.right, visiting);
  }
  if (ts.isConditionalExpression(node)) {
    return isProvenString(ctx, node.whenTrue, visiting) && isProvenString(ctx, node.whenFalse, visiting);
  }
  if (ts.isIdentifier(node)) {
    const symbol = valueSymbolOf(ctx.checker, node);
    if (symbol === undefined || visiting.has(symbol)) return false;
    if (ctx.externalStrings.has(symbol)) return true;
    const declaration = uniqueConstDeclaration(ctx, symbol);
    if (declaration?.initializer === undefined) return false;
    visiting.add(symbol);
    const proven = isProvenString(ctx, declaration.initializer, visiting);
    visiting.delete(symbol);
    return proven;
  }
  if (ts.isCallExpression(node) && node.questionDotToken === undefined && !node.arguments.some((argument) => ts.isSpreadElement(argument))) {
    const callee = unwrap(node.expression);
    if (!ts.isIdentifier(callee)) return false;
    const symbol = valueSymbolOf(ctx.checker, callee);
    if (symbol === undefined) return false;
    return isStringFunction(ctx, symbol, visiting);
  }
  return false;
}

/** A local non-async, non-generator eligible callee whose every own return is a proven string, or a seeded string function. */
function isStringFunction(ctx: Context, symbol: ts.Symbol, visiting: Set<ts.Symbol>): boolean {
  if (ctx.externalStringFunctions.has(symbol)) return true;
  if (visiting.has(symbol)) return false;
  const fn = eligibleCallee(ctx, symbol);
  if (fn === null || fn.asteriskToken !== undefined) return false;
  if ((ts.getCombinedModifierFlags(fn) & ts.ModifierFlags.Async) !== 0) return false;
  const returns = ownReturnExpressions(fn);
  if (returns.length === 0) return false;
  visiting.add(symbol);
  const proven = returns.every((returned) => returned !== null && isProvenString(ctx, returned, visiting));
  visiting.delete(symbol);
  return proven;
}

/** A binding whose value is a proven string: seeded, or a unique const with a proven-string initializer. */
function isStringValue(ctx: Context, symbol: ts.Symbol): boolean {
  if (ctx.externalStrings.has(symbol)) return true;
  const declaration = uniqueConstDeclaration(ctx, symbol);
  return declaration?.initializer !== undefined && isProvenString(ctx, declaration.initializer, new Set([symbol]));
}

/** `close()` or `close(<local function>)`: Node calls the callback with the server as `this`, which only a local function literal (whose `this` is already denied) may receive. */
function hasOnlyLocalCallback(ctx: Context, call: ts.CallExpression): boolean {
  const [callback] = call.arguments;
  if (callback === undefined) return call.arguments.length === 0;
  return call.arguments.length === 1 && normalizeListener(ctx, callback) !== null;
}

/** `end()` or `end(<proven string>)`: any callable chunk or explicit callback would run with the response as `this`. */
function hasOnlyProvenStringChunk(ctx: Context, call: ts.CallExpression): boolean {
  const [chunk] = call.arguments;
  if (chunk === undefined) return call.arguments.length === 0;
  return call.arguments.length === 1 && !ts.isSpreadElement(chunk) && isProvenString(ctx, chunk, new Set());
}

/**
 * The further positive checks on an allow-listed direct call of a proven
 * target: `listen` must be loopback-bound, `close` may carry only a local
 * function callback, `end` may carry only a proven string. Each of these calls
 * hands its receiver to a callback as an implicit `this`, so nothing but a
 * local function literal or a proven primitive may reach them.
 */
function checkAllowedCallShape(ctx: Context, access: MemberAccess, classes: ReadonlySet<AuthorityClass>): void {
  const call = directCallOf(access);
  if (call === null) return;
  const key = memberKey(ctx, access);
  if (classes.has('SERVER')) {
    if (isResolvedTo(key, SERVER_LISTEN) && !isLoopbackListen(ctx, call)) deny(ctx, 'SERVER_LISTEN_BINDING', call);
    if (isResolvedTo(key, SERVER_CLOSE) && !hasOnlyLocalCallback(ctx, call)) deny(ctx, 'SERVER_CLOSE_CALLBACK', call);
  }
  if (classes.has('RESPONSE') && isResolvedTo(key, RESPONSE_END) && !hasOnlyProvenStringChunk(ctx, call)) {
    deny(ctx, 'RESPONSE_END_ARGUMENT', call);
  }
}

/** The binding symbol of the function whose own body contains `node`, if that function is a local binding. */
function enclosingFunctionSymbol(ctx: Context, node: ts.Node): ts.Symbol | undefined {
  let current: ts.Node = node;
  while (!ts.isSourceFile(current)) {
    if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) {
      const holder = climb(current).parent;
      if (ts.isVariableDeclaration(holder) && ts.isIdentifier(holder.name)) return valueSymbolOf(ctx.checker, holder.name);
      return undefined;
    }
    if (ts.isFunctionDeclaration(current)) {
      return current.name === undefined ? undefined : valueSymbolOf(ctx.checker, current.name);
    }
    if (ts.isFunctionLike(current) || ts.isClassLike(current)) return undefined;
    current = current.parent;
  }
  return undefined;
}

/** Apply the positive policy of every class carried by `expression` at its use site. */
function checkTargetUse(ctx: Context, expression: ts.Expression, classes: ReadonlySet<AuthorityClass>): void {
  const { node, parent } = climb(expression);
  const violate = (violation: UseViolation): void => {
    for (const authority of classes) deny(ctx, `${authority}_${violation}`, node);
  };
  if (isWriteTarget(node)) {
    const direct = ts.isBinaryExpression(parent) || isUpdateExpression(parent) || ts.isDeleteExpression(parent);
    violate(direct ? 'WRITE' : 'DESTRUCTURING');
    return;
  }
  if (ts.isExpressionStatement(parent) || ts.isVoidExpression(parent) || ts.isTypeOfExpression(parent)) return;
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
    if (!ts.isIdentifier(parent.name)) violate('DESTRUCTURING');
    else if (isExported(parent)) violate('EXPORT');
    else if (!isConfinedAliasDeclaration(ctx, parent)) violate('MUTABLE_BINDING');
    return;
  }
  if (ts.isReturnStatement(parent) || (ts.isArrowFunction(parent) && parent.body === node)) {
    const fnSymbol = enclosingFunctionSymbol(ctx, parent);
    const confined = fnSymbol !== undefined && ctx.confinedFactories.has(fnSymbol);
    if (!confined || [...classes].some((authority) => authority !== 'SERVER')) violate('UNCONFINED_RETURN');
    return;
  }
  if (ts.isCallExpression(parent) && parent.expression !== node) {
    const index = parent.arguments.findIndex((argument) => argument === node);
    if (index === -1 || resolvePropagationParameter(ctx, parent, index) === null) violate('ESCAPE');
    return;
  }
  if (isMemberAccess(parent) && parent.expression === node) {
    if (![...classes].every((authority) => memberAllowed(ctx, authority, parent))) violate('MEMBER');
    else checkAllowedCallShape(ctx, parent, classes);
    return;
  }
  if (ts.isExportSpecifier(parent) || ts.isExportAssignment(parent)) {
    violate('EXPORT');
    return;
  }
  if (
    ts.isBinaryExpression(parent) &&
    parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    parent.right === node &&
    (ts.isArrayLiteralExpression(unwrap(parent.left)) || ts.isObjectLiteralExpression(unwrap(parent.left)))
  ) {
    violate('DESTRUCTURING');
    return;
  }
  violate('ESCAPE');
}

function checkCreateServerCall(ctx: Context, call: ts.CallExpression): void {
  if (call.arguments.length !== 1) {
    deny(ctx, 'CREATE_SERVER_ARITY', call);
  } else {
    const listener = listenerOf(ctx, call);
    if (listener === null) deny(ctx, 'LISTENER_NOT_FUNCTION', call);
    else if (hasThisParameter(listener)) deny(ctx, 'LISTENER_THIS_PARAMETER', listener);
    else {
      for (const parameter of listener.parameters.slice(0, 2)) {
        if (parameter.dotDotDotToken !== undefined || !ts.isIdentifier(parameter.name)) {
          deny(ctx, 'LISTENER_PARAMETER_PATTERN', parameter);
        }
      }
    }
  }
  checkTargetUse(ctx, call, new Set(['SERVER']));
}

function checkHttpNamespaceUse(ctx: Context, id: ts.Identifier): void {
  const { node, parent } = climb(id);
  if (!isMemberAccess(parent) || parent.expression !== node) {
    deny(ctx, 'HTTP_NAMESPACE_ESCAPE', node);
    return;
  }
  const key = memberKey(ctx, parent);
  if (key.kind === 'INDETERMINATE') {
    deny(ctx, 'HTTP_NAMESPACE_RUNTIME_KEY', parent);
    return;
  }
  if (!isResolvedTo(key, CREATE_SERVER)) {
    deny(ctx, 'HTTP_CLIENT_CAPABILITY', parent);
    return;
  }
  const use = climb(parent);
  if (ts.isNewExpression(use.parent) && use.parent.expression === use.node) {
    deny(ctx, 'CREATE_SERVER_NEW', use.parent);
    return;
  }
  const directlyCalled =
    ts.isCallExpression(use.parent) &&
    use.parent.expression === use.node &&
    use.parent.questionDotToken === undefined &&
    parent.questionDotToken === undefined;
  if (!directlyCalled) deny(ctx, 'CREATE_SERVER_NOT_CALLED', parent);
}

function checkCreateServerBindingUse(ctx: Context, id: ts.Identifier): void {
  const { node, parent } = climb(id);
  if (ts.isNewExpression(parent) && parent.expression === node) deny(ctx, 'CREATE_SERVER_NEW', parent);
  else if (!ts.isCallExpression(parent) || parent.expression !== node || parent.questionDotToken !== undefined) {
    deny(ctx, 'CREATE_SERVER_ESCAPE', node);
  }
}

/**
 * Shared verdict for a key read off a global receiver; `onSelfHop` handles a
 * resolved global-root key and `onProcess` the `process` key (the same object
 * as the free global). Returns whether the key is a permitted static member.
 */
function checkGlobalKey(ctx: Context, key: StaticKey, at: ts.Node, onSelfHop: () => void, onProcess: () => void): boolean {
  if (key.kind === 'INDETERMINATE') deny(ctx, 'GLOBAL_RECEIVER_RUNTIME_KEY', at);
  else if (isResolvedTo(key, NETWORK_GLOBAL_NAMES)) deny(ctx, 'GLOBAL_RECEIVER_NETWORK_MEMBER', at);
  else if (isResolvedTo(key, GLOBAL_RECEIVER_NAMES)) onSelfHop();
  else if (isResolvedTo(key, PROCESS_GLOBAL)) onProcess();
  else return true;
  return false;
}

function checkGlobalBindingPattern(ctx: Context, pattern: ts.BindingPattern): void {
  if (ts.isArrayBindingPattern(pattern)) {
    deny(ctx, 'GLOBAL_RECEIVER_DESTRUCTURING', pattern);
    return;
  }
  for (const element of pattern.elements) {
    if (element.dotDotDotToken !== undefined) {
      deny(ctx, 'GLOBAL_RECEIVER_DESTRUCTURING', element);
      continue;
    }
    let key: StaticKey = INDETERMINATE;
    if (element.propertyName !== undefined) key = resolvePropertyName(ctx, element.propertyName);
    else if (ts.isIdentifier(element.name)) key = foldKey(element.name.text);
    checkGlobalKey(
      ctx,
      key,
      element,
      () => {
        if (isBindingPattern(element.name)) checkGlobalBindingPattern(ctx, element.name);
        else deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', element);
      },
      () => { deny(ctx, 'PROCESS_GLOBAL_USE', element); },
    );
  }
}

function checkGlobalAssignmentPattern(ctx: Context, target: ts.Expression): void {
  const literal = unwrap(target);
  if (!ts.isObjectLiteralExpression(literal)) {
    deny(ctx, 'GLOBAL_RECEIVER_DESTRUCTURING', literal);
    return;
  }
  for (const property of literal.properties) {
    if (ts.isShorthandPropertyAssignment(property)) {
      checkGlobalKey(
        ctx,
        foldKey(property.name.text),
        property,
        () => { deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', property); },
        () => { deny(ctx, 'PROCESS_GLOBAL_USE', property); },
      );
    } else if (ts.isPropertyAssignment(property)) {
      checkGlobalKey(
        ctx,
        resolvePropertyName(ctx, property.name),
        property,
        () => {
          const nested = unwrap(property.initializer);
          if (ts.isObjectLiteralExpression(nested) || ts.isArrayLiteralExpression(nested)) {
            checkGlobalAssignmentPattern(ctx, nested);
          } else deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', property);
        },
        () => { deny(ctx, 'PROCESS_GLOBAL_USE', property); },
      );
    } else deny(ctx, 'GLOBAL_RECEIVER_DESTRUCTURING', property);
  }
}

/** A free global receiver root (or a static self-hop from one) may only be read through static, non-network keys; no member is ever written or invoked. */
function checkGlobalReceiverUse(ctx: Context, expression: ts.Expression): void {
  const { node, parent } = climb(expression);
  if (ts.isExpressionStatement(parent) || ts.isVoidExpression(parent) || ts.isTypeOfExpression(parent)) return;
  if (isMemberAccess(parent) && parent.expression === node) {
    const permitted = checkGlobalKey(
      ctx,
      memberKey(ctx, parent),
      parent,
      () => { checkGlobalReceiverUse(ctx, parent); },
      () => { checkProcessUse(ctx, parent); },
    );
    // A permitted static member is read-only: writing it mutates the global
    // (e.g. replacing `String`, which `isProvenString` trusts as intrinsic).
    if (permitted && isWriteTarget(parent)) {
      deny(ctx, 'GLOBAL_RECEIVER_WRITE', parent);
      return;
    }
    // A permitted static member is never invoked through the receiver: an
    // inherited mutator or a code generator called with the global as its
    // receiver rebinds globals exactly as a write does, so every call, optional
    // call, construct and tagged-template form is denied as one family. A free
    // global call such as `String(1)` goes through no receiver and is unaffected.
    if (permitted && memberCallOf(parent) !== null) deny(ctx, 'GLOBAL_RECEIVER_CALL', parent);
    return;
  }
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
    if (isBindingPattern(parent.name)) checkGlobalBindingPattern(ctx, parent.name);
    else deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', node);
    return;
  }
  if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && parent.right === node) {
    const left = unwrap(parent.left);
    if (ts.isObjectLiteralExpression(left) || ts.isArrayLiteralExpression(left)) checkGlobalAssignmentPattern(ctx, left);
    else deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', node);
    return;
  }
  deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', node);
}

/**
 * Positive policy for the `process` global, whether reached as the free
 * identifier or as `<global receiver>.process`: the only permitted runtime use
 * is an element read `process.argv[<static index>]` (the entry guard). Every
 * other operation — any other member, forwarding the object, writing `argv`,
 * or reading it whole — is denied; no per-method table is kept.
 */
function checkProcessUse(ctx: Context, expression: ts.Expression): void {
  const { node, parent } = climb(expression);
  if (ts.isExpressionStatement(parent) || ts.isVoidExpression(parent) || ts.isTypeOfExpression(parent)) return;
  if (isMemberAccess(parent) && parent.expression === node && isResolvedTo(memberKey(ctx, parent), PROCESS_ARGV) && !isWriteTarget(parent)) {
    const argv = climb(parent);
    if (ts.isElementAccessExpression(argv.parent) && argv.parent.expression === argv.node && !isWriteTarget(argv.parent)) {
      const index = memberKey(ctx, argv.parent);
      if (index.kind === 'RESOLVED' && /^\d+$/.test(index.value)) return;
    }
  }
  deny(ctx, 'PROCESS_GLOBAL_USE', node);
}

function checkFreeGlobal(ctx: Context, id: ts.Identifier): void {
  if (id.text === 'arguments') deny(ctx, 'ARGUMENTS_USE', id);
  else if (NETWORK_GLOBAL_NAMES.has(id.text)) deny(ctx, 'FREE_GLOBAL_NETWORK', id);
  else if (GLOBAL_RECEIVER_NAMES.has(id.text)) checkGlobalReceiverUse(ctx, id);
  else if (id.text === PROCESS_GLOBAL) checkProcessUse(ctx, id);
}

/**
 * Server-instantiation site bound (static, evidence-bounded, B2): the source
 * may contain at most one server-instantiation site outside the own body of a
 * confined factory — a proven createServer call, or a call of a confined
 * factory whose own body instantiates a server (directly, or through another
 * instantiating confined factory). A confined factory's internal createServer
 * is realized by its call sites and is not a site of its own; an
 * alias-returning factory adds no site. Runs over the already-collected calls
 * after the fixpoint; nothing about runtime call multiplicity is claimed.
 */
function checkInstantiationSites(ctx: Context): void {
  const memo = new Map<ts.Symbol, boolean>();
  const factoryInstantiates = (factory: ts.Symbol): boolean => {
    const known = memo.get(factory);
    if (known !== undefined) return known;
    memo.set(factory, false);
    const result = ctx.calls.some((call) => enclosingFunctionSymbol(ctx, call) === factory && instantiates(call));
    memo.set(factory, result);
    return result;
  };
  const instantiates = (call: ts.CallExpression): boolean => {
    const callee = unwrap(call.expression);
    if (isProvenCreateServerCall(ctx, call)) return true;
    if (!isConfinedFactoryCall(ctx, call)) return false;
    const factory = valueSymbolOf(ctx.checker, callee);
    if (factory === undefined) return false;
    // A factory seeded from a sibling host file instantiates a server only if the exporting file proved so.
    return ctx.externalInstantiatingFactories.has(factory) || factoryInstantiates(factory);
  };
  const sites = ctx.calls.filter((call) => {
    const owner = enclosingFunctionSymbol(ctx, call);
    return (owner === undefined || !ctx.confinedFactories.has(owner)) && instantiates(call);
  });
  ctx.instantiationSites = sites.length;
  for (const factory of ctx.confinedFactories) {
    if (ctx.externalInstantiatingFactories.has(factory) || factoryInstantiates(factory)) ctx.instantiatingFactories.add(factory);
  }
  // The tree entry counts sites across files: only the first site of the whole host tree is free.
  for (const site of sites.slice(Math.max(0, 1 - ctx.priorInstantiationSites))) deny(ctx, 'CREATE_SERVER_MULTIPLE', site);
}

function classify(ctx: Context): void {
  for (const node of ctx.thisExpressions) deny(ctx, 'THIS_EXPRESSION', node);
  for (const id of ctx.unboundValueReads) checkFreeGlobal(ctx, id);
  for (const [symbol, reads] of ctx.valueReads) {
    if (!isRuntimeShadowed(ctx.checker, symbol)) {
      for (const id of reads) checkFreeGlobal(ctx, id);
    }
    if (ctx.httpNamespaces.has(symbol)) for (const id of reads) checkHttpNamespaceUse(ctx, id);
    if (ctx.createServerBindings.has(symbol)) for (const id of reads) checkCreateServerBindingUse(ctx, id);
    const classes = new Set(factsOf(ctx, symbol).map((fact) => fact.authority));
    if (classes.size > 0) for (const id of reads) checkTargetUse(ctx, id, classes);
  }
  for (const call of ctx.calls) {
    if (isProvenCreateServerCall(ctx, call)) {
      checkCreateServerCall(ctx, call);
      continue;
    }
    // Confined factory results and receiver-call results carry authority into their use site.
    const classes = classesOf(ctx, call);
    if (classes.size > 0) checkTargetUse(ctx, call, classes);
  }
  // A factory seeded from a sibling host file is confined here exactly like a local one: direct call, typeof, or re-export only.
  for (const factory of ctx.externalFactories) {
    for (const id of ctx.valueReads.get(factory) ?? []) {
      if (!isConfinedReference(id)) deny(ctx, 'SERVER_FACTORY_ESCAPE', id);
    }
  }
  checkInstantiationSites(ctx);
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

function createContext(source: string, options: NetworkPolicyOptions): Context {
  const { sourceFile, checker } = createProgram(source);
  return {
    sourceFile,
    checker,
    findings: [],
    valueReads: new Map(),
    unboundValueReads: [],
    declaredSymbols: new Set(),
    writeCounts: new Map(),
    httpNamespaces: new Set(),
    createServerBindings: new Set(),
    calls: [],
    variableDeclarations: [],
    functionBindings: new Set(),
    thisExpressions: [],
    facts: new Map(),
    confinedFactories: new Set(),
    keyMemo: new Map(),
    keyWork: 0,
    expressionFactsEvaluations: 0,
    fixpointCeiling: options.fixpointCeiling ?? DEFAULT_FIXPOINT_CEILING,
    hostImports: options.hostImports ?? new Map(),
    priorInstantiationSites: options.priorInstantiationSites ?? 0,
    externalFactories: new Set(),
    externalInstantiatingFactories: new Set(),
    instantiatingFactories: new Set(),
    externalStrings: new Set(),
    externalStringFunctions: new Set(),
    instantiationSites: 0,
  };
}

function finish(ctx: Context, fixpoint: FixpointReport): NetworkPolicyResult {
  const reasons = [...new Set(ctx.findings.map((finding) => finding.reason))].sort();
  return { verdict: reasons.length === 0 ? 'ALLOW' : 'DENY', reasons, findings: [...ctx.findings], fixpoint };
}

/** Primitive access for direct mechanism tests; the verdict path is `analyzeNetworkPolicy`. */
export interface NetworkPolicyInspection {
  readonly sourceFile: ts.SourceFile;
  readonly checker: ts.TypeChecker;
  readonly result: NetworkPolicyResult;
  readonly valueSymbolOf: (node: ts.Node) => ts.Symbol | undefined;
  readonly resolveStaticKey: (expression: ts.Expression) => StaticKey;
  readonly writeCountOf: (symbol: ts.Symbol) => number;
  readonly factsOf: (symbol: ts.Symbol) => readonly string[];
  readonly isConfinedFactory: (symbol: ts.Symbol) => boolean;
  readonly declaredSymbolCount: number;
  readonly fixpointBound: number;
  /** Total `expressionFacts` evaluations performed by the analysis (deterministic complexity witness). */
  readonly expressionFactsEvaluations: number;
  /** Server-instantiation sites found in this file. */
  readonly instantiationSites: number;
  /** What this file proves about its own exports, as a sibling host file would see them. */
  readonly hostExports: HostModuleExports;
}

function analyze(source: string, options: NetworkPolicyOptions): { ctx: Context; result: NetworkPolicyResult } {
  const ctx = createContext(source, options);
  collect(ctx, ctx.sourceFile);
  buildWriteInventory(ctx);
  collectHttpImports(ctx);
  collectHostImports(ctx);
  const fixpoint = runFixpoint(ctx);
  if (fixpoint.state === 'EXHAUSTED') {
    deny(ctx, 'FIXPOINT_EXHAUSTED', ctx.sourceFile);
    return { ctx, result: finish(ctx, fixpoint) };
  }
  classify(ctx);
  return { ctx, result: finish(ctx, fixpoint) };
}

/** Analyze one TypeScript source file against the frozen D3 network policy. */
export function analyzeNetworkPolicy(source: string, options: NetworkPolicyOptions = {}): NetworkPolicyResult {
  return analyze(source, options).result;
}

export function inspectNetworkPolicy(source: string, options: NetworkPolicyOptions = {}): NetworkPolicyInspection {
  const { ctx, result } = analyze(source, options);
  return {
    sourceFile: ctx.sourceFile,
    checker: ctx.checker,
    result,
    valueSymbolOf: (node) => valueSymbolOf(ctx.checker, node),
    resolveStaticKey: (expression) => resolveStaticKey(ctx, expression),
    writeCountOf: (symbol) => writeCount(ctx, symbol),
    factsOf: (symbol) => [...(ctx.facts.get(symbol) ?? [])].sort(),
    isConfinedFactory: (symbol) => ctx.confinedFactories.has(symbol),
    declaredSymbolCount: ctx.declaredSymbols.size,
    fixpointBound: fixpointBound(ctx),
    expressionFactsEvaluations: ctx.expressionFactsEvaluations,
    instantiationSites: ctx.instantiationSites,
    hostExports: hostExportsOf(ctx),
  };
}

// ---------------------------------------------------------------------------
// Host module graph (tree entry)
// ---------------------------------------------------------------------------

const hasExportModifier = (node: ts.Node): boolean =>
  ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);

const hasDefaultModifier = (node: ts.Node): boolean =>
  ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword);

/** What a file proves about its own exports: confined factories, proven strings and string functions, including re-exports of proven sibling exports. */
function hostExportsOf(ctx: Context): HostModuleExports {
  const factories = new Set<string>();
  const instantiatingFactories = new Set<string>();
  const strings = new Set<string>();
  const stringFunctions = new Set<string>();
  const classifyBinding = (symbol: ts.Symbol | undefined, exportName: string): void => {
    if (symbol === undefined) return;
    if (ctx.confinedFactories.has(symbol)) factories.add(exportName);
    if (ctx.instantiatingFactories.has(symbol)) instantiatingFactories.add(exportName);
    if (isStringFunction(ctx, symbol, new Set())) stringFunctions.add(exportName);
    else if (isStringValue(ctx, symbol)) strings.add(exportName);
  };
  const copyFrom = (source: HostModuleExports, imported: string, exportName: string): void => {
    if (source.factories.has(imported)) factories.add(exportName);
    if (source.instantiatingFactories.has(imported)) instantiatingFactories.add(exportName);
    if (source.strings.has(imported)) strings.add(exportName);
    if (source.stringFunctions.has(imported)) stringFunctions.add(exportName);
  };
  for (const statement of ctx.sourceFile.statements) {
    if (isAmbient(statement)) continue;
    if (ts.isFunctionDeclaration(statement) && statement.name !== undefined && hasExportModifier(statement)) {
      classifyBinding(valueSymbolOf(ctx.checker, statement.name), hasDefaultModifier(statement) ? 'default' : statement.name.text);
    }
    if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) classifyBinding(valueSymbolOf(ctx.checker, declaration.name), declaration.name.text);
      }
    }
    if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
      const exported = unwrap(statement.expression);
      if (ts.isIdentifier(exported)) classifyBinding(valueSymbolOf(ctx.checker, exported), 'default');
    }
    if (ts.isExportDeclaration(statement) && !statement.isTypeOnly) {
      const clause = statement.exportClause;
      const specifier = statement.moduleSpecifier;
      if (specifier !== undefined) {
        const source = ts.isStringLiteralLike(specifier) ? ctx.hostImports.get(specifier.text) : undefined;
        if (source === undefined) continue;
        if (clause === undefined) {
          for (const name of source.factories) factories.add(name);
          for (const name of source.instantiatingFactories) instantiatingFactories.add(name);
          for (const name of source.strings) strings.add(name);
          for (const name of source.stringFunctions) stringFunctions.add(name);
        } else if (ts.isNamedExports(clause)) {
          for (const element of clause.elements) {
            if (!element.isTypeOnly) copyFrom(source, (element.propertyName ?? element.name).text, element.name.text);
          }
        }
      } else if (clause !== undefined && ts.isNamedExports(clause)) {
        for (const element of clause.elements) {
          if (!element.isTypeOnly) classifyBinding(valueSymbolOf(ctx.checker, element), element.name.text);
        }
      }
    }
  }
  return { factories, instantiatingFactories, strings, stringFunctions };
}

/** One host source file for the tree entry; `file` is its native path relative to the host root (win32: either separator; elsewhere a backslash is a literal filename character). */
export interface HostSource {
  readonly file: string;
  readonly text: string;
}

const EMPTY_EXPORTS: HostModuleExports = {
  factories: new Set(),
  instantiatingFactories: new Set(),
  strings: new Set(),
  stringFunctions: new Set(),
};

const sameNames = (left: ReadonlySet<string>, right: ReadonlySet<string>): boolean =>
  left.size === right.size && [...left].every((name) => right.has(name));

const sameExports = (left: HostModuleExports | undefined, right: HostModuleExports): boolean =>
  left !== undefined &&
  sameNames(left.factories, right.factories) &&
  sameNames(left.instantiatingFactories, right.instantiatingFactories) &&
  sameNames(left.strings, right.strings) &&
  sameNames(left.stringFunctions, right.stringFunctions);

const isRelativeSpecifier = (specifier: string): boolean => specifier.startsWith('./') || specifier.startsWith('../');

/** The directory separator of the platform the `HostSource.file` names come from. */
const nativeSeparator = (): '/' | '\\' => (process.platform === 'win32' ? '\\' : '/');

/** Every relative string-literal module specifier a file uses, in import, export, `require` and dynamic-import positions. */
function relativeSpecifiersOf(sourceFile: ts.SourceFile): readonly string[] {
  const specifiers = new Set<string>();
  const consider = (expression: ts.Expression | undefined): void => {
    if (expression === undefined) return;
    const literal = unwrap(expression);
    if (ts.isStringLiteralLike(literal) && isRelativeSpecifier(literal.text)) specifiers.add(literal.text);
  };
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) consider(node.moduleSpecifier);
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) consider(node.moduleReference.expression);
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) consider(node.arguments[0]);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return [...specifiers];
}

/** Synthetic root the tree's '/'-separated names hang under; a resolution that leaves it is outside the boundary. */
const TREE_ROOT_URL = new URL('file:///host/');

/** An encoded separator never folds into one (Node rejects `%2f` everywhere and `%5c` on win32): fail closed on both. */
const ENCODED_SEPARATOR = /%2f|%5c/i;

/**
 * Resolve a relative specifier against its importing file with URL semantics,
 * as Node's ESM loader does — `.`/`..` and their `%2e` forms fold, a query or
 * fragment is dropped, an encoded segment decodes — to a file of the tree
 * (`.js` → `.ts` and friends), or undefined. A resolution that leaves the root,
 * carries an encoded separator, or has a malformed escape stays outside the
 * boundary. Each importer segment is encoded first so a literal backslash in a
 * POSIX filename stays one segment instead of reading as a separator.
 */
function resolveHostSpecifier(fromFile: string, specifier: string, files: ReadonlySet<string>): string | undefined {
  if (ENCODED_SEPARATOR.test(specifier)) return undefined;
  let target: string;
  try {
    const importer = new URL(fromFile.split('/').map(encodeURIComponent).join('/'), TREE_ROOT_URL);
    const resolved = new URL(specifier, importer);
    if (!resolved.pathname.startsWith(TREE_ROOT_URL.pathname)) return undefined;
    target = resolved.pathname.slice(TREE_ROOT_URL.pathname.length).split('/').map(decodeURIComponent).join('/');
  } catch {
    return undefined;
  }
  const candidates = [
    target,
    target.replace(/\.js$/, '.ts'),
    target.replace(/\.mjs$/, '.mts'),
    target.replace(/\.cjs$/, '.cts'),
    `${target}.ts`,
    `${target}/index.ts`,
  ];
  return candidates.find((candidate) => files.has(candidate));
}

/**
 * Analyze a whole host tree: each file under the frozen single-file policy,
 * with the proven exports of the sibling files it imports seeded in (server
 * factories, proven strings, string functions), and the server-instantiation
 * site bound applied across the tree. Exports are computed to a fixpoint over
 * the import graph (bounded by the number of files) before the final pass.
 */
export function analyzeNetworkPolicyTree(
  sources: readonly HostSource[],
  options: NetworkPolicyOptions = {},
): ReadonlyMap<string, NetworkPolicyResult> {
  // Tree paths are '/'-separated: a win32 name folds its backslashes; a POSIX name keeps them, they are part of the filename.
  const separator = options.separator ?? nativeSeparator();
  const treePath = (file: string): string => (separator === '\\' ? file.replace(/\\/g, '/') : file);
  const files = sources.map((source) => ({ file: treePath(source.file), text: source.text }));
  const names = new Set(files.map((entry) => entry.file));
  const specifiers = new Map(
    files.map((entry) => [
      entry.file,
      relativeSpecifiersOf(ts.createSourceFile(entry.file, entry.text, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TS)),
    ]),
  );
  let exports = new Map<string, HostModuleExports>();
  const importsFor = (file: string): ReadonlyMap<string, HostModuleExports> => {
    const imports = new Map<string, HostModuleExports>();
    for (const specifier of specifiers.get(file) ?? []) {
      const target = resolveHostSpecifier(file, specifier, names);
      if (target !== undefined) imports.set(specifier, exports.get(target) ?? EMPTY_EXPORTS);
    }
    return imports;
  };
  for (let round = 0; round <= files.length; round += 1) {
    const next = new Map(
      files.map((entry) => [entry.file, hostExportsOf(analyze(entry.text, { ...options, hostImports: importsFor(entry.file) }).ctx)]),
    );
    const changed = files.some((entry) => !sameExports(exports.get(entry.file), next.get(entry.file) ?? EMPTY_EXPORTS));
    exports = next;
    if (!changed) break;
  }
  const results = new Map<string, NetworkPolicyResult>();
  let priorInstantiationSites = 0;
  for (const entry of files) {
    const { ctx, result } = analyze(entry.text, { ...options, hostImports: importsFor(entry.file), priorInstantiationSites });
    priorInstantiationSites += ctx.instantiationSites;
    results.set(entry.file, result);
  }
  return results;
}
