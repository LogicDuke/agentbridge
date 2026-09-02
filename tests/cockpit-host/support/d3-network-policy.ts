/**
 * Cockpit D3 — network policy for the read-only dashboard host (Stage A).
 *
 * A static, development-time source policy over ONE TypeScript file at a time.
 * It is not a runtime sandbox. The host may create exactly one inbound HTTP
 * server and must not obtain outbound network capability, socket capability,
 * hidden mutable server capability, or privileged request/response authority
 * beyond the explicitly allow-listed operations.
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
 *
 * One concept, one implementation: `valueSymbolOf` is the only symbol
 * resolution path; `resolveStaticKey` is the only key resolver;
 * `resolvePropagationParameter` is the only parameter-propagation predicate;
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

export interface NetworkPolicyOptions {
  /** Absolute safety ceiling on fixpoint iterations (test hook; default `DEFAULT_FIXPOINT_CEILING`). */
  readonly fixpointCeiling?: number;
}

export type StaticKey =
  | { readonly kind: 'RESOLVED'; readonly value: string }
  | { readonly kind: 'NOT_CAPABILITY' }
  | { readonly kind: 'INDETERMINATE' };

// ---------------------------------------------------------------------------
// Frozen policy tables
// ---------------------------------------------------------------------------

export const HTTP_MODULE_SPECIFIERS: ReadonlySet<string> = new Set(['node:http', 'http']);
export const NETWORK_GLOBAL_NAMES: ReadonlySet<string> = new Set(['fetch', 'WebSocket']);
export const GLOBAL_RECEIVER_NAMES: ReadonlySet<string> = new Set(['globalThis', 'window', 'self', 'global']);
const CREATE_SERVER = 'createServer';
export const SERVER_METHODS: ReadonlySet<string> = new Set(['listen', 'close']);
export const REQUEST_READS: ReadonlySet<string> = new Set(['method', 'url']);
export const RESPONSE_METHODS: ReadonlySet<string> = new Set(['setHeader', 'end']);
const RESPONSE_STATUS = 'statusCode';

/** Every key the policy ever compares a static string against. */
export const POLICY_KEY_NAMES: readonly string[] = [
  ...HTTP_MODULE_SPECIFIERS,
  ...NETWORK_GLOBAL_NAMES,
  ...GLOBAL_RECEIVER_NAMES,
  CREATE_SERVER,
  ...SERVER_METHODS,
  ...REQUEST_READS,
  ...RESPONSE_METHODS,
  RESPONSE_STATUS,
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
  readonly fixpointCeiling: number;
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
function isRuntimeDeclaration(declaration: ts.Declaration): boolean {
  if (isAmbient(declaration)) return false;
  if (ts.isVariableDeclaration(declaration) || ts.isBindingElement(declaration) || ts.isParameter(declaration)) {
    return true;
  }
  if (ts.isFunctionDeclaration(declaration)) return declaration.body !== undefined;
  if (ts.isClassDeclaration(declaration) || ts.isClassExpression(declaration)) return true;
  if (ts.isImportClause(declaration)) return !isTypeOnlyImportClause(declaration);
  if (ts.isNamespaceImport(declaration)) return !isTypeOnlyImportClause(declaration.parent);
  if (ts.isImportSpecifier(declaration)) {
    return !declaration.isTypeOnly && !isTypeOnlyImportClause(declaration.parent.parent);
  }
  if (ts.isEnumDeclaration(declaration)) {
    return (ts.getCombinedModifierFlags(declaration) & ts.ModifierFlags.Const) === 0;
  }
  if (ts.isModuleDeclaration(declaration)) return isInstantiatedNamespace(declaration);
  if (ts.isImportEqualsDeclaration(declaration)) return isRuntimeImportEquals(declaration);
  return false;
}

/**
 * THE runtime import-equals predicate. A non-type-only `import x = ...` is a
 * runtime alias when it references an external module (`require(...)`) or is
 * exported — the binder's own rule for what instantiates an enclosing namespace
 * (`export import get = Local.get` emits `fetch.get = Local.get`). A type-only or
 * private entity alias is erased.
 */
const isRuntimeImportEquals = (declaration: ts.ImportEqualsDeclaration): boolean =>
  !declaration.isTypeOnly && (ts.isExternalModuleReference(declaration.moduleReference) || isExported(declaration));

/**
 * A non-ambient `namespace` produces a runtime binding only when it is
 * instantiated: its body (or a nested namespace body) declares a value —
 * a variable, a bodied function, a class, or a runtime enum. A namespace that
 * holds only types is erased and shadows nothing at runtime.
 */
function isInstantiatedNamespace(declaration: ts.ModuleDeclaration): boolean {
  if (!ts.isIdentifier(declaration.name) || declaration.body === undefined) return false;
  if (ts.isModuleDeclaration(declaration.body)) return isInstantiatedNamespace(declaration.body);
  if (!ts.isModuleBlock(declaration.body)) return false;
  return declaration.body.statements.some((statement) => {
    if (isAmbient(statement)) return false;
    if (ts.isVariableStatement(statement) || ts.isClassDeclaration(statement)) return true;
    if (ts.isFunctionDeclaration(statement)) return statement.body !== undefined;
    if (ts.isEnumDeclaration(statement)) return (ts.getCombinedModifierFlags(statement) & ts.ModifierFlags.Const) === 0;
    if (ts.isModuleDeclaration(statement)) return isInstantiatedNamespace(statement);
    if (ts.isImportEqualsDeclaration(statement)) return isRuntimeImportEquals(statement);
    return false;
  });
}

const isRuntimeShadowed = (symbol: ts.Symbol): boolean => (symbol.declarations ?? []).some(isRuntimeDeclaration);

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

/** Authority classes carried by an expression (createServer result, factory result, or proven identifier). */
function classesOf(ctx: Context, expression: ts.Expression): ReadonlySet<AuthorityClass> {
  const node = unwrap(expression);
  if (isProvenCreateServerCall(ctx, node) || isConfinedFactoryCall(ctx, node)) return new Set(['SERVER']);
  if (ts.isIdentifier(node)) return new Set(factsOf(ctx, valueSymbolOf(ctx.checker, node)).map((fact) => fact.authority));
  return new Set();
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
      } else if (ts.isIdentifier(initializer)) {
        for (const fact of factsOf(ctx, valueSymbolOf(ctx.checker, initializer))) {
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

const isDirectCallee = (access: ts.Expression): boolean => {
  const { node, parent } = climb(access);
  return ts.isCallExpression(parent) && parent.expression === node && parent.questionDotToken === undefined;
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

/** Shared verdict for a key read off a global receiver; `onSelfHop` handles a resolved global-root key. */
function checkGlobalKey(ctx: Context, key: StaticKey, at: ts.Node, onSelfHop: () => void): void {
  if (key.kind === 'INDETERMINATE') deny(ctx, 'GLOBAL_RECEIVER_RUNTIME_KEY', at);
  else if (isResolvedTo(key, NETWORK_GLOBAL_NAMES)) deny(ctx, 'GLOBAL_RECEIVER_NETWORK_MEMBER', at);
  else if (isResolvedTo(key, GLOBAL_RECEIVER_NAMES)) onSelfHop();
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
    checkGlobalKey(ctx, key, element, () => {
      if (isBindingPattern(element.name)) checkGlobalBindingPattern(ctx, element.name);
      else deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', element);
    });
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
      checkGlobalKey(ctx, foldKey(property.name.text), property, () => {
        deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', property);
      });
    } else if (ts.isPropertyAssignment(property)) {
      checkGlobalKey(ctx, resolvePropertyName(ctx, property.name), property, () => {
        const nested = unwrap(property.initializer);
        if (ts.isObjectLiteralExpression(nested) || ts.isArrayLiteralExpression(nested)) {
          checkGlobalAssignmentPattern(ctx, nested);
        } else deny(ctx, 'GLOBAL_RECEIVER_ESCAPE', property);
      });
    } else deny(ctx, 'GLOBAL_RECEIVER_DESTRUCTURING', property);
  }
}

/** A free global receiver root (or a static self-hop from one) may only be read through static, non-network keys. */
function checkGlobalReceiverUse(ctx: Context, expression: ts.Expression): void {
  const { node, parent } = climb(expression);
  if (ts.isExpressionStatement(parent) || ts.isVoidExpression(parent) || ts.isTypeOfExpression(parent)) return;
  if (isMemberAccess(parent) && parent.expression === node) {
    checkGlobalKey(ctx, memberKey(ctx, parent), parent, () => {
      checkGlobalReceiverUse(ctx, parent);
    });
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

function checkFreeGlobal(ctx: Context, id: ts.Identifier): void {
  if (id.text === 'arguments') deny(ctx, 'ARGUMENTS_USE', id);
  else if (NETWORK_GLOBAL_NAMES.has(id.text)) deny(ctx, 'FREE_GLOBAL_NETWORK', id);
  else if (GLOBAL_RECEIVER_NAMES.has(id.text)) checkGlobalReceiverUse(ctx, id);
}

function classify(ctx: Context): void {
  for (const node of ctx.thisExpressions) deny(ctx, 'THIS_EXPRESSION', node);
  for (const id of ctx.unboundValueReads) checkFreeGlobal(ctx, id);
  for (const [symbol, reads] of ctx.valueReads) {
    if (!isRuntimeShadowed(symbol)) {
      for (const id of reads) checkFreeGlobal(ctx, id);
    }
    if (ctx.httpNamespaces.has(symbol)) for (const id of reads) checkHttpNamespaceUse(ctx, id);
    if (ctx.createServerBindings.has(symbol)) for (const id of reads) checkCreateServerBindingUse(ctx, id);
    const classes = new Set(factsOf(ctx, symbol).map((fact) => fact.authority));
    if (classes.size > 0) for (const id of reads) checkTargetUse(ctx, id, classes);
  }
  for (const call of ctx.calls) {
    if (isProvenCreateServerCall(ctx, call)) checkCreateServerCall(ctx, call);
    else if (isConfinedFactoryCall(ctx, call)) checkTargetUse(ctx, call, new Set(['SERVER']));
  }
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
    fixpointCeiling: options.fixpointCeiling ?? DEFAULT_FIXPOINT_CEILING,
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
}

function analyze(source: string, options: NetworkPolicyOptions): { ctx: Context; result: NetworkPolicyResult } {
  const ctx = createContext(source, options);
  collect(ctx, ctx.sourceFile);
  buildWriteInventory(ctx);
  collectHttpImports(ctx);
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
  };
}
