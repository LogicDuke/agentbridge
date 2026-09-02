/**
 * Cockpit D3 network policy — semantic regression matrix.
 *
 * Data-driven rows grouped into the eighteen frozen semantic categories. Each
 * row carries one of three expectations:
 *
 *   MUST_DENY                  the policy must reject the source; every listed
 *                              reason code must be present in the result
 *   MUST_ALLOW                 the policy must accept the source
 *   OUTSIDE_DECLARED_BOUNDARY  the source exercises a mechanism the single-file
 *                              policy does not claim (module graph, runtime
 *                              interpretation, prototype graph, RC/HA territory);
 *                              the analyzer must terminate, nothing more
 *
 * The rows are compact witnesses of policy *semantics*, not an enumeration of
 * spellings. A `closes` tag names the PR #64 finding a row structurally closes.
 */

import type { NetworkPolicyOptions, ReasonCode } from './d3-network-policy.js';

export type RegressionCategory =
  | 'free-global identity'
  | 'node:http namespace/client capability'
  | 'static/computed keys'
  | 'shorthand value binding'
  | 'socket acquisition through proven target policy'
  | 'runtime keys'
  | 'alias propagation'
  | 'local function propagation'
  | 'callee immutability'
  | 'mutation/reflection'
  | 'createServer listener boundary'
  | 'options argument DENY'
  | 'factory confinement'
  | 'result confinement'
  | 'export confinement'
  | 'convergence/exhaustion'
  | 'extra parameter false positives'
  | 'real host acceptance';

export const REGRESSION_CATEGORIES: readonly RegressionCategory[] = [
  'free-global identity',
  'node:http namespace/client capability',
  'static/computed keys',
  'shorthand value binding',
  'socket acquisition through proven target policy',
  'runtime keys',
  'alias propagation',
  'local function propagation',
  'callee immutability',
  'mutation/reflection',
  'createServer listener boundary',
  'options argument DENY',
  'factory confinement',
  'result confinement',
  'export confinement',
  'convergence/exhaustion',
  'extra parameter false positives',
  'real host acceptance',
];

export type Expectation = 'MUST_DENY' | 'MUST_ALLOW' | 'OUTSIDE_DECLARED_BOUNDARY';
export type Pr64Finding = 'F-1' | 'F-2' | 'F-3' | 'F-4' | 'F-5' | 'F-6' | 'F-7';

export interface RegressionRow {
  readonly category: RegressionCategory;
  readonly name: string;
  readonly source: string;
  readonly expectation: Expectation;
  /** MUST_DENY only: every listed reason must appear in the result. */
  readonly reasons?: readonly ReasonCode[];
  readonly options?: NetworkPolicyOptions;
  readonly closes?: readonly Pr64Finding[];
}

// ---------------------------------------------------------------------------
// Source fragments
// ---------------------------------------------------------------------------

const NS = `import http from 'node:http';`;
const STAR = `import * as http from 'node:http';`;
const NAMED = `import { createServer } from 'node:http';`;
const L = `(request: http.IncomingMessage, response: http.ServerResponse) => { response.end('ok'); }`;
const L_PLAIN = `(request, response) => { response.end('ok'); }`;

/** A namespace-imported host with a listener whose body is `body`. */
const inListener = (body: string): string => `${NS}\nhttp.createServer((request, response) => {\n  ${body}\n});`;

/** A namespace-imported host holding the proven server in `server`, followed by `rest`. */
const withServer = (rest: string): string => `${NS}\nconst server = http.createServer(${L});\n${rest}`;

/** The real host's exported confined factory plus `rest`. */
const withFactory = (rest: string): string =>
  `${NS}\nexport function createCockpitServer(): http.Server {\n  return http.createServer(${L});\n}\n${rest}`;

/** A reverse-ordered propagation chain: `f1(response)` reaches `fN` only after N fixpoint passes. */
const reverseChain = (length: number): string => {
  const functions: string[] = [];
  for (let index = length; index >= 1; index -= 1) {
    const body = index === length ? 'res.end();' : `f${String(index + 1)}(res);`;
    functions.push(`function f${String(index)}(res: http.ServerResponse): void { ${body} }`);
  }
  return `${NS}\n${functions.join('\n')}\nhttp.createServer((request, response) => { f1(response); });`;
};

const REAL_HOST_SHAPE = `${NS}
import { pathToFileURL } from 'node:url';

export const HOST = '127.0.0.1';
export const PORT = 4317;
const CONTENT_SECURITY_POLICY = "default-src 'none'";
const STYLES = 'body{}';

function applySecurityHeaders(response: http.ServerResponse): void {
  response.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
  response.setHeader('X-Content-Type-Options', 'nosniff');
}

export function buildDashboardHtml(): string {
  return '<html></html>';
}

function pathOf(url: string): string {
  const queryIndex = url.indexOf('?');
  return queryIndex === -1 ? url : url.slice(0, queryIndex);
}

export function createCockpitServer(): http.Server {
  const page = buildDashboardHtml();
  return http.createServer((request: http.IncomingMessage, response: http.ServerResponse): void => {
    applySecurityHeaders(response);
    const method = request.method ?? '';
    if (method !== 'GET') {
      response.statusCode = 405;
      response.setHeader('Allow', 'GET');
      response.end('405 Method Not Allowed');
      return;
    }
    const path = pathOf(request.url ?? '');
    if (path === '/') {
      response.statusCode = 200;
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end(page);
      return;
    }
    if (path === '/styles.css') {
      response.statusCode = 200;
      response.end(STYLES);
      return;
    }
    response.statusCode = 404;
    response.end('404 Not Found');
  });
}

function main(): void {
  const server = createCockpitServer();
  server.listen(PORT, HOST, () => {
    console.log(\`AgentBridge Cockpit: http://\${HOST}:\${String(PORT)}/\`);
  });
}

const entryArgument = process.argv[1];
const isEntry = entryArgument !== undefined && import.meta.url === pathToFileURL(entryArgument).href;
if (isEntry) {
  main();
}
`;

// ---------------------------------------------------------------------------
// Row builders
// ---------------------------------------------------------------------------

interface RowExtras {
  readonly options?: NetworkPolicyOptions;
  readonly closes?: readonly Pr64Finding[];
}

const deny = (
  category: RegressionCategory,
  name: string,
  source: string,
  reasons: readonly ReasonCode[],
  extras: RowExtras = {},
): RegressionRow => ({ category, name, source, expectation: 'MUST_DENY', reasons, ...extras });

const allow = (category: RegressionCategory, name: string, source: string, extras: RowExtras = {}): RegressionRow => ({
  category,
  name,
  source,
  expectation: 'MUST_ALLOW',
  ...extras,
});

const outside = (category: RegressionCategory, name: string, source: string): RegressionRow => ({
  category,
  name,
  source,
  expectation: 'OUTSIDE_DECLARED_BOUNDARY',
});

// ---------------------------------------------------------------------------
// 1. free-global identity
// ---------------------------------------------------------------------------

const FREE_GLOBAL: readonly RegressionRow[] = [
  deny('free-global identity', 'bare fetch call', `fetch('https://example.com/');`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'fetch aliased into a const', `const f = fetch;`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'fetch stored in an array', `const fns = [fetch];`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'fetch as a call argument', `use(fetch);`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'fetch returned from a function', `function get() { return fetch; }`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'fetch as shorthand property value', `const o = { fetch };`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'fetch exported by specifier without a local binding', `export { fetch };`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'WebSocket constructed', `new WebSocket('wss://example.com/');`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'typeof fetch is still a value read', `const t = typeof fetch;`, ['FREE_GLOBAL_NETWORK']),
  deny(
    'free-global identity',
    'ambient const shadow does not exist at runtime',
    `declare const fetch: (url: string) => unknown;\nfetch('https://example.com/');`,
    ['FREE_GLOBAL_NETWORK'],
  ),
  deny(
    'free-global identity',
    'ambient function shadow does not exist at runtime',
    `declare function fetch(url: string): unknown;\nfetch('https://example.com/');`,
    ['FREE_GLOBAL_NETWORK'],
  ),
  deny(
    'free-global identity',
    'ambient namespace member shadow does not exist at runtime',
    `declare namespace fetch { const x: number; }\nfetch;`,
    ['FREE_GLOBAL_NETWORK'],
  ),
  deny('free-global identity', 'type-only shadow does not exist at runtime', `type fetch = string;\nfetch('x');`, ['FREE_GLOBAL_NETWORK']),
  deny(
    'free-global identity',
    'type-only import shadow does not exist at runtime',
    `import type { fetch } from './x.js';\nfetch('x');`,
    ['FREE_GLOBAL_NETWORK'],
  ),
  deny('free-global identity', 'const enum shadow is erased at runtime', `const enum fetch { A }\nfetch;`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'globalThis.fetch member', `globalThis.fetch('https://example.com/');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'window["fetch"] static element key', `window['fetch']('https://example.com/');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'self folded concatenation key', `self['fe' + 'tch']('https://example.com/');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'global.WebSocket member', `new global.WebSocket('wss://example.com/');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'globalThis.globalThis self-hop', `globalThis.globalThis.fetch('x');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'mixed static self-hop chain', `globalThis.self['window'].global.fetch('x');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'wrapped receiver', `(globalThis as any).fetch('x');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'optional-chained receiver', `globalThis?.fetch?.('x');`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'global receiver forwarded through const', `const g = globalThis;`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'global receiver forwarded through container', `const box = [window];`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'global receiver forwarded through call argument', `use(self);`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'global receiver forwarded through return', `function g() { return globalThis; }`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'global receiver forwarded through assignment', `let g; g = globalThis;`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'global receiver forwarded through arbitrary expression', `const g = globalThis ?? null;`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'destructured fetch from globalThis', `const { fetch: f } = globalThis;`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'shorthand destructured fetch from globalThis', `const { fetch } = globalThis;`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'nested self-hop destructuring', `const { self: { fetch: f } } = globalThis;`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny('free-global identity', 'self-hop destructured into a binding', `const { self: s } = globalThis;`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('free-global identity', 'rest destructuring of globalThis', `const { ...rest } = globalThis;`, ['GLOBAL_RECEIVER_DESTRUCTURING']),
  deny('free-global identity', 'array destructuring of globalThis', `const [first] = globalThis as any;`, ['GLOBAL_RECEIVER_DESTRUCTURING']),
  deny('free-global identity', 'destructuring assignment from globalThis', `let f;\n({ fetch: f } = globalThis);`, ['GLOBAL_RECEIVER_NETWORK_MEMBER']),
  deny(
    'free-global identity',
    'nested destructuring assignment from globalThis',
    `let f;\n({ window: { fetch: f } } = globalThis);`,
    ['GLOBAL_RECEIVER_NETWORK_MEMBER'],
  ),
  allow('free-global identity', 'runtime const shadow of fetch', `const fetch = (url: string) => url;\nfetch('x');`),
  allow('free-global identity', 'runtime function shadow of fetch', `function fetch() { return 1; }\nfetch();`),
  allow('free-global identity', 'parameter shadow of fetch', `function run(fetch: () => void) { fetch(); }`),
  allow('free-global identity', 'binding-element shadow of fetch', `const { fetch } = { fetch: 1 };\nfetch;`),
  allow('free-global identity', 'class shadow of WebSocket', `class WebSocket {}\nnew WebSocket();`),
  allow('free-global identity', 'runtime enum shadow of fetch', `enum fetch { A }\nfetch.A;`),
  allow('free-global identity', 'value import shadow of fetch', `import { fetch } from './local.js';\nfetch('x');`),
  allow('free-global identity', 'instantiated namespace shadow of fetch', `namespace fetch {\n  export function get(value: string) {\n    return value;\n  }\n}\nfetch.get('x');`),
  allow('free-global identity', 'instantiated namespace shadow of WebSocket', `namespace WebSocket {\n  export const x = 1;\n}\nWebSocket.x;`),
  allow('free-global identity', 'nested instantiated namespace shadow of fetch', `namespace fetch {\n  export namespace inner {\n    export class C {}\n  }\n}\nnew fetch.inner.C();`),
  allow('free-global identity', 'runtime import-equals shadow of fetch', `import fetch = require('./local.js');\nfetch('x');`),
  allow('free-global identity', 'namespace instantiated by an exported runtime import alias (fetch)', `namespace Local {\n  export const get = (value: string) => value;\n}\nnamespace fetch {\n  export import get = Local.get;\n}\nfetch.get('x');`),
  allow('free-global identity', 'namespace instantiated by an exported runtime import alias (WebSocket)', `namespace Local {\n  export const open = (url: string) => url;\n}\nnamespace WebSocket {\n  export import open = Local.open;\n}\nWebSocket.open('x');`),
  deny('free-global identity', 'namespace holding only a private type alias import stays erased', `namespace Local {\n  export type T = string;\n}\nnamespace fetch {\n  import T = Local.T;\n}\nfetch;`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'type-only namespace is erased at runtime', `namespace fetch {\n  export type T = string;\n  export interface I { x: number }\n}\nfetch;`, ['FREE_GLOBAL_NETWORK']),
  deny('free-global identity', 'type-only import-equals is erased at runtime', `import type fetch = require('./local.js');\nfetch('x');`, ['FREE_GLOBAL_NETWORK']),
  allow('free-global identity', 'fetch as a property key and member name', `const o = { fetch: 1 };\no.fetch;`),
  allow('free-global identity', 'WebSocket in a type position', `let ws: WebSocket | null = null;\nws;`),
  allow('free-global identity', 'fetch as a label', `fetch: for (;;) { break fetch; }`),
  allow('free-global identity', 'harmless global member read', `globalThis.console.log('x');`),
  allow('free-global identity', 'global receiver as expression statement, void, typeof', `globalThis;\nvoid window;\ntypeof self;`),
  allow('free-global identity', 'over-long global key is not a capability', `globalThis['aVeryLongPropertyNameThatIsNotACapability'];`),
  allow('free-global identity', 'harmless destructuring from globalThis', `const { console: c } = globalThis;\nc.log('x');`),
  allow('free-global identity', 'shadowed self is an ordinary object', `const self = { fetch: 1 };
self.fetch;`),
  allow('free-global identity', 'shadowed window parameter is an ordinary object', `function f(window: { fetch: number }) { return window.fetch; }`),
  deny(
    'free-global identity',
    'globalThis cannot be shadowed (TypeScript binds the name to the intrinsic global)',
    `const globalThis = { fetch: 1 };
globalThis.fetch;`,
    ['GLOBAL_RECEIVER_NETWORK_MEMBER'],
  ),
  allow('free-global identity', 'global-root name as a property key', `const g = { globalThis: 1, window: 2 };\ng.globalThis + g.window;`),
];

// ---------------------------------------------------------------------------
// 2. node:http namespace/client capability
// ---------------------------------------------------------------------------

const HTTP_CAPABILITY: readonly RegressionRow[] = [
  deny('node:http namespace/client capability', 'named import of request', `import { request } from 'node:http';\nrequest('x');`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'named import of get', `import { get } from 'node:http';`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'named import of Agent', `import { Agent } from 'node:http';`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'named import of ClientRequest', `import { ClientRequest } from 'node:http';`, ['HTTP_CLIENT_CAPABILITY']),
  deny(
    'node:http namespace/client capability',
    'createServer alongside a client import',
    `import { createServer, request } from 'node:http';\ncreateServer(${L_PLAIN});`,
    ['HTTP_CLIENT_CAPABILITY'],
  ),
  deny('node:http namespace/client capability', 'bare http specifier client import', `import { request } from 'http';`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace http.request', `${NS}\nhttp.request('x');`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace http.get', `${STAR}\nhttp.get('x');`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace new http.Agent', `${NS}\nnew http.Agent();`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace globalAgent read', `${NS}\nconst a = http.globalAgent;`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace folded client key', `${NS}\nhttp['req' + 'uest']('x');`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace STATUS_CODES is not allow-listed', `${NS}\nhttp.STATUS_CODES;`, ['HTTP_CLIENT_CAPABILITY']),
  deny('node:http namespace/client capability', 'namespace runtime key', `${NS}\ndeclare const k: string;\nhttp[k]('x');`, ['HTTP_NAMESPACE_RUNTIME_KEY']),
  deny('node:http namespace/client capability', 'namespace aliased', `${NS}\nconst h = http;`, ['HTTP_NAMESPACE_ESCAPE']),
  deny('node:http namespace/client capability', 'namespace destructured', `${NS}\nconst { createServer } = http;`, ['HTTP_NAMESPACE_ESCAPE']),
  deny('node:http namespace/client capability', 'namespace passed as argument', `${NS}\nuse(http);`, ['HTTP_NAMESPACE_ESCAPE']),
  deny('node:http namespace/client capability', 'namespace exported', `${NS}\nexport { http };`, ['HTTP_NAMESPACE_ESCAPE']),
  deny('node:http namespace/client capability', 'namespace default-exported', `${NS}\nexport default http;`, ['HTTP_NAMESPACE_ESCAPE']),
  deny('node:http namespace/client capability', 'namespace in a container', `${NS}\nconst box = { http };`, ['HTTP_NAMESPACE_ESCAPE']),
  deny('node:http namespace/client capability', 'import-equals require of node:http', `import http = require('node:http');`, ['HTTP_IMPORT_EQUALS']),
  deny('node:http namespace/client capability', 'dynamic import of node:http', `const m = await import('node:http');`, ['HTTP_DYNAMIC_IMPORT']),
  deny('node:http namespace/client capability', 'dynamic import of folded node:http', `import('node:' + 'http');`, ['HTTP_DYNAMIC_IMPORT']),
  deny('node:http namespace/client capability', 'dynamic import with indeterminate specifier', `declare const spec: string;\nimport(spec);`, ['HTTP_DYNAMIC_IMPORT']),
  deny('node:http namespace/client capability', 'star re-export of node:http', `export * from 'node:http';`, ['HTTP_REEXPORT']),
  deny('node:http namespace/client capability', 'named re-export of createServer', `export { createServer } from 'node:http';`, ['HTTP_REEXPORT']),
  deny('node:http namespace/client capability', 'namespace re-export of node:http', `export * as h from 'node:http';`, ['HTTP_REEXPORT']),
  deny('node:http namespace/client capability', 'createServer extracted from namespace', `${NS}\nconst cs = http.createServer;`, ['CREATE_SERVER_NOT_CALLED']),
  deny('node:http namespace/client capability', 'createServer binding aliased', `${NAMED}\nconst cs = createServer;`, ['CREATE_SERVER_ESCAPE']),
  deny('node:http namespace/client capability', 'createServer binding exported', `${NAMED}\nexport { createServer };`, ['CREATE_SERVER_ESCAPE']),
  deny('node:http namespace/client capability', 'createServer binding passed as argument', `${NAMED}\nuse(createServer);`, ['CREATE_SERVER_ESCAPE']),
  allow('node:http namespace/client capability', 'type-only named import', `import type { IncomingMessage } from 'node:http';\nlet m: IncomingMessage | null = null;\nm;`),
  allow(
    'node:http namespace/client capability',
    'inline type import beside createServer',
    `import { type IncomingMessage, createServer } from 'node:http';\ncreateServer(${L_PLAIN});`,
  ),
  allow('node:http namespace/client capability', 'side-effect import', `import 'node:http';`),
  allow('node:http namespace/client capability', 'type-only re-export', `export type { Server } from 'node:http';`),
  allow('node:http namespace/client capability', 'star namespace createServer', `${STAR}\nhttp.createServer(${L});`),
  allow('node:http namespace/client capability', 'default namespace createServer', `${NS}\nhttp.createServer(${L});`),
  allow('node:http namespace/client capability', 'named createServer', `${NAMED}\ncreateServer(${L_PLAIN});`),
  allow('node:http namespace/client capability', 'renamed named createServer', `import { createServer as make } from 'node:http';\nmake(${L_PLAIN});`),
  allow('node:http namespace/client capability', 'namespace used only in type positions', `${NS}\nlet s: http.Server | null = null;\nlet t: typeof http | null = null;\ns; t;`),
];

// ---------------------------------------------------------------------------
// 3. static/computed keys
// ---------------------------------------------------------------------------

const STATIC_KEYS: readonly RegressionRow[] = [
  allow('static/computed keys', 'string literal key', `${NS}\nhttp['createServer'](${L});`),
  allow('static/computed keys', 'no-substitution template key', `${NS}\nhttp[\`createServer\`](${L});`),
  allow('static/computed keys', 'unique const key', `${NS}\nconst K = 'createServer';\nhttp[K](${L});`),
  allow('static/computed keys', 'folded concatenation', `${NS}\nconst A = 'create';\nconst B = 'Server';\nhttp[A + B](${L});`),
  allow('static/computed keys', 'template substitution of a const', `${NS}\nconst A = 'create';\nhttp[\`\${A}Server\`](${L});`),
  allow('static/computed keys', 'wrapped const key', `${NS}\nconst K = 'createServer';\nhttp[(K as string)!](${L});`),
  allow('static/computed keys', 'satisfies-wrapped key', `${NS}\nconst K = 'createServer' satisfies string;\nhttp[K](${L});`),
  allow('static/computed keys', 'scope-sensitive inner const resolves', `${NS}\nconst K = 'request';\n{\n  const K = 'createServer';\n  http[K](${L});\n}`),
  allow('static/computed keys', 'request static element key', inListener(`request['url'];\nrequest['met' + 'hod'];`)),
  allow('static/computed keys', 'response static element key', inListener(`response['statusCode'] = 200;\nresponse['end']();`)),
  allow('static/computed keys', 'server static element key', withServer(`server['listen'](1);`)),
  deny('static/computed keys', 'outer const resolves to client key', `${NS}\nconst K = 'request';\n{\n  const K = 'createServer';\n}\nhttp[K]('x');`, ['HTTP_CLIENT_CAPABILITY']),
  deny('static/computed keys', 'let key is indeterminate', `${NS}\nlet K = 'createServer';\nhttp[K](${L});`, ['HTTP_NAMESPACE_RUNTIME_KEY']),
  deny('static/computed keys', 'written const key is indeterminate', `${NS}\nconst K = 'createServer';\n(K as any) = 'x';\nhttp[K](${L});`, ['HTTP_NAMESPACE_RUNTIME_KEY']),
  deny('static/computed keys', 'cyclic const keys are indeterminate', `${NS}\nconst A: string = B;\nconst B: string = A;\nhttp[A](${L});`, ['HTTP_NAMESPACE_RUNTIME_KEY']),
  deny('static/computed keys', 'destructured key is indeterminate', `${NS}\nconst { K } = { K: 'createServer' };\nhttp[K](${L});`, ['HTTP_NAMESPACE_RUNTIME_KEY']),
  deny('static/computed keys', 'over-long key on proven target is denied', `${NS}\nhttp['createServerButMuchLongerThanAnyPolicyName'](${L});`, ['HTTP_CLIENT_CAPABILITY']),
  deny('static/computed keys', 'resolved non-allowed key on request', inListener(`request['soc' + 'ket'];`), ['REQUEST_MEMBER']),
  deny('static/computed keys', 'resolved non-allowed key on server', withServer(`server[\`on\`]('connection', () => {});`), ['SERVER_MEMBER']),
];

// ---------------------------------------------------------------------------
// 4. shorthand value binding
// ---------------------------------------------------------------------------

const SHORTHAND: readonly RegressionRow[] = [
  deny('shorthand value binding', 'server as shorthand property value', withServer(`const box = { server };`), ['SERVER_ESCAPE'], { closes: ['F-3'] }),
  deny('shorthand value binding', 'request as shorthand property value', inListener(`const box = { request };`), ['REQUEST_ESCAPE'], { closes: ['F-3'] }),
  deny('shorthand value binding', 'response as shorthand property value', inListener(`const box = { response };`), ['RESPONSE_ESCAPE'], { closes: ['F-3'] }),
  deny('shorthand value binding', 'shorthand return container', withFactory(`function bundle() { const server = createCockpitServer(); return { server }; }`), ['SERVER_ESCAPE'], {
    closes: ['F-3'],
  }),
  deny('shorthand value binding', 'shorthand destructuring assignment onto request', inListener(`({ request } = { request: null } as any);`), ['REQUEST_DESTRUCTURING'], {
    closes: ['F-3'],
  }),
  deny('shorthand value binding', 'shorthand export of server', withServer(`export { server };`), ['SERVER_EXPORT'], { closes: ['F-3', 'F-7'] }),
  allow('shorthand value binding', 'property key named request is not a value read', inListener(`const box = { request: 1 };\nbox.request;`)),
  allow(
    'shorthand value binding',
    'shorthand of a same-named unrelated binding in another scope',
    `${NS}\nhttp.createServer(${L});\nfunction other() { const request = 1; const response = 2; return { request, response }; }`,
  ),
];

// ---------------------------------------------------------------------------
// 5. socket acquisition through proven target policy
// ---------------------------------------------------------------------------

const SOCKET: readonly RegressionRow[] = [
  deny('socket acquisition through proven target policy', 'request.socket', inListener(`request.socket;`), ['REQUEST_MEMBER']),
  deny('socket acquisition through proven target policy', 'request.socket.write chain', inListener(`request.socket.write('x');`), ['REQUEST_MEMBER']),
  deny('socket acquisition through proven target policy', 'request.connection', inListener(`const c = request.connection;`), ['REQUEST_MEMBER']),
  deny('socket acquisition through proven target policy', 'response.socket', inListener(`response.socket;`), ['RESPONSE_MEMBER']),
  deny('socket acquisition through proven target policy', 'response.connection.write', inListener(`response.connection.write('x');`), ['RESPONSE_MEMBER']),
  deny('socket acquisition through proven target policy', 'destructured socket from request', inListener(`const { socket } = request;`), ['REQUEST_DESTRUCTURING'], { closes: ['F-2'] }),
  deny('socket acquisition through proven target policy', 'destructured socket from response', inListener(`const { socket: s } = response;`), ['RESPONSE_DESTRUCTURING'], { closes: ['F-2'] }),
  deny('socket acquisition through proven target policy', 'renamed destructuring of an innocuous key still denied', inListener(`const { url } = request;`), ['REQUEST_DESTRUCTURING'], {
    closes: ['F-2'],
  }),
  deny('socket acquisition through proven target policy', 'request event subscription', inListener(`request.on('data', () => {});`), ['REQUEST_MEMBER']),
  deny('socket acquisition through proven target policy', 'request.headers read', inListener(`request.headers;`), ['REQUEST_MEMBER']),
  deny('socket acquisition through proven target policy', 'response.write', inListener(`response.write('x');`), ['RESPONSE_MEMBER']),
  deny('socket acquisition through proven target policy', 'response.writeHead', inListener(`response.writeHead(200);`), ['RESPONSE_MEMBER']),
  deny('socket acquisition through proven target policy', 'response.getHeader (benign but not allow-listed)', inListener(`response.getHeader('x');`), ['RESPONSE_MEMBER']),
  deny('socket acquisition through proven target policy', 'response.statusCode read', inListener(`const c = response.statusCode;`), ['RESPONSE_MEMBER']),
  deny('socket acquisition through proven target policy', 'server.on connection', withServer(`server.on('connection', (socket) => { socket.write('x'); });`), ['SERVER_MEMBER']),
  deny('socket acquisition through proven target policy', 'server.address', withServer(`server.address();`), ['SERVER_MEMBER']),
  deny('socket acquisition through proven target policy', 'server.listen read without call', withServer(`const l = server.listen;`), ['SERVER_MEMBER']),
  deny('socket acquisition through proven target policy', 'server.listen.call nested chain', withServer(`server.listen.call(server, 1);`), ['SERVER_MEMBER', 'SERVER_ESCAPE']),
  deny('socket acquisition through proven target policy', 'server.close.bind', withServer(`const c = server.close.bind(server);`), ['SERVER_MEMBER', 'SERVER_ESCAPE']),
  deny('socket acquisition through proven target policy', 'optional-chained listen', withServer(`server?.listen(1);`), ['SERVER_MEMBER']),
  deny('socket acquisition through proven target policy', 'server.connections', withServer(`server.connections;`), ['SERVER_MEMBER']),
  allow('socket acquisition through proven target policy', 'listen with callback', withServer(`server.listen(4317, '127.0.0.1', () => { console.log('up'); });`)),
  allow('socket acquisition through proven target policy', 'close', withServer(`server.close();`)),
  allow('socket acquisition through proven target policy', 'request.method and request.url', inListener(`const m = request.method ?? '';\nconst u = request.url;\nm + u;`)),
  allow('socket acquisition through proven target policy', 'response setHeader/end/statusCode', inListener(`response.statusCode = 404;\nresponse.setHeader('a', 'b');\nresponse.end('x');`)),
];

// ---------------------------------------------------------------------------
// 6. runtime keys
// ---------------------------------------------------------------------------

const RUNTIME_KEYS: readonly RegressionRow[] = [
  deny('runtime keys', 'server[k]()', withServer(`declare const k: string;\nserver[k]();`), ['SERVER_MEMBER']),
  deny('runtime keys', 'request[k]', inListener(`declare const k: string;\nrequest[k];`), ['REQUEST_MEMBER']),
  deny('runtime keys', 'response[k] = 1', inListener(`declare const k: string;\nresponse[k] = 1;`), ['RESPONSE_MEMBER']),
  deny('runtime keys', 'server[fn()]', withServer(`server[String(1)]();`), ['SERVER_MEMBER']),
  deny('runtime keys', 'globalThis[k]', `declare const k: string;\nglobalThis[k];`, ['GLOBAL_RECEIVER_RUNTIME_KEY']),
  deny('runtime keys', 'computed destructuring key from globalThis', `declare const k: string;\nconst { [k]: v } = globalThis;`, ['GLOBAL_RECEIVER_RUNTIME_KEY']),
  deny('runtime keys', 'computed destructuring assignment key from globalThis', `declare const k: string;\nlet v;\n({ [k]: v } = globalThis);`, ['GLOBAL_RECEIVER_RUNTIME_KEY']),
  deny('runtime keys', 'parameter key on request', inListener(`function read(k: string) { return request[k]; }`), ['REQUEST_MEMBER']),
  deny('runtime keys', 'http[k] with parameter', `${NS}\nfunction pick(k: string) { return http[k]; }`, ['HTTP_NAMESPACE_RUNTIME_KEY']),
];

// ---------------------------------------------------------------------------
// 7. alias propagation
// ---------------------------------------------------------------------------

const ALIAS: readonly RegressionRow[] = [
  allow('alias propagation', 'const alias chain of server', withServer(`const a = server;\nconst b = a;\nb.listen(1);`)),
  allow('alias propagation', 'wrapped alias', withServer(`const a = (server as http.Server)!;\na.close();`)),
  allow('alias propagation', 'alias of request and response in listener', inListener(`const q = request;\nconst s = response;\nq.url;\ns.end();`)),
  allow('alias propagation', 'alias used as statement, void, typeof', withServer(`const a = server;\na;\nvoid a;\ntypeof a;`)),
  deny('alias propagation', 'let binding of server', `${NS}\nlet server = http.createServer(${L});`, ['SERVER_MUTABLE_BINDING']),
  deny('alias propagation', 'var binding of server', `${NS}\nvar server = http.createServer(${L});`, ['SERVER_MUTABLE_BINDING']),
  deny('alias propagation', 'let alias of server', withServer(`let a = server;`), ['SERVER_MUTABLE_BINDING']),
  deny('alias propagation', 'let alias of response', inListener(`let r = response;`), ['RESPONSE_MUTABLE_BINDING']),
  deny('alias propagation', 'exported const alias of server', withServer(`export const a = server;`), ['SERVER_EXPORT']),
  deny('alias propagation', 'written const alias is not immutable', withServer(`const a = server;
(a as any) = null;`), ['SERVER_MUTABLE_BINDING']),
  deny('alias propagation', 'conditional initializer', withServer(`const a = Math.random() > 0.5 ? server : null;`), ['SERVER_ESCAPE']),
  deny('alias propagation', 'comma initializer', inListener(`const r = (0, request);`), ['REQUEST_ESCAPE']),
  deny('alias propagation', 'await initializer', inListener(`const r = await response;`), ['RESPONSE_ESCAPE']),
  deny('alias propagation', 'container initializer', withServer(`const [a] = [server];`), ['SERVER_ESCAPE']),
  deny('alias propagation', 'destructuring initializer', withServer(`const { listen } = server;`), ['SERVER_DESTRUCTURING']),
  deny('alias propagation', 'assignment forwarding', withServer(`let a;\na = server;`), ['SERVER_ESCAPE']),
  deny('alias propagation', 'alias then escape', withServer(`const a = server;\nuse(a);`), ['SERVER_ESCAPE']),
  deny('alias propagation', 'alias then non-allowed member', inListener(`const q = request;\nq.socket;`), ['REQUEST_MEMBER']),
  deny('alias propagation', 'ambient const alias', withServer(`declare const a: typeof server;\nconst b = server;\nb.on('x', () => {});`), ['SERVER_MEMBER']),
];

// ---------------------------------------------------------------------------
// 8. local function propagation
// ---------------------------------------------------------------------------

const LOCAL_PROPAGATION: readonly RegressionRow[] = [
  allow(
    'local function propagation',
    'FunctionDeclaration receives response (real host applySecurityHeaders)',
    `${NS}\nfunction applySecurityHeaders(response: http.ServerResponse): void { response.setHeader('a', 'b'); }\nhttp.createServer((request, response) => { applySecurityHeaders(response); });`,
  ),
  allow(
    'local function propagation',
    'const arrow receives response',
    `${NS}\nconst apply = (res: http.ServerResponse): void => { res.end(); };\nhttp.createServer((request, response) => { apply(response); });`,
  ),
  allow(
    'local function propagation',
    'const function expression receives request',
    `${NS}\nconst read = function (req: http.IncomingMessage) { return req.url; };\nhttp.createServer((request, response) => { read(request); response.end(); });`,
  ),
  allow(
    'local function propagation',
    'two-hop propagation',
    `${NS}\nfunction a(res: http.ServerResponse) { b(res); }\nfunction b(res: http.ServerResponse) { res.end(); }\nhttp.createServer((request, response) => { a(response); });`,
  ),
  allow(
    'local function propagation',
    'parameter with default initializer',
    `${NS}\ndeclare const fallback: http.ServerResponse;\nfunction a(res: http.ServerResponse = fallback) { res.end(); }\nhttp.createServer((request, response) => { a(response); });`,
  ),
  allow('local function propagation', 'server passed to eligible local setup', withServer(`function setup(s: http.Server) { s.listen(1); }\nsetup(server);`)),
  allow('local function propagation', 'createServer result passed directly to eligible callee', `${NS}\nfunction setup(s: http.Server) { s.listen(1); }\nsetup(http.createServer(${L}));`),
  allow(
    'local function propagation',
    'mutually recursive propagation converges',
    `${NS}\nfunction a(res: http.ServerResponse, n: number) { if (n > 0) b(res, n - 1); else res.end(); }\nfunction b(res: http.ServerResponse, n: number) { a(res, n); }\nhttp.createServer((request, response) => { a(response, 3); });`,
  ),
  deny(
    'local function propagation',
    'propagated response misused',
    `${NS}\nfunction f(res: http.ServerResponse) { res.socket; }\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_MEMBER'],
  ),
  deny(
    'local function propagation',
    'propagated request destructured',
    `${NS}\nfunction f(req: http.IncomingMessage) { const { socket } = req; }\nhttp.createServer((request, response) => { f(request); });`,
    ['REQUEST_DESTRUCTURING'],
    { closes: ['F-1'] },
  ),
  deny(
    'local function propagation',
    'propagated server misused two hops away',
    withServer(`function a(s: http.Server) { b(s); }\nfunction b(s: http.Server) { s.on('x', () => {}); }\na(server);`),
    ['SERVER_MEMBER'],
  ),
  deny(
    'local function propagation',
    'rest parameter callee',
    `${NS}\nfunction f(...args: unknown[]) { args; }\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
  ),
  deny(
    'local function propagation',
    'pattern parameter callee',
    `${NS}\nfunction f({ socket }: http.IncomingMessage) { socket; }\nhttp.createServer((request, response) => { f(request); });`,
    ['REQUEST_ESCAPE'],
  ),
  deny(
    'local function propagation',
    'missing parameter callee',
    `${NS}\nfunction f() { return 1; }\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
  ),
  deny('local function propagation', 'unknown callee', inListener(`use(response);`), ['RESPONSE_ESCAPE']),
  deny('local function propagation', 'method callee', inListener(`const o = { handle(r: unknown) { return r; } };\no.handle(response);`), ['RESPONSE_ESCAPE']),
  deny('local function propagation', 'spread argument', `${NS}\nfunction f(res: unknown) { res; }\nhttp.createServer((request, response) => { f(...[response]); });`, ['RESPONSE_ESCAPE']),
  deny('local function propagation', 'let-bound callee', `${NS}\nlet f = (res: unknown) => { res; };\nhttp.createServer((request, response) => { f(response); });`, ['RESPONSE_ESCAPE']),
  deny('local function propagation', 'IIFE callee', inListener(`((r: http.IncomingMessage) => r.socket)(request);`), ['REQUEST_ESCAPE']),
  deny('local function propagation', 'optional call', `${NS}\nfunction f(res: unknown) { res; }\nhttp.createServer((request, response) => { f?.(response); });`, ['RESPONSE_ESCAPE']),
  deny('local function propagation', 'class method callee', `${NS}\nclass H { run(r: unknown) { return r; } }\nhttp.createServer((request, response) => { new H().run(response); });`, ['RESPONSE_ESCAPE']),
  deny('local function propagation', 'new argument', inListener(`class Box { constructor(public v: unknown) {} }\nnew Box(response);`), ['RESPONSE_ESCAPE']),
  deny(
    'local function propagation',
    'callee returns the request',
    `${NS}\nfunction f(req: http.IncomingMessage) { return req; }\nhttp.createServer((request, response) => { f(request); });`,
    ['REQUEST_UNCONFINED_RETURN'],
  ),
  deny(
    'local function propagation',
    'spread precedes the privileged argument',
    `${NS}\nfunction f(a: unknown, res: unknown) { a; res; }\nhttp.createServer((request, response) => { f(...[1], response); });`,
    ['RESPONSE_ESCAPE'],
  ),
];

// ---------------------------------------------------------------------------
// 9. callee immutability
// ---------------------------------------------------------------------------

const IMMUTABILITY: readonly RegressionRow[] = [
  deny(
    'callee immutability',
    'reassigned FunctionDeclaration callee',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\n(f as any) = (r: any) => r.socket.write('x');\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'destructuring-assigned FunctionDeclaration callee',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\n[(f as any)] = [null];\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'shorthand destructuring-assigned FunctionDeclaration callee',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\n({ f } = { f: null } as any);\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4', 'F-3'] },
  ),
  deny(
    'callee immutability',
    'for-of assigned FunctionDeclaration callee',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\nfor (f as any of [null]) {}\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'compound-assigned FunctionDeclaration callee',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\n(f as any) += 1;\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'updated FunctionDeclaration callee',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\n(f as any)++;\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'duplicate FunctionDeclaration is not unique',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\nfunction f(res: http.ServerResponse) { res.socket; }\nhttp.createServer((request, response) => { f(response); });`,
    ['RESPONSE_ESCAPE'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'reassigned listener FunctionDeclaration',
    `${NS}\nfunction handle(request: http.IncomingMessage, response: http.ServerResponse) { response.end(); }\n(handle as any) = null;\nhttp.createServer(handle);`,
    ['LISTENER_NOT_FUNCTION'],
    { closes: ['F-4'] },
  ),
  deny(
    'callee immutability',
    'reassigned factory FunctionDeclaration',
    `${NS}\nfunction make() { return http.createServer(${L}); }\n(make as any) = null;\nconst server = make();`,
    ['SERVER_UNCONFINED_RETURN'],
    { closes: ['F-4', 'F-6'] },
  ),
  allow(
    'callee immutability',
    'read-only aliasing of the callee leaves it immutable',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\nconst g = f;\nhttp.createServer((request, response) => { f(response); });`,
  ),
  allow(
    'callee immutability',
    'callee written only as a property key elsewhere',
    `${NS}\nfunction f(res: http.ServerResponse) { res.end(); }\nconst o = { f: 1 };\no.f = 2;\nhttp.createServer((request, response) => { f(response); });`,
  ),
];

// ---------------------------------------------------------------------------
// 10. mutation/reflection
// ---------------------------------------------------------------------------

const MUTATION: readonly RegressionRow[] = [
  deny('mutation/reflection', 'Object.defineProperty on response', inListener(`Object.defineProperty(response, 'x', { value: 1 });`), ['RESPONSE_ESCAPE']),
  deny('mutation/reflection', 'Reflect.get on request', inListener(`Reflect.get(request, 'socket');`), ['REQUEST_ESCAPE']),
  deny('mutation/reflection', 'Object.assign on server', withServer(`Object.assign(server, {});`), ['SERVER_ESCAPE']),
  deny('mutation/reflection', 'Object.getPrototypeOf on response', inListener(`Object.getPrototypeOf(response);`), ['RESPONSE_ESCAPE']),
  deny('mutation/reflection', 'Object.setPrototypeOf on server', withServer(`Object.setPrototypeOf(server, null);`), ['SERVER_ESCAPE']),
  deny('mutation/reflection', 'Reflect.get on globalThis', `Reflect.get(globalThis, 'fetch');`, ['GLOBAL_RECEIVER_ESCAPE']),
  deny('mutation/reflection', 'delete response.statusCode', inListener(`delete (response as any).statusCode;`), ['RESPONSE_MEMBER']),
  deny('mutation/reflection', 'response.end overwritten', inListener(`(response as any).end = () => {};`), ['RESPONSE_MEMBER']),
  deny('mutation/reflection', 'server.listen overwritten', withServer(`(server as any).listen = () => {};`), ['SERVER_MEMBER']),
  deny('mutation/reflection', 'request.url written', inListener(`request.url = '/x';`), ['REQUEST_MEMBER']),
  deny('mutation/reflection', 'request.method compound write', inListener(`(request as any).method += 'X';`), ['REQUEST_MEMBER']),
  deny('mutation/reflection', 'response.statusCode incremented', inListener(`response.statusCode++;`), ['RESPONSE_MEMBER']),
  deny('mutation/reflection', 'response.statusCode non-literal assignment', inListener(`declare const code: number;\nresponse.statusCode = code;`), ['RESPONSE_MEMBER']),
  deny('mutation/reflection', 'response.statusCode arithmetic assignment', inListener(`response.statusCode = 200 + 4;`), ['RESPONSE_MEMBER']),
  deny('mutation/reflection', 'response.setHeader.call', inListener(`response.setHeader.call(response, 'a', 'b');`), ['RESPONSE_MEMBER', 'RESPONSE_ESCAPE']),
  deny('mutation/reflection', 'request destructured as write target', inListener(`[request.url] = ['/x'];`), ['REQUEST_MEMBER']),
  deny('mutation/reflection', 'for-in over request', inListener(`for (const k in request) { k; }`), ['REQUEST_ESCAPE']),
  deny('mutation/reflection', 'for-of assignment to server binding', withServer(`for (server as any of []) {}`), ['SERVER_MUTABLE_BINDING']),
  deny('mutation/reflection', 'server reassigned', withServer(`(server as any) = null;`), ['SERVER_MUTABLE_BINDING']),
  deny('mutation/reflection', 'propagated server parameter reassigned', withServer(`function setup(s: http.Server) { (s as any) = null; }
setup(server);`), ['SERVER_WRITE']),
  deny('mutation/reflection', 'response reassigned', inListener(`response = null as any;`), ['RESPONSE_WRITE']),
  deny('mutation/reflection', 'ThisExpression anywhere', `${NS}\nfunction f() { return this; }`, ['THIS_EXPRESSION']),
  deny('mutation/reflection', 'arguments anywhere', `${NS}\nfunction f() { return arguments[0]; }`, ['ARGUMENTS_USE']),
  deny('mutation/reflection', 'arguments forwarded from listener', inListener(`use(arguments);`), ['ARGUMENTS_USE']),
  allow('mutation/reflection', 'unrelated reflection', `Object.freeze({ a: 1 });\nReflect.ownKeys({});`),
  allow('mutation/reflection', 'statusCode numeric literal with wrapper', inListener(`response.statusCode = (200 as number);`)),
  allow('mutation/reflection', 'this in a type position and arguments as a property key', `${NS}\nfunction f(this: void): this is void { return true; }\nconst o = { arguments: 1 };\no.arguments;`),
];

// ---------------------------------------------------------------------------
// 11. createServer listener boundary
// ---------------------------------------------------------------------------

const LISTENER_BOUNDARY: readonly RegressionRow[] = [
  deny('createServer listener boundary', 'zero arguments', `${NS}\nhttp.createServer();`, ['CREATE_SERVER_ARITY']),
  deny('createServer listener boundary', 'two listener arguments', `${NS}\nhttp.createServer(${L}, ${L});`, ['CREATE_SERVER_ARITY']),
  deny('createServer listener boundary', 'new http.createServer', `${NS}\nnew http.createServer(${L});`, ['CREATE_SERVER_NEW']),
  deny('createServer listener boundary', 'new createServer', `${NAMED}\nnew createServer(${L_PLAIN});`, ['CREATE_SERVER_NEW']),
  deny('createServer listener boundary', 'let-bound listener', `${NS}\nlet handler = ${L};\nhttp.createServer(handler);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'imported listener', `${NS}\nimport { handler } from './h.js';\nhttp.createServer(handler);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'object listener', `${NS}\nhttp.createServer({} as any);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'conditional listener', `${NS}\nhttp.createServer(Math.random() > 0.5 ? ${L} : ${L});`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'spread listener', `${NS}\ndeclare const args: [any];\nhttp.createServer(...args);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'class listener', `${NS}\nhttp.createServer(class {} as any);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'call-result listener', `${NS}\ndeclare function make(): any;\nhttp.createServer(make());`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'written const listener spine', `${NS}\nconst handler = ${L};\n(handler as any) = null;\nhttp.createServer(handler);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'cyclic listener spine', `${NS}\nconst a: any = b;\nconst b: any = a;\nhttp.createServer(a);`, ['LISTENER_NOT_FUNCTION']),
  deny('createServer listener boundary', 'pattern at parameter 0', `${NS}\nhttp.createServer(({ url }, response) => { response.end(url); });`, ['LISTENER_PARAMETER_PATTERN']),
  deny('createServer listener boundary', 'pattern at parameter 1', `${NS}\nhttp.createServer((request, { socket }) => { socket; });`, ['LISTENER_PARAMETER_PATTERN']),
  deny('createServer listener boundary', 'rest at parameter 0', `${NS}\nhttp.createServer((...args: any[]) => { args[1].socket; });`, ['LISTENER_PARAMETER_PATTERN']),
  deny('createServer listener boundary', 'rest at parameter 1', `${NS}\nhttp.createServer((request, ...rest: any[]) => { rest[0].socket; });`, ['LISTENER_PARAMETER_PATTERN']),
  deny('createServer listener boundary', 'this parameter listener', `${NS}\nhttp.createServer(function (this: unknown, request, response) { response.end(); });`, ['LISTENER_THIS_PARAMETER']),
  deny('createServer listener boundary', 'optional-chained namespace call', `${NS}\nhttp?.createServer(${L});`, ['CREATE_SERVER_NOT_CALLED']),
  deny('createServer listener boundary', 'optional-chained createServer call', `${NS}\nhttp.createServer?.(${L});`, ['CREATE_SERVER_NOT_CALLED']),
  deny('createServer listener boundary', 'tagged template createServer', `${NS}\nhttp.createServer\`x\`;`, ['CREATE_SERVER_NOT_CALLED']),
  deny('createServer listener boundary', 'optional-chained named createServer', `${NAMED}\ncreateServer?.(${L_PLAIN});`, ['CREATE_SERVER_ESCAPE']),
  allow('createServer listener boundary', 'arrow listener', `${NS}\nhttp.createServer(${L});`),
  allow('createServer listener boundary', 'async arrow listener', `${NS}\nhttp.createServer(async (request, response) => { response.end(); });`),
  allow('createServer listener boundary', 'anonymous function expression listener', `${NS}\nhttp.createServer(function (request, response) { response.end(); });`),
  allow('createServer listener boundary', 'named function expression listener', `${NS}\nhttp.createServer(function handler(request, response) { response.end(); });`),
  allow('createServer listener boundary', 'unique FunctionDeclaration listener', `${NS}\nfunction handle(request: http.IncomingMessage, response: http.ServerResponse) { response.end(request.url); }\nhttp.createServer(handle);`),
  allow('createServer listener boundary', 'hoisted FunctionDeclaration listener', `${NS}\nhttp.createServer(handle);\nfunction handle(request: http.IncomingMessage, response: http.ServerResponse) { response.end(); }`),
  allow('createServer listener boundary', 'const listener spine', `${NS}\nconst h1 = ${L};\nconst h2 = h1;\nhttp.createServer(h2);`),
  allow('createServer listener boundary', 'wrapped listener', `${NS}\nhttp.createServer((${L}) as any);`),
  allow('createServer listener boundary', 'wrapped callee', `${NS}\n(http.createServer)(${L});`),
  allow('createServer listener boundary', 'zero-parameter listener', `${NS}\nhttp.createServer(() => {});`),
  allow('createServer listener boundary', 'one-parameter listener', `${NS}\nhttp.createServer((request) => { request.url; });`),
  allow('createServer listener boundary', 'pattern at parameter 2 is unconstrained', `${NS}\nhttp.createServer((request, response, { extra }: any) => { response.end(extra); });`),
  allow('createServer listener boundary', 'exported const listener', `${NS}\nexport const handler = ${L};\nhttp.createServer(handler);`),
];

// ---------------------------------------------------------------------------
// 12. options argument DENY
// ---------------------------------------------------------------------------

const OPTIONS: readonly RegressionRow[] = [
  deny('options argument DENY', 'empty options object', `${NS}\nhttp.createServer({}, ${L});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'IncomingMessage override option', `${NS}\nclass Evil {}\nhttp.createServer({ IncomingMessage: Evil }, ${L});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'ServerResponse override option', `${NS}\nclass Evil {}\nhttp.createServer({ ServerResponse: Evil }, ${L});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'shouldUpgradeCallback option', `${NS}\nhttp.createServer({ shouldUpgradeCallback: () => true }, ${L});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'options through a const', `${NS}\nconst opts = { keepAlive: true };\nhttp.createServer(opts, ${L});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'undefined options placeholder', `${NS}\nhttp.createServer(undefined, ${L});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'options only', `${NS}\nhttp.createServer({ keepAlive: true } as any);`, ['LISTENER_NOT_FUNCTION'], { closes: ['F-5'] }),
  deny('options argument DENY', 'options with named createServer', `${NAMED}\ncreateServer({ keepAlive: true }, ${L_PLAIN});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'options in factory return', `${NS}\nexport function make() { return http.createServer({}, ${L}); }`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
  deny('options argument DENY', 'listener then options', `${NS}\nhttp.createServer(${L}, {});`, ['CREATE_SERVER_ARITY'], { closes: ['F-5'] }),
];

// ---------------------------------------------------------------------------
// 13. factory confinement
// ---------------------------------------------------------------------------

const FACTORY: readonly RegressionRow[] = [
  allow('factory confinement', 'real exported factory and const consumer', withFactory(`const server = createCockpitServer();\nserver.listen(1);`)),
  allow('factory confinement', 'const arrow factory', `${NS}\nconst make = () => http.createServer(${L});\nconst server = make();\nserver.listen(1);`),
  allow('factory confinement', 'const function-expression factory', `${NS}\nconst make = function () { return http.createServer(${L}); };\nmake().listen(1);`),
  allow('factory confinement', 'factory returning another factory', withFactory(`function outer() { return createCockpitServer(); }\nouter().listen(1);`)),
  allow('factory confinement', 'factory returning a rooted const alias', withServer(`function get() { return server; }\nget().close();`)),
  allow('factory confinement', 'multiple SERVER returns', `${NS}\nfunction make(x: boolean) { if (x) { return http.createServer(${L}); } return http.createServer(${L}); }\nmake(true).listen(1);`),
  allow('factory confinement', 'export default function factory', `${NS}\nexport default function make() { return http.createServer(${L}); }\nmake().listen(1);`),
  allow('factory confinement', 'factory exported by specifier', `${NS}\nfunction make() { return http.createServer(${L}); }\nexport { make };`),
  allow('factory confinement', 'factory referenced by typeof', `${NS}\nfunction make() { return http.createServer(${L}); }\nconst t = typeof make;\nt;`),
  allow('factory confinement', 'factory with parameters', `${NS}\nfunction make(port: number) { const s = http.createServer(${L}); s.listen(port); return s; }\nmake(1);`),
  deny('factory confinement', 'mixed SERVER/non-SERVER returns', `${NS}\nfunction make(x: boolean) { if (x) { return http.createServer(${L}); } return null; }\nmake(true);`, ['SERVER_UNCONFINED_RETURN'], {
    closes: ['F-6'],
  }),
  deny('factory confinement', 'IIFE factory', `${NS}\nconst server = (function () { return http.createServer(${L}); })();`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'class method factory', `${NS}\nclass Host { make() { return http.createServer(${L}); } }`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'object-held arrow factory', `${NS}\nconst host = { make: () => http.createServer(${L}) };`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'callback-returned server', `${NS}\n[1].map(() => http.createServer(${L}));`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory identity in array', `${NS}\nconst make = () => http.createServer(${L});\nconst fns = [make];`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory identity as argument', `${NS}\nfunction make() { return http.createServer(${L}); }\nuse(make);`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory identity aliased', `${NS}\nfunction make() { return http.createServer(${L}); }\nconst m = make;`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory identity stored on an object', `${NS}\nfunction make() { return http.createServer(${L}); }\nconst o = { make };`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory identity returned', `${NS}\nfunction make() { return http.createServer(${L}); }\nfunction pick() { return make; }`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory .call receiver', `${NS}\nfunction make() { return http.createServer(${L}); }\nmake.call(null);`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory .bind receiver', `${NS}\nfunction make() { return http.createServer(${L}); }\nconst b = make.bind(null);`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'async factory', `${NS}\nasync function make() { return http.createServer(${L}); }`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'generator factory', `${NS}\nfunction* make() { return http.createServer(${L}); }`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'let-bound arrow factory', `${NS}\nlet make = () => http.createServer(${L});`, ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory returning its parameter', withServer(`function id(s: http.Server) { return s; }\nid(server);`), ['SERVER_UNCONFINED_RETURN'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory returning a PARAM-derived alias', withServer(`function id(s: http.Server) { const t = s; return t; }\nid(server);`), ['SERVER_UNCONFINED_RETURN'], {
    closes: ['F-6'],
  }),
  deny('factory confinement', 'factory returning a let alias', `${NS}\nfunction make() { let s = http.createServer(${L}); return s; }`, ['SERVER_MUTABLE_BINDING'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory returning a wrapped conditional', `${NS}\nfunction make(x: boolean) { return (x ? http.createServer(${L}) : http.createServer(${L})); }`, ['SERVER_ESCAPE'], {
    closes: ['F-6'],
  }),
  deny('factory confinement', 'factory result non-allowed member', withFactory(`createCockpitServer().on('x', () => {});`), ['SERVER_MEMBER'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory result in container', withFactory(`const servers = [createCockpitServer()];`), ['SERVER_ESCAPE'], { closes: ['F-6'] }),
  deny('factory confinement', 'factory result exported', withFactory(`export const server = createCockpitServer();`), ['SERVER_EXPORT'], { closes: ['F-6', 'F-7'] }),
  deny('factory confinement', 'server-returning function with a this parameter', `${NS}\nfunction make(this: unknown) { return http.createServer(${L}); }`, ['SERVER_UNCONFINED_RETURN'], {
    closes: ['F-6'],
  }),
];

// ---------------------------------------------------------------------------
// 14. result confinement
// ---------------------------------------------------------------------------

const RESULT: readonly RegressionRow[] = [
  allow('result confinement', 'expression statement', `${NS}\nhttp.createServer(${L});`),
  allow('result confinement', 'void operand', `${NS}\nvoid http.createServer(${L});`),
  allow('result confinement', 'typeof operand', `${NS}\ntypeof http.createServer(${L});`),
  allow('result confinement', 'direct listen', `${NS}\nhttp.createServer(${L}).listen(1);`),
  allow('result confinement', 'direct close', `${NS}\nhttp.createServer(${L}).close();`),
  allow('result confinement', 'confined const initializer', `${NS}\nconst server = http.createServer(${L});`),
  allow('result confinement', 'confined factory return', `${NS}\nfunction make() { return http.createServer(${L}); }`),
  allow('result confinement', 'approved propagation', `${NS}\nfunction setup(s: http.Server) { s.listen(1); }\nsetup(http.createServer(${L}));`),
  deny('result confinement', 'let binding', `${NS}\nlet s = http.createServer(${L});`, ['SERVER_MUTABLE_BINDING']),
  deny('result confinement', 'var binding', `${NS}\nvar s = http.createServer(${L});`, ['SERVER_MUTABLE_BINDING']),
  deny('result confinement', 'array element', `${NS}\nconst a = [http.createServer(${L})];`, ['SERVER_ESCAPE']),
  deny('result confinement', 'object property', `${NS}\nconst o = { s: http.createServer(${L}) };`, ['SERVER_ESCAPE']),
  deny('result confinement', 'arbitrary call argument', `${NS}\nuse(http.createServer(${L}));`, ['SERVER_ESCAPE']),
  deny('result confinement', 'new argument', `${NS}\nclass Box { constructor(public v: unknown) {} }\nnew Box(http.createServer(${L}));`, ['SERVER_ESCAPE']),
  deny('result confinement', 'destructuring initializer', `${NS}\nconst { listen } = http.createServer(${L});`, ['SERVER_DESTRUCTURING']),
  deny('result confinement', 'assignment', `${NS}\nlet s;\ns = http.createServer(${L});`, ['SERVER_ESCAPE']),
  deny('result confinement', 'conditional', `${NS}\nconst s = Math.random() > 0.5 ? http.createServer(${L}) : null;`, ['SERVER_ESCAPE']),
  deny('result confinement', 'comma', `${NS}\nconst s = (0, http.createServer(${L}));`, ['SERVER_ESCAPE']),
  deny('result confinement', 'await', `${NS}\nconst s = await http.createServer(${L});`, ['SERVER_ESCAPE']),
  deny('result confinement', 'template span', `${NS}\nconst t = \`\${http.createServer(${L})}\`;`, ['SERVER_ESCAPE']),
  deny('result confinement', 'class field initializer', `${NS}\nclass Host { s = http.createServer(${L}); }`, ['SERVER_ESCAPE']),
  deny('result confinement', 'direct default export', `${NS}\nexport default http.createServer(${L});`, ['SERVER_EXPORT']),
  deny('result confinement', 'direct exported const', `${NS}\nexport const s = http.createServer(${L});`, ['SERVER_EXPORT']),
  deny('result confinement', 'non-allowed member on result', `${NS}\nhttp.createServer(${L}).on('x', () => {});`, ['SERVER_MEMBER']),
  deny('result confinement', 'member read without call on result', `${NS}\nconst l = http.createServer(${L}).listen;`, ['SERVER_MEMBER']),
  deny('result confinement', 'optional-chained member on result', `${NS}\nhttp.createServer(${L})?.listen(1);`, ['SERVER_MEMBER']),
  deny('result confinement', 'spread of result', `${NS}\nuse(...(http.createServer(${L}) as any));`, ['SERVER_ESCAPE']),
  deny('result confinement', 'result in a nullish expression', `${NS}\nconst s = http.createServer(${L}) ?? null;`, ['SERVER_ESCAPE']),
  deny('result confinement', 'result in an equality test', `${NS}\nif (http.createServer(${L}) === null) {}`, ['SERVER_ESCAPE']),
  deny('result confinement', 'result as heritage expression', `${NS}\nclass Sub extends (http.createServer(${L}) as any) {}`, ['SERVER_ESCAPE']),
];

// ---------------------------------------------------------------------------
// 15. export confinement
// ---------------------------------------------------------------------------

const EXPORT: readonly RegressionRow[] = [
  deny('export confinement', 'export { server }', withServer(`export { server };`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export { server as s }', withServer(`export { server as s };`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export { server as default }', withServer(`export { server as default };`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export default server', withServer(`export default server;`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export const server = createServer(...)', `${NS}\nexport const server = http.createServer(${L});`, ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export const server = factory()', withFactory(`export const server = createCockpitServer();`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export default factory()', withFactory(`export default createCockpitServer();`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export = server', withServer(`export = server;`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'export of a const alias of server', withServer(`const alias = server;\nexport { alias };`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  deny('export confinement', 'exported const alias of server', withServer(`export const alias = server;`), ['SERVER_EXPORT'], { closes: ['F-7'] }),
  allow('export confinement', 'export function factory', withFactory(``)),
  allow('export confinement', 'export { factory }', `${NS}\nfunction createCockpitServer() { return http.createServer(${L}); }\nexport { createCockpitServer };`),
  allow('export confinement', 'export default function factory', `${NS}\nexport default function createCockpitServer() { return http.createServer(${L}); }`),
  allow('export confinement', 'export default factory identifier', `${NS}\nfunction createCockpitServer() { return http.createServer(${L}); }\nexport default createCockpitServer;`),
  allow('export confinement', 'export of unrelated constants', withServer(`export const HOST = '127.0.0.1';\nexport const PORT = 4317;\nserver.listen(PORT, HOST);`)),
  allow('export confinement', 'export type of server type', withServer(`export type CockpitServer = typeof server;`)),
];

// ---------------------------------------------------------------------------
// 16. convergence/exhaustion
// ---------------------------------------------------------------------------

const FIXPOINT: readonly RegressionRow[] = [
  allow('convergence/exhaustion', 'reverse propagation chain converges under the default ceiling', reverseChain(6)),
  deny('convergence/exhaustion', 'reverse propagation chain exhausts a low ceiling', reverseChain(6), ['FIXPOINT_EXHAUSTED'], { options: { fixpointCeiling: 2 } }),
  deny('convergence/exhaustion', 'exhaustion denies even an otherwise-allowed real host shape', REAL_HOST_SHAPE, ['FIXPOINT_EXHAUSTED'], { options: { fixpointCeiling: 1 } }),
  allow('convergence/exhaustion', 'recursive alias/factory cycle converges', withServer(`function get() { return server; }\nfunction again() { return get(); }\nagain().close();\nget().listen(1);`)),
  allow('convergence/exhaustion', 'empty file converges', ``),
];

// ---------------------------------------------------------------------------
// 17. extra parameter false positives
// ---------------------------------------------------------------------------

const EXTRA_PARAMETERS: readonly RegressionRow[] = [
  allow('extra parameter false positives', 'listener third parameter is unprivileged', `${NS}\nhttp.createServer((request, response, extra: any) => { extra.socket.write('x'); response.end(); });`, {
    closes: ['F-1'],
  }),
  allow('extra parameter false positives', 'listener rest after index 1 is unprivileged', `${NS}\nhttp.createServer((request, response, ...rest: any[]) => { rest[0].socket; });`, { closes: ['F-1'] }),
  allow('extra parameter false positives', 'FunctionDeclaration listener third parameter', `${NS}\nfunction handle(request: http.IncomingMessage, response: http.ServerResponse, next: any) { next.socket; response.end(); }\nhttp.createServer(handle);`, {
    closes: ['F-1'],
  }),
  allow('extra parameter false positives', 'eligible callee parameter receiving a non-privileged argument', `${NS}\nfunction f(res: any) { res.socket; }\nhttp.createServer((request, response) => { f({}); response.end(); });`, {
    closes: ['F-1'],
  }),
  allow('extra parameter false positives', 'same-named parameter in an unrelated function', `${NS}\nhttp.createServer(${L});\nfunction other(request: any, response: any) { request.socket; response.socket; }`, {
    closes: ['F-1'],
  }),
  allow('extra parameter false positives', 'unusually named listener parameters', `${NS}\nhttp.createServer((a, b) => { a.url; b.end(); });`),
  deny('extra parameter false positives', 'unusually named listener parameters still privileged', `${NS}\nhttp.createServer((a, b) => { a.socket; });`, ['REQUEST_MEMBER'], { closes: ['F-1'] }),
  allow('extra parameter false positives', 'callee third parameter unprivileged even when first two are privileged', `${NS}\nfunction f(req: any, res: any, ctx: any) { ctx.socket; res.end(); }\nhttp.createServer((request, response) => { f(request, response, {}); });`, {
    closes: ['F-1'],
  }),
];

// ---------------------------------------------------------------------------
// 18. real host acceptance
// ---------------------------------------------------------------------------

const REAL_HOST: readonly RegressionRow[] = [
  allow('real host acceptance', 'inline replica of the Stage-A host', REAL_HOST_SHAPE),
  allow('real host acceptance', 'type positions on the namespace', `${NS}\nfunction f(request: http.IncomingMessage, response: http.ServerResponse): http.Server | null { request; response; return null; }`),
  allow('real host acceptance', 'request.method nullish fallback', inListener(`const method = request.method ?? '';\nif (method !== 'GET') { response.statusCode = 405; response.setHeader('Allow', 'GET'); response.end('405'); return; }`)),
  allow('real host acceptance', 'request.url passed to a pure helper', inListener(`function pathOf(url: string) { return url; }\nconst path = pathOf(request.url ?? '');\nresponse.end(path);`)),
  allow('real host acceptance', 'listen with host and port constants', withFactory(`const HOST = '127.0.0.1';\nconst PORT = 4317;\nfunction main() { const server = createCockpitServer(); server.listen(PORT, HOST, () => { console.log(HOST); }); }\nmain();`)),
];

// ---------------------------------------------------------------------------
// Outside the declared boundary (documented, terminate-only)
// ---------------------------------------------------------------------------

const OUTSIDE_BOUNDARY: readonly RegressionRow[] = [
  outside('factory confinement', 'cross-module consumption of a server factory', `import { createCockpitServer } from './server.js';\nconst s = createCockpitServer();\ns.on('x', () => {});`),
  outside('export confinement', 'module-graph re-export of another module value', `export { server as s } from './other.js';`),
  outside('mutation/reflection', 'prototype graph pollution', `(Object.prototype as any).fetch = () => {};`),
  outside('free-global identity', 'runtime code generation (RC territory)', `eval("fetch('x')");`),
  outside('node:http namespace/client capability', 'hidden builtin acquisition (HA territory)', `process.getBuiltinModule('http');`),
  outside('node:http namespace/client capability', 'CommonJS require of http', `const http = require('http');\nhttp.request('x');`),
];

export const D3_REGRESSION_MATRIX: readonly RegressionRow[] = [
  ...FREE_GLOBAL,
  ...HTTP_CAPABILITY,
  ...STATIC_KEYS,
  ...SHORTHAND,
  ...SOCKET,
  ...RUNTIME_KEYS,
  ...ALIAS,
  ...LOCAL_PROPAGATION,
  ...IMMUTABILITY,
  ...MUTATION,
  ...LISTENER_BOUNDARY,
  ...OPTIONS,
  ...FACTORY,
  ...RESULT,
  ...EXPORT,
  ...FIXPOINT,
  ...EXTRA_PARAMETERS,
  ...REAL_HOST,
  ...OUTSIDE_BOUNDARY,
];

/** The inline replica of the real host, exported for the fixpoint tests. */
export const REAL_HOST_REPLICA = REAL_HOST_SHAPE;

/** The reverse propagation chain builder, exported for the fixpoint tests. */
export const reversePropagationChain = reverseChain;
