import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { EventEmitter } from 'node:events';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createHttpsGet,
  createRetirementGitHubClient,
  GITHUB_ENDPOINTS,
  GITHUB_HOST,
  GITHUB_LIMITS,
  GITHUB_PORT,
  type GitHubGet,
  type GitHubResponse,
} from '../../src/runtime/retirement-github-client.js';

/* ------------------------------------------------------------------------- *
 * Transport-seam doubles (Family A — HTTP bounded completion)
 *
 * `createHttpsGet` pins `api.github.com:443`, so the only way to drive it
 * deterministically is to replace `node:https` itself. No network, no TLS, and
 * no production seam added for the tests' benefit.
 * ------------------------------------------------------------------------- */

type FakeRequest = EventEmitter & {
  destroyed: boolean;
  end: () => void;
  destroy: () => void;
};

type FakeResponse = EventEmitter & {
  statusCode: number;
  headers: Record<string, string | undefined>;
  destroy: () => void;
};

interface PendingRequest {
  readonly options: { readonly timeout?: number };
  readonly handler: (response: FakeResponse) => void;
  readonly request: FakeRequest;
}

const transport = vi.hoisted(() => ({
  requests: [] as PendingRequest[],
  throwOnNextRequest: false,
}));

vi.mock('node:https', async () => {
  const { EventEmitter: Emitter } = await import('node:events');
  return {
    request: (options: unknown, handler: unknown): unknown => {
      if (transport.throwOnNextRequest) {
        transport.throwOnNextRequest = false;
        throw new Error('synchronous transport failure');
      }
      const request = new Emitter() as FakeRequest;
      request.destroyed = false;
      request.end = (): void => {};
      request.destroy = (): void => {
        request.destroyed = true;
        request.emit('close');
      };
      transport.requests.push({
        options: options as { readonly timeout?: number },
        handler: handler as (response: FakeResponse) => void,
        request,
      });
      return request;
    },
  };
});

function makeResponse(
  statusCode = 200,
  headers: Record<string, string | undefined> = {},
): FakeResponse {
  const response = new EventEmitter() as FakeResponse;
  response.statusCode = statusCode;
  response.headers = headers;
  // Node emits `aborted` then `close` on a destroyed response — never `end`,
  // never `error`. That asymmetry is the whole of finding A1.
  response.destroy = (): void => {
    response.emit('aborted');
    response.emit('close');
  };
  return response;
}

function pending(): PendingRequest {
  const entry = transport.requests[0];
  if (entry === undefined) {
    throw new Error('no request was issued');
  }
  return entry;
}

const CANDIDATE_REF = 'refs/heads/repair/example';
const CANDIDATE_SHA = 'a'.repeat(40);

/** A fake GitHub server: a path -> response table, with every path recorded. */
function fakeServer(
  table: Readonly<Record<string, Partial<GitHubResponse>>>,
  fallback: Partial<GitHubResponse> = { statusCode: 404, body: '{}' },
): { readonly get: GitHubGet; readonly paths: string[] } {
  const paths: string[] = [];
  const get: GitHubGet = (path: string): Promise<GitHubResponse | null> => {
    paths.push(path);
    const entry = table[path] ?? fallback;
    return Promise.resolve({
      statusCode: entry.statusCode ?? 200,
      body: entry.body ?? '[]',
      linkHeader: entry.linkHeader ?? null,
      truncated: entry.truncated ?? false,
    });
  };
  return { get, paths };
}

const PULLS_PATH = '/repos/LogicDuke/agentbridge/pulls?state=open&per_page=100';
const ISSUES_PATH = '/repos/LogicDuke/agentbridge/issues?state=open&per_page=100';
const REPO_PATH = '/repos/LogicDuke/agentbridge';
const BRANCH_PATH = '/repos/LogicDuke/agentbridge/branches/repair%2Fexample';

function client(server: { readonly get: GitHubGet }): ReturnType<typeof createRetirementGitHubClient> {
  return createRetirementGitHubClient({ owner: 'LogicDuke', repo: 'agentbridge', get: server.get });
}

describe('GET-only by construction', () => {
  const source = readFileSync(
    fileURLToPath(new URL('../../src/runtime/retirement-github-client.ts', import.meta.url)),
    'utf8',
  );

  /**
   * The module's **code**, with comments stripped.
   *
   * The doc comments necessarily discuss the things this module refuses to do
   * ("no `Authorization` header", "no method parameter"), so scanning the raw
   * file would find the very words whose absence is the point. These assertions
   * are about what the module can *execute*.
   */
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '');

  it('names no HTTP verb but GET', () => {
    for (const verb of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
      expect(code, `verb reachable: ${verb}`).not.toContain(`'${verb}'`);
    }
    expect(code).toContain("method: 'GET'");
  });

  it('sets no Authorization header and reads no credential', () => {
    expect(code).not.toContain('Authorization');
    expect(code).not.toContain('GITHUB_TOKEN');
    expect(code).not.toContain('Bearer');
    expect(code).not.toContain('process.env');
  });

  it('writes no request body', () => {
    // `end()` with no argument is the only way the request is completed.
    expect(code).not.toMatch(/\.write\(/);
    expect(code).toContain('clientRequest.end();');
  });

  it('pins the host and port, and exposes no configuration point that widens them', () => {
    expect(GITHUB_HOST).toBe('api.github.com');
    expect(GITHUB_PORT).toBe(443);
    expect(code).not.toContain('http://');
  });

  it('declares exactly four endpoint templates', () => {
    expect(Object.keys(GITHUB_ENDPOINTS)).toHaveLength(4);
    for (const template of Object.values(GITHUB_ENDPOINTS)) {
      expect(template.startsWith('/repos/{owner}/{repo}')).toBe(true);
    }
  });

  it('pins the bounds Decision 065 fixes', () => {
    expect({ ...GITHUB_LIMITS }).toEqual({
      MAX_REQUESTS_PER_RUN: 20,
      TIMEOUT_MS: 15_000,
      MAX_RESPONSE_BYTES: 2 * 1024 * 1024,
      PER_PAGE: 100,
      MAX_PAGES: 5,
    });
  });

  it('exposes only the four named queries and the budget counter', () => {
    const instance = client(fakeServer({}));
    expect(Object.keys(instance).sort()).toEqual([
      'branch',
      'openIssues',
      'openPullRequests',
      'repository',
      'requestCount',
    ]);
    expect(Object.isFrozen(instance)).toBe(true);
  });
});

describe('request paths come from the template table, never from a caller', () => {
  it('builds each path from owner/repo and the fixed template', async () => {
    const server = fakeServer({
      [REPO_PATH]: { body: JSON.stringify({ default_branch: 'main' }) },
      [PULLS_PATH]: { body: '[]' },
      [ISSUES_PATH]: { body: '[]' },
      [BRANCH_PATH]: { statusCode: 404, body: '{}' },
    });
    const instance = client(server);
    await instance.repository();
    await instance.openPullRequests();
    await instance.openIssues();
    await instance.branch(CANDIDATE_REF);
    expect(server.paths).toEqual([REPO_PATH, PULLS_PATH, ISSUES_PATH, BRANCH_PATH]);
  });

  it('percent-encodes the branch segment rather than letting it shape the path', async () => {
    const server = fakeServer({});
    await client(server).branch('refs/heads/a/b');
    expect(server.paths[0]).toBe('/repos/LogicDuke/agentbridge/branches/a%2Fb');
  });

  it('refuses a non-canonical ref without issuing a request', async () => {
    const server = fakeServer({});
    const fact = await client(server).branch('../../etc/passwd');
    expect(fact.determinate).toBe(false);
    expect(server.paths).toEqual([]);
  });
});

describe('reading responses', () => {
  it('reads the default branch', async () => {
    const server = fakeServer({ [REPO_PATH]: { body: JSON.stringify({ default_branch: 'main' }) } });
    const fact = await client(server).repository();
    expect(fact.determinate ? fact.value : null).toEqual({ defaultBranch: 'main' });
  });

  it('reads open pull requests down to their head and base refs', async () => {
    const server = fakeServer({
      [PULLS_PATH]: {
        body: JSON.stringify([{ number: 7, head: { ref: 'repair/example' }, base: { ref: 'main' } }]),
      },
    });
    const fact = await client(server).openPullRequests();
    expect(fact.determinate ? fact.value : null).toEqual([
      { number: 7, headRef: 'repair/example', baseRef: 'main' },
    ]);
  });

  it('treats a null issue body as empty text, not as malformed', async () => {
    const server = fakeServer({
      [ISSUES_PATH]: { body: JSON.stringify([{ number: 3, title: 't', body: null }]) },
    });
    const fact = await client(server).openIssues();
    expect(fact.determinate ? fact.value : null).toEqual([{ number: 3, title: 't', body: '' }]);
  });

  it('models a 404 branch as determinate absence', async () => {
    const server = fakeServer({ [BRANCH_PATH]: { statusCode: 404, body: '{}' } });
    const fact = await client(server).branch(CANDIDATE_REF);
    expect(fact).toEqual({ determinate: true, value: null });
  });

  it('reads a 200 branch including its protection flag', async () => {
    const server = fakeServer({
      [BRANCH_PATH]: {
        body: JSON.stringify({
          name: 'repair/example',
          commit: { sha: CANDIDATE_SHA },
          protected: true,
        }),
      },
    });
    const fact = await client(server).branch(CANDIDATE_REF);
    expect(fact.determinate ? fact.value : null).toEqual({
      name: 'repair/example',
      commitSha: CANDIDATE_SHA,
      protected: true,
    });
  });
});

describe('every failure is indeterminate — never "GitHub is clear"', () => {
  it('a non-200, non-404 status', async () => {
    for (const statusCode of [403, 429, 500, 502]) {
      const server = fakeServer({ [PULLS_PATH]: { statusCode, body: '[]' } });
      expect((await client(server).openPullRequests()).determinate, String(statusCode)).toBe(false);
    }
  });

  it('a rate-limited branch read', async () => {
    const server = fakeServer({ [BRANCH_PATH]: { statusCode: 403, body: '{}' } });
    expect((await client(server).branch(CANDIDATE_REF)).determinate).toBe(false);
  });

  it('a truncated body', async () => {
    const server = fakeServer({ [PULLS_PATH]: { body: '[]', truncated: true } });
    expect((await client(server).openPullRequests()).determinate).toBe(false);
  });

  it('a malformed body', async () => {
    const server = fakeServer({ [PULLS_PATH]: { body: 'not json' } });
    expect((await client(server).openPullRequests()).determinate).toBe(false);

    const wrongShape = fakeServer({ [PULLS_PATH]: { body: JSON.stringify([{ number: 'x' }]) } });
    expect((await client(wrongShape).openPullRequests()).determinate).toBe(false);
  });

  it('a transport-level failure (null response)', async () => {
    const instance = createRetirementGitHubClient({
      owner: 'LogicDuke',
      repo: 'agentbridge',
      get: (): Promise<null> => Promise.resolve(null),
    });
    expect((await instance.openPullRequests()).determinate).toBe(false);
  });

  it('a throwing transport is contained, never propagated', async () => {
    const instance = createRetirementGitHubClient({
      owner: 'LogicDuke',
      repo: 'agentbridge',
      get: (): Promise<never> => Promise.reject(new Error('boom')),
    });
    await expect(instance.openPullRequests()).resolves.toEqual({ determinate: false });
  });
});

describe('pagination', () => {
  it('follows rel="next" across pages and concatenates in order', async () => {
    const page2 = PULLS_PATH + '&page=2';
    const server = fakeServer({
      [PULLS_PATH]: {
        body: JSON.stringify([{ number: 1, head: { ref: 'a' }, base: { ref: 'main' } }]),
        linkHeader: `<https://api.github.com${page2}>; rel="next"`,
      },
      [page2]: {
        body: JSON.stringify([{ number: 2, head: { ref: 'b' }, base: { ref: 'main' } }]),
      },
    });
    const fact = await client(server).openPullRequests();
    const items = fact.determinate ? fact.value : [];
    expect(items.map((item) => item.number)).toEqual([1, 2]);
  });

  it('refuses a next link that points off the pinned host', async () => {
    const server = fakeServer({
      [PULLS_PATH]: {
        body: '[]',
        linkHeader: '<https://evil.example.com/steal>; rel="next"',
      },
    });
    const fact = await client(server).openPullRequests();
    expect(fact.determinate).toBe(false);
    // The off-host URL was never requested.
    expect(server.paths).toEqual([PULLS_PATH]);
  });

  it('is indeterminate when a next link still remains after the page bound', async () => {
    // Every page advertises another: pagination never terminates.
    const server = {
      get: (path: string): Promise<GitHubResponse> =>
        Promise.resolve({
          statusCode: 200,
          body: '[]',
          linkHeader: `<https://api.github.com${path}x>; rel="next"`,
          truncated: false,
        }),
    };
    const fact = await client(server).openPullRequests();
    expect(fact.determinate).toBe(false);
  });
});

describe('the request budget', () => {
  it('counts every request and refuses past the per-run bound', async () => {
    const server = fakeServer({ [REPO_PATH]: { body: JSON.stringify({ default_branch: 'main' }) } });
    const instance = client(server);
    for (let index = 0; index < GITHUB_LIMITS.MAX_REQUESTS_PER_RUN; index += 1) {
      await instance.repository();
    }
    expect(instance.requestCount()).toBe(GITHUB_LIMITS.MAX_REQUESTS_PER_RUN);

    // The next one is refused without reaching the transport, and is indeterminate.
    const pathsBefore = server.paths.length;
    expect((await instance.repository()).determinate).toBe(false);
    expect(server.paths.length).toBe(pathsBefore);
  });
});

/* ------------------------------------------------------------------------- *
 * Family A — HTTP bounded completion (DDR-A-HTTP-BOUNDED-COMPLETION)
 * ------------------------------------------------------------------------- */

describe('the transport seam settles exactly once, and always within the deadline', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    transport.requests.length = 0;
    transport.throwOnNextRequest = false;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('T1 — a normal small response settles once with the response', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse(200, { link: undefined });
    handler(response);
    response.emit('data', Buffer.from('{"ok":1}'));
    response.emit('end');

    expect(await promise).toEqual({
      statusCode: 200,
      body: '{"ok":1}',
      linkHeader: null,
      truncated: false,
    });
  });

  it('T2 — a response past MAX_RESPONSE_BYTES settles once with null', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse();
    handler(response);
    // One chunk over the bound. Before the repair this destroyed the response
    // without settling, and the promise hung for the life of the process.
    response.emit('data', Buffer.alloc(GITHUB_LIMITS.MAX_RESPONSE_BYTES + 1));

    expect(await promise).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T3 — oversize followed by close/aborted does not settle a second time', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse();
    handler(response);
    response.emit('data', Buffer.alloc(GITHUB_LIMITS.MAX_RESPONSE_BYTES + 1));
    const first = await promise;

    // Everything Node would still deliver after the teardown.
    response.emit('aborted');
    response.emit('close');
    response.emit('end');
    response.emit('error', new Error('late'));

    expect(await promise).toBe(first);
    expect(first).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T4 — traffic cannot extend the deadline: a slow drip still fails closed', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse();
    handler(response);

    // A byte at a time, never idling long enough to trip an inactivity timer.
    const step = GITHUB_LIMITS.TIMEOUT_MS / 4;
    for (let tick = 0; tick < 4; tick += 1) {
      response.emit('data', Buffer.from('a'));
      await vi.advanceTimersByTimeAsync(step);
    }

    expect(await promise).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T5 — inactivity settles null within the declared bound', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    handler(makeResponse());

    await vi.advanceTimersByTimeAsync(GITHUB_LIMITS.TIMEOUT_MS);

    expect(await promise).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T6 — a request error before any response settles once with null', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    pending().request.emit('error', new Error('ECONNREFUSED'));

    expect(await promise).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T7 — a response error settles once with null', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse();
    handler(response);
    response.emit('data', Buffer.from('{"partial"'));
    response.emit('error', new Error('ECONNRESET'));

    // The partial body is discarded rather than returned as determinate data.
    expect(await promise).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T8 — an aborted response settles once with null', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse();
    handler(response);
    // Node's observed order for a peer-side abort.
    response.emit('aborted');
    response.emit('error', new Error('ECONNRESET'));

    expect(await promise).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T9 — a timeout followed by a late error absorbs the second settlement', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { request } = pending();
    // Node really does emit both, in this order, on the inactivity path.
    request.emit('timeout');
    const first = await promise;
    request.emit('error', new Error('ECONNRESET'));

    expect(first).toBeNull();
    expect(await promise).toBe(first);
    expect(request.destroyed).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T10 — normal completion clears the absolute timer', async () => {
    const promise = createHttpsGet()('/repos/o/r');
    const { handler } = pending();
    const response = makeResponse(200, { link: undefined });
    handler(response);

    expect(vi.getTimerCount()).toBe(1);
    response.emit('end');
    await promise;

    expect(vi.getTimerCount()).toBe(0);
  });

  it('T11 — a synchronous transport throw stays fail-closed', async () => {
    transport.throwOnNextRequest = true;
    const promise = createHttpsGet()('/repos/o/r');

    expect(await promise).toBeNull();
    expect(transport.requests).toHaveLength(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('arms the deadline from the adopted bound, and keeps the inactivity option', () => {
    void createHttpsGet()('/repos/o/r');
    expect(pending().options.timeout).toBe(GITHUB_LIMITS.TIMEOUT_MS);
    expect(vi.getTimerCount()).toBe(1);
  });
});

/* ------------------------------------------------------------------------- *
 * Family B — pagination anomaly indeterminacy
 * ------------------------------------------------------------------------- */

describe('a malformed next relation is an anomaly, not the end of the pages', () => {
  const FIRST_PAGE = JSON.stringify([
    { number: 1, head: { ref: 'unrelated' }, base: { ref: 'main' } },
  ]);

  it('no rel="next" at all ends pagination successfully', async () => {
    const server = fakeServer({ [PULLS_PATH]: { body: FIRST_PAGE, linkHeader: null } });
    const fact = await client(server).openPullRequests();
    expect(fact.determinate).toBe(true);
    expect(server.paths).toEqual([PULLS_PATH]);
  });

  it('a well-formed rel="next" still fetches the next page', async () => {
    const page2 = PULLS_PATH + '&page=2';
    const server = fakeServer({
      [PULLS_PATH]: {
        body: FIRST_PAGE,
        linkHeader: '<https://api.github.com' + page2 + '>; rel="next"',
      },
      [page2]: {
        body: JSON.stringify([{ number: 2, head: { ref: 'b' }, base: { ref: 'main' } }]),
      },
    });
    const fact = await client(server).openPullRequests();
    expect(fact.determinate).toBe(true);
    expect(server.paths).toEqual([PULLS_PATH, page2]);
  });

  const malformed: readonly (readonly [string, string])[] = [
    ['unclosed brackets', '<; rel="next"'],
    ['an empty target', '<>; rel="next"'],
    ['no brackets at all', 'https://api.github.com/x?page=2; rel="next"'],
    ['a reversed pair', '>https://api.github.com/x<; rel="next"'],
  ];

  for (const [label, linkHeader] of malformed) {
    it('is indeterminate when the next relation has ' + label, async () => {
      const server = fakeServer({ [PULLS_PATH]: { body: FIRST_PAGE, linkHeader } });
      const fact = await client(server).openPullRequests();
      expect(fact.determinate).toBe(false);
      // Nothing beyond the first page was requested, and nothing was reported.
      expect(server.paths).toEqual([PULLS_PATH]);
    });
  }

  it('a dependency on the omitted page cannot let F8 read as clear', async () => {
    // Page 2 carries the pull request that would block retirement; the next
    // relation pointing at it is unreadable. Reporting page 1 as the whole set
    // would clear F8 on evidence that was never gathered.
    const page2 = PULLS_PATH + '&page=2';
    const server = fakeServer({
      [PULLS_PATH]: { body: FIRST_PAGE, linkHeader: '<>; rel="next"' },
      [page2]: {
        body: JSON.stringify([
          { number: 2, head: { ref: 'repair/example' }, base: { ref: 'main' } },
        ]),
      },
    });
    const fact = await client(server).openPullRequests();

    expect(fact.determinate).toBe(false);
    expect(server.paths).not.toContain(page2);
  });

  it('malformed issue pagination is indeterminate on the same rule', async () => {
    const server = fakeServer({
      [ISSUES_PATH]: { body: '[]', linkHeader: '<>; rel="next"' },
    });
    expect((await client(server).openIssues()).determinate).toBe(false);
  });
});
