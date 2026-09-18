import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  createRetirementGitHubClient,
  GITHUB_ENDPOINTS,
  GITHUB_HOST,
  GITHUB_LIMITS,
  GITHUB_PORT,
  type GitHubGet,
  type GitHubResponse,
} from '../../src/runtime/retirement-github-client.js';

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
