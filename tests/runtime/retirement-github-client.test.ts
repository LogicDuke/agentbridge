import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import * as clientModule from '../../src/runtime/retirement-github-client.js';
import {
  createRetirementGitHubClient,
  GITHUB_LIMITS,
  type GitHubIndeterminateCause,
  type GitHubObservation,
  type RetirementGitHubClient,
} from '../../src/runtime/retirement-github-client.js';

/* ------------------------------------------------------------------------- *
 * node:https seam — test file only (DDR-SLICE3-TIER3 Rev 1 §18)
 *
 * `request` is replaced by a scripted fake; `Agent` stays real (constructing
 * one opens nothing). Each production request consumes the next queued handler,
 * which drives a fake ClientRequest / IncomingMessage pair by hand. The
 * production module has no seam of its own.
 * ------------------------------------------------------------------------- */

type ResponseCallback = (response: FakeResponse) => void;

interface Call {
  readonly options: Record<string, unknown>;
  readonly request: FakeRequest;
  /** Emit `response` for this call and return it. */
  respond(statusCode: number, headers?: Record<string, string>): FakeResponse;
}

type Handler = (call: Call) => void;

const httpsSeam = vi.hoisted(() => ({
  handle: null as ((options: unknown, callback: unknown) => unknown) | null,
}));

vi.mock('node:https', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:https')>();
  return {
    ...actual,
    request: (options: unknown, callback: unknown): unknown => {
      if (httpsSeam.handle === null) {
        throw new Error('unexpected network request in test');
      }
      return httpsSeam.handle(options, callback);
    },
  };
});

const { Agent: RealAgent } = await vi.importActual<typeof import('node:https')>('node:https');

class FakeRequest extends EventEmitter {
  ended = false;
  writes = 0;
  destroyed = false;

  end(): this {
    this.ended = true;
    return this;
  }

  write(): boolean {
    this.writes += 1;
    return true;
  }

  /** Like a real ClientRequest destroyed before completion: a late `error`, then `close`. */
  destroy(): this {
    if (!this.destroyed) {
      this.destroyed = true;
      queueMicrotask(() => {
        this.emit('error', new Error('socket hang up SECRET-ERROR-TEXT'));
        this.emit('close');
      });
    }
    return this;
  }
}

class FakeResponse extends EventEmitter {
  destroyed = false;

  constructor(
    readonly statusCode: number,
    readonly headers: Record<string, string>,
  ) {
    super();
  }

  destroy(): this {
    if (!this.destroyed) {
      this.destroyed = true;
      queueMicrotask(() => this.emit('close'));
    }
    return this;
  }
}

let calls: Call[] = [];
let handlers: Handler[] = [];
let unscripted = 0;

function install(): void {
  httpsSeam.handle = (options, callback) => {
    const request = new FakeRequest();
    const call: Call = {
      options: options as Record<string, unknown>,
      request,
      respond(statusCode, headers = {}) {
        const response = new FakeResponse(statusCode, headers);
        (callback as ResponseCallback)(response);
        return response;
      },
    };
    calls.push(call);
    const handler = handlers.shift();
    if (handler === undefined) {
      // Recorded as well as thrown: the production latch would otherwise turn
      // the throw into an ordinary TRANSPORT_ERROR and mask the extra request.
      unscripted += 1;
      throw new Error('no scripted handler for request ' + String(calls.length));
    }
    handler(call);
    return request;
  };
}

/** Queue handlers for the next requests, in order. */
function script(...next: Handler[]): void {
  handlers.push(...next);
}

/** Next microtask: status + headers, the body in the given chunks, then end and close. */
function reply(statusCode: number, body: string | Buffer | readonly Buffer[], headers: Record<string, string> = {}): Handler {
  return (call) => {
    queueMicrotask(() => {
      const response = call.respond(statusCode, headers);
      const chunks = typeof body === 'string' ? [Buffer.from(body)] : Buffer.isBuffer(body) ? [body] : body;
      for (const chunk of chunks) {
        if (chunk.length > 0) {
          response.emit('data', chunk);
        }
      }
      response.emit('end');
      response.emit('close');
    });
  };
}

function json(value: unknown, headers: Record<string, string> = {}): Handler {
  return reply(200, JSON.stringify(value), headers);
}

/** A handler that does nothing: the test drives the call by hand. */
const manual: Handler = () => undefined;

beforeEach(() => {
  calls = [];
  handlers = [];
  unscripted = 0;
  install();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  httpsSeam.handle = null;
  expect(handlers).toEqual([]);
  expect(unscripted).toBe(0);
});

/* ------------------------------------------------------------------------- *
 * Fixtures
 * ------------------------------------------------------------------------- */

const OWNER = 'LogicDuke';
const REPO = 'agentbridge';
const REPO_PATH = '/repos/LogicDuke/agentbridge';
const REPOSITORY_ID = 1_300_192;
const SHA = 'a'.repeat(40);
const LIMIT = GITHUB_LIMITS.MAX_RESPONSE_BYTES;

const REPOSITORY_BODY = { id: REPOSITORY_ID, full_name: 'LogicDuke/agentbridge', default_branch: 'main', private: false };
const BRANCH_BODY = { name: 'feature/x', commit: { sha: SHA, url: 'ignored' }, protected: false };

function pull(number: number): Record<string, unknown> {
  return {
    number,
    head: { ref: 'feature/' + String(number), repo: { full_name: 'LogicDuke/agentbridge' } },
    base: { ref: 'main' },
    title: 'ignored',
  };
}

function issue(number: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { number, title: 'Issue ' + String(number), body: 'text', ...extra };
}

function listingUrl(listing: 'pulls' | 'issues', page: number, base = 'https://api.github.com/repos/LogicDuke/agentbridge'): string {
  return `${base}/${listing}?state=open&per_page=100&page=${String(page)}`;
}

function nextLink(uri: string): Record<string, string> {
  return { link: `<${uri}>; rel="next", <https://api.github.com/repos/LogicDuke/agentbridge/pulls?state=open&per_page=100&page=5>; rel="last"` };
}

function newClient(): RetirementGitHubClient {
  const client = createRetirementGitHubClient({ owner: OWNER, repo: REPO });
  if (client === null) {
    throw new Error('fixture client must build');
  }
  return client;
}

function expectIndeterminate(
  observation: GitHubObservation<unknown>,
  cause: GitHubIndeterminateCause,
  httpStatus: number | null = null,
): void {
  expect(observation).toEqual({ kind: 'INDETERMINATE', cause, httpStatus });
  expect(Object.isFrozen(observation)).toBe(true);
}

/** Track whether a promise has settled yet, without awaiting it. */
function track<T>(promise: Promise<T>): { settled: () => boolean; promise: Promise<T> } {
  let done = false;
  void promise.then(() => {
    done = true;
  });
  return { settled: () => done, promise };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 5; index += 1) {
    await Promise.resolve();
  }
}

const EXPECTED_HEADERS = {
  Accept: 'application/vnd.github+json',
  'User-Agent': 'agentbridge-job1',
  'X-GitHub-Api-Version': '2022-11-28',
  'Accept-Encoding': 'identity',
  Connection: 'close',
};

/* ------------------------------------------------------------------------- *
 * T1–T2, T22–T23 — success and pagination
 * ------------------------------------------------------------------------- */

describe('success and pagination', () => {
  it('T1 one-page success: REPOSITORY is determinate, frozen, primitive-only', async () => {
    script(json(REPOSITORY_BODY));
    const observation = await newClient().readRepository();
    expect(observation).toEqual({ kind: 'DETERMINATE', value: { defaultBranch: 'main' } });
    expect(Object.isFrozen(observation)).toBe(true);
    if (observation.kind === 'DETERMINATE') {
      expect(Object.isFrozen(observation.value)).toBe(true);
    }
    expect(calls.map((call) => call.options.path)).toEqual([REPO_PATH]);
  });

  it('T1 BRANCH 200 is determinate present with sha and protected', async () => {
    script(json(BRANCH_BODY));
    const observation = await newClient().readBranch('refs/heads/feature/x');
    expect(observation).toEqual({ kind: 'DETERMINATE', value: { present: true, sha: SHA, protected: false } });
    expect(calls.map((call) => call.options.path)).toEqual([REPO_PATH + '/branches/feature/x']);
  });

  it('T2 paginated success follows page n+1 and freezes the listing and its records', async () => {
    script(
      json([pull(1), pull(2)], nextLink(listingUrl('pulls', 2))),
      json([pull(3)], nextLink(listingUrl('pulls', 3))),
      json([pull(4)]),
    );
    const observation = await newClient().listOpenPullRequests();
    expect(calls.map((call) => call.options.path)).toEqual([
      REPO_PATH + '/pulls?state=open&per_page=100&page=1',
      REPO_PATH + '/pulls?state=open&per_page=100&page=2',
      REPO_PATH + '/pulls?state=open&per_page=100&page=3',
    ]);
    expect(observation.kind).toBe('DETERMINATE');
    if (observation.kind === 'DETERMINATE') {
      expect(observation.value.map((record) => record.number)).toEqual([1, 2, 3, 4]);
      expect(observation.value[0]).toEqual({
        number: 1,
        headRef: 'feature/1',
        headRepoFullName: 'LogicDuke/agentbridge',
        baseRef: 'main',
      });
      expect(Object.isFrozen(observation.value)).toBe(true);
      expect(observation.value.every((record) => Object.isFrozen(record))).toBe(true);
    }
  });

  it('T2 issues listing returns pull-request-backed records unfiltered (CD-5)', async () => {
    script(json([issue(1), issue(2, { pull_request: { url: 'x' } }), issue(3, { body: null, pull_request: null })]));
    const observation = await newClient().listOpenIssues();
    expect(observation).toEqual({
      kind: 'DETERMINATE',
      value: [
        { number: 1, title: 'Issue 1', body: 'text', isPullRequest: false },
        { number: 2, title: 'Issue 2', body: 'text', isPullRequest: true },
        { number: 3, title: 'Issue 3', body: null, isPullRequest: false },
      ],
    });
  });

  it('T2 a pull request whose head repository was deleted reports null', async () => {
    script(json([{ number: 7, head: { ref: 'gone', repo: null }, base: { ref: 'main' } }]));
    const observation = await newClient().listOpenPullRequests();
    expect(observation).toEqual({
      kind: 'DETERMINATE',
      value: [{ number: 7, headRef: 'gone', headRepoFullName: null, baseRef: 'main' }],
    });
  });

  it('T22 no Link header is a clean terminal page', async () => {
    script(json([issue(1)]));
    const observation = await newClient().listOpenIssues();
    expect(observation.kind).toBe('DETERMINATE');
    expect(calls).toHaveLength(1);
  });

  it('T22 a well-formed Link without rel=next is a clean terminal page', async () => {
    script(json([issue(1)], { link: `<${listingUrl('issues', 1)}>; rel="first", <${listingUrl('issues', 1)}>; rel="prev"` }));
    expect((await newClient().listOpenIssues()).kind).toBe('DETERMINATE');
  });

  it('T23 a valid rel=next is evidence only: the client requests its own template path', async () => {
    // Owner/repo case differs in the evidence; the request uses the configured names.
    script(
      json([pull(1)], nextLink(listingUrl('pulls', 2, 'https://api.github.com/repos/logicduke/AgentBridge'))),
      json([pull(2)]),
    );
    const observation = await newClient().listOpenPullRequests();
    expect(observation.kind).toBe('DETERMINATE');
    expect(calls[1]?.options.path).toBe(REPO_PATH + '/pulls?state=open&per_page=100&page=2');
    expect(calls[1]?.options.hostname).toBe('api.github.com');
  });

  it('T23 relation types compare case-insensitively, so rel="Next" is never read as the end', async () => {
    script(json([pull(1)], { link: `<${listingUrl('pulls', 2)}>; rel="Next"` }), json([pull(2)]));
    const observation = await newClient().listOpenPullRequests();
    expect(calls).toHaveLength(2);
    expect(observation.kind).toBe('DETERMINATE');
  });
});

/* ------------------------------------------------------------------------- *
 * T3–T7, T15, T35 — byte bound and encoding (PRRT_kwDOTzqfcs6jv8em)
 * ------------------------------------------------------------------------- */

/** A valid JSON `[]` padded with whitespace to exactly `size` bytes, in 64 KiB chunks. */
function paddedEmptyArray(size: number): Buffer[] {
  const whole = Buffer.alloc(size, 0x20);
  whole.write('[]', 0);
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < size; offset += 65_536) {
    chunks.push(whole.subarray(offset, Math.min(size, offset + 65_536)));
  }
  return chunks;
}

describe('byte bound and encoding', () => {
  it('T3 exactly 2,097,152 body bytes are accepted', async () => {
    script(reply(200, paddedEmptyArray(LIMIT)));
    expect(await newClient().listOpenIssues()).toEqual({ kind: 'DETERMINATE', value: [] });
  });

  it('T3 exactly the limit with an honest Content-Length is accepted', async () => {
    script(reply(200, paddedEmptyArray(LIMIT), { 'content-length': String(LIMIT) }));
    expect((await newClient().listOpenIssues()).kind).toBe('DETERMINATE');
  });

  it('T4 byte 2,097,153 settles TOO_LARGE at the crossing chunk, with no later event emitted', async () => {
    let response: FakeResponse | null = null;
    let request: FakeRequest | null = null;
    script((call) => {
      request = call.request;
      queueMicrotask(() => {
        response = call.respond(200);
        for (const chunk of paddedEmptyArray(LIMIT + 1)) {
          response.emit('data', chunk);
        }
        // Deliberately no end, no error, no close.
      });
    });
    const pending = track(newClient().listOpenIssues());
    await flush();
    expect(pending.settled()).toBe(true);
    expectIndeterminate(await pending.promise, 'TOO_LARGE');
    expect((response as FakeResponse | null)?.destroyed).toBe(true);
    expect((request as FakeRequest | null)?.destroyed).toBe(true);
  });

  it('T5 a declared Content-Length over the limit fails before any body is read', async () => {
    let response: FakeResponse | null = null;
    script((call) => {
      queueMicrotask(() => {
        response = call.respond(200, { 'content-length': String(LIMIT + 1) });
      });
    });
    expectIndeterminate(await newClient().listOpenIssues(), 'TOO_LARGE');
    expect((response as FakeResponse | null)?.listenerCount('data')).toBe(0);
  });

  it('T6 without Content-Length a single oversized chunk is still refused', async () => {
    script(reply(200, Buffer.alloc(LIMIT + 1, 0x20)));
    expectIndeterminate(await newClient().listOpenIssues(), 'TOO_LARGE');
  });

  it('T7 a dishonest small Content-Length cannot bypass the streamed bound', async () => {
    script(reply(200, paddedEmptyArray(LIMIT + 1), { 'content-length': '10' }));
    expectIndeterminate(await newClient().listOpenIssues(), 'TOO_LARGE');
  });

  it('T7 a body that disagrees with Content-Length is INCOMPLETE, never success', async () => {
    script(reply(200, '[]          ', { 'content-length': '2' }), reply(200, '[]', { 'content-length': '9' }));
    const client = newClient();
    expectIndeterminate(await client.listOpenIssues(), 'INCOMPLETE');
    expectIndeterminate(await client.listOpenIssues(), 'INCOMPLETE');
  });

  it('T7 a malformed Content-Length is MALFORMED_BODY', async () => {
    script(reply(200, '[]', { 'content-length': '2, 2' }), reply(200, '[]', { 'content-length': '-1' }));
    const client = newClient();
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_BODY');
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_BODY');
  });

  it('T15 overrun racing end/close/error in one tick settles exactly once as TOO_LARGE', async () => {
    script((call) => {
      queueMicrotask(() => {
        const response = call.respond(200);
        response.emit('data', Buffer.alloc(LIMIT + 1, 0x20));
        response.emit('end');
        response.emit('close');
        response.emit('error', new Error('late'));
        call.request.emit('error', new Error('late'));
      });
    });
    const pending = newClient().listOpenIssues();
    const first = await pending;
    expectIndeterminate(first, 'TOO_LARGE');
    expect(await pending).toBe(first);
  });

  it('T35 any non-identity Content-Encoding is ENCODING; identity is accepted', async () => {
    script(
      reply(200, '[]', { 'content-encoding': 'gzip' }),
      reply(200, '[]', { 'content-encoding': 'deflate' }),
      reply(200, '[]', { 'content-encoding': 'br' }),
      reply(200, '[]', { 'content-encoding': 'identity, gzip' }),
      reply(200, '[]', { 'content-encoding': 'Identity' }),
    );
    const client = newClient();
    for (let index = 0; index < 4; index += 1) {
      expectIndeterminate(await client.listOpenIssues(), 'ENCODING');
    }
    expect((await client.listOpenIssues()).kind).toBe('DETERMINATE');
  });
});

/* ------------------------------------------------------------------------- *
 * T8–T14, T42, T43 — total completion and the absolute deadline
 * (PRRT_kwDOTzqfcs6jv8eq)
 * ------------------------------------------------------------------------- */

describe('total completion and the absolute deadline', () => {
  it('T8 a slow-drip body is cut at 15,000 ms of wall clock, not by inactivity', async () => {
    vi.useFakeTimers();
    script((call) => {
      queueMicrotask(() => {
        const response = call.respond(200);
        // One byte per second forever: never idle long enough for an inactivity timeout.
        const drip = setInterval(() => {
          if (response.destroyed) {
            clearInterval(drip);
            return;
          }
          response.emit('data', Buffer.from(' '));
        }, 1_000);
      });
    });
    const pending = track(newClient().listOpenIssues());
    await vi.advanceTimersByTimeAsync(14_999);
    expect(pending.settled()).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(pending.settled()).toBe(true);
    expectIndeterminate(await pending.promise, 'DEADLINE');
    await vi.advanceTimersByTimeAsync(2_000);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T9 no response ever (DNS/connect/TLS/header delay) ends at 15,000 ms', async () => {
    vi.useFakeTimers();
    script(manual);
    const pending = track(newClient().readRepository());
    await vi.advanceTimersByTimeAsync(14_999);
    expect(pending.settled()).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expectIndeterminate(await pending.promise, 'DEADLINE');
    expect(calls[0]?.request.destroyed).toBe(true);
  });

  it('T9 each page receives its own fresh 15 s budget; pagination never resets one in flight', async () => {
    vi.useFakeTimers();
    script(
      (call) => {
        setTimeout(() => {
          const response = call.respond(200, nextLink(listingUrl('issues', 2)));
          response.emit('data', Buffer.from('[]'));
          response.emit('end');
        }, 14_000);
      },
      manual,
    );
    const pending = track(newClient().listOpenIssues());
    await vi.advanceTimersByTimeAsync(14_000);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(14_999);
    expect(pending.settled()).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expectIndeterminate(await pending.promise, 'DEADLINE');
  });

  it('T10 response close without end or error settles INCOMPLETE', async () => {
    script((call) => {
      queueMicrotask(() => {
        const response = call.respond(200);
        response.emit('data', Buffer.from('[1,'));
        response.emit('close');
      });
    });
    expectIndeterminate(await newClient().listOpenIssues(), 'INCOMPLETE');
  });

  it('T10 request close before any response settles INCOMPLETE', async () => {
    script((call) => {
      queueMicrotask(() => call.request.emit('close'));
    });
    expectIndeterminate(await newClient().readRepository(), 'INCOMPLETE');
  });

  it('T11 an aborted response settles ABORTED', async () => {
    script((call) => {
      queueMicrotask(() => {
        const response = call.respond(200);
        response.emit('aborted');
      });
    });
    expectIndeterminate(await newClient().listOpenIssues(), 'ABORTED');
  });

  it('T12 a request error settles TRANSPORT_ERROR', async () => {
    script((call) => {
      queueMicrotask(() => call.request.emit('error', new Error('getaddrinfo ENOTFOUND')));
    });
    expectIndeterminate(await newClient().readRepository(), 'TRANSPORT_ERROR');
  });

  it('T13 a response error settles TRANSPORT_ERROR', async () => {
    script((call) => {
      queueMicrotask(() => {
        const response = call.respond(200);
        response.emit('data', Buffer.from('['));
        response.emit('error', new Error('ECONNRESET'));
      });
    });
    expectIndeterminate(await newClient().listOpenIssues(), 'TRANSPORT_ERROR');
  });

  it('T14 deadline then error: settles once as DEADLINE', async () => {
    vi.useFakeTimers();
    script(manual);
    const pending = newClient().readRepository();
    await vi.advanceTimersByTimeAsync(15_000);
    calls[0]?.request.emit('error', new Error('late'));
    expectIndeterminate(await pending, 'DEADLINE');
  });

  it('T14 error then deadline: settles once as TRANSPORT_ERROR and the timer is cleared', async () => {
    vi.useFakeTimers();
    script((call) => {
      setTimeout(() => call.request.emit('error', new Error('early')), 14_999);
    });
    const pending = newClient().readRepository();
    await vi.advanceTimersByTimeAsync(14_999);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(10_000);
    expectIndeterminate(await pending, 'TRANSPORT_ERROR');
  });

  it('T42 a synchronous throw from request() settles TRANSPORT_ERROR and leaves no timer', async () => {
    vi.useFakeTimers();
    script(() => {
      throw new Error('invalid header SECRET-ERROR-TEXT');
    });
    expectIndeterminate(await newClient().readRepository(), 'TRANSPORT_ERROR');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('T43 late events after settlement are inert and raise nothing', async () => {
    let response: FakeResponse | null = null;
    let request: FakeRequest | null = null;
    script((call) => {
      request = call.request;
      queueMicrotask(() => {
        response = call.respond(500);
      });
    });
    const pending = newClient().readRepository();
    const first = await pending;
    expectIndeterminate(first, 'STATUS', 500);
    const lateResponse = response as FakeResponse | null;
    const lateRequest = request as FakeRequest | null;
    expect(() => {
      lateResponse?.emit('data', Buffer.from('x'));
      lateResponse?.emit('end');
      lateResponse?.emit('aborted');
      lateResponse?.emit('error', new Error('late'));
      lateResponse?.emit('close');
      lateRequest?.emit('error', new Error('late'));
      lateRequest?.emit('close');
    }).not.toThrow();
    await flush();
    expect(await pending).toBe(first);
  });
});

/* ------------------------------------------------------------------------- *
 * T16–T19, T47 — status semantics
 * ------------------------------------------------------------------------- */

describe('status semantics', () => {
  it.each([401, 403, 429, 500, 502, 503, 204, 301, 302, 201])(
    'T16/T18/T19/T47 status %i is INDETERMINATE STATUS on every family, never a negative fact',
    async (status) => {
      script(reply(status, '{}'), reply(status, '{}'), reply(status, '[]'), reply(status, '[]'));
      const client = newClient();
      expectIndeterminate(await client.readRepository(), 'STATUS', status);
      expectIndeterminate(await client.readBranch('refs/heads/feature/x'), 'STATUS', status);
      expectIndeterminate(await client.listOpenPullRequests(), 'STATUS', status);
      expectIndeterminate(await client.listOpenIssues(), 'STATUS', status);
    },
  );

  it('T17 404 is determinate absence on BRANCH only', async () => {
    script(reply(404, '{"message":"Branch not found"}'), reply(404, '{}'), reply(404, '[]'), reply(404, '[]'));
    const client = newClient();
    expect(await client.readBranch('refs/heads/feature/x')).toEqual({ kind: 'DETERMINATE', value: { present: false } });
    expectIndeterminate(await client.readRepository(), 'STATUS', 404);
    expectIndeterminate(await client.listOpenPullRequests(), 'STATUS', 404);
    expectIndeterminate(await client.listOpenIssues(), 'STATUS', 404);
  });

  it('T19 a failing later page makes the whole listing indeterminate (all or nothing)', async () => {
    script(json([issue(1)], nextLink(listingUrl('issues', 2))), reply(502, ''));
    expectIndeterminate(await newClient().listOpenIssues(), 'STATUS', 502);
  });
});

/* ------------------------------------------------------------------------- *
 * T20, T21, T40, T41 — hostile bodies
 * ------------------------------------------------------------------------- */

describe('hostile bodies', () => {
  it('T20 malformed JSON is MALFORMED_BODY', async () => {
    script(reply(200, '{"id": 1'), reply(200, '[1,]'), reply(200, ''));
    const client = newClient();
    expectIndeterminate(await client.readRepository(), 'MALFORMED_BODY');
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_BODY');
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_BODY');
  });

  it('T40 invalid UTF-8 is MALFORMED_BODY', async () => {
    script(reply(200, Buffer.from([0x5b, 0xff, 0xfe, 0x5d])));
    expectIndeterminate(await newClient().listOpenIssues(), 'MALFORMED_BODY');
  });

  it.each<[string, unknown]>([
    ['array body', []],
    ['missing id', { full_name: 'LogicDuke/agentbridge', default_branch: 'main' }],
    ['id 0', { ...REPOSITORY_BODY, id: 0 }],
    ['id fraction', { ...REPOSITORY_BODY, id: 1.5 }],
    ['id string', { ...REPOSITORY_BODY, id: '42' }],
    ['id unsafe', { ...REPOSITORY_BODY, id: 2 ** 60 }],
    ['full_name mismatch', { ...REPOSITORY_BODY, full_name: 'LogicDuke/other' }],
    ['full_name Kelvin sign fold', { ...REPOSITORY_BODY, full_name: 'LogicDuKe/agentbridge' }],
    ['default_branch invalid', { ...REPOSITORY_BODY, default_branch: 'a..b' }],
    ['default_branch missing', { id: REPOSITORY_ID, full_name: 'LogicDuke/agentbridge' }],
    ['inherited fields only', JSON.parse('{"__proto__": {"id": 1, "full_name": "LogicDuke/agentbridge", "default_branch": "main"}}') as unknown],
  ])('T21 hostile REPOSITORY body (%s) is MALFORMED_BODY', async (_label, body) => {
    script(json(body));
    expectIndeterminate(await newClient().readRepository(), 'MALFORMED_BODY');
  });

  it.each<[string, unknown]>([
    ['name mismatch', { ...BRANCH_BODY, name: 'feature/y' }],
    ['uppercase sha', { ...BRANCH_BODY, commit: { sha: 'A'.repeat(40) } }],
    ['short sha', { ...BRANCH_BODY, commit: { sha: 'a'.repeat(39) } }],
    ['missing commit', { name: 'feature/x', protected: false }],
    ['protected string', { ...BRANCH_BODY, protected: 'false' }],
  ])('T21 hostile BRANCH body (%s) is MALFORMED_BODY', async (_label, body) => {
    script(json(body));
    expectIndeterminate(await newClient().readBranch('refs/heads/feature/x'), 'MALFORMED_BODY');
  });

  it.each<[string, unknown]>([
    ['object instead of array', { items: [] }],
    ['101 items', Array.from({ length: 101 }, (_unused, index) => pull(index + 1))],
    ['number 0', [{ ...pull(1), number: 0 }]],
    ['number string', [{ ...pull(1), number: '1' }]],
    ['head.ref too long', [{ ...pull(1), head: { ref: 'x'.repeat(1_025), repo: null } }]],
    ['head.ref empty', [{ ...pull(1), head: { ref: '', repo: null } }]],
    ['head.repo missing', [{ number: 1, head: { ref: 'x' }, base: { ref: 'main' } }]],
    ['head.repo.full_name number', [{ number: 1, head: { ref: 'x', repo: { full_name: 1 } }, base: { ref: 'main' } }]],
    ['base missing', [{ number: 1, head: { ref: 'x', repo: null } }]],
    ['element null', [null]],
  ])('T21 hostile OPEN_PULLS page (%s) is MALFORMED_BODY', async (_label, body) => {
    script(json(body));
    expectIndeterminate(await newClient().listOpenPullRequests(), 'MALFORMED_BODY');
  });

  it.each<[string, unknown]>([
    ['title too long', [issue(1, { title: 'x'.repeat(1_025) })]],
    ['body too long', [issue(1, { body: 'x'.repeat(65_537) })]],
    ['body missing', [{ number: 1, title: 't' }]],
    ['body number', [issue(1, { body: 5 })]],
    ['title missing', [{ number: 1, body: null }]],
  ])('T21 hostile OPEN_ISSUES page (%s) is MALFORMED_BODY', async (_label, body) => {
    script(json(body));
    expectIndeterminate(await newClient().listOpenIssues(), 'MALFORMED_BODY');
  });

  it('T21 prototype-bearing keys are never read and pollute nothing', async () => {
    const text =
      '[{"__proto__": {"polluted": true}, "constructor": {"prototype": {"polluted": true}}, "number": 1, "title": "t", "body": null}]';
    script(reply(200, text));
    const observation = await newClient().listOpenIssues();
    expect(observation).toEqual({ kind: 'DETERMINATE', value: [{ number: 1, title: 't', body: null, isPullRequest: false }] });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    if (observation.kind === 'DETERMINATE') {
      expect(Object.keys(observation.value[0] ?? {})).toEqual(['number', 'title', 'body', 'isPullRequest']);
    }
  });

  it('T41 a duplicate record number across pages is MALFORMED_BODY', async () => {
    script(json([issue(1)], nextLink(listingUrl('issues', 2))), json([issue(1)]));
    expectIndeterminate(await newClient().listOpenIssues(), 'MALFORMED_BODY');
  });

  it('T41 a duplicate record number within a page is MALFORMED_BODY', async () => {
    script(json([pull(3), pull(3)]));
    expectIndeterminate(await newClient().listOpenPullRequests(), 'MALFORMED_BODY');
  });
});

/* ------------------------------------------------------------------------- *
 * T24–T30, T38, T39, T46, T48 — continuation (PRRT_kwDOTzqfcs6jv8ev)
 * ------------------------------------------------------------------------- */

async function continuationOutcome(link: string, listing: 'pulls' | 'issues' = 'issues'): Promise<GitHubObservation<unknown>> {
  script(json(listing === 'pulls' ? [pull(1)] : [issue(1)], { link }));
  const client = newClient();
  return listing === 'pulls' ? client.listOpenPullRequests() : client.listOpenIssues();
}

const PAGE_2 = listingUrl('issues', 2);

describe('continuation is evidence, never a target', () => {
  it.each([
    ['bare text', 'garbage'],
    ['no parameters', `<${PAGE_2}>`],
    ['missing semicolon', `<${PAGE_2}> rel="next"`],
    ['unterminated quote', `<${PAGE_2}>; rel="next`],
    ['empty parameter', `<${PAGE_2}>;`],
    ['nested angle bracket', `<https://api.github.com/<x>; rel="next"`],
    ['trailing comma', `<${PAGE_2}>; rel="next",`],
    ['escaped quote', `<${PAGE_2}>; rel="ne\\"xt"`],
    ['empty relation token', `<${PAGE_2}>; rel="next  last"`],
    ['duplicate rel parameter', `<${PAGE_2}>; rel="prev"; rel="next"`],
    ['junk after value', `<${PAGE_2}>; rel="next" junk`],
    ['empty uri', `<>; rel="next"`],
    // Every relation must itself be a token (Rev 1 §12: space-separated tokens).
    // A relation that is not one is malformed, never an ignorable non-next relation.
    ['relation joined by tab', `<${PAGE_2}>; rel="next\tlast"`],
    ['relation joined by comma', `<${PAGE_2}>; rel="next,last"`],
    ['relation joined by semicolon', `<${PAGE_2}>; rel="next;last"`],
    ['relation joined by newline', `<${PAGE_2}>; rel="next\nlast"`],
    ['relation joined by no-break space', `<${PAGE_2}>; rel="next\u00a0last"`],
    ['relation joined by slash', `<${PAGE_2}>; rel="next/last"`],
    ['relation with control character', `<${PAGE_2}>; rel="next\u0001"`],
    ['relation with non-ASCII look-alike', `<${PAGE_2}>; rel="n\u0435xt"`],
    ['relation that is a URI', `<${PAGE_2}>; rel="https://example.com/next"`],
    ['relation with parentheses', `<${PAGE_2}>; rel="(next)"`],
    ['malformed relation beside a valid one', `<${PAGE_2}>; rel="prev la\tst"`],
    ['malformed relation on a non-next link-value', `<${PAGE_2}>; rel="next", <${listingUrl('issues', 1)}>; rel="first\tprev"`],
  ])('T24 malformed Link header (%s) is MALFORMED_CONTINUATION, never a clean end', async (_label, link) => {
    expectIndeterminate(await continuationOutcome(link), 'MALFORMED_CONTINUATION');
    expect(calls).toHaveLength(1);
  });

  it.each([
    ['rel="next"', `<${PAGE_2}>; rel="next"`],
    ['next among valid tokens', `<${PAGE_2}>; rel="prev next"`],
    ['upper-case NEXT', `<${PAGE_2}>; rel="NEXT"`],
    ['unquoted token', `<${PAGE_2}>; rel=next`],
    ['other parameters beside rel', `<${PAGE_2}>; title="a, b; c"; rel="next"`],
  ])('T24 negative control: a valid relation set with next (%s) continues to page 2', async (_label, link) => {
    script(json([issue(1)], { link }), json([issue(2)]));
    const observation = await newClient().listOpenIssues();
    expect(observation.kind).toBe('DETERMINATE');
    expect(calls).toHaveLength(2);
  });

  it.each([
    ['first and prev', `<${listingUrl('issues', 1)}>; rel="first prev"`],
    ['unfamiliar valid token', `<${listingUrl('issues', 1)}>; rel="x-custom.rel"`],
    ['token punctuation', `<${listingUrl('issues', 1)}>; rel="next!"`],
  ])('T24 negative control: a valid relation set without next (%s) is a clean end', async (_label, link) => {
    script(json([issue(1)], { link }));
    expect((await newClient().listOpenIssues()).kind).toBe('DETERMINATE');
    expect(calls).toHaveLength(1);
  });

  it.each([
    ['not a url', 'not-a-url'],
    ['empty page value', 'https://api.github.com/repos/LogicDuke/agentbridge/issues?state=open&per_page=100&page='],
    ['page zero', 'https://api.github.com/repos/LogicDuke/agentbridge/issues?state=open&per_page=100&page=0'],
    ['page leading zero', 'https://api.github.com/repos/LogicDuke/agentbridge/issues?state=open&per_page=100&page=02'],
  ])('T25 malformed next URL (%s) is MALFORMED_CONTINUATION', async (_label, uri) => {
    expectIndeterminate(await continuationOutcome(`<${uri}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it.each([
    ['http', PAGE_2.replace('https:', 'http:')],
    ['ftp', PAGE_2.replace('https:', 'ftp:')],
    ['upper-case scheme', PAGE_2.replace('https:', 'HTTPS:')],
  ])('T26 wrong scheme (%s) is MALFORMED_CONTINUATION', async (_label, uri) => {
    expectIndeterminate(await continuationOutcome(`<${uri}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it.each([
    ['suffix host', PAGE_2.replace('api.github.com', 'api.github.com.evil')],
    ['other host', PAGE_2.replace('api.github.com', 'evil.example')],
    ['userinfo', PAGE_2.replace('https://', 'https://user@')],
    ['userinfo with password', PAGE_2.replace('https://', 'https://user:pw@')],
    ['upper-case host', PAGE_2.replace('api.github.com', 'API.GITHUB.COM')],
  ])('T27 wrong host or userinfo (%s) is MALFORMED_CONTINUATION', async (_label, uri) => {
    expectIndeterminate(await continuationOutcome(`<${uri}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it.each([
    ['other repository', listingUrl('issues', 2, 'https://api.github.com/repos/LogicDuke/other')],
    ['other owner', listingUrl('issues', 2, 'https://api.github.com/repos/Other/agentbridge')],
    ['other listing', listingUrl('pulls', 2)],
    ['extra segment', 'https://api.github.com/repos/LogicDuke/agentbridge/issues/1?state=open&per_page=100&page=2'],
    ['dot segments', 'https://api.github.com/repos/LogicDuke/other/../agentbridge/issues?state=open&per_page=100&page=2'],
    ['single-dot segment', 'https://api.github.com/repos/LogicDuke/./agentbridge/issues?state=open&per_page=100&page=2'],
    ['trailing dot-dot', 'https://api.github.com/repos/LogicDuke/agentbridge/issues/x/..?state=open&per_page=100&page=2'],
    ['encoded dot segments', 'https://api.github.com/repos/LogicDuke/other/%2e%2e/agentbridge/issues?state=open&per_page=100&page=2'],
    ['backslash', 'https://api.github.com/repos\\LogicDuke/agentbridge/issues?state=open&per_page=100&page=2'],
    ['graphql', 'https://api.github.com/graphql?state=open&per_page=100&page=2'],
    ['relative', '/repos/LogicDuke/agentbridge/issues?state=open&per_page=100&page=2'],
    ['protocol-relative', '//api.github.com/repos/LogicDuke/agentbridge/issues?state=open&per_page=100&page=2'],
  ])('T28 path escape or relative continuation (%s) is MALFORMED_CONTINUATION', async (_label, uri) => {
    expectIndeterminate(await continuationOutcome(`<${uri}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it('T29 a repeated page (next = current) is MALFORMED_CONTINUATION', async () => {
    expectIndeterminate(await continuationOutcome(`<${listingUrl('issues', 1)}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it('T29 a skipped page is MALFORMED_CONTINUATION', async () => {
    expectIndeterminate(await continuationOutcome(`<${listingUrl('issues', 3)}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it('T29 a cycle back to an earlier page is MALFORMED_CONTINUATION', async () => {
    script(json([issue(1)], nextLink(listingUrl('issues', 2))), json([issue(2)], nextLink(listingUrl('issues', 1))));
    expectIndeterminate(await newClient().listOpenIssues(), 'MALFORMED_CONTINUATION');
    expect(calls).toHaveLength(2);
  });

  it('T30 page 5 with a valid next remaining is PAGE_LIMIT after exactly five requests', async () => {
    for (let page = 1; page <= 5; page += 1) {
      script(json([issue(page)], nextLink(listingUrl('issues', page + 1))));
    }
    expectIndeterminate(await newClient().listOpenIssues(), 'PAGE_LIMIT');
    expect(calls).toHaveLength(5);
  });

  it.each([
    ['duplicate page key', PAGE_2 + '&page=2'],
    ['duplicate state key', PAGE_2 + '&state=open'],
    ['unknown key', PAGE_2 + '&sort=created'],
    ['head filter', PAGE_2 + '&head=LogicDuke:main'],
    ['base filter', PAGE_2 + '&base=main'],
    ['state closed', PAGE_2.replace('state=open', 'state=closed')],
    ['per_page 50', PAGE_2.replace('per_page=100', 'per_page=50')],
    ['missing state', PAGE_2.replace('state=open&', '')],
    ['missing per_page', PAGE_2.replace('per_page=100&', '')],
    ['explicit port 443', PAGE_2.replace('api.github.com', 'api.github.com:443')],
    ['explicit other port', PAGE_2.replace('api.github.com', 'api.github.com:8443')],
    ['fragment', PAGE_2 + '#frag'],
    ['empty fragment', PAGE_2 + '#'],
  ])('T38 unusable query, port, or fragment (%s) is MALFORMED_CONTINUATION', async (_label, uri) => {
    expectIndeterminate(await continuationOutcome(`<${uri}>; rel="next"`), 'MALFORMED_CONTINUATION');
  });

  it('T39a /repositories/{id} is accepted when this client proved that id; the server URL is never requested', async () => {
    const byId = listingUrl('issues', 2, `https://api.github.com/repositories/${String(REPOSITORY_ID)}`);
    script(json(REPOSITORY_BODY), json([issue(1)], nextLink(byId)), json([issue(2)]));
    const client = newClient();
    expect((await client.readRepository()).kind).toBe('DETERMINATE');
    const observation = await client.listOpenIssues();
    expect(observation.kind).toBe('DETERMINATE');
    expect(calls.map((call) => call.options.path)).toEqual([
      REPO_PATH,
      REPO_PATH + '/issues?state=open&per_page=100&page=1',
      REPO_PATH + '/issues?state=open&per_page=100&page=2',
    ]);
  });

  it('T39b /repositories/{id} without a prior determinate REPOSITORY observation fails closed with no extra request', async () => {
    const byId = listingUrl('issues', 2, `https://api.github.com/repositories/${String(REPOSITORY_ID)}`);
    expectIndeterminate(await continuationOutcome(`<${byId}>; rel="next"`), 'MALFORMED_CONTINUATION');
    expect(calls.map((call) => call.options.path)).toEqual([REPO_PATH + '/issues?state=open&per_page=100&page=1']);
  });

  it('T39b an indeterminate REPOSITORY observation proves no id', async () => {
    const byId = listingUrl('issues', 2, `https://api.github.com/repositories/${String(REPOSITORY_ID)}`);
    script(reply(500, ''), json([issue(1)], nextLink(byId)));
    const client = newClient();
    expectIndeterminate(await client.readRepository(), 'STATUS', 500);
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_CONTINUATION');
  });

  it.each([
    ['other id', `https://api.github.com/repositories/${String(REPOSITORY_ID + 1)}`],
    ['leading zero', `https://api.github.com/repositories/0${String(REPOSITORY_ID)}`],
    ['non-numeric id', 'https://api.github.com/repositories/abc'],
  ])('T39c /repositories/{id} with %s is MALFORMED_CONTINUATION', async (_label, base) => {
    script(json(REPOSITORY_BODY), json([issue(1)], nextLink(listingUrl('issues', 2, base))));
    const client = newClient();
    expect((await client.readRepository()).kind).toBe('DETERMINATE');
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_CONTINUATION');
  });

  it('T39c a different repository id clears the proven id; a later valid observation re-proves it (Rev 1 §15)', async () => {
    const byId = listingUrl('issues', 2, `https://api.github.com/repositories/${String(REPOSITORY_ID)}`);
    script(
      json(REPOSITORY_BODY),
      json({ ...REPOSITORY_BODY, id: REPOSITORY_ID + 1 }),
      json([issue(1)], nextLink(byId)),
      json(REPOSITORY_BODY),
      json([issue(1)], nextLink(byId)),
      json([issue(2)]),
    );
    const client = newClient();
    // 1. A is proven.
    expect(await client.readRepository()).toEqual({ kind: 'DETERMINATE', value: { defaultBranch: 'main' } });
    // 2. B != A: that observation is MALFORMED_BODY and the proven id is cleared.
    expectIndeterminate(await client.readRepository(), 'MALFORMED_BODY');
    // 3. Nothing is proven now, so /repositories/{A} is not evidence.
    expectIndeterminate(await client.listOpenIssues(), 'MALFORMED_CONTINUATION');
    // 4-5. A later valid A observation is determinate and re-proves A: no latch persists.
    expect(await client.readRepository()).toEqual({ kind: 'DETERMINATE', value: { defaultBranch: 'main' } });
    // 6. /repositories/{A} is accepted again; page 2 comes from the client's own template.
    const observation = await client.listOpenIssues();
    expect(observation.kind).toBe('DETERMINATE');
    if (observation.kind === 'DETERMINATE') {
      expect(observation.value.map((record) => record.number)).toEqual([1, 2]);
    }
    // 7. Every REPOSITORY request was a caller's readRepository(); none was issued to resolve an id.
    expect(calls.map((call) => call.options.path)).toEqual([
      REPO_PATH,
      REPO_PATH,
      REPO_PATH + '/issues?state=open&per_page=100&page=1',
      REPO_PATH,
      REPO_PATH + '/issues?state=open&per_page=100&page=1',
      REPO_PATH + '/issues?state=open&per_page=100&page=2',
    ]);
  });

  it('T46 rel=next on REPOSITORY or BRANCH is MALFORMED_CONTINUATION', async () => {
    const link = { link: `<${PAGE_2}>; rel="next"` };
    script(json(REPOSITORY_BODY, link), json(BRANCH_BODY, link), reply(404, '', link));
    const client = newClient();
    expectIndeterminate(await client.readRepository(), 'MALFORMED_CONTINUATION');
    expectIndeterminate(await client.readBranch('refs/heads/feature/x'), 'MALFORMED_CONTINUATION');
    expectIndeterminate(await client.readBranch('refs/heads/feature/x'), 'MALFORMED_CONTINUATION');
  });

  it('T48 two rel=next links are MALFORMED_CONTINUATION', async () => {
    expectIndeterminate(
      await continuationOutcome(`<${PAGE_2}>; rel="next", <${PAGE_2}>; rel="next"`),
      'MALFORMED_CONTINUATION',
    );
    expectIndeterminate(await continuationOutcome(`<${PAGE_2}>; rel="next next"`), 'MALFORMED_CONTINUATION');
  });
});

/* ------------------------------------------------------------------------- *
 * T31–T34, T36, T37, T44, T45 — authority surface
 * ------------------------------------------------------------------------- */

describe('authority surface', () => {
  it('T31 token variables in the environment never produce an Authorization header', async () => {
    vi.stubEnv('GITHUB_TOKEN', 'ghp_SECRETTOKENVALUE');
    vi.stubEnv('GH_TOKEN', 'gho_SECRETTOKENVALUE');
    script(json(REPOSITORY_BODY));
    await newClient().readRepository();
    const headers = calls[0]?.options.headers as Record<string, string>;
    expect(Object.keys(headers).map((key) => key.toLowerCase())).not.toContain('authorization');
    expect(JSON.stringify(calls[0]?.options)).not.toContain('SECRETTOKENVALUE');
    expect(calls[0]?.options.auth).toBeUndefined();
  });

  it('T32 outcomes carry only the closed vocabulary, never Node error text', async () => {
    const causes = new Set<string>([
      'INVALID_INPUT',
      'BUDGET_EXHAUSTED',
      'DEADLINE',
      'TRANSPORT_ERROR',
      'ABORTED',
      'INCOMPLETE',
      'TOO_LARGE',
      'ENCODING',
      'STATUS',
      'MALFORMED_BODY',
      'MALFORMED_CONTINUATION',
      'PAGE_LIMIT',
    ]);
    script(
      (call) => {
        queueMicrotask(() => call.request.emit('error', new Error('SECRET-ERROR-TEXT')));
      },
      () => {
        throw new Error('SECRET-ERROR-TEXT');
      },
      reply(401, '{"message":"SECRET-ERROR-TEXT"}'),
      reply(200, '{"SECRET-ERROR-TEXT'),
    );
    const client = newClient();
    const observations = [
      await client.readRepository(),
      await client.readRepository(),
      await client.readRepository(),
      await client.readRepository(),
      await client.readBranch('not a ref'),
    ];
    for (const observation of observations) {
      expect(observation.kind).toBe('INDETERMINATE');
      expect(Object.keys(observation).sort()).toEqual(['cause', 'httpStatus', 'kind']);
      if (observation.kind === 'INDETERMINATE') {
        expect(causes.has(observation.cause)).toBe(true);
      }
      expect(JSON.stringify(observation)).not.toContain('SECRET');
    }
  });

  it('T33 the module and client surfaces are exactly the ratified API', () => {
    expect(Object.keys(clientModule).sort()).toEqual(['GITHUB_LIMITS', 'createRetirementGitHubClient']);
    expect(GITHUB_LIMITS).toEqual({
      MAX_REQUESTS_PER_RUN: 20,
      REQUEST_DEADLINE_MS: 15_000,
      MAX_RESPONSE_BYTES: 2_097_152,
      PER_PAGE: 100,
      MAX_PAGES: 5,
    });
    expect(Object.isFrozen(GITHUB_LIMITS)).toBe(true);
    const client = newClient();
    expect(Object.isFrozen(client)).toBe(true);
    expect(Object.keys(client).sort()).toEqual(['listOpenIssues', 'listOpenPullRequests', 'readBranch', 'readRepository']);
    expect([
      client.readRepository.length,
      client.readBranch.length,
      client.listOpenPullRequests.length,
      client.listOpenIssues.length,
    ]).toEqual([0, 1, 0, 0]);
    expect(createRetirementGitHubClient.length).toBe(1);
  });

  it('T34 source pin: one request site, GET literal, constant host, exactly the four templates, no other network surface', () => {
    const source = readFileSync(new URL('../../src/runtime/retirement-github-client.ts', import.meta.url), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    expect(code.match(/\brequest\(/g)).toHaveLength(1);
    expect(code).toContain("method: 'GET'");
    expect(code).toContain('hostname: GITHUB_HOST');
    expect(code).toContain("const GITHUB_HOST = 'api.github.com';");
    expect(code).toContain('port: 443');
    const imports = [...code.matchAll(/from '([^']+)'/g)].map((match) => match[1]);
    expect(imports).toEqual(['node:https', '../domain/repair-job.js']);
    // The four §7 templates and no other path construction.
    expect(code).toContain('const repositoryPath = `/repos/${owner}/${repo}`;');
    expect(code).toContain('`${repositoryPath}/branches/${name}`');
    expect(code).toContain('`${repositoryPath}/pulls?state=open&per_page=100&page=${String(page)}`');
    expect(code).toContain('`${repositoryPath}/issues?state=open&per_page=100&page=${String(page)}`');
    expect(code.match(/`\$\{repositoryPath\}/g)).toHaveLength(3);
    // Three call sites: one per REPOSITORY, BRANCH, and the shared listing loop.
    expect(code.match(/fetchPath\(/g)).toHaveLength(3);
    for (const forbidden of [
      /\bfetch\(/,
      /graphql/i,
      /node:http['"]/,
      /node:net/,
      /node:tls/,
      /process\.env/,
      /child_process/,
      /authorization/i,
      /console\./,
      /\.setTimeout\(/,
    ]) {
      expect(forbidden.test(code), String(forbidden)).toBe(false);
    }
  });

  it('T36 request 21 is refused before any network activity; one full observation uses at most 12', async () => {
    const client = newClient();
    script(json(REPOSITORY_BODY), json(BRANCH_BODY));
    for (let page = 1; page <= 5; page += 1) {
      script(json([pull(page)], page < 5 ? nextLink(listingUrl('pulls', page + 1)) : {}));
    }
    for (let page = 1; page <= 5; page += 1) {
      script(json([issue(page)], page < 5 ? nextLink(listingUrl('issues', page + 1)) : {}));
    }
    expect((await client.readRepository()).kind).toBe('DETERMINATE');
    expect((await client.readBranch('refs/heads/feature/x')).kind).toBe('DETERMINATE');
    expect((await client.listOpenPullRequests()).kind).toBe('DETERMINATE');
    expect((await client.listOpenIssues()).kind).toBe('DETERMINATE');
    expect(calls).toHaveLength(12);

    for (let index = 0; index < 8; index += 1) {
      script(json(REPOSITORY_BODY));
    }
    for (let index = 0; index < 8; index += 1) {
      expect((await client.readRepository()).kind).toBe('DETERMINATE');
    }
    expect(calls).toHaveLength(20);
    expectIndeterminate(await client.readRepository(), 'BUDGET_EXHAUSTED');
    expectIndeterminate(await client.listOpenIssues(), 'BUDGET_EXHAUSTED');
    expect(calls).toHaveLength(20);
  });

  it('T36 every page spends budget: a listing that meets an exhausted budget is indeterminate', async () => {
    const client = newClient();
    for (let index = 0; index < 18; index += 1) {
      script(json(REPOSITORY_BODY));
    }
    for (let index = 0; index < 18; index += 1) {
      await client.readRepository();
    }
    script(json([issue(1)], nextLink(listingUrl('issues', 2))), json([issue(2)], nextLink(listingUrl('issues', 3))));
    expectIndeterminate(await client.listOpenIssues(), 'BUDGET_EXHAUSTED');
    expect(calls).toHaveLength(20);
  });

  it.each<[string, unknown]>([
    ['empty owner', { owner: '', repo: REPO }],
    ['leading hyphen', { owner: '-x', repo: REPO }],
    ['trailing hyphen', { owner: 'x-', repo: REPO }],
    ['owner too long', { owner: 'a'.repeat(40), repo: REPO }],
    ['owner with slash', { owner: 'a/b', repo: REPO }],
    ['owner with dot', { owner: 'a.b', repo: REPO }],
    ['repo dot', { owner: OWNER, repo: '.' }],
    ['repo dot-dot', { owner: OWNER, repo: '..' }],
    ['repo with space', { owner: OWNER, repo: 'a b' }],
    ['repo with query', { owner: OWNER, repo: 'a?x=1' }],
    ['repo too long', { owner: OWNER, repo: 'a'.repeat(101) }],
    ['owner number', { owner: 1, repo: REPO }],
    ['null config', null],
    ['inherited owner', Object.assign(Object.create({ owner: OWNER }) as object, { repo: REPO })],
  ])('T37 invalid configuration (%s) builds no client', (_label, config) => {
    expect(createRetirementGitHubClient(config as { owner: string; repo: string })).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('T37 an invalid branch ref is INVALID_INPUT with zero requests and zero budget spent', async () => {
    const client = newClient();
    for (const ref of ['main', 'refs/heads/', 'refs/heads/a..b', 'refs/tags/v1', 'refs/heads/a b', 'refs/heads/x?y', 42]) {
      expectIndeterminate(await client.readBranch(ref as string), 'INVALID_INPUT');
    }
    expect(calls).toHaveLength(0);
    for (let index = 0; index < 20; index += 1) {
      script(json(REPOSITORY_BODY));
    }
    for (let index = 0; index < 20; index += 1) {
      expect((await client.readRepository()).kind).toBe('DETERMINATE');
    }
  });

  it('T44 exactly the fixed header set is sent, with no body', async () => {
    script(json(REPOSITORY_BODY));
    await newClient().readRepository();
    expect(calls[0]?.options.headers).toEqual(EXPECTED_HEADERS);
    expect(calls[0]?.options.method).toBe('GET');
    expect(calls[0]?.request.ended).toBe(true);
    expect(calls[0]?.request.writes).toBe(0);
  });

  it('T45 TLS options are pinned and every request uses the one private agent', async () => {
    script(json(REPOSITORY_BODY), json(BRANCH_BODY));
    const client = newClient();
    await client.readRepository();
    await client.readBranch('refs/heads/feature/x');
    for (const call of calls) {
      expect(call.options).toMatchObject({
        protocol: 'https:',
        hostname: 'api.github.com',
        port: 443,
        rejectUnauthorized: true,
        servername: 'api.github.com',
      });
      expect(Object.keys(call.options).sort()).toEqual(
        ['agent', 'headers', 'hostname', 'method', 'path', 'port', 'protocol', 'rejectUnauthorized', 'servername'].sort(),
      );
    }
    const agent = calls[0]?.options.agent;
    expect(agent).toBeInstanceOf(RealAgent);
    expect(calls[1]?.options.agent).toBe(agent);
    expect((agent as { keepAlive?: unknown }).keepAlive).toBe(false);
  });
});
