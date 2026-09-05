import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import {
  createLiveCockpitSource,
  createLiveObservation,
  startLiveCockpit,
  type LiveCockpitConfig,
} from '../../src/runtime/live-cockpit.js';
import {
  createCockpitServer,
  createCockpitServerFromProvider,
} from '../../src/cockpit-host/server.js';
import { AutoflowRuntime } from '../../src/autoflow/runtime.js';
import {
  createConfiguredRepositoryObserver,
  type RepositoryObservation,
  type RepositoryObserver,
} from '../../src/runtime/repository-observer.js';
import { readCockpitSnapshot } from '../../src/cockpit/index.js';
import type { WorkflowBinding, WorkflowEvent } from '../../src/domain/index.js';

const REPO = 'repo-agentbridge';
const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const SHA_B = 'ffeeddccbbaa99887766554433221100aabbccdd';
const FIXED_ISO = '2026-09-05T13:00:00.000Z';

const BINDING: WorkflowBinding = { workflowId: 'wf-live-0001', repositoryId: REPO, boundCommitSha: SHA_A };
const HEAD_OBSERVED_B: WorkflowEvent = { kind: 'HEAD_OBSERVED', observedCommitSha: SHA_B };

const REPO_OBSERVATION: RepositoryObservation = {
  repositoryId: REPO,
  observedHeadSha: SHA_A,
  defaultBranchRef: 'refs/heads/main',
};

function fixedObserver(observation: RepositoryObservation = REPO_OBSERVATION): RepositoryObserver {
  return createConfiguredRepositoryObserver(observation);
}

function baseConfig(overrides: Partial<LiveCockpitConfig> = {}): LiveCockpitConfig {
  return {
    reader: new AutoflowRuntime().reader(),
    observer: fixedObserver(),
    collectorId: 'agentbridge-live-runtime',
    clock: (): Date => new Date(FIXED_ISO),
    ...overrides,
  };
}

// --- lifecycle helpers -------------------------------------------------------

const openServers: http.Server[] = [];
function track(server: http.Server): http.Server {
  openServers.push(server);
  return server;
}
afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => {
            resolve();
          });
        }),
    ),
  );
});

function waitListening(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    const done = (): void => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        reject(new Error('no port'));
        return;
      }
      resolve(address.port);
    };
    if (server.listening) {
      done();
      return;
    }
    server.once('listening', done);
    server.once('error', reject);
  });
}

interface HttpResult {
  readonly status: number;
  readonly body: string;
}
function request(port: number, method: string, path: string): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
      });
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// --- live source (whole-observation capture) --------------------------------

describe('createLiveObservation / createLiveCockpitSource', () => {
  it('builds one observation from observer, reader, and clock with empty read-model lists', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const observation = createLiveObservation(baseConfig({ reader: runtime.reader() }));
    expect(observation.repositoryId).toBe(REPO);
    expect(observation.observedHeadSha).toBe(SHA_A);
    expect(observation.observedAt).toBe(FIXED_ISO);
    expect(observation.collectorId).toBe('agentbridge-live-runtime');
    expect(observation.pullRequests).toStrictEqual([]);
    expect(observation.autoflow?.workflowId).toBe('wf-live-0001');
  });

  it('reads observer, state, and clock exactly once per read()', () => {
    let observeCalls = 0;
    let currentCalls = 0;
    let clockCalls = 0;
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const config = baseConfig({
      observer: {
        observe: () => {
          observeCalls += 1;
          return REPO_OBSERVATION;
        },
      },
      reader: {
        current: () => {
          currentCalls += 1;
          return runtime.current();
        },
      },
      clock: (): Date => {
        clockCalls += 1;
        return new Date(FIXED_ISO);
      },
    });
    const source = createLiveCockpitSource(config);
    source.read();
    expect(observeCalls).toBe(1);
    expect(currentCalls).toBe(1);
    expect(clockCalls).toBe(1);
  });

  it('is labeled live and observedAt is the whole-observation collection time', () => {
    const source = createLiveCockpitSource(baseConfig());
    expect(source.mode).toBe('live');
    const read = readCockpitSnapshot(source.read());
    expect(read.snapshot).not.toBeNull();
    if (read.snapshot === null) throw new Error('unreachable');
    expect(read.snapshot.provenance.observedAt).toBe(FIXED_ISO);
    expect(read.snapshot.provenance.collectorId).toBe('agentbridge-live-runtime');
  });

  it('produces valid schema-v2 data that passes D1, with empty read-model lists', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const read = readCockpitSnapshot(createLiveCockpitSource(baseConfig({ reader: runtime.reader() })).read());
    expect(read.invalidFields).toStrictEqual([]);
    expect(read.snapshot).not.toBeNull();
    if (read.snapshot === null) throw new Error('unreachable');
    expect(read.snapshot.repository.repositoryId).toBe(REPO);
    expect(read.snapshot.pullRequests).toStrictEqual([]);
    expect(read.snapshot.evidence).toStrictEqual([]);
    expect(read.snapshot.autoflow?.workflowId).toBe('wf-live-0001');
  });

  it('is serialization-detached: equals its own JSON round-trip and leaks no live reference', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING);
    const liveState = runtime.current();
    const raw = createLiveCockpitSource(baseConfig({ reader: runtime.reader() })).read();
    expect(raw).toStrictEqual(JSON.parse(JSON.stringify(raw)) as unknown);
    const read = readCockpitSnapshot(raw);
    if (read.snapshot === null) throw new Error('unreachable');
    // Reconstructed autoflow is a different object than the live in-process state.
    expect(read.snapshot.autoflow).not.toBe(liveState);
    expect(read.snapshot.autoflow?.boundCommitSha).toBe(SHA_A);
  });
});

// --- server per-GET seam -----------------------------------------------------

describe('createCockpitServerFromProvider (per-GET seam)', () => {
  it('invokes the provider exactly once for GET / and zero times for other routes', async () => {
    let calls = 0;
    const server = track(
      createCockpitServerFromProvider((): string => {
        calls += 1;
        return '<!doctype html><html><body>ok</body></html>';
      }),
    );
    server.listen(0, '127.0.0.1');
    const port = await waitListening(server);

    const root = await request(port, 'GET', '/');
    expect(root.status).toBe(200);
    expect(root.body).toContain('ok');
    expect(calls).toBe(1);

    const styles = await request(port, 'GET', '/styles.css');
    expect(styles.status).toBe(200);
    const missing = await request(port, 'GET', '/nope');
    expect(missing.status).toBe(404);
    const post = await request(port, 'POST', '/');
    expect(post.status).toBe(405);

    // Only the single GET / invoked the provider.
    expect(calls).toBe(1);
  });

  it('fails closed with 500 when the provider throws (never fixture, never stale)', async () => {
    const server = track(
      createCockpitServerFromProvider((): string => {
        throw new Error('boom');
      }),
    );
    server.listen(0, '127.0.0.1');
    const port = await waitListening(server);
    const root = await request(port, 'GET', '/');
    expect(root.status).toBe(500);
    expect(root.body).not.toContain('FIXTURE DATA');
    expect(root.body).not.toContain('LIVE OBSERVATION');
  });
});

// --- DONE-predicate integration (through production AutoflowRuntime) ---------

describe('DONE predicate — live runtime wiring end to end', () => {
  it('no workflow → open → apply, each reflected on the next GET, through the real runtime', async () => {
    const runtime = new AutoflowRuntime();
    const reader = runtime.reader();
    // Cockpit path holds only the reader — open/apply are unreachable from it (DONE 4).
    expect('open' in reader).toBe(false);
    expect('apply' in reader).toBe(false);

    const server = track(startLiveCockpit({ config: baseConfig({ reader }), port: 0 }));
    const port = await waitListening(server);

    // 1) No workflow open: LIVE, honest no-workflow.
    const first = await request(port, 'GET', '/');
    expect(first.status).toBe(200);
    expect(first.body).toContain('LIVE OBSERVATION');
    expect(first.body).not.toContain('FIXTURE DATA');
    expect(first.body).not.toContain('wf-live-0001');

    // 2) Open through the production runtime; next GET reflects the real state.
    const opened = runtime.open(BINDING);
    expect(opened.outcome).toBe('APPLIED');
    const second = await request(port, 'GET', '/');
    expect(second.status).toBe(200);
    expect(second.body).toContain('wf-live-0001');
    expect(second.body).toContain('OPEN');
    expect(second.body).toContain(SHA_A);

    // 3) Apply through the production runtime; next GET reflects the transition.
    const applied = runtime.apply(HEAD_OBSERVED_B);
    expect(applied.outcome).toBe('APPLIED');
    const third = await request(port, 'GET', '/');
    expect(third.status).toBe(200);
    expect(third.body).toContain(SHA_B);
  });

  it('performs one observation capture per GET / and zero for other routes', async () => {
    let observeCalls = 0;
    const runtime = new AutoflowRuntime();
    const server = track(
      startLiveCockpit({
        config: baseConfig({
          reader: runtime.reader(),
          observer: {
            observe: () => {
              observeCalls += 1;
              return REPO_OBSERVATION;
            },
          },
        }),
        port: 0,
      }),
    );
    const port = await waitListening(server);
    observeCalls = 0; // discard the startup readiness probe's capture

    await request(port, 'GET', '/');
    expect(observeCalls).toBe(1);
    await request(port, 'GET', '/styles.css');
    await request(port, 'GET', '/nope');
    await request(port, 'POST', '/');
    expect(observeCalls).toBe(1);
  });
});

// --- failure semantics -------------------------------------------------------

describe('live failure semantics', () => {
  it('repository identity mismatch fails closed with 500 (no fixture)', async () => {
    const runtime = new AutoflowRuntime();
    const server = track(
      startLiveCockpit({
        config: baseConfig({
          reader: runtime.reader(),
          observer: fixedObserver({ ...REPO_OBSERVATION, repositoryId: 'repo-OTHER' }),
        }),
        port: 0,
      }),
    );
    const port = await waitListening(server);
    // current() === null passes the startup probe (valid absence). Now open a
    // workflow whose repositoryId differs from the observer's; D1 rejects.
    runtime.open(BINDING);
    const result = await request(port, 'GET', '/');
    expect(result.status).toBe(500);
    expect(result.body).not.toContain('FIXTURE DATA');
  });

  it('observer failure after startup fails closed with 500, never fixture', async () => {
    let fail = false;
    const runtime = new AutoflowRuntime();
    const server = track(
      startLiveCockpit({
        config: baseConfig({
          reader: runtime.reader(),
          observer: {
            observe: () => {
              if (fail) throw new Error('observer down');
              return REPO_OBSERVATION;
            },
          },
        }),
        port: 0,
      }),
    );
    const port = await waitListening(server);
    fail = true;
    const result = await request(port, 'GET', '/');
    expect(result.status).toBe(500);
    expect(result.body).not.toContain('FIXTURE DATA');
    expect(result.body).not.toContain('LIVE OBSERVATION');
  });

  it('startup readiness probe fails closed: invalid initial state throws before binding', () => {
    const runtime = new AutoflowRuntime();
    runtime.open(BINDING); // repo-agentbridge
    // Observer repo mismatches the already-open workflow, so the startup probe's
    // D1 validation rejects and startLiveCockpit throws — the host never binds.
    expect(() =>
      startLiveCockpit({
        config: baseConfig({
          reader: runtime.reader(),
          observer: fixedObserver({ ...REPO_OBSERVATION, repositoryId: 'repo-OTHER' }),
        }),
        port: 0,
      }),
    ).toThrow();
  });
});

// --- fixture mode unchanged --------------------------------------------------

describe('fixture mode remains unchanged', () => {
  it('renders the deterministic Stage-A fixture page, byte-identical across GETs', async () => {
    const server = track(createCockpitServer());
    server.listen(0, '127.0.0.1');
    const port = await waitListening(server);
    const first = await request(port, 'GET', '/');
    const second = await request(port, 'GET', '/');
    expect(first.status).toBe(200);
    expect(first.body).toContain('FIXTURE DATA');
    expect(first.body).toContain('STAGE A');
    expect(first.body).not.toContain('LIVE OBSERVATION');
    expect(second.body).toBe(first.body);
  });
});

// --- runtime smoke -----------------------------------------------------------

describe('runtime smoke', () => {
  it('serves GET / (LIVE), styles, 404, 405 and shuts down on an ephemeral port', async () => {
    const server = track(startLiveCockpit({ config: baseConfig(), port: 0 }));
    const port = await waitListening(server);
    expect((server.address() as AddressInfo).port).toBe(port);
    expect((await request(port, 'GET', '/')).status).toBe(200);
    expect((await request(port, 'GET', '/styles.css')).status).toBe(200);
    expect((await request(port, 'GET', '/nope')).status).toBe(404);
    expect((await request(port, 'POST', '/')).status).toBe(405);
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
    expect(server.listening).toBe(false);
  });

  it('surfaces EADDRINUSE when a second listener takes an already-bound port', async () => {
    const first = track(http.createServer());
    first.listen(0, '127.0.0.1');
    const port = await waitListening(first);
    const second = track(http.createServer());
    const error = await new Promise<NodeJS.ErrnoException>((resolve) => {
      second.once('error', resolve);
      second.listen(port, '127.0.0.1');
    });
    expect(error.code).toBe('EADDRINUSE');
  });
});
