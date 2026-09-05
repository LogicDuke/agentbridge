/**
 * Live-composition tests for the Autoflow Orchestration Controller milestone.
 *
 * These wire the production shape by hand — one AutoflowRuntime, one
 * AutoflowOrchestrator owning its writer, the Cockpit handed only the reader —
 * and prove a bounded startup open flows through the *same* runtime to the live
 * Cockpit. Manually calling these APIs is a boundary test; it is NOT autonomous
 * production behavior. Nothing here originates any post-start WorkflowEvent.
 */

import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { AutoflowRuntime } from '../../src/autoflow/runtime.js';
import { AutoflowOrchestrator } from '../../src/autoflow/orchestrator.js';
import { readStartupWorkflowConfig, WORKFLOW_OPEN_ENV } from '../../src/runtime/orchestration-input.js';
import {
  createLiveCockpitSource,
  startLiveCockpit,
  type LiveCockpitConfig,
} from '../../src/runtime/live-cockpit.js';
import { createConfiguredRepositoryObserver } from '../../src/runtime/repository-observer.js';
import { readCockpitSnapshot } from '../../src/cockpit/index.js';
import { TRANSITION_OUTCOME } from '../../src/domain/index.js';

const REPO = 'repo-agentbridge';
const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const FIXED_ISO = '2026-09-05T13:00:00.000Z';

const observer = createConfiguredRepositoryObserver({
  repositoryId: REPO,
  observedHeadSha: SHA_A,
  defaultBranchRef: 'refs/heads/main',
});

function configFrom(reader: LiveCockpitConfig['reader']): LiveCockpitConfig {
  return { reader, observer, collectorId: 'agentbridge-live-runtime', clock: (): Date => new Date(FIXED_ISO) };
}

// A production-shaped composition: one runtime, one orchestrator, optional open.
function compose(startupEnv: Record<string, string | undefined>): {
  reader: LiveCockpitConfig['reader'];
  openedOutcome: string | null;
} {
  const runtime = new AutoflowRuntime();
  const orchestrator = new AutoflowOrchestrator(runtime);
  const binding = readStartupWorkflowConfig(startupEnv, REPO);
  let openedOutcome: string | null = null;
  if (binding !== null) {
    openedOutcome = orchestrator.open(binding).outcome;
  }
  return { reader: orchestrator.reader(), openedOutcome };
}

const openConfig = {
  [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-startup-0001',
  [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA_A,
};

const openServers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (s) =>
        new Promise<void>((resolve) => {
          s.close(() => {
            resolve();
          });
        }),
    ),
  );
});
function waitListening(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('listening', () => {
      const a = server.address();
      if (a === null || typeof a === 'string') reject(new Error('no port'));
      else resolve(a.port);
    });
    server.once('error', reject);
  });
}
function get(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => {
        chunks.push(c);
      });
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

describe('live composition — startup-open flows through one runtime to the Cockpit', () => {
  it('no startup config → autoflow stays null (honest no-workflow)', () => {
    const { reader, openedOutcome } = compose({});
    expect(openedOutcome).toBeNull();
    expect(reader.current()).toBeNull();
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(reader)).read());
    expect(read.snapshot).not.toBeNull();
    expect(read.snapshot?.autoflow).toBeNull();
  });

  it('valid startup config → exactly one workflow, reflected through D1 identity/status/revision/sequence', () => {
    const { reader, openedOutcome } = compose(openConfig);
    expect(openedOutcome).toBe(TRANSITION_OUTCOME.APPLIED);
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(reader)).read());
    const autoflow = read.snapshot?.autoflow;
    expect(autoflow).not.toBeNull();
    expect(autoflow?.workflowId).toBe('wf-startup-0001');
    expect(autoflow?.repositoryId).toBe(REPO);
    expect(autoflow?.status).toBe('OPEN');
    expect(autoflow?.revision).toBe(0);
    expect(autoflow?.sequence).toBe(0);
  });

  it('the Cockpit-facing reader cannot open or apply', () => {
    const { reader } = compose(openConfig);
    const asRecord = reader as unknown as Record<string, unknown>;
    expect('open' in reader).toBe(false);
    expect('apply' in reader).toBe(false);
    expect(asRecord['open']).toBeUndefined();
    expect(asRecord['apply']).toBeUndefined();
  });

  it('GET / serves a LIVE 200 page on loopback with the startup workflow, no fixture', async () => {
    const { reader } = compose(openConfig);
    const server = startLiveCockpit({ config: configFrom(reader), port: 0 });
    openServers.push(server);
    const port = await waitListening(server);
    const address = server.address() as AddressInfo;
    expect(address.address).toBe('127.0.0.1');
    const res = await get(port, '/');
    expect(res.status).toBe(200);
    expect(res.body).toMatch(/>LIVE</);
    expect(res.body).not.toMatch(/FIXTURE/); // uppercase provenance marker absent
    // The populated Autoflow panel no longer shows the no-workflow placeholder.
    expect(res.body).not.toContain('Not projected yet');
  });

  it('restart honesty: a fresh composition after a prior active workflow begins null', () => {
    // First composition opens a workflow...
    const first = compose(openConfig);
    expect(first.reader.current()).not.toBeNull();
    // ...a fresh runtime/composition (simulating process restart) with no config
    // starts empty. No persistence, no recovery, no replay.
    const second = compose({});
    expect(second.reader.current()).toBeNull();
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(second.reader)).read());
    expect(read.snapshot?.autoflow).toBeNull();
  });

  it('malformed startup binding → open REJECTED (composition would fail closed)', () => {
    const { openedOutcome } = compose({
      [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: '', // present-but-empty → domain rejects
      [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA_A,
    });
    expect(openedOutcome).toBe(TRANSITION_OUTCOME.REJECTED);
  });
});
