import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  buildDashboardHtml,
  createCockpitServer,
  FIXTURE_SOURCE,
  type CockpitSource,
} from '../../src/cockpit-host/server.js';
import { produceCockpitSnapshot, type CockpitObservation } from '../../src/cockpit-snapshot/producer.js';
import type { WorkflowState } from '../../src/domain/workflow.js';
import { buildBinding, openedWorkflow, REPO_A, SHA_A } from '../domain/workflow-fixtures.js';

/**
 * Host live-source seam — ingestion, provenance labeling, and fail-closed.
 *
 * The host chooses a source through the explicit {@link CockpitSource} seam. A
 * `live` source's serialized snapshot crosses the same D1 boundary the fixture
 * does; a failed or malformed `live` source fails closed and is never silently
 * replaced by the fixture; and the page's provenance labeling is derived from the
 * selected source, never from static text.
 */

function liveObservation(
  autoflow: WorkflowState | null = openedWorkflow(buildBinding({ repositoryId: REPO_A })),
): CockpitObservation {
  return {
    repositoryId: REPO_A,
    observedHeadSha: SHA_A,
    defaultBranchRef: 'refs/heads/main',
    collectorId: 'autoflow-live-collector',
    observedAt: '2026-09-05T00:00:00.000Z',
    autoflow,
  };
}

function liveSource(autoflow?: WorkflowState | null): CockpitSource {
  return { mode: 'live', read: (): unknown => produceCockpitSnapshot(liveObservation(autoflow)) };
}

describe('live source — valid ingestion (4)', () => {
  it('renders the workflow projected from a live serialized snapshot', () => {
    const html = buildDashboardHtml(liveSource());
    expect(html).toContain('wf-0001');
    expect(html).toContain('Bound commit SHA');
    expect(html).toContain('autoflow-live-collector');
  });

  it('5. renders an honest absence panel when the live workflow is null', () => {
    const html = buildDashboardHtml(liveSource(null));
    expect(html).toContain('Not projected yet');
    expect(html).not.toContain('Bound commit SHA');
  });
});

describe('live source — provenance labeling (11, 12, 13)', () => {
  const liveHtml = buildDashboardHtml(liveSource());
  const fixtureHtml = buildDashboardHtml(FIXTURE_SOURCE);

  it('11. fixture mode is clearly labeled as fixture/development data', () => {
    expect(fixtureHtml).toContain('STAGE A');
    expect(fixtureHtml).toContain('FIXTURE DATA');
    expect(fixtureHtml).not.toContain('LIVE OBSERVATION');
  });

  it('12. live mode is clearly labeled as a live observation', () => {
    expect(liveHtml).toContain('LIVE');
    expect(liveHtml).toContain('LIVE OBSERVATION');
  });

  it('13. a live page carries no false fixture/Stage-A/not-live label', () => {
    expect(liveHtml).not.toContain('FIXTURE DATA');
    expect(liveHtml).not.toContain('STAGE A');
    expect(liveHtml).not.toContain('Stage A');
    expect(liveHtml).not.toContain('not live');
  });

  it('the two modes are mechanically distinguishable', () => {
    expect(liveHtml).not.toEqual(fixtureHtml);
    expect(liveHtml.includes('LIVE OBSERVATION')).not.toBe(fixtureHtml.includes('LIVE OBSERVATION'));
    expect(liveHtml.includes('FIXTURE DATA')).not.toBe(fixtureHtml.includes('FIXTURE DATA'));
  });
});

describe('live source — fail closed, no silent fixture fallback (8, 10)', () => {
  it('8. a malformed live snapshot fails closed (refuses to serve)', () => {
    const malformed: CockpitSource = { mode: 'live', read: (): unknown => ({ schemaVersion: 1 }) };
    expect(() => buildDashboardHtml(malformed)).toThrow(/failed D1 validation/);
  });

  it('10. an unavailable live source throws and never substitutes the fixture', () => {
    const unavailable: CockpitSource = {
      mode: 'live',
      read: (): unknown => {
        throw new Error('live source unavailable');
      },
    };
    // It must surface the failure, not fall back to fixture bytes.
    let served: string | null = null;
    expect(() => {
      served = buildDashboardHtml(unavailable);
    }).toThrow();
    expect(served).toBeNull();
    // createCockpitServer builds the page eagerly, so it fails closed too.
    expect(() => createCockpitServer(unavailable)).toThrow();
  });
});

describe('live source — determinism (14)', () => {
  it('repeated builds of the same live source are byte-identical', () => {
    expect(buildDashboardHtml(liveSource())).toEqual(buildDashboardHtml(liveSource()));
  });
});

describe('live source — served over the loopback host (ephemeral port, not 4317)', () => {
  let base = '';
  const server = createCockpitServer(liveSource());

  beforeAll(async () => {
    await new Promise<void>((resolve) => {
      // Ephemeral port on loopback: never touches the fixed 4317 runtime.
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (address === null || typeof address === 'string') {
      throw new Error('expected an AddressInfo from server.address()');
    }
    const info: AddressInfo = address;
    base = `http://127.0.0.1:${String(info.port)}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error === undefined) {
          resolve();
        } else {
          reject(error);
        }
      });
    });
  });

  it('serves the live-labeled page with GET-only, read-only semantics preserved', async () => {
    const response = await fetch(`${base}/`);
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain('READ ONLY');
    expect(body).toContain('LIVE OBSERVATION');
    expect(body).not.toContain('FIXTURE DATA');
    expect(body).toContain('wf-0001');

    const post = await fetch(`${base}/`, { method: 'POST' });
    expect(post.status).toBe(405);
  });
});
