import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { COCKPIT_BOUNDS, readCockpitSnapshot } from '../../src/cockpit/index.js';
import type {
  CockpitFindingReadModel,
  CockpitPullRequestObservation,
} from '../../src/cockpit/index.js';
import {
  produceCockpitSnapshot,
  type CockpitObservation,
} from '../../src/cockpit-snapshot/producer.js';
import type { WorkflowState } from '../../src/domain/workflow.js';
import { buildBinding, openedWorkflow, REPO_A, REPO_B, SHA_A } from '../domain/workflow-fixtures.js';

/**
 * Live Cockpit snapshot producer — unit and adversarial coverage.
 *
 * The producer's job is to serialize one authoritative observation into
 * JSON-shaped data that crosses D1's existing hostile boundary. These tests pin
 * that the produced data (a) is accepted by D1 when well-formed, (b) is rejected
 * by D1 (never by a second reader here) when malformed, (c) carries no live
 * reference across the serialization firewall, and (d) grants no authority.
 */

function workflow(repositoryId: string = REPO_A): WorkflowState {
  return openedWorkflow(buildBinding({ repositoryId }));
}

function observation(overrides: Partial<CockpitObservation> = {}): CockpitObservation {
  return {
    repositoryId: REPO_A,
    observedHeadSha: SHA_A,
    defaultBranchRef: 'refs/heads/main',
    collectorId: 'autoflow-live-collector',
    observedAt: '2026-09-05T00:00:00.000Z',
    autoflow: workflow(REPO_A),
    ...overrides,
  };
}

describe('produceCockpitSnapshot → D1 acceptance', () => {
  it('1. a valid live serialized snapshot is accepted by D1', () => {
    const read = readCockpitSnapshot(produceCockpitSnapshot(observation()));
    expect(read.invalidFields).toEqual([]);
    expect(read.snapshot).not.toBeNull();
    expect(read.snapshot?.schemaVersion).toBe(2);
  });

  it('2. the observed repositoryId binds the reconstructed workflow exactly', () => {
    const read = readCockpitSnapshot(produceCockpitSnapshot(observation()));
    expect(read.snapshot?.repository.repositoryId).toBe(REPO_A);
    expect(read.snapshot?.autoflow?.repositoryId).toBe(REPO_A);
  });

  it('3. a workflow bound to a different repository is rejected whole', () => {
    // envelope repositoryId = REPO_A, but the workflow is REPO_B.
    const read = readCockpitSnapshot(produceCockpitSnapshot(observation({ autoflow: workflow(REPO_B) })));
    expect(read.snapshot).toBeNull();
    expect(read.invalidFields).toContain('autoflow');
  });

  it('5. autoflow:null is accepted as an honest "no workflow observed"', () => {
    const read = readCockpitSnapshot(produceCockpitSnapshot(observation({ autoflow: null })));
    expect(read.invalidFields).toEqual([]);
    expect(read.snapshot?.autoflow).toBeNull();
  });

  it('6. a malformed serialized workflow is rejected by D1 (not by a second reader here)', () => {
    const malformed = { workflowId: '', repositoryId: REPO_A } as unknown as WorkflowState;
    const read = readCockpitSnapshot(produceCockpitSnapshot(observation({ autoflow: malformed })));
    expect(read.snapshot).toBeNull();
    expect(read.invalidFields).toContain('autoflow');
  });

  it('9. an oversized list is rejected by D1, never truncated', () => {
    const tooMany = Array.from({ length: COCKPIT_BOUNDS.MAX_FINDINGS + 1 }, () => ({}));
    const read = readCockpitSnapshot(
      produceCockpitSnapshot(observation({ findings: tooMany as unknown as CockpitFindingReadModel[] })),
    );
    expect(read.snapshot).toBeNull();
    expect(read.invalidFields).toContain('findings');
  });

  it('carries observed read-model lists through to the accepted snapshot', () => {
    const pullRequests: CockpitPullRequestObservation[] = [
      { pullRequestId: 'pr-1', headSha: SHA_A, baseRef: 'refs/heads/main', state: 'open', title: 'A' },
    ];
    const read = readCockpitSnapshot(produceCockpitSnapshot(observation({ pullRequests })));
    expect(read.snapshot?.pullRequests.length).toBe(1);
    expect(read.snapshot?.pullRequests[0]?.pullRequestId).toBe('pr-1');
  });
});

describe('serialization firewall', () => {
  it('20. produced data equals its own JSON round-trip (it is plain JSON)', () => {
    const raw = produceCockpitSnapshot(observation());
    expect(raw).toEqual(JSON.parse(JSON.stringify(raw)));
  });

  it('never hands the live WorkflowState reference into the snapshot', () => {
    const state = workflow(REPO_A);
    const raw = produceCockpitSnapshot(observation({ autoflow: state })) as Record<string, unknown>;
    // A different object, structurally equal to the state's JSON form.
    expect(raw.autoflow).not.toBe(state);
    expect(raw.autoflow).toEqual(JSON.parse(JSON.stringify(state)));
  });

  it('14. is deterministic: equal observations produce equal serialized data', () => {
    expect(produceCockpitSnapshot(observation())).toEqual(produceCockpitSnapshot(observation()));
  });

  it('19. mutating the produced data after ingestion cannot alter the accepted snapshot', () => {
    const raw = produceCockpitSnapshot(observation()) as {
      repository: { repositoryId: string };
      autoflow: { workflowId: string };
    };
    const read = readCockpitSnapshot(raw);
    const acceptedRepo = read.snapshot?.repository.repositoryId;
    const acceptedWorkflowId = read.snapshot?.autoflow?.workflowId;
    // Tamper with the raw producer output after D1 accepted a frozen copy.
    raw.repository.repositoryId = 'tampered';
    raw.autoflow.workflowId = 'tampered';
    expect(read.snapshot?.repository.repositoryId).toBe(acceptedRepo);
    expect(read.snapshot?.autoflow?.workflowId).toBe(acceptedWorkflowId);
    expect(Object.isFrozen(read.snapshot)).toBe(true);
  });
});

describe('producer grants no authority and owns no validation', () => {
  const producerText = readFileSync(
    new URL('../../src/cockpit-snapshot/producer.ts', import.meta.url),
    'utf8',
  );

  it('imports only the Cockpit barrel and the domain workflow type — no transition module', () => {
    const specifiers = [...producerText.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1]);
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) {
      expect(['../cockpit/index.js', '../domain/workflow.js']).toContain(specifier);
    }
    // Neither the transitions module nor the domain barrel (which re-exports the
    // transition entry points) is reachable from here.
    expect(producerText).not.toContain("from '../domain/workflow-transitions");
    expect(producerText).not.toContain("from '../domain/index");
  });

  it('21-24. calls no transition, and imports no I/O, network, git, or subprocess capability', () => {
    // Transition *calls* (with a paren) — the doc comment names them without one.
    expect(/openWorkflow\s*\(/.test(producerText)).toBe(false);
    expect(/applyWorkflowEvent\s*\(/.test(producerText)).toBe(false);
    const forbidden = [
      'node:fs',
      'node:http',
      'child_process',
      'process.env',
      'octokit',
      'simple-git',
      'fetch(',
      'execSync',
      'spawnSync',
      'spawn(',
      'XMLHttpRequest',
      'WebSocket',
      'require(',
    ];
    for (const token of forbidden) {
      expect(producerText.includes(token), `producer must not reference ${token}`).toBe(false);
    }
  });

  it('P2. never nullish-defaults an optional list (only `=== undefined` defaults)', () => {
    // The regressing pattern was `observation.<list> ?? []`, which also swallows
    // an explicit `null`. Pin that no list field uses that nullish default any
    // more. (The regex targets the code shape, so the doc comment that names the
    // old pattern in prose does not trip it.)
    expect(/observation\.\w+\s*\?\?\s*\[\]/.test(producerText)).toBe(false);
    expect(/defaultOptionalList\s*\(/.test(producerText)).toBe(true);
  });
});

describe('P2 — optional lists default only on undefined; null survives to D1', () => {
  // Every optional read-model list the producer serializes.
  const LIST_FIELDS = ['pullRequests', 'evidence', 'findings', 'repairJobs'] as const;

  it('1. an absent (undefined) optional list defaults to [] and is accepted by D1', () => {
    // observation() sets none of the four lists, so each arrives as `undefined`.
    const raw = produceCockpitSnapshot(observation()) as Record<string, unknown>;
    for (const field of LIST_FIELDS) {
      expect(Array.isArray(raw[field]), `${field} should default to []`).toBe(true);
      expect((raw[field] as readonly unknown[]).length).toBe(0);
    }
    const read = readCockpitSnapshot(raw);
    expect(read.invalidFields).toEqual([]);
    expect(read.snapshot).not.toBeNull();
  });

  it.each(LIST_FIELDS)(
    '2+3. explicit null for %s is not normalized to [] and D1 rejects the whole snapshot',
    (field) => {
      const raw = produceCockpitSnapshot(
        observation({ [field]: null } as unknown as Partial<CockpitObservation>),
      ) as Record<string, unknown>;
      // 2. the explicit null survived the producer — it was NOT sanitized to [].
      expect(raw[field]).toBeNull();
      expect(Array.isArray(raw[field])).toBe(false);
      // 3. it reaches D1, which rejects the whole snapshot on that field.
      const read = readCockpitSnapshot(raw);
      expect(read.snapshot).toBeNull();
      expect(read.invalidFields).toContain(field);
    },
  );

  it('4. a valid array is preserved unchanged and accepted', () => {
    const pullRequests: CockpitPullRequestObservation[] = [
      { pullRequestId: 'pr-1', headSha: SHA_A, baseRef: 'refs/heads/main', state: 'open', title: 'A' },
    ];
    const raw = produceCockpitSnapshot(observation({ pullRequests })) as Record<string, unknown>;
    expect(raw.pullRequests).toEqual(pullRequests);
    const read = readCockpitSnapshot(raw);
    expect(read.invalidFields).toEqual([]);
    expect(read.snapshot?.pullRequests.length).toBe(1);
    expect(read.snapshot?.pullRequests[0]?.pullRequestId).toBe('pr-1');
  });
});
