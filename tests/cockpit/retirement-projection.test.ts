import { describe, expect, it } from 'vitest';

import { projectCockpitRetirementAssessments } from '../../src/cockpit/autoflow-projection.js';
import {
  COCKPIT_BOUNDS,
  COCKPIT_SNAPSHOT_FIELD_ORDER,
  COCKPIT_SNAPSHOT_SCHEMA_VERSION,
  readCockpitSnapshot,
} from '../../src/cockpit/read-model.js';
import {
  determinate,
  EVIDENCE_ID_PREFIX,
  GOVERNANCE_HOLD,
  RETIREMENT_BOUNDS,
  RETIREMENT_CLASSIFICATION,
  RETIREMENT_FACT_ORDER,
  RETIREMENT_REASON,
  toFactRecords,
  type RetirementAssessmentEnvelope,
  type RetirementFacts,
} from '../../src/domain/retirement-assessment.js';
import { sha256Canonical } from '../../src/runtime/retirement-assessment-store.js';
import { EVIDENCE_KIND } from '../../src/domain/evidence.js';
import type { WorkflowState } from '../../src/domain/workflow.js';

const REPOSITORY_ID = 'LogicDuke/agentbridge';
const CANDIDATE_SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);

function facts(): RetirementFacts {
  return {
    f1CandidateIdentity: determinate(true),
    f2RemoteAgreement: determinate(true),
    f3StableMain: determinate(true),
    f4Containment: determinate(true),
    f5UniqueCommits: determinate(0),
    f6UniquePatches: determinate(0),
    f7WorktreeClean: determinate(true),
    f8DependencyClearance: determinate(true),
    f9GovernanceManifest: determinate(GOVERNANCE_HOLD.NO_HOLD),
    f10NotProtected: determinate(true),
  };
}

/** A digest-bound envelope, as the store would hand one out. */
function envelope(overrides: Record<string, unknown> = {}): RetirementAssessmentEnvelope {
  const body = {
    repositoryId: REPOSITORY_ID,
    candidateRef: 'refs/heads/repair/example',
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: 'c'.repeat(40),
    facts: toFactRecords(facts()),
    classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
    reasonCodes: [],
    gateRequested: true,
    manifestDigest: EVIDENCE_ID_PREFIX + 'd'.repeat(64),
    generatedAt: '2026-09-18T00:00:00.000Z',
    observerVersion: 'agentbridge-job1-observer/1',
    ...overrides,
  };
  const evidenceId = sha256Canonical(body);
  if (evidenceId === null) {
    throw new Error('fixture body must be canonicalizable');
  }
  return { evidenceId, body } as RetirementAssessmentEnvelope;
}

/** A workflow state carrying one admitted pointer at the current revision. */
function workflow(overrides: Partial<WorkflowState> = {}): WorkflowState {
  return {
    workflowId: 'wf-job1-0001',
    repositoryId: REPOSITORY_ID,
    pullRequestId: null,
    boundCommitSha: CANDIDATE_SHA,
    revision: 0,
    sequence: 1,
    status: 'OPEN',
    closureReason: null,
    humanGateOpenedAtRevision: null,
    invocations: [],
    evidence: [],
    reviews: [],
    ...overrides,
  } as WorkflowState;
}

function admission(evidenceId: string, revision = 0): WorkflowState['evidence'][number] {
  return {
    evidenceId,
    kind: EVIDENCE_KIND.REPOSITORY_STATE,
    admittedAtCommitSha: CANDIDATE_SHA,
    admittedAtRevision: revision,
    admittedAtSequence: 1,
  };
}

/* ------------------------------------------------------------------------- *
 * D1 — schema v3
 * ------------------------------------------------------------------------- */

function rawSnapshot(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: COCKPIT_SNAPSHOT_SCHEMA_VERSION,
    repository: {
      repositoryId: REPOSITORY_ID,
      observedHeadSha: CANDIDATE_SHA,
      defaultBranchRef: 'refs/heads/main',
    },
    provenance: { collectorId: 'test', observedAt: '2026-09-18T00:00:00.000Z' },
    pullRequests: [],
    evidence: [],
    findings: [],
    repairJobs: [],
    autoflow: null,
    retirementAssessments: [],
    ...overrides,
  };
}

describe('D1 schema v3 — the retirementAssessments field', () => {
  it('pins the schema version at 3 and reports the field last', () => {
    expect(COCKPIT_SNAPSHOT_SCHEMA_VERSION).toBe(3);
    expect(COCKPIT_SNAPSHOT_FIELD_ORDER.at(-1)).toBe('retirementAssessments');
  });

  it('pins the list bound to the domain kernel bound', () => {
    expect(COCKPIT_BOUNDS.MAX_RETIREMENT_ASSESSMENTS).toBe(RETIREMENT_BOUNDS.MAX_ASSESSMENTS);
  });

  it('accepts an empty list — the ordinary "no assessment" case', () => {
    const result = readCockpitSnapshot(rawSnapshot());
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot?.retirementAssessments).toEqual([]);
  });

  it('accepts a well-formed assessment', () => {
    const result = readCockpitSnapshot(
      rawSnapshot({ retirementAssessments: [JSON.parse(JSON.stringify(envelope())) as unknown] }),
    );
    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot?.retirementAssessments).toHaveLength(1);
  });

  it('rejects the whole snapshot when the field is ABSENT', () => {
    const raw = rawSnapshot();
    delete raw['retirementAssessments'];
    const result = readCockpitSnapshot(raw);
    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toContain('retirementAssessments');
  });

  it('rejects null, a non-array, and an inherited list', () => {
    for (const value of [null, {}, 'x', 42]) {
      const result = readCockpitSnapshot(rawSnapshot({ retirementAssessments: value }));
      expect(result.snapshot, JSON.stringify(value)).toBeNull();
      expect(result.invalidFields).toContain('retirementAssessments');
    }
  });

  it('rejects an oversized list rather than truncating it', () => {
    const many = Array.from({ length: COCKPIT_BOUNDS.MAX_RETIREMENT_ASSESSMENTS + 1 }, () =>
      JSON.parse(JSON.stringify(envelope())) as unknown,
    );
    const result = readCockpitSnapshot(rawSnapshot({ retirementAssessments: many }));
    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toContain('retirementAssessments');
  });

  it('rejects a malformed evidence id — D1 enforces the format', () => {
    const bad = JSON.parse(JSON.stringify(envelope())) as Record<string, unknown>;
    bad['evidenceId'] = 'not-an-id';
    const result = readCockpitSnapshot(rawSnapshot({ retirementAssessments: [bad] }));
    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toContain('retirementAssessments');
  });

  it('rejects an assessment bound to a DIFFERENT repository — D1 enforces the binding', () => {
    const foreign = JSON.parse(
      JSON.stringify(envelope({ repositoryId: 'someone/else' })),
    ) as Record<string, unknown>;
    const result = readCockpitSnapshot(rawSnapshot({ retirementAssessments: [foreign] }));
    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toContain('retirementAssessments');
  });

  it('rejects one malformed entry among valid ones — all or nothing', () => {
    const good = JSON.parse(JSON.stringify(envelope())) as unknown;
    const result = readCockpitSnapshot(rawSnapshot({ retirementAssessments: [good, { junk: 1 }] }));
    expect(result.snapshot).toBeNull();
  });

  it('rejects every schema version but 3', () => {
    for (const schemaVersion of [1, 2, 4, '3', null]) {
      const result = readCockpitSnapshot(rawSnapshot({ schemaVersion }));
      expect(result.snapshot, String(schemaVersion)).toBeNull();
      expect(result.invalidFields).toContain('schemaVersion');
    }
  });

  it('survives a plain-JSON round trip unchanged', () => {
    const result = readCockpitSnapshot(
      rawSnapshot({ retirementAssessments: [JSON.parse(JSON.stringify(envelope())) as unknown] }),
    );
    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    if (snapshot !== null) {
      expect(JSON.parse(JSON.stringify(snapshot))).toEqual(JSON.parse(JSON.stringify(snapshot)));
    }
  });

  it('never throws on hostile input', () => {
    const hostile = rawSnapshot();
    Object.defineProperty(hostile, 'retirementAssessments', {
      get(): never {
        throw new Error('boom');
      },
      configurable: true,
    });
    expect(() => readCockpitSnapshot(hostile)).not.toThrow();
    expect(readCockpitSnapshot(hostile).snapshot).toBeNull();
  });
});

/* ------------------------------------------------------------------------- *
 * D4 — integrity step I4
 * ------------------------------------------------------------------------- */

describe('D4 sub-projection — I4', () => {
  it('projects when the pointer, the revision, and the candidate SHA all line up', () => {
    const item = envelope();
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    expect(projection.integrityFailure).toBe(false);
    expect(projection.pointerId).toBe(item.evidenceId);
    expect(projection.assessment?.classification).toBe(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE);
    expect(projection.assessment?.facts).toHaveLength(RETIREMENT_FACT_ORDER.length);
  });

  it('projects nothing when no workflow was observed', () => {
    const projection = projectCockpitRetirementAssessments([envelope()], null);
    expect(projection).toEqual({ assessment: null, integrityFailure: false, pointerId: null });
  });

  it('projects nothing when no pointer was admitted at all', () => {
    const projection = projectCockpitRetirementAssessments([envelope()], workflow());
    expect(projection).toEqual({ assessment: null, integrityFailure: false, pointerId: null });
  });

  it('projects nothing when the pointer was admitted at an EARLIER revision', () => {
    const item = envelope();
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ revision: 1, evidence: [admission(item.evidenceId, 0)] }),
    );
    expect(projection.assessment).toBeNull();
    expect(projection.integrityFailure).toBe(false);
  });

  it('records an integrity failure when a pointer has no verified body behind it', () => {
    // The store omitted the body (I3 failed), so the list is empty while the
    // admitted pointer remains a true historical fact.
    const item = envelope();
    const projection = projectCockpitRetirementAssessments(
      [],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    expect(projection.integrityFailure).toBe(true);
    expect(projection.pointerId).toBe(item.evidenceId);
    // The classification is WITHHELD — never reinterpreted.
    expect(projection.assessment).toBeNull();
  });

  it('records an integrity failure when the body is bound to a DIFFERENT commit', () => {
    const item = envelope({ candidateSha: OTHER_SHA });
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    expect(projection.integrityFailure).toBe(true);
    expect(projection.assessment).toBeNull();
  });

  it('records an integrity failure when the only envelope carries a different id', () => {
    const admitted = envelope();
    const other = envelope({ generatedAt: '2026-09-18T01:00:00.000Z' });
    const projection = projectCockpitRetirementAssessments(
      [other],
      workflow({ evidence: [admission(admitted.evidenceId)] }),
    );
    expect(projection.integrityFailure).toBe(true);
    expect(projection.pointerId).toBe(admitted.evidenceId);
  });

  it('never turns an integrity failure into a classification', () => {
    const item = envelope();
    const projection = projectCockpitRetirementAssessments(
      [],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    expect(projection.assessment).toBeNull();
    expect(JSON.stringify(projection)).not.toContain('BLOCKED');
    expect(JSON.stringify(projection)).not.toContain('RETIRE_ELIGIBLE');
  });

  it('echoes the body verbatim and derives no verdict of its own', () => {
    const item = envelope({
      classification: RETIREMENT_CLASSIFICATION.BLOCKED,
      gateRequested: false,
      reasonCodes: [RETIREMENT_REASON.INDETERMINATE_FACT],
    });
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    expect(projection.assessment?.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(projection.assessment?.reasonCodes).toEqual([RETIREMENT_REASON.INDETERMINATE_FACT]);
    expect(projection.assessment?.gateRequested).toBe(false);
  });

  it('carries no authority-shaped field', () => {
    const item = envelope();
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    const serialized = JSON.stringify(projection);
    for (const forbidden of [
      'mayDelete',
      'authorized',
      'approved',
      'permit',
      'nextAction',
      'ready',
      'AUTHORIZED_TO_DELETE',
    ]) {
      expect(serialized, forbidden).not.toContain(forbidden);
    }
  });

  it('returns a deeply frozen, JSON-round-trippable projection', () => {
    const item = envelope();
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    expect(Object.isFrozen(projection)).toBe(true);
    expect(Object.isFrozen(projection.assessment)).toBe(true);
    expect(JSON.parse(JSON.stringify(projection))).toEqual(
      JSON.parse(JSON.stringify(projection)),
    );
  });

  it('renders an indeterminate fact value as null, not as a stale reading', () => {
    const item = envelope({
      facts: toFactRecords({ ...facts(), f1CandidateIdentity: { determinate: false } }),
      classification: RETIREMENT_CLASSIFICATION.BLOCKED,
      gateRequested: false,
      reasonCodes: [RETIREMENT_REASON.INDETERMINATE_FACT],
    });
    const projection = projectCockpitRetirementAssessments(
      [item],
      workflow({ evidence: [admission(item.evidenceId)] }),
    );
    const first = projection.assessment?.facts[0];
    expect(first?.key).toBe('f1CandidateIdentity');
    expect(first?.determinate).toBe(false);
    expect(first?.value).toBeNull();
  });
});
