import { describe, expect, it } from 'vitest';

import {
  determinate,
  EVIDENCE_ID_PREFIX,
  GOVERNANCE_HOLD,
  RETIREMENT_CLASSIFICATION,
  toFactRecords,
  type RetirementAssessmentBody,
  type RetirementAssessmentEnvelope,
  type RetirementFacts,
} from '../../src/domain/retirement-assessment.js';
import {
  createRetirementAssessmentStore,
  sha256Canonical,
  STORE_REFUSAL,
} from '../../src/runtime/retirement-assessment-store.js';

const CANDIDATE_SHA = 'a'.repeat(40);

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

function body(overrides: Partial<RetirementAssessmentBody> = {}): RetirementAssessmentBody {
  return {
    repositoryId: 'LogicDuke/agentbridge',
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
}

/** Build a correctly bound envelope: the pointer IS the digest of the body. */
function bound(overrides: Partial<RetirementAssessmentBody> = {}): RetirementAssessmentEnvelope {
  const value = body(overrides);
  const evidenceId = sha256Canonical(value);
  if (evidenceId === null) {
    throw new Error('fixture body must be canonicalizable');
  }
  return { evidenceId, body: value };
}

describe('sha256Canonical', () => {
  it('produces a well-formed, stable pointer', () => {
    const digest = sha256Canonical(body());
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(sha256Canonical(body())).toBe(digest);
  });

  it('gives two key orderings of one content the same digest', () => {
    expect(sha256Canonical({ a: 1, b: 2 })).toBe(sha256Canonical({ b: 2, a: 1 }));
  });

  it('gives different content different digests', () => {
    expect(sha256Canonical(body())).not.toBe(
      sha256Canonical(body({ generatedAt: '2026-09-18T00:00:01.000Z' })),
    );
  });

  it('returns null for a body with no canonical form', () => {
    expect(sha256Canonical({ when: new Date(0) })).toBeNull();
    expect(sha256Canonical({ ratio: 1.5 })).toBeNull();
  });
});

describe('store — I2 (put)', () => {
  it('admits a correctly bound envelope', () => {
    const store = createRetirementAssessmentStore();
    const result = store.put(bound());
    expect(result.stored).toBe(true);
    expect(result.refusal).toBeNull();
  });

  it('refuses an envelope whose pointer is not the digest of its body', () => {
    const store = createRetirementAssessmentStore();
    const unbound = { evidenceId: EVIDENCE_ID_PREFIX + '0'.repeat(64), body: body() };
    const result = store.put(unbound);
    expect(result.stored).toBe(false);
    expect(result.refusal).toBe(STORE_REFUSAL.UNBOUND_ENVELOPE);
    expect(store.list()).toEqual([]);
  });

  it('refuses a body with no canonical form', () => {
    const store = createRetirementAssessmentStore();
    const result = store.put({
      evidenceId: EVIDENCE_ID_PREFIX + '0'.repeat(64),
      body: { when: new Date(0) } as unknown as RetirementAssessmentBody,
    });
    expect(result.stored).toBe(false);
    expect(result.refusal).toBe(STORE_REFUSAL.NOT_CANONICALIZABLE);
  });

  it('is idempotent on the identical envelope', () => {
    const store = createRetirementAssessmentStore();
    const envelope = bound();
    expect(store.put(envelope).stored).toBe(true);
    expect(store.put(envelope).stored).toBe(true);
    expect(store.list()).toHaveLength(1);
  });

  it('refuses a SECOND, distinct assessment and never clobbers the first', () => {
    const store = createRetirementAssessmentStore();
    const first = bound();
    const second = bound({ generatedAt: '2026-09-18T01:00:00.000Z' });
    expect(store.put(first).stored).toBe(true);

    const result = store.put(second);
    expect(result.stored).toBe(false);
    expect(result.refusal).toBe(STORE_REFUSAL.SECOND_ASSESSMENT_REFUSED);

    // The first is still the one held, unchanged.
    expect(store.list()).toHaveLength(1);
    expect(store.get(first.evidenceId)).not.toBeNull();
    expect(store.get(second.evidenceId)).toBeNull();
  });
});

describe('store — I3 (recompute on every read)', () => {
  it('returns the envelope while it is still bound', () => {
    const store = createRetirementAssessmentStore();
    const envelope = bound();
    store.put(envelope);
    expect(store.get(envelope.evidenceId)).toBe(envelope);
    expect(store.integrityFaultCount()).toBe(0);
  });

  it('returns nothing for an unknown or malformed id', () => {
    const store = createRetirementAssessmentStore();
    store.put(bound());
    expect(store.get(EVIDENCE_ID_PREFIX + 'f'.repeat(64))).toBeNull();
    expect(store.get('not-an-id')).toBeNull();
  });

  it('stops returning a body that was mutated after admission, and records a fault', () => {
    const store = createRetirementAssessmentStore();
    // A mutable body: the store must not rely on the caller having frozen it.
    const mutable = body() as { generatedAt: string };
    const evidenceId = sha256Canonical(mutable);
    if (evidenceId === null) {
      throw new Error('fixture must canonicalize');
    }
    store.put({ evidenceId, body: mutable as RetirementAssessmentBody });
    expect(store.get(evidenceId)).not.toBeNull();

    mutable.generatedAt = '2026-09-18T09:99:99.000Z';

    expect(store.get(evidenceId)).toBeNull();
    expect(store.integrityFaultCount()).toBe(1);
    // The binding is re-proved every time, not cached from the first failure.
    expect(store.get(evidenceId)).toBeNull();
    expect(store.integrityFaultCount()).toBe(2);
  });

  it('omits an unbound body from list() rather than showing it', () => {
    const store = createRetirementAssessmentStore();
    const mutable = body() as { generatedAt: string };
    const evidenceId = sha256Canonical(mutable);
    if (evidenceId === null) {
      throw new Error('fixture must canonicalize');
    }
    store.put({ evidenceId, body: mutable as RetirementAssessmentBody });
    expect(store.list()).toHaveLength(1);

    mutable.generatedAt = 'tampered';

    expect(store.list()).toEqual([]);
    expect(store.integrityFaultCount()).toBe(1);
  });

  it('never reinterprets an integrity failure as a classification', () => {
    const store = createRetirementAssessmentStore();
    const mutable = body({
      classification: RETIREMENT_CLASSIFICATION.BLOCKED,
      gateRequested: false,
    }) as { classification: string };
    const evidenceId = sha256Canonical(mutable);
    if (evidenceId === null) {
      throw new Error('fixture must canonicalize');
    }
    store.put({ evidenceId, body: mutable as RetirementAssessmentBody });
    // An attacker rewrites BLOCKED -> RETIRE_ELIGIBLE in place.
    mutable.classification = RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE;

    // The store returns *nothing*. It does not return a BLOCKED assessment, and
    // it certainly does not return the rewritten one.
    expect(store.get(evidenceId)).toBeNull();
    expect(store.list()).toEqual([]);
  });
});

describe('store — surface', () => {
  it('exposes only the four read/write verbs and is frozen', () => {
    const store = createRetirementAssessmentStore();
    expect(Object.isFrozen(store)).toBe(true);
    expect(Object.keys(store).sort()).toEqual(['get', 'integrityFaultCount', 'list', 'put']);
  });

  it('returns a frozen list', () => {
    const store = createRetirementAssessmentStore();
    store.put(bound());
    expect(Object.isFrozen(store.list())).toBe(true);
  });

  it('keeps two stores independent — no module-level state', () => {
    const a = createRetirementAssessmentStore();
    const b = createRetirementAssessmentStore();
    a.put(bound());
    expect(a.list()).toHaveLength(1);
    expect(b.list()).toHaveLength(0);
  });
});
