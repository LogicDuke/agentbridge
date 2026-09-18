import { describe, expect, it } from 'vitest';

import {
  canonicalizeAssessmentBody,
  classifyRetirementCandidate,
  determinate,
  EVIDENCE_ID_PREFIX,
  GOVERNANCE_HOLD,
  INDETERMINATE,
  readEvidenceId,
  readRetirementAssessment,
  RETIREMENT_BOUNDS,
  RETIREMENT_CLASSIFICATION,
  RETIREMENT_FACT_ORDER,
  RETIREMENT_REASON,
  toFactRecords,
  type RetirementFacts,
} from '../../src/domain/retirement-assessment.js';

/** Facts for a candidate that satisfies every RETIRE_ELIGIBLE condition. */
function eligibleFacts(overrides: Partial<RetirementFacts> = {}): RetirementFacts {
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
    ...overrides,
  };
}

const SHA_A = 'a'.repeat(40);
const VALID_ID = EVIDENCE_ID_PREFIX + 'b'.repeat(64);

describe('classifyRetirementCandidate — purity', () => {
  it('takes exactly one argument: the fact set, and nothing else', () => {
    // Structural, not documentary. A digest, an admission pointer, or a
    // projection state cannot be a classifier input because there is no second
    // parameter for one to arrive through.
    expect(classifyRetirementCandidate.length).toBe(1);
  });

  it('exposes no digest-, admission-, or projection-shaped key on its input', () => {
    const forbidden = [
      'evidenceId',
      'digest',
      'sha256',
      'admitted',
      'admission',
      'projected',
      'pointer',
      'classification',
    ];
    for (const key of forbidden) {
      expect(RETIREMENT_FACT_ORDER).not.toContain(key);
    }
  });

  it('is deterministic: equal inputs yield an equal verdict', () => {
    const facts = eligibleFacts();
    expect(classifyRetirementCandidate(facts)).toEqual(classifyRetirementCandidate(facts));
  });

  it('returns a deeply frozen verdict', () => {
    const verdict = classifyRetirementCandidate(eligibleFacts());
    expect(Object.isFrozen(verdict)).toBe(true);
    expect(Object.isFrozen(verdict.reasonCodes)).toBe(true);
  });
});

describe('classifyRetirementCandidate — RETIRE_ELIGIBLE', () => {
  it('classifies a fully clear candidate as RETIRE_ELIGIBLE and requests the gate', () => {
    const verdict = classifyRetirementCandidate(eligibleFacts());
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE);
    expect(verdict.gateRequested).toBe(true);
    expect(verdict.reasonCodes).toEqual([]);
  });

  it('sets gateRequested exactly when the classification is RETIRE_ELIGIBLE', () => {
    for (const facts of [
      eligibleFacts(),
      eligibleFacts({ f5UniqueCommits: determinate(1), f4Containment: determinate(false) }),
      eligibleFacts({ f1CandidateIdentity: determinate(false) }),
      eligibleFacts({ f9GovernanceManifest: INDETERMINATE }),
    ]) {
      const verdict = classifyRetirementCandidate(facts);
      expect(verdict.gateRequested).toBe(
        verdict.classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
      );
    }
  });
});

describe('classifyRetirementCandidate — BLOCKED', () => {
  it('blocks when ANY single fact is indeterminate', () => {
    for (const key of RETIREMENT_FACT_ORDER) {
      const verdict = classifyRetirementCandidate(
        eligibleFacts({ [key]: INDETERMINATE } as Partial<RetirementFacts>),
      );
      expect(verdict.classification, `${key} indeterminate must block`).toBe(
        RETIREMENT_CLASSIFICATION.BLOCKED,
      );
      expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.INDETERMINATE_FACT);
      expect(verdict.gateRequested).toBe(false);
    }
  });

  it('blocks on each false blocking fact, with its own reason code', () => {
    const cases: readonly [keyof RetirementFacts, string][] = [
      ['f1CandidateIdentity', RETIREMENT_REASON.CANDIDATE_IDENTITY_MISMATCH],
      ['f2RemoteAgreement', RETIREMENT_REASON.REMOTE_DISAGREEMENT],
      ['f3StableMain', RETIREMENT_REASON.MAIN_UNSTABLE],
      ['f7WorktreeClean', RETIREMENT_REASON.WORKTREE_NOT_CLEAN],
      ['f8DependencyClearance', RETIREMENT_REASON.DEPENDENCY_CLEARANCE_FAILED],
      ['f10NotProtected', RETIREMENT_REASON.PROTECTED_OR_DEFAULT_BRANCH],
    ];
    for (const [key, reason] of cases) {
      const verdict = classifyRetirementCandidate(
        eligibleFacts({ [key]: determinate(false) } as Partial<RetirementFacts>),
      );
      expect(verdict.classification, `${key} false must block`).toBe(
        RETIREMENT_CLASSIFICATION.BLOCKED,
      );
      expect(verdict.reasonCodes).toContain(reason);
    }
  });

  it('blocks a containment/count contradiction rather than preferring either reading', () => {
    // Contained, yet carrying unique commits: two determinate facts disagree.
    const verdict = classifyRetirementCandidate(
      eligibleFacts({ f4Containment: determinate(true), f5UniqueCommits: determinate(3) }),
    );
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.INTERNAL_CONTRADICTION);
  });

  it('blocks "not contained" with zero unique commits — the other direction', () => {
    const verdict = classifyRetirementCandidate(
      eligibleFacts({ f4Containment: determinate(false), f5UniqueCommits: determinate(0) }),
    );
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.INTERNAL_CONTRADICTION);
  });

  it('blocks when the patch count exceeds the commit count it is drawn from', () => {
    const verdict = classifyRetirementCandidate(
      eligibleFacts({
        f4Containment: determinate(false),
        f5UniqueCommits: determinate(1),
        f6UniquePatches: determinate(2),
      }),
    );
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.INTERNAL_CONTRADICTION);
  });

  it('never yields a classification outside the closed vocabulary', () => {
    const values = [determinate(true), determinate(false), INDETERMINATE];
    // Exhaustive over the six boolean blocking facts (2^6 x indeterminate mix is
    // bounded by sampling each fact through all three shapes).
    for (const key of RETIREMENT_FACT_ORDER) {
      for (const value of values) {
        const verdict = classifyRetirementCandidate(
          eligibleFacts({ [key]: value } as Partial<RetirementFacts>),
        );
        expect(Object.values(RETIREMENT_CLASSIFICATION)).toContain(verdict.classification);
      }
    }
  });
});

describe('classifyRetirementCandidate — PRESERVE_FOR_HISTORY', () => {
  it('preserves a non-contained candidate carrying unique commits and patches', () => {
    const verdict = classifyRetirementCandidate(
      eligibleFacts({
        f4Containment: determinate(false),
        f5UniqueCommits: determinate(4),
        f6UniquePatches: determinate(2),
      }),
    );
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY);
    expect(verdict.gateRequested).toBe(false);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.UNIQUE_PATCHES_PRESENT);
  });

  it('preserves on a governance HOLD even when everything else is clear', () => {
    const verdict = classifyRetirementCandidate(
      eligibleFacts({ f9GovernanceManifest: determinate(GOVERNANCE_HOLD.HOLD) }),
    );
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.GOVERNANCE_HOLD);
  });

  it('BLOCKED outranks PRESERVE_FOR_HISTORY', () => {
    // A hold *and* a false blocking fact: precedence puts BLOCKED first.
    const verdict = classifyRetirementCandidate(
      eligibleFacts({
        f9GovernanceManifest: determinate(GOVERNANCE_HOLD.HOLD),
        f7WorktreeClean: determinate(false),
      }),
    );
    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
  });
});

describe('canonicalizeAssessmentBody — AB-CJSON-1', () => {
  it('sorts object keys by UTF-16 code unit at every depth, with no whitespace', () => {
    expect(canonicalizeAssessmentBody({ b: 1, a: 2, A: 3 })).toBe('{"A":3,"a":2,"b":1}');
    expect(canonicalizeAssessmentBody({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });

  it('preserves array order — arrays are never sorted', () => {
    expect(canonicalizeAssessmentBody(['b', 'a', 'c'])).toBe('["b","a","c"]');
  });

  it('accepts exactly string, safe integer, boolean, and null scalars', () => {
    expect(canonicalizeAssessmentBody('x')).toBe('"x"');
    expect(canonicalizeAssessmentBody(42)).toBe('42');
    expect(canonicalizeAssessmentBody(-7)).toBe('-7');
    expect(canonicalizeAssessmentBody(true)).toBe('true');
    expect(canonicalizeAssessmentBody(false)).toBe('false');
    expect(canonicalizeAssessmentBody(null)).toBe('null');
  });

  it('rejects every non-canonicalizable scalar rather than coercing it', () => {
    for (const value of [
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      -0,
      undefined,
      Symbol('s'),
      (): void => undefined,
      10n,
      new Date(0),
      new Map(),
    ]) {
      expect(canonicalizeAssessmentBody(value), typeof value).toBeNull();
    }
  });

  it('rejects a cycle instead of throwing', () => {
    const node: Record<string, unknown> = {};
    node['self'] = node;
    expect(canonicalizeAssessmentBody(node)).toBeNull();
  });

  it('rejects a sparse array hole — a hole is not null', () => {
    const sparse = [1, 2, 3];
    // eslint-disable-next-line @typescript-eslint/no-array-delete
    delete sparse[1];
    expect(canonicalizeAssessmentBody(sparse)).toBeNull();
  });

  it('rejects a value that exceeds a declared bound', () => {
    const deep = { a: { a: { a: { a: { a: { a: { a: { a: { a: { a: 1 } } } } } } } } } };
    expect(canonicalizeAssessmentBody(deep)).toBeNull();
    expect(
      canonicalizeAssessmentBody('x'.repeat(RETIREMENT_BOUNDS.MAX_CANONICAL_STRING_LENGTH + 1)),
    ).toBeNull();
  });

  it('canonicalizes a plain object and a null-prototype record, and nothing else', () => {
    expect(canonicalizeAssessmentBody({ own: 1 })).toBe('{"own":1}');
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, { own: 1 });
    expect(canonicalizeAssessmentBody(bare)).toBe('{"own":1}');
  });

  it('rejects an object carrying a custom prototype chain', () => {
    // Stricter than "ignore inherited keys": an object whose prototype is
    // neither `Object.prototype` nor `null` is refused outright, so no
    // inherited behaviour can influence the canonical bytes at all.
    const parent = { inherited: 'nope' };
    const child = Object.create(parent) as Record<string, unknown>;
    child['own'] = 1;
    expect(canonicalizeAssessmentBody(child)).toBeNull();
  });

  it('gives two key orderings of the same content one canonical form', () => {
    expect(canonicalizeAssessmentBody({ a: 1, b: 2 })).toBe(
      canonicalizeAssessmentBody({ b: 2, a: 1 }),
    );
  });
});

describe('readEvidenceId', () => {
  it('accepts exactly sha256: + 64 lowercase hex', () => {
    expect(readEvidenceId(VALID_ID)).toBe(VALID_ID);
  });

  it('rejects wrong prefix, wrong length, uppercase hex, and non-strings', () => {
    for (const value of [
      'sha1:' + 'b'.repeat(64),
      EVIDENCE_ID_PREFIX + 'b'.repeat(63),
      EVIDENCE_ID_PREFIX + 'b'.repeat(65),
      EVIDENCE_ID_PREFIX + 'B'.repeat(64),
      EVIDENCE_ID_PREFIX + 'g'.repeat(64),
      ' ' + VALID_ID,
      VALID_ID + ' ',
      null,
      undefined,
      42,
      {},
    ]) {
      expect(readEvidenceId(value), JSON.stringify(value)).toBeNull();
    }
  });
});

describe('readRetirementAssessment', () => {
  function body(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      repositoryId: 'LogicDuke/agentbridge',
      candidateRef: 'refs/heads/repair/example',
      candidateSha: SHA_A,
      authoritativeMainSha: 'c'.repeat(40),
      facts: toFactRecords(eligibleFacts()),
      classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
      reasonCodes: [],
      gateRequested: true,
      manifestDigest: EVIDENCE_ID_PREFIX + 'd'.repeat(64),
      generatedAt: '2026-09-18T00:00:00.000Z',
      observerVersion: 'agentbridge-job1-observer/1',
      ...overrides,
    };
  }

  it('accepts a well-formed envelope and returns a frozen copy', () => {
    const envelope = readRetirementAssessment({ evidenceId: VALID_ID, body: body() });
    expect(envelope).not.toBeNull();
    expect(envelope?.evidenceId).toBe(VALID_ID);
    expect(Object.isFrozen(envelope)).toBe(true);
    expect(Object.isFrozen(envelope?.body)).toBe(true);
  });

  it('rejects a malformed evidence id', () => {
    expect(readRetirementAssessment({ evidenceId: 'nope', body: body() })).toBeNull();
  });

  it('rejects a body whose gateRequested disagrees with its classification', () => {
    // The crafted case that matters: a BLOCKED body claiming a gate request.
    expect(
      readRetirementAssessment({
        evidenceId: VALID_ID,
        body: body({
          classification: RETIREMENT_CLASSIFICATION.BLOCKED,
          gateRequested: true,
          reasonCodes: [RETIREMENT_REASON.INDETERMINATE_FACT],
        }),
      }),
    ).toBeNull();
  });

  it('rejects a facts map with a missing or surplus key', () => {
    const facts = toFactRecords(eligibleFacts()) as unknown as Record<string, unknown>;
    const missing = { ...facts };
    delete missing['f1CandidateIdentity'];
    expect(readRetirementAssessment({ evidenceId: VALID_ID, body: body({ facts: missing }) })).toBeNull();

    const surplus = { ...facts, f11Extra: { determinate: true, value: true } };
    expect(readRetirementAssessment({ evidenceId: VALID_ID, body: body({ facts: surplus }) })).toBeNull();
  });

  it('rejects an indeterminate fact that carries a value', () => {
    const facts = {
      ...(toFactRecords(eligibleFacts()) as unknown as Record<string, unknown>),
      f1CandidateIdentity: { determinate: false, value: true },
    };
    expect(readRetirementAssessment({ evidenceId: VALID_ID, body: body({ facts }) })).toBeNull();
  });

  it('rejects an unknown reason code', () => {
    expect(
      readRetirementAssessment({
        evidenceId: VALID_ID,
        body: body({
          classification: RETIREMENT_CLASSIFICATION.BLOCKED,
          gateRequested: false,
          reasonCodes: ['NOT_A_REASON'],
        }),
      }),
    ).toBeNull();
  });

  it('never throws on hostile input', () => {
    const hostile = {
      get evidenceId(): string {
        throw new Error('boom');
      },
    };
    expect(() => readRetirementAssessment(hostile)).not.toThrow();
    expect(readRetirementAssessment(hostile)).toBeNull();
    for (const value of [null, undefined, 0, '', [], new Proxy({}, {})]) {
      expect(() => readRetirementAssessment(value)).not.toThrow();
    }
  });

  it('reads only own properties — an inherited field never becomes trusted', () => {
    const parent = body();
    const child = Object.create(parent) as Record<string, unknown>;
    expect(readRetirementAssessment({ evidenceId: VALID_ID, body: child })).toBeNull();
  });
});

describe('toFactRecords', () => {
  it('flattens every fact in declaration order, with null for indeterminate', () => {
    const records = toFactRecords(
      eligibleFacts({ f1CandidateIdentity: INDETERMINATE, f5UniqueCommits: determinate(3) }),
    );
    expect(Object.keys(records)).toEqual([...RETIREMENT_FACT_ORDER]);
    expect(records['f1CandidateIdentity']).toEqual({ determinate: false, value: null });
    expect(records['f5UniqueCommits']).toEqual({ determinate: true, value: 3 });
  });

  it('produces a canonicalizable map', () => {
    expect(canonicalizeAssessmentBody(toFactRecords(eligibleFacts()))).not.toBeNull();
  });
});
