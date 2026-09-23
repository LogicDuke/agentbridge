import { afterEach, describe, expect, it } from 'vitest';

import {
  canonicalizeAssessmentBody,
  classifyRetirementCandidate,
  determinate,
  GOVERNANCE_HOLD,
  INDETERMINATE,
  isRetirementCount,
  MAX_COUNT,
  readEvidenceId,
  readFullSha,
  readRetirementAssessment,
  readRetirementFactRecords,
  RETIREMENT_BOUNDS,
  RETIREMENT_CLASSIFICATION,
  RETIREMENT_FACT_ORDER,
  RETIREMENT_REASON,
  RETIREMENT_REASONS,
  toFactRecords,
  type RetirementAssessmentBody,
  type RetirementFact,
  type RetirementFactKey,
  type RetirementFacts,
  type RetirementReason,
} from '../../src/domain/retirement-assessment.js';

/* ------------------------------------------------------------------------- *
 * Fixtures — declared here, independently of the module under test
 * ------------------------------------------------------------------------- */

const CANDIDATE_SHA = 'a'.repeat(40);
const MAIN_SHA = 'b'.repeat(40);
const CANDIDATE_REF = 'refs/heads/repair/example-candidate';
const EVIDENCE_ID = 'sha256:' + '0'.repeat(64);
const MANIFEST_DIGEST = 'sha256:' + 'f'.repeat(64);

/** The one fact set that is RETIRE_ELIGIBLE: every fact determinate and clear. */
function eligibleFacts(): RetirementFacts {
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

/** Replace one fact. Typed loosely on purpose: tests also build contradictory sets. */
function withFact(
  base: RetirementFacts,
  key: RetirementFactKey,
  fact: RetirementFact<boolean | number | string>,
): RetirementFacts {
  return { ...base, [key]: fact } as RetirementFacts;
}

/** A body over the eligible facts, as the runtime would build it. */
function eligibleBody(): RetirementAssessmentBody {
  const facts = eligibleFacts();
  const verdict = classifyRetirementCandidate(facts);
  return {
    repositoryId: 'LogicDuke/agentbridge',
    candidateRef: CANDIDATE_REF,
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: MAIN_SHA,
    facts: toFactRecords(facts),
    classification: verdict.classification,
    reasonCodes: verdict.reasonCodes,
    gateRequested: verdict.gateRequested,
    manifestDigest: MANIFEST_DIGEST,
    generatedAt: '2026-09-21T00:00:00Z',
    observerVersion: 'agentbridge-job1-observer/2',
  };
}

/** Plain JSON data: what a hostile reader actually receives. */
function plain<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** A copy of `record` without `key`, built without `delete`. */
function without(record: Record<string, unknown>, key: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([name]) => name !== key));
}

/** A plain, valid serialized fact map. */
function validFactMap(): Record<string, unknown> {
  return plain(toFactRecords(eligibleFacts())) as unknown as Record<string, unknown>;
}

function validEnvelope(): Record<string, unknown> {
  return plain({ evidenceId: EVIDENCE_ID, body: eligibleBody() }) as unknown as Record<
    string,
    unknown
  >;
}

const BOOLEAN_FACTS: readonly RetirementFactKey[] = [
  'f1CandidateIdentity',
  'f2RemoteAgreement',
  'f3StableMain',
  'f4Containment',
  'f7WorktreeClean',
  'f8DependencyClearance',
  'f10NotProtected',
];

/** The blocking booleans: false on any of these is BLOCKED outright. */
const BLOCKING_BOOLEAN_FACTS: readonly RetirementFactKey[] = [
  'f1CandidateIdentity',
  'f2RemoteAgreement',
  'f3StableMain',
  'f7WorktreeClean',
  'f8DependencyClearance',
  'f10NotProtected',
];

/* ------------------------------------------------------------------------- *
 * Classifier
 * ------------------------------------------------------------------------- */

describe('classifier — the three outcomes', () => {
  it('RETIRE_ELIGIBLE exactly when every fact is determinate and clear', () => {
    const verdict = classifyRetirementCandidate(eligibleFacts());

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE);
    expect(verdict.reasonCodes).toEqual([]);
    expect(verdict.gateRequested).toBe(true);
  });

  it('F5 > 0 is PRESERVE_FOR_HISTORY (with F4 false, which is the consistent reading)', () => {
    const facts = withFact(
      withFact(eligibleFacts(), 'f5UniqueCommits', determinate(3)),
      'f4Containment',
      determinate(false),
    );
    const verdict = classifyRetirementCandidate(facts);

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY);
    expect(verdict.reasonCodes).toEqual([
      RETIREMENT_REASON.NOT_CONTAINED,
      RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT,
    ]);
    expect(verdict.gateRequested).toBe(false);
  });

  it('F6 > 0 is PRESERVE_FOR_HISTORY', () => {
    const facts = withFact(
      withFact(withFact(eligibleFacts(), 'f5UniqueCommits', determinate(2)), 'f6UniquePatches', determinate(1)),
      'f4Containment',
      determinate(false),
    );
    const verdict = classifyRetirementCandidate(facts);

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.UNIQUE_PATCHES_PRESENT);
    expect(verdict.gateRequested).toBe(false);
  });

  it('F9 = HOLD is PRESERVE_FOR_HISTORY even when everything else is clear', () => {
    const facts = withFact(eligibleFacts(), 'f9GovernanceManifest', determinate(GOVERNANCE_HOLD.HOLD));
    const verdict = classifyRetirementCandidate(facts);

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY);
    expect(verdict.reasonCodes).toEqual([RETIREMENT_REASON.GOVERNANCE_HOLD]);
    expect(verdict.gateRequested).toBe(false);
  });
});

describe('classifier — BLOCKED precedence', () => {
  const BLOCKING_REASON: Readonly<Record<string, RetirementReason>> = {
    f1CandidateIdentity: RETIREMENT_REASON.CANDIDATE_IDENTITY_MISMATCH,
    f2RemoteAgreement: RETIREMENT_REASON.REMOTE_DISAGREEMENT,
    f3StableMain: RETIREMENT_REASON.MAIN_UNSTABLE,
    f7WorktreeClean: RETIREMENT_REASON.WORKTREE_NOT_CLEAN,
    f8DependencyClearance: RETIREMENT_REASON.DEPENDENCY_CLEARANCE_FAILED,
    f10NotProtected: RETIREMENT_REASON.PROTECTED_OR_DEFAULT_BRANCH,
  };

  for (const key of BLOCKING_BOOLEAN_FACTS) {
    it(`${key} false alone is BLOCKED with its own reason`, () => {
      const verdict = classifyRetirementCandidate(withFact(eligibleFacts(), key, determinate(false)));

      expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
      expect(verdict.reasonCodes).toEqual([BLOCKING_REASON[key]]);
      expect(verdict.gateRequested).toBe(false);
    });
  }

  for (const key of RETIREMENT_FACT_ORDER) {
    it(`${key} indeterminate alone is BLOCKED with INDETERMINATE_FACT`, () => {
      const verdict = classifyRetirementCandidate(withFact(eligibleFacts(), key, INDETERMINATE));

      expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
      expect(verdict.reasonCodes).toEqual([RETIREMENT_REASON.INDETERMINATE_FACT]);
      expect(verdict.gateRequested).toBe(false);
    });
  }

  it('BLOCKED outranks PRESERVE: an indeterminate fact beside a HOLD is BLOCKED', () => {
    const facts = withFact(
      withFact(eligibleFacts(), 'f9GovernanceManifest', determinate(GOVERNANCE_HOLD.HOLD)),
      'f7WorktreeClean',
      INDETERMINATE,
    );
    const verdict = classifyRetirementCandidate(facts);

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toEqual([
      RETIREMENT_REASON.INDETERMINATE_FACT,
      RETIREMENT_REASON.GOVERNANCE_HOLD,
    ]);
  });

  it('F6 > F5 is an internal contradiction and BLOCKED, not PRESERVE', () => {
    const facts = withFact(
      withFact(withFact(eligibleFacts(), 'f5UniqueCommits', determinate(1)), 'f6UniquePatches', determinate(2)),
      'f4Containment',
      determinate(false),
    );
    const verdict = classifyRetirementCandidate(facts);

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toContain(RETIREMENT_REASON.INTERNAL_CONTRADICTION);
  });

  it('F4 true with F5 > 0 is a contradiction and BLOCKED', () => {
    const verdict = classifyRetirementCandidate(
      withFact(eligibleFacts(), 'f5UniqueCommits', determinate(1)),
    );

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toEqual([
      RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT,
      RETIREMENT_REASON.INTERNAL_CONTRADICTION,
    ]);
  });

  it('F4 false with F5 = 0 is a contradiction and BLOCKED', () => {
    const verdict = classifyRetirementCandidate(
      withFact(eligibleFacts(), 'f4Containment', determinate(false)),
    );

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toEqual([
      RETIREMENT_REASON.NOT_CONTAINED,
      RETIREMENT_REASON.INTERNAL_CONTRADICTION,
    ]);
  });
});

describe('classifier — verdict shape and purity', () => {
  it('gateRequested is true only for RETIRE_ELIGIBLE', () => {
    const outcomes = [
      classifyRetirementCandidate(eligibleFacts()),
      classifyRetirementCandidate(
        withFact(eligibleFacts(), 'f9GovernanceManifest', determinate(GOVERNANCE_HOLD.HOLD)),
      ),
      classifyRetirementCandidate(withFact(eligibleFacts(), 'f1CandidateIdentity', INDETERMINATE)),
    ];
    for (const verdict of outcomes) {
      expect(verdict.gateRequested).toBe(
        verdict.classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
      );
    }
  });

  it('reports every applicable reason in the one vocabulary order', () => {
    const facts = withFact(
      withFact(
        withFact(
          withFact(withFact(eligibleFacts(), 'f10NotProtected', determinate(false)), 'f1CandidateIdentity', determinate(false)),
          'f9GovernanceManifest',
          determinate(GOVERNANCE_HOLD.HOLD),
        ),
        'f6UniquePatches',
        determinate(3),
      ),
      'f5UniqueCommits',
      determinate(2),
    );
    const verdict = classifyRetirementCandidate(facts);

    expect(verdict.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(verdict.reasonCodes).toEqual([
      RETIREMENT_REASON.CANDIDATE_IDENTITY_MISMATCH,
      RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT,
      RETIREMENT_REASON.UNIQUE_PATCHES_PRESENT,
      RETIREMENT_REASON.GOVERNANCE_HOLD,
      RETIREMENT_REASON.PROTECTED_OR_DEFAULT_BRANCH,
      RETIREMENT_REASON.INTERNAL_CONTRADICTION,
    ]);
    // The list is a subsequence of the vocabulary order.
    let last = -1;
    for (const reason of verdict.reasonCodes) {
      const position = RETIREMENT_REASONS.indexOf(reason);
      expect(position).toBeGreaterThan(last);
      last = position;
    }
  });

  it('is deterministic: equal inputs yield equal verdicts', () => {
    const facts = withFact(eligibleFacts(), 'f3StableMain', determinate(false));

    expect(classifyRetirementCandidate(facts)).toEqual(classifyRetirementCandidate(facts));
  });

  it('takes the fact set and nothing else — arity one', () => {
    expect(classifyRetirementCandidate.length).toBe(1);
  });

  it('returns a frozen verdict with a frozen reason list', () => {
    const verdict = classifyRetirementCandidate(eligibleFacts());

    expect(Object.isFrozen(verdict)).toBe(true);
    expect(Object.isFrozen(verdict.reasonCodes)).toBe(true);
  });
});

/* ------------------------------------------------------------------------- *
 * Fact records and the typed fact reader
 * ------------------------------------------------------------------------- */

describe('MAX_COUNT and the count predicate', () => {
  it('is exactly 100000', () => {
    expect(MAX_COUNT).toBe(100_000);
  });

  it('accepts 0, MAX_COUNT, and safe integers between', () => {
    expect(isRetirementCount(0)).toBe(true);
    expect(isRetirementCount(1)).toBe(true);
    expect(isRetirementCount(MAX_COUNT)).toBe(true);
  });

  const REJECTED_COUNTS: readonly (readonly [string, unknown])[] = [
    ['a boolean', true],
    ['a string', '1'],
    ['a float', 1.5],
    ['a negative', -1],
    ['-0', -0],
    ['MAX_COUNT + 1', MAX_COUNT + 1],
    ['an unsafe integer', Number.MAX_SAFE_INTEGER + 2],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['null', null],
  ];
  for (const [label, value] of REJECTED_COUNTS) {
    it(`rejects ${label}`, () => {
      expect(isRetirementCount(value)).toBe(false);
    });
  }
});

describe('fact records — flattening and reading round-trip', () => {
  it('flattens a determinate fact to { determinate: true, value } and an indeterminate one to value null', () => {
    const records = toFactRecords(withFact(eligibleFacts(), 'f8DependencyClearance', INDETERMINATE));

    expect(records.f1CandidateIdentity).toEqual({ determinate: true, value: true });
    expect(records.f5UniqueCommits).toEqual({ determinate: true, value: 0 });
    expect(records.f9GovernanceManifest).toEqual({ determinate: true, value: 'NO_HOLD' });
    expect(records.f8DependencyClearance).toEqual({ determinate: false, value: null });
    expect(Object.keys(records)).toEqual([...RETIREMENT_FACT_ORDER]);
  });

  it('reads an exact valid map back as an equal, frozen, prototype-free copy', () => {
    const input = validFactMap();
    const read = readRetirementFactRecords(input);

    expect(read).not.toBeNull();
    expect(read).toEqual(input);
    expect(read).not.toBe(input);
    expect(Object.isFrozen(read)).toBe(true);
    expect(Object.getPrototypeOf(read)).toBeNull();
    expect(Object.isFrozen(read?.f5UniqueCommits)).toBe(true);
  });

  it('reads an indeterminate record with exactly null', () => {
    const input = { ...validFactMap(), f3StableMain: { determinate: false, value: null } };

    expect(readRetirementFactRecords(input)?.f3StableMain).toEqual({ determinate: false, value: null });
  });
});

describe('fact reader — exact key set', () => {
  for (const key of RETIREMENT_FACT_ORDER) {
    it(`rejects a map missing ${key}`, () => {
      expect(readRetirementFactRecords(without(validFactMap(), key))).toBeNull();
    });
  }

  it('rejects a surplus key', () => {
    expect(readRetirementFactRecords({ ...validFactMap(), f11Extra: { determinate: true, value: true } })).toBeNull();
  });

  it('rejects an own __proto__ key delivered through JSON', () => {
    const text = JSON.stringify(validFactMap()).replace(
      '{',
      '{"__proto__":{"determinate":true,"value":true},',
    );
    const input: unknown = JSON.parse(text);

    expect(readRetirementFactRecords(input)).toBeNull();
  });

  it('does not count inherited keys as present (prototype negative control)', () => {
    const inherited: unknown = Object.create(validFactMap());

    expect(readRetirementFactRecords(inherited)).toBeNull();
  });

  it('rejects non-objects', () => {
    for (const value of [null, undefined, 'facts', 7, true, []]) {
      expect(readRetirementFactRecords(value)).toBeNull();
    }
  });
});

describe('fact reader — per-fact value typing', () => {
  function withRecord(key: RetirementFactKey, record: unknown): Record<string, unknown> {
    return { ...validFactMap(), [key]: record };
  }

  it('rejects a boolean in F5', () => {
    expect(readRetirementFactRecords(withRecord('f5UniqueCommits', { determinate: true, value: true }))).toBeNull();
  });

  it('rejects a string in F1', () => {
    expect(readRetirementFactRecords(withRecord('f1CandidateIdentity', { determinate: true, value: 'true' }))).toBeNull();
  });

  it('rejects a number in F9', () => {
    expect(readRetirementFactRecords(withRecord('f9GovernanceManifest', { determinate: true, value: 1 }))).toBeNull();
  });

  it('rejects a hold string in a boolean fact and a boolean in F9', () => {
    expect(readRetirementFactRecords(withRecord('f7WorktreeClean', { determinate: true, value: 'NO_HOLD' }))).toBeNull();
    expect(readRetirementFactRecords(withRecord('f9GovernanceManifest', { determinate: true, value: false }))).toBeNull();
  });

  it('rejects a string outside the hold vocabulary in F9', () => {
    expect(readRetirementFactRecords(withRecord('f9GovernanceManifest', { determinate: true, value: 'hold' }))).toBeNull();
    expect(readRetirementFactRecords(withRecord('f9GovernanceManifest', { determinate: true, value: 'RELEASED' }))).toBeNull();
  });

  for (const key of BOOLEAN_FACTS) {
    it(`rejects a number in ${key}`, () => {
      expect(readRetirementFactRecords(withRecord(key, { determinate: true, value: 1 }))).toBeNull();
    });
  }

  const REJECTED_COUNT_VALUES: readonly (readonly [string, unknown])[] = [
    ['a float', 2.5],
    ['a negative', -1],
    ['-0', -0],
    ['a count above MAX_COUNT', MAX_COUNT + 1],
    ['an unsafe integer', 2 ** 53],
    ['a numeric string', '3'],
  ];
  for (const key of ['f5UniqueCommits', 'f6UniquePatches'] as const) {
    for (const [label, value] of REJECTED_COUNT_VALUES) {
      it(`rejects ${label} in ${key}`, () => {
        expect(readRetirementFactRecords(withRecord(key, { determinate: true, value }))).toBeNull();
      });
    }

    it(`accepts MAX_COUNT in ${key} when consistent`, () => {
      const read = readRetirementFactRecords(withRecord(key, { determinate: true, value: MAX_COUNT }));

      expect(read?.[key]).toEqual({ determinate: true, value: MAX_COUNT });
    });
  }

  it('rejects an indeterminate record carrying a non-null value', () => {
    expect(readRetirementFactRecords(withRecord('f2RemoteAgreement', { determinate: false, value: true }))).toBeNull();
    expect(readRetirementFactRecords(withRecord('f2RemoteAgreement', { determinate: false, value: 0 }))).toBeNull();
  });

  it('rejects malformed determinate forms', () => {
    for (const record of [
      { determinate: 'true', value: true },
      { determinate: true },
      { value: true },
      { determinate: true, value: true, extra: 1 },
      { determinate: true, value: null },
      { determinate: false },
      null,
      true,
      'determinate',
    ]) {
      expect(readRetirementFactRecords(withRecord('f4Containment', record))).toBeNull();
    }
  });

  it('rejects a record whose determinate flag is inherited rather than own', () => {
    const record: unknown = Object.create({ determinate: true, value: true });

    expect(readRetirementFactRecords(withRecord('f4Containment', record))).toBeNull();
  });
});

/* ------------------------------------------------------------------------- *
 * Identifier shapes
 * ------------------------------------------------------------------------- */

describe('identifier readers', () => {
  it('readFullSha accepts exactly 40 lowercase hex and returns it unmodified', () => {
    expect(readFullSha(CANDIDATE_SHA)).toBe(CANDIDATE_SHA);
    expect(readFullSha('A'.repeat(40))).toBeNull();
    expect(readFullSha('a'.repeat(39))).toBeNull();
    expect(readFullSha('a'.repeat(41))).toBeNull();
    expect(readFullSha(' ' + 'a'.repeat(39))).toBeNull();
    expect(readFullSha(42)).toBeNull();
  });

  it('readEvidenceId accepts exactly "sha256:" + 64 lowercase hex', () => {
    expect(readEvidenceId(EVIDENCE_ID)).toBe(EVIDENCE_ID);
    expect(readEvidenceId('sha256:' + 'A'.repeat(64))).toBeNull();
    expect(readEvidenceId('sha256:' + '0'.repeat(63))).toBeNull();
    expect(readEvidenceId('SHA256:' + '0'.repeat(64))).toBeNull();
    expect(readEvidenceId('0'.repeat(64))).toBeNull();
    expect(readEvidenceId(null)).toBeNull();
  });
});

/* ------------------------------------------------------------------------- *
 * The envelope reader
 * ------------------------------------------------------------------------- */

describe('envelope reader', () => {
  it('reads a valid envelope as an equal, frozen copy', () => {
    const input = validEnvelope();
    const read = readRetirementAssessment(input);

    expect(read).toEqual(input);
    expect(read).not.toBe(input);
    expect(Object.isFrozen(read)).toBe(true);
    expect(Object.isFrozen(read?.body)).toBe(true);
    expect(Object.isFrozen(read?.body.facts)).toBe(true);
    expect(Object.isFrozen(read?.body.reasonCodes)).toBe(true);
  });

  it('checks shape only: an unbound but well-formed id still reads (binding is the runtime’s job)', () => {
    expect(readRetirementAssessment(validEnvelope())?.evidenceId).toBe(EVIDENCE_ID);
  });

  it('rejects a malformed evidence id', () => {
    expect(readRetirementAssessment({ ...validEnvelope(), evidenceId: 'sha256:' + 'G'.repeat(64) })).toBeNull();
  });

  it('rejects surplus keys on the envelope and on the body', () => {
    expect(readRetirementAssessment({ ...validEnvelope(), extra: 1 })).toBeNull();
    const body = { ...(validEnvelope()['body'] as Record<string, unknown>), mayDelete: true };
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body })).toBeNull();
  });

  for (const key of [
    'repositoryId',
    'candidateRef',
    'candidateSha',
    'authoritativeMainSha',
    'facts',
    'classification',
    'reasonCodes',
    'gateRequested',
    'manifestDigest',
    'generatedAt',
    'observerVersion',
  ]) {
    it(`rejects a body missing ${key}`, () => {
      const body = without(validEnvelope()['body'] as Record<string, unknown>, key);

      expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body })).toBeNull();
    });
  }

  it('rejects a gateRequested that disagrees with the classification', () => {
    const body = { ...(validEnvelope()['body'] as Record<string, unknown>), gateRequested: false };

    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body })).toBeNull();
  });

  it('rejects a BLOCKED body that requests the gate', () => {
    const body = {
      ...(validEnvelope()['body'] as Record<string, unknown>),
      classification: RETIREMENT_CLASSIFICATION.BLOCKED,
      gateRequested: true,
    };

    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body })).toBeNull();
  });

  it('rejects a non-canonical candidate ref and a malformed SHA', () => {
    const base = validEnvelope()['body'] as Record<string, unknown>;
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, candidateRef: 'main' } })).toBeNull();
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, candidateSha: 'abc' } })).toBeNull();
    expect(
      readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, authoritativeMainSha: 'B'.repeat(40) } }),
    ).toBeNull();
  });

  it('rejects an unknown classification, reason, or malformed facts map', () => {
    const base = validEnvelope()['body'] as Record<string, unknown>;
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, classification: 'ELIGIBLE' } })).toBeNull();
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, reasonCodes: ['UNKNOWN'] } })).toBeNull();
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, reasonCodes: 'none' } })).toBeNull();
    expect(readRetirementAssessment({ evidenceId: EVIDENCE_ID, body: { ...base, facts: {} } })).toBeNull();
  });

  it('rejects non-objects and never throws on hostile getters', () => {
    expect(readRetirementAssessment(null)).toBeNull();
    expect(readRetirementAssessment('envelope')).toBeNull();
    const hostile = { ...validEnvelope() };
    Object.defineProperty(hostile, 'body', {
      enumerable: true,
      get: () => {
        throw new Error('hostile');
      },
    });
    expect(readRetirementAssessment(hostile)).toBeNull();
  });
});

/* ------------------------------------------------------------------------- *
 * Envelope reader — facts to verdict binding
 * ------------------------------------------------------------------------- */

/** An envelope over `facts`, carrying whatever verdict tuple `claim` states. */
function envelopeClaiming(
  facts: RetirementFacts,
  claim: {
    readonly classification: string;
    readonly reasonCodes: readonly string[];
    readonly gateRequested: boolean;
  },
): Record<string, unknown> {
  const body = { ...eligibleBody(), facts: toFactRecords(facts), ...claim };
  return plain({ evidenceId: EVIDENCE_ID, body }) as unknown as Record<string, unknown>;
}

/** An envelope over `facts` carrying exactly the verdict those facts produce. */
function honestEnvelope(facts: RetirementFacts): Record<string, unknown> {
  return envelopeClaiming(facts, classifyRetirementCandidate(facts));
}

/** F5 > 0 with the consistent F4: PRESERVE_FOR_HISTORY, two reasons. */
function preserveFacts(): RetirementFacts {
  return withFact(
    withFact(eligibleFacts(), 'f5UniqueCommits', determinate(2)),
    'f4Containment',
    determinate(false),
  );
}

/** F7 false: BLOCKED with exactly one reason. */
function blockedFacts(): RetirementFacts {
  return withFact(eligibleFacts(), 'f7WorktreeClean', determinate(false));
}

/** F1 and F3 false: BLOCKED with two reasons, in vocabulary order. */
function twoReasonFacts(): RetirementFacts {
  return withFact(
    withFact(eligibleFacts(), 'f1CandidateIdentity', determinate(false)),
    'f3StableMain',
    determinate(false),
  );
}

/** F5 = 1 with F6 = 5: F6 may not exceed F5, so BLOCKED on a contradiction. */
function contradictoryFacts(): RetirementFacts {
  return withFact(
    withFact(eligibleFacts(), 'f5UniqueCommits', determinate(1)),
    'f6UniquePatches',
    determinate(5),
  );
}

describe('envelope reader — the verdict is bound to the facts', () => {
  it('rejects a blocking fact claiming RETIRE_ELIGIBLE with an empty reason list', () => {
    const facts = withFact(eligibleFacts(), 'f1CandidateIdentity', determinate(false));

    expect(
      readRetirementAssessment(
        envelopeClaiming(facts, {
          classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
          reasonCodes: [],
          gateRequested: true,
        }),
      ),
    ).toBeNull();
  });

  it('rejects preserving facts claiming RETIRE_ELIGIBLE', () => {
    expect(
      readRetirementAssessment(
        envelopeClaiming(preserveFacts(), {
          classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
          reasonCodes: [],
          gateRequested: true,
        }),
      ),
    ).toBeNull();
  });

  it('rejects eligible facts claiming BLOCKED: the binding runs in both directions', () => {
    expect(
      readRetirementAssessment(
        envelopeClaiming(eligibleFacts(), {
          classification: RETIREMENT_CLASSIFICATION.BLOCKED,
          reasonCodes: [RETIREMENT_REASON.INDETERMINATE_FACT],
          gateRequested: false,
        }),
      ),
    ).toBeNull();
  });

  it('rejects the right classification carrying the wrong reason', () => {
    expect(
      readRetirementAssessment(
        envelopeClaiming(blockedFacts(), {
          classification: RETIREMENT_CLASSIFICATION.BLOCKED,
          reasonCodes: [RETIREMENT_REASON.MAIN_UNSTABLE],
          gateRequested: false,
        }),
      ),
    ).toBeNull();
  });

  it('rejects reordered reason codes: the order is part of the verdict', () => {
    const derived = classifyRetirementCandidate(twoReasonFacts());
    const reversed = [...derived.reasonCodes].reverse();

    expect(reversed).not.toEqual(derived.reasonCodes);
    expect(
      readRetirementAssessment(
        envelopeClaiming(twoReasonFacts(), { ...derived, reasonCodes: reversed }),
      ),
    ).toBeNull();
  });

  it('rejects a duplicated reason code', () => {
    expect(
      readRetirementAssessment(
        envelopeClaiming(blockedFacts(), {
          classification: RETIREMENT_CLASSIFICATION.BLOCKED,
          reasonCodes: [RETIREMENT_REASON.WORKTREE_NOT_CLEAN, RETIREMENT_REASON.WORKTREE_NOT_CLEAN],
          gateRequested: false,
        }),
      ),
    ).toBeNull();
  });

  it('rejects the right classification carrying the wrong gateRequested', () => {
    expect(
      readRetirementAssessment(
        envelopeClaiming(eligibleFacts(), {
          classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
          reasonCodes: [],
          gateRequested: false,
        }),
      ),
    ).toBeNull();
  });

  it('rejects a self-consistent verdict tuple that disagrees with the facts', () => {
    const claim = classifyRetirementCandidate(blockedFacts());

    // The tuple is internally coherent — it is simply not this body's verdict.
    expect(claim.gateRequested).toBe(
      claim.classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
    );
    expect(readRetirementAssessment(envelopeClaiming(preserveFacts(), claim))).toBeNull();
  });

  it('rejects an indeterminate fact claiming RETIRE_ELIGIBLE', () => {
    const facts = withFact(eligibleFacts(), 'f8DependencyClearance', INDETERMINATE);

    expect(
      readRetirementAssessment(
        envelopeClaiming(facts, {
          classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
          reasonCodes: [],
          gateRequested: true,
        }),
      ),
    ).toBeNull();
  });

  it('rejects contradiction-producing facts claiming a favourable verdict', () => {
    expect(
      readRetirementAssessment(
        envelopeClaiming(contradictoryFacts(), {
          classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
          reasonCodes: [],
          gateRequested: true,
        }),
      ),
    ).toBeNull();
  });

  it('rejects a strict subset of the derived reason codes', () => {
    const derived = classifyRetirementCandidate(twoReasonFacts());
    const subset = derived.reasonCodes.slice(0, 1);

    expect(subset.length).toBeLessThan(derived.reasonCodes.length);
    expect(
      readRetirementAssessment(
        envelopeClaiming(twoReasonFacts(), { ...derived, reasonCodes: subset }),
      ),
    ).toBeNull();
  });

  it('rejects a strict superset of the derived reason codes', () => {
    const derived = classifyRetirementCandidate(blockedFacts());
    const superset = [...derived.reasonCodes, RETIREMENT_REASON.MAIN_UNSTABLE];

    expect(
      readRetirementAssessment(
        envelopeClaiming(blockedFacts(), { ...derived, reasonCodes: superset }),
      ),
    ).toBeNull();
  });

  for (const [label, facts] of [
    ['a genuinely eligible', eligibleFacts()],
    ['a preserve-for-history', preserveFacts()],
    ['a blocked', blockedFacts()],
    ['an indeterminate', withFact(eligibleFacts(), 'f8DependencyClearance', INDETERMINATE)],
    ['an internally contradictory', contradictoryFacts()],
    ['a multi-reason', twoReasonFacts()],
  ] as readonly (readonly [string, RetirementFacts])[]) {
    it(`accepts ${label} body carrying exactly its derived tuple`, () => {
      const derived = classifyRetirementCandidate(facts);
      const read = readRetirementAssessment(honestEnvelope(facts));

      expect(read).not.toBeNull();
      expect(read?.body.classification).toBe(derived.classification);
      expect(read?.body.gateRequested).toBe(derived.gateRequested);
      expect(read?.body.reasonCodes).toEqual(derived.reasonCodes);
    });
  }
});

/* ------------------------------------------------------------------------- *
 * AB-CJSON-1
 * ------------------------------------------------------------------------- */

describe('AB-CJSON-1 canonicalization', () => {
  it('sorts object keys by UTF-16 code unit and emits no whitespace', () => {
    expect(canonicalizeAssessmentBody({ b: 1, a: 2, B: 3, _: 4 })).toBe('{"B":3,"_":4,"a":2,"b":1}');
  });

  it('sorts keys at every depth', () => {
    expect(canonicalizeAssessmentBody({ z: { y: 1, x: { w: 2, v: 3 } }, a: [] })).toBe(
      '{"a":[],"z":{"x":{"v":3,"w":2},"y":1}}',
    );
  });

  it('preserves array order and never sorts arrays', () => {
    expect(canonicalizeAssessmentBody({ list: [3, 1, 2, 'b', 'a', null, true, false] })).toBe(
      '{"list":[3,1,2,"b","a",null,true,false]}',
    );
  });

  it('gives the same semantic object the same text regardless of insertion order', () => {
    const first = canonicalizeAssessmentBody({ x: 1, y: { p: [1, 2], q: 'q' }, z: null });
    const second = canonicalizeAssessmentBody({ z: null, y: { q: 'q', p: [1, 2] }, x: 1 });

    expect(first).toBe(second);
    expect(first).not.toContain(' ');
    expect(first).not.toContain('\n');
  });

  it('escapes strings exactly as JSON does', () => {
    expect(canonicalizeAssessmentBody({ s: 'a"b\\c\nd\u0001é' })).toBe('{"s":"a\\"b\\\\c\\nd\\u0001é"}');
  });

  it('accepts safe integers, including the safe-integer extremes', () => {
    expect(canonicalizeAssessmentBody([0, 1, -1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER])).toBe(
      '[0,1,-1,9007199254740991,-9007199254740991]',
    );
  });

  const REJECTED_VALUES: readonly (readonly [string, unknown])[] = [
    ['a float', 1.5],
    ['-0', -0],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['an unsafe integer', 2 ** 53],
    ['undefined', undefined],
    ['a bigint', 1n],
    ['a symbol', Symbol('s')],
    ['a function', (): void => undefined],
    ['a Date', new Date(0)],
    ['a Map', new Map()],
    ['a Set', new Set()],
    ['a RegExp', /x/],
    ['a class instance', new (class Thing { readonly member = 1; })()],
    ['a boxed string', Object('s')],
  ];
  for (const [label, value] of REJECTED_VALUES) {
    it(`rejects ${label} at the top level and nested`, () => {
      expect(canonicalizeAssessmentBody(value)).toBeNull();
      expect(canonicalizeAssessmentBody({ nested: value })).toBeNull();
      expect(canonicalizeAssessmentBody([value])).toBeNull();
    });
  }

  it('accepts a null-prototype plain object', () => {
    const record: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    record['k'] = 1;

    expect(canonicalizeAssessmentBody(record)).toBe('{"k":1}');
  });

  it('rejects a sparse array and a cycle', () => {
    const sparse: unknown[] = [];
    sparse[2] = 1;
    expect(canonicalizeAssessmentBody(sparse)).toBeNull();

    const cyclic: Record<string, unknown> = {};
    cyclic['self'] = cyclic;
    expect(canonicalizeAssessmentBody(cyclic)).toBeNull();
  });

  it('rejects an object with a custom prototype: it is not a plain object', () => {
    const custom = Object.create({ hidden: 1 }) as Record<string, unknown>;
    custom['own'] = 2;

    expect(canonicalizeAssessmentBody(custom)).toBeNull();
    expect(canonicalizeAssessmentBody({ nested: custom })).toBeNull();
  });

  // Inverted under DDR-WF3-PR113-F02-FAMILY-WF2 §19: a non-enumerable own key is
  // state the encoding would drop, so the object rejects rather than projects.
  it('rejects a plain object carrying an own non-enumerable key', () => {
    const record: Record<string, unknown> = { visible: 1 };
    Object.defineProperty(record, 'hidden', { value: 2, enumerable: false });

    expect(Object.getPrototypeOf(record)).toBe(Object.prototype);
    expect(Object.hasOwn(record, 'hidden')).toBe(true);
    expect(canonicalizeAssessmentBody(record)).toBeNull();
  });

  it('returns null, and never propagates, for an enumerable own getter that throws', () => {
    const throwing = {};
    Object.defineProperty(throwing, 'boom', {
      enumerable: true,
      get: () => {
        throw new Error('hostile');
      },
    });

    expect(() => canonicalizeAssessmentBody(throwing)).not.toThrow();
    expect(canonicalizeAssessmentBody(throwing)).toBeNull();
    expect(canonicalizeAssessmentBody({ nested: throwing })).toBeNull();
  });

  it('bounds nesting at MAX_CANONICAL_DEPTH containers', () => {
    const nest = (containers: number): unknown => {
      let value: unknown = 1;
      for (let index = 0; index < containers; index += 1) {
        value = { a: value };
      }
      return value;
    };

    expect(canonicalizeAssessmentBody(nest(RETIREMENT_BOUNDS.MAX_CANONICAL_DEPTH))).not.toBeNull();
    expect(canonicalizeAssessmentBody(nest(RETIREMENT_BOUNDS.MAX_CANONICAL_DEPTH + 1))).toBeNull();
  });

  it('bounds keys per object at MAX_CANONICAL_KEYS', () => {
    const withKeys = (count: number): Record<string, number> => {
      const record: Record<string, number> = {};
      for (let index = 0; index < count; index += 1) {
        record[`k${String(index)}`] = index;
      }
      return record;
    };

    expect(canonicalizeAssessmentBody(withKeys(RETIREMENT_BOUNDS.MAX_CANONICAL_KEYS))).not.toBeNull();
    expect(canonicalizeAssessmentBody(withKeys(RETIREMENT_BOUNDS.MAX_CANONICAL_KEYS + 1))).toBeNull();
  });

  it('bounds elements per array at MAX_CANONICAL_ELEMENTS', () => {
    const ok = new Array<number>(RETIREMENT_BOUNDS.MAX_CANONICAL_ELEMENTS).fill(0);
    const over = new Array<number>(RETIREMENT_BOUNDS.MAX_CANONICAL_ELEMENTS + 1).fill(0);

    expect(canonicalizeAssessmentBody(ok)).not.toBeNull();
    expect(canonicalizeAssessmentBody(over)).toBeNull();
  });

  it('bounds string scalars and keys at MAX_CANONICAL_STRING_LENGTH', () => {
    const limit = RETIREMENT_BOUNDS.MAX_CANONICAL_STRING_LENGTH;

    expect(canonicalizeAssessmentBody('x'.repeat(limit))).not.toBeNull();
    expect(canonicalizeAssessmentBody('x'.repeat(limit + 1))).toBeNull();
    expect(canonicalizeAssessmentBody({ ['k'.repeat(limit + 1)]: 1 })).toBeNull();
  });

  it('canonicalizes an ordinary array unchanged', () => {
    expect(canonicalizeAssessmentBody([1, 'a', true, null])).toBe('[1,"a",true,null]');
    expect(canonicalizeAssessmentBody([])).toBe('[]');
    expect(canonicalizeAssessmentBody({ list: [1, 2] })).toBe('{"list":[1,2]}');
  });

  it('rejects an array carrying a named own enumerable property', () => {
    const withNamed: unknown[] = [1];
    (withNamed as unknown as Record<string, unknown>)['secret'] = 2;

    expect(canonicalizeAssessmentBody(withNamed)).toBeNull();
  });

  it('rejects an array carrying a named own non-enumerable property', () => {
    const withHidden: unknown[] = [1];
    Object.defineProperty(withHidden, 'hidden', { value: 2, enumerable: false });

    expect(canonicalizeAssessmentBody(withHidden)).toBeNull();
  });

  it('rejects an Array subclass instance and a reparented array', () => {
    class Exotic extends Array {}
    const reparented: unknown[] = [1];
    Object.setPrototypeOf(reparented, null);

    expect(canonicalizeAssessmentBody(new Exotic())).toBeNull();
    expect(canonicalizeAssessmentBody(reparented)).toBeNull();
  });

  it('rejects an exotic array nested in an array and in an object', () => {
    class Exotic extends Array {}
    const withNamed: unknown[] = [1];
    (withNamed as unknown as Record<string, unknown>)['secret'] = 2;

    expect(canonicalizeAssessmentBody([withNamed])).toBeNull();
    expect(canonicalizeAssessmentBody({ list: withNamed })).toBeNull();
    expect(canonicalizeAssessmentBody([new Exotic()])).toBeNull();
    expect(canonicalizeAssessmentBody({ list: new Exotic() })).toBeNull();
  });

  it('never lets an exotic array collide with its plain-array counterpart', () => {
    class Exotic extends Array {}
    const withNamed: unknown[] = [1];
    (withNamed as unknown as Record<string, unknown>)['secret'] = 2;

    expect(canonicalizeAssessmentBody(withNamed)).not.toBe(canonicalizeAssessmentBody([1]));
    expect(canonicalizeAssessmentBody(new Exotic())).not.toBe(canonicalizeAssessmentBody([]));
  });

  it('still canonicalizes the module’s own frozen lists, which carry a toJSON shadow', () => {
    const { reasonCodes } = classifyRetirementCandidate(
      withFact(eligibleFacts(), 'f9GovernanceManifest', determinate(GOVERNANCE_HOLD.HOLD)),
    );

    expect(Object.getOwnPropertyNames(reasonCodes)).toContain('toJSON');
    expect(canonicalizeAssessmentBody(reasonCodes)).toBe('["GOVERNANCE_HOLD"]');
  });

  it('rejects an array carrying an attacker-controlled own toJSON', () => {
    const enumerableString: unknown[] = [1, 2];
    (enumerableString as unknown as Record<string, unknown>)['toJSON'] = 'SECRET-PAYLOAD';

    const writableHidden: unknown[] = [1, 2];
    Object.defineProperty(writableHidden, 'toJSON', {
      value: 'SECRET-PAYLOAD',
      enumerable: false,
      writable: true,
      configurable: true,
    });

    const objectValued: unknown[] = [1, 2];
    Object.defineProperty(objectValued, 'toJSON', {
      value: { hidden: { deep: 'state' } },
      enumerable: false,
      writable: false,
      configurable: false,
    });

    const functionValued: unknown[] = [1, 2];
    (functionValued as unknown as Record<string, unknown>)['toJSON'] = () => 'HIJACK';

    expect(canonicalizeAssessmentBody(enumerableString)).toBeNull();
    expect(canonicalizeAssessmentBody(writableHidden)).toBeNull();
    expect(canonicalizeAssessmentBody(objectValued)).toBeNull();
    expect(canonicalizeAssessmentBody(functionValued)).toBeNull();
  });

  it('rejects an accessor toJSON by its descriptor, without ever invoking it', () => {
    let invoked = false;
    const accessor: unknown[] = [1, 2];
    Object.defineProperty(accessor, 'toJSON', {
      get: () => {
        invoked = true;
        return undefined;
      },
      enumerable: false,
      configurable: false,
    });

    const throwing: unknown[] = [1, 2];
    Object.defineProperty(throwing, 'toJSON', {
      get: () => {
        throw new Error('hostile');
      },
      enumerable: false,
      configurable: false,
    });

    expect(canonicalizeAssessmentBody(accessor)).toBeNull();
    expect(invoked).toBe(false);
    expect(() => canonicalizeAssessmentBody(throwing)).not.toThrow();
    expect(canonicalizeAssessmentBody(throwing)).toBeNull();
  });

  it('accepts exactly the benign toJSON shadow and rejects every near miss', () => {
    const benign: PropertyDescriptor = {
      value: undefined,
      writable: false,
      enumerable: false,
      configurable: false,
    };
    const withShadow = (descriptor: PropertyDescriptor): unknown => {
      const list: unknown[] = [1, 2];
      Object.defineProperty(list, 'toJSON', descriptor);
      return list;
    };

    expect(canonicalizeAssessmentBody(withShadow(benign))).toBe('[1,2]');

    expect(canonicalizeAssessmentBody(withShadow({ ...benign, value: 'x' }))).toBeNull();
    expect(canonicalizeAssessmentBody(withShadow({ ...benign, writable: true }))).toBeNull();
    expect(canonicalizeAssessmentBody(withShadow({ ...benign, enumerable: true }))).toBeNull();
    expect(canonicalizeAssessmentBody(withShadow({ ...benign, configurable: true }))).toBeNull();
    expect(
      canonicalizeAssessmentBody(
        withShadow({ get: () => undefined, enumerable: false, configurable: false }),
      ),
    ).toBeNull();
  });

  it('never lets a toJSON-bearing array collide with its plain counterpart', () => {
    const hidden: unknown[] = [1, 2];
    (hidden as unknown as Record<string, unknown>)['toJSON'] = 'SECRET-PAYLOAD';

    expect(canonicalizeAssessmentBody([1, 2])).toBe('[1,2]');
    expect(canonicalizeAssessmentBody(hidden)).not.toBe(canonicalizeAssessmentBody([1, 2]));
    expect(canonicalizeAssessmentBody([hidden])).toBeNull();
    expect(canonicalizeAssessmentBody({ list: hidden })).toBeNull();
  });

  it('canonicalizes a real assessment body and its JSON round-trip identically', () => {
    const body = eligibleBody();
    const direct = canonicalizeAssessmentBody(body);

    expect(direct).not.toBeNull();
    expect(canonicalizeAssessmentBody(plain(body))).toBe(direct);
    expect(direct).not.toContain(' ');
  });
});

/* ------------------------------------------------------------------------- *
 * AB-CJSON-1 — own state the encoding would drop rejects, never projects
 * (DDR-WF3-PR113-F02-FAMILY-WF2 §15)
 * ------------------------------------------------------------------------- */

/** An own symbol accessor whose getter throws, counting every invocation. */
function withSymbolAccessor<T extends object>(target: T): { readonly target: T; readonly calls: () => number } {
  let calls = 0;
  Object.defineProperty(target, Symbol('acc'), {
    enumerable: true,
    configurable: true,
    get: () => {
      calls += 1;
      throw new Error('hostile');
    },
  });
  return { target, calls: () => calls };
}

function withSymbol<T extends object>(target: T, enumerable = true, key: symbol = Symbol('secret')): T {
  Object.defineProperty(target, key, { value: 2, enumerable, configurable: true, writable: true });
  return target;
}

function withHiddenKey<T extends object>(target: T): T {
  Object.defineProperty(target, 'hidden', { value: 2, enumerable: false });
  return target;
}

/** AB-CJSON-1 text of {@link eligibleBody}, as emitted at the reviewed head 034d809. */
const ELIGIBLE_BODY_TEXT =
  '{"authoritativeMainSha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","candidateRef":"refs/heads/repair/example-candidate","candidateSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","classification":"RETIRE_ELIGIBLE","facts":{"f10NotProtected":{"determinate":true,"value":true},"f1CandidateIdentity":{"determinate":true,"value":true},"f2RemoteAgreement":{"determinate":true,"value":true},"f3StableMain":{"determinate":true,"value":true},"f4Containment":{"determinate":true,"value":true},"f5UniqueCommits":{"determinate":true,"value":0},"f6UniquePatches":{"determinate":true,"value":0},"f7WorktreeClean":{"determinate":true,"value":true},"f8DependencyClearance":{"determinate":true,"value":true},"f9GovernanceManifest":{"determinate":true,"value":"NO_HOLD"}},"gateRequested":true,"generatedAt":"2026-09-21T00:00:00Z","manifestDigest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","observerVersion":"agentbridge-job1-observer/2","reasonCodes":[],"repositoryId":"LogicDuke/agentbridge"}';

describe('AB-CJSON-1 — extra own container state rejects, never drops', () => {
  it('rejects an array carrying an own enumerable string property', () => {
    const carrier: unknown[] = [1];
    (carrier as unknown as Record<string, unknown>)['secret'] = 2;
    expect(canonicalizeAssessmentBody(carrier)).toBeNull();
  });

  it('rejects an array carrying an own non-enumerable string property', () => {
    expect(canonicalizeAssessmentBody(withHiddenKey<unknown[]>([1]))).toBeNull();
  });

  it('rejects an array carrying an own symbol property', () => {
    expect(canonicalizeAssessmentBody(withSymbol<unknown[]>([1]))).toBeNull();
  });

  it('rejects an array carrying an own non-enumerable symbol property', () => {
    expect(canonicalizeAssessmentBody(withSymbol<unknown[]>([1], false))).toBeNull();
  });

  it('rejects an array carrying an own Symbol.iterator', () => {
    const carrier: unknown[] = [1];
    (carrier as unknown as Record<symbol, unknown>)[Symbol.iterator] = function* (): Generator<number> {
      yield 9;
    };
    expect(canonicalizeAssessmentBody(carrier)).toBeNull();
  });

  it('rejects an array carrying several own symbol keys', () => {
    const carrier = withSymbol(withSymbol(withSymbol<unknown[]>([1], true, Symbol('s1')), false, Symbol('s2')), true, Symbol('s3'));
    expect(canonicalizeAssessmentBody(carrier)).toBeNull();
  });

  it('rejects an array carrying an own symbol accessor without invoking its getter', () => {
    const { target, calls } = withSymbolAccessor<unknown[]>([1]);
    expect(() => canonicalizeAssessmentBody(target)).not.toThrow();
    expect(canonicalizeAssessmentBody(target)).toBeNull();
    expect(calls()).toBe(0);
  });

  it('rejects a plain object carrying an own non-enumerable string property', () => {
    expect(canonicalizeAssessmentBody(withHiddenKey<Record<string, unknown>>({ a: 1 }))).toBeNull();
  });

  it('rejects a plain object carrying an own symbol property', () => {
    expect(canonicalizeAssessmentBody(withSymbol<Record<string, unknown>>({ a: 1 }))).toBeNull();
  });

  it('rejects a plain object carrying an own non-enumerable symbol property', () => {
    expect(canonicalizeAssessmentBody(withSymbol<Record<string, unknown>>({ a: 1 }, false))).toBeNull();
  });

  it('rejects a plain object carrying several own symbol keys', () => {
    const carrier = withSymbol(withSymbol<Record<string, unknown>>({ a: 1 }, true, Symbol('s1')), false, Symbol('s2'));
    expect(canonicalizeAssessmentBody(carrier)).toBeNull();
  });

  it('rejects a plain object carrying an own symbol accessor without invoking its getter', () => {
    const { target, calls } = withSymbolAccessor<Record<string, unknown>>({ a: 1 });
    expect(() => canonicalizeAssessmentBody(target)).not.toThrow();
    expect(canonicalizeAssessmentBody(target)).toBeNull();
    expect(calls()).toBe(0);
  });

  it('rejects a null-prototype object carrying a symbol or a hidden key', () => {
    const base = (): Record<string, unknown> => {
      const record = Object.create(null) as Record<string, unknown>;
      record['a'] = 1;
      return record;
    };
    expect(canonicalizeAssessmentBody(withSymbol(base()))).toBeNull();
    expect(canonicalizeAssessmentBody(withHiddenKey(base()))).toBeNull();
  });

  it('rejects symbol carriers nested at any depth in arrays and objects', () => {
    expect(canonicalizeAssessmentBody([withSymbol<unknown[]>([1])])).toBeNull();
    expect(canonicalizeAssessmentBody({ list: withSymbol<unknown[]>([1]) })).toBeNull();
    expect(canonicalizeAssessmentBody({ inner: withSymbol<Record<string, unknown>>({ a: 1 }) })).toBeNull();
    expect(canonicalizeAssessmentBody([withSymbol<Record<string, unknown>>({ a: 1 })])).toBeNull();
    expect(canonicalizeAssessmentBody({ x: [{ y: [withSymbol<unknown[]>([1])] }] })).toBeNull();
  });

  it('rejects a hidden-key object nested in an array and in an object', () => {
    expect(canonicalizeAssessmentBody([withHiddenKey<Record<string, unknown>>({ a: 1 })])).toBeNull();
    expect(canonicalizeAssessmentBody({ inner: withHiddenKey<Record<string, unknown>>({ a: 1 }) })).toBeNull();
    expect(canonicalizeAssessmentBody({ x: [{ y: withHiddenKey<Record<string, unknown>>({ a: 1 }) }] })).toBeNull();
  });

  it('never lets a carrier collide with its clean baseline', () => {
    const carriers: readonly (readonly [unknown, unknown])[] = [
      [withSymbol<unknown[]>([1]), [1]],
      [withSymbol<unknown[]>([1], false), [1]],
      [withSymbolAccessor<unknown[]>([1]).target, [1]],
      [withHiddenKey<Record<string, unknown>>({ a: 1 }), { a: 1 }],
      [withSymbol<Record<string, unknown>>({ a: 1 }), { a: 1 }],
      [withSymbolAccessor<Record<string, unknown>>({ a: 1 }).target, { a: 1 }],
      [{ list: withSymbol<unknown[]>([1]) }, { list: [1] }],
      [{ inner: withHiddenKey<Record<string, unknown>>({ a: 1 }) }, { inner: { a: 1 } }],
    ];
    for (const [carrier, baseline] of carriers) {
      expect(canonicalizeAssessmentBody(baseline)).not.toBeNull();
      expect(canonicalizeAssessmentBody(carrier)).not.toBe(canonicalizeAssessmentBody(baseline));
    }
  });

  /* Positive controls — byte-identical to the reviewed head 034d809. */

  const UNCHANGED: readonly (readonly [string, unknown, string])[] = [
    ['an empty array', [], '[]'],
    ['an array of scalars', [1, 'a', true, null], '[1,"a",true,null]'],
    ['nested arrays', [[1, [2]], []], '[[1,[2]],[]]'],
    ['an ordinary object', { b: 1, a: 'x' }, '{"a":"x","b":1}'],
    ['nested objects', { z: { y: { x: null } }, a: {} }, '{"a":{},"z":{"y":{"x":null}}}'],
    ['mixed arrays and objects', { list: [{ k: [1, { m: false }] }], n: -7 }, '{"list":[{"k":[1,{"m":false}]}],"n":-7}'],
    ['safe-integer extremes', [Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER, 0], '[9007199254740991,-9007199254740991,0]'],
    ['a frozen plain object', Object.freeze({ b: [2], a: 1 }), '{"a":1,"b":[2]}'],
  ];
  for (const [label, value, text] of UNCHANGED) {
    it(`still canonicalizes ${label} byte-identically`, () => {
      expect(canonicalizeAssessmentBody(value)).toBe(text);
    });
  }

  it('still canonicalizes a null-prototype object byte-identically', () => {
    const record = Object.create(null) as Record<string, unknown>;
    record['b'] = [1];
    record['a'] = 2;
    expect(canonicalizeAssessmentBody(record)).toBe('{"a":2,"b":[1]}');
  });

  it('still accepts an array with a non-enumerable index, emitted positionally', () => {
    const carrier: unknown[] = [1, 2];
    Object.defineProperty(carrier, '0', { value: 1, enumerable: false, writable: true, configurable: true });
    expect(Object.getOwnPropertyDescriptor(carrier, '0')?.enumerable).toBe(false);
    expect(canonicalizeAssessmentBody(carrier)).toBe('[1,2]');
  });

  it('still accepts an enumerable string accessor, emitting its result', () => {
    const record = {};
    Object.defineProperty(record, 'a', { enumerable: true, get: () => 1 });
    expect(canonicalizeAssessmentBody(record)).toBe('{"a":1}');
  });

  it('still canonicalizes the module’s frozen reasonCodes, toJSON shadow included', () => {
    const { reasonCodes } = classifyRetirementCandidate(
      withFact(eligibleFacts(), 'f9GovernanceManifest', determinate(GOVERNANCE_HOLD.HOLD)),
    );
    expect(Object.getOwnPropertySymbols(reasonCodes)).toEqual([]);
    expect(canonicalizeAssessmentBody(reasonCodes)).toBe('["GOVERNANCE_HOLD"]');
  });

  it('still canonicalizes the full assessment body byte-identically', () => {
    expect(canonicalizeAssessmentBody(eligibleBody())).toBe(ELIGIBLE_BODY_TEXT);
  });
});

/* ------------------------------------------------------------------------- *
 * AB-CJSON-1 — numeric conversion is immune to a mutated global String
 * ------------------------------------------------------------------------- */

const REAL_STRING = String;

/**
 * Run `body` with `globalThis.String` replaced by `poison`, restoring the real
 * intrinsic even if canonicalization throws. Returns the canonical text, or the
 * thrown error, so a test can assert on either.
 */
function withPoisonedString(poison: unknown, value: unknown): string | null | Error {
  try {
    (globalThis as unknown as Record<string, unknown>)['String'] = poison;
    return canonicalizeAssessmentBody(value);
  } catch (error) {
    return error as Error;
  } finally {
    (globalThis as unknown as Record<string, unknown>)['String'] = REAL_STRING;
  }
}

/** A body whose earlier key `a` poisons `String` before the later key `z` is read. */
function poisonsBeforeNumber(poison: unknown, later: unknown): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  Object.defineProperty(body, 'a', {
    enumerable: true,
    configurable: true,
    get: () => {
      (globalThis as unknown as Record<string, unknown>)['String'] = poison;
      return 'x';
    },
  });
  Object.defineProperty(body, 'z', { enumerable: true, configurable: true, value: later });
  return body;
}

describe('AB-CJSON-1 — a mutated global String cannot reach numeric conversion', () => {
  afterEach(() => {
    (globalThis as unknown as Record<string, unknown>)['String'] = REAL_STRING;
  });

  it('restores the real intrinsic after every probe', () => {
    expect(globalThis.String).toBe(REAL_STRING);
  });

  it('encodes the number when a getter installs a throwing String', () => {
    const poison = (): string => {
      throw new Error('poisoned String');
    };

    expect(withPoisonedString(poison, poisonsBeforeNumber(poison, 42))).toBe('{"a":"x","z":42}');
  });

  it('encodes the number when a getter installs a constant formatter', () => {
    const poison = (): string => '0';

    expect(withPoisonedString(poison, poisonsBeforeNumber(poison, 42))).toBe('{"a":"x","z":42}');
  });

  it('encodes the number when a getter installs a non-function', () => {
    expect(withPoisonedString(123, poisonsBeforeNumber(123, 42))).toBe('{"a":"x","z":42}');
  });

  it('encodes the number when a getter removes String entirely', () => {
    expect(withPoisonedString(undefined, poisonsBeforeNumber(undefined, 42))).toBe(
      '{"a":"x","z":42}',
    );
  });

  it('encodes the number when a getter installs a state-changing formatter', () => {
    let calls = 0;
    const poison = (): string => REAL_STRING((calls += 1));

    expect(withPoisonedString(poison, poisonsBeforeNumber(poison, 42))).toBe('{"a":"x","z":42}');
  });

  it('is unaffected when the poisoning happens after an earlier numeric member', () => {
    const poison = (): string => '0';
    const body: Record<string, unknown> = {};
    Object.defineProperty(body, 'a', { enumerable: true, configurable: true, value: 42 });
    Object.defineProperty(body, 'z', {
      enumerable: true,
      configurable: true,
      get: () => {
        (globalThis as unknown as Record<string, unknown>)['String'] = poison;
        return 7;
      },
    });

    expect(withPoisonedString(poison, body)).toBe('{"a":42,"z":7}');
  });

  it('encodes every later numeric member, not just the first', () => {
    const poison = (): string => '0';
    const body: Record<string, unknown> = {};
    Object.defineProperty(body, 'a', {
      enumerable: true,
      configurable: true,
      get: () => {
        (globalThis as unknown as Record<string, unknown>)['String'] = poison;
        return 'x';
      },
    });
    for (const [key, value] of [
      ['w', 11],
      ['x', 22],
      ['y', 33],
      ['z', 44],
    ] as readonly (readonly [string, number])[]) {
      Object.defineProperty(body, key, { enumerable: true, configurable: true, value });
    }

    expect(withPoisonedString(poison, body)).toBe('{"a":"x","w":11,"x":22,"y":33,"z":44}');
  });

  it('encodes a number nested behind a poisoning array element', () => {
    const poison = (): string => '0';
    const first: Record<string, unknown> = {};
    Object.defineProperty(first, 'k', {
      enumerable: true,
      configurable: true,
      get: () => {
        (globalThis as unknown as Record<string, unknown>)['String'] = poison;
        return 'x';
      },
    });

    expect(withPoisonedString(poison, [first, { n: 99 }])).toBe('[{"k":"x"},{"n":99}]');
  });

  it('is unaffected when String is replaced after module load but before the call', () => {
    expect(withPoisonedString((): string => '0', { z: 42 })).toBe('{"z":42}');
  });

  it('keeps two different numbers distinguishable under poisoning', () => {
    const poison = (): string => '0';
    const first = withPoisonedString(poison, poisonsBeforeNumber(poison, 42));
    const second = withPoisonedString(poison, poisonsBeforeNumber(poison, 7));

    expect(first).toBe('{"a":"x","z":42}');
    expect(second).toBe('{"a":"x","z":7}');
    expect(first).not.toBe(second);
  });

  it('is unchanged in an ordinary environment', () => {
    expect(canonicalizeAssessmentBody({ a: 'x', z: 42 })).toBe('{"a":"x","z":42}');
  });

  for (const [label, value, expected] of [
    ['0', 0, '0'],
    ['1', 1, '1'],
    ['-1', -1, '-1'],
    ['42', 42, '42'],
    ['-42', -42, '-42'],
    ['MAX_SAFE_INTEGER', Number.MAX_SAFE_INTEGER, '9007199254740991'],
    ['MIN_SAFE_INTEGER', Number.MIN_SAFE_INTEGER, '-9007199254740991'],
  ] as readonly (readonly [string, number, string])[]) {
    it(`encodes ${label} byte-identically`, () => {
      expect(canonicalizeAssessmentBody(value)).toBe(expected);
      expect(withPoisonedString((): string => 'POISON', value)).toBe(expected);
    });
  }

  for (const [label, value] of [
    ['-0', -0],
    ['NaN', NaN],
    ['Infinity', Infinity],
    ['-Infinity', -Infinity],
    ['1.5', 1.5],
    ['an unsafe integer', Number.MAX_SAFE_INTEGER + 2],
  ] as readonly (readonly [string, number])[]) {
    it(`still rejects ${label}`, () => {
      expect(canonicalizeAssessmentBody(value)).toBeNull();
      expect(withPoisonedString((): string => 'POISON', value)).toBeNull();
    });
  }
});
