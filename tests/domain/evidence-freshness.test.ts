import { describe, expect, it } from 'vitest';

import {
  currentEvidenceOfKind,
  EVIDENCE_KIND,
  EVIDENCE_KINDS,
  EVIDENCE_SOURCES,
  evaluateEvidenceFreshness,
  evaluateEvidenceSet,
  FRESHNESS,
  FRESHNESS_REASON,
  FRESHNESS_REASONS,
  FRESHNESS_STATES,
  isEvidenceKind,
  isEvidenceSource,
  REQUIRED_EVIDENCE_FIELDS,
} from '../../src/domain/index.js';
import {
  buildEvidence,
  buildTarget,
  FRESHNESS_SCENARIOS,
  HEAD_A,
  HEAD_B,
  MALFORMED_VALUES,
  REPO_A,
  REPO_B,
  UNSUPPORTED_KINDS,
  UNSUPPORTED_SOURCES,
  withoutField,
  withRawField,
} from './evidence-fixtures.js';

describe('independently declared freshness matrix', () => {
  for (const scenario of FRESHNESS_SCENARIOS) {
    it(`returns ${scenario.expected} for ${scenario.name}`, () => {
      const result = evaluateEvidenceFreshness(scenario.evidence, scenario.target);

      expect(result.state).toBe(scenario.expected);
    });
  }

  it('covers all three states in the scenario table', () => {
    const covered = new Set(FRESHNESS_SCENARIOS.map((s) => s.expected));

    expect([...covered].sort()).toEqual(['CURRENT', 'INVALID', 'STALE']);
  });
});

describe('current evidence', () => {
  it('reports CURRENT with the binding reason and no invalid fields', () => {
    const result = evaluateEvidenceFreshness(buildEvidence(), buildTarget());

    expect(result.state).toBe(FRESHNESS.CURRENT);
    expect(result.reason).toBe(FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD);
    expect(result.invalidFields).toEqual([]);
    expect(result.commitSha).toBe(HEAD_A);
    expect(result.targetHeadSha).toBe(HEAD_A);
    expect(result.repositoryId).toBe(REPO_A);
  });

  it('is CURRENT for every supported kind and source', () => {
    for (const kind of EVIDENCE_KINDS) {
      for (const source of EVIDENCE_SOURCES) {
        const result = evaluateEvidenceFreshness(
          buildEvidence({ kind, source }),
          buildTarget(),
        );

        expect(result.state, `${kind}/${source}`).toBe(FRESHNESS.CURRENT);
      }
    }
  });
});

describe('a HEAD change makes prior evidence stale', () => {
  it('turns SHA-A evidence stale once HEAD moves to SHA-B', () => {
    const evidence = buildEvidence({ commitSha: HEAD_A });

    expect(evaluateEvidenceFreshness(evidence, buildTarget({ currentHeadSha: HEAD_A })).state).toBe(
      FRESHNESS.CURRENT,
    );
    expect(evaluateEvidenceFreshness(evidence, buildTarget({ currentHeadSha: HEAD_B })).state).toBe(
      FRESHNESS.STALE,
    );
  });

  it('reports the SHA mismatch reason without inventing invalid fields', () => {
    const result = evaluateEvidenceFreshness(
      buildEvidence({ commitSha: HEAD_A }),
      buildTarget({ currentHeadSha: HEAD_B }),
    );

    expect(result.reason).toBe(FRESHNESS_REASON.COMMIT_SHA_MISMATCH);
    expect(result.invalidFields).toEqual([]);
    expect(result.commitSha).toBe(HEAD_A);
    expect(result.targetHeadSha).toBe(HEAD_B);
  });

  it('is stale for every supported kind and source when the SHA differs', () => {
    for (const kind of EVIDENCE_KINDS) {
      for (const source of EVIDENCE_SOURCES) {
        const result = evaluateEvidenceFreshness(
          buildEvidence({ kind, source, commitSha: HEAD_A }),
          buildTarget({ currentHeadSha: HEAD_B }),
        );

        expect(result.state, `${kind}/${source}`).toBe(FRESHNESS.STALE);
      }
    }
  });
});

describe('cross-repository replay', () => {
  it('never reports CURRENT for evidence about another repository', () => {
    const result = evaluateEvidenceFreshness(
      buildEvidence({ repositoryId: REPO_B, commitSha: HEAD_A }),
      buildTarget({ repositoryId: REPO_A, currentHeadSha: HEAD_A }),
    );

    expect(result.state).not.toBe(FRESHNESS.CURRENT);
    expect(result.reason).toBe(FRESHNESS_REASON.REPOSITORY_MISMATCH);
  });

  it('rejects the replay even when the SHA strings are identical', () => {
    for (const kind of EVIDENCE_KINDS) {
      const result = evaluateEvidenceFreshness(
        buildEvidence({ repositoryId: REPO_B, commitSha: HEAD_A, kind }),
        buildTarget({ repositoryId: REPO_A, currentHeadSha: HEAD_A }),
      );

      expect(result.state, kind).not.toBe(FRESHNESS.CURRENT);
    }
  });

  it('rejects the replay in both directions', () => {
    const aToB = evaluateEvidenceFreshness(
      buildEvidence({ repositoryId: REPO_A }),
      buildTarget({ repositoryId: REPO_B, currentHeadSha: HEAD_A }),
    );
    const bToA = evaluateEvidenceFreshness(
      buildEvidence({ repositoryId: REPO_B }),
      buildTarget({ repositoryId: REPO_A, currentHeadSha: HEAD_A }),
    );

    expect(aToB.state).not.toBe(FRESHNESS.CURRENT);
    expect(bToA.state).not.toBe(FRESHNESS.CURRENT);
  });
});

describe('malformed evidence fails closed without throwing', () => {
  for (const field of REQUIRED_EVIDENCE_FIELDS) {
    it(`is INVALID when ${field} is omitted entirely`, () => {
      const evidence = withoutField(field);

      expect(() => evaluateEvidenceFreshness(evidence, buildTarget())).not.toThrow();

      const result = evaluateEvidenceFreshness(evidence, buildTarget());
      expect(result.state).toBe(FRESHNESS.INVALID);
      expect(result.reason).toBe(FRESHNESS_REASON.EVIDENCE_MALFORMED);
      expect(result.invalidFields).toContain(field);
    });
  }

  it('is INVALID for every malformed runtime value in every required field', () => {
    for (const field of REQUIRED_EVIDENCE_FIELDS) {
      for (const [label, value] of MALFORMED_VALUES) {
        const evidence = withRawField(field, value);

        expect(() => evaluateEvidenceFreshness(evidence, buildTarget())).not.toThrow();

        const result = evaluateEvidenceFreshness(evidence, buildTarget());
        expect(result.state, `${field} = ${label}`).toBe(FRESHNESS.INVALID);
        expect(result.invalidFields, `${field} = ${label}`).toContain(field);
      }
    }
  });

  it('never echoes a non-string runtime value into the result', () => {
    for (const [, value] of MALFORMED_VALUES) {
      const result = evaluateEvidenceFreshness(
        withRawField('commitSha', value),
        buildTarget(),
      );

      expect(result.commitSha === null || typeof result.commitSha === 'string').toBe(true);
    }
  });

  it('reports every malformed field at once', () => {
    const evidence = {
      ...buildEvidence(),
      evidenceId: undefined,
      commitSha: null,
      reference: 42,
    } as unknown as ReturnType<typeof buildEvidence>;
    const result = evaluateEvidenceFreshness(evidence, buildTarget());

    expect([...result.invalidFields].sort()).toEqual(
      ['commitSha', 'evidenceId', 'reference'].sort(),
    );
  });

  it('is INVALID for unsupported evidence kinds', () => {
    for (const kind of UNSUPPORTED_KINDS) {
      const result = evaluateEvidenceFreshness(withRawField('kind', kind), buildTarget());

      expect(result.state, kind).toBe(FRESHNESS.INVALID);
      expect(result.invalidFields, kind).toContain('kind');
      expect(result.kind, kind).toBeNull();
    }
  });

  it('is INVALID for unsupported evidence sources', () => {
    for (const source of UNSUPPORTED_SOURCES) {
      const result = evaluateEvidenceFreshness(withRawField('source', source), buildTarget());

      expect(result.state, source).toBe(FRESHNESS.INVALID);
      expect(result.invalidFields, source).toContain('source');
      expect(result.source, source).toBeNull();
    }
  });

  it('does not treat prototype keys as supported vocabulary', () => {
    for (const value of ['__proto__', 'constructor', 'toString', 'valueOf']) {
      expect(isEvidenceKind(value), value).toBe(false);
      expect(isEvidenceSource(value), value).toBe(false);
    }
  });
});

describe('the evaluation target is validated too', () => {
  for (const [label, value] of MALFORMED_VALUES) {
    it(`is INVALID when the target HEAD is ${label}`, () => {
      const target = { repositoryId: REPO_A, currentHeadSha: value } as unknown as ReturnType<
        typeof buildTarget
      >;

      expect(() => evaluateEvidenceFreshness(buildEvidence(), target)).not.toThrow();

      const result = evaluateEvidenceFreshness(buildEvidence(), target);
      expect(result.state).toBe(FRESHNESS.INVALID);
      expect(result.reason).toBe(FRESHNESS_REASON.EVALUATION_TARGET_INVALID);
    });
  }

  it('is INVALID when the target repository is blank', () => {
    const result = evaluateEvidenceFreshness(buildEvidence(), buildTarget({ repositoryId: '  ' }));

    expect(result.state).toBe(FRESHNESS.INVALID);
    expect(result.reason).toBe(FRESHNESS_REASON.EVALUATION_TARGET_INVALID);
    expect(result.invalidFields).toContain('target.repositoryId');
  });
});

describe('result vocabulary and shape', () => {
  it('emits only declared states and reasons', () => {
    for (const scenario of FRESHNESS_SCENARIOS) {
      const result = evaluateEvidenceFreshness(scenario.evidence, scenario.target);

      expect(FRESHNESS_STATES).toContain(result.state);
      expect(FRESHNESS_REASONS).toContain(result.reason);
    }
  });

  it('round-trips through JSON without loss', () => {
    for (const scenario of FRESHNESS_SCENARIOS) {
      const result = evaluateEvidenceFreshness(scenario.evidence, scenario.target);
      const revived: unknown = JSON.parse(JSON.stringify(result));

      expect(revived).toEqual(result);
    }
  });

  it('carries no authority field', () => {
    const keys = Object.keys(evaluateEvidenceFreshness(buildEvidence(), buildTarget()));

    for (const forbidden of [
      'approvedForMerge',
      'authorized',
      'mayExecute',
      'mayExecuteAutonomously',
      'approved',
      'decision',
      'requiresHumanApproval',
    ]) {
      expect(keys).not.toContain(forbidden);
    }
  });
});

describe('evidence set evaluation', () => {
  const records = [
    buildEvidence({ evidenceId: 'ev-current-ci', commitSha: HEAD_A, kind: EVIDENCE_KIND.CI_RESULT }),
    buildEvidence({
      evidenceId: 'ev-current-review',
      commitSha: HEAD_A,
      kind: EVIDENCE_KIND.CODE_REVIEW,
    }),
    buildEvidence({ evidenceId: 'ev-stale', commitSha: HEAD_B }),
    buildEvidence({ evidenceId: 'ev-foreign', repositoryId: REPO_B }),
    withRawField('commitSha', null),
  ];

  it('partitions records without changing any individual verdict', () => {
    const evaluation = evaluateEvidenceSet(records, buildTarget());

    expect(evaluation.results.length).toBe(records.length);
    expect(evaluation.current.map((r) => r.evidenceId)).toEqual([
      'ev-current-ci',
      'ev-current-review',
    ]);
    expect(evaluation.stale.map((r) => r.evidenceId)).toEqual(['ev-stale']);
    expect(evaluation.invalid.length).toBe(2);
  });

  it('matches single evaluation for every record', () => {
    const evaluation = evaluateEvidenceSet(records, buildTarget());

    records.forEach((record, index) => {
      expect(evaluation.results[index]).toEqual(
        evaluateEvidenceFreshness(record, buildTarget()),
      );
    });
  });

  it('never promotes a stale record when it is surrounded by current ones', () => {
    const evaluation = evaluateEvidenceSet(records, buildTarget());

    for (const result of evaluation.current) {
      expect(result.commitSha).toBe(HEAD_A);
    }
    expect(evaluation.current.map((r) => r.evidenceId)).not.toContain('ev-stale');
  });

  it('re-partitions entirely when HEAD moves: previously current records go stale', () => {
    const evaluation = evaluateEvidenceSet(records, buildTarget({ currentHeadSha: HEAD_B }));

    expect(evaluation.current.map((r) => r.evidenceId)).toEqual(['ev-stale']);
    expect(evaluation.stale.map((r) => r.evidenceId)).toEqual([
      'ev-current-ci',
      'ev-current-review',
    ]);
  });

  it('handles an empty collection', () => {
    const evaluation = evaluateEvidenceSet([], buildTarget());

    expect(evaluation.results).toEqual([]);
    expect(evaluation.current).toEqual([]);
  });

  it('queries current evidence by kind without crossing buckets', () => {
    const evaluation = evaluateEvidenceSet(records, buildTarget());

    expect(currentEvidenceOfKind(evaluation, EVIDENCE_KIND.CI_RESULT).map((r) => r.evidenceId)).toEqual(
      ['ev-current-ci'],
    );
    expect(
      currentEvidenceOfKind(evaluation, EVIDENCE_KIND.CODE_REVIEW).map((r) => r.evidenceId),
    ).toEqual(['ev-current-review']);
    expect(currentEvidenceOfKind(evaluation, EVIDENCE_KIND.SECURITY_REVIEW)).toEqual([]);
  });

  it('drops old-HEAD evidence from a by-kind query once HEAD moves on', () => {
    const evaluation = evaluateEvidenceSet(records, buildTarget({ currentHeadSha: HEAD_B }));
    const currentCi = currentEvidenceOfKind(evaluation, EVIDENCE_KIND.CI_RESULT).map(
      (r) => r.evidenceId,
    );

    // ev-current-ci was bound to HEAD_A and must no longer be queryable as current.
    expect(currentCi).not.toContain('ev-current-ci');
    // ev-stale is bound to HEAD_B, so it is legitimately current at the new HEAD.
    expect(currentCi).toEqual(['ev-stale']);
    // The code review bound to HEAD_A is gone from its own kind query too.
    expect(currentEvidenceOfKind(evaluation, EVIDENCE_KIND.CODE_REVIEW)).toEqual([]);
  });
});
