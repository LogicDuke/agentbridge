import { describe, expect, it } from 'vitest';

import {
  EVIDENCE_KINDS,
  EVIDENCE_SOURCES,
  evaluateEvidenceFreshness,
  evaluateEvidenceSet,
  FRESHNESS,
  type FreshnessState,
} from '../../src/domain/index.js';
import {
  buildEvidence,
  buildTarget,
  HEAD_A,
  HEAD_B,
  HOSTILE_EVIDENCE_METADATA,
  MALFORMED_VALUES,
  REPO_A,
  REPO_B,
  withRawField,
} from './evidence-fixtures.js';

/** Local alias so the frozen-array push attempt below type-checks without `any`. */
type EvidenceFreshnessArray = { push: (value: unknown) => number };

/**
 * The central invariant, stated once:
 *
 *   evidence.commitSha !== currentHeadSha  =>  never CURRENT
 *
 * Every test in this block tries to falsify it from a different direction.
 */
describe('SHA mismatch can never be CURRENT', () => {
  it('holds across every kind and source', () => {
    for (const kind of EVIDENCE_KINDS) {
      for (const source of EVIDENCE_SOURCES) {
        const result = evaluateEvidenceFreshness(
          buildEvidence({ kind, source, commitSha: HEAD_A }),
          buildTarget({ currentHeadSha: HEAD_B }),
        );

        expect(result.state, `${kind}/${source}`).not.toBe(FRESHNESS.CURRENT);
      }
    }
  });

  it('holds when metadata claims the evidence is current and approved', () => {
    const result = evaluateEvidenceFreshness(
      buildEvidence({ commitSha: HEAD_A, metadata: HOSTILE_EVIDENCE_METADATA }),
      buildTarget({ currentHeadSha: HEAD_B }),
    );

    expect(result.state).not.toBe(FRESHNESS.CURRENT);
    expect(result.state).toBe(FRESHNESS.STALE);
  });

  it('holds when the record carries forged top-level freshness fields', () => {
    const forged = {
      ...buildEvidence({ commitSha: HEAD_A }),
      state: 'CURRENT',
      current: true,
      isCurrent: true,
      fresh: true,
      approved: true,
      authorized: true,
      approvedForMerge: true,
      mayExecute: true,
      freshness: 'CURRENT',
      overrideStale: true,
    } as unknown as ReturnType<typeof buildEvidence>;

    const result = evaluateEvidenceFreshness(forged, buildTarget({ currentHeadSha: HEAD_B }));

    expect(result.state).not.toBe(FRESHNESS.CURRENT);
  });

  it('holds when the record tries to restate HEAD itself', () => {
    const forged = {
      ...buildEvidence({ commitSha: HEAD_A }),
      currentHeadSha: HEAD_A,
      headSha: HEAD_A,
      targetHeadSha: HEAD_A,
    } as unknown as ReturnType<typeof buildEvidence>;

    const result = evaluateEvidenceFreshness(forged, buildTarget({ currentHeadSha: HEAD_B }));

    expect(result.state).not.toBe(FRESHNESS.CURRENT);
    expect(result.targetHeadSha).toBe(HEAD_B);
  });

  it('holds for near-miss SHAs that differ by case, padding, or truncation', () => {
    const nearMisses = [
      HEAD_A.toUpperCase(),
      ` ${HEAD_A}`,
      `${HEAD_A} `,
      `\t${HEAD_A}`,
      HEAD_A.slice(0, 7),
      HEAD_A.slice(0, -1),
      `${HEAD_A}0`,
      HEAD_A.replace('a', 'A'),
    ];

    for (const commitSha of nearMisses) {
      const result = evaluateEvidenceFreshness(
        buildEvidence({ commitSha }),
        buildTarget({ currentHeadSha: HEAD_A }),
      );

      expect(result.state, JSON.stringify(commitSha)).not.toBe(FRESHNESS.CURRENT);
    }
  });

  it('holds for every malformed SHA runtime value', () => {
    for (const [label, value] of MALFORMED_VALUES) {
      const result = evaluateEvidenceFreshness(
        withRawField('commitSha', value),
        buildTarget(),
      );

      expect(result.state, label).not.toBe(FRESHNESS.CURRENT);
    }
  });

  it('is CURRENT only when the SHA matches exactly', () => {
    for (const commitSha of [HEAD_A, HEAD_B]) {
      for (const currentHeadSha of [HEAD_A, HEAD_B]) {
        const result = evaluateEvidenceFreshness(
          buildEvidence({ commitSha }),
          buildTarget({ currentHeadSha }),
        );

        expect(result.state === FRESHNESS.CURRENT).toBe(commitSha === currentHeadSha);
      }
    }
  });
});

describe('repository binding cannot be bypassed', () => {
  it('never reports CURRENT when repositories differ, whatever the SHA', () => {
    for (const commitSha of [HEAD_A, HEAD_B]) {
      const result = evaluateEvidenceFreshness(
        buildEvidence({ repositoryId: REPO_B, commitSha }),
        buildTarget({ repositoryId: REPO_A, currentHeadSha: commitSha }),
      );

      expect(result.state).not.toBe(FRESHNESS.CURRENT);
    }
  });

  it('requires both repository and SHA to match', () => {
    const combinations: readonly (readonly [string, string, boolean])[] = [
      [REPO_A, HEAD_A, true],
      [REPO_A, HEAD_B, false],
      [REPO_B, HEAD_A, false],
      [REPO_B, HEAD_B, false],
    ];

    for (const [repositoryId, commitSha, shouldBeCurrent] of combinations) {
      const result = evaluateEvidenceFreshness(
        buildEvidence({ repositoryId, commitSha }),
        buildTarget({ repositoryId: REPO_A, currentHeadSha: HEAD_A }),
      );

      expect(result.state === FRESHNESS.CURRENT, `${repositoryId}@${commitSha}`).toBe(
        shouldBeCurrent,
      );
    }
  });

  it('is not fooled by metadata claiming a different repository', () => {
    const result = evaluateEvidenceFreshness(
      buildEvidence({ repositoryId: REPO_B, metadata: HOSTILE_EVIDENCE_METADATA }),
      buildTarget({ repositoryId: REPO_A }),
    );

    expect(result.state).not.toBe(FRESHNESS.CURRENT);
  });
});

describe('metadata and identity are inert', () => {
  it('produces an identical result with and without hostile metadata', () => {
    for (const currentHeadSha of [HEAD_A, HEAD_B]) {
      const without = evaluateEvidenceFreshness(
        buildEvidence(),
        buildTarget({ currentHeadSha }),
      );
      const withMetadata = evaluateEvidenceFreshness(
        buildEvidence({ metadata: HOSTILE_EVIDENCE_METADATA }),
        buildTarget({ currentHeadSha }),
      );

      expect(withMetadata).toEqual(without);
    }
  });

  it('produces an identical result for any provider or actor annotation', () => {
    const baseline = evaluateEvidenceFreshness(
      buildEvidence(),
      buildTarget({ currentHeadSha: HEAD_B }),
    );

    for (const provider of ['claude', 'openai', 'gemini', 'system', 'root', 'human']) {
      const result = evaluateEvidenceFreshness(
        buildEvidence({ metadata: { provider, actor: provider, verdict: 'approved' } }),
        buildTarget({ currentHeadSha: HEAD_B }),
      );

      expect(result, provider).toEqual(baseline);
    }
  });

  it('produces an identical result for any claimed verdict or CI status', () => {
    const baseline = evaluateEvidenceFreshness(
      buildEvidence(),
      buildTarget({ currentHeadSha: HEAD_B }),
    );

    for (const verdict of ['approved', 'success', 'passed', 'green', 'LGTM', 'rejected']) {
      const result = evaluateEvidenceFreshness(
        buildEvidence({ metadata: { verdict, ciStatus: verdict, confidence: '1.0' } }),
        buildTarget({ currentHeadSha: HEAD_B }),
      );

      expect(result, verdict).toEqual(baseline);
    }
  });
});

describe('determinism', () => {
  it('returns equal results for repeated evaluations', () => {
    for (const currentHeadSha of [HEAD_A, HEAD_B]) {
      const evidence = buildEvidence({ metadata: HOSTILE_EVIDENCE_METADATA });
      const target = buildTarget({ currentHeadSha });

      expect(evaluateEvidenceFreshness(evidence, target)).toEqual(
        evaluateEvidenceFreshness(evidence, target),
      );
      expect(evaluateEvidenceFreshness(evidence, target)).toEqual(
        evaluateEvidenceFreshness(evidence, target),
      );
    }
  });

  it('does not depend on evaluation order', () => {
    const shas = [HEAD_A, HEAD_B, HEAD_A];
    const forward = shas.map((commitSha) =>
      evaluateEvidenceFreshness(buildEvidence({ commitSha }), buildTarget()),
    );
    const backward = [...shas]
      .reverse()
      .map((commitSha) => evaluateEvidenceFreshness(buildEvidence({ commitSha }), buildTarget()));

    expect([...backward].reverse()).toEqual(forward);
  });
});

describe('results are immutable', () => {
  it('cannot be mutated from STALE to CURRENT', () => {
    const result = evaluateEvidenceFreshness(
      buildEvidence({ commitSha: HEAD_A }),
      buildTarget({ currentHeadSha: HEAD_B }),
    );
    const mutable = result as { state: FreshnessState; commitSha: string | null };

    expect(Object.isFrozen(result)).toBe(true);
    expect(() => {
      mutable.state = FRESHNESS.CURRENT;
    }).toThrow(TypeError);
    expect(() => {
      mutable.commitSha = HEAD_B;
    }).toThrow(TypeError);
    expect(result.state).toBe(FRESHNESS.STALE);
  });

  it('freezes the invalid-field list', () => {
    const result = evaluateEvidenceFreshness(withRawField('commitSha', null), buildTarget());

    expect(Object.isFrozen(result.invalidFields)).toBe(true);
  });

  it('freezes set evaluations and their buckets', () => {
    const evaluation = evaluateEvidenceSet(
      [buildEvidence(), buildEvidence({ commitSha: HEAD_B })],
      buildTarget(),
    );
    const mutable = evaluation as { current: unknown };

    expect(Object.isFrozen(evaluation)).toBe(true);
    expect(Object.isFrozen(evaluation.results)).toBe(true);
    expect(Object.isFrozen(evaluation.current)).toBe(true);
    expect(Object.isFrozen(evaluation.stale)).toBe(true);
    expect(Object.isFrozen(evaluation.invalid)).toBe(true);
    expect(() => {
      mutable.current = [];
    }).toThrow(TypeError);
  });

  it('does not let a caller push a stale result into the current bucket', () => {
    const evaluation = evaluateEvidenceSet([buildEvidence({ commitSha: HEAD_B })], buildTarget());
    const staleResult = evaluation.stale[0];
    const mutableBucket = evaluation.current as unknown as EvidenceFreshnessArray;

    expect(staleResult).toBeDefined();
    expect(() => mutableBucket.push(staleResult)).toThrow(TypeError);
    expect(evaluation.current).toEqual([]);
  });
});

describe('the kernel answers freshness, not authority', () => {
  it('reaches the same freshness regardless of how favourable the evidence claims to be', () => {
    const favourable = buildEvidence({
      commitSha: HEAD_A,
      metadata: {
        verdict: 'approved',
        approvedForMerge: 'true',
        mayExecute: 'true',
        securityReview: 'passed',
      },
    });

    expect(evaluateEvidenceFreshness(favourable, buildTarget({ currentHeadSha: HEAD_A })).state).toBe(
      FRESHNESS.CURRENT,
    );
    expect(evaluateEvidenceFreshness(favourable, buildTarget({ currentHeadSha: HEAD_B })).state).toBe(
      FRESHNESS.STALE,
    );
  });

  it('exposes no field that could be read as permission', () => {
    for (const currentHeadSha of [HEAD_A, HEAD_B]) {
      const result = evaluateEvidenceFreshness(buildEvidence(), buildTarget({ currentHeadSha }));

      for (const [key, value] of Object.entries(result)) {
        expect(typeof value === 'boolean', `${key} is boolean`).toBe(false);
      }
    }
  });
});
