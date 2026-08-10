import { describe, expect, it } from 'vitest';

import {
  EVIDENCE_KINDS,
  EVIDENCE_SOURCES,
  evaluateEvidenceFreshness,
  evaluateEvidenceSet,
  FRESHNESS,
  FRESHNESS_REASON,
  FRESHNESS_REASONS,
  FRESHNESS_STATES,
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

/**
 * Regression cover for the exported vocabulary being mutable at runtime.
 *
 * `as const` is compile-time only. Expected states here are bare literals, not
 * `FRESHNESS.*`, because the vocabulary object is exactly what is under test.
 */
describe('the exported freshness vocabulary is frozen', () => {
  it('cannot be mutated to make a stale SHA report CURRENT', () => {
    expect(Object.isFrozen(FRESHNESS)).toBe(true);

    const mutable = FRESHNESS as unknown as Record<string, string>;
    expect(() => {
      mutable['STALE'] = 'CURRENT';
    }).toThrow(TypeError);

    const result = evaluateEvidenceFreshness(
      buildEvidence({ commitSha: HEAD_A }),
      buildTarget({ currentHeadSha: HEAD_B }),
    );

    expect(result.state).toBe('STALE');
    expect(result.state).not.toBe('CURRENT');
  });

  it('cannot have CURRENT redefined', () => {
    const mutable = FRESHNESS as unknown as Record<string, string>;

    expect(() => {
      mutable['CURRENT'] = 'STALE';
    }).toThrow(TypeError);
    expect(FRESHNESS.CURRENT).toBe('CURRENT');
  });

  it('freezes the reason vocabulary and both listing arrays', () => {
    expect(Object.isFrozen(FRESHNESS_REASON)).toBe(true);
    expect(Object.isFrozen(FRESHNESS_STATES)).toBe(true);
    expect(Object.isFrozen(FRESHNESS_REASONS)).toBe(true);
  });
});

/**
 * Regression cover for time-of-check/time-of-use on an untrusted record.
 * A getter or Proxy may return a different value on each read.
 */
describe('untrusted evidence is snapshotted exactly once', () => {
  it('reads every freshness-relevant property exactly once', () => {
    const reads: Record<string, number> = {};
    const backing = buildEvidence() as unknown as Record<string, unknown>;
    const counted = new Proxy(backing, {
      get(t, p) {
        const key = String(p);
        reads[key] = (reads[key] ?? 0) + 1;
        return t[key];
      },
    }) as unknown as ReturnType<typeof buildEvidence>;

    evaluateEvidenceFreshness(counted, buildTarget());

    for (const field of [
      'evidenceId',
      'repositoryId',
      'commitSha',
      'reference',
      'observedAt',
      'kind',
      'source',
    ]) {
      expect(reads[field], field).toBe(1);
    }
  });

  it('compares the same commitSha it reports, when the value flips between reads', () => {
    let reads = 0;
    const flipping = {
      ...buildEvidence(),
      get commitSha(): string {
        reads += 1;
        return reads === 1 ? HEAD_B : HEAD_A;
      },
    } as ReturnType<typeof buildEvidence>;

    const result = evaluateEvidenceFreshness(flipping, buildTarget({ currentHeadSha: HEAD_B }));

    expect(reads).toBe(1);
    // The reported SHA is the one that was compared — no second value slipped in.
    expect(result.state === 'CURRENT').toBe(result.commitSha === result.targetHeadSha);
  });

  it('never reports CURRENT when the reported repositoryId differs from the target', () => {
    let reads = 0;
    const flipping = {
      ...buildEvidence(),
      get repositoryId(): string {
        reads += 1;
        return reads === 1 ? REPO_B : REPO_A;
      },
    } as ReturnType<typeof buildEvidence>;

    const result = evaluateEvidenceFreshness(flipping, buildTarget({ repositoryId: REPO_A }));

    expect(result.state).not.toBe('CURRENT');
    expect(result.repositoryId).toBe(REPO_B);
  });

  it('does not throw on a Proxy that flips every property', () => {
    let reads = 0;
    const hostile = new Proxy(buildEvidence() as unknown as Record<string, unknown>, {
      get(t, p) {
        reads += 1;
        return reads % 2 === 0 ? undefined : t[String(p)];
      },
    }) as unknown as ReturnType<typeof buildEvidence>;

    expect(() => evaluateEvidenceFreshness(hostile, buildTarget())).not.toThrow();
  });

  it('keeps a stale record stale even when its SHA later claims to be HEAD', () => {
    let reads = 0;
    const flipping = {
      ...buildEvidence(),
      get commitSha(): string {
        reads += 1;
        return reads === 1 ? HEAD_A : HEAD_B;
      },
    } as ReturnType<typeof buildEvidence>;

    const result = evaluateEvidenceFreshness(flipping, buildTarget({ currentHeadSha: HEAD_B }));

    expect(result.state).toBe('STALE');
    expect(result.commitSha).toBe(HEAD_A);
  });
});

/** Regression cover for dereferencing a non-object record. */
describe('non-object evidence fails closed', () => {
  const NON_OBJECTS: readonly (readonly [string, unknown])[] = [
    ['null', null],
    ['undefined', undefined],
    ['a string', 'evidence'],
    ['a number', 42],
    ['a zero', 0],
    ['a boolean', true],
    ['a function', (): string => HEAD_A],
    ['a symbol', Symbol('evidence')],
    ['a bigint', 10n],
  ];

  for (const [label, value] of NON_OBJECTS) {
    it(`returns INVALID without throwing when evidence is ${label}`, () => {
      const evidence = value as ReturnType<typeof buildEvidence>;

      expect(() => evaluateEvidenceFreshness(evidence, buildTarget())).not.toThrow();

      const result = evaluateEvidenceFreshness(evidence, buildTarget());
      expect(result.state).toBe('INVALID');
      expect(result.state).not.toBe('CURRENT');
      expect(result.invalidFields).toContain('evidence');
      expect(result.commitSha).toBeNull();
    });
  }

  it('evaluates the rest of a set when one element is null or undefined', () => {
    const records = [
      buildEvidence({ evidenceId: 'ev-ok', commitSha: HEAD_A }),
      null,
      buildEvidence({ evidenceId: 'ev-stale', commitSha: HEAD_B }),
      undefined,
      { ...buildEvidence({ evidenceId: 'ev-bad' }), commitSha: 42 },
    ] as ReturnType<typeof buildEvidence>[];

    expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();

    const evaluation = evaluateEvidenceSet(records, buildTarget());
    expect(evaluation.results.length).toBe(5);
    expect(evaluation.current.map((r) => r.evidenceId)).toEqual(['ev-ok']);
    expect(evaluation.stale.map((r) => r.evidenceId)).toEqual(['ev-stale']);
    expect(evaluation.invalid.length).toBe(3);
  });

  for (const [label, value] of NON_OBJECTS) {
    it(`returns INVALID without throwing when the target is ${label}`, () => {
      const target = value as ReturnType<typeof buildTarget>;

      expect(() => evaluateEvidenceFreshness(buildEvidence(), target)).not.toThrow();

      const result = evaluateEvidenceFreshness(buildEvidence(), target);
      expect(result.state).toBe('INVALID');
      expect(result.state).not.toBe('CURRENT');
      expect(result.reason).toBe(FRESHNESS_REASON.EVALUATION_TARGET_INVALID);
      expect(result.targetRepositoryId).toBeNull();
      expect(result.targetHeadSha).toBeNull();
    });
  }

  for (const [label, value] of NON_OBJECTS) {
    it(`evaluates an empty set without throwing when the collection is ${label}`, () => {
      const records = value as ReturnType<typeof buildEvidence>[];

      expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();

      const evaluation = evaluateEvidenceSet(records, buildTarget());
      expect(evaluation.results).toEqual([]);
      expect(evaluation.current).toEqual([]);
      expect(evaluation.stale).toEqual([]);
      expect(evaluation.invalid).toEqual([]);
    });
  }

  it('keeps a mixed set deterministic and never promotes a bad record', () => {
    const records = [
      null,
      buildEvidence({ commitSha: HEAD_B }),
      undefined,
      buildEvidence({ commitSha: HEAD_A }),
    ] as ReturnType<typeof buildEvidence>[];

    const first = evaluateEvidenceSet(records, buildTarget());
    const second = evaluateEvidenceSet(records, buildTarget());

    expect(second).toEqual(first);
    expect(first.current.length).toBe(1);
    for (const result of first.current) {
      expect(result.commitSha).toBe(HEAD_A);
    }
  });
});

/**
 * Regression cover for a hostile record mutating the caller-supplied target
 * partway through a set evaluation.
 */
describe('the set target is snapshotted before any record is evaluated', () => {
  it('does not let one record retarget the evaluation for a later record', () => {
    const target = { repositoryId: REPO_A, currentHeadSha: HEAD_A };
    const hostile = {
      ...buildEvidence({ evidenceId: 'ev-hostile', repositoryId: REPO_A, commitSha: HEAD_A }),
      get kind(): string {
        // Retarget the caller's object midway through the set.
        target.repositoryId = REPO_B;
        target.currentHeadSha = HEAD_B;
        return 'ci-result';
      },
    } as ReturnType<typeof buildEvidence>;
    const later = buildEvidence({
      evidenceId: 'ev-later',
      repositoryId: REPO_B,
      commitSha: HEAD_B,
    });

    const evaluation = evaluateEvidenceSet([hostile, later], target);
    const laterResult = evaluation.results[1];

    expect(laterResult?.state).not.toBe('CURRENT');
    expect(laterResult?.state).toBe('INVALID');
    expect(evaluation.current.map((r) => r.evidenceId)).toEqual(['ev-hostile']);
  });

  it('evaluates every record against the same repository and HEAD', () => {
    const target = { repositoryId: REPO_A, currentHeadSha: HEAD_A };
    const hostile = {
      ...buildEvidence({ evidenceId: 'ev-hostile' }),
      get source(): string {
        target.currentHeadSha = HEAD_B;
        return 'github';
      },
    } as ReturnType<typeof buildEvidence>;

    const evaluation = evaluateEvidenceSet(
      [hostile, buildEvidence({ evidenceId: 'ev-a', commitSha: HEAD_A })],
      target,
    );

    for (const result of evaluation.results) {
      expect(result.targetRepositoryId).toBe(REPO_A);
      expect(result.targetHeadSha).toBe(HEAD_A);
    }
  });

  it('is unaffected by a target mutated after evaluation returns', () => {
    const target = { repositoryId: REPO_A, currentHeadSha: HEAD_A };
    const evaluation = evaluateEvidenceSet([buildEvidence({ commitSha: HEAD_A })], target);

    target.repositoryId = REPO_B;
    target.currentHeadSha = HEAD_B;

    expect(evaluation.results[0]?.targetHeadSha).toBe(HEAD_A);
    expect(evaluation.current.length).toBe(1);
  });
});

/** Regression cover for property reads that throw. */
describe('hostile property access fails closed', () => {
  const throwingGetter = (field: string): ReturnType<typeof buildEvidence> =>
    Object.defineProperty({ ...buildEvidence() }, field, {
      get(): never {
        throw new Error(`hostile ${field}`);
      },
      configurable: true,
      enumerable: true,
    }) as ReturnType<typeof buildEvidence>;

  for (const field of ['commitSha', 'repositoryId', 'evidenceId', 'kind', 'source']) {
    it(`returns INVALID when the ${field} getter throws`, () => {
      const evidence = throwingGetter(field);

      expect(() => evaluateEvidenceFreshness(evidence, buildTarget())).not.toThrow();

      const result = evaluateEvidenceFreshness(evidence, buildTarget());
      expect(result.state).toBe('INVALID');
      expect(result.state).not.toBe('CURRENT');
      expect(result.invalidFields).toContain('evidence');
    });
  }

  it('returns INVALID when a Proxy get trap throws', () => {
    const hostile = new Proxy(buildEvidence() as unknown as Record<string, unknown>, {
      get(): never {
        throw new Error('trap');
      },
    }) as unknown as ReturnType<typeof buildEvidence>;

    expect(() => evaluateEvidenceFreshness(hostile, buildTarget())).not.toThrow();
    expect(evaluateEvidenceFreshness(hostile, buildTarget()).state).toBe('INVALID');
  });

  it('returns INVALID when a target getter throws', () => {
    const hostileTarget = new Proxy(buildTarget() as unknown as Record<string, unknown>, {
      get(): never {
        throw new Error('hostile target');
      },
    }) as unknown as ReturnType<typeof buildTarget>;

    expect(() => evaluateEvidenceFreshness(buildEvidence(), hostileTarget)).not.toThrow();

    const result = evaluateEvidenceFreshness(buildEvidence(), hostileTarget);
    expect(result.state).toBe('INVALID');
    expect(result.reason).toBe(FRESHNESS_REASON.EVALUATION_TARGET_INVALID);
    expect(result.targetHeadSha).toBeNull();
  });

  it('does not let a hostile target abort a whole set', () => {
    const hostileTarget = new Proxy(buildTarget() as unknown as Record<string, unknown>, {
      get(): never {
        throw new Error('hostile target');
      },
    }) as unknown as ReturnType<typeof buildTarget>;

    expect(() =>
      evaluateEvidenceSet([buildEvidence(), buildEvidence()], hostileTarget),
    ).not.toThrow();

    const evaluation = evaluateEvidenceSet([buildEvidence(), buildEvidence()], hostileTarget);
    expect(evaluation.results.length).toBe(2);
    expect(evaluation.current).toEqual([]);
  });

  it('does not let a hostile record abort a set containing valid records', () => {
    const records = [
      throwingGetter('commitSha'),
      buildEvidence({ evidenceId: 'ev-ok', commitSha: HEAD_A }),
      new Proxy(buildEvidence() as unknown as Record<string, unknown>, {
        get(): never {
          throw new Error('trap');
        },
      }) as unknown as ReturnType<typeof buildEvidence>,
      buildEvidence({ evidenceId: 'ev-stale', commitSha: HEAD_B }),
    ];

    expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();

    const evaluation = evaluateEvidenceSet(records, buildTarget());
    expect(evaluation.results.length).toBe(4);
    expect(evaluation.current.map((r) => r.evidenceId)).toEqual(['ev-ok']);
    expect(evaluation.stale.map((r) => r.evidenceId)).toEqual(['ev-stale']);
    expect(evaluation.invalid.length).toBe(2);
  });
});

/** Regression cover for invoking an untrusted collection's own `map`. */
describe('set iteration does not use the collection’s own map', () => {
  it('evaluates an array carrying an own non-function map', () => {
    const records = [buildEvidence({ commitSha: HEAD_A })];
    (records as unknown as Record<string, unknown>)['map'] = 'not a function';

    expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();
    expect(evaluateEvidenceSet(records, buildTarget()).current.length).toBe(1);
  });

  it('evaluates an array whose map getter throws', () => {
    const records = [buildEvidence({ commitSha: HEAD_A })];
    Object.defineProperty(records, 'map', {
      get(): never {
        throw new Error('poisoned map getter');
      },
      configurable: true,
    });

    expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();
    expect(evaluateEvidenceSet(records, buildTarget()).current.length).toBe(1);
  });

  it('evaluates when Array.prototype.map is poisoned', () => {
    const original = Array.prototype.map;
    Object.defineProperty(Array.prototype, 'map', {
      value: function poisoned(): never {
        throw new Error('poisoned prototype');
      },
      configurable: true,
      writable: true,
    });

    try {
      const evaluation = evaluateEvidenceSet(
        [buildEvidence({ commitSha: HEAD_A }), buildEvidence({ commitSha: HEAD_B })],
        buildTarget(),
      );

      expect(evaluation.results.length).toBe(2);
      expect(evaluation.current.length).toBe(1);
      expect(evaluation.stale.length).toBe(1);
    } finally {
      Object.defineProperty(Array.prototype, 'map', {
        value: original,
        configurable: true,
        writable: true,
      });
    }
  });

  it('preserves input order and survives a throwing index getter', () => {
    const records = [
      buildEvidence({ evidenceId: 'ev-0', commitSha: HEAD_A }),
      buildEvidence({ evidenceId: 'ev-2', commitSha: HEAD_B }),
    ];
    Object.defineProperty(records, 1, {
      get(): never {
        throw new Error('hostile index');
      },
      configurable: true,
      enumerable: true,
    });

    expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();

    const evaluation = evaluateEvidenceSet(records, buildTarget());
    expect(evaluation.results.length).toBe(2);
    expect(evaluation.results[0]?.evidenceId).toBe('ev-0');
    expect(evaluation.results[1]?.state).toBe('INVALID');
  });
});

/**
 * Regression cover for the shared root cause behind the intrinsic findings:
 * untrusted evidence is read through getters and Proxy traps that run *during*
 * evaluation, so they can repoint any built-in the evaluator relies on
 * afterwards.
 *
 * Every poisoned global is restored in a `finally` so one test cannot
 * contaminate another, and assertions run only after restoration.
 */
describe('poisoned intrinsics cannot alter evaluation', () => {
  /** Run `body` while `owner[key]` is replaced, restoring it unconditionally. */
  function withPoisoned<T>(
    owner: object,
    key: PropertyKey,
    replacement: unknown,
    body: () => T,
  ): T {
    const original = Object.getOwnPropertyDescriptor(owner, key);
    Object.defineProperty(owner, key, {
      value: replacement,
      configurable: true,
      writable: true,
    });
    try {
      return body();
    } finally {
      if (original === undefined) {
        Reflect.deleteProperty(owner, key);
      } else {
        Object.defineProperty(owner, key, original);
      }
    }
  }

  /** A record whose first-read property poisons an intrinsic mid-evaluation. */
  function poisoningRecord(
    poison: () => void,
    rest: Record<string, unknown>,
  ): ReturnType<typeof buildEvidence> {
    return {
      get evidenceId(): string {
        poison();
        return 'ev-attack';
      },
      repositoryId: REPO_A,
      commitSha: HEAD_A,
      kind: 'ci-result',
      source: 'github',
      reference: 'ref',
      observedAt: 'ts',
      ...rest,
    } as unknown as ReturnType<typeof buildEvidence>;
  }

  it('rejects a bogus kind and source when Set.prototype.has is poisoned', () => {
    const result = withPoisoned(Set.prototype, 'has', () => true, () =>
      evaluateEvidenceFreshness(
        poisoningRecord(
          () => {
            Object.defineProperty(Set.prototype, 'has', {
              value: () => true,
              configurable: true,
              writable: true,
            });
          },
          { kind: 'TOTALLY-BOGUS', source: 'evil' },
        ),
        buildTarget(),
      ),
    );

    expect(result.state).not.toBe('CURRENT');
    expect(result.state).toBe('INVALID');
    expect(result.kind).toBeNull();
    expect(result.source).toBeNull();
  });

  it('rejects blank identifiers when String.prototype.trim is poisoned', () => {
    const result = withPoisoned(String.prototype, 'trim', () => 'x', () =>
      evaluateEvidenceFreshness(
        poisoningRecord(
          () => {
            Object.defineProperty(String.prototype, 'trim', {
              value: () => 'x',
              configurable: true,
              writable: true,
            });
          },
          { reference: '   ', observedAt: '   ' },
        ),
        buildTarget(),
      ),
    );

    expect(result.state).not.toBe('CURRENT');
    expect(result.state).toBe('INVALID');
    expect([...result.invalidFields].sort()).toEqual(['observedAt', 'reference'].sort());
  });

  it('still freezes results when Object.freeze is poisoned', () => {
    const result = withPoisoned(Object, 'freeze', (value: unknown) => value, () =>
      evaluateEvidenceFreshness(
        buildEvidence({ commitSha: HEAD_A }),
        buildTarget({ currentHeadSha: HEAD_B }),
      ),
    );

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.invalidFields)).toBe(true);

    const mutable = result as { state: FreshnessState };
    expect(() => {
      mutable.state = 'CURRENT';
    }).toThrow(TypeError);
    expect(result.state).toBe('STALE');
  });

  it('builds invalidFields when Array.prototype[Symbol.iterator] is poisoned', () => {
    const result = withPoisoned(
      Array.prototype,
      Symbol.iterator,
      function poisoned(): never {
        throw new Error('poisoned iterator');
      },
      () => evaluateEvidenceFreshness(buildEvidence({ commitSha: '' }), buildTarget()),
    );

    expect(result.state).toBe('INVALID');
    expect(result.invalidFields.length).toBe(1);
    expect(result.invalidFields[0]).toBe('commitSha');
  });

  it('partitions a set when Array.prototype.filter is poisoned', () => {
    const evaluation = withPoisoned(
      Array.prototype,
      'filter',
      function poisoned(): never {
        throw new Error('poisoned filter');
      },
      () =>
        evaluateEvidenceSet(
          [
            buildEvidence({ evidenceId: 'ev-current', commitSha: HEAD_A }),
            buildEvidence({ evidenceId: 'ev-stale', commitSha: HEAD_B }),
          ],
          buildTarget(),
        ),
    );

    expect(evaluation.results.length).toBe(2);
    expect(evaluation.current.length).toBe(1);
    expect(evaluation.current[0]?.evidenceId).toBe('ev-current');
    expect(evaluation.stale[0]?.evidenceId).toBe('ev-stale');
  });

  it('collects results when Array.prototype.push is poisoned', () => {
    const evaluation = withPoisoned(
      Array.prototype,
      'push',
      function poisoned(): never {
        throw new Error('poisoned push');
      },
      () =>
        evaluateEvidenceSet(
          [
            buildEvidence({ evidenceId: 'ev-a', commitSha: HEAD_A }),
            buildEvidence({ evidenceId: 'ev-b', commitSha: HEAD_B }),
            buildEvidence({ evidenceId: 'ev-c', commitSha: HEAD_A }),
          ],
          buildTarget(),
        ),
    );

    expect(evaluation.results.length).toBe(3);
    expect(evaluation.current.length).toBe(2);
    expect(evaluation.stale.length).toBe(1);
  });

  it('keeps a stale record stale when every array intrinsic is poisoned at once', () => {
    const evaluation = withPoisoned(Array.prototype, 'push', null, () =>
      withPoisoned(Array.prototype, 'filter', null, () =>
        withPoisoned(Array.prototype, 'map', null, () =>
          evaluateEvidenceSet(
            [
              buildEvidence({ evidenceId: 'ev-stale', commitSha: HEAD_A }),
              buildEvidence({ evidenceId: 'ev-current', commitSha: HEAD_B }),
            ],
            buildTarget({ currentHeadSha: HEAD_B }),
          ),
        ),
      ),
    );

    expect(evaluation.results.length).toBe(2);
    expect(evaluation.current[0]?.evidenceId).toBe('ev-current');
    expect(evaluation.stale[0]?.evidenceId).toBe('ev-stale');
  });

  it('does not let a poisoned intrinsic promote cross-repository evidence', () => {
    const result = withPoisoned(Set.prototype, 'has', () => true, () =>
      withPoisoned(String.prototype, 'trim', () => 'x', () =>
        evaluateEvidenceFreshness(
          buildEvidence({ repositoryId: REPO_B, commitSha: HEAD_A }),
          buildTarget({ repositoryId: REPO_A, currentHeadSha: HEAD_A }),
        ),
      ),
    );

    expect(result.state).not.toBe('CURRENT');
    expect(result.state).toBe('INVALID');
  });
});

/** Regression cover for revoked Proxy inputs. */
describe('revoked proxies fail closed', () => {
  it('treats a revoked proxy collection as empty without throwing', () => {
    const revocable = Proxy.revocable([buildEvidence()], {});
    revocable.revoke();
    const collection = revocable.proxy as unknown as ReturnType<typeof buildEvidence>[];

    expect(() => evaluateEvidenceSet(collection, buildTarget())).not.toThrow();

    const evaluation = evaluateEvidenceSet(collection, buildTarget());
    expect(evaluation.results).toEqual([]);
    expect(evaluation.current).toEqual([]);
  });

  it('treats a revoked proxy record as INVALID without throwing', () => {
    const revocable = Proxy.revocable(buildEvidence(), {});
    revocable.revoke();
    const record = revocable.proxy;

    expect(() => evaluateEvidenceFreshness(record, buildTarget())).not.toThrow();
    expect(evaluateEvidenceFreshness(record, buildTarget()).state).toBe('INVALID');
  });

  it('treats a revoked proxy target as INVALID without throwing', () => {
    const revocable = Proxy.revocable(buildTarget(), {});
    revocable.revoke();
    const target = revocable.proxy;

    expect(() => evaluateEvidenceFreshness(buildEvidence(), target)).not.toThrow();
    expect(evaluateEvidenceFreshness(buildEvidence(), target).state).toBe('INVALID');
  });

  it('keeps evaluating a set that contains a revoked proxy element', () => {
    const revocable = Proxy.revocable(buildEvidence(), {});
    revocable.revoke();
    const records = [
      buildEvidence({ evidenceId: 'ev-ok', commitSha: HEAD_A }),
      revocable.proxy,
      buildEvidence({ evidenceId: 'ev-stale', commitSha: HEAD_B }),
    ];

    expect(() => evaluateEvidenceSet(records, buildTarget())).not.toThrow();

    const evaluation = evaluateEvidenceSet(records, buildTarget());
    expect(evaluation.results.length).toBe(3);
    expect(evaluation.current[0]?.evidenceId).toBe('ev-ok');
    expect(evaluation.invalid.length).toBe(1);
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
