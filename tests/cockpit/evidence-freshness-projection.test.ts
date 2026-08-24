import { describe, expect, it } from 'vitest';

import {
  projectCockpitEvidenceFreshness,
  readCockpitSnapshot,
  type CockpitEvidenceFreshnessProjection,
  type CockpitEvidenceReadModel,
  type CockpitSnapshot,
} from '../../src/cockpit/index.js';
import type { EvidenceRecord } from '../../src/domain/evidence.js';
import {
  evaluateEvidenceSet,
  FRESHNESS,
  FRESHNESS_REASON,
} from '../../src/domain/evidence-freshness.js';
import {
  buildEvidence,
  buildFinding,
  buildRepository,
  buildSnapshot,
  HEAD_A,
  HEAD_B,
  REPO_A,
} from './read-model-fixtures.js';

/* -------------------------------------------------------------------------
 * Fixtures: every input below is a snapshot that D1 has actually accepted
 * (Option A trust boundary). No malformed snapshot is ever handed to D2.
 * ------------------------------------------------------------------------- */

/** Pass a fixture through D1's read boundary and assert it was accepted. */
function validSnapshot(overrides: Partial<CockpitSnapshot> = {}): CockpitSnapshot {
  const result = readCockpitSnapshot(buildSnapshot(overrides));
  expect(result.invalidFields).toEqual([]);
  expect(result.snapshot).not.toBeNull();
  return result.snapshot as CockpitSnapshot;
}

const CURRENT_EVIDENCE = buildEvidence({ evidenceId: 'ev-current', commitSha: HEAD_A });
const STALE_EVIDENCE = buildEvidence({
  evidenceId: 'ev-stale',
  kind: 'code-review',
  source: 'agent',
  commitSha: HEAD_B,
  reference: 'review-77',
});

/** Recursively assert every object/array node is frozen. */
function expectDeepFrozen(value: unknown, path = 'projection'): void {
  if (typeof value !== 'object' || value === null) {
    return;
  }
  expect(Object.isFrozen(value), `${path} must be frozen`).toBe(true);
  for (const key of Object.keys(value)) {
    expectDeepFrozen((value as Record<string, unknown>)[key], `${path}.${key}`);
  }
}

/* -------------------------------------------------------------------------
 * Core freshness projection
 * ------------------------------------------------------------------------- */

describe('projectCockpitEvidenceFreshness — core projection', () => {
  it('1. projects one CURRENT evidence item as CURRENT / BOUND_TO_CURRENT_HEAD', () => {
    const projection = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE] }),
    );

    expect(projection.results).toHaveLength(1);
    expect(projection.results[0]).toEqual({
      evidenceId: 'ev-current',
      kind: 'ci-result',
      source: 'github',
      commitSha: HEAD_A,
      state: FRESHNESS.CURRENT,
      reason: FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD,
      invalidFields: [],
    });
    expect(projection.counts).toEqual({ current: 1, stale: 0, invalid: 0, total: 1 });
  });

  it('2. projects one STALE evidence item as STALE / COMMIT_SHA_MISMATCH', () => {
    const projection = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [STALE_EVIDENCE] }),
    );

    expect(projection.results).toHaveLength(1);
    expect(projection.results[0]).toEqual({
      evidenceId: 'ev-stale',
      kind: 'code-review',
      source: 'agent',
      commitSha: HEAD_B,
      state: FRESHNESS.STALE,
      reason: FRESHNESS_REASON.COMMIT_SHA_MISMATCH,
      invalidFields: [],
    });
    expect(projection.counts).toEqual({ current: 0, stale: 1, invalid: 0, total: 1 });
  });

  it('3. projects a mixed CURRENT + STALE snapshot with exact ordered results and counts', () => {
    const projection = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [STALE_EVIDENCE, CURRENT_EVIDENCE, STALE_EVIDENCE] }),
    );

    expect(projection.results.map((item) => [item.evidenceId, item.state])).toEqual([
      ['ev-stale', FRESHNESS.STALE],
      ['ev-current', FRESHNESS.CURRENT],
      ['ev-stale', FRESHNESS.STALE],
    ]);
    expect(projection.counts).toEqual({ current: 1, stale: 2, invalid: 0, total: 3 });
    expect(projection.counts.current + projection.counts.stale + projection.counts.invalid).toBe(
      projection.counts.total,
    );
    expect(projection.counts.total).toBe(projection.results.length);
  });

  it('4. state/reason/invalidFields equal a direct evaluateEvidenceSet() over the same snapshot', () => {
    const snapshot = validSnapshot({
      evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE, buildEvidence({ evidenceId: 'ev-3' })],
    });
    const projection = projectCockpitEvidenceFreshness(snapshot);

    const records: EvidenceRecord[] = snapshot.evidence.map((item) => ({
      evidenceId: item.evidenceId,
      repositoryId: snapshot.repository.repositoryId,
      commitSha: item.commitSha,
      kind: item.kind,
      source: item.source,
      reference: item.reference,
      observedAt: item.observedAt,
    }));
    const direct = evaluateEvidenceSet(records, {
      repositoryId: snapshot.repository.repositoryId,
      currentHeadSha: snapshot.repository.observedHeadSha,
    });

    expect(projection.results).toHaveLength(direct.results.length);
    for (let index = 0; index < direct.results.length; index += 1) {
      const projected = projection.results[index];
      const kernel = direct.results[index];
      expect(projected?.state).toBe(kernel?.state);
      expect(projected?.reason).toBe(kernel?.reason);
      expect(projected?.invalidFields).toEqual(kernel?.invalidFields);
      expect(projected?.evidenceId).toBe(kernel?.evidenceId);
      expect(projected?.commitSha).toBe(kernel?.commitSha);
      expect(projected?.kind).toBe(kernel?.kind);
      expect(projected?.source).toBe(kernel?.source);
    }
    expect(projection.counts).toEqual({
      current: direct.current.length,
      stale: direct.stale.length,
      invalid: direct.invalid.length,
      total: direct.results.length,
    });
  });
});

/* -------------------------------------------------------------------------
 * Target identity comes only from the enclosing snapshot
 * ------------------------------------------------------------------------- */

describe('projectCockpitEvidenceFreshness — target identity', () => {
  it('5. injects repositoryId from snapshot.repository.repositoryId', () => {
    const OTHER_REPO = 'github.com/LogicDuke/other';
    const snapshot = validSnapshot({
      repository: buildRepository({ repositoryId: OTHER_REPO }),
      evidence: [CURRENT_EVIDENCE],
    });
    const projection = projectCockpitEvidenceFreshness(snapshot);

    expect(projection.repositoryId).toBe(OTHER_REPO);
    // The injected identity is what the kernel compares against, so the record
    // is about this repository and evaluates CURRENT — never REPOSITORY_MISMATCH.
    expect(projection.results[0]?.state).toBe(FRESHNESS.CURRENT);
    expect(projection.results[0]?.reason).toBe(FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD);
  });

  it('6. uses snapshot.repository.observedHeadSha as EvidenceTarget.currentHeadSha', () => {
    const snapshot = validSnapshot({
      repository: buildRepository({ observedHeadSha: HEAD_B }),
      evidence: [STALE_EVIDENCE],
    });
    const projection = projectCockpitEvidenceFreshness(snapshot);

    expect(projection.observedHeadSha).toBe(HEAD_B);
    // STALE_EVIDENCE is bound to HEAD_B, so against an observed HEAD_B it is CURRENT.
    expect(projection.results[0]?.state).toBe(FRESHNESS.CURRENT);
  });

  it('7. changing observedHeadSha flips freshness exactly as the domain kernel dictates', () => {
    const atA = projectCockpitEvidenceFreshness(
      validSnapshot({
        repository: buildRepository({ observedHeadSha: HEAD_A }),
        evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE],
      }),
    );
    const atB = projectCockpitEvidenceFreshness(
      validSnapshot({
        repository: buildRepository({ observedHeadSha: HEAD_B }),
        evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE],
      }),
    );

    expect(atA.results.map((item) => item.state)).toEqual([FRESHNESS.CURRENT, FRESHNESS.STALE]);
    expect(atB.results.map((item) => item.state)).toEqual([FRESHNESS.STALE, FRESHNESS.CURRENT]);
    expect(atA.counts).toEqual({ current: 1, stale: 1, invalid: 0, total: 2 });
    expect(atB.counts).toEqual({ current: 1, stale: 1, invalid: 0, total: 2 });
  });

  it('8. an evidence commitSha can never become HEAD authority', () => {
    // Every record agrees on HEAD_B; the snapshot observed HEAD_A. Agreement
    // among records is not a HEAD, so all of them are STALE.
    const snapshot = validSnapshot({
      repository: buildRepository({ observedHeadSha: HEAD_A }),
      evidence: [
        buildEvidence({ evidenceId: 'e1', commitSha: HEAD_B }),
        buildEvidence({ evidenceId: 'e2', commitSha: HEAD_B, kind: 'repository-state' }),
        buildEvidence({ evidenceId: 'e3', commitSha: HEAD_B, kind: 'human-decision' }),
      ],
    });
    const projection = projectCockpitEvidenceFreshness(snapshot);

    expect(projection.observedHeadSha).toBe(HEAD_A);
    expect(projection.results.every((item) => item.state === FRESHNESS.STALE)).toBe(true);
    expect(projection.counts).toEqual({ current: 0, stale: 3, invalid: 0, total: 3 });
  });

  it('9. findings and advisoryFreshness have no effect on the projection', () => {
    const withoutFindings = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE], findings: [] }),
    );
    const withContradictingFindings = projectCockpitEvidenceFreshness(
      validSnapshot({
        evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE],
        findings: [
          buildFinding({ findingId: 'f1', reviewedCommitSha: HEAD_B, advisoryFreshness: 'CURRENT' }),
          buildFinding({ findingId: 'f2', reviewedCommitSha: HEAD_A, advisoryFreshness: 'STALE' }),
          buildFinding({ findingId: 'f3', reviewedCommitSha: HEAD_B, advisoryFreshness: 'INVALID' }),
        ],
      }),
    );

    expect(withContradictingFindings).toEqual(withoutFindings);
    expect(Object.keys(withContradictingFindings)).toEqual([
      'repositoryId',
      'observedHeadSha',
      'results',
      'counts',
    ]);
  });
});

/* -------------------------------------------------------------------------
 * Ordering, emptiness, and bounds
 * ------------------------------------------------------------------------- */

describe('projectCockpitEvidenceFreshness — order and bounds', () => {
  it('10. preserves snapshot.evidence input order, without sorting or deduplication', () => {
    const evidence: CockpitEvidenceReadModel[] = [
      buildEvidence({ evidenceId: 'z', commitSha: HEAD_B }),
      buildEvidence({ evidenceId: 'a', commitSha: HEAD_A }),
      buildEvidence({ evidenceId: 'z', commitSha: HEAD_B }),
      buildEvidence({ evidenceId: 'm', commitSha: HEAD_A }),
    ];
    const snapshot = validSnapshot({ evidence });
    const projection = projectCockpitEvidenceFreshness(snapshot);

    expect(projection.results.map((item) => item.evidenceId)).toEqual(['z', 'a', 'z', 'm']);
    for (let index = 0; index < snapshot.evidence.length; index += 1) {
      expect(projection.results[index]?.evidenceId).toBe(snapshot.evidence[index]?.evidenceId);
      expect(projection.results[index]?.commitSha).toBe(snapshot.evidence[index]?.commitSha);
    }
  });

  it('11. an empty VALID evidence list projects to [] with all counts 0', () => {
    const projection = projectCockpitEvidenceFreshness(validSnapshot({ evidence: [] }));

    expect(projection.results).toEqual([]);
    expect(projection.counts).toEqual({ current: 0, stale: 0, invalid: 0, total: 0 });
    expect(projection.repositoryId).toBe(REPO_A);
    expect(projection.observedHeadSha).toBe(HEAD_A);
  });

  it('12. projects all 1,000 records of a D1-maximum snapshot in order, with no new D2 bound', () => {
    const evidence: CockpitEvidenceReadModel[] = [];
    for (let index = 0; index < 1_000; index += 1) {
      evidence.push(
        buildEvidence({
          evidenceId: `ev-${String(index)}`,
          commitSha: index % 2 === 0 ? HEAD_A : HEAD_B,
        }),
      );
    }
    const snapshot = validSnapshot({ evidence });
    expect(snapshot.evidence).toHaveLength(1_000);

    const projection = projectCockpitEvidenceFreshness(snapshot);

    expect(projection.results).toHaveLength(1_000);
    expect(projection.counts).toEqual({ current: 500, stale: 500, invalid: 0, total: 1_000 });
    for (let index = 0; index < 1_000; index += 1) {
      expect(projection.results[index]?.evidenceId).toBe(`ev-${String(index)}`);
      expect(projection.results[index]?.state).toBe(
        index % 2 === 0 ? FRESHNESS.CURRENT : FRESHNESS.STALE,
      );
    }
  });

  it('13. a contract-valid D1 snapshot never becomes INVALID through D2 reconstruction', () => {
    const kinds = [
      'ci-result',
      'code-review',
      'security-review',
      'test-result',
      'repository-state',
      'human-decision',
    ] as const;
    const sources = ['github', 'local-verification', 'agent', 'human'] as const;
    const evidence: CockpitEvidenceReadModel[] = [];
    for (const kind of kinds) {
      for (const source of sources) {
        evidence.push(
          buildEvidence({ evidenceId: `${kind}/${source}/A`, kind, source, commitSha: HEAD_A }),
        );
        evidence.push(
          buildEvidence({ evidenceId: `${kind}/${source}/B`, kind, source, commitSha: HEAD_B }),
        );
      }
    }
    const projection = projectCockpitEvidenceFreshness(validSnapshot({ evidence }));

    expect(projection.results).toHaveLength(evidence.length);
    expect(projection.counts.invalid).toBe(0);
    for (const item of projection.results) {
      expect(item.state).not.toBe(FRESHNESS.INVALID);
      expect(item.invalidFields).toEqual([]);
      expect([FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD, FRESHNESS_REASON.COMMIT_SHA_MISMATCH]).toContain(
        item.reason,
      );
    }
  });
});

/* -------------------------------------------------------------------------
 * Immutability, purity, determinism, JSON
 * ------------------------------------------------------------------------- */

describe('projectCockpitEvidenceFreshness — immutability and purity', () => {
  it('14. returns a deeply immutable projection', () => {
    const projection = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] }),
    );

    expectDeepFrozen(projection);
    expect(Object.isFrozen(projection.results)).toBe(true);
    expect(Object.isFrozen(projection.counts)).toBe(true);
    for (const item of projection.results) {
      expect(Object.isFrozen(item)).toBe(true);
      expect(Object.isFrozen(item.invalidFields)).toBe(true);
      for (const value of Object.values(item)) {
        expect(typeof value).not.toBe('function');
      }
    }
    expect(() => {
      (projection as { results: unknown }).results = [];
    }).toThrow(TypeError);
    expect(() => {
      (projection.results as unknown[]).push(null);
    }).toThrow(TypeError);
    expect(() => {
      (projection.results[0] as { state: string }).state = 'CURRENT';
    }).toThrow(TypeError);
    expect(() => {
      (projection.counts as { current: number }).current = 99;
    }).toThrow(TypeError);
  });

  it('14b. is detached from the caller snapshot — shares no object reference', () => {
    const snapshot = validSnapshot({ evidence: [CURRENT_EVIDENCE] });
    const projection = projectCockpitEvidenceFreshness(snapshot);

    expect(projection.results).not.toBe(snapshot.evidence);
    expect(projection.results[0]).not.toBe(snapshot.evidence[0]);
    expect(projection.counts).not.toBe(snapshot.repository);
  });

  it('15. does not mutate the input snapshot', () => {
    const raw = buildSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] });
    const before = JSON.stringify(raw);
    const snapshot = validSnapshot(raw);
    const snapshotBefore = JSON.stringify(snapshot);

    projectCockpitEvidenceFreshness(snapshot);

    expect(JSON.stringify(raw)).toBe(before);
    expect(JSON.stringify(snapshot)).toBe(snapshotBefore);
    expect(Object.keys(snapshot.evidence[0] ?? {})).not.toContain('repositoryId');
    expect(Object.keys(snapshot.evidence[0] ?? {})).not.toContain('state');
  });

  it('16. two equal valid inputs yield structurally equal projections', () => {
    const first = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] }),
    );
    const second = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] }),
    );

    expect(first).toEqual(second);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first).not.toBe(second);
  });

  it('17. survives a JSON round trip with its enumerable data unchanged', () => {
    const projection = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] }),
    );
    const roundTripped = JSON.parse(JSON.stringify(projection)) as CockpitEvidenceFreshnessProjection;

    expect(roundTripped).toEqual(projection);
    expect(Object.keys(roundTripped)).toEqual(Object.keys(projection));
    expect(roundTripped.results.map((item) => Object.keys(item))).toEqual(
      projection.results.map((item) => Object.keys(item)),
    );
  });
});

/* -------------------------------------------------------------------------
 * Ambient-realm mutation after D1 validation
 * ------------------------------------------------------------------------- */

// Test-side intrinsics captured before any test swaps them, so install and
// restore keep working while `Object.defineProperty` itself is replaced.
const realDefineProperty = Object.defineProperty;
const realGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const realDeleteProperty = Reflect.deleteProperty;

function withPrototypeProperty<T>(
  target: object,
  key: PropertyKey,
  descriptor: PropertyDescriptor,
  body: () => T,
): T {
  const original = realGetOwnPropertyDescriptor(target, key);
  // The helper's own descriptor must not inherit a `get`/`set` that a nested
  // call has already installed on `Object.prototype`, so it is built with a
  // `null` prototype — the same insulation D2 gives its descriptors.
  const install: PropertyDescriptor = Object.assign(Object.create(null) as PropertyDescriptor, descriptor, {
    configurable: true,
  });
  realDefineProperty(target, key, install);
  try {
    return body();
  } finally {
    if (original === undefined) {
      realDeleteProperty(target, key);
    } else {
      realDefineProperty(target, key, original);
    }
  }
}

function withReplacedIntrinsic<T>(
  holder: object,
  key: PropertyKey,
  replacement: unknown,
  body: () => T,
): T {
  return withPrototypeProperty(
    holder,
    key,
    { value: replacement, writable: true, enumerable: false },
    body,
  );
}

describe('projectCockpitEvidenceFreshness — ambient prototype mutation', () => {
  const expected = projectCockpitEvidenceFreshness(
    validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] }),
  );
  const expectedJson = JSON.stringify(expected);

  it('18. a hostile Object.prototype.toJSON cannot alter the projection or its JSON form', () => {
    const snapshot = validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] });
    const POISON = '__poisoned__';
    const { projection, json } = withPrototypeProperty(
      Object.prototype,
      'toJSON',
      { value: () => POISON, writable: true, enumerable: false },
      () => {
        const projection = projectCockpitEvidenceFreshness(snapshot);
        return { projection, json: JSON.stringify(projection) };
      },
    );

    expect(json).toBe(expectedJson);
    expect(json).not.toContain(POISON);
    expect(projection).toEqual(expected);
    expect(Object.getPrototypeOf(projection)).toBeNull();
    expect(Object.getPrototypeOf(projection.results[0])).toBeNull();
    expect(Object.getPrototypeOf(projection.counts)).toBeNull();
    expect(Object.getOwnPropertyDescriptor(projection.results, 'toJSON')).toEqual({
      value: undefined,
      writable: false,
      enumerable: false,
      configurable: false,
    });
    // Realm restored.
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON')).toBeUndefined();
  });

  it('19. hostile Object.prototype.get / set cannot break D2-owned descriptors', () => {
    const snapshot = validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] });
    const accessor = { value: () => undefined, writable: true, enumerable: false };
    const projection = withPrototypeProperty(Object.prototype, 'get', accessor, () =>
      withPrototypeProperty(Object.prototype, 'set', accessor, () =>
        projectCockpitEvidenceFreshness(snapshot),
      ),
    );

    expect(projection).toEqual(expected);
    expect(JSON.stringify(projection)).toBe(expectedJson);
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'get')).toBeUndefined();
    expect(Object.getOwnPropertyDescriptor(Object.prototype, 'set')).toBeUndefined();
  });

  it('19b. inherited numeric setters and poisoned Array.prototype methods cannot affect results', () => {
    const snapshot = validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] });
    const throwing = () => {
      throw new Error('poisoned prototype method');
    };
    const projection = withPrototypeProperty(
      Object.prototype,
      '0',
      { set: throwing, get: () => 'inherited', enumerable: false },
      () =>
        withPrototypeProperty(
          Array.prototype,
          '1',
          { set: throwing, get: () => 'inherited', enumerable: false },
          () =>
            withReplacedIntrinsic(Array.prototype, 'push', throwing, () =>
              withReplacedIntrinsic(Array.prototype, 'map', throwing, () =>
                withReplacedIntrinsic(Array.prototype, 'filter', throwing, () =>
                  withReplacedIntrinsic(Array.prototype, Symbol.iterator, throwing, () =>
                    projectCockpitEvidenceFreshness(snapshot),
                  ),
                ),
              ),
            ),
        ),
    );

    expect(Object.hasOwn(projection.results, '0')).toBe(true);
    expect(Object.hasOwn(projection.results, '1')).toBe(true);
    expect(projection).toEqual(expected);
    expect(JSON.stringify(projection)).toBe(expectedJson);
  });

  it('20. post-module-load replacement of Object intrinsics does not change D2 behaviour', () => {
    const snapshot = validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] });
    const noFreeze = <T>(value: T): T => value;
    const throwing = () => {
      throw new Error('replaced intrinsic');
    };
    const projection = withReplacedIntrinsic(Object, 'freeze', noFreeze, () =>
      withReplacedIntrinsic(Object, 'defineProperty', throwing, () =>
        withReplacedIntrinsic(Object, 'setPrototypeOf', throwing, () =>
          projectCockpitEvidenceFreshness(snapshot),
        ),
      ),
    );

    // Captured references were used: the output is still frozen, detached from
    // Object.prototype, and equal to the unpoisoned projection.
    expectDeepFrozen(projection);
    expect(Object.getPrototypeOf(projection)).toBeNull();
    expect(projection).toEqual(expected);
    expect(JSON.stringify(projection)).toBe(expectedJson);
    expect(Object.freeze).not.toBe(noFreeze);
  });
});

/* -------------------------------------------------------------------------
 * Authority leakage
 * ------------------------------------------------------------------------- */

describe('projectCockpitEvidenceFreshness — no authority', () => {
  it('21. carries no authority-shaped key anywhere in the projection', () => {
    const forbidden = [
      'decision',
      'permit',
      'approval',
      'approved',
      'mayExecuteOnce',
      'authority',
      'mergeReady',
      'mayMerge',
    ];
    const projection = projectCockpitEvidenceFreshness(
      validSnapshot({ evidence: [CURRENT_EVIDENCE, STALE_EVIDENCE] }),
    );
    const nodes: object[] = [projection, projection.counts, projection.results, ...projection.results];
    for (const node of nodes) {
      for (const key of forbidden) {
        expect(Object.hasOwn(node, key), `forbidden key ${key}`).toBe(false);
      }
    }
    expect(Object.keys(projection)).toEqual(['repositoryId', 'observedHeadSha', 'results', 'counts']);
    expect(Object.keys(projection.counts)).toEqual(['current', 'stale', 'invalid', 'total']);
    expect(Object.keys(projection.results[0] ?? {})).toEqual([
      'evidenceId',
      'kind',
      'source',
      'commitSha',
      'state',
      'reason',
      'invalidFields',
    ]);
  });

  it('exposes no current/stale/invalid buckets', () => {
    const projection = projectCockpitEvidenceFreshness(validSnapshot());
    expect(Object.hasOwn(projection, 'current')).toBe(false);
    expect(Object.hasOwn(projection, 'stale')).toBe(false);
    expect(Object.hasOwn(projection, 'invalid')).toBe(false);
  });
});
