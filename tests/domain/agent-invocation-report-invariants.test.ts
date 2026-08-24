import { describe, expect, it } from 'vitest';

import {
  ingestInvocationReport,
  type ClaimedArtifactInput,
} from '../../src/domain/index.js';
import { buildClaim, buildInvocation, buildReport, SHA_B } from './invocation-fixtures.js';

/**
 * C1-AIR-F1 — report ingestion stays total under a hostile `Object.prototype`.
 *
 * `ingestInvocationReport` accumulates normalized claims and rejected claims
 * with `append`, which defines an own index via `Object.defineProperty`. Because
 * a descriptor object literal inherits from `Object.prototype`, an inherited
 * `get`/`set` accessor was consulted by ToPropertyDescriptor and made the call
 * throw a `TypeError` — an otherwise-valid report carrying >= 1 artifact claim
 * turned into a crash, losing the evidence the report was meant to construct.
 * The repair detaches the descriptor's prototype before the define, so only its
 * own data attributes are read.
 *
 * Poison installers use null-prototype descriptors so the harness never
 * reproduces the bug itself; product code runs under poison, the realm is
 * restored, and assertions run afterwards (Section 13 of the repair gate).
 */
describe('C1-AIR-F1 append survives hostile Object.prototype get/set', () => {
  const defineProp = Object.defineProperty;
  const getOwnDesc = Object.getOwnPropertyDescriptor;

  function nullProto<T extends object>(object: T): T {
    Object.setPrototypeOf(object, null);
    return object;
  }

  /** Plant inherited data-property poison; return a realm-restoring function. */
  function poisonPrototype(keys: readonly string[]): () => void {
    const saved: Record<string, PropertyDescriptor | undefined> = Object.create(
      null,
    ) as Record<string, PropertyDescriptor | undefined>;
    for (const key of keys) {
      saved[key] = getOwnDesc(Object.prototype, key);
    }
    for (const key of keys) {
      defineProp(
        Object.prototype,
        key,
        nullProto({ value: 'inherited-poison', configurable: true, writable: true }),
      );
    }
    return () => {
      for (const key of keys) {
        const descriptor = saved[key];
        if (descriptor === undefined) {
          Reflect.deleteProperty(Object.prototype, key);
        } else {
          defineProp(Object.prototype, key, nullProto({ ...descriptor }));
        }
      }
    };
  }

  function underPoison<T>(
    keys: readonly string[],
    run: () => T,
  ): { result: T | null; thrown: unknown } {
    const restore = poisonPrototype(keys);
    let result: T | null = null;
    let thrown: unknown = null;
    try {
      result = run();
    } catch (error: unknown) {
      thrown = error;
    } finally {
      restore();
    }
    return { result, thrown };
  }

  const POISON_SETS: readonly (readonly string[])[] = [['get'], ['set'], ['get', 'set']];

  for (const keys of POISON_SETS) {
    it(`ingests a report with one artifact claim under ${keys.join('+')} poison`, () => {
      const { result, thrown } = underPoison(keys, () =>
        ingestInvocationReport(buildInvocation(), buildReport([buildClaim()])),
      );

      expect(thrown).toBeNull();
      expect(result?.outcome).toBe('INGESTED');
      expect(result?.claims.length).toBe(1);
    });
  }

  it('preserves claim order under get+set poison', () => {
    const report = buildReport([
      buildClaim({ reference: 'ref-0' }),
      buildClaim({ reference: 'ref-1' }),
      buildClaim({ reference: 'ref-2' }),
    ]);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestInvocationReport(buildInvocation(), report),
    );

    expect(thrown).toBeNull();
    expect(result?.claims.map((claim) => claim.reference)).toEqual([
      'ref-0',
      'ref-1',
      'ref-2',
    ]);
    expect(result?.claims.map((claim) => claim.claimId)).toEqual(['c0', 'c1', 'c2']);
  });

  it('produces claim content identical to the clean control under get+set poison', () => {
    const report = buildReport([buildClaim({ commitSha: SHA_B })]);
    const clean = ingestInvocationReport(buildInvocation(), report);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestInvocationReport(buildInvocation(), report),
    );

    expect(thrown).toBeNull();
    expect(result).toEqual(clean);
  });

  it('appends a rejected claim under get+set poison', () => {
    const report = buildReport([
      buildClaim({ reference: 'kept' }),
      { reference: '' } as ClaimedArtifactInput,
    ]);
    const clean = ingestInvocationReport(buildInvocation(), report);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestInvocationReport(buildInvocation(), report),
    );

    expect(thrown).toBeNull();
    expect(result?.claims.length).toBe(1);
    expect(result?.claims[0]?.reference).toBe('kept');
    expect(result?.rejectedClaims.length).toBe(1);
    expect(result?.rejectedClaims[0]?.reason).toBe('REFERENCE_MISSING');
    expect(result).toEqual(clean);
  });

  it('survives a claim getter that installs get poison mid-evaluation', () => {
    const saved = getOwnDesc(Object.prototype, 'get');
    let result: ReturnType<typeof ingestInvocationReport> | null = null;
    let thrown: unknown = null;
    try {
      const hostile = defineProp({ ...buildClaim() }, 'reference', {
        get(): string {
          defineProp(
            Object.prototype,
            'get',
            nullProto({ value: 'planted', configurable: true, writable: true }),
          );
          return 'ref-mid'; // valid, so append(claims, claim) runs under the freshly installed poison
        },
        configurable: true,
        enumerable: true,
      }) as ClaimedArtifactInput;
      const report = buildReport([hostile, buildClaim({ reference: 'ref-after' })]);
      try {
        result = ingestInvocationReport(buildInvocation(), report);
      } catch (error: unknown) {
        thrown = error;
      }
    } finally {
      if (saved === undefined) {
        Reflect.deleteProperty(Object.prototype, 'get');
      } else {
        defineProp(Object.prototype, 'get', nullProto({ ...saved }));
      }
    }

    expect(thrown).toBeNull();
    expect(result?.outcome).toBe('INGESTED');
    expect(result?.claims.map((claim) => claim.reference)).toEqual(['ref-mid', 'ref-after']);
  });

  it('survives a claim getter that installs set poison mid-evaluation', () => {
    const saved = getOwnDesc(Object.prototype, 'set');
    let result: ReturnType<typeof ingestInvocationReport> | null = null;
    let thrown: unknown = null;
    try {
      const hostile = defineProp({ ...buildClaim() }, 'reference', {
        get(): string {
          defineProp(
            Object.prototype,
            'set',
            nullProto({ value: 'planted', configurable: true, writable: true }),
          );
          return 'ref-mid';
        },
        configurable: true,
        enumerable: true,
      }) as ClaimedArtifactInput;
      const report = buildReport([hostile, buildClaim({ reference: 'ref-after' })]);
      try {
        result = ingestInvocationReport(buildInvocation(), report);
      } catch (error: unknown) {
        thrown = error;
      }
    } finally {
      if (saved === undefined) {
        Reflect.deleteProperty(Object.prototype, 'set');
      } else {
        defineProp(Object.prototype, 'set', nullProto({ ...saved }));
      }
    }

    expect(thrown).toBeNull();
    expect(result?.outcome).toBe('INGESTED');
    expect(result?.claims.map((claim) => claim.reference)).toEqual(['ref-mid', 'ref-after']);
  });

  it('ingests a clean report identically with and without poison', () => {
    const report = buildReport([buildClaim()]);
    const clean = ingestInvocationReport(buildInvocation(), report);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestInvocationReport(buildInvocation(), report),
    );

    expect(thrown).toBeNull();
    expect(result).toEqual(clean);
  });

  it('restores Object.prototype after every poisoned run', () => {
    underPoison(['get', 'set'], () =>
      ingestInvocationReport(buildInvocation(), buildReport([buildClaim()])),
    );

    expect(getOwnDesc(Object.prototype, 'get')).toBeUndefined();
    expect(getOwnDesc(Object.prototype, 'set')).toBeUndefined();
  });
});
