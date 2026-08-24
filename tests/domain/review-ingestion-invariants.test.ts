import { describe, expect, it } from 'vitest';

import {
  INGESTION_OUTCOME,
  INGESTION_OUTCOMES,
  ingestReview,
  REVIEW_BOUNDS,
  REVIEW_CLASSIFICATIONS,
  REVIEW_FINDING_STATUSES,
  REVIEW_SEVERITIES,
} from '../../src/domain/index.js';
import {
  buildContext,
  buildFinding,
  buildSubmission,
  HOSTILE_FINDING_FIELDS,
  NON_OBJECTS,
  PR_A,
  PR_B,
  REPO_A,
  REPO_B,
  SHA_A,
  SHA_B,
} from './review-fixtures.js';

/**
 * The central invariant: trusted binding context is the only source of
 * repository, pull request, commit, provider, reviewer, and review identity.
 */
describe('reviewer content can never set a binding field', () => {
  it('ignores binding fields echoed inside a candidate finding', () => {
    const hostile = { ...buildFinding(), ...HOSTILE_FINDING_FIELDS } as ReturnType<
      typeof buildFinding
    >;
    const result = ingestReview(buildContext(), buildSubmission([hostile]));
    const finding = result.findings[0];

    expect(finding?.repositoryId).toBe(REPO_A);
    expect(finding?.pullRequestId).toBe(PR_A);
    expect(finding?.reviewedCommitSha).toBe(SHA_A);
    expect(finding?.provider).toBe('codex');
    expect(finding?.reviewerId).toBe('reviewer-1');
    expect(finding?.reviewId).toBe('review-0001');
    expect(finding?.findingId).toBe('f0');
    expect(finding?.ordinal).toBe(0);
  });

  it('keeps a review of SHA A bound to SHA A even when the payload claims SHA B', () => {
    const claiming = {
      ...buildFinding({
        title: `Reviewed at ${SHA_B}`,
        message: `This finding applies to commit ${SHA_B} in ${REPO_B} PR ${PR_B}.`,
      }),
      reviewedCommitSha: SHA_B,
      repositoryId: REPO_B,
      pullRequestId: PR_B,
    } as ReturnType<typeof buildFinding>;

    const result = ingestReview(
      buildContext({ reviewedCommitSha: SHA_A }),
      buildSubmission([claiming]),
    );

    expect(result.reviewedCommitSha).toBe(SHA_A);
    expect(result.findings[0]?.reviewedCommitSha).toBe(SHA_A);
    expect(result.findings[0]?.reviewedCommitSha).not.toBe(SHA_B);
    expect(result.findings[0]?.repositoryId).toBe(REPO_A);
  });

  it('produces identical findings with and without hostile impersonation fields', () => {
    const clean = ingestReview(buildContext(), buildSubmission([buildFinding()]));
    const hostile = ingestReview(
      buildContext(),
      buildSubmission([{ ...buildFinding(), ...HOSTILE_FINDING_FIELDS }]),
    );

    expect(hostile.findings[0]).toEqual(clean.findings[0]);
  });

  it('is unaffected by prototype-shaped keys on the candidate', () => {
    const baseline = ingestReview(buildContext(), buildSubmission([buildFinding()]));

    for (const key of ['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']) {
      const candidate = { ...buildFinding(), [key]: 'polluted' } as ReturnType<
        typeof buildFinding
      >;
      const result = ingestReview(buildContext(), buildSubmission([candidate]));

      expect(result.findings[0], key).toEqual(baseline.findings[0]);
    }
  });

  it('ignores inherited properties planted on Object.prototype', () => {
    const proto = Object.prototype as unknown as Record<string, unknown>;
    const planted = ['title', 'message', 'severity', 'classification', 'filePath'];
    const saved: Record<string, PropertyDescriptor | undefined> = {};

    for (const key of planted) {
      saved[key] = Object.getOwnPropertyDescriptor(Object.prototype, key);
      Object.defineProperty(Object.prototype, key, {
        value: 'inherited-pollution',
        configurable: true,
        writable: true,
      });
    }
    let result: ReturnType<typeof ingestReview>;
    try {
      // `{}` has no own fields; every value would have to come from the prototype.
      result = ingestReview(buildContext(), buildSubmission([{}]));
    } finally {
      for (const key of planted) {
        const descriptor = saved[key];
        if (descriptor === undefined) {
          Reflect.deleteProperty(Object.prototype, key);
        } else {
          Object.defineProperty(Object.prototype, key, descriptor);
        }
      }
      void proto;
    }

    expect(result.findings).toEqual([]);
    expect(result.rejected[0]?.reason).toBe('REQUIRED_FIELD_MISSING');
  });
});

describe('provider identity is inert', () => {
  it('normalizes identically for every provider label', () => {
    const baseline = ingestReview(
      buildContext({ provider: 'codex' }),
      buildSubmission([buildFinding()]),
    );

    for (const provider of [
      'claude',
      'openai',
      'gemini',
      'coderabbit',
      'system',
      'root',
      'admin',
      'agentbridge-internal',
    ]) {
      const result = ingestReview(
        buildContext({ provider }),
        buildSubmission([buildFinding()]),
      );

      expect({ ...result.findings[0], provider: 'codex' }, provider).toEqual(baseline.findings[0]);
    }
  });

  it('does not reinterpret provider-specific severity language for any provider', () => {
    for (const provider of ['codex', 'claude', 'coderabbit']) {
      for (const severity of ['P1', 'BLOCKING', 'critical', 'nit']) {
        const result = ingestReview(
          buildContext({ provider }),
          buildSubmission([{ ...buildFinding(), severity }]),
        );

        expect(result.findings[0]?.severity, `${provider}/${severity}`).toBe('unknown');
      }
    }
  });
});

describe('hostile runtime input is total', () => {
  const throwingGetter = (field: string): ReturnType<typeof buildFinding> =>
    Object.defineProperty({ ...buildFinding() }, field, {
      get(): never {
        throw new Error(`hostile ${field}`);
      },
      configurable: true,
      enumerable: true,
    }) as ReturnType<typeof buildFinding>;

  for (const field of ['title', 'message', 'severity', 'filePath', 'startLine', 'sourceId']) {
    it(`does not let a throwing ${field} getter escape`, () => {
      const submission = buildSubmission([throwingGetter(field)]);

      expect(() => ingestReview(buildContext(), submission)).not.toThrow();
      expect(ingestReview(buildContext(), submission).outcome).toBe(
        INGESTION_OUTCOME.INGESTED,
      );
    });
  }

  it('does not let a throwing Proxy trap escape', () => {
    const hostile = new Proxy({} as Record<string, unknown>, {
      get(): never {
        throw new Error('trap');
      },
      has(): never {
        throw new Error('trap');
      },
      getOwnPropertyDescriptor(): never {
        throw new Error('trap');
      },
    }) as unknown as ReturnType<typeof buildFinding>;

    expect(() => ingestReview(buildContext(), buildSubmission([hostile]))).not.toThrow();
    expect(ingestReview(buildContext(), buildSubmission([hostile])).findings).toEqual([]);
  });

  it('does not let a revoked Proxy escape', () => {
    const record = Proxy.revocable({ ...buildFinding() }, {});
    record.revoke();
    const collection = Proxy.revocable([buildFinding()], {});
    collection.revoke();

    expect(() => ingestReview(buildContext(), buildSubmission([record.proxy]))).not.toThrow();
    expect(() =>
      ingestReview(buildContext(), { findings: collection.proxy } as unknown as ReturnType<
        typeof buildSubmission
      >),
    ).not.toThrow();
  });

  it('does not consult a String global poisoned by a finding getter', () => {
    const intrinsicString = globalThis.String;
    const hostile = Object.defineProperty({ ...buildFinding() }, 'title', {
      get(): string {
        globalThis.String = (() => {
          throw new Error('poisoned String global');
        }) as unknown as StringConstructor;
        return 'valid title';
      },
      configurable: true,
      enumerable: true,
    }) as ReturnType<typeof buildFinding>;

    try {
      expect(() => ingestReview(buildContext(), buildSubmission([hostile]))).not.toThrow();
      expect(ingestReview(buildContext(), buildSubmission([buildFinding()])).findings[0]?.findingId).toBe(
        'f0',
      );
    } finally {
      globalThis.String = intrinsicString;
    }
  });

  for (const [label, value] of NON_OBJECTS) {
    it(`fails closed when the context is ${label}`, () => {
      const context = value as ReturnType<typeof buildContext>;

      expect(() => ingestReview(context, buildSubmission([buildFinding()]))).not.toThrow();

      const result = ingestReview(context, buildSubmission([buildFinding()]));
      expect(result.outcome).toBe(INGESTION_OUTCOME.CONTEXT_INVALID);
      expect(result.findings).toEqual([]);
    });

    it(`fails closed when the submission is ${label}`, () => {
      const submission = value as ReturnType<typeof buildSubmission>;

      expect(() => ingestReview(buildContext(), submission)).not.toThrow();

      const result = ingestReview(buildContext(), submission);
      expect(result.outcome).toBe(INGESTION_OUTCOME.INGESTED);
      expect(result.findings).toEqual([]);
    });
  }

  it('emits only declared vocabulary values for any input', () => {
    const candidates: unknown[] = [
      buildFinding(),
      { ...buildFinding(), severity: 'P1', classification: 'bug', status: 'closed' },
      null,
      42,
      { title: 'only title' },
    ];
    const result = ingestReview(buildContext(), buildSubmission(candidates));

    expect(INGESTION_OUTCOMES).toContain(result.outcome);
    for (const finding of result.findings) {
      expect(REVIEW_SEVERITIES).toContain(finding.severity);
      expect(REVIEW_CLASSIFICATIONS).toContain(finding.classification);
      expect(REVIEW_FINDING_STATUSES).toContain(finding.status);
    }
  });
});

describe('collection bounds are enforced before iteration', () => {
  it('rejects an absurd proxy length without reading any element', () => {
    let elementReads = 0;
    const findings = new Proxy([buildFinding()], {
      get(target, property, receiver): unknown {
        if (property === 'length') {
          return Number.MAX_SAFE_INTEGER;
        }
        if (typeof property === 'string' && /^\d+$/.test(property)) {
          elementReads += 1;
        }
        return Reflect.get(target, property, receiver);
      },
    });

    const result = ingestReview(buildContext(), { findings } as unknown as ReturnType<
      typeof buildSubmission
    >);

    expect(result.findings.length).toBeLessThanOrEqual(REVIEW_BOUNDS.MAX_FINDINGS);
    expect(elementReads).toBeLessThanOrEqual(REVIEW_BOUNDS.MAX_FINDINGS);
    expect(result.truncated).toBe(true);
  });

  it('handles the maximum sparse-array length without unbounded work', () => {
    const findings = new Array(4_294_967_295) as unknown[];

    const result = ingestReview(buildContext(), buildSubmission(findings));

    expect(result.findings).toEqual([]);
    expect(result.rejected.length).toBe(REVIEW_BOUNDS.MAX_FINDINGS);
    expect(result.truncated).toBe(true);
  });

  it('defines own entries when Array.prototype has an inherited index setter', () => {
    const previous = Object.getOwnPropertyDescriptor(Array.prototype, '0');
    let result: ReturnType<typeof ingestReview>;

    Object.defineProperty(Array.prototype, '0', { set() {}, configurable: true });
    try {
      result = ingestReview(
        buildContext(),
        buildSubmission([buildFinding({ title: 'kept' }), { title: 'rejected' }]),
      );
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(Array.prototype, '0');
      } else {
        Object.defineProperty(Array.prototype, '0', previous);
      }
    }

    expect(result.findings.length).toBe(1);
    expect(result.findings[0]?.title).toBe('kept');
    expect(result.rejected.length).toBe(1);
  });
});

describe('results are immutable', () => {
  it('freezes the result, findings, and rejection lists', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([buildFinding(), { title: 'bad' }]),
    );

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.findings)).toBe(true);
    expect(Object.isFrozen(result.rejected)).toBe(true);
    expect(Object.isFrozen(result.findings[0])).toBe(true);
    expect(Object.isFrozen(result.rejected[0])).toBe(true);
  });

  it('cannot have a finding rebound to another commit after ingestion', () => {
    const result = ingestReview(buildContext(), buildSubmission([buildFinding()]));
    const mutable = result.findings[0] as unknown as { reviewedCommitSha: string };

    expect(() => {
      mutable.reviewedCommitSha = SHA_B;
    }).toThrow(TypeError);
    expect(result.findings[0]?.reviewedCommitSha).toBe(SHA_A);
  });

  it('cannot have a finding pushed into the frozen findings list', () => {
    const result = ingestReview(buildContext(), buildSubmission([buildFinding()]));
    const bucket = result.findings as unknown as { push: (value: unknown) => number };

    expect(() => bucket.push(result.findings[0])).toThrow(TypeError);
    expect(result.findings.length).toBe(1);
  });
});

describe('ingestion decides nothing beyond normalization', () => {
  it('exposes no freshness or currency field', () => {
    const result = ingestReview(buildContext(), buildSubmission([buildFinding()]));
    const resultKeys = Object.keys(result);
    const findingKeys = Object.keys(result.findings[0] ?? {});

    for (const forbidden of ['state', 'freshness', 'current', 'isCurrent', 'stale', 'expired']) {
      expect(resultKeys, forbidden).not.toContain(forbidden);
      expect(findingKeys, forbidden).not.toContain(forbidden);
    }
  });

  it('exposes no authority or merge field', () => {
    const result = ingestReview(buildContext(), buildSubmission([buildFinding()]));
    const findingKeys = Object.keys(result.findings[0] ?? {});

    for (const forbidden of [
      'decision',
      'outcome',
      'mayExecute',
      'mayExecuteAutonomously',
      'requiresHumanApproval',
      'approved',
      'approvedForMerge',
      'authorized',
      'mergeable',
    ]) {
      expect(findingKeys, forbidden).not.toContain(forbidden);
    }
  });

  it('never emits an ALLOW, DENY, or ESCALATE value anywhere', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([{ ...buildFinding(), ...HOSTILE_FINDING_FIELDS }]),
    );
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain('ALLOW');
    expect(serialized).not.toContain('DENY');
    expect(serialized).not.toContain('ESCALATE');
    expect(serialized).not.toContain('AUTONOMOUS');
  });

  it('round-trips through JSON without loss', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([buildFinding(), { title: 'bad' }, null]),
    );
    const revived: unknown = JSON.parse(JSON.stringify(result));

    expect(revived).toEqual(result);
  });
});

/**
 * C1-RI-F1 — review ingestion stays total under a hostile `Object.prototype`.
 *
 * `ingestReview` accumulates normalized findings and rejected findings with
 * `append`, which defines an own index via `Object.defineProperty`. Because a
 * descriptor object literal inherits from `Object.prototype`, an inherited
 * `get`/`set` accessor was consulted by ToPropertyDescriptor and made the call
 * throw a `TypeError` — an otherwise-valid submission carrying >= 1 finding
 * turned into a crash, losing the evidence being ingested. The repair detaches
 * the descriptor's prototype before the define, so only its own data attributes
 * are read.
 *
 * Poison installers use null-prototype descriptors so the harness never
 * reproduces the bug itself; product code runs under poison, the realm is
 * restored, and assertions run afterwards (Section 13 of the repair gate).
 */
describe('C1-RI-F1 append survives hostile Object.prototype get/set', () => {
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
    it(`ingests a submission with one finding under ${keys.join('+')} poison`, () => {
      const { result, thrown } = underPoison(keys, () =>
        ingestReview(buildContext(), buildSubmission([buildFinding()])),
      );

      expect(thrown).toBeNull();
      expect(result?.outcome).toBe(INGESTION_OUTCOME.INGESTED);
      expect(result?.findings.length).toBe(1);
    });
  }

  it('preserves finding order under get+set poison', () => {
    const submission = buildSubmission([
      buildFinding({ title: 'first' }),
      buildFinding({ title: 'second' }),
      buildFinding({ title: 'third' }),
    ]);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestReview(buildContext(), submission),
    );

    expect(thrown).toBeNull();
    expect(result?.findings.map((finding) => finding.title)).toEqual([
      'first',
      'second',
      'third',
    ]);
    expect(result?.findings.map((finding) => finding.findingId)).toEqual(['f0', 'f1', 'f2']);
  });

  it('produces finding content identical to the clean control under get+set poison', () => {
    const submission = buildSubmission([buildFinding()]);
    const clean = ingestReview(buildContext(), submission);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestReview(buildContext(), submission),
    );

    expect(thrown).toBeNull();
    expect(result).toEqual(clean);
  });

  it('appends a rejected finding under get+set poison', () => {
    const submission = buildSubmission([
      buildFinding({ title: 'kept' }),
      { message: 'no title' },
    ]);
    const clean = ingestReview(buildContext(), submission);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestReview(buildContext(), submission),
    );

    expect(thrown).toBeNull();
    expect(result?.findings.length).toBe(1);
    expect(result?.findings[0]?.title).toBe('kept');
    expect(result?.rejected.length).toBe(1);
    expect(result?.rejected[0]?.reason).toBe('REQUIRED_FIELD_MISSING');
    expect(result).toEqual(clean);
  });

  it('survives a finding getter that installs get poison mid-evaluation', () => {
    const saved = getOwnDesc(Object.prototype, 'get');
    let result: ReturnType<typeof ingestReview> | null = null;
    let thrown: unknown = null;
    try {
      const hostile = defineProp({ ...buildFinding() }, 'title', {
        get(): string {
          defineProp(
            Object.prototype,
            'get',
            nullProto({ value: 'planted', configurable: true, writable: true }),
          );
          return 'title-mid'; // valid, so append(findings, finding) runs under the freshly installed poison
        },
        configurable: true,
        enumerable: true,
      }) as ReturnType<typeof buildFinding>;
      const submission = buildSubmission([hostile, buildFinding({ title: 'title-after' })]);
      try {
        result = ingestReview(buildContext(), submission);
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
    expect(result?.outcome).toBe(INGESTION_OUTCOME.INGESTED);
    expect(result?.findings.map((finding) => finding.title)).toEqual([
      'title-mid',
      'title-after',
    ]);
  });

  it('survives a finding getter that installs set poison mid-evaluation', () => {
    const saved = getOwnDesc(Object.prototype, 'set');
    let result: ReturnType<typeof ingestReview> | null = null;
    let thrown: unknown = null;
    try {
      const hostile = defineProp({ ...buildFinding() }, 'title', {
        get(): string {
          defineProp(
            Object.prototype,
            'set',
            nullProto({ value: 'planted', configurable: true, writable: true }),
          );
          return 'title-mid';
        },
        configurable: true,
        enumerable: true,
      }) as ReturnType<typeof buildFinding>;
      const submission = buildSubmission([hostile, buildFinding({ title: 'title-after' })]);
      try {
        result = ingestReview(buildContext(), submission);
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
    expect(result?.outcome).toBe(INGESTION_OUTCOME.INGESTED);
    expect(result?.findings.map((finding) => finding.title)).toEqual([
      'title-mid',
      'title-after',
    ]);
  });

  it('ingests a clean submission identically with and without poison', () => {
    const submission = buildSubmission([buildFinding()]);
    const clean = ingestReview(buildContext(), submission);
    const { result, thrown } = underPoison(['get', 'set'], () =>
      ingestReview(buildContext(), submission),
    );

    expect(thrown).toBeNull();
    expect(result).toEqual(clean);
  });

  it('restores Object.prototype after every poisoned run', () => {
    underPoison(['get', 'set'], () =>
      ingestReview(buildContext(), buildSubmission([buildFinding()])),
    );

    expect(getOwnDesc(Object.prototype, 'get')).toBeUndefined();
    expect(getOwnDesc(Object.prototype, 'set')).toBeUndefined();
  });
});
