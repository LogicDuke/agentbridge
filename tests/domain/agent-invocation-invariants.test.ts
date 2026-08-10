import { describe, expect, it } from 'vitest';

import {
  evaluateEvidenceFreshness,
  ingestInvocationReport,
  ingestReview,
  INVOCATION_BOUNDS,
  INVOCATION_PURPOSES,
  REPORT_OUTCOMES,
  type AgentInvocation,
  type AgentReport,
  type ClaimedArtifactInput,
  type EvidenceRecord,
} from '../../src/domain/index.js';
import {
  ALL_ARTIFACT_TYPES,
  ALL_STATUSES,
  buildClaim,
  buildInvocation,
  buildReport,
  CLAIM_LIMIT,
  FORBIDDEN_FIELD_NAMES,
  HOSTILE_CLAIM_FIELDS,
  IDENTIFIER_LIMIT,
  INVOCATION_A,
  label,
  NON_OBJECTS,
  oversized,
  PR_A,
  PROVIDER_LABELS,
  REPO_A,
  REQUESTED_AT,
  SHA_A,
  SHA_B,
} from './invocation-fixtures.js';

/**
 * The central invariant: the trusted invocation is the only source of
 * invocation identity, repository, pull request, commit, provider, agent, and
 * purpose.
 */
describe('provider output can never set a binding field', () => {
  it('ignores binding and authority fields echoed inside a claim', () => {
    const hostile = {
      ...buildClaim(),
      ...HOSTILE_CLAIM_FIELDS,
    } as unknown as ClaimedArtifactInput;
    const result = ingestInvocationReport(buildInvocation(), buildReport([hostile]));
    const claim = result.claims[0];

    expect(claim?.invocationId).toBe(INVOCATION_A);
    expect(claim?.repositoryId).toBe(REPO_A);
    expect(claim?.claimId).toBe('c0');
    expect(claim?.ordinal).toBe(0);
    expect(claim?.truncated).toBe(false);
    expect(result.purpose).toBe('review');
    expect(result.providerId).toBe('codex');
    expect(result.agentId).toBe('agent-1');
    expect(result.targetCommitSha).toBe(SHA_A);
    expect(result.pullRequestId).toBe(PR_A);
  });

  it('produces identical claims with and without hostile impersonation fields', () => {
    const clean = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));
    const hostile = ingestInvocationReport(
      buildInvocation(),
      buildReport([{ ...buildClaim(), ...HOSTILE_CLAIM_FIELDS } as unknown as ClaimedArtifactInput]),
    );

    expect(hostile.claims[0]).toEqual(clean.claims[0]);
    expect(hostile).toEqual(clean);
  });

  it('is unaffected by prototype-shaped keys on the candidate', () => {
    const baseline = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));

    for (const key of ['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']) {
      const candidate = { ...buildClaim(), [key]: 'polluted' } as ClaimedArtifactInput;
      const result = ingestInvocationReport(buildInvocation(), buildReport([candidate]));

      expect(result.claims[0], key).toEqual(baseline.claims[0]);
    }
  });

  it('ignores inherited properties planted on Object.prototype', () => {
    const planted = ['reference', 'artifactType', 'commitSha', 'status', 'detail'];
    const saved: Record<string, PropertyDescriptor | undefined> = {};

    for (const key of planted) {
      saved[key] = Object.getOwnPropertyDescriptor(Object.prototype, key);
      Object.defineProperty(Object.prototype, key, {
        value: 'inherited-pollution',
        configurable: true,
        writable: true,
      });
    }
    let result: ReturnType<typeof ingestInvocationReport>;
    try {
      // `{}` has no own fields; every value would have to come from the prototype.
      result = ingestInvocationReport(buildInvocation(), { artifacts: [{}] } as AgentReport);
    } finally {
      for (const key of planted) {
        const descriptor = saved[key];
        if (descriptor === undefined) {
          Reflect.deleteProperty(Object.prototype, key);
        } else {
          Object.defineProperty(Object.prototype, key, descriptor);
        }
      }
    }

    expect(result.claims).toEqual([]);
    expect(result.rejectedClaims[0]?.reason).toBe('REFERENCE_MISSING');
    expect(result.reportedStatus).toBe('unknown');
    expect(result.reportedDetail).toBeNull();
  });

  it('ignores an inherited invocation field planted on Object.prototype', () => {
    const saved = Object.getOwnPropertyDescriptor(Object.prototype, 'invocationId');
    Object.defineProperty(Object.prototype, 'invocationId', {
      value: 'inherited-invocation',
      configurable: true,
      writable: true,
    });
    let result: ReturnType<typeof ingestInvocationReport>;
    try {
      const { invocationId: _omitted, ...rest } = buildInvocation();
      void _omitted;
      result = ingestInvocationReport(rest as AgentInvocation, buildReport([]));
    } finally {
      if (saved === undefined) {
        Reflect.deleteProperty(Object.prototype, 'invocationId');
      } else {
        Object.defineProperty(Object.prototype, 'invocationId', saved);
      }
    }

    expect(result.outcome).toBe('INVOCATION_INVALID');
    expect(result.invalidInvocationFields).toContain('invocationId');
    expect(JSON.stringify(result)).not.toContain('inherited-invocation');
  });
});

describe('provider identity is inert', () => {
  it('normalizes identically for every provider label', () => {
    const baseline = ingestInvocationReport(
      buildInvocation({ providerId: 'codex' }),
      buildReport([buildClaim()]),
    );

    for (const providerId of PROVIDER_LABELS) {
      const result = ingestInvocationReport(
        buildInvocation({ providerId }),
        buildReport([buildClaim()]),
      );

      expect({ ...result, providerId: 'codex' }, providerId).toEqual(baseline);
    }
  });

  it('normalizes identically for every agent label', () => {
    const baseline = ingestInvocationReport(
      buildInvocation({ agentId: 'agent-1' }),
      buildReport([buildClaim()]),
    );

    for (const agentId of PROVIDER_LABELS) {
      const result = ingestInvocationReport(
        buildInvocation({ agentId }),
        buildReport([buildClaim()]),
      );

      expect({ ...result, agentId: 'agent-1' }, agentId).toEqual(baseline);
    }
  });

  it('does not reinterpret provider-specific status language for any provider', () => {
    for (const providerId of PROVIDER_LABELS) {
      for (const status of ['complete', 'success', 'done', 'COMPLETE', 'finished']) {
        const result = ingestInvocationReport(
          buildInvocation({ providerId }),
          buildReport([], { status }),
        );

        expect(result.reportedStatus, `${providerId}/${status}`).toBe('unknown');
      }
    }
  });

  it('does not reinterpret provider-specific artifact language for any provider', () => {
    for (const providerId of PROVIDER_LABELS) {
      for (const artifactType of ['pull-request', 'pr', 'merge-request', 'child-pr']) {
        const result = ingestInvocationReport(
          buildInvocation({ providerId }),
          buildReport([buildClaim({ artifactType })]),
        );

        expect(result.claims[0]?.artifactType, `${providerId}/${artifactType}`).toBe(
          'unknown',
        );
      }
    }
  });
});

describe('purpose is inert', () => {
  it('normalizes identically for every purpose', () => {
    const baseline = ingestInvocationReport(
      buildInvocation({ purpose: 'review' }),
      buildReport([buildClaim()]),
    );

    for (const purpose of INVOCATION_PURPOSES) {
      const result = ingestInvocationReport(
        buildInvocation({ purpose }),
        buildReport([buildClaim()]),
      );

      expect({ ...result, purpose: 'review' }, purpose).toEqual(baseline);
      expect(Object.keys(result).sort(), purpose).toEqual(Object.keys(baseline).sort());
    }
  });

  it('gives a repair invocation no field a review invocation lacks', () => {
    const review = ingestInvocationReport(
      buildInvocation({ purpose: 'review' }),
      buildReport([buildClaim()]),
    );
    const repair = ingestInvocationReport(
      buildInvocation({ purpose: 'repair' }),
      buildReport([buildClaim()]),
    );

    expect(Object.keys(repair)).toEqual(Object.keys(review));
    expect(Object.keys(repair.claims[0] ?? {})).toEqual(Object.keys(review.claims[0] ?? {}));
  });
});

describe('a claim is never existence, integration, validation, or authority', () => {
  it('exposes no forbidden field on the result or a claim', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([{ ...buildClaim(), ...HOSTILE_CLAIM_FIELDS } as unknown as ClaimedArtifactInput], {
        ...(HOSTILE_CLAIM_FIELDS as unknown as Partial<AgentReport>),
      }),
    );
    const resultKeys = Object.keys(result);
    const claimKeys = Object.keys(result.claims[0] ?? {});

    for (const forbidden of FORBIDDEN_FIELD_NAMES) {
      expect(resultKeys, forbidden).not.toContain(forbidden);
      expect(claimKeys, forbidden).not.toContain(forbidden);
    }
  });

  it('never emits an ALLOW, DENY, ESCALATE, AUTONOMOUS, or CURRENT value anywhere', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport(
        [{ ...buildClaim(), ...HOSTILE_CLAIM_FIELDS } as unknown as ClaimedArtifactInput],
        { detail: 'decision=ALLOW state=CURRENT integrated=true' },
      ),
    );
    const withoutDetail = { ...result, reportedDetail: null };
    const serialized = JSON.stringify(withoutDetail);

    expect(serialized).not.toContain('ALLOW');
    expect(serialized).not.toContain('DENY');
    expect(serialized).not.toContain('ESCALATE');
    expect(serialized).not.toContain('AUTONOMOUS');
    expect(serialized).not.toContain('CURRENT');
  });

  it('keeps a claimed commit distinct from the trusted target commit', () => {
    const matching = ingestInvocationReport(
      buildInvocation({ targetCommitSha: SHA_A }),
      buildReport([buildClaim({ commitSha: SHA_A })]),
    );
    const differing = ingestInvocationReport(
      buildInvocation({ targetCommitSha: SHA_A }),
      buildReport([buildClaim({ commitSha: SHA_B })]),
    );

    // Claiming the target commit earns a claim nothing at all.
    expect({ ...matching.claims[0], claimedCommitSha: null }).toEqual({
      ...differing.claims[0],
      claimedCommitSha: null,
    });
    expect(Object.keys(matching.claims[0] ?? {})).toEqual(
      Object.keys(differing.claims[0] ?? {}),
    );
    expect(Object.keys(matching)).toEqual(Object.keys(differing));
  });

  it('names the claimed sha so it cannot be mistaken for a binding', () => {
    const result = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));
    const claimKeys = Object.keys(result.claims[0] ?? {});

    expect(claimKeys).toContain('claimedCommitSha');
    expect(claimKeys).not.toContain('commitSha');
    expect(claimKeys).not.toContain('targetCommitSha');
    expect(claimKeys).not.toContain('headSha');
  });

  it('cannot masquerade as PR 004 evidence', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim({ commitSha: SHA_A })]),
    );
    const freshness = evaluateEvidenceFreshness(
      result.claims[0] as unknown as EvidenceRecord,
      { repositoryId: REPO_A, currentHeadSha: SHA_A },
    );

    // A claim carries no evidence identity, kind, source, or bound commit, so it
    // can never be current for any target. Reaching rung 4 needs a new record.
    expect(freshness.state).toBe('INVALID');
    expect(freshness.reason).toBe('EVIDENCE_MALFORMED');
  });
});

describe('collection bounds are enforced before iteration', () => {
  it('rejects an absurd proxy length without reading every element', () => {
    let elementReads = 0;
    const artifacts = new Proxy([buildClaim()], {
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

    const result = ingestInvocationReport(buildInvocation(), {
      artifacts,
    } as unknown as AgentReport);

    expect(result.claims.length).toBeLessThanOrEqual(CLAIM_LIMIT);
    expect(elementReads).toBeLessThanOrEqual(CLAIM_LIMIT);
    expect(result.truncated).toBe(true);
  });

  it('handles the maximum sparse-array length without unbounded work', () => {
    const artifacts = new Array(4_294_967_295) as unknown[];

    const result = ingestInvocationReport(buildInvocation(), buildReport(artifacts));

    expect(result.claims).toEqual([]);
    expect(result.rejectedClaims.length).toBe(CLAIM_LIMIT);
    expect(result.truncated).toBe(true);
  });

  it('keeps exactly the claim limit and flags anything beyond it', () => {
    const atLimit = Array.from({ length: CLAIM_LIMIT }, (_unused, index) =>
      buildClaim({ reference: `ref-${String(index)}` }),
    );
    const overLimit = [...atLimit, buildClaim({ reference: 'ref-extra' })];

    const kept = ingestInvocationReport(buildInvocation(), buildReport(atLimit));
    const dropped = ingestInvocationReport(buildInvocation(), buildReport(overLimit));

    expect(kept.claims.length).toBe(CLAIM_LIMIT);
    expect(kept.truncated).toBe(false);
    expect(dropped.claims.length).toBe(CLAIM_LIMIT);
    expect(dropped.truncated).toBe(true);
    expect(JSON.stringify(dropped)).not.toContain('ref-extra');
  });

  it('defines own entries when Array.prototype has an inherited index setter', () => {
    const previous = Object.getOwnPropertyDescriptor(Array.prototype, '0');
    let result: ReturnType<typeof ingestInvocationReport>;

    Object.defineProperty(Array.prototype, '0', { set() {}, configurable: true });
    try {
      result = ingestInvocationReport(
        buildInvocation(),
        buildReport([buildClaim({ reference: 'kept' }), { reference: '' }]),
      );
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(Array.prototype, '0');
      } else {
        Object.defineProperty(Array.prototype, '0', previous);
      }
    }

    expect(result.claims.length).toBe(1);
    expect(result.claims[0]?.reference).toBe('kept');
    expect(result.rejectedClaims.length).toBe(1);
  });
});

describe('hostile runtime input is total', () => {
  const throwingClaimGetter = (field: string): ClaimedArtifactInput =>
    Object.defineProperty({ ...buildClaim() }, field, {
      get(): never {
        throw new Error(`hostile ${field}`);
      },
      configurable: true,
      enumerable: true,
    }) as ClaimedArtifactInput;

  for (const field of ['artifactType', 'reference', 'commitSha']) {
    it(`does not let a throwing ${field} getter escape`, () => {
      const report = buildReport([throwingClaimGetter(field)]);

      expect(() => ingestInvocationReport(buildInvocation(), report)).not.toThrow();
      expect(ingestInvocationReport(buildInvocation(), report).outcome).toBe('INGESTED');
    });
  }

  for (const field of ['status', 'detail', 'artifacts']) {
    it(`does not let a throwing report ${field} getter escape`, () => {
      const report = Object.defineProperty({ ...buildReport([buildClaim()]) }, field, {
        get(): never {
          throw new Error(`hostile ${field}`);
        },
        configurable: true,
        enumerable: true,
      }) as AgentReport;

      expect(() => ingestInvocationReport(buildInvocation(), report)).not.toThrow();
      expect(ingestInvocationReport(buildInvocation(), report).outcome).toBe('INGESTED');
    });
  }

  for (const field of [
    'invocationId',
    'repositoryId',
    'pullRequestId',
    'targetCommitSha',
    'providerId',
    'agentId',
    'purpose',
    'requestedAt',
  ]) {
    it(`does not let a throwing invocation ${field} getter escape`, () => {
      const invocation = Object.defineProperty({ ...buildInvocation() }, field, {
        get(): never {
          throw new Error(`hostile ${field}`);
        },
        configurable: true,
        enumerable: true,
      }) as AgentInvocation;

      expect(() =>
        ingestInvocationReport(invocation, buildReport([buildClaim()])),
      ).not.toThrow();

      const result = ingestInvocationReport(invocation, buildReport([buildClaim()]));
      expect(result.outcome).toBe('INVOCATION_INVALID');
      expect(result.invalidInvocationFields).toContain(field);
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
    });

    expect(() =>
      ingestInvocationReport(
        buildInvocation(),
        buildReport([hostile as unknown as ClaimedArtifactInput]),
      ),
    ).not.toThrow();
    expect(() =>
      ingestInvocationReport(hostile as unknown as AgentInvocation, buildReport([])),
    ).not.toThrow();
    expect(() =>
      ingestInvocationReport(buildInvocation(), hostile as unknown as AgentReport),
    ).not.toThrow();
  });

  it('does not let a revoked Proxy escape', () => {
    const claim = Proxy.revocable({ ...buildClaim() }, {});
    claim.revoke();
    const collection = Proxy.revocable([buildClaim()], {});
    collection.revoke();
    const invocation = Proxy.revocable({ ...buildInvocation() }, {});
    invocation.revoke();

    expect(() =>
      ingestInvocationReport(
        buildInvocation(),
        buildReport([claim.proxy as unknown as ClaimedArtifactInput]),
      ),
    ).not.toThrow();
    expect(() =>
      ingestInvocationReport(buildInvocation(), {
        artifacts: collection.proxy,
      } as unknown as AgentReport),
    ).not.toThrow();
    expect(() =>
      ingestInvocationReport(invocation.proxy as unknown as AgentInvocation, buildReport([])),
    ).not.toThrow();
  });

  it('does not consult globals poisoned by a claim getter', () => {
    const intrinsicString = globalThis.String;
    const intrinsicFreeze = Object.freeze;
    const intrinsicIsArray = Array.isArray;
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const intrinsicTrim = String.prototype.trim;

    const hostile = Object.defineProperty({ ...buildClaim() }, 'reference', {
      get(): string {
        // `String.prototype` must be repointed before the `String` global is
        // replaced: the replacement has no `prototype`, so the reverse order
        // would throw inside the getter and never exercise the poisoning.
        String.prototype.trim = function poisonedTrim(): string {
          throw new Error('poisoned trim');
        };
        Object.freeze = (() => {
          throw new Error('poisoned freeze');
        }) as unknown as typeof Object.freeze;
        Array.isArray = (() => {
          throw new Error('poisoned isArray');
        }) as unknown as typeof Array.isArray;
        globalThis.String = (() => {
          throw new Error('poisoned String');
        }) as unknown as StringConstructor;
        return 'ref-1';
      },
      configurable: true,
      enumerable: true,
    }) as ClaimedArtifactInput;

    // Assertions run only after the intrinsics are restored: calling into the
    // test framework while the globals are poisoned would fail the harness
    // rather than the code under test.
    let thrown: unknown = null;
    let result: ReturnType<typeof ingestInvocationReport> | null = null;
    try {
      result = ingestInvocationReport(
        buildInvocation(),
        buildReport([hostile, buildClaim({ reference: 'ref-2' })]),
      );
    } catch (error: unknown) {
      thrown = error;
    } finally {
      globalThis.String = intrinsicString;
      Object.freeze = intrinsicFreeze;
      Array.isArray = intrinsicIsArray;
      String.prototype.trim = intrinsicTrim;
    }

    expect(thrown).toBeNull();
    expect(result?.claims.length).toBe(2);
    expect(result?.claims[0]?.reference).toBe('ref-1');
    expect(result?.claims[1]?.claimId).toBe('c1');
    expect(Object.isFrozen(result)).toBe(true);
  });

  for (const [valueLabel, value] of NON_OBJECTS) {
    it(`fails closed when the invocation is ${valueLabel}`, () => {
      const invocation = value as AgentInvocation;

      expect(() =>
        ingestInvocationReport(invocation, buildReport([buildClaim()])),
      ).not.toThrow();

      const result = ingestInvocationReport(invocation, buildReport([buildClaim()]));
      expect(result.outcome).toBe('INVOCATION_INVALID');
      expect(result.claims).toEqual([]);
    });

    it(`fails closed when the report is ${valueLabel}`, () => {
      const report = value as AgentReport;

      expect(() => ingestInvocationReport(buildInvocation(), report)).not.toThrow();

      const result = ingestInvocationReport(buildInvocation(), report);
      expect(result.outcome).toBe('INGESTED');
      expect(result.claims).toEqual([]);
      expect(result.reportedStatus).toBe('unknown');
    });
  }

  it('emits only declared vocabulary values for any input', () => {
    const candidates: unknown[] = [
      buildClaim(),
      { ...buildClaim(), artifactType: 'pull-request' },
      { reference: 'only-reference' },
      null,
      42,
      { ...buildClaim(), ...HOSTILE_CLAIM_FIELDS },
    ];
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport(candidates, { status: 'anything' }),
    );

    expect(REPORT_OUTCOMES).toContain(result.outcome);
    expect(ALL_STATUSES).toContain(result.reportedStatus);
    for (const claim of result.claims) {
      expect(ALL_ARTIFACT_TYPES, label(claim.artifactType)).toContain(claim.artifactType);
    }
    for (const rejection of result.rejectedClaims) {
      expect(
        ['CLAIM_UNREADABLE', 'REFERENCE_MISSING', 'REFERENCE_OVERSIZED'],
        rejection.reason,
      ).toContain(rejection.reason);
    }
  });
});

describe('results are deterministic and immutable', () => {
  it('produces an equal result for equal arguments', () => {
    const first = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim(), { reference: '' }, null]),
    );
    const second = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim(), { reference: '' }, null]),
    );

    expect(second).toEqual(first);
    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });

  it('freezes the result, claims, and rejection lists', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim(), { reference: '' }]),
    );

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.claims)).toBe(true);
    expect(Object.isFrozen(result.rejectedClaims)).toBe(true);
    expect(Object.isFrozen(result.claims[0])).toBe(true);
    expect(Object.isFrozen(result.rejectedClaims[0])).toBe(true);
    expect(Object.isFrozen(result.invalidInvocationFields)).toBe(true);
  });

  it('cannot have a claim rebound to another invocation after ingestion', () => {
    const result = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));
    const mutable = result.claims[0] as unknown as {
      invocationId: string;
      claimedCommitSha: string | null;
    };

    expect(() => {
      mutable.invocationId = 'other';
    }).toThrow(TypeError);
    expect(() => {
      mutable.claimedCommitSha = SHA_A;
    }).toThrow(TypeError);
    expect(result.claims[0]?.invocationId).toBe(INVOCATION_A);
  });

  it('cannot have a claim pushed into the frozen claims list', () => {
    const result = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));
    const bucket = result.claims as unknown as { push: (value: unknown) => number };

    expect(() => bucket.push(result.claims[0])).toThrow(TypeError);
    expect(result.claims.length).toBe(1);
  });

  it('freezes the exported vocabularies and bounds', () => {
    expect(Object.isFrozen(INVOCATION_BOUNDS)).toBe(true);
    expect(Object.isFrozen(INVOCATION_PURPOSES)).toBe(true);
    expect(Object.isFrozen(REPORT_OUTCOMES)).toBe(true);
  });

  it('round-trips through JSON without loss', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim(), { reference: '' }, null]),
    );
    const revived: unknown = JSON.parse(JSON.stringify(result));

    expect(revived).toEqual(result);
  });
});

describe('PR 005 correlation convention', () => {
  it('carries an invocation id through review ingestion unchanged', () => {
    const invocationId = oversized(IDENTIFIER_LIMIT);
    const accepted = ingestInvocationReport(
      buildInvocation({ invocationId }),
      buildReport([]),
    );
    const review = ingestReview(
      {
        repositoryId: REPO_A,
        pullRequestId: PR_A,
        reviewedCommitSha: SHA_A,
        provider: 'codex',
        reviewerId: 'agent-1',
        reviewId: invocationId,
      },
      { findings: [{ title: 'a', message: 'b' }] },
    );

    expect(accepted.outcome).toBe('INGESTED');
    expect(accepted.invocationId).toBe(invocationId);
    expect(review.reviewId).toBe(invocationId);
    expect(review.findings[0]?.reviewId).toBe(invocationId);
  });

  it('never mints an invocation id that review ingestion would cut', () => {
    const tooLong = oversized(IDENTIFIER_LIMIT + 1);
    const rejected = ingestInvocationReport(
      buildInvocation({ invocationId: tooLong }),
      buildReport([]),
    );

    expect(rejected.outcome).toBe('INVOCATION_INVALID');
    expect(rejected.invalidInvocationFields).toContain('invocationId');
    expect(rejected.invocationId).toBeNull();
  });

  it('does not echo the invocation requestedAt into the result', () => {
    const result = ingestInvocationReport(
      buildInvocation({ requestedAt: REQUESTED_AT }),
      buildReport([]),
    );

    // requestedAt is validated for traceability but is not part of the report
    // contract, so it cannot be mistaken for an observation timestamp.
    expect(Object.keys(result)).not.toContain('requestedAt');
  });
});
