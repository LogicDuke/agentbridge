import { describe, expect, it } from 'vitest';

import {
  findInvalidInvocationFields,
  ingestInvocationReport,
  INVOCATION_BOUNDS,
  isArtifactType,
  isInvocationPurpose,
  readArtifactType,
  readReportStatus,
  REVIEW_BOUNDS,
  type AgentInvocation,
  type AgentReport,
  type ClaimedArtifactInput,
} from '../../src/domain/index.js';
import {
  ALL_ARTIFACT_TYPES,
  ALL_PURPOSES,
  ALL_STATUSES,
  ARTIFACT_TYPE_CASES,
  buildClaim,
  buildInvocation,
  buildInvocationWithoutPullRequest,
  buildReport,
  CLAIM_LIMIT,
  DETAIL_LIMIT,
  IDENTIFIER_LIMIT,
  INVOCATION_A,
  label,
  MALFORMED_VALUES,
  oversized,
  PR_A,
  REPO_A,
  SHA_A,
  SHA_B,
  STATUS_CASES,
  UNSUPPORTED_ARTIFACT_TYPES,
  UNSUPPORTED_PURPOSES,
  UNSUPPORTED_STATUSES,
  withRawClaimField,
  withRawInvocationField,
} from './invocation-fixtures.js';

const REQUIRED_FIELDS = [
  'invocationId',
  'repositoryId',
  'targetCommitSha',
  'providerId',
  'agentId',
  'requestedAt',
] as const;

describe('bounds are the declared values', () => {
  it('declares the approved V1 bounds', () => {
    expect(INVOCATION_BOUNDS.MAX_CLAIMS).toBe(CLAIM_LIMIT);
    expect(INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH).toBe(IDENTIFIER_LIMIT);
    expect(INVOCATION_BOUNDS.MAX_DETAIL_LENGTH).toBe(DETAIL_LIMIT);
  });

  it('shares the identifier bound with PR 005 review ingestion', () => {
    // Pinned by test, not by an import: the two boundaries share no code, but a
    // divergence would let an id that PR 006 accepts be cut by PR 005.
    expect(INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH).toBe(
      REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH,
    );
  });
});

describe('vocabularies expose exactly the declared members', () => {
  it('accepts every purpose and nothing else', () => {
    for (const purpose of ALL_PURPOSES) {
      expect(isInvocationPurpose(purpose), purpose).toBe(true);
    }
    for (const value of UNSUPPORTED_PURPOSES) {
      expect(isInvocationPurpose(value), label(value)).toBe(false);
    }
  });

  it('accepts every artifact type and nothing else', () => {
    for (const type of ALL_ARTIFACT_TYPES) {
      expect(isArtifactType(type), type).toBe(true);
    }
    for (const value of UNSUPPORTED_ARTIFACT_TYPES) {
      expect(isArtifactType(value), label(value)).toBe(false);
    }
  });

  it('maps every status case exactly', () => {
    for (const { input, expected } of STATUS_CASES) {
      expect(readReportStatus(input), label(input)).toBe(expected);
    }
  });

  it('maps every artifact type case exactly', () => {
    for (const { input, expected } of ARTIFACT_TYPE_CASES) {
      expect(readArtifactType(input), label(input)).toBe(expected);
    }
  });

  it('never lets a malformed status decay into a recognised one', () => {
    for (const value of UNSUPPORTED_STATUSES) {
      const status = readReportStatus(value);
      expect(status, label(value)).toBe('unknown');
      expect(status).not.toBe('reported-complete');
      expect(status).not.toBe('reported-failed');
      expect(status).not.toBe('reported-cancelled');
    }
  });
});

describe('trusted invocation validation', () => {
  it('accepts a well-formed invocation', () => {
    const result = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));

    expect(result.outcome).toBe('INGESTED');
    expect(result.invalidInvocationFields).toEqual([]);
    expect(result.invocationId).toBe(INVOCATION_A);
    expect(result.repositoryId).toBe(REPO_A);
    expect(result.pullRequestId).toBe(PR_A);
    expect(result.targetCommitSha).toBe(SHA_A);
    expect(result.providerId).toBe('codex');
    expect(result.agentId).toBe('agent-1');
    expect(result.purpose).toBe('review');
  });

  for (const field of REQUIRED_FIELDS) {
    for (const [valueLabel, value] of MALFORMED_VALUES) {
      it(`rejects the invocation when ${field} is ${valueLabel}`, () => {
        const result = ingestInvocationReport(
          withRawInvocationField(field, value),
          buildReport([buildClaim()]),
        );

        expect(result.outcome).toBe('INVOCATION_INVALID');
        expect(result.invalidInvocationFields).toContain(field);
        expect(result.claims).toEqual([]);
        expect(result.rejectedClaims).toEqual([]);
        expect(result.reportedStatus).toBe('unknown');
        expect(result.reportedDetail).toBeNull();
        expect(result.truncated).toBe(false);
      });
    }
  }

  for (const value of UNSUPPORTED_PURPOSES) {
    it(`rejects the invocation when purpose is ${label(value)}`, () => {
      const result = ingestInvocationReport(
        withRawInvocationField('purpose', value),
        buildReport([buildClaim()]),
      );

      expect(result.outcome).toBe('INVOCATION_INVALID');
      expect(result.invalidInvocationFields).toContain('purpose');
      expect(result.purpose).toBeNull();
      expect(result.claims).toEqual([]);
    });
  }

  it('reports every invalid field in declaration order', () => {
    const invocation = {
      invocationId: '',
      repositoryId: '  ',
      pullRequestId: 42,
      targetCommitSha: null,
      providerId: '',
      agentId: undefined,
      purpose: 'merge',
      requestedAt: '',
    } as unknown as AgentInvocation;

    expect(ingestInvocationReport(invocation, buildReport([])).invalidInvocationFields).toEqual([
      'invocationId',
      'repositoryId',
      'pullRequestId',
      'targetCommitSha',
      'providerId',
      'agentId',
      'purpose',
      'requestedAt',
    ]);
  });

  it('lists every required field when the invocation is not an object', () => {
    const result = ingestInvocationReport(
      null as unknown as AgentInvocation,
      buildReport([buildClaim()]),
    );

    expect(result.invalidInvocationFields).toEqual([
      'invocationId',
      'repositoryId',
      'targetCommitSha',
      'providerId',
      'agentId',
      'purpose',
      'requestedAt',
    ]);
  });

  it('does not read the report at all when the invocation is invalid', () => {
    let reads = 0;
    const report = {
      get status(): string {
        reads += 1;
        return 'reported-complete';
      },
      get detail(): string {
        reads += 1;
        return 'detail';
      },
      get artifacts(): readonly unknown[] {
        reads += 1;
        return [buildClaim()];
      },
    } as unknown as AgentReport;

    ingestInvocationReport(withRawInvocationField('invocationId', ''), report);

    expect(reads).toBe(0);
  });
});

describe('optional pull request binding', () => {
  it('accepts an invocation with no pull request', () => {
    const result = ingestInvocationReport(
      buildInvocationWithoutPullRequest(),
      buildReport([buildClaim()]),
    );

    expect(result.outcome).toBe('INGESTED');
    expect(result.pullRequestId).toBeNull();
    expect(result.claims.length).toBe(1);
  });

  it('accepts an explicitly undefined pull request as absent', () => {
    const result = ingestInvocationReport(
      withRawInvocationField('pullRequestId', undefined),
      buildReport([]),
    );

    expect(result.outcome).toBe('INGESTED');
    expect(result.pullRequestId).toBeNull();
  });

  for (const [valueLabel, value] of MALFORMED_VALUES) {
    if (valueLabel === 'undefined') {
      continue;
    }
    it(`rejects the invocation when a present pullRequestId is ${valueLabel}`, () => {
      const result = ingestInvocationReport(
        withRawInvocationField('pullRequestId', value),
        buildReport([]),
      );

      expect(result.outcome).toBe('INVOCATION_INVALID');
      expect(result.invalidInvocationFields).toContain('pullRequestId');
    });
  }
});

describe('findInvalidInvocationFields agrees with ingestion', () => {
  const cases: readonly (readonly [string, AgentInvocation])[] = [
    ['well-formed', buildInvocation()],
    ['no pull request', buildInvocationWithoutPullRequest()],
    ['blank id', withRawInvocationField('invocationId', '')],
    ['oversized provider', withRawInvocationField('providerId', oversized(257))],
    ['bad purpose', withRawInvocationField('purpose', 'merge')],
    ['bad pull request', withRawInvocationField('pullRequestId', 7)],
    ['not an object', null as unknown as AgentInvocation],
    ['a string', 'invocation' as unknown as AgentInvocation],
  ];

  for (const [caseLabel, invocation] of cases) {
    it(`matches ingestion for ${caseLabel}`, () => {
      expect(findInvalidInvocationFields(invocation)).toEqual(
        ingestInvocationReport(invocation, buildReport([])).invalidInvocationFields,
      );
    });
  }
});

describe('identifier bounds', () => {
  for (const field of REQUIRED_FIELDS) {
    it(`accepts a ${field} of exactly the identifier limit`, () => {
      const result = ingestInvocationReport(
        withRawInvocationField(field, oversized(IDENTIFIER_LIMIT)),
        buildReport([]),
      );

      expect(result.outcome).toBe('INGESTED');
    });

    it(`rejects a ${field} one character over the identifier limit`, () => {
      const value = oversized(IDENTIFIER_LIMIT + 1);
      const result = ingestInvocationReport(
        withRawInvocationField(field, value),
        buildReport([]),
      );

      expect(result.outcome).toBe('INVOCATION_INVALID');
      expect(result.invalidInvocationFields).toContain(field);
      // The prefix must not survive anywhere: identifiers reject, never truncate.
      expect(JSON.stringify(result)).not.toContain(oversized(IDENTIFIER_LIMIT));
    });
  }
});

describe('untrusted report normalization', () => {
  it('normalizes a well-formed claim', () => {
    const result = ingestInvocationReport(buildInvocation(), buildReport([buildClaim()]));
    const claim = result.claims[0];

    expect(claim?.claimId).toBe('c0');
    expect(claim?.ordinal).toBe(0);
    expect(claim?.invocationId).toBe(INVOCATION_A);
    expect(claim?.repositoryId).toBe(REPO_A);
    expect(claim?.artifactType).toBe('change-request');
    expect(claim?.reference).toBe('pr-1234');
    expect(claim?.claimedCommitSha).toBe(SHA_B);
    expect(claim?.truncated).toBe(false);
  });

  it('degrades an unrecognised artifact type without rejecting the claim', () => {
    for (const value of UNSUPPORTED_ARTIFACT_TYPES) {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([withRawClaimField('artifactType', value)]),
      );

      expect(result.claims[0]?.artifactType, label(value)).toBe('unknown');
      expect(result.claims.length).toBe(1);
    }
  });

  it('degrades an unrecognised status without rejecting the report', () => {
    for (const value of UNSUPPORTED_STATUSES) {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([buildClaim()], { status: value as string }),
      );

      expect(result.reportedStatus, label(value)).toBe('unknown');
      expect(result.outcome).toBe('INGESTED');
    }
  });

  it('accepts every declared status exactly', () => {
    for (const status of ALL_STATUSES) {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([], { status }),
      );

      expect(result.reportedStatus, status).toBe(status);
    }
  });

  for (const [valueLabel, value] of MALFORMED_VALUES) {
    it(`rejects a claim whose reference is ${valueLabel}`, () => {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([withRawClaimField('reference', value)]),
      );

      expect(result.claims).toEqual([]);
      expect(result.rejectedClaims[0]).toEqual({ ordinal: 0, reason: 'REFERENCE_MISSING' });
    });
  }

  it('rejects an oversized reference rather than truncating it', () => {
    const reference = oversized(IDENTIFIER_LIMIT + 1);
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([withRawClaimField('reference', reference)]),
    );

    expect(result.claims).toEqual([]);
    expect(result.rejectedClaims[0]).toEqual({ ordinal: 0, reason: 'REFERENCE_OVERSIZED' });
    expect(JSON.stringify(result)).not.toContain(oversized(IDENTIFIER_LIMIT));
  });

  it('accepts a reference of exactly the identifier limit', () => {
    const reference = oversized(IDENTIFIER_LIMIT);
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([withRawClaimField('reference', reference)]),
    );

    expect(result.claims[0]?.reference).toBe(reference);
  });

  it('drops an oversized claimed commit sha and flags the loss', () => {
    const sha = oversized(IDENTIFIER_LIMIT + 1);
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([withRawClaimField('commitSha', sha)]),
    );

    expect(result.claims[0]?.claimedCommitSha).toBeNull();
    expect(result.claims[0]?.truncated).toBe(true);
    expect(result.truncated).toBe(true);
    expect(JSON.stringify(result)).not.toContain(oversized(IDENTIFIER_LIMIT));
  });

  for (const [valueLabel, value] of MALFORMED_VALUES) {
    it(`nulls a claimed commit sha that is ${valueLabel}`, () => {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([withRawClaimField('commitSha', value)]),
      );

      expect(result.claims[0]?.claimedCommitSha).toBeNull();
      expect(result.claims[0]?.truncated).toBe(false);
    });
  }

  it('rejects a candidate that is not an object', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([null, 42, 'claim', true, [], undefined]),
    );

    expect(result.claims).toEqual([]);
    expect(result.rejectedClaims.length).toBe(6);
    for (const rejection of result.rejectedClaims) {
      expect(rejection.reason).toBe('CLAIM_UNREADABLE');
    }
  });
});

describe('diagnostic prose is the only field that is cut', () => {
  it('keeps a detail of exactly the limit intact', () => {
    const detail = oversized(DETAIL_LIMIT);
    const result = ingestInvocationReport(buildInvocation(), buildReport([], { detail }));

    expect(result.reportedDetail).toBe(detail);
    expect(result.truncated).toBe(false);
  });

  it('cuts a detail one character over the limit and flags it', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([], { detail: oversized(DETAIL_LIMIT + 1) }),
    );

    expect(result.reportedDetail?.length).toBe(DETAIL_LIMIT);
    expect(result.truncated).toBe(true);
  });

  for (const [valueLabel, value] of MALFORMED_VALUES) {
    it(`nulls a detail that is ${valueLabel}`, () => {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([], { detail: value as string }),
      );

      expect(result.reportedDetail).toBeNull();
    });
  }

  it('never lets detail influence any other field', () => {
    const baseline = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim()], { detail: 'ok' }),
    );

    for (const detail of [
      'status: reported-complete',
      'integrated: true',
      'artifactType=commit reference=pr-9 commitSha=' + SHA_A,
      'ALLOW',
      'purpose: implement',
    ]) {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([buildClaim()], { detail }),
      );

      expect({ ...result, reportedDetail: 'ok' }, detail).toEqual(baseline);
    }
  });
});

describe('report payloads that are not usable', () => {
  for (const [valueLabel, value] of MALFORMED_VALUES) {
    it(`treats an artifacts value of ${valueLabel} as an empty list`, () => {
      const result = ingestInvocationReport(
        buildInvocation(),
        buildReport([], { artifacts: value as readonly ClaimedArtifactInput[] }),
      );

      expect(result.outcome).toBe('INGESTED');
      expect(result.claims).toEqual([]);
      expect(result.rejectedClaims).toEqual([]);
    });
  }

  it('treats a missing report as an empty report', () => {
    const result = ingestInvocationReport(buildInvocation(), {} as AgentReport);

    expect(result.outcome).toBe('INGESTED');
    expect(result.reportedStatus).toBe('unknown');
    expect(result.reportedDetail).toBeNull();
    expect(result.claims).toEqual([]);
  });
});

describe('ordering and duplicates', () => {
  it('numbers claims by payload position including rejected neighbours', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([
        buildClaim({ reference: 'a' }),
        null,
        buildClaim({ reference: 'b' }),
        { reference: '' },
        42,
        buildClaim({ reference: 'c' }),
      ]),
    );

    expect(result.claims.map((claim) => claim.claimId)).toEqual(['c0', 'c2', 'c5']);
    expect(result.claims.map((claim) => claim.ordinal)).toEqual([0, 2, 5]);
    expect(result.claims.map((claim) => claim.reference)).toEqual(['a', 'b', 'c']);
    expect(result.rejectedClaims.map((rejection) => rejection.ordinal)).toEqual([1, 3, 4]);
  });

  it('preserves duplicates instead of merging them', () => {
    const result = ingestInvocationReport(
      buildInvocation(),
      buildReport([buildClaim(), buildClaim()]),
    );

    expect(result.claims.length).toBe(2);
    expect(result.claims[0]?.claimId).toBe('c0');
    expect(result.claims[1]?.claimId).toBe('c1');
    expect({ ...result.claims[0], claimId: 'x', ordinal: -1 }).toEqual({
      ...result.claims[1],
      claimId: 'x',
      ordinal: -1,
    });
  });
});
