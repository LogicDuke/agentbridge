import { describe, expect, it } from 'vitest';

import {
  INGESTION_OUTCOME,
  ingestReview,
  REQUIRED_CONTEXT_FIELDS,
  REVIEW_BOUNDS,
  REVIEW_REJECTION,
} from '../../src/domain/index.js';
import {
  buildContext,
  buildFinding,
  buildSubmission,
  CLASSIFICATION_CASES,
  MALFORMED_VALUES,
  PR_A,
  REPO_A,
  SEVERITY_CASES,
  SHA_A,
  UNSUPPORTED_CLASSIFICATIONS,
  UNSUPPORTED_SEVERITIES,
  withRawFindingField,
} from './review-fixtures.js';

describe('a valid single finding', () => {
  it('normalizes every field', () => {
    const result = ingestReview(buildContext(), buildSubmission([buildFinding()]));

    expect(result.outcome).toBe(INGESTION_OUTCOME.INGESTED);
    expect(result.findings.length).toBe(1);
    expect(result.rejected).toEqual([]);
    expect(result.invalidContextFields).toEqual([]);
    expect(result.truncated).toBe(false);

    expect(result.findings[0]).toEqual({
      findingId: 'f0',
      ordinal: 0,
      repositoryId: REPO_A,
      pullRequestId: PR_A,
      reviewedCommitSha: SHA_A,
      reviewId: 'review-0001',
      provider: 'codex',
      reviewerId: 'reviewer-1',
      severity: 'major',
      classification: 'correctness',
      status: 'open',
      title: 'Missing null guard',
      message: 'The evaluator dereferences an unvalidated value.',
      filePath: 'src/domain/example.ts',
      startLine: 10,
      endLine: 12,
      sourceId: 'thread-7',
      providerFindingId: 'codex-1',
      truncated: false,
    });
  });

  it('echoes the trusted binding onto the result', () => {
    const result = ingestReview(buildContext(), buildSubmission([]));

    expect(result.repositoryId).toBe(REPO_A);
    expect(result.pullRequestId).toBe(PR_A);
    expect(result.reviewedCommitSha).toBe(SHA_A);
    expect(result.provider).toBe('codex');
    expect(result.reviewerId).toBe('reviewer-1');
    expect(result.reviewId).toBe('review-0001');
  });

  it('represents an absent reviewId as null rather than dropping it', () => {
    const context = buildContext();
    const withoutReviewId = { ...context } as Record<string, unknown>;
    delete withoutReviewId['reviewId'];

    const result = ingestReview(
      withoutReviewId as unknown as ReturnType<typeof buildContext>,
      buildSubmission([buildFinding()]),
    );

    expect(result.reviewId).toBeNull();
    expect(result.findings[0]?.reviewId).toBeNull();
    expect(Object.keys(result)).toContain('reviewId');
  });
});

describe('multiple findings', () => {
  it('preserves submission order with stable ordinals and ids', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([
        buildFinding({ title: 'first' }),
        buildFinding({ title: 'second' }),
        buildFinding({ title: 'third' }),
      ]),
    );

    expect(result.findings.length).toBe(3);
    expect(result.findings.map((f) => f.title)).toEqual(['first', 'second', 'third']);
    expect(result.findings.map((f) => f.ordinal)).toEqual([0, 1, 2]);
    expect(result.findings.map((f) => f.findingId)).toEqual(['f0', 'f1', 'f2']);
  });

  it('keeps ordinals aligned to payload position when a neighbour is rejected', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([
        buildFinding({ title: 'kept-first' }),
        { title: 'no message' },
        buildFinding({ title: 'kept-last' }),
      ]),
    );

    expect(result.findings.map((f) => f.ordinal)).toEqual([0, 2]);
    expect(result.findings.map((f) => f.findingId)).toEqual(['f0', 'f2']);
    expect(result.rejected).toEqual([
      { ordinal: 1, reason: REVIEW_REJECTION.REQUIRED_FIELD_MISSING },
    ]);
  });

  it('is byte-equivalent across repeated ingestion', () => {
    const context = buildContext();
    const submission = buildSubmission([
      buildFinding({ title: 'a' }),
      buildFinding({ title: 'b' }),
    ]);

    const first = ingestReview(context, submission);
    const second = ingestReview(context, submission);

    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
  });
});

describe('empty and absent payloads', () => {
  it('returns a valid empty result for zero findings', () => {
    const result = ingestReview(buildContext(), buildSubmission([]));

    expect(result.outcome).toBe(INGESTION_OUTCOME.INGESTED);
    expect(result.findings).toEqual([]);
    expect(result.rejected).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  it('returns a valid empty result when findings is absent', () => {
    const result = ingestReview(buildContext(), {} as ReturnType<typeof buildSubmission>);

    expect(result.outcome).toBe(INGESTION_OUTCOME.INGESTED);
    expect(result.findings).toEqual([]);
  });

  for (const [label, value] of MALFORMED_VALUES) {
    it(`returns an empty finding list when findings is ${label}`, () => {
      const submission = { findings: value } as unknown as ReturnType<typeof buildSubmission>;

      expect(() => ingestReview(buildContext(), submission)).not.toThrow();
      expect(ingestReview(buildContext(), submission).findings).toEqual([]);
    });
  }
});

describe('severity and classification normalization', () => {
  for (const testCase of SEVERITY_CASES) {
    it(`maps severity ${JSON.stringify(testCase.input)} to ${testCase.expected}`, () => {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('severity', testCase.input)]),
      );

      expect(result.findings[0]?.severity).toBe(testCase.expected);
    });
  }

  for (const testCase of CLASSIFICATION_CASES) {
    it(`maps classification ${JSON.stringify(testCase.input)} to ${testCase.expected}`, () => {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('classification', testCase.input)]),
      );

      expect(result.findings[0]?.classification).toBe(testCase.expected);
    });
  }

  it('fails unsupported severities closed to unknown, never to a low value', () => {
    for (const severity of UNSUPPORTED_SEVERITIES) {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('severity', severity)]),
      );

      expect(result.findings[0]?.severity, severity).toBe('unknown');
      expect(result.findings[0]?.severity, severity).not.toBe('info');
      expect(result.findings[0]?.severity, severity).not.toBe('minor');
    }
  });

  it('fails unsupported classifications closed to unknown, not to other', () => {
    for (const classification of UNSUPPORTED_CLASSIFICATIONS) {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('classification', classification)]),
      );

      expect(result.findings[0]?.classification, classification).toBe('unknown');
      expect(result.findings[0]?.classification, classification).not.toBe('other');
    }
  });

  it('fails unsupported statuses closed to unknown, not to resolved', () => {
    for (const status of ['OPEN', 'closed', 'resolved ', '', 42, null, {}]) {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('status', status)]),
      );

      expect(result.findings[0]?.status).toBe('unknown');
      expect(result.findings[0]?.status).not.toBe('resolved');
    }
  });
});

describe('required finding fields', () => {
  for (const [label, value] of MALFORMED_VALUES) {
    it(`rejects a finding whose title is ${label}`, () => {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('title', value)]),
      );

      expect(result.findings).toEqual([]);
      expect(result.rejected).toEqual([
        { ordinal: 0, reason: REVIEW_REJECTION.REQUIRED_FIELD_MISSING },
      ]);
    });

    it(`rejects a finding whose message is ${label}`, () => {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('message', value)]),
      );

      expect(result.findings).toEqual([]);
      expect(result.rejected[0]?.reason).toBe(REVIEW_REJECTION.REQUIRED_FIELD_MISSING);
    });
  }

  it('rejects a non-object candidate as unreadable', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([null, undefined, 'text', 42, true, []]),
    );

    expect(result.findings).toEqual([]);
    expect(result.rejected.length).toBe(6);
    for (const rejection of result.rejected) {
      expect(rejection.reason).toBe(REVIEW_REJECTION.FINDING_UNREADABLE);
    }
  });
});

describe('locations', () => {
  it('keeps a coherent range', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([buildFinding({ startLine: 5, endLine: 9 })]),
    );

    expect(result.findings[0]?.startLine).toBe(5);
    expect(result.findings[0]?.endLine).toBe(9);
  });

  it('drops an incoherent or malformed range without throwing', () => {
    const cases: readonly (readonly [unknown, unknown])[] = [
      [9, 5],
      [0, 3],
      [-1, 4],
      [1.5, 4],
      ['3', '4'],
      [null, null],
      [undefined, 7],
      [NaN, NaN],
      [Infinity, Infinity],
      [{}, []],
    ];

    for (const [startLine, endLine] of cases) {
      const finding = { ...buildFinding(), startLine, endLine } as ReturnType<
        typeof buildFinding
      >;

      expect(() => ingestReview(buildContext(), buildSubmission([finding]))).not.toThrow();

      const result = ingestReview(buildContext(), buildSubmission([finding]));
      const normalized = result.findings[0];
      expect(normalized).toBeDefined();
      if (normalized !== undefined) {
        if (normalized.startLine === null) {
          expect(normalized.endLine).toBeNull();
        }
        const coherent =
          normalized.endLine === null || normalized.endLine >= (normalized.startLine ?? 0);
        expect(coherent).toBe(true);
      }
    }
  });

  it('treats a malformed file path as absent', () => {
    for (const [, value] of MALFORMED_VALUES) {
      const result = ingestReview(
        buildContext(),
        buildSubmission([withRawFindingField('filePath', value)]),
      );

      expect(result.findings[0]?.filePath).toBeNull();
    }
  });
});

describe('duplicates are preserved, not merged', () => {
  it('emits one finding per identical candidate with distinct stable ids', () => {
    const duplicate = buildFinding({ title: 'same', message: 'same body' });
    const result = ingestReview(
      buildContext(),
      buildSubmission([duplicate, duplicate, duplicate]),
    );

    expect(result.findings.length).toBe(3);
    expect(result.findings.map((f) => f.findingId)).toEqual(['f0', 'f1', 'f2']);
    expect(new Set(result.findings.map((f) => f.findingId)).size).toBe(3);
    for (const finding of result.findings) {
      expect(finding.title).toBe('same');
    }
  });

  it('is deterministic across repeated ingestion of duplicates', () => {
    const duplicate = buildFinding({ title: 'same' });
    const submission = buildSubmission([duplicate, duplicate]);

    expect(JSON.stringify(ingestReview(buildContext(), submission))).toBe(
      JSON.stringify(ingestReview(buildContext(), submission)),
    );
  });
});

describe('binding context validation', () => {
  for (const field of REQUIRED_CONTEXT_FIELDS) {
    it(`refuses to ingest when ${field} is blank`, () => {
      const result = ingestReview(
        buildContext({ [field]: '  ' }),
        buildSubmission([buildFinding()]),
      );

      expect(result.outcome).toBe(INGESTION_OUTCOME.CONTEXT_INVALID);
      expect(result.findings).toEqual([]);
      expect(result.invalidContextFields).toContain(field);
      expect(result.repositoryId).toBeNull();
    });
  }

  it('reports every invalid binding field at once', () => {
    const result = ingestReview(
      { repositoryId: '', pullRequestId: '', reviewedCommitSha: '' } as ReturnType<
        typeof buildContext
      >,
      buildSubmission([buildFinding()]),
    );

    expect([...result.invalidContextFields].sort()).toEqual(
      ['provider', 'pullRequestId', 'repositoryId', 'reviewedCommitSha', 'reviewerId'].sort(),
    );
  });

  it('does not ingest any finding when the context is invalid', () => {
    const result = ingestReview(
      buildContext({ reviewedCommitSha: '' }),
      buildSubmission([buildFinding(), buildFinding()]),
    );

    expect(result.findings).toEqual([]);
    expect(result.rejected).toEqual([]);
  });
});

describe('bounds', () => {
  it('caps the finding count and flags truncation', () => {
    const overflow = REVIEW_BOUNDS.MAX_FINDINGS + 25;
    const candidates: unknown[] = [];
    for (let index = 0; index < overflow; index += 1) {
      candidates[candidates.length] = buildFinding({ title: `t${String(index)}` });
    }

    const result = ingestReview(buildContext(), buildSubmission(candidates));

    expect(result.findings.length).toBe(REVIEW_BOUNDS.MAX_FINDINGS);
    expect(result.truncated).toBe(true);
    expect(result.findings[0]?.title).toBe('t0');
  });

  it('does not flag truncation at exactly the cap', () => {
    const candidates: unknown[] = [];
    for (let index = 0; index < REVIEW_BOUNDS.MAX_FINDINGS; index += 1) {
      candidates[candidates.length] = buildFinding();
    }

    const result = ingestReview(buildContext(), buildSubmission(candidates));

    expect(result.findings.length).toBe(REVIEW_BOUNDS.MAX_FINDINGS);
    expect(result.truncated).toBe(false);
  });

  it('clamps oversized text deterministically and flags it', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([
        buildFinding({
          title: 'x'.repeat(REVIEW_BOUNDS.MAX_TITLE_LENGTH + 500),
          message: 'y'.repeat(REVIEW_BOUNDS.MAX_MESSAGE_LENGTH + 500),
          filePath: 'z'.repeat(REVIEW_BOUNDS.MAX_PATH_LENGTH + 500),
        }),
      ]),
    );

    const finding = result.findings[0];
    expect(finding?.title.length).toBe(REVIEW_BOUNDS.MAX_TITLE_LENGTH);
    expect(finding?.message.length).toBe(REVIEW_BOUNDS.MAX_MESSAGE_LENGTH);
    expect(finding?.filePath?.length).toBe(REVIEW_BOUNDS.MAX_PATH_LENGTH);
    expect(finding?.truncated).toBe(true);
    expect(result.truncated).toBe(true);
  });

  it('clamps identifier-shaped fields', () => {
    const result = ingestReview(
      buildContext(),
      buildSubmission([
        buildFinding({
          sourceId: 's'.repeat(REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH + 100),
          providerFindingId: 'p'.repeat(REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH + 100),
        }),
      ]),
    );

    expect(result.findings[0]?.sourceId?.length).toBe(REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH);
    expect(result.findings[0]?.providerFindingId?.length).toBe(
      REVIEW_BOUNDS.MAX_IDENTIFIER_LENGTH,
    );
  });
});
