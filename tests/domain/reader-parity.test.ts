/**
 * Differential parity between the PR 005, PR 006, and PR 007 untrusted-input
 * readers.
 *
 * The three boundaries are deliberately independent: `agent-invocation.ts`
 * imports nothing from `review.ts`, and `workflow.ts` imports no reader from
 * either, so a defect or refactor on one side cannot change another's
 * validation and each captures its own intrinsics at its own load time. That
 * independence is worth more than deduplicating a handful of small readers —
 * but it does create a drift risk, because the shared readers are
 * byte-equivalent today by convention rather than by construction.
 *
 * This suite converts that convention into a build failure. It runs one shared
 * hostile-input corpus through every copy of every reader whose contract
 * overlaps and asserts identical results, so a change to one side that is not
 * mirrored on the others cannot merge silently.
 *
 * **This file is the only place the three modules meet.** It is a test, so it
 * creates no production dependency; none of `src/domain/review*.ts`,
 * `src/domain/agent-invocation*.ts`, or `src/domain/workflow*.ts` references
 * another's readers at runtime.
 *
 * Where the boundaries intentionally differ, the divergence is pinned
 * explicitly at the bottom of this file rather than omitted.
 */

import { describe, expect, it } from 'vitest';

import {
  clampText as invocationClampText,
  readExactIdentifier,
  readOwnProperty as invocationReadOwnProperty,
  readText as invocationReadText,
} from '../../src/domain/agent-invocation.js';
import { ingestInvocationReport } from '../../src/domain/agent-invocation-report.js';
import {
  clampText as reviewClampText,
  readOwnProperty as reviewReadOwnProperty,
  readText as reviewReadText,
} from '../../src/domain/review.js';
import { ingestReview } from '../../src/domain/review-ingestion.js';
import {
  clampText as workflowClampText,
  readExactIdentifier as workflowReadExactIdentifier,
  readOwnProperty as workflowReadOwnProperty,
  readText as workflowReadText,
  WORKFLOW_BOUNDS,
} from '../../src/domain/workflow.js';
import { buildInvocation, buildReport, label, oversized, PR_A, REPO_A, SHA_A } from './invocation-fixtures.js';

/** Limits that straddle both boundaries' bounds and their edges. */
const LIMITS: readonly number[] = Object.freeze([0, 1, 2, 5, 40, 255, 256, 257, 512, 1_024, 2_048, 8_192]);

/** Strings chosen to exercise blankness, edges, and surrogate splitting. */
const STRING_CORPUS: readonly string[] = Object.freeze([
  '',
  ' ',
  '\t',
  '\n',
  '   \t\n ',
  'a',
  'abc',
  ' abc',
  'abc ',
  ' abc ',
  '\u0000',
  ' ',
  'null',
  'undefined',
  '__proto__',
  'constructor',
  'café',
  '👍👍',
  'a👍',
  '👍a',
  oversized(255),
  oversized(256),
  oversized(257),
  oversized(2_048),
  oversized(2_049),
  `${oversized(255)} `,
  ` ${oversized(255)}`,
  ' '.repeat(300),
]);

/** Values that are not strings at all. */
const NON_STRING_CORPUS: readonly unknown[] = Object.freeze([
  undefined,
  null,
  0,
  42,
  -1,
  Number.NaN,
  Number.POSITIVE_INFINITY,
  true,
  false,
  {},
  [],
  ['abc'],
  (): string => 'abc',
  Symbol('abc'),
  7n,
  new Date(0),
  /abc/,
  // A boxed string is `typeof 'object'`; both readers must refuse it.
  Object('abc'),
]);

const VALUE_CORPUS: readonly unknown[] = Object.freeze([...STRING_CORPUS, ...NON_STRING_CORPUS]);

/** Property keys that probe own-only reads and prototype-shaped names. */
const KEY_CORPUS: readonly string[] = Object.freeze([
  'reference',
  'title',
  'message',
  'severity',
  'commitSha',
  'artifactType',
  'missing',
  'length',
  '0',
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  'hasOwnProperty',
]);

/** Objects whose reads are ordinary, absent, lazy, hostile, or impossible. */
function buildTargets(): readonly (readonly [string, object])[] {
  const throwingGetter = {};
  Object.defineProperty(throwingGetter, 'reference', {
    get(): never {
      throw new Error('hostile getter');
    },
    configurable: true,
    enumerable: true,
  });

  const revoked = Proxy.revocable({ reference: 'r' }, {});
  revoked.revoke();

  const inherited: object = Object.create({ reference: 'inherited', title: 'inherited' }) as object;

  const nullPrototype: object = Object.assign(Object.create(null) as object, { reference: 'np' });

  return Object.freeze([
    ['plain', { reference: 'r', title: 't' }],
    ['own undefined', { reference: undefined }],
    ['own null', { reference: null }],
    ['empty', {}],
    ['inherited only', inherited],
    ['null prototype', nullPrototype],
    ['frozen', Object.freeze({ reference: 'frozen' })],
    ['array', ['a', 'b']],
    ['throwing getter', throwingGetter],
    [
      'throwing proxy',
      new Proxy(
        {},
        {
          get(): never {
            throw new Error('trap');
          },
          has(): never {
            throw new Error('trap');
          },
          getOwnPropertyDescriptor(): never {
            throw new Error('trap');
          },
        },
      ),
    ],
    ['revoked proxy', revoked.proxy],
    ['prototype-keyed', { ['__proto__']: 'polluted', constructor: 'polluted', toString: 'polluted' }],
  ] as const);
}

describe('the reader copies are genuinely independent', () => {
  it('are distinct function objects, so parity is a real assertion', () => {
    expect(invocationReadText).not.toBe(reviewReadText);
    expect(workflowReadText).not.toBe(reviewReadText);
    expect(workflowReadText).not.toBe(invocationReadText);

    expect(invocationClampText).not.toBe(reviewClampText);
    expect(workflowClampText).not.toBe(reviewClampText);
    expect(workflowClampText).not.toBe(invocationClampText);

    expect(invocationReadOwnProperty).not.toBe(reviewReadOwnProperty);
    expect(workflowReadOwnProperty).not.toBe(reviewReadOwnProperty);
    expect(workflowReadOwnProperty).not.toBe(invocationReadOwnProperty);

    expect(workflowReadExactIdentifier).not.toBe(readExactIdentifier);
  });
});

describe('readText parity', () => {
  it('agrees on every corpus value at every limit', () => {
    for (const value of VALUE_CORPUS) {
      for (const limit of LIMITS) {
        const review = reviewReadText(value, limit);
        const invocation = invocationReadText(value, limit);
        const workflow = workflowReadText(value, limit);

        expect(invocation, `${label(value)} @ ${String(limit)}`).toBe(review);
        expect(workflow, `${label(value)} @ ${String(limit)}`).toBe(review);
      }
    }
  });

  it('agrees that a bounded-then-blank value is null', () => {
    // The bound is applied before the blankness check on every side, so a
    // string whose first `limit` characters are whitespace reads as blank.
    const value = `${' '.repeat(10)}text`;

    expect(invocationReadText(value, 5)).toBeNull();
    expect(reviewReadText(value, 5)).toBeNull();
    expect(workflowReadText(value, 5)).toBeNull();
  });

  it('agrees that the returned value is never the trimmed form', () => {
    for (const value of [' abc', 'abc ', ' abc ']) {
      expect(invocationReadText(value, 256)).toBe(value);
      expect(reviewReadText(value, 256)).toBe(value);
      expect(workflowReadText(value, 256)).toBe(value);
    }
  });
});

describe('clampText parity', () => {
  it('agrees on every string at every limit', () => {
    for (const value of STRING_CORPUS) {
      for (const limit of LIMITS) {
        const review = reviewClampText(value, limit);
        const invocation = invocationClampText(value, limit);
        const workflow = workflowClampText(value, limit);

        expect(invocation, `${label(value)} @ ${String(limit)}`).toBe(review);
        expect(workflow, `${label(value)} @ ${String(limit)}`).toBe(review);
        expect(invocation.length).toBeLessThanOrEqual(Math.min(value.length, limit));
      }
    }
  });

  it('agrees on splitting a surrogate pair at an odd boundary', () => {
    expect(invocationClampText('👍👍', 1)).toBe(reviewClampText('👍👍', 1));
    expect(workflowClampText('👍👍', 1)).toBe(reviewClampText('👍👍', 1));
    expect(invocationClampText('👍👍', 3)).toBe(reviewClampText('👍👍', 3));
    expect(workflowClampText('👍👍', 3)).toBe(reviewClampText('👍👍', 3));
  });
});

describe('readOwnProperty parity', () => {
  it('agrees on every target and key, including hostile ones', () => {
    for (const [targetLabel, target] of buildTargets()) {
      for (const key of KEY_CORPUS) {
        const review: unknown = reviewReadOwnProperty(target, key);
        const invocation: unknown = invocationReadOwnProperty(target, key);
        const workflow: unknown = workflowReadOwnProperty(target, key);

        expect(invocation, `${targetLabel}.${key}`).toBe(review);
        expect(workflow, `${targetLabel}.${key}`).toBe(review);
      }
    }
  });

  it('agrees that an inherited value is invisible to all three', () => {
    const inherited: object = Object.create({ reference: 'inherited' }) as object;

    expect(invocationReadOwnProperty(inherited, 'reference')).toBeUndefined();
    expect(reviewReadOwnProperty(inherited, 'reference')).toBeUndefined();
    expect(workflowReadOwnProperty(inherited, 'reference')).toBeUndefined();
  });

  it('agrees that none throws for any target and key', () => {
    for (const [targetLabel, target] of buildTargets()) {
      for (const key of KEY_CORPUS) {
        expect(() => reviewReadOwnProperty(target, key), `${targetLabel}.${key}`).not.toThrow();
        expect(() => invocationReadOwnProperty(target, key), `${targetLabel}.${key}`).not.toThrow();
        expect(() => workflowReadOwnProperty(target, key), `${targetLabel}.${key}`).not.toThrow();
      }
    }
  });
});

describe('readExactIdentifier parity between PR 006 and PR 007', () => {
  it('agrees on every corpus value', () => {
    for (const value of VALUE_CORPUS) {
      expect(workflowReadExactIdentifier(value), label(value)).toBe(readExactIdentifier(value));
    }
  });

  it('agrees that oversize rejects rather than shortens on both sides', () => {
    expect(readExactIdentifier(oversized(257))).toBeNull();
    expect(workflowReadExactIdentifier(oversized(257))).toBeNull();
    expect(workflowReadExactIdentifier(oversized(256))).toBe(oversized(256));
  });
});

describe('exact-identifier parity through the public boundaries', () => {
  const identifierCases: readonly (readonly [string, string])[] = Object.freeze([
    ['at the limit', oversized(256)],
    ['one over the limit', oversized(257)],
    ['far over the limit', oversized(4_096)],
    ['blank', ''],
    ['whitespace only', '   '],
    ['leading space', ' abc'],
  ]);

  for (const [caseLabel, value] of identifierCases) {
    it(`agrees on a repository identifier that is ${caseLabel}`, () => {
      const review = ingestReview(
        {
          repositoryId: value,
          pullRequestId: PR_A,
          reviewedCommitSha: SHA_A,
          provider: 'codex',
          reviewerId: 'agent-1',
        },
        { findings: [] },
      );
      const invocation = ingestInvocationReport(
        buildInvocation({ repositoryId: value }),
        buildReport([]),
      );

      const reviewRejected = review.outcome === 'CONTEXT_INVALID';
      const invocationRejected = invocation.outcome === 'INVOCATION_INVALID';

      // Both boundaries treat repository, pull request, and commit identifiers
      // as exact bindings: accepted whole, or rejected outright.
      expect(invocationRejected, caseLabel).toBe(reviewRejected);
      if (!reviewRejected) {
        expect(review.repositoryId).toBe(value);
        expect(invocation.repositoryId).toBe(value);
      }
    });
  }

  it('agrees that an exact binding is never silently shortened', () => {
    const value = oversized(256);

    expect(readExactIdentifier(value)).toBe(value);
    expect(readExactIdentifier(oversized(257))).toBeNull();
    expect(reviewReadText(oversized(257), 256)).toBe(oversized(256));
    // The review-side reader *would* shorten; the exact-identifier wrapper is
    // what prevents it. PR 006 applies that wrapper to every identifier.
  });
});

describe('intentional divergence is pinned, not hidden', () => {
  /**
   * PR 005 bounds `provider`, `reviewerId`, and `reviewId` with `readText`,
   * which shortens an oversized value. PR 006 rejects the equivalent
   * `providerId` and `agentId` outright.
   *
   * This is deliberate and recorded in
   * `docs/architecture/006-agent-invocation-boundary.md`: PR 006 mints its own
   * identifiers and rejects oversized ones, so no AgentBridge-issued value can
   * ever reach PR 005's shortening path. Hardening PR 005 to match is required
   * only if a provider-supplied invocation id ever becomes the join key.
   *
   * If PR 005 is hardened per that trigger, this test is expected to fail. That
   * failure is the intended signal to update the divergence record, not a
   * regression.
   */
  it('pins PR 005 shortening a provider label and PR 006 rejecting one', () => {
    const provider = oversized(257);

    const review = ingestReview(
      {
        repositoryId: REPO_A,
        pullRequestId: PR_A,
        reviewedCommitSha: SHA_A,
        provider,
        reviewerId: 'agent-1',
      },
      { findings: [] },
    );
    const invocation = ingestInvocationReport(
      buildInvocation({ providerId: provider }),
      buildReport([]),
    );

    expect(review.outcome).toBe('INGESTED');
    expect(review.provider).toBe(oversized(256));

    expect(invocation.outcome).toBe('INVOCATION_INVALID');
    expect(invocation.invalidInvocationFields).toContain('providerId');
    expect(invocation.providerId).toBeNull();
  });

  it('pins the identifier bound as equal on all three sides', () => {
    // Shared by convention, not by import. If any side changes its bound, the
    // id that one boundary accepts is no longer the id another stores.
    expect(readExactIdentifier(oversized(256))).not.toBeNull();
    expect(readExactIdentifier(oversized(257))).toBeNull();
    expect(workflowReadExactIdentifier(oversized(256))).not.toBeNull();
    expect(workflowReadExactIdentifier(oversized(257))).toBeNull();
    expect(reviewReadText(oversized(256), 256)).toBe(oversized(256));
    expect(WORKFLOW_BOUNDS.MAX_IDENTIFIER_LENGTH).toBe(256);
  });

  /**
   * PR 007 has no truncating path at all: it stores no prose, so `clampText`
   * and `readText` exist there only to keep the reader set byte-equivalent and
   * pinnable. Every field it stores goes through `readExactIdentifier`.
   */
  it('pins PR 007 as having no field that truncates', () => {
    const workflow = ingestInvocationReport(buildInvocation(), buildReport([]));

    expect(workflow.outcome).toBe('INGESTED');
    expect(workflowReadExactIdentifier(oversized(257))).toBeNull();
  });
});
