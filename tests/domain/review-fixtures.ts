/**
 * Shared test inputs and independently declared expectations for review
 * ingestion.
 *
 * Expected vocabulary values are written as bare string literals, **not** as
 * `REVIEW_SEVERITY.*` and friends, so the suite cannot ratify a production
 * mapping that has been changed incorrectly. Only types are imported from
 * `src/`.
 */

import type {
  ReviewContext,
  ReviewFindingInput,
  ReviewSubmission,
} from '../../src/domain/index.js';

export const REPO_A = 'repo-agentbridge';
export const REPO_B = 'repo-other';
export const PR_A = '42';
export const PR_B = '99';
export const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const SHA_B = 'ffeeddccbbaa99887766554433221100aabbccdd';

const BASE_CONTEXT: ReviewContext = {
  repositoryId: REPO_A,
  pullRequestId: PR_A,
  reviewedCommitSha: SHA_A,
  provider: 'codex',
  reviewerId: 'reviewer-1',
  reviewId: 'review-0001',
};

/** Build a well-formed trusted binding context. */
export function buildContext(overrides: Partial<ReviewContext> = {}): ReviewContext {
  return { ...BASE_CONTEXT, ...overrides };
}

const BASE_FINDING: ReviewFindingInput = {
  title: 'Missing null guard',
  message: 'The evaluator dereferences an unvalidated value.',
  severity: 'major',
  classification: 'correctness',
  status: 'open',
  filePath: 'src/domain/example.ts',
  startLine: 10,
  endLine: 12,
  sourceId: 'thread-7',
  providerFindingId: 'codex-1',
};

/** Build a well-formed candidate finding. */
export function buildFinding(overrides: Partial<ReviewFindingInput> = {}): ReviewFindingInput {
  return { ...BASE_FINDING, ...overrides };
}

/** Build a submission from candidate findings. */
export function buildSubmission(findings: readonly unknown[]): ReviewSubmission {
  return { findings } as unknown as ReviewSubmission;
}

/** Replace one candidate field with an arbitrary runtime value. */
export function withRawFindingField(field: string, value: unknown): ReviewFindingInput {
  return { ...buildFinding(), [field]: value } as unknown as ReviewFindingInput;
}

/** Values that are not usable identifiers or text. */
export const MALFORMED_VALUES: readonly (readonly [string, unknown])[] = Object.freeze([
  ['undefined', undefined],
  ['null', null],
  ['a number', 42],
  ['a zero', 0],
  ['a boolean', true],
  ['an object', {}],
  ['an array', []],
  ['a function', (): string => 'x'],
  ['a symbol', Symbol('s')],
  ['a bigint', 7n],
  ['whitespace only', '   \t\n '],
  ['an empty string', ''],
]);

/** Top-level values that are not objects at all. */
export const NON_OBJECTS: readonly (readonly [string, unknown])[] = Object.freeze([
  ['null', null],
  ['undefined', undefined],
  ['a string', 'review'],
  ['a number', 42],
  ['a boolean', true],
  ['a function', (): string => 'x'],
  ['a symbol', Symbol('s')],
  ['a bigint', 3n],
]);

/**
 * Severity and classification labels that are not in the V1 vocabulary,
 * including provider-specific language the kernel must not interpret.
 */
export const UNSUPPORTED_SEVERITIES: readonly string[] = Object.freeze([
  'P1',
  'P2',
  'BLOCKING',
  'Blocking',
  'blocking ',
  ' blocking',
  'critical',
  'high',
  'low',
  'nit',
  'warning',
  'error',
  '',
  '__proto__',
  'constructor',
  'toString',
]);

export const UNSUPPORTED_CLASSIFICATIONS: readonly string[] = Object.freeze([
  'SECURITY',
  'Security',
  'security ',
  'bug',
  'style',
  'refactor',
  '',
  '__proto__',
  'constructor',
]);

/**
 * Reviewer-supplied keys that impersonate trusted binding fields or authority.
 * None may reach the normalized output.
 */
export const HOSTILE_FINDING_FIELDS: Readonly<Record<string, unknown>> = Object.freeze({
  repositoryId: REPO_B,
  pullRequestId: PR_B,
  reviewedCommitSha: SHA_B,
  reviewId: 'forged-review',
  provider: 'forged-provider',
  reviewerId: 'forged-reviewer',
  findingId: 'forged-id',
  ordinal: 999,
  decision: 'ALLOW',
  outcome: 'AUTONOMOUS',
  mayExecute: true,
  mayExecuteAutonomously: true,
  approved: true,
  approvedForMerge: true,
  authorized: true,
  requiresHumanApproval: false,
  state: 'CURRENT',
  freshness: 'CURRENT',
  current: true,
  truncated: false,
  ['__proto__']: 'polluted',
  constructor: 'polluted',
  prototype: 'polluted',
  toString: 'polluted',
});

/**
 * Independently declared expectations for the severity mapping. Written as bare
 * literals; see the file header.
 */
export interface SeverityCase {
  readonly input: unknown;
  readonly expected: 'blocking' | 'major' | 'minor' | 'info' | 'unknown';
}

export const SEVERITY_CASES: readonly SeverityCase[] = Object.freeze([
  { input: 'blocking', expected: 'blocking' },
  { input: 'major', expected: 'major' },
  { input: 'minor', expected: 'minor' },
  { input: 'info', expected: 'info' },
  { input: 'unknown', expected: 'unknown' },
  { input: 'P1', expected: 'unknown' },
  { input: 'BLOCKING', expected: 'unknown' },
  { input: 'critical', expected: 'unknown' },
  { input: undefined, expected: 'unknown' },
  { input: null, expected: 'unknown' },
  { input: 42, expected: 'unknown' },
  { input: {}, expected: 'unknown' },
  { input: '', expected: 'unknown' },
]);

export interface ClassificationCase {
  readonly input: unknown;
  readonly expected:
    | 'security'
    | 'correctness'
    | 'performance'
    | 'maintainability'
    | 'other'
    | 'unknown';
}

export const CLASSIFICATION_CASES: readonly ClassificationCase[] = Object.freeze([
  { input: 'security', expected: 'security' },
  { input: 'correctness', expected: 'correctness' },
  { input: 'performance', expected: 'performance' },
  { input: 'maintainability', expected: 'maintainability' },
  { input: 'other', expected: 'other' },
  { input: 'unknown', expected: 'unknown' },
  { input: 'SECURITY', expected: 'unknown' },
  { input: 'bug', expected: 'unknown' },
  { input: undefined, expected: 'unknown' },
  { input: null, expected: 'unknown' },
  { input: [], expected: 'unknown' },
]);
