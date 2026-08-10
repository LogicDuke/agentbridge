/**
 * Shared test inputs and independently declared expectations for the agent
 * invocation boundary.
 *
 * Expected vocabulary values are written as bare string literals, **not** as
 * `INVOCATION_PURPOSE.*` and friends, so the suite cannot ratify a production
 * mapping that has been changed incorrectly. Only types are imported from
 * `src/`.
 */

import type {
  AgentInvocation,
  AgentReport,
  ClaimedArtifactInput,
} from '../../src/domain/index.js';

export const INVOCATION_A = 'inv-0001';
export const INVOCATION_B = 'inv-0002';
export const REPO_A = 'repo-agentbridge';
export const REPO_B = 'repo-other';
export const PR_A = '42';
export const PR_B = '99';
export const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const SHA_B = 'ffeeddccbbaa99887766554433221100aabbccdd';
export const REQUESTED_AT = '2026-01-01T00:00:00.000Z';

/** The bound every identifier in this boundary is measured against. */
export const IDENTIFIER_LIMIT = 256;
export const DETAIL_LIMIT = 2_048;
export const CLAIM_LIMIT = 64;

/** A string of exactly `length` `x` characters. */
export function oversized(length: number): string {
  return 'x'.repeat(length);
}

/**
 * A safe, stable label for an arbitrary runtime value.
 *
 * Test names and assertion messages must never stringify an unknown value
 * directly: a symbol throws, and an object degrades to `[object Object]`.
 */
export function label(value: unknown): string {
  if (typeof value === 'string') {
    return value === '' ? "''" : `'${value}'`;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (typeof value === 'bigint') {
    return `${String(value)}n`;
  }
  if (typeof value === 'symbol') {
    return `symbol(${value.description ?? ''})`;
  }
  if (value === null) {
    return 'null';
  }
  if (value === undefined) {
    return 'undefined';
  }
  if (Array.isArray(value)) {
    return 'array';
  }
  if (typeof value === 'function') {
    return 'function';
  }
  return 'object';
}

const BASE_INVOCATION: AgentInvocation = {
  invocationId: INVOCATION_A,
  repositoryId: REPO_A,
  pullRequestId: PR_A,
  targetCommitSha: SHA_A,
  providerId: 'codex',
  agentId: 'agent-1',
  purpose: 'review',
  requestedAt: REQUESTED_AT,
};

/** Build a well-formed trusted invocation. */
export function buildInvocation(overrides: Partial<AgentInvocation> = {}): AgentInvocation {
  return { ...BASE_INVOCATION, ...overrides };
}

/** Build an invocation with no pull request bound to it. */
export function buildInvocationWithoutPullRequest(): AgentInvocation {
  const { pullRequestId: _omitted, ...rest } = BASE_INVOCATION;
  void _omitted;
  return rest;
}

/** Replace one invocation field with an arbitrary runtime value. */
export function withRawInvocationField(field: string, value: unknown): AgentInvocation {
  return { ...BASE_INVOCATION, [field]: value } as unknown as AgentInvocation;
}

const BASE_CLAIM: ClaimedArtifactInput = {
  artifactType: 'change-request',
  reference: 'pr-1234',
  commitSha: SHA_B,
};

/** Build a well-formed candidate artifact claim. */
export function buildClaim(
  overrides: Partial<ClaimedArtifactInput> = {},
): ClaimedArtifactInput {
  return { ...BASE_CLAIM, ...overrides };
}

/** Replace one claim field with an arbitrary runtime value. */
export function withRawClaimField(field: string, value: unknown): ClaimedArtifactInput {
  return { ...BASE_CLAIM, [field]: value } as unknown as ClaimedArtifactInput;
}

/** Build a report from candidate claims. */
export function buildReport(
  artifacts: readonly unknown[],
  overrides: Partial<AgentReport> = {},
): AgentReport {
  return { status: 'reported-complete', detail: 'done', artifacts, ...overrides } as AgentReport;
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
  ['a string', 'invocation'],
  ['a number', 42],
  ['a boolean', true],
  ['a function', (): string => 'x'],
  ['a symbol', Symbol('s')],
  ['a bigint', 3n],
]);

/**
 * Purpose labels outside the V1 vocabulary. None may be accepted, and none may
 * degrade into a recognised purpose.
 */
export const UNSUPPORTED_PURPOSES: readonly unknown[] = Object.freeze([
  'Review',
  'REVIEW',
  'review ',
  ' review',
  'unknown',
  'merge',
  'deploy',
  'implement\n',
  '',
  '__proto__',
  'constructor',
  'toString',
  42,
  true,
  null,
  undefined,
  {},
  [],
  Symbol('review'),
]);

/**
 * Status labels outside the V1 vocabulary, including provider-specific language
 * the boundary must not interpret.
 */
export const UNSUPPORTED_STATUSES: readonly unknown[] = Object.freeze([
  'complete',
  'COMPLETE',
  'Reported-Complete',
  'reported-complete ',
  ' reported-complete',
  'success',
  'succeeded',
  'done',
  'ok',
  'finished',
  'failed',
  'cancelled',
  'error',
  '',
  '__proto__',
  'constructor',
  42,
  true,
  null,
  undefined,
  [],
  {},
]);

/** Artifact type labels outside the V1 vocabulary. */
export const UNSUPPORTED_ARTIFACT_TYPES: readonly unknown[] = Object.freeze([
  'Commit',
  'COMMIT',
  'commit ',
  'pull-request',
  'pullrequest',
  'pr',
  'merge-request',
  'diff',
  '',
  '__proto__',
  'constructor',
  42,
  null,
  undefined,
  {},
  [],
]);

/**
 * Provider and agent labels, including privileged-sounding ones. Normalization
 * must be byte-identical across every one of them.
 */
export const PROVIDER_LABELS: readonly string[] = Object.freeze([
  'claude',
  'openai',
  'codex',
  'coderabbit',
  'gemini',
  'anthropic',
  'system',
  'root',
  'admin',
  'human',
  'agentbridge',
  'agentbridge-internal',
]);

/** Every member of the V1 purpose vocabulary, as bare literals. */
export const ALL_PURPOSES: readonly string[] = Object.freeze([
  'review',
  'implement',
  'repair',
  'audit',
]);

/** Every member of the V1 report status vocabulary, as bare literals. */
export const ALL_STATUSES: readonly string[] = Object.freeze([
  'reported-complete',
  'reported-failed',
  'reported-cancelled',
  'unknown',
]);

/** Every member of the V1 artifact type vocabulary, as bare literals. */
export const ALL_ARTIFACT_TYPES: readonly string[] = Object.freeze([
  'commit',
  'branch',
  'change-request',
  'patch',
  'report',
  'unknown',
]);

/**
 * Provider-supplied keys that impersonate trusted binding fields, claim
 * identity, or authority. None may reach the normalized output.
 */
export const HOSTILE_CLAIM_FIELDS: Readonly<Record<string, unknown>> = Object.freeze({
  invocationId: INVOCATION_B,
  repositoryId: REPO_B,
  pullRequestId: PR_B,
  targetCommitSha: SHA_A,
  providerId: 'forged-provider',
  agentId: 'forged-agent',
  purpose: 'implement',
  requestedAt: '1970-01-01T00:00:00.000Z',
  claimId: 'forged-claim',
  ordinal: 999,
  truncated: false,
  exists: true,
  existsRemotely: true,
  verified: true,
  integrated: true,
  merged: true,
  applied: true,
  landed: true,
  validated: true,
  authorized: true,
  mergeable: true,
  approved: true,
  approvedForMerge: true,
  mayExecute: true,
  mayExecuteAutonomously: true,
  requiresHumanApproval: false,
  decision: 'ALLOW',
  outcome: 'AUTONOMOUS',
  state: 'CURRENT',
  freshness: 'CURRENT',
  current: true,
  isCurrent: true,
  stale: false,
  expired: false,
  nextAction: 'merge',
  shouldRetry: true,
  attempt: 1,
  attempts: 1,
  retries: 0,
  deadline: 'never',
  timeout: 0,
  parentInvocationId: INVOCATION_B,
  supersedes: INVOCATION_A,
  ['__proto__']: 'polluted',
  constructor: 'polluted',
  prototype: 'polluted',
  toString: 'polluted',
});

/**
 * Field names that must never appear on a result or a claim. Declared here as
 * bare literals so the assertion does not depend on production constants.
 */
export const FORBIDDEN_FIELD_NAMES: readonly string[] = Object.freeze([
  'exists',
  'existsRemotely',
  'verified',
  'integrated',
  'merged',
  'applied',
  'landed',
  'validated',
  'authorized',
  'mergeable',
  'approved',
  'approvedForMerge',
  'mayExecute',
  'mayExecuteAutonomously',
  'requiresHumanApproval',
  'decision',
  'state',
  'freshness',
  'current',
  'isCurrent',
  'stale',
  'expired',
  'nextAction',
  'shouldRetry',
  'attempt',
  'attempts',
  'retries',
  'deadline',
  'timeout',
  'parentInvocationId',
  'supersedes',
]);

/** Independently declared expectations for the report status mapping. */
export interface StatusCase {
  readonly input: unknown;
  readonly expected:
    | 'reported-complete'
    | 'reported-failed'
    | 'reported-cancelled'
    | 'unknown';
}

export const STATUS_CASES: readonly StatusCase[] = Object.freeze([
  { input: 'reported-complete', expected: 'reported-complete' },
  { input: 'reported-failed', expected: 'reported-failed' },
  { input: 'reported-cancelled', expected: 'reported-cancelled' },
  { input: 'unknown', expected: 'unknown' },
  { input: 'complete', expected: 'unknown' },
  { input: 'COMPLETE', expected: 'unknown' },
  { input: 'success', expected: 'unknown' },
  { input: 'done', expected: 'unknown' },
  { input: undefined, expected: 'unknown' },
  { input: null, expected: 'unknown' },
  { input: 42, expected: 'unknown' },
  { input: {}, expected: 'unknown' },
  { input: '', expected: 'unknown' },
]);

/** Independently declared expectations for the artifact type mapping. */
export interface ArtifactTypeCase {
  readonly input: unknown;
  readonly expected:
    | 'commit'
    | 'branch'
    | 'change-request'
    | 'patch'
    | 'report'
    | 'unknown';
}

export const ARTIFACT_TYPE_CASES: readonly ArtifactTypeCase[] = Object.freeze([
  { input: 'commit', expected: 'commit' },
  { input: 'branch', expected: 'branch' },
  { input: 'change-request', expected: 'change-request' },
  { input: 'patch', expected: 'patch' },
  { input: 'report', expected: 'report' },
  { input: 'unknown', expected: 'unknown' },
  { input: 'pull-request', expected: 'unknown' },
  { input: 'COMMIT', expected: 'unknown' },
  { input: undefined, expected: 'unknown' },
  { input: null, expected: 'unknown' },
  { input: [], expected: 'unknown' },
]);
