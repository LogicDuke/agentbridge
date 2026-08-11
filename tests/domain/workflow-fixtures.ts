/**
 * Shared test inputs for the Autoflow state machine.
 *
 * Expected vocabulary values are written as bare string literals throughout the
 * suite, **not** as `WORKFLOW_STATUS.*` and friends, so the tests cannot ratify
 * a production mapping that has been changed incorrectly. Only types and the
 * two entry points are imported from `src/`.
 *
 * The PR 004, PR 005, and PR 006 results here are built as literals rather than
 * produced by their owning layers, so a hostile variant can differ in exactly
 * one field. `tests/domain/workflow-transitions.test.ts` additionally drives the
 * real `evaluateEvidenceFreshness`, `ingestReview`, and `ingestInvocationReport`
 * through the state machine, so the literals are pinned against the genuine
 * shapes rather than trusted on their own.
 */

import {
  applyWorkflowEvent,
  openWorkflow,
  type AgentInvocation,
  type EvidenceFreshness,
  type InvocationReportResult,
  type ReviewResult,
  type WorkflowBinding,
  type WorkflowEvent,
  type WorkflowState,
} from '../../src/domain/index.js';

export const WORKFLOW_A = 'wf-0001';
export const REPO_A = 'repo-agentbridge';
export const REPO_B = 'repo-other';
export const PR_A = '42';
export const PR_B = '99';
export const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
export const SHA_B = 'ffeeddccbbaa99887766554433221100aabbccdd';
export const SHA_C = '0123456789abcdef0123456789abcdef01234567';
export const INVOCATION_A = 'inv-0001';
export const INVOCATION_B = 'inv-0002';
export const REVIEW_A = 'rev-0001';
export const REVIEW_B = 'rev-0002';
export const EVIDENCE_A = 'ev-0001';
export const EVIDENCE_B = 'ev-0002';
export const REQUESTED_AT = '2026-01-01T00:00:00.000Z';

/** The bound every identifier in this boundary is measured against. */
export const IDENTIFIER_LIMIT = 256;

/** A string of exactly `length` `x` characters. */
export function oversized(length: number): string {
  return 'x'.repeat(length);
}

/**
 * A safe, stable label for an arbitrary runtime value.
 *
 * Test names must never stringify an unknown value directly: a symbol throws,
 * and an object degrades to `[object Object]`.
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

const BASE_BINDING: WorkflowBinding = {
  workflowId: WORKFLOW_A,
  repositoryId: REPO_A,
  pullRequestId: PR_A,
  boundCommitSha: SHA_A,
};

/** A well-formed trusted binding. */
export function buildBinding(overrides: Partial<WorkflowBinding> = {}): WorkflowBinding {
  return { ...BASE_BINDING, ...overrides };
}

/** A binding with no pull request. */
export function buildBindingWithoutPullRequest(): WorkflowBinding {
  const { pullRequestId: _omitted, ...rest } = BASE_BINDING;
  void _omitted;
  return rest;
}

/** Replace one binding field with an arbitrary runtime value. */
export function withRawBindingField(field: string, value: unknown): WorkflowBinding {
  return { ...BASE_BINDING, [field]: value } as unknown as WorkflowBinding;
}

/** Open a workflow, failing the fixture loudly if the binding is unusable. */
export function openedWorkflow(binding: WorkflowBinding = buildBinding()): WorkflowState {
  const result = openWorkflow(binding);
  if (result.state === null) {
    throw new Error('fixture binding must open');
  }
  return result.state;
}

/** Apply an event, failing the fixture loudly if it was refused. */
export function applyOrThrow(state: WorkflowState, event: WorkflowEvent): WorkflowState {
  const result = applyWorkflowEvent(state, event);
  if (result.outcome !== 'APPLIED') {
    throw new Error(`fixture event must apply, got ${String(result.rejection)}`);
  }
  return result.state;
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

/** A well-formed PR 006 trusted invocation. */
export function buildInvocation(overrides: Partial<AgentInvocation> = {}): AgentInvocation {
  return { ...BASE_INVOCATION, ...overrides };
}

/** An invocation with no pull request bound to it. */
export function buildInvocationWithoutPullRequest(): AgentInvocation {
  const { pullRequestId: _omitted, ...rest } = BASE_INVOCATION;
  void _omitted;
  return rest;
}

/** Replace one invocation field with an arbitrary runtime value. */
export function withRawInvocationField(field: string, value: unknown): AgentInvocation {
  return { ...BASE_INVOCATION, [field]: value } as unknown as AgentInvocation;
}

const BASE_REPORT: InvocationReportResult = {
  outcome: 'INGESTED',
  invocationId: INVOCATION_A,
  repositoryId: REPO_A,
  pullRequestId: PR_A,
  targetCommitSha: SHA_A,
  providerId: 'codex',
  agentId: 'agent-1',
  purpose: 'review',
  reportedStatus: 'reported-complete',
  reportedDetail: 'done',
  claims: [],
  rejectedClaims: [],
  invalidInvocationFields: [],
  truncated: false,
};

/** A well-formed PR 006 ingestion result. */
export function buildReport(
  overrides: Partial<InvocationReportResult> = {},
): InvocationReportResult {
  return { ...BASE_REPORT, ...overrides };
}

/** Replace one report field with an arbitrary runtime value. */
export function withRawReportField(field: string, value: unknown): InvocationReportResult {
  return { ...BASE_REPORT, [field]: value } as unknown as InvocationReportResult;
}

const BASE_REVIEW: ReviewResult = {
  outcome: 'INGESTED',
  repositoryId: REPO_A,
  pullRequestId: PR_A,
  reviewedCommitSha: SHA_A,
  reviewId: REVIEW_A,
  provider: 'coderabbit',
  reviewerId: 'reviewer-1',
  findings: [],
  rejected: [],
  invalidContextFields: [],
  truncated: false,
};

/** A well-formed PR 005 ingestion result. */
export function buildReview(overrides: Partial<ReviewResult> = {}): ReviewResult {
  return { ...BASE_REVIEW, ...overrides };
}

/** Replace one review field with an arbitrary runtime value. */
export function withRawReviewField(field: string, value: unknown): ReviewResult {
  return { ...BASE_REVIEW, [field]: value } as unknown as ReviewResult;
}

const BASE_VERDICT: EvidenceFreshness = {
  evidenceId: EVIDENCE_A,
  repositoryId: REPO_A,
  commitSha: SHA_A,
  kind: 'ci-result',
  source: 'github',
  targetRepositoryId: REPO_A,
  targetHeadSha: SHA_A,
  state: 'CURRENT',
  reason: 'BOUND_TO_CURRENT_HEAD',
  // Frozen, exactly as PR 004 emits it: `evaluateEvidenceFreshness` freezes
  // every result list, and emptiness is only provable for a non-extensible
  // value. A plain `[]` here would not be faithful to the real producer.
  invalidFields: Object.freeze([]),
};

/** A well-formed PR 004 freshness verdict, CURRENT at the bound commit. */
export function buildVerdict(overrides: Partial<EvidenceFreshness> = {}): EvidenceFreshness {
  return { ...BASE_VERDICT, ...overrides };
}

/** Replace one verdict field with an arbitrary runtime value. */
export function withRawVerdictField(field: string, value: unknown): EvidenceFreshness {
  return { ...BASE_VERDICT, [field]: value } as unknown as EvidenceFreshness;
}

/** A human-decision verdict, which is what clears an open human gate. */
export function buildHumanDecisionVerdict(
  overrides: Partial<EvidenceFreshness> = {},
): EvidenceFreshness {
  return buildVerdict({ kind: 'human-decision', source: 'human', ...overrides });
}

/* ------------------------------------------------------------------ events */

export function requestInvocation(invocation: AgentInvocation = buildInvocation()): WorkflowEvent {
  return { kind: 'INVOCATION_REQUESTED', invocation };
}

export function reportInvocation(
  report: InvocationReportResult = buildReport(),
): WorkflowEvent {
  return { kind: 'INVOCATION_REPORTED', report };
}

export function admitReview(review: ReviewResult = buildReview()): WorkflowEvent {
  return { kind: 'REVIEW_ADMITTED', review };
}

export function admitEvidence(verdict: EvidenceFreshness = buildVerdict()): WorkflowEvent {
  return { kind: 'EVIDENCE_ADMITTED', verdict };
}

export function observeHead(observedCommitSha: string = SHA_B): WorkflowEvent {
  return { kind: 'HEAD_OBSERVED', observedCommitSha };
}

export function openHumanGate(atCommitSha: string = SHA_A): WorkflowEvent {
  return { kind: 'HUMAN_GATE_OPENED', atCommitSha };
}

export function closeWorkflow(closureReason = 'CALLER_CLOSED'): WorkflowEvent {
  return { kind: 'CLOSE_REQUESTED', closureReason } as WorkflowEvent;
}

/** Every event kind, as a valid instance bound to the default fixture state. */
export function everyValidEvent(): readonly (readonly [string, WorkflowEvent])[] {
  return Object.freeze([
    ['INVOCATION_REQUESTED', requestInvocation()],
    ['INVOCATION_REPORTED', reportInvocation()],
    ['REVIEW_ADMITTED', admitReview()],
    ['EVIDENCE_ADMITTED', admitEvidence()],
    ['HEAD_OBSERVED', observeHead()],
    ['HUMAN_GATE_OPENED', openHumanGate()],
    ['CLOSE_REQUESTED', closeWorkflow()],
  ] as const);
}

/* ----------------------------------------------------------------- hostile */

/** Values that are not usable identifiers. */
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
  ['a string', 'workflow'],
  ['a number', 42],
  ['a boolean', true],
  ['a function', (): string => 'x'],
  ['a symbol', Symbol('s')],
  ['a bigint', 3n],
]);

/** Event kinds outside the vocabulary. None may be accepted or degrade. */
export const UNSUPPORTED_EVENT_KINDS: readonly unknown[] = Object.freeze([
  'invocation_requested',
  'INVOCATION_REQUESTED ',
  ' INVOCATION_REQUESTED',
  'Invocation_Requested',
  'HUMAN_DECISION_RECORDED',
  'MERGE',
  'unknown',
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
  Symbol('INVOCATION_REQUESTED'),
]);

/** Provider labels, including privileged-sounding ones. All must be inert. */
export const PROVIDER_LABELS: readonly string[] = Object.freeze([
  'claude',
  'openai',
  'gemini',
  'codex',
  'system',
  'root',
  'admin',
  'agentbridge-internal',
]);

/** Every PR 006 purpose. All must be inert. */
export const PURPOSES: readonly string[] = Object.freeze([
  'review',
  'implement',
  'repair',
  'audit',
]);

/** Every PR 006 reported status. All must be inert. */
export const REPORT_STATUSES: readonly string[] = Object.freeze([
  'reported-complete',
  'reported-failed',
  'reported-cancelled',
  'unknown',
]);

/** Field names no serialized workflow state may ever contain as a key. */
export const FORBIDDEN_STATE_KEYS: readonly string[] = Object.freeze([
  'exists',
  'verified',
  'observed',
  'integrated',
  'merged',
  'applied',
  'validated',
  'authorized',
  'mergeable',
  'approved',
  'mayMerge',
  'mayExecute',
  'ready',
  'readyForMerge',
  'blocking',
  'findingCount',
  'freshness',
  'current',
  'stale',
  'nextAction',
  'nextInvocation',
  'attempt',
  'attempts',
  'retries',
  'maxAttempts',
  'budget',
  'deadline',
  'timeout',
  'expiresAt',
  'backoff',
  'cost',
  'tokens',
  'converged',
  'requested',
  'unsolicited',
]);

/** Values no serialized workflow state may ever contain. */
export const FORBIDDEN_STATE_VALUES: readonly string[] = Object.freeze([
  'ALLOW',
  'DENY',
  'ESCALATE',
  'AUTONOMOUS',
  'CURRENT',
  'STALE',
]);

/** An object whose named property throws when read. */
export function withThrowingGetter<T extends object>(base: T, field: string): T {
  const target = { ...base } as Record<string, unknown>;
  Object.defineProperty(target, field, {
    get() {
      throw new Error('hostile getter');
    },
    enumerable: true,
    configurable: true,
  });
  return target as T;
}

/** An object whose named property returns a different value on each read. */
export function withUnstableGetter<T extends object>(
  base: T,
  field: string,
  values: readonly unknown[],
): T {
  const target = { ...base } as Record<string, unknown>;
  let reads = 0;
  Object.defineProperty(target, field, {
    get() {
      const value = values[reads] ?? values[values.length - 1];
      reads += 1;
      return value;
    },
    enumerable: true,
    configurable: true,
  });
  return target as T;
}

/** A revoked Proxy: every trap, and `Array.isArray`, throws on it. */
export function revokedProxy(): object {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  return proxy;
}

/** An array-like Proxy reporting an absurd length. */
export function absurdLengthArray(): unknown {
  return new Proxy([], {
    get(target, key): unknown {
      if (key === 'length') {
        return Number.MAX_SAFE_INTEGER;
      }
      return Reflect.get(target, key);
    },
  });
}
