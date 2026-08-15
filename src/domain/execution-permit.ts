/**
 * One-time execution permits, and the separate operator merge authority
 * (Cockpit C1).
 *
 * ## A permit is not a bearer token
 *
 * An {@link ExecutionPermit} is the record of a single authorization: exactly
 * one job, exactly one normalized operation, exactly one set of operands, bound
 * to the job's repository, parent pull request, parent HEAD, and policy
 * version at the moment the decision was made.
 *
 * **It is not trusted on its face.** `permitAuthorizes` in
 * `job-authorization.ts` re-derives the whole decision from the job and the
 * request, and compares. The security property that follows is precise and
 * worth stating in the form it actually holds:
 *
 * > A forged permit that passes re-verification is a permit the evaluator
 * > would have issued anyway.
 *
 * Forgery therefore buys nothing. A permit widens no authority; it records
 * authority already derived from trusted configuration.
 *
 * ## Single use
 *
 * A permit represents permission for **one** execution. It is not a standing
 * "yes", and the model says so structurally: there is no `expiresAt`, no
 * `uses`, no `remaining`, no `renew`, no `refresh`, and no scope wider than one
 * operation. `singleUse` is typed as the literal `true` and `scope` as the
 * literal `'exactly-one-execution'`, so neither can be widened by assignment,
 * and the object is frozen.
 *
 * C1 stores nothing and consumes nothing — there is no persistence in this PR.
 * What C1 guarantees is that the *identity* of a permit is a total function of
 * the exact execution it authorizes, so a consumer that records consumed
 * `permitId`s can detect a replay rather than being unable to distinguish one.
 *
 * ## Permit identity
 *
 * `permitId` is derived deterministically — no clock, no randomness, no
 * counter, matching the purity of every other AgentBridge domain layer. It is
 * **not a nonce**: two authorizations of byte-identical executions produce the
 * same id, which is the property that makes replay detectable.
 *
 * Two legitimate executions of the same operation are distinguished by
 * `requestId`, which the caller mints per attempt and which participates in
 * permit identity. `requestId` confers no authority: an agent that mints a
 * fresh one obtains exactly the authority it already had, for exactly one more
 * execution of an operation the job already authorizes.
 *
 * The encoding is length-prefixed, so no operand value can inject a delimiter
 * and make one execution's id collide with another's.
 */

import type { RepairJobSnapshot } from './repair-job.js';
import { append, readExactIdentifier, readOwnProperty } from './repair-job.js';
import {
  operandValues,
  type PermitOperands,
  type RepairAuthorizableOperation,
} from './job-operation.js';

const objectFreeze = Object.freeze;
// `String` performs the abstract number-to-string conversion; it does not look
// up `Number.prototype.toString`, so a poisoned prototype is not on the path.
const stringOf = String;

/** Version tag of the permit identity encoding. Changing it invalidates every id. */
const PERMIT_ID_SCHEME = 'abp1';

/**
 * Encode parts into a delimiter-injection-proof string.
 *
 * Each part is written as `<length>:<part>`, so a part containing `:`, `|`, or
 * any other separator cannot be mistaken for a boundary and two different
 * executions cannot be encoded to the same id.
 */
function encodeParts(parts: readonly string[]): string {
  let encoded = PERMIT_ID_SCHEME;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index] ?? '';
    encoded += '|' + stringOf(part.length) + ':' + part;
  }
  return encoded;
}

/**
 * A permit for exactly one execution of exactly one operation.
 *
 * Every field is a primitive, a literal, or a frozen object of primitives, so
 * the record is JSON-serializable and survives a round trip unchanged.
 *
 * `operation` is typed {@link RepairAuthorizableOperation}, which does not
 * include `merge` or any other forbidden operation. **A merge permit does not
 * type-check.** This is the type-level half of the merge barrier; the evaluator
 * enforces the runtime half.
 */
export interface ExecutionPermit {
  /** Deterministic identity of this exact authorization. */
  readonly permitId: string;
  /** Policy version that produced the decision. Part of permit identity. */
  readonly policyVersion: string;
  /** The one job this permit belongs to. */
  readonly jobId: string;
  /** The one repository this permit is valid in. */
  readonly repositoryId: string;
  /** The one parent pull request this permit is valid under. */
  readonly parentPullRequestId: string;
  /** The exact parent HEAD this permit was issued against. */
  readonly parentHeadSha: string;
  /** The caller-minted identity of this one execution attempt. */
  readonly requestId: string;
  /** The one operation this permit authorizes. Never a forbidden operation. */
  readonly operation: RepairAuthorizableOperation;
  /** The exact operands. Every operand the operation does not define is `null`. */
  readonly operands: PermitOperands;
  /** Structural: this permit authorizes one execution, not a standing right. */
  readonly singleUse: true;
  /** Structural: there is no wider scope this permit could be widened to. */
  readonly scope: 'exactly-one-execution';
}

/**
 * Mint a permit for an already-authorized operation.
 *
 * **Not exported from the domain index.** The evaluator calls it at its single
 * `ALLOW_ONCE` return site, after every check has passed. It is not a
 * capability: its `operation` parameter cannot be a forbidden operation, and a
 * permit it produced outside the evaluator would fail re-verification unless
 * the evaluator would have produced it anyway.
 */
export function issueExecutionPermit(
  job: RepairJobSnapshot,
  operation: RepairAuthorizableOperation,
  requestId: string,
  operands: PermitOperands,
): ExecutionPermit {
  const parts: string[] = [];
  append(parts, job.policyVersion);
  append(parts, job.jobId);
  append(parts, job.repositoryId);
  append(parts, job.parentPullRequestId);
  append(parts, job.parentHeadSha);
  append(parts, requestId);
  append(parts, operation);
  const values = operandValues(operands);
  for (let index = 0; index < values.length; index += 1) {
    append(parts, values[index] ?? '');
  }

  return objectFreeze({
    permitId: encodeParts(parts),
    policyVersion: job.policyVersion,
    jobId: job.jobId,
    repositoryId: job.repositoryId,
    parentPullRequestId: job.parentPullRequestId,
    parentHeadSha: job.parentHeadSha,
    requestId,
    operation,
    operands,
    singleUse: true,
    scope: 'exactly-one-execution',
  });
}

/**
 * Compare a candidate permit against a freshly issued one, field by field.
 *
 * The candidate is **untrusted**: it may be a hostile object, a Proxy, or a
 * record with throwing getters. Every property is read own-only, once, and
 * guarded, so a candidate that changes under observation cannot match on one
 * read and be used on another.
 *
 * `singleUse` and `scope` are compared too. A candidate that omits them, or
 * that carries a widened value, is not equal to a permit this layer issued.
 */
export function permitsEqual(candidate: ExecutionPermit, issued: ExecutionPermit): boolean {
  const record: unknown = candidate;
  if (typeof record !== 'object' || record === null) {
    return false;
  }

  // Compared as a raw own value, not through the identifier reader: an encoded
  // permit id concatenates several identifiers and legitimately exceeds the
  // single-identifier bound.
  if (readOwnProperty(record, 'permitId') !== issued.permitId) {
    return false;
  }
  if (readOwnProperty(record, 'policyVersion') !== issued.policyVersion) {
    return false;
  }
  if (readOwnProperty(record, 'jobId') !== issued.jobId) {
    return false;
  }
  if (readOwnProperty(record, 'repositoryId') !== issued.repositoryId) {
    return false;
  }
  if (readOwnProperty(record, 'parentPullRequestId') !== issued.parentPullRequestId) {
    return false;
  }
  if (readOwnProperty(record, 'parentHeadSha') !== issued.parentHeadSha) {
    return false;
  }
  if (readOwnProperty(record, 'requestId') !== issued.requestId) {
    return false;
  }
  if (readOwnProperty(record, 'operation') !== issued.operation) {
    return false;
  }
  if (readOwnProperty(record, 'singleUse') !== true) {
    return false;
  }
  if (readOwnProperty(record, 'scope') !== 'exactly-one-execution') {
    return false;
  }

  const rawOperands = readOwnProperty(record, 'operands');
  if (typeof rawOperands !== 'object' || rawOperands === null) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'force') !== false) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'worktreeId') !== issued.operands.worktreeId) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'path') !== issued.operands.path) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'commandClass') !== issued.operands.commandClass) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'ref') !== issued.operands.ref) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'sourceRef') !== issued.operands.sourceRef) {
    return false;
  }
  if (readOwnProperty(rawOperands, 'targetRef') !== issued.operands.targetRef) {
    return false;
  }
  return true;
}

/**
 * A merge authorization that originated from a human operator.
 *
 * **This is not job authority and is not reachable from job authority.** No
 * function in AgentBridge produces one: there is no factory, no builder, and no
 * evaluator output that contains one. The boundary that turns a human decision
 * into a record of this shape does not exist yet, and building it is an
 * explicit later decision, not an implementation detail of some other layer.
 *
 * It is defined here so that the *shape* of the only thing that may ever
 * authorize a merge is written down while the merge barrier is being
 * established, rather than improvised later by whoever needs it first.
 *
 * It is deliberately **not** an `ApprovalRecord`. That type is human decision
 * data about an `ActionRequest` at PR 003's gate; reusing it here would make
 * every existing approval a candidate merge authority.
 *
 * The required properties, all of which {@link operatorMergeAuthorizes}
 * enforces:
 *
 * - operator-originated — `operatorId` names a human, and nothing in the
 *   domain mints one
 * - repository-bound, pull-request-bound, and bound to an exact HEAD SHA
 * - single-use, and invalid the moment HEAD changes
 * - incapable of authorizing another pull request or a future SHA
 */
export interface OperatorMergeAuthorization {
  /** Caller-minted identity of this one operator decision. */
  readonly authorizationId: string;
  /** The human who decided. Never an agent, and never inferred from a label. */
  readonly operatorId: string;
  /** The one repository this authorization is valid in. */
  readonly repositoryId: string;
  /** The one pull request this authorization is valid for. */
  readonly pullRequestId: string;
  /** The exact HEAD the operator approved. A different HEAD is a different merge. */
  readonly headSha: string;
  /** Caller-supplied timestamp. Data; no clock is read here. */
  readonly authorizedAt: string;
  /** Structural: one merge, then nothing. */
  readonly singleUse: true;
}

/** The exact merge an operator authorization is being checked against. */
export interface MergeTarget {
  readonly repositoryId: string;
  readonly pullRequestId: string;
  /** The repository's HEAD *now*, supplied by a trusted adapter. */
  readonly currentHeadSha: string;
}

/**
 * Does this operator authorization cover exactly this merge, right now?
 *
 * Pure, total, and deterministic; never throws. Both arguments are read
 * defensively, own-only, and exactly once.
 *
 * Every comparison is exact string equality, so a HEAD that moved by one commit
 * invalidates the authorization, and an authorization for pull request 41 can
 * never cover pull request 42. There is no path that widens, refreshes, or
 * re-binds an authorization to a newer SHA: a new HEAD requires a new operator
 * decision.
 *
 * C1 executes no merge. This predicate exists so that the merge barrier is
 * defined by something more precise than a comment.
 */
export function operatorMergeAuthorizes(
  authorization: OperatorMergeAuthorization,
  target: MergeTarget,
): boolean {
  const record: unknown = authorization;
  if (typeof record !== 'object' || record === null) {
    return false;
  }
  const targetRecord: unknown = target;
  if (typeof targetRecord !== 'object' || targetRecord === null) {
    return false;
  }

  const authorizationId = readExactIdentifier(readOwnProperty(record, 'authorizationId'));
  const operatorId = readExactIdentifier(readOwnProperty(record, 'operatorId'));
  const repositoryId = readExactIdentifier(readOwnProperty(record, 'repositoryId'));
  const pullRequestId = readExactIdentifier(readOwnProperty(record, 'pullRequestId'));
  const headSha = readExactIdentifier(readOwnProperty(record, 'headSha'));
  const authorizedAt = readExactIdentifier(readOwnProperty(record, 'authorizedAt'));
  const singleUse = readOwnProperty(record, 'singleUse');

  const targetRepositoryId = readExactIdentifier(readOwnProperty(targetRecord, 'repositoryId'));
  const targetPullRequestId = readExactIdentifier(readOwnProperty(targetRecord, 'pullRequestId'));
  const targetHeadSha = readExactIdentifier(readOwnProperty(targetRecord, 'currentHeadSha'));

  if (
    authorizationId === null ||
    operatorId === null ||
    repositoryId === null ||
    pullRequestId === null ||
    headSha === null ||
    authorizedAt === null ||
    singleUse !== true
  ) {
    return false;
  }
  if (targetRepositoryId === null || targetPullRequestId === null || targetHeadSha === null) {
    return false;
  }

  return (
    repositoryId === targetRepositoryId &&
    pullRequestId === targetPullRequestId &&
    headSha === targetHeadSha
  );
}
