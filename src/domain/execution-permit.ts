/**
 * One-time execution permits, and the separate operator merge authority *shape*
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
 * The structural shape a merge authorization must have. **Not proof that one
 * exists.**
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
 * ## A value of this type is untrusted data, not authority
 *
 * Nothing in C1 establishes where such a value came from. There is no minting
 * boundary, so a caller can write the object literal by hand and C1 will read it
 * exactly as it reads any other untrusted record. What this layer models is the
 * *binding* a merge authority must carry:
 *
 * - repository-bound, pull-request-bound, and bound to one exact HEAD SHA
 * - carrying the structural `singleUse: true` marker
 * - incapable of covering another pull request or a different SHA
 *
 * {@link operatorMergeAuthorizes} checks exactly that binding, and nothing more.
 * It compares the record against a caller-supplied {@link MergeTarget}, so it
 * does **not** establish that the target SHA is authoritative or fresh, nor
 * operator origin, human identity, authentication, trusted minting, uniqueness,
 * one-time consumption, or replay prevention.
 *
 * A future trusted operator boundary — the merge broker — owns those properties:
 * it must authenticate the operator, guarantee that the record was minted by
 * that boundary rather than assembled by a caller, obtain the authoritative
 * pull-request HEAD immediately before merging and require the record to match
 * it, and consume the record so it cannot authorize a second merge. Until that
 * boundary exists, a record of this shape proves nothing about a human.
 */
export interface OperatorMergeAuthorization {
  /** Caller-minted identity of this one operator decision. */
  readonly authorizationId: string;
  /**
   * Identifier of the operator a future trusted boundary must authenticate.
   * Descriptive data here: C1 checks only that it is a readable identifier, and
   * never establishes that it names a human rather than an agent or a caller.
   */
  readonly operatorId: string;
  /** The one repository this authorization is valid in. */
  readonly repositoryId: string;
  /** The one pull request this authorization is valid for. */
  readonly pullRequestId: string;
  /** The one HEAD SHA this record names. A different SHA is a different merge. */
  readonly headSha: string;
  /** Caller-supplied timestamp. Data; no clock is read here. */
  readonly authorizedAt: string;
  /**
   * Structural intent: this record is *shaped* as a single-use capability. C1
   * has no consumed-capability store, so single consumption is not enforced
   * here — a later trusted boundary must enforce it.
   */
  readonly singleUse: true;
}

/**
 * The merge a candidate authorization is being checked against.
 *
 * Every field is **caller-supplied input**. C1 reads no repository, no API, and
 * no adapter, so it cannot check any of these values against reality. They
 * define what the candidate is compared *to*, and nothing more.
 */
export interface MergeTarget {
  readonly repositoryId: string;
  readonly pullRequestId: string;
  /**
   * The HEAD SHA supplied for this merge target. **C1 does not establish that
   * this value is authoritative or current** — it performs no repository, API,
   * or adapter observation, so a stale, invented, or caller-constructed SHA is
   * indistinguishable from a live one here. The future trusted merge boundary
   * must obtain the authoritative repository/pull-request HEAD immediately
   * before the merge attempt and supply and enforce that exact value.
   */
  readonly currentHeadSha: string;
}

/**
 * Is this candidate record *structurally bound* to exactly this **supplied**
 * merge target?
 *
 * Pure, total, and deterministic; never throws. Both arguments are read
 * defensively, own-only, and exactly once.
 *
 * ## What a `true` result proves
 *
 * Only that the candidate carries the required structural fields as readable
 * identifiers, that its `singleUse` is literally `true`, and that its
 * `repositoryId`, `pullRequestId`, and `headSha` are exactly equal to the
 * corresponding fields of the supplied {@link MergeTarget} — including
 * `target.currentHeadSha`, which is an **input value, not an observation**.
 * Every comparison is exact string equality, so a candidate naming pull request
 * 41 can never cover a target naming pull request 42, and a candidate whose
 * `headSha` differs from the supplied target SHA never matches. There is no path
 * that widens, refreshes, or re-binds a candidate to a different SHA.
 *
 * ## What a `true` result does not prove
 *
 * Stated explicitly, because overclaiming here would be worse than not checking:
 *
 * - **That the target SHA is authoritative or fresh.** C1 fetches nothing and
 *   observes no repository, so it cannot tell a live HEAD from a stale or
 *   invented one, and cannot know whether the repository moved after the target
 *   was built. The binding is only ever as good as the supplied target.
 * - **Operator origin.** The first argument is untrusted data. A plain object
 *   literal, written by any caller with the right field names, satisfies this
 *   predicate.
 * - **Human identity or authentication.** `operatorId` is a readable string and
 *   nothing more. C1 performs no authentication and reads no credential.
 * - **Trusted minting or possession.** There is no signature, no secret, and no
 *   issuing boundary, so this predicate cannot distinguish a record a trusted
 *   boundary minted from one a caller assembled.
 * - **That a changed SHA reflects a new operator decision.** If the supplied
 *   target SHA changes, the previous candidate simply stops matching, and *some*
 *   candidate whose `headSha` equals the newly supplied target SHA would be
 *   required. C1 cannot tell whether such a candidate is a fresh human decision
 *   or the same untrusted caller assembling another literal.
 * - **Uniqueness, one-time consumption, or replay prevention.** C1 stores
 *   nothing and consumes nothing. The identical record returns `true` on every
 *   call for as long as the same target is supplied. `singleUse: true` is a
 *   structural intent marker, not enforcement.
 *
 * **A `true` result is therefore not sufficient proof that a merge may
 * execute.** It is a necessary binding check that a future trusted operator
 * boundary / merge broker must run *in addition to* authenticating the operator,
 * verifying that it minted the record itself, obtaining the authoritative
 * pull-request HEAD at merge time and requiring the candidate to match that
 * value, and consuming the record atomically. Those properties belong to that
 * later, explicitly reviewed layer.
 *
 * C1 executes no merge. This predicate exists so that the binding half of the
 * merge barrier is defined by something more precise than a comment.
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

  // The supplied target is captured *before* any candidate property is read.
  // Reading the untrusted candidate runs its own getters and Proxy traps, which
  // could otherwise mutate the still-live target before its fields are captured
  // and make a stale candidate match a target it was rewritten to fit.
  const targetRepositoryId = readExactIdentifier(readOwnProperty(targetRecord, 'repositoryId'));
  const targetPullRequestId = readExactIdentifier(readOwnProperty(targetRecord, 'pullRequestId'));
  const targetHeadSha = readExactIdentifier(readOwnProperty(targetRecord, 'currentHeadSha'));

  const authorizationId = readExactIdentifier(readOwnProperty(record, 'authorizationId'));
  const operatorId = readExactIdentifier(readOwnProperty(record, 'operatorId'));
  const repositoryId = readExactIdentifier(readOwnProperty(record, 'repositoryId'));
  const pullRequestId = readExactIdentifier(readOwnProperty(record, 'pullRequestId'));
  const headSha = readExactIdentifier(readOwnProperty(record, 'headSha'));
  const authorizedAt = readExactIdentifier(readOwnProperty(record, 'authorizedAt'));
  const singleUse = readOwnProperty(record, 'singleUse');

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
