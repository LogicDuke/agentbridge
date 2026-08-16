/**
 * The repair job authorization evaluator, and the merge barrier (Cockpit C1).
 *
 *     trusted job envelope + untrusted operation request -> JobAuthorizationDecision
 *
 * `authorizeJobOperation` is a pure function of its two arguments. It executes
 * nothing, spawns nothing, reads no clock, touches no filesystem or network,
 * loads no configuration, and persists nothing. Equal arguments always produce
 * an equal result, and no input throws.
 *
 * ## The decision vocabulary
 *
 * - `ALLOW_ONCE` — this exact normalized operation, under this exact job
 *   binding, may be executed **once**, under the accompanying
 *   {@link ExecutionPermit}. It is not a standing permission and does not
 *   generalise to a similar operation, a later HEAD, or another job.
 * - `DENY` — refused. Nothing at this layer converts a `DENY` into an allow:
 *   there is no override parameter, no approval parameter, and no field on
 *   either argument that is consulted after a denial is reached.
 * - `OPERATOR_REQUIRED` — outside every autonomous envelope. Only a human
 *   operator, through the separate `OperatorMergeAuthorization` type, can ever
 *   authorize it, and no evaluator in AgentBridge produces one. This is **not**
 *   "escalate and retry": this function never returns a permit alongside it.
 *
 * The vocabulary deliberately does not reuse PR 003's `ALLOW`/`ESCALATE`/`DENY`
 * or its `AUTONOMOUS` outcome. Those answer "what is this action?" for a
 * read-only V1; this answers "may this bounded job perform this exact operation
 * once?", which is a different question with different operands.
 *
 * ## The merge barrier
 *
 * Merge is operator-only. This is a permanent AgentBridge Cockpit invariant
 * unless an explicit later architecture decision changes it, and C1 enforces it
 * structurally rather than by convention:
 *
 * 1. `merge` is not a member of `RepairAuthorizableOperation`. `ExecutionPermit
 *    .operation` is typed to that union, so **a merge permit does not
 *    type-check.**
 * 2. `ALLOW_ONCE` is produced at exactly one `return` in this file, reachable
 *    only after the operation has been narrowed to `RepairAuthorizableOperation`
 *    by two type guards.
 * 3. The merge check is the *first* decision made, before the job envelope is
 *    even validated, so no envelope, binding, or operand state can precede it.
 * 4. `authorizeJobOperation` **has no approval parameter**. There is no
 *    argument through which an `ApprovalRecord` — approved or otherwise — can
 *    reach this evaluator, so no human approval can turn merge into job
 *    authority.
 * 5. Nothing here reads an agent id, a provider id, a rationale, or metadata.
 *    The request type has no such field, and the normalizer reads no such key.
 *
 * The maximum autonomous state a future workflow may reach is therefore
 * "ready for an operator to merge". C1 implements no such state and no state
 * machine; it establishes only that ordinary job authority has no permission
 * that could become merge.
 */

import {
  containsValue,
  isVerificationCommandClass,
  readRepairJobAuthorization,
  type RepairJobAuthorization,
  type RepairJobField,
  type RepairJobSnapshot,
} from './repair-job.js';
import {
  FORBIDDEN_OPERATION,
  isForbiddenJobOperation,
  JOB_OPERATION,
  type JobOperation,
  type JobOperationRequest,
  type NormalizedJobOperation,
  projectOperands,
  readJobOperation,
  type RepairAuthorizableOperation,
  UNKNOWN_JOB_OPERATION,
} from './job-operation.js';
import {
  type ExecutionPermit,
  issueExecutionPermit,
  permitsEqual,
} from './execution-permit.js';

const objectFreeze = Object.freeze;

/** The three outcomes this evaluator can reach. */
export const JOB_AUTHORIZATION = objectFreeze({
  /** One execution of this exact operation is authorized, under a permit. */
  ALLOW_ONCE: 'ALLOW_ONCE',
  /** Refused. No input at this layer converts this into an allow. */
  DENY: 'DENY',
  /** Only a human operator may ever authorize this. Job authority never can. */
  OPERATOR_REQUIRED: 'OPERATOR_REQUIRED',
} as const);

export type JobAuthorizationOutcome =
  (typeof JOB_AUTHORIZATION)[keyof typeof JOB_AUTHORIZATION];

/** Every member of the {@link JobAuthorizationOutcome} union. */
export const JOB_AUTHORIZATION_OUTCOMES: readonly JobAuthorizationOutcome[] = objectFreeze([
  JOB_AUTHORIZATION.ALLOW_ONCE,
  JOB_AUTHORIZATION.DENY,
  JOB_AUTHORIZATION.OPERATOR_REQUIRED,
]);

/** Stable, machine-readable rationale for an authorization outcome. */
export const JOB_AUTHORIZATION_REASON = objectFreeze({
  /** The operation and every operand fall inside the job's envelope. */
  WITHIN_JOB_ENVELOPE: 'WITHIN_JOB_ENVELOPE',
  /** Merge. Operator-only, permanently, regardless of every other input. */
  MERGE_IS_OPERATOR_ONLY: 'MERGE_IS_OPERATOR_ONLY',
  /** A modeled operation ordinary job authority may never perform. */
  OPERATION_FORBIDDEN: 'OPERATION_FORBIDDEN',
  /** The operation name is not modeled at all. */
  OPERATION_UNKNOWN: 'OPERATION_UNKNOWN',
  /** The request could not be read as an object. */
  OPERATION_UNREADABLE: 'OPERATION_UNREADABLE',
  /** The job envelope is missing or malformed. See `invalidJobFields`. */
  JOB_ENVELOPE_INVALID: 'JOB_ENVELOPE_INVALID',
  /** The request names a different job. */
  JOB_MISMATCH: 'JOB_MISMATCH',
  /** The request names a different repository. */
  REPOSITORY_MISMATCH: 'REPOSITORY_MISMATCH',
  /** The request names a different parent pull request. */
  PARENT_PULL_REQUEST_MISMATCH: 'PARENT_PULL_REQUEST_MISMATCH',
  /** The request names a different parent HEAD. */
  PARENT_HEAD_MISMATCH: 'PARENT_HEAD_MISMATCH',
  /** The finding was verified against a commit that is no longer the job's HEAD. */
  FINDING_SHA_STALE: 'FINDING_SHA_STALE',
  /** A required operand is absent. */
  OPERAND_MISSING: 'OPERAND_MISSING',
  /** A path was supplied but is not a usable repository-relative path. */
  PATH_MALFORMED: 'PATH_MALFORMED',
  /** The path is not in the job's authorized file scope. */
  PATH_NOT_AUTHORIZED: 'PATH_NOT_AUTHORIZED',
  /** The worktree operand is not the job's isolated repair worktree. */
  WORKTREE_NOT_AUTHORIZED: 'WORKTREE_NOT_AUTHORIZED',
  /** The verification class is unmodeled or not in the job's authorized set. */
  COMMAND_CLASS_NOT_AUTHORIZED: 'COMMAND_CLASS_NOT_AUTHORIZED',
  /** A ref operand was supplied but is not a canonical `refs/heads/<name>` ref. */
  REF_MALFORMED: 'REF_MALFORMED',
  /** The operation names the protected parent ref as a write target. */
  PROTECTED_REF_MUTATION: 'PROTECTED_REF_MUTATION',
  /** The ref operand is not the job's isolated repair branch. */
  REF_NOT_REPAIR_BRANCH: 'REF_NOT_REPAIR_BRANCH',
  /** The stacked change request does not target the protected parent ref. */
  CHANGE_REQUEST_TARGET_INVALID: 'CHANGE_REQUEST_TARGET_INVALID',
  /** A push was requested with force, or without a readable non-force flag. */
  FORCE_PUSH_FORBIDDEN: 'FORCE_PUSH_FORBIDDEN',
} as const);

export type JobAuthorizationReason =
  (typeof JOB_AUTHORIZATION_REASON)[keyof typeof JOB_AUTHORIZATION_REASON];

/**
 * The evaluator's answer about one operation.
 *
 * Every field is a primitive, `null`, a frozen list of strings, or a frozen
 * permit, so the record is JSON-serializable and survives a round trip
 * unchanged. Echoed identifiers are `null` rather than omitted, so
 * `JSON.stringify` cannot silently drop an authorization-relevant field.
 *
 * The request's rationale, metadata, agent identity, and provider identity are
 * **not** echoed, because they were not weighed. Reproducing them would suggest
 * otherwise. `requestId` links the decision back to the full request.
 */
export interface JobAuthorizationDecision {
  /** The job's identity, or `null` when the envelope was unreadable. */
  readonly jobId: string | null;
  /** The job's repository, or `null` when the envelope was unreadable. */
  readonly repositoryId: string | null;
  /** The policy version that produced this decision. */
  readonly policyVersion: string | null;
  /** The request's own identity, echoed for correlation. */
  readonly requestId: string | null;
  /** The resolved operation. `unknown` for anything unmodeled. */
  readonly operation: JobOperation;
  /** The outcome. */
  readonly decision: JobAuthorizationOutcome;
  /** Stable, machine-readable rationale. */
  readonly reason: JobAuthorizationReason;
  /** Job fields that failed validation, in declaration order. */
  readonly invalidJobFields: readonly RepairJobField[];
  /**
   * The single reliable answer to "may this be executed, once, now?"
   *
   * True only at the one `ALLOW_ONCE` return site, where a permit is always
   * issued. No other input can raise it.
   */
  readonly mayExecuteOnce: boolean;
  /** The permit, present only alongside `ALLOW_ONCE`. */
  readonly permit: ExecutionPermit | null;
}

/** Build a refusal. Never carries a permit; `mayExecuteOnce` is always false. */
function refuse(
  snapshot: RepairJobSnapshot | null,
  invalidJobFields: readonly RepairJobField[],
  operation: NormalizedJobOperation,
  decision: JobAuthorizationOutcome,
  reason: JobAuthorizationReason,
): JobAuthorizationDecision {
  return objectFreeze({
    jobId: snapshot === null ? null : snapshot.jobId,
    repositoryId: snapshot === null ? null : snapshot.repositoryId,
    policyVersion: snapshot === null ? null : snapshot.policyVersion,
    requestId: operation.requestId,
    operation: operation.operation,
    decision,
    reason,
    invalidJobFields,
    mayExecuteOnce: false,
    permit: null,
  });
}

/**
 * Check the operands one authorizable operation defines.
 *
 * Returns the refusal reason, or `null` when every operand is inside the
 * envelope. Split out so the main evaluator's control flow — and in particular
 * its single `ALLOW_ONCE` return — stays readable.
 *
 * Every comparison is exact string equality against a value from the trusted
 * job snapshot. No prefix matching, no normalisation, no case folding.
 */
function checkOperands(
  job: RepairJobSnapshot,
  operation: RepairAuthorizableOperation,
  request: NormalizedJobOperation,
): JobAuthorizationReason | null {
  switch (operation) {
    case JOB_OPERATION.SOURCE_READ:
    case JOB_OPERATION.SOURCE_EDIT: {
      if (request.worktreeId !== job.repairWorktreeId) {
        return JOB_AUTHORIZATION_REASON.WORKTREE_NOT_AUTHORIZED;
      }
      if (request.pathMalformed) {
        return JOB_AUTHORIZATION_REASON.PATH_MALFORMED;
      }
      if (request.path === null) {
        return JOB_AUTHORIZATION_REASON.OPERAND_MISSING;
      }
      if (!containsValue(job.authorizedPaths, request.path)) {
        return JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED;
      }
      return null;
    }
    case JOB_OPERATION.VERIFICATION_RUN: {
      if (request.worktreeId !== job.repairWorktreeId) {
        return JOB_AUTHORIZATION_REASON.WORKTREE_NOT_AUTHORIZED;
      }
      if (request.commandClass === null) {
        return JOB_AUTHORIZATION_REASON.OPERAND_MISSING;
      }
      // Two independent conditions: the class must be one C1 models at all, and
      // the job must have been configured to permit it.
      if (
        !isVerificationCommandClass(request.commandClass) ||
        !containsValue(job.authorizedCommandClasses, request.commandClass)
      ) {
        return JOB_AUTHORIZATION_REASON.COMMAND_CLASS_NOT_AUTHORIZED;
      }
      return null;
    }
    case JOB_OPERATION.REPAIR_COMMIT: {
      if (request.worktreeId !== job.repairWorktreeId) {
        return JOB_AUTHORIZATION_REASON.WORKTREE_NOT_AUTHORIZED;
      }
      // A non-canonical spelling is refused for being unusable, before any
      // comparison: `main` and `heads/main` may both denote `refs/heads/main`,
      // so comparing either as a distinct string is exactly the bypass.
      if (request.refMalformed) {
        return JOB_AUTHORIZATION_REASON.REF_MALFORMED;
      }
      if (request.ref === null) {
        return JOB_AUTHORIZATION_REASON.OPERAND_MISSING;
      }
      if (request.ref === job.protectedParentRef) {
        return JOB_AUTHORIZATION_REASON.PROTECTED_REF_MUTATION;
      }
      if (request.ref !== job.repairBranch) {
        return JOB_AUTHORIZATION_REASON.REF_NOT_REPAIR_BRANCH;
      }
      return null;
    }
    case JOB_OPERATION.REPAIR_PUSH: {
      // Checked before the ref, so a forced push to the *authorized* repair
      // branch is refused for being forced rather than accidentally allowed.
      if (request.force) {
        return JOB_AUTHORIZATION_REASON.FORCE_PUSH_FORBIDDEN;
      }
      if (request.refMalformed) {
        return JOB_AUTHORIZATION_REASON.REF_MALFORMED;
      }
      if (request.ref === null) {
        return JOB_AUTHORIZATION_REASON.OPERAND_MISSING;
      }
      if (request.ref === job.protectedParentRef) {
        return JOB_AUTHORIZATION_REASON.PROTECTED_REF_MUTATION;
      }
      if (request.ref !== job.repairBranch) {
        return JOB_AUTHORIZATION_REASON.REF_NOT_REPAIR_BRANCH;
      }
      return null;
    }
    case JOB_OPERATION.REPAIR_CHANGE_REQUEST: {
      // Both ends are narrowed to the canonical spelling before either is
      // compared, so source/target separation is separation of branches rather
      // than of strings: an alias of the protected parent cannot be presented
      // as the source, and an alias of the repair branch cannot be the target.
      if (request.sourceRefMalformed || request.targetRefMalformed) {
        return JOB_AUTHORIZATION_REASON.REF_MALFORMED;
      }
      if (request.sourceRef === null || request.targetRef === null) {
        return JOB_AUTHORIZATION_REASON.OPERAND_MISSING;
      }
      // The stacked validation change request is the one place the protected
      // parent ref may be named, and only as a *target*. Opening a change
      // request against a ref does not mutate it; the parent stays untouched
      // until an operator merges.
      if (request.sourceRef !== job.repairBranch) {
        return JOB_AUTHORIZATION_REASON.REF_NOT_REPAIR_BRANCH;
      }
      if (request.targetRef !== job.protectedParentRef) {
        return JOB_AUTHORIZATION_REASON.CHANGE_REQUEST_TARGET_INVALID;
      }
      return null;
    }
  }
}

/**
 * Authorize one operation under one repair job.
 *
 * Pure, total, and deterministic; never throws. Both arguments are read exactly
 * once into frozen snapshots before any decision is made, so a getter or Proxy
 * that returns a different value on each access cannot validate one operand and
 * have a different one reach the decision or the permit.
 *
 * **There is no third parameter, and there never should be.** Not an approval,
 * not an actor, not an override, not a policy escape hatch. Authority is a
 * function of trusted configuration and exact operands, and adding an argument
 * is how that stops being true.
 *
 * @param job Trusted job configuration from an operator-controlled boundary.
 * @param request Untrusted operation request.
 */
export function authorizeJobOperation(
  job: RepairJobAuthorization,
  request: JobOperationRequest,
): JobAuthorizationDecision {
  const operation = readJobOperation(request);
  const jobRead = readRepairJobAuthorization(job);
  const snapshot = jobRead.snapshot;
  const kind: JobOperation = operation.operation;

  if (!operation.readable) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.OPERATION_UNREADABLE,
    );
  }

  // ---------------------------------------------------------------------
  // The merge barrier. First, unconditional, and above every other check.
  //
  // The answer to "may a repair job merge?" does not depend on the job, the
  // binding, the operands, the provider, or any human record, so nothing about
  // any of them is consulted before answering. OPERATOR_REQUIRED is returned
  // without a permit, here and nowhere else.
  // ---------------------------------------------------------------------
  if (kind === FORBIDDEN_OPERATION.MERGE) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.OPERATOR_REQUIRED,
      JOB_AUTHORIZATION_REASON.MERGE_IS_OPERATOR_ONLY,
    );
  }

  if (isForbiddenJobOperation(kind)) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.OPERATION_FORBIDDEN,
    );
  }

  if (kind === UNKNOWN_JOB_OPERATION) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.OPERATION_UNKNOWN,
    );
  }

  if (snapshot === null) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID,
    );
  }

  // Binding. Each comparison is exact string equality against the trusted
  // snapshot, and a `null` operand can never equal a validated snapshot value,
  // so an absent claim fails exactly like a wrong one.
  if (operation.jobId !== snapshot.jobId) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.JOB_MISMATCH,
    );
  }
  if (operation.repositoryId !== snapshot.repositoryId) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.REPOSITORY_MISMATCH,
    );
  }
  if (operation.parentPullRequestId !== snapshot.parentPullRequestId) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.PARENT_PULL_REQUEST_MISMATCH,
    );
  }
  if (operation.parentHeadSha !== snapshot.parentHeadSha) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.PARENT_HEAD_MISMATCH,
    );
  }

  // The finding must have been verified against the commit the job is bound to.
  // A repair derived from a finding about some other commit is a repair of
  // something that may no longer be there. PR 004 owns CURRENT versus STALE for
  // evidence; this is the narrower structural check that the job's own two SHAs
  // agree, which C1 can decide without importing that kernel.
  if (snapshot.findingHeadSha !== snapshot.parentHeadSha) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.FINDING_SHA_STALE,
    );
  }

  // Permit identity is a total function of the exact execution, so an execution
  // with no identity of its own cannot be authorized.
  const requestId = operation.requestId;
  if (requestId === null) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      JOB_AUTHORIZATION_REASON.OPERAND_MISSING,
    );
  }

  const operandFailure = checkOperands(snapshot, kind, operation);
  if (operandFailure !== null) {
    return refuse(
      snapshot,
      jobRead.invalidFields,
      operation,
      JOB_AUTHORIZATION.DENY,
      operandFailure,
    );
  }

  // ---------------------------------------------------------------------
  // The single ALLOW_ONCE return in AgentBridge.
  //
  // `kind` is narrowed to RepairAuthorizableOperation here by the two guards
  // above, which is why no forbidden operation — merge included — can reach
  // this line even if every check below it were removed.
  // ---------------------------------------------------------------------
  return objectFreeze({
    jobId: snapshot.jobId,
    repositoryId: snapshot.repositoryId,
    policyVersion: snapshot.policyVersion,
    requestId,
    operation: kind,
    decision: JOB_AUTHORIZATION.ALLOW_ONCE,
    reason: JOB_AUTHORIZATION_REASON.WITHIN_JOB_ENVELOPE,
    invalidJobFields: jobRead.invalidFields,
    mayExecuteOnce: true,
    permit: issueExecutionPermit(snapshot, kind, requestId, projectOperands(kind, operation)),
  });
}

/**
 * Does this permit authorize this exact operation, under this job, right now?
 *
 * The permit is **not trusted on its face**. This re-derives the entire
 * decision from the trusted job and the untrusted request and then compares,
 * so a permit only ever authorizes what the evaluator would authorize at the
 * moment of use. Three consequences worth being explicit about:
 *
 * - A permit issued for job A cannot be presented under job B: the re-derived
 *   permit binds to B's identity and does not match.
 * - A permit issued for one operation or operand cannot be presented for
 *   another: operands are part of permit identity.
 * - A permit issued against one parent HEAD stops verifying the moment the job
 *   is re-bound to a new HEAD, and re-claiming the new HEAD in the request
 *   produces a different permit identity rather than reviving the old one.
 *
 * It does **not** implement consumption. C1 has no store, and single use is a
 * property of the permit's meaning and identity, not of a counter this pure
 * layer could keep. A consumer must record consumed `permitId`s and refuse a
 * repeat; this function tells it whether a permit is *valid*, never whether it
 * is *unused*.
 *
 * Pure, total, and deterministic; never throws.
 */
export function permitAuthorizes(
  permit: ExecutionPermit,
  job: RepairJobAuthorization,
  request: JobOperationRequest,
): boolean {
  const decision = authorizeJobOperation(job, request);
  if (!decision.mayExecuteOnce || decision.permit === null) {
    return false;
  }
  return permitsEqual(permit, decision.permit);
}
