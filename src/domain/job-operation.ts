/**
 * Structured repair-job operations (Cockpit C1).
 *
 * A generic action name is **not** sufficient for Cockpit write authority. A
 * request to "write the repository" authorizes nothing, because there is no
 * such operation: every write-shaped operation names the exact operand that
 * makes it decidable — which path, which ref, which worktree, which
 * verification class.
 *
 * This module models and normalizes operations. It decides nothing;
 * `job-authorization.ts` does. Nothing here executes: there is no shell
 * parsing, no command string, no argument vector, no subprocess, no filesystem,
 * and no git.
 *
 * ## Two vocabularies, deliberately disjoint
 *
 * {@link JOB_OPERATION} names what a repair job may *ever* be authorized to do.
 * {@link FORBIDDEN_OPERATION} names what ordinary job authority may *never* do,
 * modeled explicitly so that refusing it is a deterministic decision with a
 * stable reason rather than an accident of falling through to `unknown`.
 *
 * The two are disjoint by construction and the authorizable union is a
 * TypeScript type that does not contain `merge`. An `ExecutionPermit` is typed
 * to carry only a {@link RepairAuthorizableOperation}, so a merge permit does
 * not type-check — the merge barrier is enforced by the type system before any
 * runtime check runs. A test pins the disjointness at runtime as well.
 */

import {
  append,
  containsValue,
  readExactIdentifier,
  readOwnProperty,
  readRepositoryRelativePath,
} from './repair-job.js';

const objectFreeze = Object.freeze;

/**
 * Operations a repair job may be authorized to perform.
 *
 * Each names the operand that makes it decidable. There is deliberately no
 * `repository.write`, no `git.run`, and no `shell.exec`: an operation whose
 * authority cannot be checked against an exact operand has no place here.
 *
 * `repair.change_request` covers creating *or updating* the stacked validation
 * pull request. `change_request` is the provider-neutral name PR 006 already
 * uses for what a given forge calls a pull or merge request.
 */
export const JOB_OPERATION = objectFreeze({
  /** Read one authorized source file inside the repair worktree. */
  SOURCE_READ: 'source.read',
  /** Edit one authorized source file inside the repair worktree. */
  SOURCE_EDIT: 'source.edit',
  /** Run one authorized verification command class in the repair worktree. */
  VERIFICATION_RUN: 'verification.run',
  /** Commit to the authorized repair branch inside the repair worktree. */
  REPAIR_COMMIT: 'repair.commit',
  /** Push the authorized repair branch. Never forced, never another ref. */
  REPAIR_PUSH: 'repair.push',
  /** Create or update the stacked validation change request. */
  REPAIR_CHANGE_REQUEST: 'repair.change_request',
} as const);

export type RepairAuthorizableOperation =
  (typeof JOB_OPERATION)[keyof typeof JOB_OPERATION];

/** Every member of the {@link RepairAuthorizableOperation} union. */
export const REPAIR_AUTHORIZABLE_OPERATIONS: readonly RepairAuthorizableOperation[] =
  objectFreeze([
    JOB_OPERATION.SOURCE_READ,
    JOB_OPERATION.SOURCE_EDIT,
    JOB_OPERATION.VERIFICATION_RUN,
    JOB_OPERATION.REPAIR_COMMIT,
    JOB_OPERATION.REPAIR_PUSH,
    JOB_OPERATION.REPAIR_CHANGE_REQUEST,
  ]);

/**
 * Operations ordinary repair-job authority may never perform.
 *
 * These are modeled rather than left unmodeled on purpose. An unmodeled name
 * fails closed as `unknown`, which is correct but uninformative; naming these
 * makes the refusal explicit, gives it a stable reason code, and makes the
 * mandatory hard denials mechanically testable rather than incidental.
 *
 * **`merge` is the load-bearing member.** It is the only operation anywhere in
 * C1 that resolves to `OPERATOR_REQUIRED` rather than `DENY`, because merge is
 * not forbidden — it is *operator-only*. Every other member here is forbidden
 * outright, for a repair job and for an operator alike, at this layer.
 *
 * `auto_merge.enable` is `DENY`, not `OPERATOR_REQUIRED`, and the distinction
 * is deliberate: enabling auto-merge delegates the merge decision away from the
 * human who would otherwise make it at the moment HEAD is final. An operator
 * asking for auto-merge is asking to not be the operator.
 */
export const FORBIDDEN_OPERATION = objectFreeze({
  /** Merge. Operator-only, permanently. */
  MERGE: 'merge',
  /** Enable auto-merge. Delegates the operator's decision; never permitted. */
  AUTO_MERGE_ENABLE: 'auto_merge.enable',
  /** Direct mutation of the protected parent ref. */
  PARENT_REF_WRITE: 'parent_ref.write',
  /** Force push, to any ref. */
  PUSH_FORCE: 'push.force',
  /** Reset, rebase, amend, or any rewrite of protected integration history. */
  HISTORY_REWRITE: 'history.rewrite',
  /** Deletion of any ref. */
  BRANCH_DELETE: 'branch.delete',
  /** Modification of the policy that governs this envelope. */
  POLICY_MODIFY: 'policy.modify',
  /** Access to secrets, credentials, or tokens. */
  SECRET_ACCESS: 'secret.access',
  /** Deployment of anything, anywhere. */
  DEPLOYMENT_RUN: 'deployment.run',
  /** Mutation of a staging environment. */
  STAGING_CHANGE: 'staging.change',
  /** Mutation of a production environment. */
  PRODUCTION_CHANGE: 'production.change',
  /** Any database write. */
  DATABASE_WRITE: 'database.write',
  /** Any schema migration. */
  DATABASE_MIGRATE: 'database.migrate',
} as const);

export type ForbiddenJobOperation =
  (typeof FORBIDDEN_OPERATION)[keyof typeof FORBIDDEN_OPERATION];

/** Every member of the {@link ForbiddenJobOperation} union. */
export const FORBIDDEN_OPERATIONS: readonly ForbiddenJobOperation[] = objectFreeze([
  FORBIDDEN_OPERATION.MERGE,
  FORBIDDEN_OPERATION.AUTO_MERGE_ENABLE,
  FORBIDDEN_OPERATION.PARENT_REF_WRITE,
  FORBIDDEN_OPERATION.PUSH_FORCE,
  FORBIDDEN_OPERATION.HISTORY_REWRITE,
  FORBIDDEN_OPERATION.BRANCH_DELETE,
  FORBIDDEN_OPERATION.POLICY_MODIFY,
  FORBIDDEN_OPERATION.SECRET_ACCESS,
  FORBIDDEN_OPERATION.DEPLOYMENT_RUN,
  FORBIDDEN_OPERATION.STAGING_CHANGE,
  FORBIDDEN_OPERATION.PRODUCTION_CHANGE,
  FORBIDDEN_OPERATION.DATABASE_WRITE,
  FORBIDDEN_OPERATION.DATABASE_MIGRATE,
]);

/** Sentinel for any operation this module does not model. */
export const UNKNOWN_JOB_OPERATION = 'unknown';

export type UnknownJobOperation = typeof UNKNOWN_JOB_OPERATION;

/** Every operation name that can be resolved, including the unknown sentinel. */
export type JobOperation =
  | RepairAuthorizableOperation
  | ForbiddenJobOperation
  | UnknownJobOperation;

/**
 * Membership is backed by a `Map`, not a plain object.
 *
 * A plain-object lookup inherits `Object.prototype`, so `'toString'`,
 * `'constructor'`, and `'__proto__'` would resolve to a truthy entry. A `Map`
 * has no prototype chain for keys. Same reasoning as PR 002's taxonomy.
 */
const OPERATION_LOOKUP: ReadonlyMap<string, RepairAuthorizableOperation | ForbiddenJobOperation> =
  new Map<string, RepairAuthorizableOperation | ForbiddenJobOperation>([
    ...REPAIR_AUTHORIZABLE_OPERATIONS.map(
      (operation) => [operation, operation] as const,
    ),
    ...FORBIDDEN_OPERATIONS.map((operation) => [operation, operation] as const),
  ]);

/**
 * Resolve an untrusted operation name to a modeled member.
 *
 * Matching is exact and case-sensitive. No trimming, case folding, aliasing, or
 * fuzzy matching, because lenient matching on a security boundary is a
 * privilege-escalation vector: `'SOURCE.EDIT '` must not become `source.edit`.
 *
 * Anything unrecognised resolves to {@link UNKNOWN_JOB_OPERATION}, including
 * the literal string `'unknown'` — the sentinel names the absence of a model,
 * so requesting it by name is still an unmodeled request. Never throws.
 */
export function resolveJobOperation(value: unknown): JobOperation {
  if (typeof value !== 'string') {
    return UNKNOWN_JOB_OPERATION;
  }
  return OPERATION_LOOKUP.get(value) ?? UNKNOWN_JOB_OPERATION;
}

/** Type guard: is this a modeled operation a repair job may be authorized for? */
export function isRepairAuthorizableOperation(
  value: JobOperation,
): value is RepairAuthorizableOperation {
  return containsValue(REPAIR_AUTHORIZABLE_OPERATIONS, value);
}

/** Type guard: is this a modeled operation ordinary job authority may never do? */
export function isForbiddenJobOperation(value: JobOperation): value is ForbiddenJobOperation {
  return containsValue(FORBIDDEN_OPERATIONS, value);
}

/**
 * An untrusted request to perform one operation under one repair job.
 *
 * Declared shape is advisory: at runtime every property is read defensively and
 * any type may arrive. Properties not listed here are ignored.
 *
 * The binding fields (`jobId`, `repositoryId`, `parentPullRequestId`,
 * `parentHeadSha`) are what the requester *claims* to be operating against.
 * They are never a source of authority: the evaluator compares each to the
 * trusted job envelope and refuses on any mismatch. Their only purpose is to
 * make a request that names the wrong repository, pull request, or commit
 * refusable instead of silently re-targeted at whatever the job says.
 *
 * There is deliberately **no** `agentId`, `providerId`, `rationale`,
 * `metadata`, `approval`, `role`, `priority`, `urgency`, `confidence`, or
 * `override` field. Extra properties carrying such values may be present at
 * runtime and are read by nothing; a test pins that adding them changes no
 * decision byte.
 */
export interface JobOperationRequest {
  /** Caller-minted identity for this one execution attempt. */
  readonly requestId?: string;
  /** Claimed job. Must match the trusted envelope exactly. */
  readonly jobId?: string;
  /** Claimed repository. Must match the trusted envelope exactly. */
  readonly repositoryId?: string;
  /** Claimed parent pull request. Must match the trusted envelope exactly. */
  readonly parentPullRequestId?: string;
  /** Claimed parent HEAD. Must match the trusted envelope exactly. */
  readonly parentHeadSha?: string;
  /** Operation name. Resolved exactly; anything unmodeled becomes `unknown`. */
  readonly operation?: string;
  /** Worktree operand, for filesystem-shaped operations. */
  readonly worktreeId?: string;
  /** Path operand, for `source.read` and `source.edit`. */
  readonly path?: string;
  /** Verification class operand, for `verification.run`. */
  readonly commandClass?: string;
  /** Ref operand, for `repair.commit` and `repair.push`. */
  readonly ref?: string;
  /** Change-request source ref operand. */
  readonly sourceRef?: string;
  /** Change-request target ref operand. */
  readonly targetRef?: string;
  /** Force flag for a push. Anything that is not exactly absent or `false` is force. */
  readonly force?: boolean;
}

/**
 * A frozen, single-read snapshot of one operation request.
 *
 * Every security-relevant property is read exactly once, own-only, guarded, and
 * narrowed, and everything downstream reads only this snapshot. A getter or
 * Proxy that returns a different value on each access therefore cannot validate
 * one operand and have another reach the decision or the permit.
 */
export interface NormalizedJobOperation {
  /** False when the request itself could not be read as an object. */
  readonly readable: boolean;
  readonly requestId: string | null;
  readonly jobId: string | null;
  readonly repositoryId: string | null;
  readonly parentPullRequestId: string | null;
  readonly parentHeadSha: string | null;
  readonly operation: JobOperation;
  readonly worktreeId: string | null;
  readonly path: string | null;
  /** True when a `path` was supplied but did not survive path validation. */
  readonly pathMalformed: boolean;
  readonly commandClass: string | null;
  readonly ref: string | null;
  readonly sourceRef: string | null;
  readonly targetRef: string | null;
  /** Fails closed: only an absent or literally `false` value is not force. */
  readonly force: boolean;
}

const UNREADABLE_OPERATION: NormalizedJobOperation = objectFreeze({
  readable: false,
  requestId: null,
  jobId: null,
  repositoryId: null,
  parentPullRequestId: null,
  parentHeadSha: null,
  operation: UNKNOWN_JOB_OPERATION,
  worktreeId: null,
  path: null,
  pathMalformed: false,
  commandClass: null,
  ref: null,
  sourceRef: null,
  targetRef: null,
  force: true,
});

/**
 * Read a force flag, failing closed.
 *
 * Absent or literally `false` is not a force. **Everything else is**, including
 * `0`, `''`, `null`, `'false'`, and an object — a value that cannot be read as
 * "definitely not forced" is treated as forced, and forced pushes are denied
 * unconditionally.
 */
function readForceFlag(value: unknown): boolean {
  return !(value === undefined || value === false);
}

/**
 * Normalize an untrusted operation request into a frozen snapshot.
 *
 * Pure, total, and deterministic; never throws. A non-object request, a revoked
 * Proxy, a throwing getter, or a payload of the wrong types all yield a
 * snapshot that authorizes nothing rather than an exception.
 */
export function readJobOperation(request: JobOperationRequest): NormalizedJobOperation {
  const record: unknown = request;
  if (typeof record !== 'object' || record === null) {
    return UNREADABLE_OPERATION;
  }

  const rawPath = readOwnProperty(record, 'path');
  const path = readRepositoryRelativePath(rawPath);

  return objectFreeze({
    readable: true,
    requestId: readExactIdentifier(readOwnProperty(record, 'requestId')),
    jobId: readExactIdentifier(readOwnProperty(record, 'jobId')),
    repositoryId: readExactIdentifier(readOwnProperty(record, 'repositoryId')),
    parentPullRequestId: readExactIdentifier(readOwnProperty(record, 'parentPullRequestId')),
    parentHeadSha: readExactIdentifier(readOwnProperty(record, 'parentHeadSha')),
    operation: resolveJobOperation(readOwnProperty(record, 'operation')),
    worktreeId: readExactIdentifier(readOwnProperty(record, 'worktreeId')),
    path,
    pathMalformed: path === null && rawPath !== undefined,
    commandClass: readExactIdentifier(readOwnProperty(record, 'commandClass')),
    ref: readExactIdentifier(readOwnProperty(record, 'ref')),
    sourceRef: readExactIdentifier(readOwnProperty(record, 'sourceRef')),
    targetRef: readExactIdentifier(readOwnProperty(record, 'targetRef')),
    force: readForceFlag(readOwnProperty(record, 'force')),
  });
}

/**
 * The operands an issued permit carries.
 *
 * Every field an operation does not define is `null`, so an unused operand
 * cannot ride along into execution. A `source.read` request that also carries a
 * `ref` naming the protected parent produces a permit whose `ref` is `null`:
 * the executor is bound to the permit, and the permit contains only what its
 * operation means.
 *
 * `force` is present and always `false` in an issued permit. It is kept rather
 * than dropped so that "this permit does not authorize a force push" is a
 * value an auditor can read, not an absence they must infer.
 */
export interface PermitOperands {
  readonly worktreeId: string | null;
  readonly path: string | null;
  readonly commandClass: string | null;
  readonly ref: string | null;
  readonly sourceRef: string | null;
  readonly targetRef: string | null;
  readonly force: false;
}

/** Every operand field, in a fixed order, for deterministic comparison. */
export const PERMIT_OPERAND_ORDER = objectFreeze([
  'worktreeId',
  'path',
  'commandClass',
  'ref',
  'sourceRef',
  'targetRef',
] as const);

const NO_OPERANDS = objectFreeze({
  worktreeId: null,
  path: null,
  commandClass: null,
  ref: null,
  sourceRef: null,
  targetRef: null,
  force: false,
} as const);

/**
 * Project the operands one operation actually defines.
 *
 * Called once at permit issue and again on every re-verification, so the two
 * cannot disagree about which operands are part of a permit's identity.
 */
export function projectOperands(
  operation: RepairAuthorizableOperation,
  normalized: NormalizedJobOperation,
): PermitOperands {
  switch (operation) {
    case JOB_OPERATION.SOURCE_READ:
    case JOB_OPERATION.SOURCE_EDIT:
      return objectFreeze({
        ...NO_OPERANDS,
        worktreeId: normalized.worktreeId,
        path: normalized.path,
      });
    case JOB_OPERATION.VERIFICATION_RUN:
      return objectFreeze({
        ...NO_OPERANDS,
        worktreeId: normalized.worktreeId,
        commandClass: normalized.commandClass,
      });
    case JOB_OPERATION.REPAIR_COMMIT:
      return objectFreeze({
        ...NO_OPERANDS,
        worktreeId: normalized.worktreeId,
        ref: normalized.ref,
      });
    case JOB_OPERATION.REPAIR_PUSH:
      return objectFreeze({ ...NO_OPERANDS, ref: normalized.ref });
    case JOB_OPERATION.REPAIR_CHANGE_REQUEST:
      return objectFreeze({
        ...NO_OPERANDS,
        sourceRef: normalized.sourceRef,
        targetRef: normalized.targetRef,
      });
  }
}

/**
 * The operand values of a permit, in {@link PERMIT_OPERAND_ORDER} order.
 *
 * A `null` operand becomes the empty string. No reader on this boundary ever
 * returns an empty string — blank values are rejected — so the empty string
 * unambiguously means "not part of this operation".
 */
export function operandValues(operands: PermitOperands): readonly string[] {
  const values: string[] = [];
  append(values, operands.worktreeId ?? '');
  append(values, operands.path ?? '');
  append(values, operands.commandClass ?? '');
  append(values, operands.ref ?? '');
  append(values, operands.sourceRef ?? '');
  append(values, operands.targetRef ?? '');
  return objectFreeze(values);
}
