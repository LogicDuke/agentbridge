import { describe, expect, it, vi } from 'vitest';

import {
  APPROVAL_STATE,
  authorizeJobOperation,
  FORBIDDEN_OPERATION,
  FORBIDDEN_OPERATIONS,
  INVOCATION_BOUNDS,
  isForbiddenJobOperation,
  isRepairAuthorizableOperation,
  JOB_AUTHORIZATION,
  JOB_AUTHORIZATION_REASON,
  JOB_BOUNDS,
  JOB_OPERATION,
  operatorMergeAuthorizes,
  readCanonicalBranchRef,
  readJobOperation,
  REPAIR_AUTHORIZABLE_OPERATIONS,
  resolveJobOperation,
  satisfiesIndependentValidator,
  UNKNOWN_JOB_OPERATION,
  findInvalidRepairJobFields,
  readRepairJobAuthorization,
  type ApprovalRecord,
  type JobOperationRequest,
  type OperatorMergeAuthorization,
  type RepairJobAuthorization,
  type ValidatorClaim,
  type VerificationCommandClass,
} from '../../src/domain/index.js';
import {
  AUTHORIZED_PATH,
  buildEdit,
  buildJob,
  buildPush,
  buildRequest,
  HEAD_A,
  HEAD_B,
  HOSTILE_REQUEST_FIELDS,
  NON_OBJECTS,
  PARENT_PR_A,
  PARENT_REF,
  PARENT_REF_ALIASES,
  PRIVILEGED_LABELS,
  REPAIR_BRANCH,
  REPAIR_WORKTREE,
  REPO_A,
  revokedProxy,
  throwingRecord,
  unstableRecord,
  UNAUTHORIZED_PATH,
  withPrototypePollution,
} from './repair-job-fixtures.js';

/* -------------------------------------------------------------------------
 * The merge barrier
 * ------------------------------------------------------------------------- */

describe('merge is operator-only, permanently', () => {
  it('answers OPERATOR_REQUIRED for merge and issues no permit', () => {
    const decision = authorizeJobOperation(
      buildJob(),
      buildRequest({ operation: FORBIDDEN_OPERATION.MERGE }),
    );

    expect(decision.decision).toBe(JOB_AUTHORIZATION.OPERATOR_REQUIRED);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.MERGE_IS_OPERATOR_ONLY);
    expect(decision.mayExecuteOnce).toBe(false);
    expect(decision.permit).toBeNull();
  });

  it('denies auto-merge outright, which is a stronger answer than OPERATOR_REQUIRED', () => {
    const decision = authorizeJobOperation(
      buildJob(),
      buildRequest({ operation: FORBIDDEN_OPERATION.AUTO_MERGE_ENABLE }),
    );

    // Auto-merge delegates the operator's decision away from the moment HEAD is
    // final, so there is no operator path to it either.
    expect(decision.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.OPERATION_FORBIDDEN);
    expect(decision.permit).toBeNull();
  });

  it('refuses merge under every job, operand, and label permutation', () => {
    const jobs: readonly RepairJobAuthorization[] = [
      buildJob(),
      buildJob({ repairAgentId: 'root', independentValidatorId: 'system' }),
      buildJob({ findingSource: 'agentbridge-internal' }),
      buildJob({ authorizedPaths: [], authorizedCommandClasses: [] }),
      buildJob({ protectedParentRef: 'refs/heads/main' }),
      buildJob({ repairBranch: 'refs/heads/main', protectedParentRef: 'refs/heads/main' }),
    ];
    const operands: readonly Partial<JobOperationRequest>[] = [
      {},
      { ref: PARENT_REF },
      { ref: REPAIR_BRANCH },
      { sourceRef: REPAIR_BRANCH, targetRef: PARENT_REF },
      { worktreeId: REPAIR_WORKTREE, path: AUTHORIZED_PATH },
      { force: true },
      { force: false },
    ];

    for (const job of jobs) {
      for (const operand of operands) {
        for (const label of PRIVILEGED_LABELS) {
          const request = {
            ...buildRequest({ operation: FORBIDDEN_OPERATION.MERGE, ...operand }),
            ...HOSTILE_REQUEST_FIELDS,
            agentId: label,
            providerId: label,
          } as unknown as JobOperationRequest;
          const decision = authorizeJobOperation(job, request);

          expect(decision.decision, label).toBe(JOB_AUTHORIZATION.OPERATOR_REQUIRED);
          expect(decision.mayExecuteOnce, label).toBe(false);
          expect(decision.permit, label).toBeNull();
        }
      }
    }
  });

  it('has no authorizable operation that is a forbidden one', () => {
    for (const operation of REPAIR_AUTHORIZABLE_OPERATIONS) {
      expect(FORBIDDEN_OPERATIONS, operation).not.toContain(operation);
      expect(isForbiddenJobOperation(operation), operation).toBe(false);
    }
    for (const operation of FORBIDDEN_OPERATIONS) {
      expect(REPAIR_AUTHORIZABLE_OPERATIONS, operation).not.toContain(operation);
      expect(isRepairAuthorizableOperation(operation), operation).toBe(false);
    }
  });

  it('never allows any operation that is forbidden by name', () => {
    for (const operation of FORBIDDEN_OPERATIONS) {
      const decision = authorizeJobOperation(buildJob(), buildRequest({ operation }));

      expect(decision.decision, operation).not.toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
      expect(decision.mayExecuteOnce, operation).toBe(false);
      expect(decision.permit, operation).toBeNull();
    }
  });

  it('mentions merge in the operation vocabulary but never in a permit type', () => {
    // The type-level half of the barrier: ExecutionPermit.operation is a
    // RepairAuthorizableOperation, so this does not compile.
    //
    // @ts-expect-error merge is not a repair-authorizable operation
    const merge: (typeof REPAIR_AUTHORIZABLE_OPERATIONS)[number] = 'merge';
    expect(merge).toBe('merge');
  });

  it('cannot be turned into job authority by a human ApprovalRecord', () => {
    // `authorizeJobOperation` has no approval parameter, so the only way to try
    // is to smuggle one through the request. It is read by nothing.
    const approval: ApprovalRecord = {
      requestId: 'req-0001',
      state: APPROVAL_STATE.APPROVED,
      decidedBy: 'operator',
      decidedAt: '2026-08-14T00:00:00Z',
    };
    const plain = authorizeJobOperation(
      buildJob(),
      buildRequest({ operation: FORBIDDEN_OPERATION.MERGE }),
    );
    const withApproval = authorizeJobOperation(
      buildJob(),
      {
        ...buildRequest({ operation: FORBIDDEN_OPERATION.MERGE }),
        approval,
        approvalState: APPROVAL_STATE.APPROVED,
        approved: true,
      } as unknown as JobOperationRequest,
    );

    expect(withApproval).toEqual(plain);
    expect(withApproval.decision).toBe(JOB_AUTHORIZATION.OPERATOR_REQUIRED);
    expect(withApproval.permit).toBeNull();
    expect(authorizeJobOperation).toHaveLength(2);
  });

  it('cannot be reached by an ordinarily forbidden operation carrying an approval', () => {
    const forbidden = [
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
    ];

    for (const operation of forbidden) {
      const decision = authorizeJobOperation(
        buildJob(),
        {
          ...buildRequest({ operation }),
          ...HOSTILE_REQUEST_FIELDS,
        } as unknown as JobOperationRequest,
      );

      expect(decision.decision, operation).toBe(JOB_AUTHORIZATION.DENY);
      expect(decision.reason, operation).toBe(JOB_AUTHORIZATION_REASON.OPERATION_FORBIDDEN);
      expect(decision.permit, operation).toBeNull();
    }
  });

  it('never produces an operator merge authorization from job authority', () => {
    const decision = authorizeJobOperation(buildJob(), buildEdit());
    const serialized = JSON.stringify(decision);

    for (const key of ['authorizationId', 'operatorId', 'merge', 'mergeable', 'readyForMerge']) {
      expect(serialized, key).not.toContain(key);
    }
  });
});

describe('operator merge authorization is separate, exact, and structurally single-use', () => {
  const authorization: OperatorMergeAuthorization = {
    authorizationId: 'op-merge-1',
    operatorId: 'human-operator-1',
    repositoryId: REPO_A,
    pullRequestId: PARENT_PR_A,
    headSha: HEAD_A,
    authorizedAt: '2026-08-14T00:00:00Z',
    singleUse: true,
  };

  it('covers exactly the repository, pull request, and HEAD it names', () => {
    expect(
      operatorMergeAuthorizes(authorization, {
        repositoryId: REPO_A,
        pullRequestId: PARENT_PR_A,
        currentHeadSha: HEAD_A,
      }),
    ).toBe(true);
  });

  it('stops matching once a different target SHA is supplied', () => {
    expect(
      operatorMergeAuthorizes(authorization, {
        repositoryId: REPO_A,
        pullRequestId: PARENT_PR_A,
        currentHeadSha: HEAD_B,
      }),
    ).toBe(false);
  });

  it('cannot authorize another pull request or another repository', () => {
    expect(
      operatorMergeAuthorizes(authorization, {
        repositoryId: REPO_A,
        pullRequestId: '43',
        currentHeadSha: HEAD_A,
      }),
    ).toBe(false);
    expect(
      operatorMergeAuthorizes(authorization, {
        repositoryId: 'github.com/other/repo',
        pullRequestId: PARENT_PR_A,
        currentHeadSha: HEAD_A,
      }),
    ).toBe(false);
  });

  it('refuses an authorization that is not structurally single-use', () => {
    const widened = { ...authorization, singleUse: false } as unknown as OperatorMergeAuthorization;

    expect(
      operatorMergeAuthorizes(widened, {
        repositoryId: REPO_A,
        pullRequestId: PARENT_PR_A,
        currentHeadSha: HEAD_A,
      }),
    ).toBe(false);
  });

  // The next two tests pin what C1 deliberately does NOT prove, so that the
  // documented limitation cannot drift away from the implementation. They are
  // not a statement that this behaviour is desirable forever: the future trusted
  // operator boundary / merge broker must supersede both, and when it does these
  // tests are expected to be replaced rather than preserved.
  it('accepts a plain caller-written literal: it proves binding, not operator origin', () => {
    const callerWritten = {
      authorizationId: 'assembled-by-any-caller',
      operatorId: 'not-authenticated-just-a-string',
      repositoryId: REPO_A,
      pullRequestId: PARENT_PR_A,
      headSha: HEAD_A,
      authorizedAt: 'caller-supplied',
      singleUse: true,
    } as const;

    expect(
      operatorMergeAuthorizes(callerWritten, {
        repositoryId: REPO_A,
        pullRequestId: PARENT_PR_A,
        currentHeadSha: HEAD_A,
      }),
    ).toBe(true);
  });

  it('returns true repeatedly for the same record: C1 has no consumed-capability store', () => {
    const target = {
      repositoryId: REPO_A,
      pullRequestId: PARENT_PR_A,
      currentHeadSha: HEAD_A,
    };

    expect([
      operatorMergeAuthorizes(authorization, target),
      operatorMergeAuthorizes(authorization, target),
      operatorMergeAuthorizes(authorization, target),
    ]).toEqual([true, true, true]);
  });

  it('fails closed on hostile input without throwing', () => {
    for (const value of NON_OBJECTS) {
      expect(() =>
        operatorMergeAuthorizes(value as OperatorMergeAuthorization, {
          repositoryId: REPO_A,
          pullRequestId: PARENT_PR_A,
          currentHeadSha: HEAD_A,
        }),
      ).not.toThrow();
      expect(
        operatorMergeAuthorizes(value as OperatorMergeAuthorization, {
          repositoryId: REPO_A,
          pullRequestId: PARENT_PR_A,
          currentHeadSha: HEAD_A,
        }),
      ).toBe(false);
    }

    expect(
      operatorMergeAuthorizes(
        throwingRecord(['authorizationId', 'operatorId', 'repositoryId', 'headSha']) as unknown as OperatorMergeAuthorization,
        { repositoryId: REPO_A, pullRequestId: PARENT_PR_A, currentHeadSha: HEAD_A },
      ),
    ).toBe(false);
    expect(
      operatorMergeAuthorizes(revokedProxy() as unknown as OperatorMergeAuthorization, {
        repositoryId: REPO_A,
        pullRequestId: PARENT_PR_A,
        currentHeadSha: HEAD_A,
      }),
    ).toBe(false);
  });
});

/* -------------------------------------------------------------------------
 * Identity, prose, and metadata are inert
 * ------------------------------------------------------------------------- */

describe('nothing an agent controls can increase authority', () => {
  it('produces a byte-identical decision with and without hostile fields', () => {
    const clean = authorizeJobOperation(buildJob(), buildEdit());
    const hostile = authorizeJobOperation(
      buildJob(),
      { ...buildEdit(), ...HOSTILE_REQUEST_FIELDS } as unknown as JobOperationRequest,
    );

    expect(JSON.stringify(hostile)).toBe(JSON.stringify(clean));
  });

  it('does not let hostile fields rescue an out-of-scope edit', () => {
    const decision = authorizeJobOperation(
      buildJob(),
      {
        ...buildEdit({ path: UNAUTHORIZED_PATH }),
        ...HOSTILE_REQUEST_FIELDS,
      } as unknown as JobOperationRequest,
    );

    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED);
    expect(decision.permit).toBeNull();
  });

  it('is unchanged by a privileged-sounding repair agent or finding source', () => {
    const baseline = authorizeJobOperation(buildJob(), buildEdit());

    for (const label of PRIVILEGED_LABELS) {
      const job = buildJob({
        repairAgentId: label,
        findingSource: label,
        independentValidatorId: `${label}-validator`,
      });
      const decision = authorizeJobOperation(job, buildEdit());

      expect(decision.decision, label).toBe(baseline.decision);
      expect(decision.permit?.permitId, label).toBe(baseline.permit?.permitId);
    }
  });

  it('is unchanged by a privileged-sounding requester label on a denied operation', () => {
    const baseline = authorizeJobOperation(buildJob(), buildEdit({ path: UNAUTHORIZED_PATH }));

    for (const label of PRIVILEGED_LABELS) {
      const decision = authorizeJobOperation(
        buildJob(),
        {
          ...buildEdit({ path: UNAUTHORIZED_PATH }),
          agentId: label,
          providerId: label,
          actorId: label,
          role: label,
        } as unknown as JobOperationRequest,
      );

      expect(JSON.stringify(decision), label).toBe(JSON.stringify(baseline));
    }
  });

  it('never widens file or command scope from the request', () => {
    // The request claims a wider scope than the job configures. The job wins.
    const decision = authorizeJobOperation(
      buildJob({ authorizedPaths: [], authorizedCommandClasses: [] }),
      {
        ...buildEdit(),
        authorizedPaths: [AUTHORIZED_PATH, UNAUTHORIZED_PATH, '**'],
        authorizedCommandClasses: ['test', 'lint', 'typecheck', 'build', 'audit'],
        scope: '**',
      } as unknown as JobOperationRequest,
    );

    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED);
    expect(decision.permit).toBeNull();
  });

  it('never lets a request rewrite the protected parent or repair branch', () => {
    const decision = authorizeJobOperation(
      buildJob(),
      {
        ...buildPush({ ref: PARENT_REF }),
        protectedParentRef: 'some-other-ref',
        repairBranch: PARENT_REF,
      } as unknown as JobOperationRequest,
    );

    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.PROTECTED_REF_MUTATION);
  });
});

describe('the independent-validator constraint', () => {
  it('is satisfied only by the configured validator identity', () => {
    expect(satisfiesIndependentValidator(buildJob(), { validatorId: 'validator-1' })).toBe(true);
  });

  it('is not satisfied by the repair agent claiming another role or provider', () => {
    const job = buildJob();
    const claims: readonly ValidatorClaim[] = [
      { validatorId: 'repair-agent-1' },
      { validatorId: 'repair-agent-1', role: 'independent-validator' },
      { validatorId: 'repair-agent-1', providerId: 'coderabbit' },
      { validatorId: 'repair-agent-1', role: 'validator', providerId: 'agentbridge-internal' },
      { role: 'independent-validator' },
      { role: 'validator-1' },
      { providerId: 'validator-1' },
      {},
    ];

    for (const claim of claims) {
      expect(satisfiesIndependentValidator(job, claim), JSON.stringify(claim)).toBe(false);
    }
  });

  it('is not satisfied by a privileged-sounding label', () => {
    for (const label of PRIVILEGED_LABELS) {
      expect(
        satisfiesIndependentValidator(buildJob(), { validatorId: label, role: label }),
        label,
      ).toBe(false);
    }
  });

  it('cannot be satisfied at all when the job is invalid', () => {
    const job = buildJob({ independentValidatorId: 'repair-agent-1' });

    expect(satisfiesIndependentValidator(job, { validatorId: 'repair-agent-1' })).toBe(false);
  });

  it('fails closed on hostile claims without throwing', () => {
    for (const claim of NON_OBJECTS) {
      expect(() =>
        satisfiesIndependentValidator(buildJob(), claim as ValidatorClaim),
      ).not.toThrow();
      expect(satisfiesIndependentValidator(buildJob(), claim as ValidatorClaim)).toBe(
        false,
      );
    }
    expect(
      satisfiesIndependentValidator(
        buildJob(),
        throwingRecord(['validatorId']) as unknown as ValidatorClaim,
      ),
    ).toBe(false);
  });
});

/* -------------------------------------------------------------------------
 * Hostile runtime
 * ------------------------------------------------------------------------- */

describe('hostile runtime input fails closed without throwing', () => {
  it('survives a non-object job or request', () => {
    for (const value of NON_OBJECTS) {
      expect(() =>
        authorizeJobOperation(value as RepairJobAuthorization, buildEdit()),
      ).not.toThrow();
      expect(
        authorizeJobOperation(value as RepairJobAuthorization, buildEdit())
          .mayExecuteOnce,
      ).toBe(false);

      expect(() =>
        authorizeJobOperation(buildJob(), value as JobOperationRequest),
      ).not.toThrow();
      expect(
        authorizeJobOperation(buildJob(), value as JobOperationRequest).mayExecuteOnce,
      ).toBe(false);
    }
  });

  it('survives throwing getters on every field of both arguments', () => {
    const jobKeys = [
      'jobId',
      'policyVersion',
      'repositoryId',
      'parentPullRequestId',
      'protectedParentRef',
      'parentHeadSha',
      'findingSource',
      'findingId',
      'findingHeadSha',
      'repairBranch',
      'repairWorktreeId',
      'authorizedPaths',
      'authorizedCommandClasses',
      'repairAgentId',
      'independentValidatorId',
    ];
    const requestKeys = [
      'requestId',
      'jobId',
      'repositoryId',
      'parentPullRequestId',
      'parentHeadSha',
      'operation',
      'worktreeId',
      'path',
      'commandClass',
      'ref',
      'sourceRef',
      'targetRef',
      'force',
    ];

    expect(() =>
      authorizeJobOperation(throwingRecord(jobKeys) as unknown as RepairJobAuthorization, buildEdit()),
    ).not.toThrow();
    expect(
      authorizeJobOperation(
        throwingRecord(jobKeys) as unknown as RepairJobAuthorization,
        buildEdit(),
      ).mayExecuteOnce,
    ).toBe(false);

    expect(() =>
      authorizeJobOperation(buildJob(), throwingRecord(requestKeys) as unknown as JobOperationRequest),
    ).not.toThrow();
    expect(
      authorizeJobOperation(buildJob(), throwingRecord(requestKeys) as unknown as JobOperationRequest)
        .mayExecuteOnce,
    ).toBe(false);
  });

  it('survives a revoked Proxy as either argument', () => {
    expect(() =>
      authorizeJobOperation(revokedProxy() as unknown as RepairJobAuthorization, buildEdit()),
    ).not.toThrow();
    expect(() =>
      authorizeJobOperation(buildJob(), revokedProxy() as unknown as JobOperationRequest),
    ).not.toThrow();
    expect(
      authorizeJobOperation(buildJob(), revokedProxy() as unknown as JobOperationRequest)
        .mayExecuteOnce,
    ).toBe(false);
  });

  it('survives a revoked Proxy as the authorized path list', () => {
    const job = buildJob({
      authorizedPaths: revokedProxy() as unknown as readonly string[],
    });

    expect(() => authorizeJobOperation(job, buildEdit())).not.toThrow();
    expect(authorizeJobOperation(job, buildEdit()).reason).toBe(
      JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID,
    );
  });

  it('survives an array-like Proxy whose length is hostile', () => {
    const hostile = new Proxy([AUTHORIZED_PATH], {
      get(target, key, receiver): unknown {
        if (key === 'length') {
          return Number.MAX_SAFE_INTEGER;
        }
        return Reflect.get(target, key, receiver);
      },
    });
    const job = buildJob({ authorizedPaths: hostile });

    expect(() => authorizeJobOperation(job, buildEdit())).not.toThrow();
    expect(authorizeJobOperation(job, buildEdit()).mayExecuteOnce).toBe(false);
  });
});

describe('a value read twice cannot differ between validation and use', () => {
  it('reads each request operand exactly once', () => {
    // The path reads as authorized first and as an escape afterwards. A
    // boundary that validated one read and used another would authorize
    // `../../etc/passwd`.
    const request = unstableRecord({ ...buildEdit() }, 'path', [
      AUTHORIZED_PATH,
      '../../etc/passwd',
      '../../etc/passwd',
    ]) as unknown as JobOperationRequest;

    const decision = authorizeJobOperation(buildJob(), request);

    // Whatever the first read returned is the value that was both validated and
    // written into the permit. The two can never diverge.
    expect(decision.permit?.operands.path).toBe(AUTHORIZED_PATH);
    expect(decision.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);

    const normalized = readJobOperation(
      unstableRecord({ ...buildEdit() }, 'path', [
        AUTHORIZED_PATH,
        '../../etc/passwd',
      ]) as unknown as JobOperationRequest,
    );
    expect(normalized.path).toBe(AUTHORIZED_PATH);
    // Re-reading the frozen snapshot always answers the same way.
    expect(normalized.path).toBe(AUTHORIZED_PATH);
  });

  it('reads the ref exactly once, so a push cannot be validated then redirected', () => {
    const request = unstableRecord({ ...buildPush() }, 'ref', [
      REPAIR_BRANCH,
      PARENT_REF,
      PARENT_REF,
    ]) as unknown as JobOperationRequest;

    const decision = authorizeJobOperation(buildJob(), request);

    expect(decision.permit?.operands.ref).toBe(REPAIR_BRANCH);
    expect(decision.permit?.operands.ref).not.toBe(PARENT_REF);
  });

  it('reads the job envelope into a snapshot, so a later read cannot widen it', () => {
    // `authorizedPaths` reads as a narrow list first and a wide one afterwards.
    const job = unstableRecord({ ...buildJob() }, 'authorizedPaths', [
      [AUTHORIZED_PATH],
      [AUTHORIZED_PATH, UNAUTHORIZED_PATH],
      [AUTHORIZED_PATH, UNAUTHORIZED_PATH],
    ]) as unknown as RepairJobAuthorization;

    const decision = authorizeJobOperation(job, buildEdit({ path: UNAUTHORIZED_PATH }));

    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED);
    expect(decision.permit).toBeNull();
  });

  it('copies the authorized path list, so mutating the caller’s array changes nothing', () => {
    const paths = [AUTHORIZED_PATH];
    const job = buildJob({ authorizedPaths: paths });
    const before = authorizeJobOperation(job, buildEdit({ path: UNAUTHORIZED_PATH }));

    paths.push(UNAUTHORIZED_PATH);
    const after = authorizeJobOperation(job, buildEdit({ path: UNAUTHORIZED_PATH }));

    // The snapshot is taken per call, so this one does change — the guarantee is
    // that it cannot change *within* a single evaluation, which the unstable
    // getter test above pins. Recorded here so the boundary of the claim is
    // explicit rather than assumed.
    expect(before.reason).toBe(JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED);
    expect(after.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(Object.isFrozen(before.invalidJobFields)).toBe(true);
  });
});

describe('prototype pollution and inherited properties create no authority', () => {
  it('ignores authorization fields planted on Object.prototype', () => {
    const baseline = authorizeJobOperation(buildJob(), buildEdit({ path: UNAUTHORIZED_PATH }));

    const polluted = withPrototypePollution(
      {
        path: AUTHORIZED_PATH,
        worktreeId: REPAIR_WORKTREE,
        ref: REPAIR_BRANCH,
        operation: 'source.edit',
        force: false,
        authorizedPaths: [UNAUTHORIZED_PATH],
        mayExecuteOnce: true,
        singleUse: true,
      },
      () => authorizeJobOperation(buildJob(), buildEdit({ path: UNAUTHORIZED_PATH })),
    );

    expect(JSON.stringify(polluted)).toBe(JSON.stringify(baseline));
  });

  it('does not let an inherited operand supply a missing own one', () => {
    // The request has no own `path` at all; every value would have to come from
    // the prototype.
    const request = buildRequest({ operation: 'source.edit', worktreeId: REPAIR_WORKTREE });

    const polluted = withPrototypePollution({ path: AUTHORIZED_PATH }, () =>
      authorizeJobOperation(buildJob(), request),
    );

    expect(polluted.mayExecuteOnce).toBe(false);
    expect(polluted.reason).toBe(JOB_AUTHORIZATION_REASON.OPERAND_MISSING);
  });

  it('does not let an inherited job field supply a missing own one', () => {
    const job: Record<string, unknown> = { ...buildJob() };
    delete job['repairWorktreeId'];

    const polluted = withPrototypePollution({ repairWorktreeId: REPAIR_WORKTREE }, () =>
      authorizeJobOperation(job as unknown as RepairJobAuthorization, buildEdit()),
    );

    expect(polluted.reason).toBe(JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID);
    expect(polluted.invalidJobFields).toContain('repairWorktreeId');
  });

  it('does not resolve a prototype-shaped operation name', () => {
    for (const operation of ['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']) {
      const decision = authorizeJobOperation(buildJob(), buildEdit({ operation }));

      expect(decision.reason, operation).toBe(JOB_AUTHORIZATION_REASON.OPERATION_UNKNOWN);
    }
  });

  it('is unaffected by prototype-shaped keys on the request', () => {
    const baseline = authorizeJobOperation(buildJob(), buildEdit());

    for (const key of ['__proto__', 'constructor', 'prototype', 'toString', 'valueOf']) {
      const decision = authorizeJobOperation(
        buildJob(),
        { ...buildEdit(), [key]: 'polluted' } as unknown as JobOperationRequest,
      );

      expect(JSON.stringify(decision), key).toBe(JSON.stringify(baseline));
    }
  });
});

/* -------------------------------------------------------------------------
 * Hostile mutation of the runtime itself
 * ------------------------------------------------------------------------- */

/**
 * Run `body` with `Map.prototype.get` replaced by one that answers
 * `'source.edit'` to everything, then restore the captured descriptor.
 *
 * `source.edit` is the payload precisely because it is the canonical *allowed*
 * operation: if operation resolution consults a poisonable container method,
 * every forbidden and unmodeled name collapses onto the one operation an
 * ordinary repair job is authorized to perform.
 *
 * The original descriptor is captured and restored in a `finally`, so a failing
 * assertion inside `body` cannot leave the runtime poisoned for another test.
 */
function withPoisonedMapGet<T>(body: () => T): T {
  const saved = Object.getOwnPropertyDescriptor(Map.prototype, 'get');
  Object.defineProperty(Map.prototype, 'get', {
    value: function poisonedGet(): string {
      return JOB_OPERATION.SOURCE_EDIT;
    },
    writable: true,
    configurable: true,
  });
  try {
    return body();
  } finally {
    if (saved === undefined) {
      Reflect.deleteProperty(Map.prototype, 'get');
    } else {
      Object.defineProperty(Map.prototype, 'get', saved);
    }
  }
}

describe('poisoning Map.prototype.get cannot re-resolve an operation', () => {
  it('proves the poisoning is actually in effect', () => {
    // Without this the whole section could pass vacuously, on a runtime that
    // was never hostile in the first place.
    const observed = withPoisonedMapGet(() => new Map<string, string>().get('anything'));

    expect(observed).toBe(JOB_OPERATION.SOURCE_EDIT);
  });

  it('keeps merge resolving to merge', () => {
    const resolved = withPoisonedMapGet(() => resolveJobOperation(FORBIDDEN_OPERATION.MERGE));

    expect(resolved).toBe(FORBIDDEN_OPERATION.MERGE);
  });

  it('keeps auto_merge.enable resolving to auto_merge.enable', () => {
    const resolved = withPoisonedMapGet(() =>
      resolveJobOperation(FORBIDDEN_OPERATION.AUTO_MERGE_ENABLE),
    );

    expect(resolved).toBe(FORBIDDEN_OPERATION.AUTO_MERGE_ENABLE);
  });

  it('keeps an unmodeled operation resolving to unknown', () => {
    const resolved = withPoisonedMapGet(() => resolveJobOperation('shell.exec'));

    expect(resolved).toBe(UNKNOWN_JOB_OPERATION);
  });

  it('keeps source.edit resolving to source.edit', () => {
    const resolved = withPoisonedMapGet(() => resolveJobOperation(JOB_OPERATION.SOURCE_EDIT));

    expect(resolved).toBe(JOB_OPERATION.SOURCE_EDIT);
  });

  it('resolves every modeled operation to itself and nothing else', () => {
    const modeled = [...REPAIR_AUTHORIZABLE_OPERATIONS, ...FORBIDDEN_OPERATIONS];

    const resolved = withPoisonedMapGet(() => modeled.map((o) => resolveJobOperation(o)));

    expect(resolved).toStrictEqual(modeled);
  });

  it('does not let a merge request reach ALLOW_ONCE', () => {
    // The request carries valid `source.edit` operands, so nothing earlier in
    // the evaluator can refuse it on an operand ground. The only thing standing
    // between it and a permit is that `merge` still resolves as `merge`.
    const decision = withPoisonedMapGet(() =>
      authorizeJobOperation(
        buildJob(),
        buildEdit({ operation: FORBIDDEN_OPERATION.MERGE }),
      ),
    );

    expect(decision.operation).toBe(FORBIDDEN_OPERATION.MERGE);
    expect(decision.decision).toBe(JOB_AUTHORIZATION.OPERATOR_REQUIRED);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.MERGE_IS_OPERATOR_ONLY);
    expect(decision.mayExecuteOnce).toBe(false);
    expect(decision.permit).toBeNull();
  });

  it('does not let an auto-merge request reach ALLOW_ONCE', () => {
    const decision = withPoisonedMapGet(() =>
      authorizeJobOperation(
        buildJob(),
        buildEdit({ operation: FORBIDDEN_OPERATION.AUTO_MERGE_ENABLE }),
      ),
    );

    expect(decision.operation).toBe(FORBIDDEN_OPERATION.AUTO_MERGE_ENABLE);
    expect(decision.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.OPERATION_FORBIDDEN);
    expect(decision.mayExecuteOnce).toBe(false);
    expect(decision.permit).toBeNull();
  });

  it('does not let an unmodeled request reach ALLOW_ONCE', () => {
    const decision = withPoisonedMapGet(() =>
      authorizeJobOperation(buildJob(), buildEdit({ operation: 'shell.exec' })),
    );

    expect(decision.operation).toBe(UNKNOWN_JOB_OPERATION);
    expect(decision.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.OPERATION_UNKNOWN);
    expect(decision.mayExecuteOnce).toBe(false);
    expect(decision.permit).toBeNull();
  });

  it('still authorizes a legitimate source.edit under the same poisoning', () => {
    // Fail-closed is not enough on its own: a repair that refused everything
    // would satisfy every assertion above and break the boundary instead.
    const baseline = authorizeJobOperation(buildJob(), buildEdit());
    const poisoned = withPoisonedMapGet(() => authorizeJobOperation(buildJob(), buildEdit()));

    expect(poisoned.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(poisoned.reason).toBe(JOB_AUTHORIZATION_REASON.WITHIN_JOB_ENVELOPE);
    expect(poisoned.mayExecuteOnce).toBe(true);
    expect(JSON.stringify(poisoned)).toBe(JSON.stringify(baseline));
  });

  it('restores Map.prototype.get afterwards', () => {
    withPoisonedMapGet(() => undefined);

    expect(new Map<string, string>([['k', 'v']]).get('k')).toBe('v');
  });
});

/**
 * Build a length-2 array holding `own` at index 0 and a genuine **hole** at 1.
 *
 * `Array.isArray` still answers `true` and `length` is still 2, so every bound
 * and shape check upstream is satisfied; the only thing wrong with index 1 is
 * that nothing ever put an own element there.
 */
function withHoleAtOne(own: string): string[] {
  const sparse: string[] = [];
  sparse[0] = own;
  sparse.length = 2;
  return sparse;
}

/** The same hole, with `victim` reachable at index 1 through a custom prototype. */
function sparseWithInheritedElement(own: string, victim: string): string[] {
  const sparse = withHoleAtOne(own);
  Object.setPrototypeOf(sparse, { 1: victim });
  return sparse;
}

/** Run `body` with `victim` planted at `Array.prototype[1]`, then restore. */
function withArrayPrototypeElement<T>(victim: string, body: () => T): T {
  const saved = Object.getOwnPropertyDescriptor(Array.prototype, 1);
  Object.defineProperty(Array.prototype, 1, {
    value: victim,
    writable: true,
    configurable: true,
    enumerable: false,
  });
  try {
    return body();
  } finally {
    if (saved === undefined) {
      Reflect.deleteProperty(Array.prototype, 1);
    } else {
      Object.defineProperty(Array.prototype, 1, saved);
    }
  }
}

describe('an inherited numeric property cannot become an authorization entry', () => {
  it('proves the custom-prototype setup is actually active', () => {
    // Without this the section could pass vacuously, on an array that was never
    // hostile: the hole must be a hole, and the inherited value must be there.
    const sparse = sparseWithInheritedElement(AUTHORIZED_PATH, UNAUTHORIZED_PATH);

    expect(Array.isArray(sparse)).toBe(true);
    expect(sparse.length).toBe(2);
    expect(Object.hasOwn(sparse, 1)).toBe(false);
    // An ordinary indexed read — the thing the reader must not do — resolves it.
    expect(sparse[1]).toBe(UNAUTHORIZED_PATH);
  });

  it('rejects an authorized-path list whose hole is filled by a custom prototype', () => {
    const job = buildJob({
      authorizedPaths: sparseWithInheritedElement(AUTHORIZED_PATH, UNAUTHORIZED_PATH),
    });

    expect(readRepairJobAuthorization(job).snapshot).toBeNull();
    expect(findInvalidRepairJobFields(job)).toContain('authorizedPaths');
  });

  it('does not let a custom-prototype path reach ALLOW_ONCE or a permit', () => {
    const job = buildJob({
      authorizedPaths: sparseWithInheritedElement(AUTHORIZED_PATH, UNAUTHORIZED_PATH),
    });

    const decision = authorizeJobOperation(job, buildEdit({ path: UNAUTHORIZED_PATH }));

    expect(decision.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID);
    expect(decision.mayExecuteOnce).toBe(false);
    expect(decision.permit).toBeNull();
    // The fabricated path is nowhere in the answer, not even as an echo.
    expect(JSON.stringify(decision)).not.toContain(UNAUTHORIZED_PATH);
  });

  it('proves the Array.prototype pollution is actually active', () => {
    const observed = withArrayPrototypeElement(UNAUTHORIZED_PATH, () => {
      const sparse = withHoleAtOne(AUTHORIZED_PATH);
      return { own: Object.hasOwn(sparse, 1), read: sparse[1], length: sparse.length };
    });

    expect(observed.own).toBe(false);
    expect(observed.read).toBe(UNAUTHORIZED_PATH);
    expect(observed.length).toBe(2);
  });

  it('rejects an authorized-path list whose hole is filled by Array.prototype', () => {
    const outcome = withArrayPrototypeElement(UNAUTHORIZED_PATH, () => {
      const job = buildJob({ authorizedPaths: withHoleAtOne(AUTHORIZED_PATH) });

      return {
        snapshot: readRepairJobAuthorization(job).snapshot,
        invalidFields: findInvalidRepairJobFields(job),
        decision: authorizeJobOperation(job, buildEdit({ path: UNAUTHORIZED_PATH })),
      };
    });

    expect(outcome.snapshot).toBeNull();
    expect(outcome.invalidFields).toContain('authorizedPaths');
    expect(outcome.decision.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(outcome.decision.reason).toBe(JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID);
    expect(outcome.decision.mayExecuteOnce).toBe(false);
    expect(outcome.decision.permit).toBeNull();
  });

  it('restores Array.prototype afterwards', () => {
    withArrayPrototypeElement(UNAUTHORIZED_PATH, () => undefined);

    expect(Object.hasOwn(Array.prototype, 1)).toBe(false);
    expect(withHoleAtOne(AUTHORIZED_PATH)[1]).toBeUndefined();
  });

  it('does not let an inherited command class enter the trusted snapshot', () => {
    // `test` is a genuine, well-formed verification class. Shape is not the
    // question; nobody put it in this job's list.
    const sparse = sparseWithInheritedElement('lint', 'test');
    const job = buildJob({
      authorizedCommandClasses: sparse as unknown as readonly VerificationCommandClass[],
    });

    expect(Object.hasOwn(sparse, 1)).toBe(false);
    expect(readRepairJobAuthorization(job).snapshot).toBeNull();
    expect(findInvalidRepairJobFields(job)).toContain('authorizedCommandClasses');
  });

  it('does not let an inherited command class gain command-class authority', () => {
    const job = buildJob({
      authorizedCommandClasses: sparseWithInheritedElement(
        'lint',
        'test',
      ) as unknown as readonly VerificationCommandClass[],
    });

    const decision = authorizeJobOperation(
      job,
      buildRequest({
        operation: 'verification.run',
        worktreeId: REPAIR_WORKTREE,
        commandClass: 'test',
      }),
    );

    expect(decision.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(decision.mayExecuteOnce).toBe(false);
    expect(decision.permit).toBeNull();
  });

  it('still accepts dense own lists, and still reaches ALLOW_ONCE inside them', () => {
    const job = buildJob({
      authorizedPaths: [AUTHORIZED_PATH, UNAUTHORIZED_PATH],
      authorizedCommandClasses: ['lint', 'test'],
    });

    expect(findInvalidRepairJobFields(job)).toEqual([]);
    expect(readRepairJobAuthorization(job).snapshot?.authorizedPaths).toEqual([
      AUTHORIZED_PATH,
      UNAUTHORIZED_PATH,
    ]);

    // The same path that had to be refused when it was merely inherited is
    // authorized the moment an operator actually puts it in the list.
    const edit = authorizeJobOperation(job, buildEdit({ path: UNAUTHORIZED_PATH }));
    expect(edit.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(edit.reason).toBe(JOB_AUTHORIZATION_REASON.WITHIN_JOB_ENVELOPE);
    expect(edit.mayExecuteOnce).toBe(true);
    expect(edit.permit).not.toBeNull();

    const verify = authorizeJobOperation(
      job,
      buildRequest({
        operation: 'verification.run',
        worktreeId: REPAIR_WORKTREE,
        commandClass: 'test',
      }),
    );
    expect(verify.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(verify.mayExecuteOnce).toBe(true);
  });

  it('keeps a plain sparse hole failing closed with nothing inherited at all', () => {
    const job = buildJob({ authorizedPaths: withHoleAtOne(AUTHORIZED_PATH) });

    expect(findInvalidRepairJobFields(job)).toContain('authorizedPaths');
    expect(authorizeJobOperation(job, buildEdit()).mayExecuteOnce).toBe(false);
  });

  it('rejects rather than throws when the own check itself is hostile', () => {
    // A Proxy whose `getOwnPropertyDescriptor` trap throws: the own-only read
    // must fail closed, and the entry point must stay total.
    const hostile = new Proxy([AUTHORIZED_PATH, AUTHORIZED_PATH], {
      getOwnPropertyDescriptor(): PropertyDescriptor {
        throw new Error('hostile own-property trap');
      },
    });
    const job = buildJob({ authorizedPaths: hostile });

    expect(() => findInvalidRepairJobFields(job)).not.toThrow();
    expect(findInvalidRepairJobFields(job)).toContain('authorizedPaths');
    expect(authorizeJobOperation(job, buildEdit()).mayExecuteOnce).toBe(false);
  });

  it('rejects rather than throws when an element getter is hostile', () => {
    const hostile: string[] = [AUTHORIZED_PATH, AUTHORIZED_PATH];
    Object.defineProperty(hostile, 1, {
      get(): string {
        throw new Error('hostile element getter');
      },
      configurable: true,
      enumerable: true,
    });
    const job = buildJob({ authorizedPaths: hostile });

    expect(() => authorizeJobOperation(job, buildEdit())).not.toThrow();
    expect(findInvalidRepairJobFields(job)).toContain('authorizedPaths');
    expect(authorizeJobOperation(job, buildEdit()).mayExecuteOnce).toBe(false);
  });

  it('pins the documented limit: a Proxy that misreports ownership widens nothing', () => {
    // The honest boundary, recorded so the guarantee is not read as stronger
    // than it is. A Proxy *defines* the observable result of `Object.hasOwn`
    // and of the read, so one that claims a hole is own while the read forwards
    // through the target's prototype passes the inherited value through. No
    // reader can tell it apart from a truthful object, and this test does not
    // pretend otherwise — it pins the *consequence*, which is that nothing is
    // widened.
    const target = withHoleAtOne(AUTHORIZED_PATH);
    Object.setPrototypeOf(target, { 1: UNAUTHORIZED_PATH });
    const liar = new Proxy(target, {
      getOwnPropertyDescriptor(t, key): PropertyDescriptor | undefined {
        if (key === '1') {
          return { value: UNAUTHORIZED_PATH, writable: true, enumerable: true, configurable: true };
        }
        return Reflect.getOwnPropertyDescriptor(t, key);
      },
    });

    // The lie is in effect: the object reports the hole as its own.
    expect(Object.hasOwn(target, 1)).toBe(false);
    expect(Object.hasOwn(liar, 1)).toBe(true);

    const viaProxy = authorizeJobOperation(
      buildJob({ authorizedPaths: liar }),
      buildEdit({ path: UNAUTHORIZED_PATH }),
    );
    // The same caller, supplying the same value as a plain dense own element —
    // which needs no Proxy and no lie at all.
    const viaDenseArray = authorizeJobOperation(
      buildJob({ authorizedPaths: [AUTHORIZED_PATH, UNAUTHORIZED_PATH] }),
      buildEdit({ path: UNAUTHORIZED_PATH }),
    );

    // Byte-identical: the Proxy reaches exactly what configuration already
    // reaches, so it is not an escalation, and the documentation says so.
    expect(JSON.stringify(viaProxy)).toBe(JSON.stringify(viaDenseArray));
  });

  it('needs no global Symbol call to evaluate, so the sentinel depends on no mutable global', async () => {
    // The absence marker is a bare object literal. A module that built it with
    // `Symbol(...)` would call the global factory during evaluation; this
    // module must not, so a replaced `Symbol` is not on its load path at all.
    const saved = globalThis.Symbol;
    let calls = 0;
    // A Proxy over the real Symbol keeps every own property — `Symbol.iterator`
    // and friends — so the module loader itself is unaffected.
    const counting = new Proxy(saved, {
      apply(target, thisArg, args: readonly unknown[]): unknown {
        calls += 1;
        return Reflect.apply(target as (...a: readonly unknown[]) => unknown, thisArg, args);
      },
    });

    let fresh: typeof import('../../src/domain/repair-job.js');
    try {
      globalThis.Symbol = counting;
      vi.resetModules();
      // Awaited inside the try, so the module actually evaluates while the
      // counting Symbol is installed.
      fresh = await import('../../src/domain/repair-job.js');
    } finally {
      globalThis.Symbol = saved;
    }

    expect(calls).toBe(0);
    // And the freshly evaluated module still behaves.
    expect(fresh.findInvalidRepairJobFields(buildJob())).toEqual([]);
    expect(
      fresh.findInvalidRepairJobFields(buildJob({ authorizedPaths: withHoleAtOne(AUTHORIZED_PATH) })),
    ).toContain('authorizedPaths');
  });

  it('leaves the merge and auto-merge barriers exactly where they were', () => {
    // The A03 repair touches list-element provenance and nothing else.
    const job = buildJob({
      authorizedPaths: sparseWithInheritedElement(AUTHORIZED_PATH, UNAUTHORIZED_PATH),
    });

    const merge = authorizeJobOperation(job, buildRequest({ operation: 'merge' }));
    expect(merge.decision).toBe(JOB_AUTHORIZATION.OPERATOR_REQUIRED);
    expect(merge.reason).toBe(JOB_AUTHORIZATION_REASON.MERGE_IS_OPERATOR_ONLY);
    expect(merge.mayExecuteOnce).toBe(false);
    expect(merge.permit).toBeNull();

    const auto = authorizeJobOperation(job, buildRequest({ operation: 'auto_merge.enable' }));
    expect(auto.decision).toBe(JOB_AUTHORIZATION.DENY);
    expect(auto.reason).toBe(JOB_AUTHORIZATION_REASON.OPERATION_FORBIDDEN);
    expect(auto.permit).toBeNull();
  });
});

/* -------------------------------------------------------------------------
 * Cross-boundary conventions
 * ------------------------------------------------------------------------- */

describe('bounds stay aligned with the neighbouring boundaries', () => {
  it('uses the same identifier bound as the PR 006 invocation boundary', () => {
    // A jobId may be correlated with an invocationId. The two boundaries share
    // no code, so the convention is pinned by a test rather than by an import.
    expect(JOB_BOUNDS.MAX_IDENTIFIER_LENGTH).toBe(INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH);
  });

  it('rejects rather than truncates a maximum-length-plus-one identifier', () => {
    const atLimit = 'j'.repeat(JOB_BOUNDS.MAX_IDENTIFIER_LENGTH);
    const overLimit = 'j'.repeat(JOB_BOUNDS.MAX_IDENTIFIER_LENGTH + 1);

    expect(readJobOperation({ requestId: atLimit }).requestId).toBe(atLimit);
    expect(readJobOperation({ requestId: overLimit }).requestId).toBeNull();
    // The prefix never reaches the output, so two ids sharing a 256-character
    // prefix can never collapse into one.
    expect(readJobOperation({ requestId: overLimit }).requestId).not.toBe(atLimit);
  });
});

/* -------------------------------------------------------------------------
 * C1-A04: Git-equivalent branch-ref spellings
 *
 * Git resolves `main`, `heads/main`, and `refs/heads/main` to one ref. A
 * boundary that compares ref *strings* therefore has three names for one
 * authority target unless it fixes the spelling first, and the quarantine
 * invariant — "the repair branch and the protected parent are distinct actual
 * branches" — degrades into "the two strings are unequal".
 * ------------------------------------------------------------------------- */

/** Spellings of one and the same branch. One simple, one nested. */
const ALIAS_FAMILIES: readonly {
  readonly branch: string;
  readonly spellings: readonly string[];
}[] = [
  {
    branch: 'refs/heads/main',
    spellings: ['main', 'heads/main', 'refs/heads/main'],
  },
  {
    branch: 'refs/heads/feature/pr-042-parent',
    spellings: [
      'feature/pr-042-parent',
      'heads/feature/pr-042-parent',
      'refs/heads/feature/pr-042-parent',
    ],
  },
];

/** The operations that mutate a ref, and so must never accept an alias. */
const REF_WRITE_OPERATIONS: readonly string[] = [
  JOB_OPERATION.REPAIR_COMMIT,
  JOB_OPERATION.REPAIR_PUSH,
];

/** Alias spellings of the fixture repair branch. */
const REPAIR_BRANCH_ALIASES: readonly string[] = ['repair/job-0001', 'heads/repair/job-0001'];

function refRequest(operation: string, ref: string): JobOperationRequest {
  return buildRequest({ operation, worktreeId: REPAIR_WORKTREE, ref, force: false });
}

describe('the canonical branch-ref reader', () => {
  it('accepts only the fully qualified refs/heads/<name> spelling', () => {
    expect(readCanonicalBranchRef('refs/heads/main')).toBe('refs/heads/main');
    expect(readCanonicalBranchRef(PARENT_REF)).toBe(PARENT_REF);
    expect(readCanonicalBranchRef('refs/heads/repair/c1-a04_ref.alias-1')).toBe(
      'refs/heads/repair/c1-a04_ref.alias-1',
    );
  });

  it('refuses every other spelling of the same branch', () => {
    for (const family of ALIAS_FAMILIES) {
      for (const spelling of family.spellings) {
        if (spelling === family.branch) {
          expect(readCanonicalBranchRef(spelling), spelling).toBe(spelling);
          continue;
        }
        expect(readCanonicalBranchRef(spelling), spelling).toBeNull();
      }
    }
    for (const alias of [...PARENT_REF_ALIASES, ...REPAIR_BRANCH_ALIASES]) {
      expect(readCanonicalBranchRef(alias), alias).toBeNull();
    }
  });

  it('refuses partially qualified, differently rooted, and mis-cased prefixes', () => {
    for (const value of [
      'refs/heads/',
      'refs/head/main',
      'refs/tags/main',
      'refs/remotes/origin/main',
      'Refs/Heads/main',
      'REFS/HEADS/main',
      '/refs/heads/main',
      'refs/heads//main',
      'refs/heads/main/',
      ' refs/heads/main',
      'refs/heads/main ',
      'refs/heads/main\n',
    ]) {
      expect(readCanonicalBranchRef(value), JSON.stringify(value)).toBeNull();
    }
  });

  it('refuses the ref-name forms git itself refuses, and the revision operators', () => {
    for (const value of [
      'refs/heads/.hidden',
      'refs/heads/main.',
      'refs/heads/feature/.x',
      'refs/heads/a..b',
      'refs/heads/../../etc/passwd',
      'refs/heads/main.lock',
      'refs/heads/main.LOCK',
      'refs/heads/feature/x.lock',
      'refs/heads/main@{1}',
      'refs/heads/main^{}',
      'refs/heads/main~1',
      'refs/heads/ma in',
      'refs/heads/ma:in',
      'refs/heads/ma?in',
      'refs/heads/ma*in',
      'refs/heads/ma[in',
      'refs/heads/ma\\in',
      // Non-ASCII is refused outright: the precomposed and decomposed spellings
      // below are unequal strings that a loose ref can resolve to a single ref.
      'refs/heads/café',
      'refs/heads/café',
    ]) {
      expect(readCanonicalBranchRef(value), JSON.stringify(value)).toBeNull();
    }
  });

  it('fails closed on hostile values without throwing', () => {
    for (const value of NON_OBJECTS) {
      expect(() => readCanonicalBranchRef(value)).not.toThrow();
      expect(readCanonicalBranchRef(value)).toBeNull();
    }
    expect(readCanonicalBranchRef({ toString: () => 'refs/heads/main' })).toBeNull();
    expect(readCanonicalBranchRef(['refs/heads/main'])).toBeNull();
    expect(readCanonicalBranchRef(revokedProxy())).toBeNull();
    // The identifier bound applies, and rejects rather than truncating.
    expect(
      readCanonicalBranchRef('refs/heads/' + 'a'.repeat(JOB_BOUNDS.MAX_IDENTIFIER_LENGTH)),
    ).toBeNull();
  });
});

describe('an alias spelling can never separate a repair branch from its parent', () => {
  it('rejects the verified A04 configuration outright', () => {
    // The reported exploit exactly: two spellings, one branch.
    const job = buildJob({ protectedParentRef: 'refs/heads/main', repairBranch: 'main' });

    expect(findInvalidRepairJobFields(job)).toContain('repairBranch');
    expect(readRepairJobAuthorization(job).snapshot).toBeNull();

    for (const operation of REF_WRITE_OPERATIONS) {
      const decision = authorizeJobOperation(job, refRequest(operation, 'main'));

      expect(decision.decision, operation).toBe(JOB_AUTHORIZATION.DENY);
      expect(decision.reason, operation).toBe(JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID);
      expect(decision.mayExecuteOnce, operation).toBe(false);
      expect(decision.permit, operation).toBeNull();
    }
  });

  it('rejects every alias pairing of one branch, for every ref-writing operation', () => {
    for (const family of ALIAS_FAMILIES) {
      for (const protectedParentRef of family.spellings) {
        for (const repairBranch of family.spellings) {
          const job = buildJob({ protectedParentRef, repairBranch });
          const label = `${protectedParentRef} | ${repairBranch}`;

          // The two refs denote one branch, so this is never a quarantined job.
          // Whichever field is the offending one — a non-canonical spelling is
          // reported against itself, a canonical collision against
          // `repairBranch` — the envelope is refused and nothing is snapshotted.
          expect(readRepairJobAuthorization(job).snapshot, label).toBeNull();
          if (protectedParentRef === family.branch) {
            expect(findInvalidRepairJobFields(job), label).toContain('repairBranch');
          } else {
            expect(findInvalidRepairJobFields(job), label).toContain('protectedParentRef');
          }

          for (const operation of REF_WRITE_OPERATIONS) {
            for (const ref of family.spellings) {
              const decision = authorizeJobOperation(job, refRequest(operation, ref));
              const attempt = `${label} -> ${operation} ${ref}`;

              expect(decision.decision, attempt).not.toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
              expect(decision.mayExecuteOnce, attempt).toBe(false);
              expect(decision.permit, attempt).toBeNull();
            }
          }
        }
      }
    }
  });

  it('rejects a repair branch that differs from the parent only by ASCII case', () => {
    // Git stores loose refs as files, so on a case-insensitive filesystem these
    // pairs can be one ref. C1 observes no filesystem, so it refuses the pair.
    const pairs: readonly (readonly [string, string])[] = [
      ['refs/heads/main', 'refs/heads/Main'],
      ['refs/heads/Main', 'refs/heads/main'],
      ['refs/heads/feature/pr-042-parent', 'refs/heads/Feature/PR-042-Parent'],
    ];

    for (const [protectedParentRef, repairBranch] of pairs) {
      const job = buildJob({ protectedParentRef, repairBranch });
      const label = `${protectedParentRef} | ${repairBranch}`;

      expect(findInvalidRepairJobFields(job), label).toContain('repairBranch');
      for (const operation of REF_WRITE_OPERATIONS) {
        const decision = authorizeJobOperation(job, refRequest(operation, repairBranch));

        expect(decision.mayExecuteOnce, label).toBe(false);
        expect(decision.permit, label).toBeNull();
      }
    }
  });
});

describe('an alias spelling in a request is refused, never compared', () => {
  it('denies a commit or push naming an alias of the repair branch', () => {
    for (const alias of REPAIR_BRANCH_ALIASES) {
      for (const operation of REF_WRITE_OPERATIONS) {
        const decision = authorizeJobOperation(buildJob(), refRequest(operation, alias));
        const label = `${operation} ${alias}`;

        expect(decision.reason, label).toBe(JOB_AUTHORIZATION_REASON.REF_MALFORMED);
        expect(decision.decision, label).toBe(JOB_AUTHORIZATION.DENY);
        expect(decision.mayExecuteOnce, label).toBe(false);
        expect(decision.permit, label).toBeNull();
      }
    }
  });

  it('denies a commit or push naming an alias of the protected parent', () => {
    for (const alias of PARENT_REF_ALIASES) {
      for (const operation of REF_WRITE_OPERATIONS) {
        const decision = authorizeJobOperation(buildJob(), refRequest(operation, alias));
        const label = `${operation} ${alias}`;

        expect(decision.reason, label).toBe(JOB_AUTHORIZATION_REASON.REF_MALFORMED);
        expect(decision.mayExecuteOnce, label).toBe(false);
        expect(decision.permit, label).toBeNull();
      }
    }

    // The canonical spelling of the parent is still refused, and still refused
    // as an escape attempt rather than as a malformed operand.
    for (const operation of REF_WRITE_OPERATIONS) {
      expect(
        authorizeJobOperation(buildJob(), refRequest(operation, PARENT_REF)).reason,
        operation,
      ).toBe(JOB_AUTHORIZATION_REASON.PROTECTED_REF_MUTATION);
    }
  });

  it('never carries an alias operand into a normalized request', () => {
    for (const alias of [...PARENT_REF_ALIASES, ...REPAIR_BRANCH_ALIASES]) {
      const normalized = readJobOperation(refRequest(JOB_OPERATION.REPAIR_PUSH, alias));

      expect(normalized.ref, alias).toBeNull();
      expect(normalized.refMalformed, alias).toBe(true);
    }
  });
});

describe('change-request source and target separation survives aliasing', () => {
  it('refuses an alias on either end', () => {
    const job = buildJob();
    const cases: readonly (readonly [string, string])[] = [
      ['repair/job-0001', PARENT_REF],
      ['heads/repair/job-0001', PARENT_REF],
      [REPAIR_BRANCH, 'feature/pr-042-parent'],
      [REPAIR_BRANCH, 'heads/feature/pr-042-parent'],
      ['repair/job-0001', 'feature/pr-042-parent'],
    ];

    for (const [sourceRef, targetRef] of cases) {
      const decision = authorizeJobOperation(
        job,
        buildRequest({ operation: JOB_OPERATION.REPAIR_CHANGE_REQUEST, sourceRef, targetRef }),
      );
      const label = `${sourceRef} -> ${targetRef}`;

      expect(decision.reason, label).toBe(JOB_AUTHORIZATION_REASON.REF_MALFORMED);
      expect(decision.decision, label).toBe(JOB_AUTHORIZATION.DENY);
      expect(decision.permit, label).toBeNull();
    }
  });

  it('never models a change request whose source and target are one branch', () => {
    for (const family of ALIAS_FAMILIES) {
      for (const sourceRef of family.spellings) {
        for (const targetRef of family.spellings) {
          const decision = authorizeJobOperation(
            buildJob({ protectedParentRef: family.branch, repairBranch: sourceRef }),
            buildRequest({
              operation: JOB_OPERATION.REPAIR_CHANGE_REQUEST,
              sourceRef,
              targetRef,
            }),
          );
          const label = `${sourceRef} -> ${targetRef}`;

          expect(decision.decision, label).not.toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
          expect(decision.mayExecuteOnce, label).toBe(false);
          expect(decision.permit, label).toBeNull();
        }
      }
    }
  });
});

describe('legitimate distinct canonical refs still authorize the bounded operations', () => {
  it('allows a push, a commit, and a stacked change request', () => {
    const job = buildJob();

    const push = authorizeJobOperation(job, refRequest(JOB_OPERATION.REPAIR_PUSH, REPAIR_BRANCH));
    expect(push.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(push.reason).toBe(JOB_AUTHORIZATION_REASON.WITHIN_JOB_ENVELOPE);
    expect(push.permit?.operands.ref).toBe(REPAIR_BRANCH);

    const commit = authorizeJobOperation(
      job,
      refRequest(JOB_OPERATION.REPAIR_COMMIT, REPAIR_BRANCH),
    );
    expect(commit.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(commit.permit?.operands.ref).toBe(REPAIR_BRANCH);

    const changeRequest = authorizeJobOperation(
      job,
      buildRequest({
        operation: JOB_OPERATION.REPAIR_CHANGE_REQUEST,
        sourceRef: REPAIR_BRANCH,
        targetRef: PARENT_REF,
      }),
    );
    expect(changeRequest.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(changeRequest.permit?.operands.sourceRef).toBe(REPAIR_BRANCH);
    expect(changeRequest.permit?.operands.targetRef).toBe(PARENT_REF);
  });

  it('allows a nested repair branch stacked under a nested protected parent', () => {
    const repairBranch = 'refs/heads/repair/c1-a04-ref-alias';
    const job = buildJob({
      protectedParentRef: 'refs/heads/feature/pr-042-parent',
      repairBranch,
    });

    expect(findInvalidRepairJobFields(job)).toHaveLength(0);
    const decision = authorizeJobOperation(
      job,
      refRequest(JOB_OPERATION.REPAIR_PUSH, repairBranch),
    );

    expect(decision.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(decision.permit?.operands.ref).toBe(repairBranch);
  });
});
