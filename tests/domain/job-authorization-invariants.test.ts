import { describe, expect, it } from 'vitest';

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
  operatorMergeAuthorizes,
  readJobOperation,
  REPAIR_AUTHORIZABLE_OPERATIONS,
  satisfiesIndependentValidator,
  type ApprovalRecord,
  type JobOperationRequest,
  type OperatorMergeAuthorization,
  type RepairJobAuthorization,
  type ValidatorClaim,
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
      buildJob({ protectedParentRef: 'main' }),
      buildJob({ repairBranch: 'main', protectedParentRef: 'main' }),
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

describe('operator merge authorization is separate, exact, and single-use', () => {
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

  it('becomes invalid the moment HEAD moves', () => {
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
