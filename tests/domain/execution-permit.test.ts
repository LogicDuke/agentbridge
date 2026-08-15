import { describe, expect, it } from 'vitest';

import {
  authorizeJobOperation,
  JOB_AUTHORIZATION,
  permitAuthorizes,
  type ExecutionPermit,
  type JobOperationRequest,
  type RepairJobAuthorization,
} from '../../src/domain/index.js';
import {
  AUTHORIZED_PATH,
  buildEdit,
  buildJob,
  buildPush,
  buildRequest,
  HEAD_B,
  JOB_B,
  NON_OBJECTS,
  PARENT_PR_B,
  PARENT_REF,
  REPAIR_BRANCH,
  REPAIR_WORKTREE,
  REPO_B,
  SECOND_AUTHORIZED_PATH,
  throwingRecord,
  UNAUTHORIZED_PATH,
} from './repair-job-fixtures.js';

/** Issue a permit for the canonical in-scope edit. */
function issue(
  job: RepairJobAuthorization = buildJob(),
  request: JobOperationRequest = buildEdit(),
): ExecutionPermit {
  const decision = authorizeJobOperation(job, request);
  expect(decision.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
  const permit = decision.permit;
  if (permit === null) {
    throw new Error('expected a permit');
  }
  return permit;
}

describe('a permit is bound to exactly one execution', () => {
  it('verifies against the job and request it was issued for', () => {
    expect(permitAuthorizes(issue(), buildJob(), buildEdit())).toBe(true);
  });

  it('states its single-use scope structurally', () => {
    const permit = issue();

    expect(permit.singleUse).toBe(true);
    expect(permit.scope).toBe('exactly-one-execution');
    expect(Object.isFrozen(permit)).toBe(true);
    expect(Object.isFrozen(permit.operands)).toBe(true);

    // There is no field a consumer could read as a standing right, a renewal,
    // a remaining count, or an expiry it could extend.
    for (const key of [
      'expiresAt',
      'expiry',
      'ttl',
      'uses',
      'usesRemaining',
      'remaining',
      'count',
      'renew',
      'refresh',
      'reusable',
      'persistent',
      'scopes',
      'wildcard',
    ]) {
      expect(Object.hasOwn(permit, key), key).toBe(false);
    }

    expect(Object.keys(permit).sort()).toEqual(
      [
        'jobId',
        'operands',
        'operation',
        'parentHeadSha',
        'parentPullRequestId',
        'permitId',
        'policyVersion',
        'repositoryId',
        'requestId',
        'scope',
        'singleUse',
      ].sort(),
    );
  });

  it('gives byte-identical executions the same identity, so replay is detectable', () => {
    // Deterministic, not a nonce. A consumer that records consumed permitIds
    // can therefore recognise the second presentation of the same execution.
    expect(issue().permitId).toBe(issue().permitId);
  });

  it('gives two distinct execution attempts distinct identities', () => {
    const first = issue(buildJob(), buildEdit({ requestId: 'req-0001' }));
    const second = issue(buildJob(), buildEdit({ requestId: 'req-0002' }));

    expect(first.permitId).not.toBe(second.permitId);
  });

  it('cannot be authorized without a request identity of its own', () => {
    const request: Record<string, unknown> = { ...buildEdit() };
    delete request['requestId'];

    expect(
      authorizeJobOperation(buildJob(), request as unknown as JobOperationRequest)
        .mayExecuteOnce,
    ).toBe(false);
  });
});

describe('cross-job replay', () => {
  it('does not verify under a different job', () => {
    const permit = issue();

    expect(
      permitAuthorizes(permit, buildJob({ jobId: JOB_B }), buildEdit({ jobId: JOB_B })),
    ).toBe(false);
  });

  it('does not verify under a different repository', () => {
    const permit = issue();

    expect(
      permitAuthorizes(
        permit,
        buildJob({ repositoryId: REPO_B }),
        buildEdit({ repositoryId: REPO_B }),
      ),
    ).toBe(false);
  });

  it('does not verify under a different parent pull request', () => {
    const permit = issue();

    expect(
      permitAuthorizes(
        permit,
        buildJob({ parentPullRequestId: PARENT_PR_B }),
        buildEdit({ parentPullRequestId: PARENT_PR_B }),
      ),
    ).toBe(false);
  });

  it('does not verify under a different policy version', () => {
    const permit = issue();

    expect(
      permitAuthorizes(permit, buildJob({ policyVersion: 'cockpit-policy-v2' }), buildEdit()),
    ).toBe(false);
  });
});

describe('cross-operation replay', () => {
  it('does not verify for a different operation', () => {
    const permit = issue();

    expect(permitAuthorizes(permit, buildJob(), buildEdit({ operation: 'source.read' }))).toBe(
      false,
    );
  });

  it('does not verify for a different path', () => {
    const permit = issue();

    expect(
      permitAuthorizes(permit, buildJob(), buildEdit({ path: SECOND_AUTHORIZED_PATH })),
    ).toBe(false);
  });

  it('does not verify for a different ref', () => {
    const permit = issue(buildJob(), buildPush());
    const job = buildJob({ repairBranch: 'repair/job-0001-b' });

    expect(permitAuthorizes(permit, job, buildPush({ ref: 'repair/job-0001-b' }))).toBe(false);
  });

  it('does not verify for a different verification class', () => {
    const permit = issue(
      buildJob(),
      buildRequest({
        operation: 'verification.run',
        worktreeId: REPAIR_WORKTREE,
        commandClass: 'test',
      }),
    );

    expect(
      permitAuthorizes(
        permit,
        buildJob(),
        buildRequest({
          operation: 'verification.run',
          worktreeId: REPAIR_WORKTREE,
          commandClass: 'lint',
        }),
      ),
    ).toBe(false);
  });

  it('does not verify for an operation that is no longer in scope', () => {
    const permit = issue();

    expect(
      permitAuthorizes(permit, buildJob({ authorizedPaths: [SECOND_AUTHORIZED_PATH] }), buildEdit()),
    ).toBe(false);
  });
});

describe('a permit is invalid the moment HEAD moves', () => {
  it('does not verify once the job is re-bound to a new HEAD', () => {
    const permit = issue();
    const movedJob = buildJob({ parentHeadSha: HEAD_B, findingHeadSha: HEAD_B });

    // The original request still claims the old HEAD, so the job binding refuses.
    expect(permitAuthorizes(permit, movedJob, buildEdit())).toBe(false);
    // Re-claiming the new HEAD produces a different permit identity rather than
    // reviving the old permit.
    expect(permitAuthorizes(permit, movedJob, buildEdit({ parentHeadSha: HEAD_B }))).toBe(false);
  });

  it('does not verify when only the request claims the new HEAD', () => {
    const permit = issue();

    expect(permitAuthorizes(permit, buildJob(), buildEdit({ parentHeadSha: HEAD_B }))).toBe(false);
  });

  it('re-issues a distinct permit at the new HEAD', () => {
    const before = issue();
    const after = issue(
      buildJob({ parentHeadSha: HEAD_B, findingHeadSha: HEAD_B }),
      buildEdit({ parentHeadSha: HEAD_B }),
    );

    expect(after.permitId).not.toBe(before.permitId);
  });
});

describe('a permit cannot be forged into wider authority', () => {
  it('rejects a permit whose fields were widened after issue', () => {
    const permit = issue();
    const forged = {
      ...permit,
      operands: { ...permit.operands, path: UNAUTHORIZED_PATH },
    } as unknown as ExecutionPermit;

    expect(permitAuthorizes(forged, buildJob(), buildEdit())).toBe(false);
    expect(
      permitAuthorizes(forged, buildJob(), buildEdit({ path: UNAUTHORIZED_PATH })),
    ).toBe(false);
  });

  it('rejects a permit that claims not to be single-use', () => {
    const permit = issue();

    for (const widened of [
      { ...permit, singleUse: false },
      { ...permit, scope: 'unlimited' },
      { ...permit, scope: 'exactly-one-execution ' },
    ]) {
      expect(permitAuthorizes(widened as unknown as ExecutionPermit, buildJob(), buildEdit())).toBe(
        false,
      );
    }
  });

  it('rejects a permit whose id was rewritten to match another execution', () => {
    const other = issue(buildJob(), buildEdit({ path: SECOND_AUTHORIZED_PATH }));
    const forged = { ...issue(), permitId: other.permitId } as unknown as ExecutionPermit;

    expect(permitAuthorizes(forged, buildJob(), buildEdit())).toBe(false);
  });

  it('rejects a permit assembled from scratch for an out-of-scope operation', () => {
    // A permit is not a bearer token. Even a perfectly shaped one only ever
    // authorizes what the evaluator would authorize at the moment of use.
    const forged = {
      permitId: 'abp1|whatever',
      policyVersion: 'cockpit-policy-v1',
      jobId: 'job-0001',
      repositoryId: 'github.com/LogicDuke/agentbridge',
      parentPullRequestId: '42',
      parentHeadSha: 'a'.repeat(40),
      requestId: 'req-0001',
      operation: 'source.edit',
      operands: {
        worktreeId: REPAIR_WORKTREE,
        path: UNAUTHORIZED_PATH,
        commandClass: null,
        ref: null,
        sourceRef: null,
        targetRef: null,
        force: false,
      },
      singleUse: true,
      scope: 'exactly-one-execution',
    } as unknown as ExecutionPermit;

    expect(
      permitAuthorizes(forged, buildJob(), buildEdit({ path: UNAUTHORIZED_PATH })),
    ).toBe(false);
  });

  it('cannot be presented for the protected parent ref', () => {
    const permit = issue(buildJob(), buildPush());

    expect(permitAuthorizes(permit, buildJob(), buildPush({ ref: PARENT_REF }))).toBe(false);
    expect(permitAuthorizes(permit, buildJob(), buildPush({ force: true }))).toBe(false);
  });

  it('fails closed on a hostile permit without throwing', () => {
    for (const value of NON_OBJECTS) {
      expect(() =>
        permitAuthorizes(value as ExecutionPermit, buildJob(), buildEdit()),
      ).not.toThrow();
      expect(permitAuthorizes(value as ExecutionPermit, buildJob(), buildEdit())).toBe(
        false,
      );
    }

    const throwing = throwingRecord([
      'permitId',
      'policyVersion',
      'jobId',
      'repositoryId',
      'parentHeadSha',
      'operation',
      'operands',
      'singleUse',
      'scope',
    ]) as unknown as ExecutionPermit;

    expect(() => permitAuthorizes(throwing, buildJob(), buildEdit())).not.toThrow();
    expect(permitAuthorizes(throwing, buildJob(), buildEdit())).toBe(false);
  });

  it('never verifies when the underlying decision is not ALLOW_ONCE', () => {
    const permit = issue();
    const refusedRequests = [
      buildEdit({ path: UNAUTHORIZED_PATH }),
      buildEdit({ operation: 'merge' }),
      buildEdit({ operation: 'auto_merge.enable' }),
      buildEdit({ operation: 'nonsense' }),
      buildPush({ force: true }),
    ];

    for (const request of refusedRequests) {
      expect(permitAuthorizes(permit, buildJob(), request), request.operation).toBe(false);
    }
  });
});

describe('permit identity cannot be collided by operand content', () => {
  it('is not confusable by a delimiter inside an operand', () => {
    // Length-prefixed encoding: no operand value can straddle a boundary and
    // make one execution encode identically to another.
    const first = issue(
      buildJob({ authorizedPaths: ['a|b/c.ts', 'a/b|c.ts'] }),
      buildEdit({ path: 'a|b/c.ts' }),
    );
    const second = issue(
      buildJob({ authorizedPaths: ['a|b/c.ts', 'a/b|c.ts'] }),
      buildEdit({ path: 'a/b|c.ts' }),
    );

    expect(first.permitId).not.toBe(second.permitId);
  });

  it('distinguishes an operand that ends where the next begins', () => {
    const first = issue(
      buildJob({ authorizedPaths: ['ab/c.ts'] }),
      buildEdit({ path: 'ab/c.ts', requestId: 'r1' }),
    );
    const second = issue(
      buildJob({ authorizedPaths: ['ab/c.ts'] }),
      buildEdit({ path: 'ab/c.ts', requestId: 'r1x' }),
    );

    expect(first.permitId).not.toBe(second.permitId);
  });

  it('never omits an operand from identity', () => {
    const readPermit = issue(buildJob(), buildEdit({ operation: 'source.read' }));
    const editPermit = issue(buildJob(), buildEdit());

    expect(readPermit.permitId).not.toBe(editPermit.permitId);
    expect(readPermit.operands.path).toBe(AUTHORIZED_PATH);
    expect(editPermit.operands.path).toBe(AUTHORIZED_PATH);
  });

  it('excludes operands the operation does not define, so they cannot ride along', () => {
    const withStowaway = issue(
      buildJob(),
      buildEdit({ ref: REPAIR_BRANCH, targetRef: PARENT_REF, commandClass: 'test' }),
    );
    const clean = issue(buildJob(), buildEdit());

    expect(withStowaway.permitId).toBe(clean.permitId);
    expect(withStowaway.operands.ref).toBeNull();
    expect(withStowaway.operands.targetRef).toBeNull();
    expect(withStowaway.operands.commandClass).toBeNull();
  });
});
