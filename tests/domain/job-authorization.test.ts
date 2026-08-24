import { describe, expect, it } from 'vitest';

import {
  authorizeJobOperation,
  findInvalidRepairJobFields,
  JOB_AUTHORIZATION,
  JOB_AUTHORIZATION_REASON,
  readRepositoryRelativePath,
  type JobOperationRequest,
  type RepairJobAuthorization,
} from '../../src/domain/index.js';
import {
  AUTHORIZED_PATH,
  buildEdit,
  buildJob,
  buildPush,
  buildRequest,
  HEAD_A,
  HEAD_B,
  JOB_B,
  PARENT_PR_B,
  PARENT_REF,
  REPAIR_BRANCH,
  REPAIR_WORKTREE,
  REPO_B,
  SECOND_AUTHORIZED_PATH,
  UNAUTHORIZED_PATH,
} from './repair-job-fixtures.js';

/** Nothing was authorized, and no permit escaped. */
function expectRefused(
  decision: ReturnType<typeof authorizeJobOperation>,
  reason: string,
): void {
  expect(decision.reason).toBe(reason);
  expect(decision.mayExecuteOnce).toBe(false);
  expect(decision.permit).toBeNull();
}

describe('the authorized edit', () => {
  it('allows an exact authorized edit, once, with a permit', () => {
    const decision = authorizeJobOperation(buildJob(), buildEdit());

    expect(decision.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(decision.reason).toBe(JOB_AUTHORIZATION_REASON.WITHIN_JOB_ENVELOPE);
    expect(decision.mayExecuteOnce).toBe(true);
    expect(decision.permit?.operation).toBe('source.edit');
    expect(decision.permit?.operands.path).toBe(AUTHORIZED_PATH);
    expect(decision.permit?.singleUse).toBe(true);
    expect(decision.permit?.scope).toBe('exactly-one-execution');
  });

  it('allows every operation the envelope covers, and only with its own operands', () => {
    const job = buildJob();
    const allowed: readonly JobOperationRequest[] = [
      buildEdit({ operation: 'source.read' }),
      buildEdit(),
      buildEdit({ operation: 'source.edit', path: SECOND_AUTHORIZED_PATH }),
      buildRequest({
        operation: 'verification.run',
        worktreeId: REPAIR_WORKTREE,
        commandClass: 'test',
      }),
      buildRequest({
        operation: 'repair.commit',
        worktreeId: REPAIR_WORKTREE,
        ref: REPAIR_BRANCH,
      }),
      buildPush(),
      buildRequest({
        operation: 'repair.change_request',
        sourceRef: REPAIR_BRANCH,
        targetRef: PARENT_REF,
      }),
    ];

    for (const request of allowed) {
      const decision = authorizeJobOperation(job, request);
      expect(decision.decision, request.operation).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    }
  });

  it('carries only the operands its own operation defines', () => {
    // A read request that also names the protected parent ref: the ref has no
    // meaning for a read, and must not ride along into the permit.
    const decision = authorizeJobOperation(
      buildJob(),
      buildEdit({ operation: 'source.read', ref: PARENT_REF, sourceRef: PARENT_REF }),
    );

    expect(decision.decision).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    expect(decision.permit?.operands.ref).toBeNull();
    expect(decision.permit?.operands.sourceRef).toBeNull();
    expect(decision.permit?.operands.commandClass).toBeNull();
    expect(decision.permit?.operands.force).toBe(false);
  });
});

describe('binding: one job authorizes one repository, pull request, and HEAD', () => {
  it('denies a request naming another repository', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildEdit({ repositoryId: REPO_B })),
      JOB_AUTHORIZATION_REASON.REPOSITORY_MISMATCH,
    );
  });

  it('denies a request naming another parent pull request', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildEdit({ parentPullRequestId: PARENT_PR_B })),
      JOB_AUTHORIZATION_REASON.PARENT_PULL_REQUEST_MISMATCH,
    );
  });

  it('denies a request naming another parent HEAD', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildEdit({ parentHeadSha: HEAD_B })),
      JOB_AUTHORIZATION_REASON.PARENT_HEAD_MISMATCH,
    );
  });

  it('denies a request naming another job', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildEdit({ jobId: JOB_B })),
      JOB_AUTHORIZATION_REASON.JOB_MISMATCH,
    );
  });

  it('denies a request that omits a binding field rather than defaulting it', () => {
    for (const field of [
      'jobId',
      'repositoryId',
      'parentPullRequestId',
      'parentHeadSha',
    ] as const) {
      const request: Record<string, unknown> = { ...buildEdit() };
      Reflect.deleteProperty(request, field);
      const decision = authorizeJobOperation(
        buildJob(),
        request as unknown as JobOperationRequest,
      );

      expect(decision.mayExecuteOnce, field).toBe(false);
      expect(decision.permit, field).toBeNull();
    }
  });

  it('denies when the job binds to a different HEAD than the finding was verified against', () => {
    // The job is internally inconsistent: the finding was verified at HEAD_B
    // while the job is bound to HEAD_A. The repair would target something the
    // finding never described.
    expectRefused(
      authorizeJobOperation(buildJob({ findingHeadSha: HEAD_B }), buildEdit()),
      JOB_AUTHORIZATION_REASON.FINDING_SHA_STALE,
    );
  });

  it('denies a stale-finding job for every authorizable operation, not just edits', () => {
    const job = buildJob({ findingHeadSha: HEAD_B });
    for (const request of [buildEdit(), buildPush()]) {
      const decision = authorizeJobOperation(job, request);
      expect(decision.reason, request.operation).toBe(
        JOB_AUTHORIZATION_REASON.FINDING_SHA_STALE,
      );
    }
  });
});

describe('authorized file scope', () => {
  it('denies an edit outside the authorized paths', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildEdit({ path: UNAUTHORIZED_PATH })),
      JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED,
    );
  });

  it('does not treat an authorized path as authority over its directory', () => {
    // `src/domain/policy-gate.ts` is authorized. Its directory is not, and
    // neither is a sibling, a prefix-extension, or the directory itself.
    for (const path of [
      'src/domain',
      'src/domain/',
      'src/domain/policy-gate.ts.bak',
      'src/domain/policy-gate.tsx',
      'src',
    ]) {
      const decision = authorizeJobOperation(buildJob(), buildEdit({ path }));
      expect(decision.mayExecuteOnce, path).toBe(false);
    }
  });

  it('denies malformed and escaping paths without resolving them', () => {
    const hostile = [
      '../secrets.env',
      'src/../../etc/passwd',
      './src/domain/policy-gate.ts',
      '/etc/passwd',
      'C:/Windows/System32/config',
      'src\\domain\\policy-gate.ts',
      '~/.ssh/id_rsa',
      '.git/config',
      '.GIT/hooks/pre-commit',
      'src//domain/policy-gate.ts',
      'src/domain/policy-gate.ts/',
      'src/domain/policy-gate.ts\u0000.png',
      'file.txt:stream',
      '',
      '   ',
    ];

    for (const path of hostile) {
      const decision = authorizeJobOperation(buildJob(), buildEdit({ path }));
      expect(decision.mayExecuteOnce, path).toBe(false);
      expect(decision.permit, path).toBeNull();
    }
  });

  it('rejects the same hostile paths in job configuration, all-or-nothing', () => {
    for (const path of ['../x', '/x', '.git/config', 'a\\b']) {
      const job = buildJob({ authorizedPaths: [AUTHORIZED_PATH, path] });

      expect(findInvalidRepairJobFields(job), path).toContain('authorizedPaths');
      // And the good path in the same list is not salvaged.
      expect(authorizeJobOperation(job, buildEdit()).reason, path).toBe(
        JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID,
      );
    }
  });

  it('authorizes no file at all when the scope is empty', () => {
    const job = buildJob({ authorizedPaths: [] });

    expect(findInvalidRepairJobFields(job)).toEqual([]);
    expectRefused(
      authorizeJobOperation(job, buildEdit()),
      JOB_AUTHORIZATION_REASON.PATH_NOT_AUTHORIZED,
    );
  });

  it('reads a path exactly, with no normalisation', () => {
    expect(readRepositoryRelativePath('src/a.ts')).toBe('src/a.ts');
    // Not case-folded: an authorized path is not its uppercase spelling.
    expect(readRepositoryRelativePath('SRC/A.TS')).toBe('SRC/A.TS');
    expect(
      authorizeJobOperation(buildJob(), buildEdit({ path: AUTHORIZED_PATH.toUpperCase() }))
        .mayExecuteOnce,
    ).toBe(false);
  });

  it('rejects segments Windows would silently rewrite', () => {
    // `a.txt ` and `a.txt` compare unequal here but can name one file on
    // Windows, so neither padded form is readable at all.
    for (const path of ['src/a.ts ', ' src/a.ts', 'src /a.ts', 'src/a.ts.', 'src./a.ts']) {
      expect(readRepositoryRelativePath(path), path).toBeNull();
    }
    expect(
      authorizeJobOperation(buildJob(), buildEdit({ path: `${AUTHORIZED_PATH} ` })).mayExecuteOnce,
    ).toBe(false);
  });

  it('rejects a .git segment at any depth', () => {
    for (const path of [
      '.git/config',
      '.GIT/hooks/pre-commit',
      '.Git/objects/x',
      'vendor/lib/.git/config',
      'a/b/.git/hooks/post-checkout',
    ]) {
      expect(readRepositoryRelativePath(path), path).toBeNull();
    }
  });

  it('denies an edit in a worktree that is not the job\u2019s repair worktree', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildEdit({ worktreeId: 'parent-worktree' })),
      JOB_AUTHORIZATION_REASON.WORKTREE_NOT_AUTHORIZED,
    );
    // An omitted worktree is refused exactly like a wrong one; it does not
    // default to the repair worktree.
    expectRefused(
      authorizeJobOperation(
        buildJob(),
        buildRequest({ operation: 'source.edit', path: AUTHORIZED_PATH }),
      ),
      JOB_AUTHORIZATION_REASON.WORKTREE_NOT_AUTHORIZED,
    );
  });
});

describe('refs: the repair branch is not the protected parent', () => {
  it('distinguishes a push to the repair branch from a push to the parent', () => {
    expect(authorizeJobOperation(buildJob(), buildPush()).decision).toBe(
      JOB_AUTHORIZATION.ALLOW_ONCE,
    );
    expectRefused(
      authorizeJobOperation(buildJob(), buildPush({ ref: PARENT_REF })),
      JOB_AUTHORIZATION_REASON.PROTECTED_REF_MUTATION,
    );
  });

  it('denies a commit onto the protected parent ref', () => {
    expectRefused(
      authorizeJobOperation(
        buildJob(),
        buildRequest({
          operation: 'repair.commit',
          worktreeId: REPAIR_WORKTREE,
          ref: PARENT_REF,
        }),
      ),
      JOB_AUTHORIZATION_REASON.PROTECTED_REF_MUTATION,
    );
  });

  it('denies a push to any third ref', () => {
    for (const ref of [
      'refs/heads/main',
      'refs/heads/develop',
      'refs/heads/release/1.0',
      'refs/heads/repair/job-0002',
    ]) {
      const decision = authorizeJobOperation(buildJob(), buildPush({ ref }));
      expect(decision.reason, ref).toBe(JOB_AUTHORIZATION_REASON.REF_NOT_REPAIR_BRANCH);
    }
  });

  it('always denies a force push, including to the authorized repair branch', () => {
    expectRefused(
      authorizeJobOperation(buildJob(), buildPush({ force: true })),
      JOB_AUTHORIZATION_REASON.FORCE_PUSH_FORBIDDEN,
    );
    expectRefused(
      authorizeJobOperation(buildJob(), buildPush({ ref: PARENT_REF, force: true })),
      JOB_AUTHORIZATION_REASON.FORCE_PUSH_FORBIDDEN,
    );
  });

  it('treats an unreadable force flag as force', () => {
    // Only an absent or literally `false` flag is not a force. Anything a
    // requester could smuggle in that is merely falsy is still a force.
    const forces: readonly unknown[] = [0, '', null, 'false', 'no', NaN, {}, []];
    for (const [index, force] of forces.entries()) {
      const decision = authorizeJobOperation(
        buildJob(),
        buildPush({ force } as unknown as Partial<JobOperationRequest>),
      );
      expect(decision.reason, `force[${String(index)}]`).toBe(
        JOB_AUTHORIZATION_REASON.FORCE_PUSH_FORBIDDEN,
      );
    }
  });

  it('allows a push whose force flag is absent', () => {
    const request: Record<string, unknown> = { ...buildPush() };
    delete request['force'];

    expect(
      authorizeJobOperation(buildJob(), request as unknown as JobOperationRequest).decision,
    ).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
  });

  it('requires the stacked change request to run from repair branch to protected parent', () => {
    const job = buildJob();

    // The one authorized shape.
    expect(
      authorizeJobOperation(
        job,
        buildRequest({
          operation: 'repair.change_request',
          sourceRef: REPAIR_BRANCH,
          targetRef: PARENT_REF,
        }),
      ).decision,
    ).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);

    // Reversed: a change request *from* the protected parent is not a stacked
    // validation PR, it is a proposal to move the parent.
    expectRefused(
      authorizeJobOperation(
        job,
        buildRequest({
          operation: 'repair.change_request',
          sourceRef: PARENT_REF,
          targetRef: REPAIR_BRANCH,
        }),
      ),
      JOB_AUTHORIZATION_REASON.REF_NOT_REPAIR_BRANCH,
    );

    // Escaping quarantine by targeting the integration branch directly.
    expectRefused(
      authorizeJobOperation(
        job,
        buildRequest({
          operation: 'repair.change_request',
          sourceRef: REPAIR_BRANCH,
          targetRef: 'refs/heads/main',
        }),
      ),
      JOB_AUTHORIZATION_REASON.CHANGE_REQUEST_TARGET_INVALID,
    );
  });
});

describe('command authority', () => {
  it('allows only verification classes the job was configured for', () => {
    const job = buildJob();

    for (const commandClass of ['test', 'lint', 'typecheck']) {
      const decision = authorizeJobOperation(
        job,
        buildRequest({ operation: 'verification.run', worktreeId: REPAIR_WORKTREE, commandClass }),
      );
      expect(decision.decision, commandClass).toBe(JOB_AUTHORIZATION.ALLOW_ONCE);
    }

    // Modeled, but not authorized by this job.
    for (const commandClass of ['build', 'audit']) {
      const decision = authorizeJobOperation(
        job,
        buildRequest({ operation: 'verification.run', worktreeId: REPAIR_WORKTREE, commandClass }),
      );
      expect(decision.reason, commandClass).toBe(
        JOB_AUTHORIZATION_REASON.COMMAND_CLASS_NOT_AUTHORIZED,
      );
    }
  });

  it('never authorizes a command string, only a class', () => {
    for (const commandClass of [
      'npm test',
      'npm run test',
      'test; rm -rf /',
      'test && curl evil.example',
      'TEST',
      'test ',
      'sh',
      'powershell',
    ]) {
      const decision = authorizeJobOperation(
        buildJob(),
        buildRequest({ operation: 'verification.run', worktreeId: REPAIR_WORKTREE, commandClass }),
      );
      expect(decision.reason, commandClass).toBe(
        JOB_AUTHORIZATION_REASON.COMMAND_CLASS_NOT_AUTHORIZED,
      );
    }
  });

  it('rejects an unmodeled class in job configuration rather than accepting it', () => {
    const job = buildJob({
      authorizedCommandClasses: ['test', 'deploy'] as unknown as RepairJobAuthorization['authorizedCommandClasses'],
    });

    expect(findInvalidRepairJobFields(job)).toContain('authorizedCommandClasses');
    expect(authorizeJobOperation(job, buildEdit()).reason).toBe(
      JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID,
    );
  });
});

describe('job envelope validation', () => {
  it('rejects a job whose repair branch is the protected parent ref', () => {
    const job = buildJob({ repairBranch: PARENT_REF });

    expect(findInvalidRepairJobFields(job)).toContain('repairBranch');
    expectRefused(
      authorizeJobOperation(job, buildEdit()),
      JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID,
    );
  });

  it('rejects a job whose repair agent is its own independent validator', () => {
    const job = buildJob({ independentValidatorId: 'repair-agent-1' });

    expect(findInvalidRepairJobFields(job)).toContain('independentValidatorId');
    expectRefused(
      authorizeJobOperation(job, buildEdit()),
      JOB_AUTHORIZATION_REASON.JOB_ENVELOPE_INVALID,
    );
  });

  it('rejects a job missing any required field', () => {
    const fields: readonly (keyof RepairJobAuthorization)[] = [
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

    for (const field of fields) {
      const job: Record<string, unknown> = { ...buildJob() };
      Reflect.deleteProperty(job, field);
      const typed = job as unknown as RepairJobAuthorization;

      expect(findInvalidRepairJobFields(typed), field).toContain(field);
      expect(authorizeJobOperation(typed, buildEdit()).mayExecuteOnce, field).toBe(false);
    }
  });

  it('reports invalid fields in declaration order', () => {
    const job = buildJob({ repositoryId: '', findingId: '  ', repairAgentId: '' });

    expect(findInvalidRepairJobFields(job)).toEqual([
      'repositoryId',
      'findingId',
      'repairAgentId',
    ]);
  });

  it('rejects an oversized identifier rather than truncating it', () => {
    const long = 'j'.repeat(257);
    const job = buildJob({ jobId: long });

    expect(findInvalidRepairJobFields(job)).toContain('jobId');
    expect(authorizeJobOperation(job, buildEdit({ jobId: long })).mayExecuteOnce).toBe(false);
  });

  it('rejects an oversized authorized-path list rather than truncating it', () => {
    const paths: string[] = [AUTHORIZED_PATH];
    for (let index = 0; index < 512; index += 1) {
      paths.push(`src/f${String(index)}.ts`);
    }
    const job = buildJob({ authorizedPaths: paths });

    expect(findInvalidRepairJobFields(job)).toContain('authorizedPaths');
    expect(authorizeJobOperation(job, buildEdit()).mayExecuteOnce).toBe(false);
  });

  it('rejects a sparse authorized-path list rather than collapsing the holes', () => {
    const sparse: string[] = [];
    sparse[0] = AUTHORIZED_PATH;
    sparse[3] = SECOND_AUTHORIZED_PATH;
    const job = buildJob({ authorizedPaths: sparse });

    expect(findInvalidRepairJobFields(job)).toContain('authorizedPaths');
  });

  it('accepts a fully valid job with no invalid fields', () => {
    expect(findInvalidRepairJobFields(buildJob())).toEqual([]);
  });
});

describe('unknown operations', () => {
  it('denies every unmodeled operation name', () => {
    for (const operation of [
      'repository.write',
      'git.push',
      'shell.exec',
      'source.write',
      'SOURCE.EDIT',
      'source.edit ',
      ' source.edit',
      'source_edit',
      'unknown',
      'toString',
      'constructor',
      '__proto__',
      'valueOf',
      'hasOwnProperty',
      '',
    ]) {
      const decision = authorizeJobOperation(buildJob(), buildEdit({ operation }));

      expect(decision.reason, operation).toBe(JOB_AUTHORIZATION_REASON.OPERATION_UNKNOWN);
      expect(decision.decision, operation).toBe(JOB_AUTHORIZATION.DENY);
      expect(decision.permit, operation).toBeNull();
    }
  });

  it('denies an absent or non-string operation', () => {
    const operations: readonly unknown[] = [undefined, null, 0, 1, true, {}, [], Symbol('op')];
    for (const [index, operation] of operations.entries()) {
      const decision = authorizeJobOperation(
        buildJob(),
        buildEdit({ operation } as unknown as Partial<JobOperationRequest>),
      );
      expect(decision.mayExecuteOnce, `operation[${String(index)}]`).toBe(false);
    }
  });
});

describe('the decision record', () => {
  it('never echoes rationale, metadata, or requester identity', () => {
    const decision = authorizeJobOperation(buildJob(), buildEdit());
    const serialized = JSON.stringify(decision);

    for (const key of [
      'rationale',
      'metadata',
      'agentId',
      'providerId',
      'actorId',
      'approval',
      'approvalState',
      'role',
      'override',
    ]) {
      expect(Object.hasOwn(decision, key), key).toBe(false);
      expect(serialized, key).not.toContain(key);
    }
  });

  it('survives a JSON round trip unchanged', () => {
    const decision = authorizeJobOperation(buildJob(), buildEdit());

    expect(JSON.parse(JSON.stringify(decision)) as unknown).toEqual(decision);
  });

  it('is frozen, along with the permit it carries', () => {
    const decision = authorizeJobOperation(buildJob(), buildEdit());

    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.permit)).toBe(true);
    expect(Object.isFrozen(decision.permit?.operands)).toBe(true);
  });

  it('is deterministic', () => {
    const first = authorizeJobOperation(buildJob(), buildEdit());
    const second = authorizeJobOperation(buildJob(), buildEdit());

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it('echoes the exact HEAD it was decided against', () => {
    const decision = authorizeJobOperation(buildJob(), buildEdit());

    expect(decision.permit?.parentHeadSha).toBe(HEAD_A);
  });
});
