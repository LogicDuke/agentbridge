import { describe, expect, it } from 'vitest';

import {
  readStartupHumanGateConfig,
  readStartupWorkflowConfig,
  STARTUP_HUMAN_GATE_ENV,
  WORKFLOW_OPEN_ENV,
  type StartupEnv,
} from '../../src/runtime/orchestration-input.js';

const REPO = 'LogicDuke/agentbridge';
const SHA = '843d517a3251e365e84ab0bd31eaaba74cd50f5d';

function env(overrides: Record<string, string | undefined>): StartupEnv {
  return overrides;
}

describe('readStartupWorkflowConfig', () => {
  it('returns null when no workflow-open variables are present (no startup workflow)', () => {
    expect(readStartupWorkflowConfig(env({}), REPO)).toBeNull();
    // Unrelated runtime vars do not request a startup open.
    expect(
      readStartupWorkflowConfig(env({ AGENTBRIDGE_REPOSITORY_ID: REPO }), REPO),
    ).toBeNull();
  });

  it('mints a complete WorkflowBinding from a valid request, repositoryId = runtime identity', () => {
    const binding = readStartupWorkflowConfig(
      env({
        [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-0001',
        [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA,
      }),
      REPO,
    );
    expect(binding).toEqual({ workflowId: 'wf-0001', repositoryId: REPO, boundCommitSha: SHA });
  });

  it('includes an optional pullRequestId only when present', () => {
    const binding = readStartupWorkflowConfig(
      env({
        [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-0001',
        [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA,
        [WORKFLOW_OPEN_ENV.PULL_REQUEST_ID]: '81',
      }),
      REPO,
    );
    expect(binding).toEqual({
      workflowId: 'wf-0001',
      repositoryId: REPO,
      boundCommitSha: SHA,
      pullRequestId: '81',
    });
  });

  it('accepts an explicit workflow repository id that equals the runtime identity', () => {
    const binding = readStartupWorkflowConfig(
      env({
        [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-0001',
        [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA,
        [WORKFLOW_OPEN_ENV.REPOSITORY_ID]: REPO,
      }),
      REPO,
    );
    expect(binding?.repositoryId).toBe(REPO);
  });

  it('fails closed on a partial request: workflowId without boundCommitSha', () => {
    expect(() =>
      readStartupWorkflowConfig(env({ [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-0001' }), REPO),
    ).toThrow();
  });

  it('fails closed on a partial request: boundCommitSha without workflowId', () => {
    expect(() =>
      readStartupWorkflowConfig(env({ [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA }), REPO),
    ).toThrow();
  });

  it('fails closed on an optional-only request: pullRequestId only (never silently null)', () => {
    const call = (): unknown =>
      readStartupWorkflowConfig(env({ [WORKFLOW_OPEN_ENV.PULL_REQUEST_ID]: '82' }), REPO);
    expect(call).toThrow();
  });

  it('fails closed on an optional-only request: workflow repository id only', () => {
    const call = (): unknown =>
      readStartupWorkflowConfig(env({ [WORKFLOW_OPEN_ENV.REPOSITORY_ID]: REPO }), REPO);
    expect(call).toThrow();
  });

  it('optional-only with a mismatched repository id cannot silently become null', () => {
    // A workflow-open var is present, so this is a request; it is incomplete, so
    // it must throw — never silently return null (the old bypass).
    expect(() =>
      readStartupWorkflowConfig(
        env({ [WORKFLOW_OPEN_ENV.REPOSITORY_ID]: 'someone-else/other' }),
        REPO,
      ),
    ).toThrow();
  });

  it('fails closed on repository identity mismatch', () => {
    expect(() =>
      readStartupWorkflowConfig(
        env({
          [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-0001',
          [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA,
          [WORKFLOW_OPEN_ENV.REPOSITORY_ID]: 'someone-else/other',
        }),
        REPO,
      ),
    ).toThrow();
  });

  it('treats an empty-string required value as present-but-malformed (binding built for the domain to reject)', () => {
    // Empty is not absence: the request is honored and a binding is minted with
    // the empty value, which the domain openWorkflow rejects downstream — the
    // seam never silently drops a malformed value as "not requested".
    const binding = readStartupWorkflowConfig(
      env({
        [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: '',
        [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA,
      }),
      REPO,
    );
    expect(binding).not.toBeNull();
    expect(binding?.workflowId).toBe('');
  });
});

describe('readStartupHumanGateConfig (Decision 061 — strict "1" semantics)', () => {
  it('absent → false (no startup human gate requested)', () => {
    expect(readStartupHumanGateConfig(env({}))).toBe(false);
    // An unrelated var present does not request the gate.
    expect(readStartupHumanGateConfig(env({ AGENTBRIDGE_REPOSITORY_ID: REPO }))).toBe(false);
  });

  it('exact string "1" → true', () => {
    expect(readStartupHumanGateConfig(env({ [STARTUP_HUMAN_GATE_ENV]: '1' }))).toBe(true);
  });

  it.each(['0', 'false', 'true', 'yes', 'no', ' ', '01', '', '1 ', ' 1', 'TRUE', '2', '1.0'])(
    'any other present value is invalid configuration and fails closed: %o',
    (value) => {
      expect(() => readStartupHumanGateConfig(env({ [STARTUP_HUMAN_GATE_ENV]: value }))).toThrow();
    },
  );

  it('no trimming, no case-folding, no numeric/boolean coercion', () => {
    // If any coercion were applied, at least one of these would pass as truthy.
    expect(() => readStartupHumanGateConfig(env({ [STARTUP_HUMAN_GATE_ENV]: ' 1 ' }))).toThrow();
    expect(() => readStartupHumanGateConfig(env({ [STARTUP_HUMAN_GATE_ENV]: 'true' }))).toThrow();
    expect(() => readStartupHumanGateConfig(env({ [STARTUP_HUMAN_GATE_ENV]: 'yes' }))).toThrow();
  });

  it('reads the variable exactly once and consults nothing else (single-read snapshot)', () => {
    // A hostile env whose accessor counts reads and mutates on each access:
    // a single read yields the decision; a re-read would flip/observe the change.
    let reads = 0;
    const hostile: StartupEnv = new Proxy(
      {},
      {
        get(_target, key): string | undefined {
          if (key === STARTUP_HUMAN_GATE_ENV) {
            reads += 1;
            return reads === 1 ? '1' : 'poisoned-second-read';
          }
          return undefined;
        },
      },
    );
    expect(readStartupHumanGateConfig(hostile)).toBe(true);
    expect(reads).toBe(1);
  });
});
