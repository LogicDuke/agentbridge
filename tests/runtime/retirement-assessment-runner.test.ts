import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi, beforeEach } from 'vitest';

/** Fake git: a per-argv response table keyed by the first token of the vector. */
const gitScript = vi.hoisted(() => ({
  table: {} as Record<string, { exitCode: number; stdout: string }>,
  calls: [] as readonly string[][],
  outcome: 'EXITED' as string,
}));

vi.mock('../../src/adapters/process-transport.js', () => ({
  invokeAgentProcess: (spec: { args: readonly string[] }): Promise<unknown> => {
    gitScript.calls = [...gitScript.calls, [...spec.args]];
    const key = spec.args[0] === '-C' ? 'status' : (spec.args[0] ?? '');
    const scripted = gitScript.table[key] ?? { exitCode: 0, stdout: '' };
    return Promise.resolve({
      outcome: gitScript.outcome,
      rejection: null,
      exitCode: scripted.exitCode,
      terminatingSignal: null,
      stdout: scripted.stdout,
      stderr: '',
      stdoutTruncated: false,
      stderrTruncated: false,
      stdoutBytes: 0,
      stderrBytes: 0,
      terminationScope: 'DIRECT_CHILD',
    });
  },
}));

const { AutoflowRuntime } = await import('../../src/autoflow/runtime.js');
const { AutoflowOrchestrator, AUTOFLOW_ASSESSMENT_REFUSED } = await import(
  '../../src/autoflow/orchestrator.js'
);
const { RETIREMENT_CLASSIFICATION, GOVERNANCE_HOLD, EVIDENCE_ID_PREFIX } = await import(
  '../../src/domain/retirement-assessment.js'
);
const { WORKFLOW_STATUS } = await import('../../src/domain/workflow.js');
const { readGovernanceRunManifest } = await import('../../src/runtime/retirement-manifest.js');
const { sha256Canonical } = await import('../../src/runtime/retirement-assessment-store.js');
const { runRetirementAssessment, RUN_ABORT } = await import(
  '../../src/runtime/retirement-assessment-runner.js'
);
/**
 * A stand-in "git executable": a real file on disk whose bytes the observer can
 * hash at boot (Amendment 1 A-6). It is never actually spawned — the transport
 * is mocked — so its contents are irrelevant beyond having a stable digest.
 */
const FAKE_GIT_PATH = join(mkdtempSync(join(tmpdir(), 'ab-job1-')), 'git-stub');
writeFileSync(FAKE_GIT_PATH, 'not really git');
const FAKE_GIT_SHA256 =
  'sha256:' + createHash('sha256').update('not really git', 'utf8').digest('hex');

const REPOSITORY_ID = 'LogicDuke/agentbridge';
const CANDIDATE_REF = 'refs/heads/repair/example';
const SHORT_NAME = 'repair/example';
const CANDIDATE_SHA = 'a'.repeat(40);
const MAIN_SHA = 'c'.repeat(40);
const GENERATED_AT = '2026-09-18T06:00:00.000Z';
const BOOT_MS = Date.UTC(2026, 8, 18, 12, 0, 0);

/* ------------------------------------------------------------------------- *
 * Fixtures
 * ------------------------------------------------------------------------- */

function manifestObject(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    candidateRef: CANDIDATE_REF,
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: MAIN_SHA,
    generatedAt: GENERATED_AT,
    gateId: 'prerun-gate-0001',
    sources: [
      {
        role: 'deferred-findings-register',
        driveFileId: 'register-id',
        title: 'AGENTBRIDGE_DEFERRED_FINDINGS_REGISTER',
        modifiedTime: '2026-09-18T02:18:02.748Z',
        sha256: EVIDENCE_ID_PREFIX + '1'.repeat(64),
      },
      {
        role: 'current-state-checkpoint',
        driveFileId: 'checkpoint-id',
        title: 'AGENTBRIDGE_CURRENT_STATE_V2_23',
        modifiedTime: '2026-09-18T02:26:52.242Z',
        sha256: EVIDENCE_ID_PREFIX + '2'.repeat(64),
      },
    ],
    holdResult: GOVERNANCE_HOLD.NO_HOLD,
    reasonCodes: [],
    matchingEntries: [],
    git: { path: FAKE_GIT_PATH, sha256: FAKE_GIT_SHA256 },
    ...overrides,
  };
}

function signedManifest(overrides: Record<string, unknown> = {}): {
  readonly text: string;
  readonly digest: string;
} {
  const object = manifestObject(overrides);
  const accepted = readGovernanceRunManifest(object);
  if (accepted === null) {
    throw new Error('fixture manifest must be schema-valid');
  }
  const digest = sha256Canonical(accepted);
  if (digest === null) {
    throw new Error('fixture manifest must be canonicalizable');
  }
  return { text: JSON.stringify(object), digest };
}

/** A fake GitHub with nothing depending on the candidate. */
function clearGitHub(
  overrides: Record<string, { status: number; body: string }> = {},
): NonNullable<Parameters<typeof runRetirementAssessment>[1]['githubGet']> {
  const table: Record<string, { status: number; body: string }> = {
    '/repos/LogicDuke/agentbridge': { status: 200, body: JSON.stringify({ default_branch: 'main' }) },
    '/repos/LogicDuke/agentbridge/pulls?state=open&per_page=100': { status: 200, body: '[]' },
    '/repos/LogicDuke/agentbridge/issues?state=open&per_page=100': { status: 200, body: '[]' },
    '/repos/LogicDuke/agentbridge/branches/repair%2Fexample': {
      status: 200,
      body: JSON.stringify({ name: SHORT_NAME, commit: { sha: CANDIDATE_SHA }, protected: false }),
    },
    ...overrides,
  };
  return (path: string) => {
    const entry = table[path] ?? { status: 404, body: '{}' };
    return Promise.resolve({
      statusCode: entry.status,
      body: entry.body,
      linkHeader: null,
      truncated: false,
    });
  };
}

/** Script the fake git so every Git fact supports RETIRE_ELIGIBLE. */
function scriptEligibleGit(): void {
  gitScript.table = {
    'rev-parse': { exitCode: 0, stdout: CANDIDATE_SHA + '\n' },
    'ls-remote': {
      exitCode: 0,
      stdout: `${CANDIDATE_SHA}\t${CANDIDATE_REF}\n${MAIN_SHA}\trefs/heads/main\n`,
    },
    'merge-base': { exitCode: 0, stdout: '' },
    'rev-list': { exitCode: 0, stdout: '0\n' },
    cherry: { exitCode: 0, stdout: '' },
    worktree: { exitCode: 0, stdout: '' },
    status: { exitCode: 0, stdout: '' },
    'for-each-ref': { exitCode: 0, stdout: 'refs/heads/main\trefs/remotes/origin/main\n' },
  };
}

function baseConfig(
  overrides: Partial<Parameters<typeof runRetirementAssessment>[1]> = {},
): Parameters<typeof runRetirementAssessment>[1] {
  const manifest = signedManifest();
  return {
    repositoryId: REPOSITORY_ID,
    owner: 'LogicDuke',
    repo: 'agentbridge',
    candidateRef: CANDIDATE_REF,
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: MAIN_SHA,
    repositoryPath: 'C:\\repo',
    runtimeRoot: 'C:\\runtime',
    manifestPath: 'C:\\manifest.json',
    manifestDigest: manifest.digest,
    manifestText: manifest.text,
    generatedAt: GENERATED_AT,
    bootEpochMs: BOOT_MS,
    platform: 'win32',
    environmentSource: {},
    githubGet: clearGitHub(),
    ...overrides,
  };
}

/** An orchestrator with one open workflow bound to the candidate SHA. */
function openOrchestrator(candidateRef: string | null = CANDIDATE_REF): InstanceType<
  typeof AutoflowOrchestrator
> {
  const runtime = new AutoflowRuntime();
  const orchestrator = new AutoflowOrchestrator(runtime, candidateRef);
  const opened = orchestrator.open({
    workflowId: 'wf-job1-0001',
    repositoryId: REPOSITORY_ID,
    boundCommitSha: CANDIDATE_SHA,
  });
  expect(opened.outcome).toBe('APPLIED');
  return orchestrator;
}

beforeEach(() => {
  gitScript.table = {};
  gitScript.calls = [];
  gitScript.outcome = 'EXITED';
});

/* ------------------------------------------------------------------------- *
 * The three mandated acceptance outcomes
 * ------------------------------------------------------------------------- */

describe('the three Decision 065 acceptance outcomes', () => {
  it('ELIGIBLE: admits RETIRE_ELIGIBLE, opens the gate, ends AWAITING_HUMAN_DECISION at sequence 2', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { store, result } = await runRetirementAssessment(orchestrator, baseConfig());

    expect(result.abort).toBeNull();
    expect(result.admitted).toBe(true);
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE);
    expect(result.gateOpened).toBe(true);

    const state = orchestrator.reader().current();
    expect(state?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    expect(state?.sequence).toBe(2);
    expect(store.list()).toHaveLength(1);
  });

  it('PRESERVED: admits PRESERVE_FOR_HISTORY, opens no gate, stays OPEN at sequence 1', async () => {
    scriptEligibleGit();
    // Not contained, carrying unique commits and patches.
    gitScript.table['merge-base'] = { exitCode: 1, stdout: '' };
    gitScript.table['rev-list'] = { exitCode: 0, stdout: '3\n' };
    gitScript.table['cherry'] = { exitCode: 0, stdout: '+ aaa\n+ bbb\n' };

    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());

    expect(result.abort).toBeNull();
    expect(result.envelope?.body.classification).toBe(
      RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY,
    );
    expect(result.gateOpened).toBe(false);

    const state = orchestrator.reader().current();
    expect(state?.status).toBe(WORKFLOW_STATUS.OPEN);
    expect(state?.sequence).toBe(1);
    expect(state?.humanGateOpenedAtRevision).toBeNull();
  });

  it('BLOCKED: admits BLOCKED, opens no gate, stays OPEN at sequence 1', async () => {
    scriptEligibleGit();
    // A worktree on the candidate is dirty.
    gitScript.table['worktree'] = {
      exitCode: 0,
      stdout: `worktree C:/wt\nHEAD ${CANDIDATE_SHA}\nbranch ${CANDIDATE_REF}\n\n`,
    };
    gitScript.table['status'] = { exitCode: 0, stdout: '?? junk.txt\n' };

    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());

    expect(result.abort).toBeNull();
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(result.gateOpened).toBe(false);

    const state = orchestrator.reader().current();
    expect(state?.status).toBe(WORKFLOW_STATUS.OPEN);
    expect(state?.sequence).toBe(1);
  });
});

/* ------------------------------------------------------------------------- *
 * Observation failures are admitted; integrity failures abort
 * ------------------------------------------------------------------------- */

describe('observation failures are informative, not fatal', () => {
  it('a mutated manifest byte renders BLOCKED, still admitted', async () => {
    scriptEligibleGit();
    const base = signedManifest();
    const mutated = JSON.parse(base.text) as Record<string, unknown>;
    mutated['gateId'] = 'tampered';

    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(
      orchestrator,
      baseConfig({ manifestText: JSON.stringify(mutated), manifestDigest: base.digest }),
    );

    expect(result.abort).toBeNull();
    expect(result.admitted).toBe(true);
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
    expect(result.gateOpened).toBe(false);
  });

  it('a Git timeout renders BLOCKED, still admitted', async () => {
    scriptEligibleGit();
    gitScript.outcome = 'TIMED_OUT';
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.abort).toBeNull();
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
  });

  it('a GitHub rate limit renders BLOCKED, still admitted', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(
      orchestrator,
      baseConfig({
        githubGet: clearGitHub({
          '/repos/LogicDuke/agentbridge/pulls?state=open&per_page=100': { status: 403, body: '{}' },
        }),
      }),
    );
    expect(result.abort).toBeNull();
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
  });

  it('an open PR on the candidate blocks dependency clearance', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(
      orchestrator,
      baseConfig({
        githubGet: clearGitHub({
          '/repos/LogicDuke/agentbridge/pulls?state=open&per_page=100': {
            status: 200,
            body: JSON.stringify([
              { number: 9, head: { ref: SHORT_NAME }, base: { ref: 'main' } },
            ]),
          },
        }),
      }),
    );
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
  });

  it('a local branch still tracking the candidate blocks clearance', async () => {
    scriptEligibleGit();
    gitScript.table['for-each-ref'] = {
      exitCode: 0,
      stdout: `refs/heads/work\trefs/remotes/origin/${SHORT_NAME}\n`,
    };
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
  });

  it('a protected candidate branch is never eligible', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(
      orchestrator,
      baseConfig({
        githubGet: clearGitHub({
          '/repos/LogicDuke/agentbridge/branches/repair%2Fexample': {
            status: 200,
            body: JSON.stringify({
              name: SHORT_NAME,
              commit: { sha: CANDIDATE_SHA },
              protected: true,
            }),
          },
        }),
      }),
    );
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.BLOCKED);
  });

  it('a verified HOLD preserves rather than retires', async () => {
    scriptEligibleGit();
    const held = signedManifest({
      holdResult: GOVERNANCE_HOLD.HOLD,
      reasonCodes: ['REGISTER_OPEN_OBLIGATION'],
      matchingEntries: ['open obligation naming the candidate'],
    });
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(
      orchestrator,
      baseConfig({ manifestText: held.text, manifestDigest: held.digest }),
    );
    expect(result.envelope?.body.classification).toBe(
      RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY,
    );
    expect(result.gateOpened).toBe(false);
  });
});

describe('integrity failures abort before serving (I1, admission)', () => {
  it('a rejected admission aborts and never opens the gate', async () => {
    scriptEligibleGit();
    // The orchestrator is constructed for a DIFFERENT candidate ref, so the
    // envelope is foreign and admission is refused.
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime, 'refs/heads/other');
    orchestrator.open({
      workflowId: 'wf-job1-0001',
      repositoryId: REPOSITORY_ID,
      boundCommitSha: CANDIDATE_SHA,
    });

    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.abort).toBe(RUN_ABORT.ADMISSION_REJECTED);
    expect(result.admitted).toBe(false);
    expect(result.gateOpened).toBe(false);
    // Nothing was applied at all: the open itself is sequence 0, and the refused
    // admission advanced nothing.
    expect(orchestrator.reader().current()?.sequence).toBe(0);
  });

  it('a candidate SHA that is not the workflow binding aborts admission', async () => {
    scriptEligibleGit();
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime, CANDIDATE_REF);
    // Workflow bound to a different commit than the candidate.
    orchestrator.open({
      workflowId: 'wf-job1-0001',
      repositoryId: REPOSITORY_ID,
      boundCommitSha: MAIN_SHA,
    });
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.abort).toBe(RUN_ABORT.ADMISSION_REJECTED);
    expect(result.gateOpened).toBe(false);
  });

  it('with no workflow open nothing is admitted and no gate opens', async () => {
    scriptEligibleGit();
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime, CANDIDATE_REF);
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.abort).toBe(RUN_ABORT.ADMISSION_REJECTED);
    expect(orchestrator.reader().current()).toBeNull();
  });
});

/* ------------------------------------------------------------------------- *
 * The admission origin's own guards
 * ------------------------------------------------------------------------- */

describe('admitRetirementAssessment guards', () => {
  it('refuses every envelope when no Job #1 candidate is configured', async () => {
    scriptEligibleGit();
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    orchestrator.open({
      workflowId: 'wf',
      repositoryId: REPOSITORY_ID,
      boundCommitSha: CANDIDATE_SHA,
    });
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.abort).toBe(RUN_ABORT.ADMISSION_REJECTED);
  });

  it('refuses a foreign candidate ref as a provable no-op', () => {
    const orchestrator = openOrchestrator();
    const before = orchestrator.reader().current();
    const outcome = orchestrator.admitRetirementAssessment({
      evidenceId: EVIDENCE_ID_PREFIX + '0'.repeat(64),
      body: {
        repositoryId: REPOSITORY_ID,
        candidateRef: 'refs/heads/somewhere-else',
        candidateSha: CANDIDATE_SHA,
        authoritativeMainSha: MAIN_SHA,
        facts: {},
        classification: RETIREMENT_CLASSIFICATION.BLOCKED,
        reasonCodes: [],
        gateRequested: false,
        manifestDigest: EVIDENCE_ID_PREFIX + '0'.repeat(64),
        generatedAt: GENERATED_AT,
        observerVersion: 'v',
      },
    });
    expect(outcome.outcome).toBe(AUTOFLOW_ASSESSMENT_REFUSED);
    expect(orchestrator.reader().current()).toBe(before);
  });

  it('refuses a malformed evidence id as a provable no-op', () => {
    const orchestrator = openOrchestrator();
    const before = orchestrator.reader().current();
    const outcome = orchestrator.admitRetirementAssessment({
      evidenceId: 'not-an-id',
      body: {
        repositoryId: REPOSITORY_ID,
        candidateRef: CANDIDATE_REF,
        candidateSha: CANDIDATE_SHA,
        authoritativeMainSha: MAIN_SHA,
        facts: {},
        classification: RETIREMENT_CLASSIFICATION.BLOCKED,
        reasonCodes: [],
        gateRequested: false,
        manifestDigest: EVIDENCE_ID_PREFIX + '0'.repeat(64),
        generatedAt: GENERATED_AT,
        observerVersion: 'v',
      },
    });
    expect(outcome.outcome).toBe(AUTOFLOW_ASSESSMENT_REFUSED);
    expect(orchestrator.reader().current()).toBe(before);
  });

  it('refuses a SECOND admission in the same runtime', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const first = await runRetirementAssessment(orchestrator, baseConfig());
    expect(first.result.admitted).toBe(true);

    const envelope = first.result.envelope;
    expect(envelope).not.toBeNull();
    if (envelope !== null) {
      const second = orchestrator.admitRetirementAssessment(envelope);
      expect(second.outcome).toBe(AUTOFLOW_ASSESSMENT_REFUSED);
    }
  });

  it('exposes no generic apply(event) — only the two named origins', () => {
    const orchestrator = openOrchestrator();
    const surface = new Set<string>();
    let prototype: object | null = Object.getPrototypeOf(orchestrator) as object | null;
    while (prototype !== null && prototype !== Object.prototype) {
      for (const name of Object.getOwnPropertyNames(prototype)) {
        surface.add(name);
      }
      prototype = Object.getPrototypeOf(prototype) as object | null;
    }
    expect([...surface].sort()).toEqual([
      'admitRetirementAssessment',
      'constructor',
      'open',
      'openHumanGate',
      'reader',
    ]);
  });
});

/* ------------------------------------------------------------------------- *
 * The body, and what reaches the store
 * ------------------------------------------------------------------------- */

describe('the admitted body', () => {
  it('is digest-bound to its pointer', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    const envelope = result.envelope;
    expect(envelope).not.toBeNull();
    if (envelope !== null) {
      expect(sha256Canonical(envelope.body)).toBe(envelope.evidenceId);
    }
  });

  it('records the immutable configured identity verbatim', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(result.envelope?.body.repositoryId).toBe(REPOSITORY_ID);
    expect(result.envelope?.body.candidateRef).toBe(CANDIDATE_REF);
    expect(result.envelope?.body.candidateSha).toBe(CANDIDATE_SHA);
    expect(result.envelope?.body.authoritativeMainSha).toBe(MAIN_SHA);
  });

  it('carries all ten facts', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    const { result } = await runRetirementAssessment(orchestrator, baseConfig());
    expect(Object.keys(result.envelope?.body.facts ?? {})).toHaveLength(10);
  });

  it('never mutates the repository: only read-only argv is ever emitted', async () => {
    scriptEligibleGit();
    const orchestrator = openOrchestrator();
    await runRetirementAssessment(orchestrator, baseConfig());
    expect(gitScript.calls.length).toBeGreaterThan(0);
    const forbidden = ['fetch', 'push', 'commit', 'checkout', 'reset', 'branch', 'tag', 'merge'];
    for (const call of gitScript.calls) {
      for (const verb of forbidden) {
        expect(call, `write verb emitted: ${verb}`).not.toContain(verb);
      }
    }
  });
});
