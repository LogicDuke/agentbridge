/**
 * Live-composition tests for the Autoflow Orchestration Controller milestone.
 *
 * These wire the production shape by hand — one AutoflowRuntime, one
 * AutoflowOrchestrator owning its writer, the Cockpit handed only the reader —
 * and prove a bounded startup open flows through the *same* runtime to the live
 * Cockpit. Manually calling these APIs is a boundary test; it is NOT autonomous
 * production behavior. Nothing here originates any post-start WorkflowEvent.
 */

import http from 'node:http';
import type { AddressInfo } from 'node:net';

import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Fake git for the Job #1 arm of the exclusivity matrix (G3/G4): a per-argv
 * response table keyed by the first token of the vector, exactly as the Job #1
 * runner suite scripts it. No real process is ever spawned, so G3/G4 are
 * deterministic and carry no network or repository dependency.
 */
const gitScript = vi.hoisted(() => ({
  table: {} as Record<string, { exitCode: number; stdout: string }>,
}));

vi.mock('../../src/adapters/process-transport.js', () => ({
  invokeAgentProcess: (spec: { args: readonly string[] }): Promise<unknown> => {
    const key = spec.args[0] === '-C' ? 'status' : (spec.args[0] ?? '');
    const scripted = gitScript.table[key] ?? { exitCode: 0, stdout: '' };
    return Promise.resolve({
      outcome: 'EXITED',
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

import { AutoflowRuntime } from '../../src/autoflow/runtime.js';
import { AutoflowOrchestrator } from '../../src/autoflow/orchestrator.js';
import {
  JOB1_ENV,
  readStartupWorkflowConfig,
  STARTUP_HUMAN_GATE_ENV,
  WORKFLOW_OPEN_ENV,
} from '../../src/runtime/orchestration-input.js';
import {
  createLiveCockpitSource,
  runStartupProgression,
  startLiveCockpit,
  type LiveCockpitConfig,
} from '../../src/runtime/live-cockpit.js';
import { runRetirementAssessment } from '../../src/runtime/retirement-assessment-runner.js';
import {
  EVIDENCE_ID_PREFIX,
  GOVERNANCE_HOLD,
  RETIREMENT_CLASSIFICATION,
} from '../../src/domain/retirement-assessment.js';
import { readGovernanceRunManifest } from '../../src/runtime/retirement-manifest.js';
import { sha256Canonical } from '../../src/runtime/retirement-assessment-store.js';
import { createConfiguredRepositoryObserver } from '../../src/runtime/repository-observer.js';
import { readCockpitSnapshot } from '../../src/cockpit/index.js';
import { TRANSITION_OUTCOME, TRANSITION_REJECTION } from '../../src/domain/index.js';

const REPO = 'repo-agentbridge';
const SHA_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678';
const FIXED_ISO = '2026-09-05T13:00:00.000Z';

const observer = createConfiguredRepositoryObserver({
  repositoryId: REPO,
  observedHeadSha: SHA_A,
  defaultBranchRef: 'refs/heads/main',
});

function configFrom(reader: LiveCockpitConfig['reader']): LiveCockpitConfig {
  return { reader, observer, collectorId: 'agentbridge-live-runtime', clock: (): Date => new Date(FIXED_ISO) };
}

// A production-shaped composition: one runtime, one orchestrator, optional open.
function compose(startupEnv: Record<string, string | undefined>): {
  reader: LiveCockpitConfig['reader'];
  openedOutcome: string | null;
} {
  const runtime = new AutoflowRuntime();
  const orchestrator = new AutoflowOrchestrator(runtime);
  const binding = readStartupWorkflowConfig(startupEnv, REPO);
  let openedOutcome: string | null = null;
  if (binding !== null) {
    openedOutcome = orchestrator.open(binding).outcome;
  }
  return { reader: orchestrator.reader(), openedOutcome };
}

const openConfig = {
  [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-startup-0001',
  [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA_A,
};

const openServers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (s) =>
        new Promise<void>((resolve) => {
          s.close(() => {
            resolve();
          });
        }),
    ),
  );
});
function waitListening(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('listening', () => {
      const a = server.address();
      if (a === null || typeof a === 'string') reject(new Error('no port'));
      else resolve(a.port);
    });
    server.once('error', reject);
  });
}
function get(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => {
        chunks.push(c);
      });
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

describe('live composition — startup-open flows through one runtime to the Cockpit', () => {
  it('no startup config → autoflow stays null (honest no-workflow)', () => {
    const { reader, openedOutcome } = compose({});
    expect(openedOutcome).toBeNull();
    expect(reader.current()).toBeNull();
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(reader)).read());
    expect(read.snapshot).not.toBeNull();
    expect(read.snapshot?.autoflow).toBeNull();
  });

  it('valid startup config → exactly one workflow, reflected through D1 identity/status/revision/sequence', () => {
    const { reader, openedOutcome } = compose(openConfig);
    expect(openedOutcome).toBe(TRANSITION_OUTCOME.APPLIED);
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(reader)).read());
    const autoflow = read.snapshot?.autoflow;
    expect(autoflow).not.toBeNull();
    expect(autoflow?.workflowId).toBe('wf-startup-0001');
    expect(autoflow?.repositoryId).toBe(REPO);
    expect(autoflow?.status).toBe('OPEN');
    expect(autoflow?.revision).toBe(0);
    expect(autoflow?.sequence).toBe(0);
  });

  it('the Cockpit-facing reader cannot open or apply', () => {
    const { reader } = compose(openConfig);
    const asRecord = reader as unknown as Record<string, unknown>;
    expect('open' in reader).toBe(false);
    expect('apply' in reader).toBe(false);
    expect(asRecord['open']).toBeUndefined();
    expect(asRecord['apply']).toBeUndefined();
  });

  it('GET / serves a LIVE 200 page on loopback with the startup workflow, no fixture', async () => {
    const { reader } = compose(openConfig);
    const server = startLiveCockpit({ config: configFrom(reader), port: 0 });
    openServers.push(server);
    const port = await waitListening(server);
    const address = server.address() as AddressInfo;
    expect(address.address).toBe('127.0.0.1');
    const res = await get(port, '/');
    expect(res.status).toBe(200);
    expect(res.body).toMatch(/>LIVE</);
    expect(res.body).not.toMatch(/FIXTURE/); // uppercase provenance marker absent
    // The populated Autoflow panel no longer shows the no-workflow placeholder.
    expect(res.body).not.toContain('Not projected yet');
  });

  it('restart honesty: a fresh composition after a prior active workflow begins null', () => {
    // First composition opens a workflow...
    const first = compose(openConfig);
    expect(first.reader.current()).not.toBeNull();
    // ...a fresh runtime/composition (simulating process restart) with no config
    // starts empty. No persistence, no recovery, no replay.
    const second = compose({});
    expect(second.reader.current()).toBeNull();
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(second.reader)).read());
    expect(read.snapshot?.autoflow).toBeNull();
  });

  it('malformed startup binding → open REJECTED (composition would fail closed)', () => {
    const { openedOutcome } = compose({
      [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: '', // present-but-empty → domain rejects
      [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA_A,
    });
    expect(openedOutcome).toBe(TRANSITION_OUTCOME.REJECTED);
  });
});

describe('runStartupProgression — Decision 061 startup-scripted human-gate boot flow', () => {
  // Exercise the exact production boot progression directly (no process.exit).
  function progress(startupEnv: Record<string, string | undefined>): LiveCockpitConfig['reader'] {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime());
    runStartupProgression(orchestrator, startupEnv, REPO);
    return orchestrator.reader();
  }

  it('valid startup-open + gate absent → OPEN', () => {
    const reader = progress(openConfig);
    expect(reader.current()?.status).toBe('OPEN');
    expect(reader.current()?.sequence).toBe(0);
  });

  it('valid startup-open + gate "1" → AWAITING_HUMAN_DECISION at sequence 1, gate revision 0', () => {
    const reader = progress({ ...openConfig, [STARTUP_HUMAN_GATE_ENV]: '1' });
    expect(reader.current()?.status).toBe('AWAITING_HUMAN_DECISION');
    expect(reader.current()?.sequence).toBe(1);
    expect(reader.current()?.humanGateOpenedAtRevision).toBe(0);
  });

  it('neither configured → no workflow (current() stays null)', () => {
    const reader = progress({});
    expect(reader.current()).toBeNull();
  });

  it('gate "1" WITHOUT a valid startup-open → startup-fatal (throws before serving)', () => {
    expect(() => progress({ [STARTUP_HUMAN_GATE_ENV]: '1' })).toThrow();
    // Partial open + gate is likewise fatal (partial open throws first).
    expect(() =>
      progress({ [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-x', [STARTUP_HUMAN_GATE_ENV]: '1' }),
    ).toThrow();
  });

  it('invalid gate value → startup-fatal before any open or serving', () => {
    expect(() => progress({ ...openConfig, [STARTUP_HUMAN_GATE_ENV]: 'true' })).toThrow();
    expect(() => progress({ ...openConfig, [STARTUP_HUMAN_GATE_ENV]: '0' })).toThrow();
  });

  it('non-APPLIED startup open → startup-fatal (throws), gate never reached', () => {
    // Present-but-empty workflowId → domain open REJECTED → progression throws.
    expect(() =>
      progress({
        [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: '',
        [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: SHA_A,
        [STARTUP_HUMAN_GATE_ENV]: '1',
      }),
    ).toThrow();
  });

  it('gate progression is reflected LIVE through the reader → D1 snapshot as AWAITING_HUMAN_DECISION', () => {
    const reader = progress({ ...openConfig, [STARTUP_HUMAN_GATE_ENV]: '1' });
    const read = readCockpitSnapshot(createLiveCockpitSource(configFrom(reader)).read());
    expect(read.snapshot?.autoflow?.status).toBe('AWAITING_HUMAN_DECISION');
  });
});

/* ------------------------------------------------------------------------- *
 * INV-STARTUP-GATE-EXCLUSIVITY  (G1-G8)
 *
 * A boot may configure at most one production HUMAN_GATE_OPENED origin. The
 * Decision 061 startup gate and the Decision 065 Job #1 run are mutually
 * incompatible in one boot, and the combination is refused by
 * `runStartupProgression` before `orchestrator.open(...)`, before any gate
 * transition, and before Job #1 could run.
 * ------------------------------------------------------------------------- */

const JOB1_REPOSITORY_ID = 'LogicDuke/agentbridge';
const JOB1_CANDIDATE_REF = 'refs/heads/repair/example';
const JOB1_SHORT_NAME = 'repair/example';
const JOB1_CANDIDATE_SHA = 'a'.repeat(40);
const JOB1_MAIN_SHA = 'c'.repeat(40);
const JOB1_GENERATED_AT = '2026-09-18T06:00:00.000Z';
const JOB1_BOOT_MS = Date.UTC(2026, 8, 18, 12, 0, 0);

/**
 * A stand-in "git executable": a real file whose bytes the observer hashes at
 * boot (Amendment 1 A-6). It is never spawned - the transport is mocked.
 */
const FAKE_GIT_PATH = join(mkdtempSync(join(tmpdir(), 'ab-gate-excl-')), 'git-stub');
writeFileSync(FAKE_GIT_PATH, 'not really git');
const FAKE_GIT_SHA256 =
  'sha256:' + createHash('sha256').update('not really git', 'utf8').digest('hex');

/** A schema-valid, correctly-digested governance run manifest. */
function signedManifest(): { readonly text: string; readonly digest: string } {
  const object: Record<string, unknown> = {
    candidateRef: JOB1_CANDIDATE_REF,
    candidateSha: JOB1_CANDIDATE_SHA,
    authoritativeMainSha: JOB1_MAIN_SHA,
    generatedAt: JOB1_GENERATED_AT,
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
  };
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
function clearGitHub(): NonNullable<Parameters<typeof runRetirementAssessment>[1]['githubGet']> {
  const table: Record<string, { status: number; body: string }> = {
    '/repos/LogicDuke/agentbridge': {
      status: 200,
      body: JSON.stringify({ default_branch: 'main' }),
    },
    '/repos/LogicDuke/agentbridge/pulls?state=open&per_page=100': { status: 200, body: '[]' },
    '/repos/LogicDuke/agentbridge/issues?state=open&per_page=100': { status: 200, body: '[]' },
    '/repos/LogicDuke/agentbridge/branches/repair%2Fexample': {
      status: 200,
      body: JSON.stringify({
        name: JOB1_SHORT_NAME,
        commit: { sha: JOB1_CANDIDATE_SHA },
        protected: false,
      }),
    },
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
    'rev-parse': { exitCode: 0, stdout: JOB1_CANDIDATE_SHA + '\n' },
    'ls-remote': {
      exitCode: 0,
      stdout: `${JOB1_CANDIDATE_SHA}\t${JOB1_CANDIDATE_REF}\n${JOB1_MAIN_SHA}\trefs/heads/main\n`,
    },
    'merge-base': { exitCode: 0, stdout: '' },
    'rev-list': { exitCode: 0, stdout: '0\n' },
    cherry: { exitCode: 0, stdout: '' },
    worktree: { exitCode: 0, stdout: '' },
    status: { exitCode: 0, stdout: '' },
    'for-each-ref': { exitCode: 0, stdout: 'refs/heads/main\trefs/remotes/origin/main\n' },
  };
}

function job1RunConfig(): Parameters<typeof runRetirementAssessment>[1] {
  const manifest = signedManifest();
  return {
    repositoryId: JOB1_REPOSITORY_ID,
    owner: 'LogicDuke',
    repo: 'agentbridge',
    candidateRef: JOB1_CANDIDATE_REF,
    candidateSha: JOB1_CANDIDATE_SHA,
    authoritativeMainSha: JOB1_MAIN_SHA,
    repositoryPath: 'C:\\repo',
    runtimeRoot: 'C:\\runtime',
    manifestPath: 'C:\\manifest.json',
    manifestDigest: manifest.digest,
    manifestText: manifest.text,
    generatedAt: JOB1_GENERATED_AT,
    bootEpochMs: JOB1_BOOT_MS,
    platform: 'win32',
    environmentSource: {},
    githubGet: clearGitHub(),
  };
}

/** The startup-open binding Job #1 admission is bound against. */
const job1OpenConfig = {
  [WORKFLOW_OPEN_ENV.WORKFLOW_ID]: 'wf-job1-0001',
  [WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA]: JOB1_CANDIDATE_SHA,
};

/** The complete Job #1 environment block (presence of ENABLED is the trigger). */
const job1EnvBlock = {
  [JOB1_ENV.ENABLED]: '1',
  [JOB1_ENV.CANDIDATE_REF]: JOB1_CANDIDATE_REF,
  [JOB1_ENV.CANDIDATE_SHA]: JOB1_CANDIDATE_SHA,
  [JOB1_ENV.MAIN_SHA]: JOB1_MAIN_SHA,
  [JOB1_ENV.REPOSITORY_PATH]: 'C:\\repo',
  [JOB1_ENV.RUNTIME_ROOT]: 'C:\\runtime',
  [JOB1_ENV.MANIFEST_PATH]: 'C:\\manifest.json',
  [JOB1_ENV.MANIFEST_SHA256]: 'sha256:' + '9'.repeat(64),
  [JOB1_ENV.GENERATED_AT]: JOB1_GENERATED_AT,
};

describe('INV-STARTUP-GATE-EXCLUSIVITY - startup gate vs Job #1 (G1-G8)', () => {
  beforeEach(() => {
    gitScript.table = {};
  });

  /** Boot exactly as `main` does: the progression, through the one writer. */
  function bootProgression(
    startupEnv: Record<string, string | undefined>,
    repositoryId = JOB1_REPOSITORY_ID,
  ): AutoflowOrchestrator {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime(), JOB1_CANDIDATE_REF);
    runStartupProgression(orchestrator, startupEnv, repositoryId);
    return orchestrator;
  }

  it('G1: startup gate OFF + Job #1 OFF -> normal startup', () => {
    const orchestrator = bootProgression(job1OpenConfig);
    const state = orchestrator.reader().current();
    expect(state?.status).toBe('OPEN');
    expect(state?.sequence).toBe(0);
    expect(state?.humanGateOpenedAtRevision).toBeNull();
  });

  it('G2: startup gate ON + Job #1 OFF -> Decision-061 behavior preserved', () => {
    const orchestrator = bootProgression({
      ...job1OpenConfig,
      [STARTUP_HUMAN_GATE_ENV]: '1',
    });
    const state = orchestrator.reader().current();
    expect(state?.status).toBe('AWAITING_HUMAN_DECISION');
    expect(state?.sequence).toBe(1);
    expect(state?.humanGateOpenedAtRevision).toBe(0);
  });

  it('G3: startup gate OFF + Job #1 ON + RETIRE_ELIGIBLE -> the Job #1 gate opens normally', async () => {
    scriptEligibleGit();
    const orchestrator = bootProgression({ ...job1OpenConfig, ...job1EnvBlock });
    // The progression itself opened no gate: the Job #1 origin is the only one.
    expect(orchestrator.reader().current()?.status).toBe('OPEN');

    const { result } = await runRetirementAssessment(orchestrator, job1RunConfig());
    expect(result.abort).toBeNull();
    expect(result.envelope?.body.classification).toBe(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE);
    expect(result.gateOpened).toBe(true);

    const state = orchestrator.reader().current();
    expect(state?.status).toBe('AWAITING_HUMAN_DECISION');
    expect(state?.sequence).toBe(2);
  });

  it('G4: startup gate OFF + Job #1 ON + non-eligible -> no gate opened', async () => {
    scriptEligibleGit();
    // Not contained, carrying unique commits and patches -> PRESERVE_FOR_HISTORY.
    gitScript.table['merge-base'] = { exitCode: 1, stdout: '' };
    gitScript.table['rev-list'] = { exitCode: 0, stdout: '3\n' };
    gitScript.table['cherry'] = { exitCode: 0, stdout: '+ aaa\n+ bbb\n' };

    const orchestrator = bootProgression({ ...job1OpenConfig, ...job1EnvBlock });
    const { result } = await runRetirementAssessment(orchestrator, job1RunConfig());
    expect(result.abort).toBeNull();
    expect(result.envelope?.body.classification).toBe(
      RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY,
    );
    expect(result.gateOpened).toBe(false);

    const state = orchestrator.reader().current();
    expect(state?.status).toBe('OPEN');
    expect(state?.sequence).toBe(1);
    expect(state?.humanGateOpenedAtRevision).toBeNull();
  });

  it('G5: startup gate ON + Job #1 ON -> throws before any workflow open or gate transition', () => {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime(), JOB1_CANDIDATE_REF);
    expect(() => {
      runStartupProgression(
        orchestrator,
        { ...job1OpenConfig, ...job1EnvBlock, [STARTUP_HUMAN_GATE_ENV]: '1' },
        JOB1_REPOSITORY_ID,
      );
    }).toThrow(/incompatible/);
    // State is untouched: no workflow was opened, so there is nothing to gate.
    expect(orchestrator.reader().current()).toBeNull();
  });

  it('G6: startup gate ON + Job #1 ON but Job #1 config incomplete -> still throws on incompatibility', () => {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime(), JOB1_CANDIDATE_REF);
    // Only the trigger is present; every other Job #1 variable is missing. The
    // guard tests presence alone, so the incompatibility is still refused first.
    expect(() => {
      runStartupProgression(
        orchestrator,
        { ...job1OpenConfig, [JOB1_ENV.ENABLED]: '1', [STARTUP_HUMAN_GATE_ENV]: '1' },
        JOB1_REPOSITORY_ID,
      );
    }).toThrow(/incompatible/);
    expect(orchestrator.reader().current()).toBeNull();

    // An out-of-contract trigger value is likewise refused before any transition.
    const other = new AutoflowOrchestrator(new AutoflowRuntime(), JOB1_CANDIDATE_REF);
    expect(() => {
      runStartupProgression(
        other,
        { ...job1OpenConfig, [JOB1_ENV.ENABLED]: '0', [STARTUP_HUMAN_GATE_ENV]: '1' },
        JOB1_REPOSITORY_ID,
      );
    }).toThrow(/incompatible/);
    expect(other.reader().current()).toBeNull();
  });

  it('G7: startup gate ON + Job #1 OFF but startup binding missing -> existing misconfiguration behavior', () => {
    const orchestrator = new AutoflowOrchestrator(new AutoflowRuntime(), JOB1_CANDIDATE_REF);
    expect(() => {
      runStartupProgression(orchestrator, { [STARTUP_HUMAN_GATE_ENV]: '1' }, JOB1_REPOSITORY_ID);
    }).toThrow(/requires a valid startup/);
    expect(orchestrator.reader().current()).toBeNull();
  });

  it('G8: a direct second gate open remains REJECTED / HUMAN_GATE_ALREADY_OPEN', () => {
    const orchestrator = bootProgression({
      ...job1OpenConfig,
      [STARTUP_HUMAN_GATE_ENV]: '1',
    });
    const before = orchestrator.reader().current();
    const second = orchestrator.openHumanGate();
    expect(second.outcome).toBe(TRANSITION_OUTCOME.REJECTED);
    expect(second.rejection).toBe(TRANSITION_REJECTION.HUMAN_GATE_ALREADY_OPEN);
    // The domain refusal leaves the state unchanged; it is not reinterpreted.
    const after = orchestrator.reader().current();
    expect(after?.sequence).toBe(before?.sequence);
    expect(after?.revision).toBe(before?.revision);
    expect(after?.status).toBe('AWAITING_HUMAN_DECISION');
  });
});
