import type {
  CockpitEvidenceReadModel,
  CockpitFindingReadModel,
  CockpitProvenance,
  CockpitPullRequestObservation,
  CockpitRepairJobReadModel,
  CockpitRepositoryObservation,
  CockpitSnapshot,
} from '../../src/cockpit/index.js';

export const REPO_A = 'github.com/LogicDuke/agentbridge';
export const HEAD_A = 'a'.repeat(40);
export const HEAD_B = 'b'.repeat(40);
export const COLLECTOR_A = 'collector-github-1';
export const OBSERVED_AT = '2026-08-21T10:00:00Z';

/**
 * Mutable-field builders. Overrides use `Partial` plus `unknown` casts at call
 * sites when a test deliberately supplies malformed values.
 */
export function buildRepository(
  overrides: Partial<CockpitRepositoryObservation> = {},
): CockpitRepositoryObservation {
  return {
    repositoryId: REPO_A,
    observedHeadSha: HEAD_A,
    defaultBranchRef: 'refs/heads/main',
    ...overrides,
  };
}

export function buildProvenance(overrides: Partial<CockpitProvenance> = {}): CockpitProvenance {
  return {
    collectorId: COLLECTOR_A,
    observedAt: OBSERVED_AT,
    ...overrides,
  };
}

export function buildPullRequest(
  overrides: Partial<CockpitPullRequestObservation> = {},
): CockpitPullRequestObservation {
  return {
    pullRequestId: '42',
    headSha: HEAD_A,
    baseRef: 'refs/heads/main',
    state: 'open',
    title: 'Autoflow state machine',
    ...overrides,
  };
}

export function buildEvidence(
  overrides: Partial<CockpitEvidenceReadModel> = {},
): CockpitEvidenceReadModel {
  return {
    evidenceId: 'evidence-1',
    kind: 'ci-result',
    source: 'github',
    commitSha: HEAD_A,
    reference: 'check-run-9001',
    observedAt: OBSERVED_AT,
    ...overrides,
  };
}

export function buildFinding(
  overrides: Partial<CockpitFindingReadModel> = {},
): CockpitFindingReadModel {
  return {
    findingId: 'f1',
    pullRequestId: '42',
    reviewedCommitSha: HEAD_A,
    provider: 'coderabbit',
    reviewerId: 'reviewer-1',
    severity: 'major',
    classification: 'correctness',
    status: 'open',
    title: 'Off-by-one in sequence bound',
    message: 'The upper bound admits one extra revision.',
    filePath: 'src/domain/policy-gate.ts',
    disposition: 'deferred',
    advisoryFreshness: 'STALE',
    ...overrides,
  };
}

export function buildRepairJob(
  overrides: Partial<CockpitRepairJobReadModel> = {},
): CockpitRepairJobReadModel {
  return {
    jobId: 'job-0001',
    parentPullRequestId: '42',
    findingId: 'f1',
    repairBranch: 'refs/heads/repair/job-0001',
    repairAgentId: 'repair-agent-1',
    independentValidatorId: 'validator-1',
    ...overrides,
  };
}

export function buildSnapshot(overrides: Partial<CockpitSnapshot> = {}): CockpitSnapshot {
  return {
    schemaVersion: 1,
    repository: buildRepository(),
    provenance: buildProvenance(),
    pullRequests: [buildPullRequest()],
    evidence: [buildEvidence()],
    findings: [buildFinding()],
    repairJobs: [buildRepairJob()],
    ...overrides,
  };
}
