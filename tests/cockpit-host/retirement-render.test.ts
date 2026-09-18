import { describe, expect, it } from 'vitest';

import { projectCockpitEvidenceFreshness } from '../../src/cockpit/evidence-freshness-projection.js';
import { COCKPIT_SNAPSHOT_SCHEMA_VERSION, readCockpitSnapshot } from '../../src/cockpit/read-model.js';
import type { CockpitSnapshot } from '../../src/cockpit/read-model.js';
import { renderDashboard } from '../../src/cockpit-host/render.js';
import { EVIDENCE_KIND } from '../../src/domain/evidence.js';
import {
  determinate,
  EVIDENCE_ID_PREFIX,
  GOVERNANCE_HOLD,
  RETIREMENT_CLASSIFICATION,
  RETIREMENT_REASON,
  toFactRecords,
  type RetirementFacts,
} from '../../src/domain/retirement-assessment.js';
import { sha256Canonical } from '../../src/runtime/retirement-assessment-store.js';

const REPOSITORY_ID = 'LogicDuke/agentbridge';
const CANDIDATE_SHA = 'a'.repeat(40);

function facts(): RetirementFacts {
  return {
    f1CandidateIdentity: determinate(true),
    f2RemoteAgreement: determinate(true),
    f3StableMain: determinate(true),
    f4Containment: determinate(true),
    f5UniqueCommits: determinate(0),
    f6UniquePatches: determinate(0),
    f7WorktreeClean: determinate(true),
    f8DependencyClearance: determinate(true),
    f9GovernanceManifest: determinate(GOVERNANCE_HOLD.NO_HOLD),
    f10NotProtected: determinate(true),
  };
}

function envelopeRaw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const body = {
    repositoryId: REPOSITORY_ID,
    candidateRef: 'refs/heads/repair/example',
    candidateSha: CANDIDATE_SHA,
    authoritativeMainSha: 'c'.repeat(40),
    facts: toFactRecords(facts()),
    classification: RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE,
    reasonCodes: [],
    gateRequested: true,
    manifestDigest: EVIDENCE_ID_PREFIX + 'd'.repeat(64),
    generatedAt: '2026-09-18T00:00:00.000Z',
    observerVersion: 'agentbridge-job1-observer/1',
    ...overrides,
  };
  const evidenceId = sha256Canonical(body);
  if (evidenceId === null) {
    throw new Error('fixture body must be canonicalizable');
  }
  return JSON.parse(JSON.stringify({ evidenceId, body })) as Record<string, unknown>;
}

function autoflowRaw(evidenceId: string | null): unknown {
  return {
    workflowId: 'wf-job1-0001',
    repositoryId: REPOSITORY_ID,
    pullRequestId: null,
    boundCommitSha: CANDIDATE_SHA,
    revision: 0,
    // Sequence counts applied transitions: an open with no admission is 0, and
    // one admitted assessment is 1. A workflow claiming otherwise is internally
    // inconsistent and the domain reader rejects it.
    sequence: evidenceId === null ? 0 : 1,
    status: 'OPEN',
    closureReason: null,
    humanGateOpenedAtRevision: null,
    invocations: [],
    evidence:
      evidenceId === null
        ? []
        : [
            {
              evidenceId,
              kind: EVIDENCE_KIND.REPOSITORY_STATE,
              admittedAtCommitSha: CANDIDATE_SHA,
              admittedAtRevision: 0,
              admittedAtSequence: 1,
            },
          ],
    reviews: [],
  };
}

/** Build a validated snapshot, or fail loudly — the renderer only sees valid ones. */
function snapshot(
  assessments: readonly unknown[],
  autoflow: unknown,
): CockpitSnapshot {
  const result = readCockpitSnapshot({
    schemaVersion: COCKPIT_SNAPSHOT_SCHEMA_VERSION,
    repository: {
      repositoryId: REPOSITORY_ID,
      observedHeadSha: CANDIDATE_SHA,
      defaultBranchRef: 'refs/heads/main',
    },
    provenance: { collectorId: 'test', observedAt: '2026-09-18T00:00:00.000Z' },
    pullRequests: [],
    evidence: [],
    findings: [],
    repairJobs: [],
    autoflow,
    retirementAssessments: assessments,
  });
  if (result.snapshot === null) {
    throw new Error(`fixture snapshot invalid: ${result.invalidFields.join(', ')}`);
  }
  return result.snapshot;
}

function render(assessments: readonly unknown[], autoflow: unknown): string {
  const validated = snapshot(assessments, autoflow);
  return renderDashboard(validated, projectCockpitEvidenceFreshness(validated), null, 'live');
}

describe('the retirement panel — projected assessment', () => {
  const item = envelopeRaw();
  const html = render([item], autoflowRaw(item['evidenceId'] as string));

  it('shows the classification, the candidate identity, and the manifest digest', () => {
    expect(html).toContain('Retirement assessment');
    expect(html).toContain(RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE);
    expect(html).toContain('refs/heads/repair/example');
    expect(html).toContain(CANDIDATE_SHA);
    expect(html).toContain(EVIDENCE_ID_PREFIX + 'd'.repeat(64));
  });

  it('shows every fact with its determinacy', () => {
    expect(html).toContain('f1CandidateIdentity');
    expect(html).toContain('f10NotProtected');
    expect(html).toContain('determinate');
  });

  it('says plainly that RETIRE_ELIGIBLE is not deletion authority', () => {
    expect(html).toContain('not deletion');
    expect(html).toContain('grants no mutation authority');
  });

  it('offers no control — describing an action is not offering one', () => {
    const panel = html.slice(html.indexOf('Retirement assessment'));
    expect(panel).not.toContain('<button');
    expect(panel).not.toContain('<form');
    expect(panel).not.toContain('<input');
    expect(panel).not.toContain('href="/retire');
  });
});

describe('the retirement panel — integrity failure', () => {
  const item = envelopeRaw();
  // The pointer is admitted, but the verified list is empty: I3 omitted the body.
  const html = render([], autoflowRaw(item['evidenceId'] as string));

  it('renders the exact Decision 065 copy', () => {
    expect(html).toContain('No verified assessment (integrity failure recorded)');
  });

  it('shows the pointer id', () => {
    expect(html).toContain(item['evidenceId'] as string);
  });

  it('WITHHOLDS the classification — never reinterpreting the failure as one', () => {
    const panel = html.slice(html.indexOf('Retirement assessment'));
    expect(panel).not.toContain('RETIRE_ELIGIBLE');
    expect(panel).not.toContain('PRESERVE_FOR_HISTORY');
    expect(panel).not.toContain('>BLOCKED<');
  });

  it('states that workflow state is unchanged and no authority was gained', () => {
    expect(html).toContain('Workflow state is unchanged');
    expect(html).toContain('gains no authority');
  });
});

describe('the retirement panel — non-eligible outcomes', () => {
  it('renders the open-but-inert copy for PRESERVE_FOR_HISTORY', () => {
    const item = envelopeRaw({
      classification: RETIREMENT_CLASSIFICATION.PRESERVE_FOR_HISTORY,
      gateRequested: false,
      reasonCodes: [RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT],
    });
    const html = render([item], autoflowRaw(item['evidenceId'] as string));
    expect(html).toContain('Assessment complete, no human gate open, Job #1 stopped');
    expect(html).toContain('No further');
    expect(html).toContain('no mutation is authorized');
    expect(html).toContain(RETIREMENT_REASON.UNIQUE_COMMITS_PRESENT);
  });

  it('renders the open-but-inert copy for BLOCKED', () => {
    const item = envelopeRaw({
      classification: RETIREMENT_CLASSIFICATION.BLOCKED,
      gateRequested: false,
      reasonCodes: [RETIREMENT_REASON.INDETERMINATE_FACT],
    });
    const html = render([item], autoflowRaw(item['evidenceId'] as string));
    expect(html).toContain('Job #1 stopped');
    expect(html).toContain(RETIREMENT_CLASSIFICATION.BLOCKED);
  });
});

describe('the retirement panel — honest absence', () => {
  it('shows no assessment, and invents no value, when none was admitted', () => {
    const html = render([], autoflowRaw(null));
    expect(html).toContain('No assessment observed');
    const panel = html.slice(html.indexOf('Retirement assessment'));
    expect(panel).not.toContain('RETIRE_ELIGIBLE');
    expect(panel).not.toContain('integrity failure');
  });

  it('shows no assessment when no workflow was observed at all', () => {
    const html = render([], null);
    expect(html).toContain('No assessment observed');
  });
});

describe('escaping', () => {
  it('renders hostile assessment text as inert escaped text', () => {
    const item = envelopeRaw({
      candidateRef: 'refs/heads/repair/x',
      observerVersion: '<script>alert(1)</script>',
    });
    const html = render([item], autoflowRaw(item['evidenceId'] as string));
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('adds no inline script, handler, or style to the document', () => {
    const item = envelopeRaw();
    const html = render([item], autoflowRaw(item['evidenceId'] as string));
    expect(html).not.toContain('<script');
    expect(html).not.toMatch(/\son\w+=/);
    expect(html).not.toMatch(/\sstyle="/);
  });
});
