import { describe, expect, it } from 'vitest';

import {
  COCKPIT_BOUNDS,
  COCKPIT_FINDING_DISPOSITION,
  COCKPIT_FINDING_DISPOSITIONS,
  COCKPIT_PULL_REQUEST_STATE,
  COCKPIT_PULL_REQUEST_STATES,
  COCKPIT_SNAPSHOT_FIELD_ORDER,
  COCKPIT_SNAPSHOT_SCHEMA_VERSION,
  EVIDENCE_KINDS,
  EVIDENCE_SOURCES,
  FRESHNESS,
  FRESHNESS_STATES,
  readCockpitFindingDisposition,
  readCockpitPullRequestState,
  readCockpitSnapshot,
  REVIEW_BOUNDS,
  REVIEW_SEVERITIES,
  type CockpitSnapshot,
} from '../../src/index.js';
import {
  buildEvidence,
  buildFinding,
  buildProvenance,
  buildPullRequest,
  buildRepairJob,
  buildRepository,
  buildSnapshot,
  HEAD_A,
  OBSERVED_AT,
  REPO_A,
} from './read-model-fixtures.js';

describe('valid snapshot construction', () => {
  it('accepts a fully populated snapshot and echoes every field', () => {
    const result = readCockpitSnapshot(buildSnapshot());

    expect(result.invalidFields).toEqual([]);
    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      return;
    }
    expect(snapshot.schemaVersion).toBe(COCKPIT_SNAPSHOT_SCHEMA_VERSION);
    expect(snapshot.repository.repositoryId).toBe(REPO_A);
    expect(snapshot.repository.observedHeadSha).toBe(HEAD_A);
    expect(snapshot.repository.defaultBranchRef).toBe('refs/heads/main');
    expect(snapshot.provenance.collectorId).toBe('collector-github-1');
    expect(snapshot.provenance.observedAt).toBe(OBSERVED_AT);
    expect(snapshot.pullRequests).toHaveLength(1);
    expect(snapshot.pullRequests[0]?.state).toBe(COCKPIT_PULL_REQUEST_STATE.OPEN);
    expect(snapshot.evidence).toHaveLength(1);
    expect(snapshot.evidence[0]?.kind).toBe('ci-result');
    expect(snapshot.findings).toHaveLength(1);
    expect(snapshot.findings[0]?.severity).toBe('major');
    expect(snapshot.findings[0]?.disposition).toBe(COCKPIT_FINDING_DISPOSITION.DEFERRED);
    expect(snapshot.findings[0]?.advisoryFreshness).toBe(FRESHNESS.STALE);
    expect(snapshot.repairJobs).toHaveLength(1);
    expect(snapshot.repairJobs[0]?.repairBranch).toBe('refs/heads/repair/job-0001');
  });

  it('accepts empty observation lists: a quiet repository is a valid snapshot', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({ pullRequests: [], evidence: [], findings: [], repairJobs: [] }),
    );

    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot?.pullRequests).toEqual([]);
    expect(result.snapshot?.findings).toEqual([]);
  });

  it('treats absent optional fields as null, distinct from malformed ones', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({
        repository: buildRepository({ defaultBranchRef: null }),
        pullRequests: [buildPullRequest({ baseRef: null, title: null })],
        findings: [buildFinding({ filePath: null, advisoryFreshness: null })],
      }),
    );

    expect(result.invalidFields).toEqual([]);
    expect(result.snapshot?.repository.defaultBranchRef).toBeNull();
    expect(result.snapshot?.pullRequests[0]?.baseRef).toBeNull();
    expect(result.snapshot?.pullRequests[0]?.title).toBeNull();
    expect(result.snapshot?.findings[0]?.filePath).toBeNull();
    expect(result.snapshot?.findings[0]?.advisoryFreshness).toBeNull();
  });
});

describe('malformed input is rejected deterministically', () => {
  it('rejects non-object values with every field reported, never throwing', () => {
    for (const value of [null, undefined, 0, 1, '', 'snapshot', true, false, Symbol('x'), 123n]) {
      const result = readCockpitSnapshot(value);
      expect(result.snapshot).toBeNull();
      expect(result.invalidFields).toEqual(COCKPIT_SNAPSHOT_FIELD_ORDER);
    }
  });

  it('rejects any schema version other than the one this reader defines', () => {
    // Version 2 is now the sole supported version; 1 is a superseded shape and,
    // like every other non-2 value, is rejected whole.
    for (const schemaVersion of [0, 1, 3, '2', 1.5, null, undefined, {}]) {
      const result = readCockpitSnapshot(
        buildSnapshot({ schemaVersion: schemaVersion as never }),
      );
      expect(result.snapshot).toBeNull();
      expect(result.invalidFields).toContain('schemaVersion');
    }
  });

  it('rejects blank and missing provenance and repository identity', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({
        repository: buildRepository({ repositoryId: '   ', observedHeadSha: '' }),
        provenance: { collectorId: '  ' } as never,
      }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual([
      'repository.repositoryId',
      'repository.observedHeadSha',
      'provenance.collectorId',
      'provenance.observedAt',
    ]);
  });

  it('rejects a present-but-malformed optional field instead of folding it to null', () => {
    const badRef = readCockpitSnapshot(
      buildSnapshot({ repository: buildRepository({ defaultBranchRef: 'main' }) }),
    );
    expect(badRef.snapshot).toBeNull();
    expect(badRef.invalidFields).toEqual(['repository.defaultBranchRef']);

    const badTitle = readCockpitSnapshot(
      buildSnapshot({ pullRequests: [buildPullRequest({ title: 42 as never })] }),
    );
    expect(badTitle.snapshot).toBeNull();
    expect(badTitle.invalidFields).toEqual(['pullRequests']);
  });

  it('rejects the whole snapshot when one list element is malformed', () => {
    const cases: readonly Partial<CockpitSnapshot>[] = [
      { pullRequests: [buildPullRequest({ pullRequestId: '' })] },
      { evidence: [buildEvidence({ kind: 'gossip' as never })] },
      { evidence: [buildEvidence({ source: 'trust-me' as never })] },
      { findings: [buildFinding({ title: '   ' })] },
      { findings: [buildFinding({ reviewedCommitSha: undefined as never })] },
      { repairJobs: [buildRepairJob({ repairBranch: 'main' })] },
      { repairJobs: [42 as never] },
    ];
    for (const overrides of cases) {
      const result = readCockpitSnapshot(buildSnapshot(overrides));
      expect(result.snapshot).toBeNull();
      expect(result.invalidFields).toHaveLength(1);
    }
  });

  it('rejects an oversized list rather than truncating it', () => {
    const findings = Array.from({ length: COCKPIT_BOUNDS.MAX_FINDINGS + 1 }, (_, index) =>
      buildFinding({ findingId: `f${String(index)}` }),
    );
    const result = readCockpitSnapshot(buildSnapshot({ findings }));

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['findings']);
  });

  it('rejects an oversized identifier rather than truncating it', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({
        provenance: buildProvenance({ collectorId: 'c'.repeat(257) }),
      }),
    );

    expect(result.snapshot).toBeNull();
    expect(result.invalidFields).toEqual(['provenance.collectorId']);
  });
});

describe('vocabulary folding fails closed', () => {
  it('folds an unrecognised pull-request state to unknown, never rejecting', () => {
    expect(readCockpitPullRequestState('draft')).toBe(COCKPIT_PULL_REQUEST_STATE.UNKNOWN);
    expect(readCockpitPullRequestState(undefined)).toBe(COCKPIT_PULL_REQUEST_STATE.UNKNOWN);
    expect(readCockpitPullRequestState(1)).toBe(COCKPIT_PULL_REQUEST_STATE.UNKNOWN);

    const result = readCockpitSnapshot(
      buildSnapshot({ pullRequests: [buildPullRequest({ state: 'DRAFT' as never })] }),
    );
    expect(result.snapshot?.pullRequests[0]?.state).toBe(COCKPIT_PULL_REQUEST_STATE.UNKNOWN);
  });

  it('folds an unrecognised disposition to unspecified', () => {
    expect(readCockpitFindingDisposition('blocking')).toBe(
      COCKPIT_FINDING_DISPOSITION.UNSPECIFIED,
    );
    expect(readCockpitFindingDisposition(undefined)).toBe(
      COCKPIT_FINDING_DISPOSITION.UNSPECIFIED,
    );
  });

  it('folds unrecognised severity, classification, and status through the domain readers', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({
        findings: [
          buildFinding({
            severity: 'catastrophic' as never,
            classification: 'vibes' as never,
            status: 'wontfix' as never,
          }),
        ],
      }),
    );

    expect(result.snapshot?.findings[0]?.severity).toBe('unknown');
    expect(result.snapshot?.findings[0]?.classification).toBe('unknown');
    expect(result.snapshot?.findings[0]?.status).toBe('unknown');
  });
});

describe('freshness and disposition are distinct axes', () => {
  it('shares no member between the disposition and freshness vocabularies', () => {
    for (const disposition of COCKPIT_FINDING_DISPOSITIONS) {
      expect(FRESHNESS_STATES).not.toContain(disposition);
    }
    for (const state of FRESHNESS_STATES) {
      expect(COCKPIT_FINDING_DISPOSITIONS).not.toContain(state);
    }
  });

  it('never accepts a freshness state as a disposition, or a disposition as freshness', () => {
    expect(readCockpitFindingDisposition('CURRENT')).toBe(
      COCKPIT_FINDING_DISPOSITION.UNSPECIFIED,
    );
    expect(readCockpitFindingDisposition('STALE')).toBe(COCKPIT_FINDING_DISPOSITION.UNSPECIFIED);

    const result = readCockpitSnapshot(
      buildSnapshot({ findings: [buildFinding({ advisoryFreshness: 'deferred' as never })] }),
    );
    expect(result.snapshot?.findings[0]?.advisoryFreshness).toBeNull();
    expect(result.snapshot?.findings[0]?.disposition).toBe(
      COCKPIT_FINDING_DISPOSITION.DEFERRED,
    );
  });

  it('folds an unrecognised advisory freshness to null, never to a state', () => {
    for (const value of ['current', 'FRESH', 1, true, {}]) {
      const result = readCockpitSnapshot(
        buildSnapshot({ findings: [buildFinding({ advisoryFreshness: value as never })] }),
      );
      expect(result.snapshot?.findings[0]?.advisoryFreshness).toBeNull();
    }
  });

  it('carries enough data to recompute freshness instead of trusting the echo', () => {
    const result = readCockpitSnapshot(
      buildSnapshot({ findings: [buildFinding({ advisoryFreshness: 'CURRENT' })] }),
    );
    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    // The finding's bound commit and the envelope's observed HEAD are both
    // present, which is exactly what the domain freshness kernel needs.
    expect(snapshot?.findings[0]?.reviewedCommitSha).toBe(HEAD_A);
    expect(snapshot?.repository.observedHeadSha).toBe(HEAD_A);
  });
});

describe('domain vocabulary reuse', () => {
  it('validates evidence kind and source against the domain vocabularies', () => {
    for (const kind of EVIDENCE_KINDS) {
      const result = readCockpitSnapshot(buildSnapshot({ evidence: [buildEvidence({ kind })] }));
      expect(result.snapshot?.evidence[0]?.kind).toBe(kind);
    }
    for (const source of EVIDENCE_SOURCES) {
      const result = readCockpitSnapshot(
        buildSnapshot({ evidence: [buildEvidence({ source })] }),
      );
      expect(result.snapshot?.evidence[0]?.source).toBe(source);
    }
  });

  it('accepts every domain review severity unchanged', () => {
    for (const severity of REVIEW_SEVERITIES) {
      const result = readCockpitSnapshot(
        buildSnapshot({ findings: [buildFinding({ severity })] }),
      );
      expect(result.snapshot?.findings[0]?.severity).toBe(severity);
    }
  });

  it('pins the finding capacity to the ingestion bound it re-presents', () => {
    expect(COCKPIT_BOUNDS.MAX_FINDINGS).toBe(REVIEW_BOUNDS.MAX_FINDINGS);
  });
});

describe('immutability and serialization', () => {
  it('freezes the result, the snapshot, and every nested record and list', () => {
    const result = readCockpitSnapshot(buildSnapshot());
    const snapshot = result.snapshot;
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      return;
    }

    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.invalidFields)).toBe(true);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.repository)).toBe(true);
    expect(Object.isFrozen(snapshot.provenance)).toBe(true);
    for (const list of [
      snapshot.pullRequests,
      snapshot.evidence,
      snapshot.findings,
      snapshot.repairJobs,
    ]) {
      expect(Object.isFrozen(list)).toBe(true);
      for (const element of list) {
        expect(Object.isFrozen(element)).toBe(true);
      }
    }
  });

  it('freezes the vocabulary constants themselves', () => {
    for (const constant of [
      COCKPIT_BOUNDS,
      COCKPIT_FINDING_DISPOSITION,
      COCKPIT_FINDING_DISPOSITIONS,
      COCKPIT_PULL_REQUEST_STATE,
      COCKPIT_PULL_REQUEST_STATES,
      COCKPIT_SNAPSHOT_FIELD_ORDER,
    ]) {
      expect(Object.isFrozen(constant)).toBe(true);
    }
  });

  it('survives a plain-JSON round trip and re-reads to an equal snapshot', () => {
    const first = readCockpitSnapshot(buildSnapshot()).snapshot;
    expect(first).not.toBeNull();

    const serialized = JSON.stringify(first);
    const revived: unknown = JSON.parse(serialized);
    const second = readCockpitSnapshot(revived);

    expect(second.invalidFields).toEqual([]);
    expect(second.snapshot).toEqual(first);
  });
});
