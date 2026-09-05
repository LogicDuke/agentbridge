/**
 * Deterministic Stage-A fixture for the Cockpit D3 dashboard host.
 *
 * This is **not live data**. It is a hand-authored snapshot shaped like the
 * JSON a future collector would emit, deliberately typed as `unknown`: the host
 * must pass it through D1's `readCockpitSnapshot()` before rendering any value,
 * exactly as it would treat real collector output. Nothing here is trusted by
 * virtue of living in the source tree.
 *
 * The fixture intentionally includes hostile prose (script tags, an
 * `onerror` image payload, raw `&`/`<`/`>`/quotes) in reviewer-controlled title
 * and message fields. Those strings are legitimate bounded text to D1, so they
 * pass validation and reach the renderer, where they must appear only as inert
 * escaped text — the property the host's escaping tests assert.
 *
 * The SHAs are obvious fixtures (`c0ffee…`, `dead0…`), not any real repository
 * HEAD, so the page can never be mistaken for a live observation. Evidence bound
 * to the observed HEAD projects as `CURRENT`; evidence bound to the older SHA
 * projects as `STALE`, giving D2 a non-trivial mix to display.
 */

/** The fixture's observed HEAD. Evidence bound here projects CURRENT. */
const HEAD_SHA = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';
/** An older commit. Evidence bound here projects STALE. */
const OLD_SHA = 'dead0000dead0000dead0000dead0000dead0000';

export const STAGE_A_FIXTURE: unknown = {
  schemaVersion: 2,
  repository: {
    repositoryId: 'LogicDuke/agentbridge',
    observedHeadSha: HEAD_SHA,
    defaultBranchRef: 'refs/heads/main',
  },
  provenance: {
    collectorId: 'cockpit-stage-a-fixture',
    observedAt: '2026-08-24T12:00:00.000Z',
  },
  pullRequests: [
    {
      pullRequestId: 'pr-42',
      headSha: HEAD_SHA,
      baseRef: 'refs/heads/main',
      state: 'open',
      title: 'Harden login authentication path',
    },
    {
      pullRequestId: 'pr-43',
      headSha: OLD_SHA,
      baseRef: 'refs/heads/main',
      state: 'merged',
      // Hostile title: must render as inert escaped text.
      title: '<b>Bold</b> & "quotes" <script>alert(2)</script>',
    },
  ],
  evidence: [
    {
      evidenceId: 'ev-ci-001',
      kind: 'ci-result',
      source: 'github',
      commitSha: HEAD_SHA,
      reference: 'gh-actions/run/1024',
      observedAt: '2026-08-24T11:40:00.000Z',
    },
    {
      evidenceId: 'ev-review-002',
      kind: 'code-review',
      source: 'agent',
      commitSha: HEAD_SHA,
      reference: 'claude/review/pr-42',
      observedAt: '2026-08-24T11:45:00.000Z',
    },
    {
      evidenceId: 'ev-sec-003',
      kind: 'security-review',
      source: 'local-verification',
      commitSha: OLD_SHA,
      reference: 'local/security-scan/pr-42',
      observedAt: '2026-08-23T09:10:00.000Z',
    },
    {
      evidenceId: 'ev-test-004',
      kind: 'test-result',
      source: 'local-verification',
      commitSha: HEAD_SHA,
      reference: 'vitest/run/883',
      observedAt: '2026-08-24T11:50:00.000Z',
    },
    {
      evidenceId: 'ev-human-005',
      kind: 'human-decision',
      source: 'human',
      commitSha: HEAD_SHA,
      reference: 'maintainer/gate/pr-42',
      observedAt: '2026-08-24T11:55:00.000Z',
    },
    {
      evidenceId: 'ev-repo-006',
      kind: 'repository-state',
      source: 'github',
      commitSha: OLD_SHA,
      reference: 'gh/tree/dead0000',
      observedAt: '2026-08-23T08:00:00.000Z',
    },
  ],
  findings: [
    {
      findingId: 'f-001',
      pullRequestId: 'pr-42',
      reviewedCommitSha: OLD_SHA,
      provider: 'claude',
      reviewerId: 'claude-review-bot',
      severity: 'blocking',
      classification: 'security',
      status: 'open',
      // Hostile title + message: must render as inert escaped text.
      title: "<script>alert('xss-title')</script> SQL injection in login handler",
      message:
        '"><img src=x onerror=alert(1)> Use parameterized queries & escape < > characters before rendering.',
      filePath: 'src/auth/login.ts',
      disposition: 'future-layer-obligation',
      advisoryFreshness: 'STALE',
    },
    {
      findingId: 'f-002',
      pullRequestId: 'pr-42',
      reviewedCommitSha: HEAD_SHA,
      provider: 'codex',
      reviewerId: 'codex-review-bot',
      severity: 'major',
      classification: 'correctness',
      status: 'open',
      title: 'Off-by-one in session expiry comparison',
      message: 'The expiry check uses <= where < is intended; sessions live one tick too long.',
      filePath: 'src/auth/session.ts',
      disposition: 'maintenance-observation',
      advisoryFreshness: 'CURRENT',
    },
    {
      findingId: 'f-003',
      pullRequestId: 'pr-43',
      reviewedCommitSha: HEAD_SHA,
      provider: 'claude',
      reviewerId: 'claude-review-bot',
      severity: 'minor',
      classification: 'maintainability',
      status: 'resolved',
      title: 'Extract duplicated header-building logic',
      message: 'Two handlers build the same response headers; factor into one helper.',
      filePath: 'src/http/headers.ts',
      disposition: 'optional-cleanup',
      advisoryFreshness: null,
    },
    {
      findingId: 'f-004',
      pullRequestId: 'pr-43',
      reviewedCommitSha: HEAD_SHA,
      provider: 'coderabbit',
      reviewerId: 'coderabbit-bot',
      severity: 'info',
      classification: 'performance',
      status: 'unknown',
      title: 'Consider memoizing the freshness projection',
      message: 'For large snapshots the projection could be cached per observed HEAD.',
      filePath: null,
      disposition: 'deferred',
      advisoryFreshness: null,
    },
  ],
  repairJobs: [
    {
      jobId: 'repair-001',
      parentPullRequestId: 'pr-42',
      findingId: 'f-001',
      repairBranch: 'refs/heads/repair/f-001-login-injection',
      repairAgentId: 'claude-repair-agent',
      independentValidatorId: 'codex-independent-validator',
    },
  ],
  // Serialized Autoflow observation (schema v2). Shaped like the JSON a future
  // collector would emit — an OPEN workflow bound to the observed HEAD with one
  // outstanding (REQUESTED) review invocation. It is hand-authored, NOT produced
  // by executing a transition, and reaches the renderer only after D1 rebuilds it
  // through the domain's `readWorkflowState` hostile reader. A `null` here would
  // instead show the honest "no workflow observed" absence panel.
  autoflow: {
    workflowId: 'wf-stage-a-0001',
    repositoryId: 'LogicDuke/agentbridge',
    pullRequestId: 'pr-42',
    boundCommitSha: HEAD_SHA,
    revision: 0,
    sequence: 1,
    status: 'OPEN',
    closureReason: null,
    humanGateOpenedAtRevision: null,
    invocations: [
      {
        invocationId: 'inv-review-0001',
        targetCommitSha: HEAD_SHA,
        purpose: 'review',
        providerId: 'claude',
        agentId: 'claude-review-bot',
        requestedAtRevision: 0,
        requestedAtSequence: 1,
        state: 'REQUESTED',
        reportedStatus: null,
        reportedAtRevision: null,
        reportedAtSequence: null,
      },
    ],
    evidence: [],
    reviews: [],
  },
};
