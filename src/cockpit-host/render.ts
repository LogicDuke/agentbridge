/**
 * Cockpit D3 — pure server-side HTML rendering.
 *
 * Turns a **D1-validated** {@link CockpitSnapshot} and its **D2** evidence
 * freshness projection into a single self-contained HTML string. This module is
 * pure and total: no I/O, no network, no process access, no clock, no mutation.
 * It imports only the Cockpit read-model boundary and the local escaper.
 *
 * Every dynamic value is passed through {@link escapeHtml} before it enters the
 * markup. The output contains no `<script>`, no inline event handler, and no
 * inline `style` attribute, so a strict `script-src 'none'; style-src 'self'`
 * Content-Security-Policy renders it unchanged.
 *
 * The host is presentation only. Nothing rendered here grants, records, or
 * implies authority: reviewer findings are shown as *claims*, evidence as
 * *observation*, freshness as *derived judgment*, and every human-only action is
 * described, never offered as a control.
 */

import type {
  CockpitEvidenceFreshnessProjection,
  CockpitEvidenceReadModel,
  CockpitFindingReadModel,
  CockpitPullRequestObservation,
  CockpitRepairJobReadModel,
  CockpitSnapshot,
} from '../cockpit/index.js';
import { escapeHtml } from './escape.js';

/** Escape a required string for text/attribute output. */
function text(value: string): string {
  return escapeHtml(value);
}

/** Render an optional string, or an inert "not observed" placeholder. */
function optional(value: string | null): string {
  return value === null ? '<span class="empty">not observed</span>' : escapeHtml(value);
}

/** Numbers are rendered through an explicit string conversion. */
function num(value: number): string {
  return String(value);
}

function repositorySection(snapshot: CockpitSnapshot): string {
  const repo = snapshot.repository;
  return `
  <section>
    <h2>Repository identity <span class="section-cat cat cat-observation">observation</span></h2>
    <dl class="kv">
      <dt>Repository</dt><dd class="mono">${text(repo.repositoryId)}</dd>
      <dt>Observed HEAD SHA</dt><dd class="mono">${text(repo.observedHeadSha)}</dd>
      <dt>Default branch ref</dt><dd class="mono">${optional(repo.defaultBranchRef)}</dd>
      <dt>Collector</dt><dd class="mono">${text(snapshot.provenance.collectorId)}</dd>
      <dt>Observed at</dt><dd class="mono">${text(snapshot.provenance.observedAt)}</dd>
    </dl>
  </section>`;
}

function gapSection(): string {
  return `
  <section>
    <h2>Capability notices</h2>
    <div class="notice">
      <b>Tree SHA — not projected.</b> The current D1 read model carries the
      observed HEAD only. No tree SHA field exists, so none is shown. A value is
      never invented from the implementation base.
    </div>
    <div class="notice">
      <b>Autoflow — not projected yet.</b> Real Autoflow workflow state (status,
      revision, sequence, invocations, human gate) requires a future pure
      Cockpit D4 projection. Stage A shows no Autoflow values because none are
      projected through the D1/D2 boundary.
    </div>
  </section>`;
}

function autoflowSection(): string {
  return `
  <section>
    <h2>Autoflow <span class="section-cat cat cat-orchestration">orchestration state</span></h2>
    <p class="empty">Not projected yet.</p>
    <p>
      Real Autoflow workflow state requires a future pure Cockpit D4 projection.
      This panel deliberately shows no status, revision, sequence, invocation,
      or human-gate value: those would be manufactured, not observed.
    </p>
  </section>`;
}

function pullRequestsSection(pullRequests: readonly CockpitPullRequestObservation[]): string {
  if (pullRequests.length === 0) {
    return `
  <section>
    <h2>Pull requests <span class="section-cat cat cat-observation">observation</span></h2>
    <p class="empty">No pull requests in this snapshot.</p>
  </section>`;
  }
  const rows = pullRequests
    .map(
      (pr) => `
      <tr>
        <td class="mono">${text(pr.pullRequestId)}</td>
        <td><span class="tag">${text(pr.state)}</span></td>
        <td>${optional(pr.title)}</td>
        <td class="mono">${text(pr.headSha)}</td>
        <td class="mono">${optional(pr.baseRef)}</td>
      </tr>`,
    )
    .join('');
  return `
  <section>
    <h2>Pull requests <span class="section-cat cat cat-observation">observation</span></h2>
    <table>
      <thead><tr><th>PR</th><th>State</th><th>Title</th><th>Head SHA</th><th>Base ref</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

function evidenceSection(
  evidence: readonly CockpitEvidenceReadModel[],
  projection: CockpitEvidenceFreshnessProjection,
): string {
  const counts = projection.counts;
  const summary = `
    <div class="counts">
      <div class="count"><b>${num(counts.total)}</b><span>total</span></div>
      <div class="count"><b>${num(counts.current)}</b><span>current</span></div>
      <div class="count"><b>${num(counts.stale)}</b><span>stale</span></div>
      <div class="count"><b>${num(counts.invalid)}</b><span>invalid</span></div>
    </div>`;
  if (evidence.length === 0) {
    return `
  <section>
    <h2>Evidence <span class="section-cat cat cat-evidence">evidence + derived judgment</span></h2>
    ${summary}
    <p class="empty">No evidence records in this snapshot.</p>
  </section>`;
  }
  const rows = evidence
    .map((record, index) => {
      const item = projection.results[index];
      const freshness =
        item === undefined
          ? '<span class="empty">—</span>'
          : `<span class="tag state-${item.state}">${text(item.state)}</span> <span class="mono">${text(item.reason)}</span>`;
      return `
      <tr>
        <td class="mono">${text(record.evidenceId)}</td>
        <td>${text(record.kind)}</td>
        <td>${text(record.source)}</td>
        <td class="mono">${text(record.commitSha)}</td>
        <td class="mono">${text(record.reference)}</td>
        <td class="mono">${text(record.observedAt)}</td>
        <td>${freshness}</td>
      </tr>`;
    })
    .join('');
  return `
  <section>
    <h2>Evidence <span class="section-cat cat cat-evidence">evidence + derived judgment</span></h2>
    ${summary}
    <p class="empty">Freshness column is PR&nbsp;004's derived judgment, projected verbatim by D2 against the observed HEAD.</p>
    <table>
      <thead><tr><th>ID</th><th>Kind</th><th>Source</th><th>Commit SHA</th><th>Reference</th><th>Observed at</th><th>Freshness (derived)</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

function findingsSection(findings: readonly CockpitFindingReadModel[]): string {
  if (findings.length === 0) {
    return `
  <section>
    <h2>Findings <span class="section-cat cat cat-claim">claim</span></h2>
    <p class="empty">No findings in this snapshot.</p>
  </section>`;
  }
  const rows = findings
    .map((finding) => {
      const advisory =
        finding.advisoryFreshness === null
          ? '<span class="empty">no claim</span>'
          : `<span class="tag state-${finding.advisoryFreshness}">${text(finding.advisoryFreshness)}</span>`;
      return `
      <tr>
        <td class="mono">${text(finding.findingId)}</td>
        <td class="mono">${text(finding.pullRequestId)}</td>
        <td class="mono">${text(finding.reviewedCommitSha)}</td>
        <td>${text(finding.provider)}</td>
        <td class="mono">${text(finding.reviewerId)}</td>
        <td><span class="tag sev-${finding.severity}">${text(finding.severity)}</span></td>
        <td>${text(finding.classification)}</td>
        <td>${text(finding.status)}</td>
        <td>${text(finding.disposition)}</td>
        <td>${text(finding.title)}</td>
        <td>${text(finding.message)}</td>
        <td class="mono">${optional(finding.filePath)}</td>
        <td>${advisory}</td>
      </tr>`;
    })
    .join('');
  return `
  <section>
    <h2>Findings <span class="section-cat cat cat-claim">claim</span></h2>
    <p class="empty">A finding is a reviewer/agent claim. Advisory freshness is a recomputable echo (derived judgment), never authority.</p>
    <table>
      <thead><tr><th>ID</th><th>PR</th><th>Reviewed commit</th><th>Provider</th><th>Reviewer</th><th>Severity</th><th>Classification</th><th>Status</th><th>Disposition</th><th>Title</th><th>Message</th><th>File</th><th>Advisory freshness</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

function repairJobsSection(repairJobs: readonly CockpitRepairJobReadModel[]): string {
  if (repairJobs.length === 0) {
    return `
  <section>
    <h2>Repair jobs &amp; carried obligations <span class="section-cat cat cat-orchestration">orchestration state</span></h2>
    <p class="empty">No repair jobs in this snapshot.</p>
  </section>`;
  }
  const rows = repairJobs
    .map(
      (job) => `
      <tr>
        <td class="mono">${text(job.jobId)}</td>
        <td class="mono">${text(job.parentPullRequestId)}</td>
        <td class="mono">${text(job.findingId)}</td>
        <td class="mono">${text(job.repairBranch)}</td>
        <td class="mono">${text(job.repairAgentId)}</td>
        <td class="mono">${text(job.independentValidatorId)}</td>
      </tr>`,
    )
    .join('');
  return `
  <section>
    <h2>Repair jobs &amp; carried obligations <span class="section-cat cat cat-orchestration">orchestration state</span></h2>
    <p class="empty">Identity only. This is what a human sees in a list, not an execution capability — no path, command class, permit, or decision is shown or held.</p>
    <table>
      <thead><tr><th>Job</th><th>Parent PR</th><th>Finding</th><th>Repair branch</th><th>Repair agent</th><th>Independent validator</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

function legendSection(): string {
  const items: readonly { readonly cls: string; readonly name: string; readonly desc: string }[] = [
    { cls: 'cat-claim', name: 'Claim', desc: 'An agent or reviewer said something. Never promoted to truth.' },
    { cls: 'cat-observation', name: 'Observation', desc: 'An adapter independently observed something at an exact SHA.' },
    { cls: 'cat-evidence', name: 'Evidence', desc: 'A stored observation bound to one repository and one commit.' },
    { cls: 'cat-derived', name: 'Derived judgment', desc: 'A pure verdict from evidence plus a trusted target (freshness).' },
    { cls: 'cat-orchestration', name: 'Orchestration state', desc: 'What was requested and admitted, in order, for one bound commit.' },
    { cls: 'cat-authority', name: 'Authority', desc: 'Permission to act. Held by the policy gate plus a human — never here.' },
    { cls: 'cat-human', name: 'Human-only action', desc: 'Merge and approval stay external. This dashboard offers no such control.' },
  ];
  const cards = items
    .map(
      (item) => `
      <div class="item">
        <h3><span class="cat ${item.cls}">${text(item.name)}</span></h3>
        <p>${text(item.desc)}</p>
      </div>`,
    )
    .join('');
  return `
  <section>
    <h2>Authority legend <span class="section-cat cat cat-authority">reference only</span></h2>
    <p class="empty">Explanatory only. This legend grants nothing; a reviewer recommendation is never permission.</p>
    <div class="legend">${cards}</div>
  </section>`;
}

/**
 * Build the complete dashboard HTML document from a validated snapshot and its
 * D2 freshness projection.
 */
export function renderDashboard(
  snapshot: CockpitSnapshot,
  projection: CockpitEvidenceFreshnessProjection,
): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentBridge Cockpit — Stage A (Read Only)</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body>
<div class="wrap">
  <div class="banner">
    <h1>AgentBridge Cockpit</h1>
    <div>Observability surface — presentation only, no authority.</div>
    <div class="badges">
      <span class="badge readonly">READ ONLY</span>
      <span class="badge stage">STAGE A</span>
      <span class="badge fixture">FIXTURE DATA</span>
      <span class="badge">GET-only · loopback</span>
    </div>
  </div>
  ${repositorySection(snapshot)}
  ${gapSection()}
  ${pullRequestsSection(snapshot.pullRequests)}
  ${evidenceSection(snapshot.evidence, projection)}
  ${findingsSection(snapshot.findings)}
  ${repairJobsSection(snapshot.repairJobs)}
  ${autoflowSection()}
  ${legendSection()}
  <footer>
    AgentBridge Cockpit D3 · Stage A fixture data · not live · read-only ·
    human merge authority remains external.
  </footer>
</div>
</body>
</html>`;
}
