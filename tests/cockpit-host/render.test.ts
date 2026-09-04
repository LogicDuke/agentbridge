import { describe, expect, it } from 'vitest';

import { projectCockpitEvidenceFreshness, readCockpitSnapshot } from '../../src/cockpit/index.js';
import { projectCockpitAutoflow } from '../../src/cockpit/autoflow-projection.js';
import { STAGE_A_FIXTURE } from '../../src/cockpit-host/fixtures/stage-a.js';
import { escapeHtml } from '../../src/cockpit-host/escape.js';
import { renderDashboard } from '../../src/cockpit-host/render.js';
import { buildDashboardHtml } from '../../src/cockpit-host/server.js';
import type { CockpitSnapshot } from '../../src/cockpit/index.js';
import {
  applyOrThrow,
  buildInvocation,
  buildReport,
  openedWorkflow,
  reportInvocation,
  requestInvocation,
} from '../domain/workflow-fixtures.js';

describe('Cockpit D3 escaping', () => {
  it('escapes the five HTML-significant characters', () => {
    expect(escapeHtml(`& < > " '`)).toBe('&amp; &lt; &gt; &quot; &#39;');
  });

  it('leaves ordinary text unchanged', () => {
    expect(escapeHtml('refs/heads/main')).toBe('refs/heads/main');
  });
});

describe('Cockpit D3 Stage-A ingestion', () => {
  it('the Stage-A fixture passes D1 validation before any render', () => {
    const read = readCockpitSnapshot(STAGE_A_FIXTURE);
    expect(read.invalidFields).toEqual([]);
    expect(read.snapshot).not.toBeNull();
  });

  it('D1 fails closed on a malformed snapshot (the boundary the host relies on)', () => {
    const read = readCockpitSnapshot({ schemaVersion: 1 });
    expect(read.snapshot).toBeNull();
    expect(read.invalidFields.length).toBeGreaterThan(0);
  });
});

describe('Cockpit D3 rendered page', () => {
  const html = buildDashboardHtml();

  it('identifies itself as read-only Stage-A fixture data', () => {
    expect(html).toContain('AgentBridge Cockpit');
    expect(html).toContain('READ ONLY');
    expect(html).toContain('STAGE A');
    expect(html).toContain('FIXTURE DATA');
  });

  it('honestly labels Autoflow as not projected', () => {
    expect(html).toContain('Autoflow');
    expect(html).toContain('Not projected yet');
    expect(html).toContain('Cockpit D4 projection');
  });

  it('honestly labels tree SHA as not projected', () => {
    expect(html).toContain('Tree SHA');
    expect(html).toContain('not projected');
  });

  it('renders hostile finding prose only as inert escaped text', () => {
    // The raw script/image payloads from the fixture must never appear verbatim.
    expect(html).not.toContain("<script>alert('xss-title')</script>");
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script>alert(2)</script>');
    // They must appear in escaped form instead.
    expect(html).toContain('&lt;script&gt;alert(&#39;xss-title&#39;)&lt;/script&gt;');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('does not dump the raw fixture object as JSON', () => {
    // A raw JSON.stringify of the fixture would contain quoted property keys.
    expect(html).not.toContain('"findingId":');
    expect(html).not.toContain('"repositoryId":');
  });

  it('presents the authority legend without offering any action control', () => {
    expect(html).toContain('Authority legend');
    expect(html).toContain('Human-only action');
    // No interactive authority surface exists anywhere in the markup.
    expect(html).not.toContain('<button');
    expect(html).not.toContain('<form');
    expect(html).not.toContain('onclick');
  });

  it('carries no client-side script or inline style', () => {
    expect(html).not.toContain('<script');
    expect(html).not.toContain(' style=');
    expect(html).not.toContain('javascript:');
  });

  it('shows the D2 freshness states projected from the fixture', () => {
    expect(html).toContain('state-CURRENT');
    expect(html).toContain('state-STALE');
  });
});

describe('Cockpit D4 Autoflow panel', () => {
  function validSnapshot(): CockpitSnapshot {
    const read = readCockpitSnapshot(STAGE_A_FIXTURE);
    expect(read.snapshot).not.toBeNull();
    return read.snapshot as CockpitSnapshot;
  }

  const snapshot = validSnapshot();
  const freshness = projectCockpitEvidenceFreshness(snapshot);

  it('shows an honest absence state when no workflow projection is supplied (24)', () => {
    const html = renderDashboard(snapshot, freshness);
    expect(html).toContain('Autoflow');
    expect(html).toContain('Not projected yet');
    expect(html).toContain('Cockpit D4 projection');
    // No fabricated workflow values in the absence state.
    expect(html).not.toContain('Bound commit SHA');
  });

  it('renders projected workflow facts when a projection is supplied', () => {
    let state = openedWorkflow();
    state = applyOrThrow(
      state,
      requestInvocation(
        buildInvocation({ invocationId: 'inv-1', providerId: 'a&b', agentId: 'c<d>' }),
      ),
    );
    state = applyOrThrow(state, reportInvocation(buildReport({ invocationId: 'inv-1' })));
    state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: 'inv-2' })));

    const html = renderDashboard(snapshot, freshness, projectCockpitAutoflow(state));

    // The absence copy is replaced once a projection is actually supplied.
    expect(html).not.toContain('Not projected yet');
    // Verbatim facts are shown.
    expect(html).toContain(state.workflowId);
    expect(html).toContain('Bound commit SHA');
    expect(html).toContain('REQUESTED');
    expect(html).toContain('REPORTED');
    // Inert echoed identifiers are rendered as inert escaped text.
    expect(html).toContain('a&amp;b');
    expect(html).toContain('c&lt;d&gt;');
    expect(html).not.toContain('c<d>');
    // No interactive authority surface is introduced by the panel.
    expect(html).not.toContain('<button');
    expect(html).not.toContain('<form');
    expect(html).not.toContain('onclick');
    expect(html).not.toContain('<script');
  });
});

describe('Cockpit D4 gap-notice / panel consistency (PR72-F1)', () => {
  function validSnapshot(): CockpitSnapshot {
    const read = readCockpitSnapshot(STAGE_A_FIXTURE);
    expect(read.snapshot).not.toBeNull();
    return read.snapshot as CockpitSnapshot;
  }

  const snapshot = validSnapshot();
  const freshness = projectCockpitEvidenceFreshness(snapshot);

  // The distinctive capability-notice strings (the <b>…</b> labels in the
  // "Capability notices" section), separate from the Autoflow panel's own copy.
  const AUTOFLOW_GAP_NOTICE = '<b>Autoflow — not projected yet.</b>';
  const TREE_SHA_GAP_NOTICE = '<b>Tree SHA — not projected.</b>';

  function projectionHtml(): string {
    let state = openedWorkflow();
    state = applyOrThrow(state, requestInvocation(buildInvocation({ invocationId: 'inv-1' })));
    return renderDashboard(snapshot, freshness, projectCockpitAutoflow(state));
  }

  it('1. keeps the Autoflow gap notice when no projection is supplied', () => {
    const html = renderDashboard(snapshot, freshness);
    expect(html).toContain(AUTOFLOW_GAP_NOTICE);
  });

  it('2. renders the populated Autoflow panel when a projection is supplied', () => {
    expect(projectionHtml()).toContain('Bound commit SHA');
  });

  it('3. omits the obsolete Autoflow gap notice when a projection is supplied', () => {
    // The core PR72-F1 contradiction: the populated panel and the "not projected
    // yet" gap notice must never appear together.
    expect(projectionHtml()).not.toContain(AUTOFLOW_GAP_NOTICE);
  });

  it('4. keeps unrelated capability-gap notices (Tree SHA) in both states', () => {
    expect(renderDashboard(snapshot, freshness)).toContain(TREE_SHA_GAP_NOTICE);
    expect(projectionHtml()).toContain(TREE_SHA_GAP_NOTICE);
  });

  it('5. never emits raw script markup in either state', () => {
    expect(renderDashboard(snapshot, freshness)).not.toContain('<script');
    expect(projectionHtml()).not.toContain('<script');
  });
});

describe('Cockpit D3 finding binding (D3-CODEX-F1)', () => {
  const html = buildDashboardHtml();

  // Fixture SHAs. Each finding is reviewed against exactly one of these.
  const HEAD_SHA = 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00';
  const OLD_SHA = 'dead0000dead0000dead0000dead0000dead0000';

  // Isolate the Findings <section> so assertions are scoped to it, not to the
  // whole page: the PR ids and reviewed-commit SHAs also legitimately appear in
  // the Pull requests, Evidence, and Repair-jobs sections, so a page-wide
  // `toContain` would pass even if the Findings table still omitted the binding.
  const headingAt = html.indexOf('<h2>Findings');
  const sectionStart = html.lastIndexOf('<section>', headingAt);
  const sectionEnd = html.indexOf('</section>', headingAt);
  const findingsSection = html.slice(sectionStart, sectionEnd);

  // The header row, and each finding's <tr>, scoped within the Findings section.
  const headerRow = findingsSection.slice(
    findingsSection.indexOf('<thead>'),
    findingsSection.indexOf('</thead>'),
  );
  const rowFor = (findingId: string): string => {
    const rows = findingsSection.split('</tr>');
    const row = rows.find((candidate) => candidate.includes(`>${findingId}<`));
    expect(row, `row for ${findingId}`).toBeDefined();
    return row as string;
  };

  it('labels finding identity and reviewer attribution as distinct columns', () => {
    expect(headerRow).toContain('<th>PR</th>');
    expect(headerRow).toContain('<th>Reviewed commit</th>');
    expect(headerRow).toContain('<th>Provider</th>');
    expect(headerRow).toContain('<th>Reviewer</th>');
    expect(headerRow).toContain('<th>Advisory freshness</th>');
    // "Reviewed commit" is the load-bearing label: it must not collapse to a
    // bare "Commit", which would blur it against the repository Observed HEAD
    // SHA and the PR Head SHA shown elsewhere on the page.
    expect(headerRow).not.toContain('<th>Commit</th>');
  });

  it('binds f-001 to pr-42 reviewed against the older (STALE) commit', () => {
    const row = rowFor('f-001');
    expect(row).toContain('pr-42');
    expect(row).toContain(OLD_SHA);
  });

  it('binds f-002 to pr-42 reviewed against the observed HEAD commit', () => {
    const row = rowFor('f-002');
    expect(row).toContain('pr-42');
    expect(row).toContain(HEAD_SHA);
  });

  it('binds an f-003/pr-43 finding to its PR and reviewed commit', () => {
    const row = rowFor('f-003');
    expect(row).toContain('pr-43');
    expect(row).toContain(HEAD_SHA);
  });

  it('attributes claims from different providers to their exact reviewers', () => {
    const claudeRow = rowFor('f-001');
    expect(claudeRow).toContain('claude');
    expect(claudeRow).toContain('claude-review-bot');

    const codexRow = rowFor('f-002');
    expect(codexRow).toContain('codex');
    expect(codexRow).toContain('codex-review-bot');

    const coderabbitRow = rowFor('f-004');
    expect(coderabbitRow).toContain('coderabbit');
    expect(coderabbitRow).toContain('coderabbit-bot');
  });

  it('keeps two same-PR findings distinguishable by reviewed commit', () => {
    // f-001 and f-002 are both pr-42 but were reviewed against different
    // commits; the reviewed-commit binding, not advisory freshness, is what
    // tells them apart.
    expect(rowFor('f-001')).toContain(OLD_SHA);
    expect(rowFor('f-002')).toContain(HEAD_SHA);
    expect(rowFor('f-001')).not.toContain(HEAD_SHA);
  });

  it('keeps advisory freshness separate from reviewed-commit identity', () => {
    // f-003 carries no advisory claim yet still shows its reviewed commit:
    // freshness is not a substitute for commit identity.
    const row = rowFor('f-003');
    expect(row).toContain(HEAD_SHA);
    expect(row).toContain('no claim');
  });

  it('renders both binding values as inert escaped text', () => {
    // pullRequestId / reviewedCommitSha go through the same escaper as every
    // other value; no raw markup or interactive control is introduced.
    expect(findingsSection).not.toContain('<a ');
    expect(findingsSection).not.toContain('href=');
    expect(findingsSection).not.toContain('<button');
    expect(findingsSection).not.toContain('onclick');
  });
});
