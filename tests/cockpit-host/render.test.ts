import { describe, expect, it } from 'vitest';

import { readCockpitSnapshot } from '../../src/cockpit/index.js';
import { STAGE_A_FIXTURE } from '../../src/cockpit-host/fixtures/stage-a.js';
import { escapeHtml } from '../../src/cockpit-host/escape.js';
import { buildDashboardHtml } from '../../src/cockpit-host/server.js';

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

  it('labels PR, Reviewed commit, and Advisory freshness as distinct columns', () => {
    expect(headerRow).toContain('<th>PR</th>');
    expect(headerRow).toContain('<th>Reviewed commit</th>');
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
