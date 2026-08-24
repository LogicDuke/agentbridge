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
