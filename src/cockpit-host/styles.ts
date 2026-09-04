/**
 * The Cockpit D3 dashboard stylesheet, served verbatim at `/styles.css`.
 *
 * Kept as a compiled-in string constant rather than a runtime file read so the
 * host performs no filesystem access and exposes no on-disk path. The page
 * links this sheet with `<link rel="stylesheet" href="/styles.css">`, which a
 * `style-src 'self'` Content-Security-Policy permits; the page uses no inline
 * `style=""` attributes, so the policy needs no `'unsafe-inline'`.
 */

export const STYLES = `
:root {
  color-scheme: light dark;
  --bg: #0f1115;
  --panel: #171a21;
  --panel-2: #1e222b;
  --border: #2b303b;
  --text: #e6e9ef;
  --muted: #9aa4b2;
  --accent: #5aa9e6;
  --warn: #e6b800;
  --danger: #e5534b;
  --ok: #3fb950;
  --stale: #d29922;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
.wrap { max-width: 1100px; margin: 0 auto; padding: 24px 20px 64px; }
.banner {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: linear-gradient(180deg, var(--panel), var(--panel-2));
  padding: 18px 20px;
  margin-bottom: 22px;
}
.banner h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: 0.5px; }
.badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.badge {
  font-size: 12px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--panel-2);
  color: var(--muted);
}
.badge.readonly { color: #061; background: #d7f5dd; border-color: #9be0ab; }
.badge.stage { color: #5a4600; background: #fff2b8; border-color: #e6cf6a; }
.badge.fixture { color: #7a1f1a; background: #ffdad6; border-color: #f2a9a2; }
section {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--panel);
  padding: 16px 18px;
  margin-bottom: 18px;
}
section > h2 {
  margin: 0 0 12px;
  font-size: 14px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--muted);
}
.kv { display: grid; grid-template-columns: 200px 1fr; gap: 6px 16px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; word-break: break-all; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
td.mono, dd.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
.tag { display: inline-block; font-size: 12px; padding: 2px 8px; border-radius: 6px; border: 1px solid var(--border); background: var(--panel-2); }
.tag.state-CURRENT { color: #06421a; background: #b8f0c6; border-color: #7fd79a; }
.tag.state-STALE { color: #5a4600; background: #ffe7a3; border-color: #e6c65a; }
.tag.state-INVALID { color: #7a1f1a; background: #ffcdc7; border-color: #f2a9a2; }
.tag.sev-blocking { color: #7a1f1a; background: #ffcdc7; }
.tag.sev-major { color: #5a4600; background: #ffe7a3; }
.tag.sev-minor { color: #123c5a; background: #cbe6ff; }
.tag.sev-info { color: #333; background: #e4e7ec; }
.counts { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 12px; }
.count { border: 1px solid var(--border); border-radius: 8px; padding: 8px 14px; background: var(--panel-2); }
.count b { display: block; font-size: 20px; }
.count span { font-size: 12px; color: var(--muted); }
.notice { border-left: 3px solid var(--stale); padding: 8px 12px; background: var(--panel-2); border-radius: 0 8px 8px 0; }
.notice + .notice { margin-top: 10px; }
.notice b { color: var(--warn); }
.legend { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }
.legend .item { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; background: var(--panel-2); }
.legend .item h3 { margin: 0 0 4px; font-size: 13px; }
.legend .item p { margin: 0; font-size: 12px; color: var(--muted); }
.cat { font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; }
.cat-claim { color: #c98bdb; }
.cat-observation { color: #5aa9e6; }
.cat-evidence { color: #3fb950; }
.cat-derived { color: #e6b800; }
.cat-orchestration { color: #b0b8c4; }
.cat-authority { color: #e5534b; }
.cat-human { color: #ff8c42; }
.section-cat { float: right; }
.empty { color: var(--muted); font-style: italic; }
footer { color: var(--muted); font-size: 12px; margin-top: 24px; text-align: center; }
`;
