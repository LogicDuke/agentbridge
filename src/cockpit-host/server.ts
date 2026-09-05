/**
 * Cockpit D3 — Read-Only Dashboard Host (Stage A).
 *
 * A minimal `node:http` server that renders one deterministic fixture snapshot,
 * validated through the D1/D2 Cockpit boundary, as a read-only browser page.
 *
 * Boundaries this host holds, by construction:
 *
 * - **Read-only.** It serves `GET` only; any other method is `405`. There is no
 *   mutation route, no request-body handling, no cookie, and no session. No
 *   repository, Git, GitHub, agent, permit, or merge capability is imported.
 * - **Loopback only.** It binds the literal address `127.0.0.1`, never
 *   `0.0.0.0`, `::`, or a hostname that could resolve off-box.
 * - **Fail closed, no silent fallback.** Every source — the default Stage-A
 *   fixture or a real `live` source — is treated as untrusted input: it must
 *   pass D1's `readCockpitSnapshot()` before anything renders. If a source errors
 *   or its snapshot fails D1, the host refuses to serve; a failed `live` source
 *   is never silently replaced by the fixture. The source is chosen by an
 *   explicit seam ({@link CockpitSource}); the default is {@link FIXTURE_SOURCE}.
 * - **No secrets, no paths, no shell.** It reads no environment variable, spawns
 *   no process, runs no Git command, and puts no filesystem path in the page.
 *
 * The page itself carries no client-side JavaScript; a strict
 * `script-src 'none'; style-src 'self'` Content-Security-Policy accompanies
 * every response.
 */

import http from 'node:http';
import { pathToFileURL } from 'node:url';

import { projectCockpitAutoflow } from '../cockpit/autoflow-projection.js';
import { projectCockpitEvidenceFreshness, readCockpitSnapshot } from '../cockpit/index.js';
import { STAGE_A_FIXTURE } from './fixtures/stage-a.js';
import { renderDashboard } from './render.js';
import { STYLES } from './styles.js';

/** Loopback only. Never `0.0.0.0`, `::`, or a resolvable hostname. */
export const HOST = '127.0.0.1';

/** Fixed non-privileged port for the Stage-A dashboard. */
export const PORT = 4317;

/** Content-Security-Policy: allow only the same-origin stylesheet; block scripts and everything else. */
const CONTENT_SECURITY_POLICY =
  "default-src 'none'; style-src 'self'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** Apply the fixed security headers carried on every response. */
function applySecurityHeaders(response: http.ServerResponse): void {
  response.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Cache-Control', 'no-store');
}

/**
 * Which observation source the host is rendering, for provenance labeling only.
 *
 * `fixture` is the deterministic Stage-A development fixture; `live` is a real
 * serialized observation produced on the Autoflow side and crossing D1. The mode
 * is an out-of-band, non-spoofable signal supplied by the seam that selected the
 * source — never read from the snapshot's own content — so a snapshot can never
 * relabel itself, in either direction. It carries no authority: it changes only
 * how the page announces its provenance.
 *
 * The union is structurally identical to the renderer's own
 * `CockpitProvenanceMode`, so the two are assignable without either module
 * importing the other, and the host↔renderer import set stays exactly as the D3
 * frozen-source pin requires.
 */
export type CockpitSourceMode = 'fixture' | 'live';

/**
 * A read-only Cockpit snapshot source: a provenance mode plus a `read` that
 * returns JSON-shaped serialized snapshot data (`unknown`) to cross D1's hostile
 * boundary. `read` is expected to throw (or return a value D1 rejects) when a
 * live source is unavailable or malformed; there is deliberately no
 * success/fallback envelope, because the host must **fail closed**, never
 * substitute the fixture for a failed live observation.
 */
export interface CockpitSource {
  readonly mode: CockpitSourceMode;
  readonly read: () => unknown;
}

/**
 * The default development source: the deterministic Stage-A fixture, labeled
 * `fixture`. This preserves the historical zero-argument behavior of
 * {@link buildDashboardHtml} and {@link createCockpitServer} exactly.
 */
export const FIXTURE_SOURCE: CockpitSource = {
  mode: 'fixture',
  read: (): unknown => STAGE_A_FIXTURE,
};

/**
 * Read the selected source through D1, project freshness through D2 and Autoflow
 * through D4, and render the page. Throws (fail closed) if the source errors or
 * its snapshot does not pass D1, so neither a malformed snapshot nor a failed
 * live source can ever be served as raw data — and, critically, a failed `live`
 * source is **never** silently replaced by the fixture: the error propagates and
 * the host refuses to serve.
 *
 * The Autoflow projection is derived from the snapshot's already-validated,
 * trusted `autoflow` state (a read-only observation); the host executes no
 * workflow transition and imports neither `openWorkflow` nor `applyWorkflowEvent`.
 * The source's provenance `mode` is passed to the renderer for labeling only.
 */
export function buildDashboardHtml(source: CockpitSource = FIXTURE_SOURCE): string {
  const raw = source.read();
  const read = readCockpitSnapshot(raw);
  if (read.snapshot === null) {
    throw new Error(
      `Cockpit ${source.mode} snapshot failed D1 validation; refusing to serve. Invalid fields: ${read.invalidFields.join(', ')}`,
    );
  }
  const projection = projectCockpitEvidenceFreshness(read.snapshot);
  const autoflow =
    read.snapshot.autoflow === null ? null : projectCockpitAutoflow(read.snapshot.autoflow);
  return renderDashboard(read.snapshot, projection, autoflow, source.mode);
}

/** Strip any query string, returning just the request path. */
function pathOf(url: string): string {
  const queryIndex = url.indexOf('?');
  return queryIndex === -1 ? url : url.slice(0, queryIndex);
}

/**
 * Build the configured (but not yet listening) HTTP server. The page is
 * rendered once here; every request serves the same immutable bytes.
 */
export function createCockpitServer(source: CockpitSource = FIXTURE_SOURCE): http.Server {
  const page = buildDashboardHtml(source);

  return http.createServer((request: http.IncomingMessage, response: http.ServerResponse): void => {
    applySecurityHeaders(response);

    const method = request.method ?? '';
    if (method !== 'GET') {
      response.statusCode = 405;
      response.setHeader('Allow', 'GET');
      response.setHeader('Content-Type', 'text/plain; charset=utf-8');
      response.end('405 Method Not Allowed');
      return;
    }

    const path = pathOf(request.url ?? '');
    if (path === '/') {
      response.statusCode = 200;
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end(page);
      return;
    }
    if (path === '/styles.css') {
      response.statusCode = 200;
      response.setHeader('Content-Type', 'text/css; charset=utf-8');
      response.end(STYLES);
      return;
    }

    response.statusCode = 404;
    response.setHeader('Content-Type', 'text/plain; charset=utf-8');
    response.end('404 Not Found');
  });
}

/** Start the server on the loopback address and print the exact URL. */
function main(): void {
  const server = createCockpitServer();
  server.listen(PORT, HOST, () => {
    const url = `http://${HOST}:${String(PORT)}/`;
    console.log(`AgentBridge Cockpit: ${url}`);
    console.log('READ ONLY — Stage A fixture data (not live).');
  });
}

const entryArgument = process.argv[1];
const isEntry = entryArgument !== undefined && import.meta.url === pathToFileURL(entryArgument).href;
if (isEntry) {
  main();
}
