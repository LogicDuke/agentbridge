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
 * - **Fail closed.** The fixture is treated as untrusted input: it must pass
 *   D1's `readCockpitSnapshot()` before anything renders. If it does not, the
 *   host refuses to serve rather than falling back to raw fixture data.
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
 * Validate the Stage-A fixture through D1, project freshness through D2 and
 * Autoflow through D4, and render the page. Throws (fail closed) if the fixture
 * does not pass D1, so a malformed fixture can never be served as raw data.
 *
 * The Autoflow projection is derived from the snapshot's already-validated,
 * trusted `autoflow` state (a read-only observation); the host executes no
 * workflow transition and imports neither `openWorkflow` nor `applyWorkflowEvent`.
 */
export function buildDashboardHtml(): string {
  const read = readCockpitSnapshot(STAGE_A_FIXTURE);
  if (read.snapshot === null) {
    throw new Error(
      `Stage-A fixture failed D1 validation; refusing to serve. Invalid fields: ${read.invalidFields.join(', ')}`,
    );
  }
  const projection = projectCockpitEvidenceFreshness(read.snapshot);
  const autoflow =
    read.snapshot.autoflow === null ? null : projectCockpitAutoflow(read.snapshot.autoflow);
  return renderDashboard(read.snapshot, projection, autoflow);
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
export function createCockpitServer(): http.Server {
  const page = buildDashboardHtml();

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
