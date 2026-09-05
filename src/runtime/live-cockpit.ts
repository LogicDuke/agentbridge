/**
 * Live Cockpit runtime composition (Live Runtime Wiring milestone, Decision 059).
 *
 * The composition root that wires the three narrow production parts through the
 * existing D5 seam — it configures and wires, it is **not** the workflow
 * authority ({@link AutoflowRuntime} is):
 *
 *     AutoflowRuntime
 *       -> read-only AutoflowStateReader
 *       -> RepositoryObserver
 *       -> whole CockpitObservation
 *       -> produceCockpitSnapshot        [D5, JSON serialization firewall]
 *       -> CockpitSource(mode='live')
 *       -> readCockpitSnapshot(unknown)  [D1, sole hostile boundary]
 *       -> D2 freshness + D4 autoflow projection
 *       -> renderer
 *       -> GET /
 *
 * The only capability handed toward the Cockpit is {@link AutoflowStateReader}
 * (`current()` only) plus the serialized `unknown` bytes the producer emits. No
 * `open`/`apply`, runtime handle, Policy, provider, or repository handle crosses.
 *
 * No polling, interval, watcher, or background task exists here: a `GET /` is the
 * only thing that triggers an observation, and it does so at most once per
 * request.
 */

import http from 'node:http';
import { pathToFileURL } from 'node:url';

import { produceCockpitSnapshot, type CockpitObservation } from '../cockpit-snapshot/producer.js';
import {
  buildDashboardHtml,
  createCockpitServerFromProvider,
  HOST,
  PORT,
  type CockpitSource,
} from '../cockpit-host/server.js';
import { AutoflowRuntime, type AutoflowStateReader } from '../autoflow/runtime.js';
import {
  createConfiguredRepositoryObserver,
  type RepositoryObserver,
} from './repository-observer.js';

/**
 * Everything the live observation builder needs. `reader` is the narrowed
 * read-only capability (never the runtime writer); `observer` is the narrow
 * repository seam; `collectorId` labels the source; `clock` supplies the
 * whole-observation collection time.
 */
export interface LiveCockpitConfig {
  readonly reader: AutoflowStateReader;
  readonly observer: RepositoryObserver;
  readonly collectorId: string;
  /** Read once per observation for `observedAt` (whole-observation collection time). */
  readonly clock: () => Date;
}

/** Options for {@link startLiveCockpit}. Host/port default to the loopback pin. */
export interface StartLiveCockpitOptions {
  readonly config: LiveCockpitConfig;
  readonly host?: string;
  readonly port?: number;
}

/**
 * Build ONE authoritative {@link CockpitObservation} — the whole-observation
 * capture rule:
 *
 * 1. `observer.observe()` exactly once,
 * 2. `reader.current()` captured exactly once,
 * 3. `clock()` read exactly once for `observedAt`,
 * 4. build one observation,
 *
 * with no `await` between capture and the caller's serialization. `observedAt`
 * is the whole-observation collection time — when this complete observation was
 * collected — not a workflow-transition time. The four read-model lists are
 * honestly empty this milestone (no live PR/evidence/finding/repair collector is
 * in scope). Nothing is fixture-derived or invented.
 */
export function createLiveObservation(config: LiveCockpitConfig): CockpitObservation {
  const repository = config.observer.observe();
  const autoflow = config.reader.current();
  const observedAt = config.clock().toISOString();

  return {
    repositoryId: repository.repositoryId,
    observedHeadSha: repository.observedHeadSha,
    defaultBranchRef: repository.defaultBranchRef,
    collectorId: config.collectorId,
    observedAt,
    pullRequests: [],
    evidence: [],
    findings: [],
    repairJobs: [],
    autoflow,
  };
}

/**
 * The live {@link CockpitSource}: `mode: 'live'` (out-of-band, non-spoofable
 * provenance) and a `read` that builds one whole observation and immediately
 * routes it through {@link produceCockpitSnapshot}'s JSON serialization firewall,
 * returning serialized `unknown`. No live reference crosses; no page/observation
 * is cached; each `read()` is one fresh capture.
 */
export function createLiveCockpitSource(config: LiveCockpitConfig): CockpitSource {
  return {
    mode: 'live',
    read: (): unknown => produceCockpitSnapshot(createLiveObservation(config)),
  };
}

/**
 * Start the live Cockpit host on the loopback address.
 *
 * A **startup readiness probe** builds one page from the live source before
 * listening; if the source or its D1 validation is invalid at startup (a
 * misconfiguration), it throws and the host never binds — startup-fatal, never a
 * fixture fallback. A `current() === null` workflow is valid absence and passes
 * the probe. After binding, each `GET /` rebuilds the page from a fresh
 * observation (so a state change appears on the next GET), and any per-request
 * failure is contained as `500` by the host.
 *
 * The returned server is not yet guaranteed listening; the caller attaches
 * `'listening'`/`'error'` handlers (an `EADDRINUSE` surfaces on `'error'`).
 */
export function startLiveCockpit(options: StartLiveCockpitOptions): http.Server {
  const source = createLiveCockpitSource(options.config);

  // Startup readiness probe: fail closed at startup on invalid initial state.
  // The result is discarded — the per-GET provider re-reads live each request.
  buildDashboardHtml(source);

  const server = createCockpitServerFromProvider((): string => buildDashboardHtml(source));
  server.listen(options.port ?? PORT, options.host ?? HOST);
  return server;
}

/** Read a required environment variable or fail startup. */
function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim().length === 0) {
    throw new Error(`Live Cockpit runtime config invalid: ${name} is required.`);
  }
  return value;
}

/**
 * Production entrypoint (`npm run cockpit:live`). Owns configuration, start,
 * signal handling, and error propagation.
 *
 * Repository observation values are runtime-supplied (environment) — not "live
 * Git observation." The AutoflowRuntime starts owning no workflow (`current()`
 * is `null`), which renders the honest LIVE no-workflow page; this milestone
 * establishes the production write path (`open`/`apply`) but deliberately runs no
 * autonomous event source. Any startup fault exits non-zero (fail closed).
 */
function main(): void {
  let server: http.Server;
  try {
    const runtime = new AutoflowRuntime();
    const observer = createConfiguredRepositoryObserver({
      repositoryId: requireEnv('AGENTBRIDGE_REPOSITORY_ID'),
      observedHeadSha: requireEnv('AGENTBRIDGE_OBSERVED_HEAD_SHA'),
      defaultBranchRef: process.env['AGENTBRIDGE_DEFAULT_BRANCH_REF'] ?? null,
    });
    const collectorId = process.env['AGENTBRIDGE_COLLECTOR_ID'] ?? 'agentbridge-live-runtime';

    server = startLiveCockpit({
      config: { reader: runtime.reader(), observer, collectorId, clock: (): Date => new Date() },
    });
  } catch (error) {
    console.error('AgentBridge Cockpit (live): startup failed.', error);
    process.exit(1);
  }

  server.on('error', (error: NodeJS.ErrnoException): void => {
    console.error('AgentBridge Cockpit (live): host error.', error);
    process.exit(1);
  });
  server.on('listening', (): void => {
    console.log(`AgentBridge Cockpit (live): http://${HOST}:${String(PORT)}/`);
    console.log('READ ONLY — live observation.');
  });

  const shutdown = (): void => {
    server.close((): void => {
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const entryArgument = process.argv[1];
const isEntry = entryArgument !== undefined && import.meta.url === pathToFileURL(entryArgument).href;
if (isEntry) {
  main();
}
