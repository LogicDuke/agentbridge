/**
 * Live Cockpit runtime composition (Live Runtime Wiring milestone, Decision 059).
 *
 * Decision 062 ordering: the post-start control channel is started only after
 * this host has bound its fixed loopback port (see
 * {@link startControlChannelAfterCockpitBind}); a bind loser never publishes a
 * control descriptor, and a control-startup failure never takes the Cockpit down.
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
import { AutoflowOrchestrator } from '../autoflow/orchestrator.js';
import { TRANSITION_OUTCOME } from '../domain/index.js';
import {
  createConfiguredRepositoryObserver,
  type RepositoryObserver,
} from './repository-observer.js';
import {
  readStartupHumanGateConfig,
  readStartupWorkflowConfig,
  STARTUP_HUMAN_GATE_ENV,
  type StartupEnv,
} from './orchestration-input.js';
import {
  startControlChannel,
  type ControlChannelHandle,
} from '../control/control-runtime.js';

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

/**
 * Options for {@link startLiveCockpit}.
 *
 * There is deliberately **no host option**: the supported live runtime is pinned
 * to the loopback {@link HOST} (`127.0.0.1`) and no caller may widen the bind
 * address to `0.0.0.0`, `::`, a LAN, or any routable interface. `port` is
 * optional only so tests can bind an ephemeral port (`0`) on the same loopback
 * address; it never affects which interface is bound.
 */
export interface StartLiveCockpitOptions {
  readonly config: LiveCockpitConfig;
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
  // Loopback pin: the bind address is always HOST (127.0.0.1); it is never
  // caller-controlled, so the live path cannot gain remote-listen authority.
  // Only the port may vary (ephemeral `0` for tests), never the interface.
  server.listen(options.port ?? PORT, HOST);
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
 * Run the whole bounded, synchronous **startup progression** through the one
 * production writer, exactly once at boot (Decision 061 — Startup-Scripted
 * Human-Gate Progression). This is the **single production call site** capable of
 * invoking {@link AutoflowOrchestrator.openHumanGate}: there is no loop, timer,
 * poll, callback, or post-start path anywhere.
 *
 * The authorized boot flow, and the only one:
 *
 * 1. read the bounded startup workflow-open config (existing authorized path);
 * 2. read the startup human-gate trigger **exactly once** (strict `"1"`);
 * 3. gate requested **without** a valid startup-open binding → fail closed (the
 *    trigger carries no identity and may never manufacture a workflow);
 * 4. with a binding, `open` it — a non-`APPLIED` result is startup-fatal;
 * 5. if the gate is requested, submit exactly one `HUMAN_GATE_OPENED` via
 *    {@link AutoflowOrchestrator.openHumanGate} — a non-`APPLIED` result is
 *    startup-fatal.
 *
 * On any misconfiguration or non-`APPLIED` transition this throws, and the caller
 * (`main`) exits non-zero before serving. It is factored out of `main` only so it
 * can be exercised directly without `process.exit`; production reaches it through
 * `main` alone.
 */
export function runStartupProgression(
  orchestrator: AutoflowOrchestrator,
  env: StartupEnv,
  repositoryId: string,
): void {
  const startupBinding = readStartupWorkflowConfig(env, repositoryId);
  // Read the human-gate trigger exactly once; strict "1" or throw.
  const humanGateRequested = readStartupHumanGateConfig(env);

  // The gate trigger cannot open a workflow. Requesting it without a valid
  // startup-open is a misconfiguration — fail closed before serving.
  if (humanGateRequested && startupBinding === null) {
    throw new Error(
      `Live Cockpit runtime: ${STARTUP_HUMAN_GATE_ENV}=1 requires a valid startup ` +
        `workflow-open configuration; the human-gate trigger cannot open a workflow.`,
    );
  }

  if (startupBinding !== null) {
    const opened = orchestrator.open(startupBinding);
    if (opened.outcome !== TRANSITION_OUTCOME.APPLIED) {
      throw new Error(`Live Cockpit runtime: startup workflow open failed (${opened.outcome}).`);
    }
  }

  // The sole production HUMAN_GATE_OPENED submission — one synchronous call, no
  // external event object, bound internally to the workflow's own commit.
  if (humanGateRequested) {
    const gated = orchestrator.openHumanGate();
    if (gated.outcome !== TRANSITION_OUTCOME.APPLIED) {
      throw new Error(`Live Cockpit runtime: startup human-gate open failed (${gated.outcome}).`);
    }
  }
}

/** A control-channel starter; production binds `startControlChannel` over the orchestrator. */
export type ControlChannelStarter = () => Promise<ControlChannelHandle | null>;

/** The bind-gated control channel: `current()` is the handle once (and only if) it started. */
export interface BindGatedControlChannel {
  current(): ControlChannelHandle | null;
}

/**
 * Start the control channel only AFTER the Cockpit host has successfully bound
 * its loopback port (Decision 062 §17, descriptor lifecycle v2 ordering).
 *
 * The fixed loopback bind is the process-level single-runtime gate: a second
 * runtime's bind fails with `EADDRINUSE` and that runtime exits before it ever
 * publishes a control descriptor. This function makes that ordering structural:
 *
 * - `start` is invoked exactly once, from the server's `'listening'` event (or
 *   immediately if it is already listening);
 * - if the server emits `'error'` first (a bind loser), `start` is never invoked
 *   — nothing is published, no pipe is created;
 * - a control-startup failure (a `null` handle or a rejection) is contained and
 *   logged; it never throws into the Cockpit path and never stops the host:
 *   CONTROL_STARTUP_FAILURE ⇏ COCKPIT_FAILURE. Control provisioning is never a
 *   prerequisite for Cockpit availability.
 *
 * No `await` blocks the Cockpit: it is already serving when `start` runs.
 */
export function startControlChannelAfterCockpitBind(
  server: http.Server,
  start: ControlChannelStarter,
  log: (message: string) => void = (message: string): void => {
    console.error(message);
  },
): BindGatedControlChannel {
  let handle: ControlChannelHandle | null = null;
  const state = { started: false, failed: false };
  const begin = (): void => {
    if (state.started || state.failed) {
      return;
    }
    state.started = true;
    let started: Promise<ControlChannelHandle | null>;
    try {
      started = start();
    } catch {
      log('AgentBridge control channel: disabled (startup error).');
      return;
    }
    void started
      .then((result): void => {
        handle = result;
      })
      .catch((): void => {
        // Fail closed; the Cockpit remains available.
        log('AgentBridge control channel: disabled (startup error).');
      });
  };
  server.once('error', (): void => {
    // A bind loser never starts — and therefore never publishes — control.
    state.failed = true;
  });
  if (server.listening) {
    begin();
  } else {
    server.once('listening', begin);
  }
  return { current: (): ControlChannelHandle | null => handle };
}

/**
 * Production entrypoint (`npm run cockpit:live`). Owns configuration, start,
 * signal handling, and error propagation.
 *
 * Repository observation values are runtime-supplied (environment) — not "live
 * Git observation." A single {@link AutoflowRuntime} is owned for writing only by
 * the {@link AutoflowOrchestrator}; the Cockpit is handed the runtime's read-only
 * reader, never the writer. This milestone's production write actions are a
 * bounded **startup workflow open** (from {@link readStartupWorkflowConfig}) and,
 * under Decision 061, an optional bounded **startup human-gate** — both performed
 * once at boot by {@link runStartupProgression}. With no such config the runtime
 * starts owning no workflow (`current()` is `null`), rendering the honest LIVE
 * no-workflow page. It runs **no autonomous event source** — nothing originates a
 * {@link WorkflowEvent} after startup. Any startup fault, including a rejected
 * startup open or human-gate, exits non-zero (fail closed).
 */
function main(): void {
  let server: http.Server;
  let controlChannel: BindGatedControlChannel;
  try {
    const runtime = new AutoflowRuntime();
    const orchestrator = new AutoflowOrchestrator(runtime);
    const repositoryId = requireEnv('AGENTBRIDGE_REPOSITORY_ID');
    const observer = createConfiguredRepositoryObserver({
      repositoryId,
      observedHeadSha: requireEnv('AGENTBRIDGE_OBSERVED_HEAD_SHA'),
      defaultBranchRef: process.env['AGENTBRIDGE_DEFAULT_BRANCH_REF'] ?? null,
    });
    const collectorId = process.env['AGENTBRIDGE_COLLECTOR_ID'] ?? 'agentbridge-live-runtime';

    // Bounded startup progression: the only production write actions this
    // milestone, performed exactly once at boot through the one writer. Any
    // misconfiguration or non-APPLIED transition throws and exits non-zero
    // (fail closed) before serving. No post-start event source exists.
    runStartupProgression(orchestrator, process.env, repositoryId);

    server = startLiveCockpit({
      config: {
        reader: orchestrator.reader(),
        observer,
        collectorId,
        clock: (): Date => new Date(),
      },
    });

    // Decision 062: start the post-start operator control channel only AFTER the
    // read-only Cockpit host has BOUND its loopback port (§17) — the fixed bind
    // is the single-runtime gate, so a bind loser never publishes a descriptor.
    // Control fails **closed** on any fault — an unverified control anchor, a
    // pipe collision, a creation or verification failure disables the channel
    // and returns null; the Cockpit stays up and read-only, and the writer is
    // never exposed to it. Nothing awaits: the Cockpit is already serving.
    controlChannel = startControlChannelAfterCockpitBind(server, async () => {
      const handle = await startControlChannel({ orchestrator });
      if (handle !== null) {
        console.log('AgentBridge control channel: listening (OPEN_HUMAN_GATE).');
      }
      return handle;
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
    const closeServer = (): void => {
      server.close((): void => {
        process.exit(0);
      });
    };
    // Best-effort orderly control-channel shutdown (removes its own
    // identity-named descriptor, then its pipe), then close the Cockpit host.
    const handle = controlChannel.current();
    if (handle !== null) {
      void handle.close().then(closeServer, closeServer);
    } else {
      closeServer();
    }
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const entryArgument = process.argv[1];
const isEntry = entryArgument !== undefined && import.meta.url === pathToFileURL(entryArgument).href;
if (isEntry) {
  main();
}
