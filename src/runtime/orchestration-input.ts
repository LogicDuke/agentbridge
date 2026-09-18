/**
 * Startup-open input seam for the Autoflow Orchestration Controller milestone
 * (Decision 060).
 *
 * The **only** production trigger for opening a workflow this milestone is
 * bounded, process-scoped **startup configuration**. This module reads that
 * configuration and mints at most one {@link WorkflowBinding}. It is emphatically
 * **not** autonomous observation: there is no network, no GitHub, no Git CLI, no
 * filesystem inbox, no file watcher, no shell, no timer, and no generated or
 * random identity. Every identity is operator-supplied and exact.
 *
 * ## Environment contract
 *
 * - `AGENTBRIDGE_WORKFLOW_ID` — required when a startup open is requested.
 * - `AGENTBRIDGE_WORKFLOW_BOUND_COMMIT_SHA` — required when requested.
 * - `AGENTBRIDGE_WORKFLOW_PULL_REQUEST_ID` — optional.
 * - `AGENTBRIDGE_WORKFLOW_REPOSITORY_ID` — optional; when present it MUST equal
 *   the configured runtime repository identity. When absent, the workflow's
 *   repository identity **is** the runtime identity (explicit equality by
 *   construction), so one snapshot can never describe two repositories.
 *
 * ## Fail-closed behavior
 *
 * - **No** workflow-open variable present (required or optional) → no startup
 *   workflow (`null`); the runtime starts honestly with `current() === null`.
 * - A complete, consistent request → exactly one {@link WorkflowBinding}.
 * - A **partial** request — any workflow-open variable present while the
 *   required set (`workflowId` + `boundCommitSha`) is incomplete, including an
 *   optional-only request (just `pullRequestId`, or just the workflow
 *   repository identity) → throws; startup fails closed. No partially-minted
 *   binding is returned.
 * - A repository-identity **mismatch** → throws; startup fails closed.
 *
 * Field-*content* validity (non-empty, length bounds, exact-identifier shape) is
 * **not** re-judged here: it is the sole responsibility of the domain
 * `openWorkflow`, which rejects a malformed binding. The composition treats a
 * non-`APPLIED` startup open as startup-fatal, so a malformed value also fails
 * closed — without duplicating the domain's validation authority.
 */

import type { WorkflowBinding } from '../domain/index.js';

/** The environment shape this seam reads. `process.env` satisfies it. */
export type StartupEnv = Readonly<Record<string, string | undefined>>;

/** Environment variable names that make up the startup-open contract. */
export const WORKFLOW_OPEN_ENV = Object.freeze({
  WORKFLOW_ID: 'AGENTBRIDGE_WORKFLOW_ID',
  BOUND_COMMIT_SHA: 'AGENTBRIDGE_WORKFLOW_BOUND_COMMIT_SHA',
  PULL_REQUEST_ID: 'AGENTBRIDGE_WORKFLOW_PULL_REQUEST_ID',
  REPOSITORY_ID: 'AGENTBRIDGE_WORKFLOW_REPOSITORY_ID',
} as const);

/**
 * The startup human-gate trigger variable (Decision 061 — Startup-Scripted
 * Human-Gate Progression).
 *
 * This is a **presence-and-exact-value** trigger only. It carries no workflow
 * identity, no commit, and no repository — it can never manufacture or open a
 * workflow. It merely requests that, *after* a separately-configured startup
 * workflow-open has succeeded, exactly one `HUMAN_GATE_OPENED` event be
 * submitted at boot. Requesting the gate without a valid startup-open is a
 * misconfiguration that the composition treats as startup-fatal.
 */
export const STARTUP_HUMAN_GATE_ENV = 'AGENTBRIDGE_STARTUP_OPEN_HUMAN_GATE';

/**
 * Read the startup human-gate trigger with **exact-value** semantics
 * (Decision 061).
 *
 * The variable is read **exactly once** into an inert local and never consulted
 * again:
 *
 * - absent (`undefined`) → not requested (`false`);
 * - the exact byte string `"1"` → requested (`true`);
 * - any other present value → **invalid configuration**; throws so startup fails
 *   closed before serving.
 *
 * There is deliberately **no** trimming, case-folding, `Boolean(value)`,
 * `Number(value)`, or truthy/loose parsing: `"0"`, `"false"`, `"true"`, `"yes"`,
 * `"no"`, `" "`, `"01"`, and every other value but `"1"` are rejected. An empty
 * string is a present-but-invalid value and is rejected too.
 *
 * @param env The process-scoped environment (typically `process.env`).
 * @returns `true` when the gate is requested, `false` when absent.
 * @throws Error when the variable is present with any value other than `"1"`.
 */
export function readStartupHumanGateConfig(env: StartupEnv): boolean {
  const raw = env[STARTUP_HUMAN_GATE_ENV];
  if (raw === undefined) {
    return false;
  }
  if (raw === '1') {
    return true;
  }
  throw new Error(
    `Startup human-gate config invalid: ${STARTUP_HUMAN_GATE_ENV} must be exactly "1" when set.`,
  );
}

/**
 * Read the bounded startup-open configuration and mint at most one
 * {@link WorkflowBinding}.
 *
 * @param env The process-scoped environment (typically `process.env`).
 * @param runtimeRepositoryId The already-validated runtime repository identity
 *   (`AGENTBRIDGE_REPOSITORY_ID`). The minted binding's `repositoryId` equals
 *   this value, and an explicit `AGENTBRIDGE_WORKFLOW_REPOSITORY_ID`, if
 *   supplied, must match it exactly.
 * @returns One {@link WorkflowBinding} when a complete, consistent startup open
 *   is requested; `null` when no startup open is requested.
 * @throws Error when the request is partial or the repository identity
 *   mismatches — startup must fail closed.
 */
export function readStartupWorkflowConfig(
  env: StartupEnv,
  runtimeRepositoryId: string,
): WorkflowBinding | null {
  const workflowId = env[WORKFLOW_OPEN_ENV.WORKFLOW_ID];
  const boundCommitSha = env[WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA];
  const pullRequestId = env[WORKFLOW_OPEN_ENV.PULL_REQUEST_ID];
  const workflowRepositoryId = env[WORKFLOW_OPEN_ENV.REPOSITORY_ID];

  // A startup open is "requested" if **any** workflow-open variable is present —
  // required or optional. An optional-only request (e.g. only the pull-request
  // id, or only the workflow repository identity) is a *partial* request and
  // must fail closed below, never be read as "no startup workflow". Presence is
  // `!== undefined`: an empty string is present-but-malformed and reaches the
  // domain's rejection, never absence.
  const requested =
    workflowId !== undefined ||
    boundCommitSha !== undefined ||
    pullRequestId !== undefined ||
    workflowRepositoryId !== undefined;
  if (!requested) {
    return null;
  }

  if (workflowId === undefined || boundCommitSha === undefined) {
    throw new Error(
      `Startup workflow-open config invalid: both ${WORKFLOW_OPEN_ENV.WORKFLOW_ID} and ` +
        `${WORKFLOW_OPEN_ENV.BOUND_COMMIT_SHA} are required to open a startup workflow.`,
    );
  }

  if (workflowRepositoryId !== undefined && workflowRepositoryId !== runtimeRepositoryId) {
    throw new Error(
      `Startup workflow-open config invalid: ${WORKFLOW_OPEN_ENV.REPOSITORY_ID} ` +
        `must equal the runtime repository identity.`,
    );
  }

  const binding: WorkflowBinding =
    pullRequestId === undefined
      ? { workflowId, repositoryId: runtimeRepositoryId, boundCommitSha }
      : { workflowId, repositoryId: runtimeRepositoryId, boundCommitSha, pullRequestId };

  return binding;
}

/**
 * Environment variable names that make up the Autoflow Job #1 contract
 * (Decision 065 Revision 2).
 *
 * Every value is **operator-supplied and exact**. Nothing here is discovered,
 * generated, defaulted, or widened: the candidate identity is immutable and fixed
 * at boot (Decision 065 §2), so there is no variable that lets the runtime choose
 * a candidate, and no variable that carries a token, a credential, or a URL.
 */
export const JOB1_ENV = Object.freeze({
  /** Presence-and-exact-value trigger. Exactly `"1"` enables Job #1. */
  ENABLED: 'AGENTBRIDGE_JOB1_ENABLED',
  /** The immutable candidate ref, e.g. `refs/heads/repair/foo`. */
  CANDIDATE_REF: 'AGENTBRIDGE_JOB1_CANDIDATE_REF',
  /** The immutable candidate SHA. 40 lowercase hex. */
  CANDIDATE_SHA: 'AGENTBRIDGE_JOB1_CANDIDATE_SHA',
  /** The configured authoritative main SHA. */
  MAIN_SHA: 'AGENTBRIDGE_JOB1_AUTHORITATIVE_MAIN_SHA',
  /** Absolute path to the managed repository. */
  REPOSITORY_PATH: 'AGENTBRIDGE_JOB1_REPOSITORY_PATH',
  /** Absolute runtime root, used as the observer child's `HOME`. */
  RUNTIME_ROOT: 'AGENTBRIDGE_JOB1_RUNTIME_ROOT',
  /** Path to the PRE-RUN gate's governance run manifest document. */
  MANIFEST_PATH: 'AGENTBRIDGE_JOB1_MANIFEST_PATH',
  /** The manifest digest, supplied out of band from the document itself. */
  MANIFEST_SHA256: 'AGENTBRIDGE_JOB1_MANIFEST_SHA256',
  /** Externally supplied assessment timestamp. Observation data, not a clock read. */
  GENERATED_AT: 'AGENTBRIDGE_JOB1_GENERATED_AT',
} as const);

/**
 * The bounded Job #1 startup configuration, or `null` when Job #1 is not
 * requested.
 *
 * `owner`/`repo` are split from the runtime repository identity rather than
 * configured separately, so one snapshot can never describe two repositories and
 * there is no variable through which a caller could point the GitHub path at a
 * different repository than the one being observed.
 */
export interface Job1Config {
  readonly owner: string;
  readonly repo: string;
  readonly candidateRef: string;
  readonly candidateSha: string;
  readonly authoritativeMainSha: string;
  readonly repositoryPath: string;
  readonly runtimeRoot: string;
  readonly manifestPath: string;
  readonly manifestDigest: string;
  readonly generatedAt: string;
}

/**
 * Read the bounded Job #1 startup configuration.
 *
 * **Fail-closed, exactly as the workflow-open seam is:**
 *
 * - `AGENTBRIDGE_JOB1_ENABLED` absent → Job #1 not requested (`null`);
 * - present and not exactly `"1"` → throws; startup fails closed;
 * - enabled with any required variable missing or blank → throws;
 * - a `repositoryId` that is not exactly `owner/repo` → throws.
 *
 * There is deliberately no trimming, case-folding, or truthy parsing of the
 * trigger, and no default for any required value. Field-*content* validity
 * beyond non-blankness is not re-judged here: the observer validates the ref and
 * SHAs against their exact readers, and an invalid value makes its fact
 * indeterminate — hence `BLOCKED` — rather than being silently corrected.
 *
 * @param env The process-scoped environment (typically `process.env`).
 * @param runtimeRepositoryId The already-validated runtime repository identity.
 * @throws Error when the request is enabled but incomplete or inconsistent.
 */
export function readJob1Config(env: StartupEnv, runtimeRepositoryId: string): Job1Config | null {
  const raw = env[JOB1_ENV.ENABLED];
  if (raw === undefined) {
    return null;
  }
  if (raw !== '1') {
    throw new Error(`Job #1 config invalid: ${JOB1_ENV.ENABLED} must be exactly "1" when set.`);
  }

  const required = (name: string): string => {
    const value = env[name];
    if (value === undefined || value.trim().length === 0) {
      throw new Error(`Job #1 config invalid: ${name} is required when Job #1 is enabled.`);
    }
    return value;
  };

  const slash = runtimeRepositoryId.indexOf('/');
  if (slash <= 0 || slash !== runtimeRepositoryId.lastIndexOf('/') || slash === runtimeRepositoryId.length - 1) {
    throw new Error(
      'Job #1 config invalid: the runtime repository identity must be exactly "owner/repo".',
    );
  }

  return {
    owner: runtimeRepositoryId.slice(0, slash),
    repo: runtimeRepositoryId.slice(slash + 1),
    candidateRef: required(JOB1_ENV.CANDIDATE_REF),
    candidateSha: required(JOB1_ENV.CANDIDATE_SHA),
    authoritativeMainSha: required(JOB1_ENV.MAIN_SHA),
    repositoryPath: required(JOB1_ENV.REPOSITORY_PATH),
    runtimeRoot: required(JOB1_ENV.RUNTIME_ROOT),
    manifestPath: required(JOB1_ENV.MANIFEST_PATH),
    manifestDigest: required(JOB1_ENV.MANIFEST_SHA256),
    generatedAt: required(JOB1_ENV.GENERATED_AT),
  };
}
