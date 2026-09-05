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
