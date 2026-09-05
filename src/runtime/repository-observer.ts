/**
 * RepositoryObserver — the narrow, synchronous seam the live composition uses to
 * obtain the repository identity/HEAD an observation is taken against (Live
 * Runtime Wiring milestone, Decision 059).
 *
 * For THIS milestone the one supported production observer echoes
 * **runtime-supplied, immutable, configured repository observation inputs**. It
 * is deliberately NOT a Git/GitHub/subprocess/network observer:
 *
 * - no `child_process`, no Git CLI, no GitHub API, no `fetch`/network;
 * - no filesystem traversal, no hidden repository collection;
 * - no mutation capability of any kind;
 * - the returned observation is frozen, and no repository handle is exposed —
 *   the Cockpit host/renderer/D1/D2/D4 never receive one.
 *
 * These values are runtime-supplied repository observation inputs. They are
 * **not** "live Git observation." A concrete Git/GitHub-backed observer is a
 * separate, deferred authority/capability gate.
 *
 * `observe()` is synchronous so the live `CockpitSource.read(): unknown` needs no
 * signature change. Invalid configuration throws from the factory, so a
 * misconfigured live runtime **fails at startup** rather than per request.
 */

/** One repository observation: identity, observed HEAD, and default branch ref. */
export interface RepositoryObservation {
  readonly repositoryId: string;
  readonly observedHeadSha: string;
  /** Canonical default branch ref, or `null` when not observed. */
  readonly defaultBranchRef: string | null;
}

/** The narrow read seam: obtain the current repository observation. */
export interface RepositoryObserver {
  observe(): RepositoryObservation;
}

/** A non-empty, trimmed identifier string. */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Build the one supported production {@link RepositoryObserver} for this
 * milestone from runtime-supplied immutable values.
 *
 * The configuration is validated eagerly and, on any violation, throws — so an
 * invalid live configuration is a startup-fatal error, never a per-request
 * surprise. The returned observer is frozen and returns the same frozen
 * observation on every call; it performs no I/O.
 *
 * @param input Runtime-supplied repository observation inputs.
 * @throws Error when `repositoryId`/`observedHeadSha` are not non-empty strings,
 *   or `defaultBranchRef` is neither a string nor `null`.
 */
export function createConfiguredRepositoryObserver(
  input: RepositoryObservation,
): RepositoryObserver {
  if (!isNonEmptyString(input.repositoryId)) {
    throw new Error('RepositoryObserver config invalid: repositoryId must be a non-empty string.');
  }
  if (!isNonEmptyString(input.observedHeadSha)) {
    throw new Error(
      'RepositoryObserver config invalid: observedHeadSha must be a non-empty string.',
    );
  }
  if (input.defaultBranchRef !== null && typeof input.defaultBranchRef !== 'string') {
    throw new Error(
      'RepositoryObserver config invalid: defaultBranchRef must be a string or null.',
    );
  }

  const observation: RepositoryObservation = Object.freeze({
    repositoryId: input.repositoryId,
    observedHeadSha: input.observedHeadSha,
    defaultBranchRef: input.defaultBranchRef,
  });

  return Object.freeze<RepositoryObserver>({
    observe: (): RepositoryObservation => observation,
  });
}
