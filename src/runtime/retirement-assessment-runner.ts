/**
 * Autoflow Job #1 runner — observation, classification, and the
 * post-classification evidence-integrity sequence (Decision 065 Revision 2).
 *
 * The one place the whole Job #1 causal chain is expressed, in this exact order:
 *
 * ```
 *   F1..F10 (observed)
 *     -> classifyRetirementCandidate        [pure; no digest input exists]
 *     -> immutable assessment body
 *     -> AB-CJSON-1 canonical bytes
 *     -> SHA-256 evidenceId                 [runtime layer only]
 *     -> I1 self-check
 *     -> I2 store put
 *     -> admission (EVIDENCE_ADMITTED)
 *     -> conditional HUMAN_GATE_OPENED      [only for RETIRE_ELIGIBLE]
 * ```
 *
 * The arrow from classification to digest is **one-way**. The classifier runs to
 * completion before any digest exists, and no integrity outcome is ever fed back
 * into it: a digest failure aborts the run, it never becomes a classification
 * (Decision 065 §14).
 *
 * ## Where each failure goes
 *
 * There are exactly two failure destinations, and they are not interchangeable:
 *
 * - **Observation failures** — a manifest that did not verify, a Git operation
 *   that timed out, a truncated output, a GitHub non-200, a contradiction —
 *   become indeterminate facts, hence `BLOCKED`, and the assessment **is still
 *   admitted** so the Cockpit can show *why*. This is the informative path.
 * - **Integrity failures** — a body that will not canonicalize, a digest
 *   self-check mismatch, a refused store put, a rejected admission — abort the
 *   run before serving. Nothing is admitted, no gate is opened, and the caller
 *   exits non-zero. This is the fail-closed path.
 *
 * ## The gate
 *
 * `openHumanGate()` is called **once**, and only when the *admitted*
 * classification is `RETIRE_ELIGIBLE`. `PRESERVE_FOR_HISTORY` and `BLOCKED` stop
 * without a gate, leaving the workflow `OPEN` at sequence 1 with
 * `gateRequested: false` — the "open but inert" boundary. Opening the gate grants
 * no mutation authority and originates nothing further (Decision 065 §9).
 *
 * ## Authority
 *
 * Read-only against the managed repository, throughout. Nothing here deletes a
 * worktree, branch, or remote ref; commits; pushes; creates, updates, or merges a
 * PR; resolves a thread; deploys; or crosses the human gate.
 */

import { readFileSync } from 'node:fs';

import type { AutoflowOrchestrator } from '../autoflow/orchestrator.js';
import { AUTOFLOW_ASSESSMENT_REFUSED } from '../autoflow/orchestrator.js';
import { TRANSITION_OUTCOME } from '../domain/index.js';
import {
  classifyRetirementCandidate,
  determinate,
  GOVERNANCE_HOLD,
  INDETERMINATE,
  RETIREMENT_CLASSIFICATION,
  toFactRecords,
  type RetirementAssessmentBody,
  type RetirementAssessmentEnvelope,
  type RetirementFact,
  type RetirementFacts,
} from '../domain/retirement-assessment.js';
import { readCanonicalBranchRef } from '../domain/repair-job.js';
import {
  verifyGovernanceRunManifest,
  type GovernanceRunManifest,
  type ManifestVerification,
} from './retirement-manifest.js';
import {
  createRetirementGitObserver,
  readFullSha,
  type RetirementGitObserver,
} from './retirement-git-observer.js';
import {
  createRetirementGitHubClient,
  type GitHubGet,
  type RetirementGitHubClient,
} from './retirement-github-client.js';
import {
  createRetirementAssessmentStore,
  sha256Canonical,
  type RetirementAssessmentStore,
} from './retirement-assessment-store.js';

const objectFreeze = Object.freeze;
const objectSetPrototypeOf = Object.setPrototypeOf;

function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

/** The observer build identity recorded on every assessment body. Audit only. */
export const OBSERVER_VERSION = 'agentbridge-job1-observer/1';

/**
 * Why a run aborted before serving. A closed vocabulary; every member is an
 * **integrity** failure, never an observation failure and never a classification.
 */
export const RUN_ABORT = objectFreeze({
  /** The assessment body has no AB-CJSON-1 canonical form, so it has no digest. */
  NOT_CANONICALIZABLE: 'NOT_CANONICALIZABLE',
  /** I1: re-digesting the body did not reproduce the computed `evidenceId`. */
  SELF_CHECK_FAILED: 'SELF_CHECK_FAILED',
  /** I2: the store refused the envelope. */
  STORE_REFUSED: 'STORE_REFUSED',
  /** Admission was refused or rejected by the orchestrator/domain. */
  ADMISSION_REJECTED: 'ADMISSION_REJECTED',
  /** The human gate was requested but the transition did not apply. */
  GATE_FAILED: 'GATE_FAILED',
} as const);

export type RunAbort = (typeof RUN_ABORT)[keyof typeof RUN_ABORT];

/** The outcome of one Job #1 run. */
export interface RetirementRunResult {
  /** `true` when the assessment was admitted (whatever its classification). */
  readonly admitted: boolean;
  /** The admitted envelope, or `null` when the run aborted. */
  readonly envelope: RetirementAssessmentEnvelope | null;
  /** `true` exactly when `HUMAN_GATE_OPENED` was applied. */
  readonly gateOpened: boolean;
  /** Non-null exactly when the run aborted before serving. */
  readonly abort: RunAbort | null;
}

/** The immutable, human-configured Job #1 run identity. Fixed at boot. */
export interface RetirementRunConfig {
  readonly repositoryId: string;
  /** `owner` and `repo` for the GitHub path, split from `repositoryId` by the caller. */
  readonly owner: string;
  readonly repo: string;
  /** The immutable candidate ref. Job #1 never discovers or widens this. */
  readonly candidateRef: string;
  /** The immutable candidate SHA. Job #1 never originates `HEAD_OBSERVED`. */
  readonly candidateSha: string;
  /** The configured authoritative main SHA. Drift makes F3 false. */
  readonly authoritativeMainSha: string;
  /** Absolute path to the managed repository. Becomes the observer's cwd. */
  readonly repositoryPath: string;
  /** Absolute runtime root. Becomes the observer child's `HOME`. */
  readonly runtimeRoot: string;
  /** Path to the PRE-RUN gate's manifest document. */
  readonly manifestPath: string;
  /** `AGENTBRIDGE_JOB1_MANIFEST_SHA256`, supplied out of band from the document. */
  readonly manifestDigest: string;
  /** Externally supplied assessment timestamp. Data, not a clock read here. */
  readonly generatedAt: string;
  /** Boot instant in epoch milliseconds, for the manifest freshness window. */
  readonly bootEpochMs: number;
  readonly platform: 'win32' | 'posix';
  /** Source environment for the observer's three passthrough names. */
  readonly environmentSource: Readonly<Record<string, string | undefined>>;
  /** Test seam: a fake GitHub GET. Omit in production. */
  readonly githubGet?: GitHubGet;
  /** Test seam: a pre-read manifest document. Omit to read `manifestPath`. */
  readonly manifestText?: string;
}

/* ------------------------------------------------------------------------- *
 * Fact observation
 * ------------------------------------------------------------------------- */

/** Everything the observation step needs, already constructed. */
interface ObservationParts {
  readonly observer: RetirementGitObserver;
  readonly github: RetirementGitHubClient;
  readonly verification: ManifestVerification;
  readonly config: RetirementRunConfig;
}

/**
 * Observe F1..F10.
 *
 * Every fact is produced independently and every failure folds to
 * {@link INDETERMINATE} — never to a default, never to a permissive value, and
 * never to a classification. The observation is deliberately *complete*: facts
 * are not short-circuited when an earlier one is already indeterminate, so the
 * Cockpit can show the whole picture of what was and was not establishable.
 */
async function observeFacts(parts: ObservationParts): Promise<RetirementFacts> {
  const { observer, github, verification, config } = parts;
  const candidateRef = readCanonicalBranchRef(config.candidateRef);
  const candidateSha = readFullSha(config.candidateSha);
  const mainSha = readFullSha(config.authoritativeMainSha);

  // F1 — the locally resolved candidate ref equals the configured immutable SHA.
  let f1: RetirementFact<boolean> = INDETERMINATE;
  if (candidateRef !== null && candidateSha !== null) {
    const resolved = await observer.resolveRef(candidateRef);
    f1 = resolved.determinate ? determinate(resolved.value === candidateSha) : INDETERMINATE;
  }

  // F2 — the remote's candidate ref agrees with the configured SHA. A remote that
  // does not carry the ref at all is a disagreement, not an absence to excuse:
  // the configured identity claims a ref the remote does not have.
  // F3 — authoritative main equals the configured value.
  let f2: RetirementFact<boolean> = INDETERMINATE;
  let f3: RetirementFact<boolean> = INDETERMINATE;
  let remoteCandidateSha: string | null = null;
  let remoteObserved = false;
  if (candidateRef !== null && candidateSha !== null && mainSha !== null) {
    const remote = await observer.remoteRefs(candidateRef);
    if (remote.determinate) {
      remoteObserved = true;
      remoteCandidateSha = remote.value.candidateSha;
      f2 = determinate(remote.value.candidateSha === candidateSha);
      f3 = determinate(remote.value.mainSha === mainSha);
    }
  }

  // F4 — containment. F5 — unique commits. F6 — unique patches.
  let f4: RetirementFact<boolean> = INDETERMINATE;
  let f5: RetirementFact<number> = INDETERMINATE;
  let f6: RetirementFact<number> = INDETERMINATE;
  if (candidateSha !== null && mainSha !== null) {
    f4 = await observer.isAncestor(candidateSha, mainSha);
    f5 = await observer.uniqueCommitCount(mainSha, candidateSha);
    f6 = await observer.uniquePatchCount(mainSha, candidateSha);
  }

  // F7 — every registered worktree on the candidate is clean and not prunable.
  // A worktree list that reports the candidate nowhere is vacuously clean; a
  // prunable registration is not, and neither is a dirty status.
  let f7: RetirementFact<boolean> = INDETERMINATE;
  const worktrees = await observer.worktrees();
  if (worktrees.determinate) {
    let clean = true;
    let indeterminate = false;
    for (let index = 0; index < worktrees.value.length; index += 1) {
      const entry = worktrees.value[index];
      if (entry === undefined) {
        continue;
      }
      const onCandidate =
        (candidateRef !== null && entry.branchRef === candidateRef) ||
        (candidateSha !== null && entry.headSha === candidateSha);
      if (!onCandidate) {
        continue;
      }
      if (entry.prunable) {
        clean = false;
        continue;
      }
      const status = await observer.worktreeClean(entry.path);
      if (!status.determinate) {
        indeterminate = true;
      } else if (!status.value) {
        clean = false;
      }
    }
    f7 = indeterminate ? INDETERMINATE : determinate(clean);
  }

  // F8 — GitHub dependency clearance. Every listed check must clear; any one that
  // cannot be established makes the whole fact indeterminate.
  const f8 = await observeDependencyClearance({
    github,
    observer,
    candidateRef,
    remoteCandidateSha,
    remoteObserved,
  });

  // F9 — the verified governance manifest's hold result. A failed verification is
  // indeterminate, never `NO_HOLD`.
  const f9: RetirementFact<typeof GOVERNANCE_HOLD.HOLD | typeof GOVERNANCE_HOLD.NO_HOLD> =
    verification.holdResult === null ? INDETERMINATE : determinate(verification.holdResult);

  // F10 — the candidate is not main, not the default branch, and not protected.
  const f10 = await observeNotProtected({ github, candidateRef });

  return freezeRecord({
    f1CandidateIdentity: f1,
    f2RemoteAgreement: f2,
    f3StableMain: f3,
    f4Containment: f4,
    f5UniqueCommits: f5,
    f6UniquePatches: f6,
    f7WorktreeClean: f7,
    f8DependencyClearance: f8,
    f9GovernanceManifest: f9,
    f10NotProtected: f10,
  });
}

interface ClearanceParts {
  readonly github: RetirementGitHubClient;
  readonly observer: RetirementGitObserver;
  readonly candidateRef: string | null;
  readonly remoteCandidateSha: string | null;
  readonly remoteObserved: boolean;
}

/**
 * F8 — dependency clearance. **All** of these must clear:
 *
 * - no open PR has the candidate as head;
 * - no open PR has the candidate as base;
 * - the branch resource agrees with `ls-remote` (a 200 whose commit SHA equals
 *   the remote's, or a 404 consistent with remote absence) and is not protected;
 * - no open issue's title or body mentions the branch name;
 * - no local branch has the candidate's remote ref as its configured upstream.
 *
 * Any non-200, malformed body, non-terminating pagination, or contradiction
 * between GitHub and Git makes F8 **indeterminate**.
 */
async function observeDependencyClearance(
  parts: ClearanceParts,
): Promise<RetirementFact<boolean>> {
  const { github, observer, candidateRef, remoteCandidateSha, remoteObserved } = parts;
  if (candidateRef === null || !remoteObserved) {
    return INDETERMINATE;
  }
  const shortName = candidateRef.slice('refs/heads/'.length);

  const pulls = await github.openPullRequests();
  if (!pulls.determinate) {
    return INDETERMINATE;
  }
  let clear = true;
  for (let index = 0; index < pulls.value.length; index += 1) {
    const pull = pulls.value[index];
    if (pull === undefined) {
      continue;
    }
    if (pull.headRef === shortName || pull.baseRef === shortName) {
      clear = false;
    }
  }

  const branch = await github.branch(candidateRef);
  if (!branch.determinate) {
    return INDETERMINATE;
  }
  if (branch.value === null) {
    // A 404 must agree with `ls-remote`: if the remote listed the ref, GitHub and
    // Git disagree about the same repository, and a contradiction is
    // indeterminate rather than resolved in either direction.
    if (remoteCandidateSha !== null) {
      return INDETERMINATE;
    }
  } else {
    if (remoteCandidateSha === null || branch.value.commitSha !== remoteCandidateSha) {
      return INDETERMINATE;
    }
    if (branch.value.protected) {
      clear = false;
    }
  }

  const issues = await github.openIssues();
  if (!issues.determinate) {
    return INDETERMINATE;
  }
  for (let index = 0; index < issues.value.length; index += 1) {
    const issue = issues.value[index];
    if (issue === undefined) {
      continue;
    }
    if (issue.title.includes(shortName) || issue.body.includes(shortName)) {
      clear = false;
    }
  }

  const upstreams = await observer.branchUpstreams();
  if (!upstreams.determinate) {
    return INDETERMINATE;
  }
  const remoteUpstream = 'refs/remotes/origin/' + shortName;
  for (let index = 0; index < upstreams.value.length; index += 1) {
    const entry = upstreams.value[index];
    if (entry === undefined) {
      continue;
    }
    if (entry.upstreamRef === remoteUpstream) {
      clear = false;
    }
  }

  return determinate(clear);
}

/** F10 — the candidate is not `main`, not the default branch, and not protected. */
async function observeNotProtected(parts: {
  readonly github: RetirementGitHubClient;
  readonly candidateRef: string | null;
}): Promise<RetirementFact<boolean>> {
  const { github, candidateRef } = parts;
  if (candidateRef === null) {
    return INDETERMINATE;
  }
  const shortName = candidateRef.slice('refs/heads/'.length);
  if (shortName === 'main' || shortName === 'master') {
    // A literal main/master candidate is refused without asking GitHub: the
    // answer cannot depend on a network call succeeding.
    return determinate(false);
  }
  const repository = await github.repository();
  if (!repository.determinate) {
    return INDETERMINATE;
  }
  if (repository.value.defaultBranch === shortName) {
    return determinate(false);
  }
  const branch = await github.branch(candidateRef);
  if (!branch.determinate) {
    return INDETERMINATE;
  }
  // An absent branch is not a protected branch.
  return determinate(branch.value === null || !branch.value.protected);
}

/* ------------------------------------------------------------------------- *
 * The run
 * ------------------------------------------------------------------------- */

/** Everything one run produces besides the workflow effects. */
export interface RetirementRunParts {
  readonly store: RetirementAssessmentStore;
  readonly result: RetirementRunResult;
}

/** Build the frozen abort result. */
function aborted(abort: RunAbort): RetirementRunResult {
  return freezeRecord({ admitted: false, envelope: null, gateOpened: false, abort });
}

/**
 * Run Job #1 exactly once.
 *
 * Returns the store (for the composition root to hand to the producer as data)
 * and the run result. The caller treats a non-null `abort` as startup-fatal and
 * exits non-zero **before serving** — the Cockpit must never show a page built
 * from a run whose integrity could not be established.
 *
 * @param orchestrator The single production writer. Its `admitRetirementAssessment`
 *   and `openHumanGate` are the only two event origins reached here.
 * @param config The immutable, human-configured run identity.
 */
export async function runRetirementAssessment(
  orchestrator: AutoflowOrchestrator,
  config: RetirementRunConfig,
): Promise<RetirementRunParts> {
  const store = createRetirementAssessmentStore();

  // 1. Verify the governance run manifest. A failure is NOT fatal: it makes F9
  //    indeterminate, the classification BLOCKED, and the assessment is still
  //    admitted so the Cockpit can say the manifest did not verify.
  let manifestText: string;
  if (config.manifestText !== undefined) {
    manifestText = config.manifestText;
  } else {
    try {
      manifestText = readFileSync(config.manifestPath, 'utf8');
    } catch {
      manifestText = '';
    }
  }
  const verification = verifyGovernanceRunManifest({
    manifestText,
    expectedDigest: config.manifestDigest,
    candidateRef: config.candidateRef,
    candidateSha: config.candidateSha,
    authoritativeMainSha: config.authoritativeMainSha,
    bootEpochMs: config.bootEpochMs,
  });

  // 2. Build the observer against the manifest's pinned git identity. With no
  //    verified manifest there is no pinned identity to bind to, so the observer
  //    is built against an unusable path and every Git fact folds to
  //    indeterminate — the run still proceeds to an admitted BLOCKED assessment.
  const manifest: GovernanceRunManifest | null = verification.manifest;
  const observer = createRetirementGitObserver({
    gitPath: manifest === null ? '' : manifest.git.path,
    gitSha256: manifest === null ? '' : manifest.git.sha256,
    repositoryPath: config.repositoryPath,
    runtimeRoot: config.runtimeRoot,
    environmentSource: config.environmentSource,
    platform: config.platform,
  });

  // The executable identity is verified at boot, before any operation runs
  // (Amendment 1 A-6). An unverified executable means no Git fact may be
  // observed at all.
  const executableVerified = manifest !== null && observer.verifyExecutable();

  const github = createRetirementGitHubClient(
    config.githubGet === undefined
      ? { owner: config.owner, repo: config.repo }
      : { owner: config.owner, repo: config.repo, get: config.githubGet },
  );

  // 3. Observe F1..F10.
  const facts = executableVerified
    ? await observeFacts({ observer, github, verification, config })
    : await observeWithoutGit({ github, verification, config });

  // 4. Classify. Pure, and the last point at which the classification is decided:
  //    nothing below can change it.
  const assessed = classifyRetirementCandidate(facts);

  // 5. Build the immutable body.
  const body: RetirementAssessmentBody = {
    repositoryId: config.repositoryId,
    candidateRef: config.candidateRef,
    candidateSha: config.candidateSha,
    authoritativeMainSha: config.authoritativeMainSha,
    facts: toFactRecords(facts),
    classification: assessed.classification,
    reasonCodes: assessed.reasonCodes,
    gateRequested: assessed.gateRequested,
    // The manifest digest is recorded as identity even when verification failed,
    // so the Cockpit can name which document was presented. `null` is not an
    // option on this field, so an unverifiable digest is recorded as the
    // all-zero pointer — a value that can never be a real SHA-256 of a document
    // this system produced, and that reads as "no verified manifest".
    manifestDigest: verification.digest ?? UNVERIFIED_MANIFEST_DIGEST,
    generatedAt: config.generatedAt,
    observerVersion: OBSERVER_VERSION,
  };

  // 6. Canonicalize and digest. Runtime layer only.
  const evidenceId = sha256Canonical(body);
  if (evidenceId === null) {
    return { store, result: aborted(RUN_ABORT.NOT_CANONICALIZABLE) };
  }

  const envelope: RetirementAssessmentEnvelope = freezeRecord({ evidenceId, body });

  // 7. I1 — runner self-check. Re-digest and compare. A mismatch means the body
  //    changed under us between digest and envelope construction; nothing is
  //    admitted and no gate opens.
  if (sha256Canonical(envelope.body) !== evidenceId) {
    return { store, result: aborted(RUN_ABORT.SELF_CHECK_FAILED) };
  }

  // 8. I2 — store put.
  const put = store.put(envelope);
  if (!put.stored) {
    return { store, result: aborted(RUN_ABORT.STORE_REFUSED) };
  }

  // 9. Admission.
  const admitted = orchestrator.admitRetirementAssessment(envelope);
  if (
    admitted.outcome === AUTOFLOW_ASSESSMENT_REFUSED ||
    admitted.outcome !== TRANSITION_OUTCOME.APPLIED
  ) {
    return { store, result: aborted(RUN_ABORT.ADMISSION_REJECTED) };
  }

  // 10. The gate — once, and only for an admitted RETIRE_ELIGIBLE. The
  //     classification consulted here is the one that was admitted, not a
  //     re-derivation.
  let gateOpened = false;
  if (envelope.body.classification === RETIREMENT_CLASSIFICATION.RETIRE_ELIGIBLE) {
    const gate = orchestrator.openHumanGate();
    if (gate.outcome !== TRANSITION_OUTCOME.APPLIED) {
      return { store, result: aborted(RUN_ABORT.GATE_FAILED) };
    }
    gateOpened = true;
  }

  return {
    store,
    result: freezeRecord({ admitted: true, envelope, gateOpened, abort: null }),
  };
}

/**
 * The all-zero pointer recorded when no manifest digest could be computed.
 *
 * It is a well-formed `evidenceId` so the body still reads and canonicalizes, and
 * it is not a value any real document digests to, so it cannot be mistaken for a
 * verified manifest. F9 is independently indeterminate in this case, so the
 * classification is `BLOCKED` regardless of what this field says.
 */
const UNVERIFIED_MANIFEST_DIGEST = 'sha256:' + '0'.repeat(64);

/**
 * Observe F1..F10 when the git executable could not be verified.
 *
 * Every Git-derived fact is indeterminate by construction — no operation is
 * attempted at all, because an unverified executable is not one this observer may
 * run (Amendment 1 A-6). The GitHub-derived and manifest-derived facts are still
 * observed, so the Cockpit shows everything that *was* establishable.
 */
async function observeWithoutGit(parts: {
  readonly github: RetirementGitHubClient;
  readonly verification: ManifestVerification;
  readonly config: RetirementRunConfig;
}): Promise<RetirementFacts> {
  const { github, verification, config } = parts;
  const candidateRef = readCanonicalBranchRef(config.candidateRef);
  const f9: RetirementFact<typeof GOVERNANCE_HOLD.HOLD | typeof GOVERNANCE_HOLD.NO_HOLD> =
    verification.holdResult === null ? INDETERMINATE : determinate(verification.holdResult);
  const f10 = await observeNotProtected({ github, candidateRef });
  return freezeRecord({
    f1CandidateIdentity: INDETERMINATE,
    f2RemoteAgreement: INDETERMINATE,
    f3StableMain: INDETERMINATE,
    f4Containment: INDETERMINATE,
    f5UniqueCommits: INDETERMINATE,
    f6UniquePatches: INDETERMINATE,
    f7WorktreeClean: INDETERMINATE,
    // F8 cannot clear without the Git-side upstream check, so it is indeterminate
    // rather than partially established from GitHub alone.
    f8DependencyClearance: INDETERMINATE,
    f9GovernanceManifest: f9,
    f10NotProtected: f10,
  });
}
