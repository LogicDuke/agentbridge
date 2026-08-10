/**
 * Deterministic normalization of untrusted agent output.
 *
 *     trusted invocation binding + untrusted agent report -> InvocationReportResult
 *
 * PR 006 scope: normalization only. Nothing here invokes an agent, calls
 * GitHub, Claude, OpenAI, or CodeRabbit, opens a socket, reads a clock, touches
 * the filesystem, spawns a process, persists anything, verifies an artifact,
 * detects integration, dispatches a repair, selects a provider, retries,
 * schedules, or makes a merge decision. `ingestInvocationReport` is a pure
 * function of its two arguments.
 *
 * It answers exactly one question:
 *
 *     What did AgentBridge ask which agent to do, against which exact
 *     repository and commit, and what did that agent *claim* resulted?
 *
 * It does not answer whether a claimed artifact exists remotely, whether it was
 * integrated, whether it is validated, whether the evidence is current, or
 * whether anything may merge. Existence is an adapter observation recorded as
 * PR 004 evidence; freshness stays in PR 004's kernel; authority stays in PR
 * 003's gate.
 *
 * The epistemic ladder this boundary sits on:
 *
 *   1. requested            <- modelled here (AgentInvocation)
 *   2. reported complete    <- modelled here (reportedStatus)
 *   3. artifact claimed     <- modelled here (ClaimedArtifact)
 *   4. remotely observed    -> GitHub adapter, recorded as PR 004 evidence
 *   5. integrated           -> PR 004 freshness against a new trusted HEAD
 *   6. validated            -> PR 004 + PR 005
 *   7. authorized           -> PR 003 gate + human approval
 *
 * Rungs 4 to 7 are structurally inexpressible here. There is no code path that
 * promotes a claim: reaching rung 4 requires a *new record* built from an
 * independent observation, never a transformation of provider output.
 */

import {
  AGENT_REPORT_STATUS,
  type AgentInvocation,
  type AgentReport,
  type AgentReportStatus,
  type ArtifactType,
  CLAIM_REJECTION,
  type ClaimRejection,
  INVOCATION_BOUNDS,
  type InvocationPurpose,
  isInvocationPurpose,
  readArtifactType,
  readExactIdentifier,
  readOwnProperty,
  readReportStatus,
  readText,
  REPORT_OUTCOME,
  type ReportOutcome,
  REQUIRED_INVOCATION_FIELDS,
} from './agent-invocation.js';

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible. Array handling avoids `push`, `filter`, spread, and ordinary
 * indexed assignment, so neither prototype methods nor inherited index setters
 * are on the path. Same pattern as `evidence-freshness.ts` and
 * `review-ingestion.ts`.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;
const stringConstructor = String;

/** Append by defining an own element, bypassing inherited index setters. */
function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * One artifact an agent **claims** it produced.
 *
 * A claim is the lowest rung of the ladder above. It asserts nothing about
 * remote existence, integration, validation, freshness, approval, or
 * authorization, and there is deliberately no field through which it could.
 *
 * `reference` is opaque provider text: it is stored and echoed, never parsed,
 * resolved, or dereferenced. `claimedCommitSha` is a provider claim and must
 * never be substituted for a trusted SHA — it may not become an
 * `EvidenceRecord.commitSha` or an `EvidenceTarget.currentHeadSha`.
 */
export interface ClaimedArtifact {
  /** Identity within this report: `c<ordinal>`. */
  readonly claimId: string;
  /** Position in the submitted payload, including rejected neighbours. */
  readonly ordinal: number;
  /** From the trusted invocation only. */
  readonly invocationId: string;
  /** From the trusted invocation only. */
  readonly repositoryId: string;
  readonly artifactType: ArtifactType;
  /** Provider-side identifier. Required, exact, opaque. */
  readonly reference: string;
  /** Provider-claimed commit. Never a binding. */
  readonly claimedCommitSha: string | null;
  /** True when this claim lost content to a bound. */
  readonly truncated: boolean;
}

/** A candidate claim that could not be normalized. */
export interface RejectedClaim {
  readonly ordinal: number;
  readonly reason: ClaimRejection;
}

/**
 * The result of one report ingestion call.
 *
 * Every field is a primitive, `null`, or a frozen list of such objects, so the
 * result is JSON-serializable and survives a round trip unchanged. There is
 * deliberately no field expressing existence, integration, validation,
 * freshness, permission, or merge readiness.
 */
export interface InvocationReportResult {
  readonly outcome: ReportOutcome;
  readonly invocationId: string | null;
  readonly repositoryId: string | null;
  readonly pullRequestId: string | null;
  readonly targetCommitSha: string | null;
  readonly providerId: string | null;
  readonly agentId: string | null;
  readonly purpose: InvocationPurpose | null;
  /** Status as reported by the provider. Never a statement of fact. */
  readonly reportedStatus: AgentReportStatus;
  /** Diagnostic prose. Bounded, echoed, never parsed. */
  readonly reportedDetail: string | null;
  readonly claims: readonly ClaimedArtifact[];
  readonly rejectedClaims: readonly RejectedClaim[];
  /** Invalid trusted fields, in declaration order. */
  readonly invalidInvocationFields: readonly string[];
  /** True when the payload exceeded a bound and content was dropped or cut. */
  readonly truncated: boolean;
}

/** The validated trusted binding, snapshotted once. */
interface NormalizedInvocation {
  readonly invocationId: string;
  readonly repositoryId: string;
  readonly pullRequestId: string | null;
  readonly targetCommitSha: string;
  readonly providerId: string;
  readonly agentId: string;
  readonly purpose: InvocationPurpose;
  readonly requestedAt: string;
}

/** A claim plus whichever of the two outcomes applies. */
interface NormalizedClaim {
  readonly claim: ClaimedArtifact | null;
  readonly rejection: RejectedClaim | null;
}

/** Every required field, for an invocation that cannot be read at all. */
function allRequiredFields(): readonly string[] {
  const all: string[] = [];
  for (let index = 0; index < REQUIRED_INVOCATION_FIELDS.length; index += 1) {
    const field = REQUIRED_INVOCATION_FIELDS[index];
    if (field !== undefined) {
      append(all, field);
    }
  }
  return objectFreeze(all);
}

/**
 * The result for an invocation that cannot be bound exactly.
 *
 * The report is deliberately not read at all in this case: a claim that cannot
 * be attributed to an exact invocation is not worth recording.
 */
function emptyResult(invalidInvocationFields: readonly string[]): InvocationReportResult {
  return objectFreeze({
    outcome: REPORT_OUTCOME.INVOCATION_INVALID,
    invocationId: null,
    repositoryId: null,
    pullRequestId: null,
    targetCommitSha: null,
    providerId: null,
    agentId: null,
    purpose: null,
    reportedStatus: AGENT_REPORT_STATUS.UNKNOWN,
    reportedDetail: null,
    claims: objectFreeze([]),
    rejectedClaims: objectFreeze([]),
    invalidInvocationFields: objectFreeze(invalidInvocationFields),
    truncated: false,
  });
}

/**
 * Validate and snapshot the trusted invocation.
 *
 * The invocation is caller-supplied and therefore trusted for *binding*, but it
 * is still dereferenced, so a non-object or a throwing getter must fail closed
 * rather than abort. Every field is read **exactly once**: a getter can return a
 * different value on each read, so validating one read and storing another
 * would let an invocation pass validation with one identity and be recorded
 * under a different one.
 *
 * Trusted context is all-or-nothing. There is no partially accepted invocation
 * and no field that degrades silently.
 */
function normalizeInvocation(invocation: AgentInvocation): {
  readonly normalized: NormalizedInvocation | null;
  readonly invalidFields: readonly string[];
} {
  const record: unknown = invocation;
  if (typeof record !== 'object' || record === null) {
    return { normalized: null, invalidFields: allRequiredFields() };
  }

  const invocationId = readExactIdentifier(readOwnProperty(record, 'invocationId'));
  const repositoryId = readExactIdentifier(readOwnProperty(record, 'repositoryId'));
  const rawPullRequestId = readOwnProperty(record, 'pullRequestId');
  const pullRequestId =
    rawPullRequestId === undefined ? null : readExactIdentifier(rawPullRequestId);
  const targetCommitSha = readExactIdentifier(readOwnProperty(record, 'targetCommitSha'));
  const providerId = readExactIdentifier(readOwnProperty(record, 'providerId'));
  const agentId = readExactIdentifier(readOwnProperty(record, 'agentId'));
  const rawPurpose = readOwnProperty(record, 'purpose');
  const purpose = isInvocationPurpose(rawPurpose) ? rawPurpose : null;
  const requestedAt = readExactIdentifier(readOwnProperty(record, 'requestedAt'));

  // Built in INVOCATION_FIELD_ORDER order with indexed appends, so a poisoned
  // array iterator cannot drop entries and the order is deterministic.
  const invalidFields: string[] = [];
  if (invocationId === null) {
    append(invalidFields, 'invocationId');
  }
  if (repositoryId === null) {
    append(invalidFields, 'repositoryId');
  }
  if (rawPullRequestId !== undefined && pullRequestId === null) {
    append(invalidFields, 'pullRequestId');
  }
  if (targetCommitSha === null) {
    append(invalidFields, 'targetCommitSha');
  }
  if (providerId === null) {
    append(invalidFields, 'providerId');
  }
  if (agentId === null) {
    append(invalidFields, 'agentId');
  }
  if (purpose === null) {
    append(invalidFields, 'purpose');
  }
  if (requestedAt === null) {
    append(invalidFields, 'requestedAt');
  }

  if (
    invocationId === null ||
    repositoryId === null ||
    targetCommitSha === null ||
    providerId === null ||
    agentId === null ||
    purpose === null ||
    requestedAt === null ||
    invalidFields.length > 0
  ) {
    return { normalized: null, invalidFields: objectFreeze(invalidFields) };
  }

  return {
    normalized: {
      invocationId,
      repositoryId,
      pullRequestId,
      targetCommitSha,
      providerId,
      agentId,
      purpose,
      requestedAt,
    },
    invalidFields: objectFreeze(invalidFields),
  };
}

/**
 * Normalize one candidate artifact claim.
 *
 * Binding fields come from `invocation` only. Nothing the provider supplies can
 * reach them, because they are never read from the candidate: a claim carrying
 * `invocationId`, `repositoryId`, `targetCommitSha`, `providerId`, `agentId`,
 * or `purpose` is normalized exactly like one that does not.
 */
function normalizeClaim(
  candidate: unknown,
  ordinal: number,
  invocation: NormalizedInvocation,
): NormalizedClaim {
  // An array is `typeof 'object'` but is never a plausible claim record, so it
  // is unreadable rather than merely incomplete. Keeping the rejection reasons
  // honest matters for audit. `Array.isArray` itself throws on a revoked Proxy.
  let candidateIsArray = false;
  try {
    candidateIsArray = arrayIsArray(candidate);
  } catch {
    candidateIsArray = true;
  }
  if (typeof candidate !== 'object' || candidate === null || candidateIsArray) {
    return {
      claim: null,
      rejection: objectFreeze({ ordinal, reason: CLAIM_REJECTION.CLAIM_UNREADABLE }),
    };
  }

  const rawReference = readOwnProperty(candidate, 'reference');
  const rawArtifactType = readOwnProperty(candidate, 'artifactType');
  const rawCommitSha = readOwnProperty(candidate, 'commitSha');

  // Oversize is distinguished from absent on purpose: an oversized reference is
  // something the provider did send, and rejecting it loudly is what stops a
  // 256-character prefix from ever standing in for a different object.
  if (
    typeof rawReference === 'string' &&
    rawReference.length > INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH
  ) {
    return {
      claim: null,
      rejection: objectFreeze({ ordinal, reason: CLAIM_REJECTION.REFERENCE_OVERSIZED }),
    };
  }

  const reference = readExactIdentifier(rawReference);
  if (reference === null) {
    return {
      claim: null,
      rejection: objectFreeze({ ordinal, reason: CLAIM_REJECTION.REFERENCE_MISSING }),
    };
  }

  // An oversized claimed SHA is dropped rather than cut. A truncated SHA is
  // strictly worse than none, because commit prefixes resolve.
  const claimedCommitSha = readExactIdentifier(rawCommitSha);
  const truncated =
    typeof rawCommitSha === 'string' &&
    rawCommitSha.length > INVOCATION_BOUNDS.MAX_IDENTIFIER_LENGTH;

  return {
    claim: objectFreeze({
      claimId: `c${stringConstructor(ordinal)}`,
      ordinal,
      invocationId: invocation.invocationId,
      repositoryId: invocation.repositoryId,
      artifactType: readArtifactType(rawArtifactType),
      reference,
      claimedCommitSha,
      truncated,
    }),
    rejection: null,
  };
}

/**
 * Ingest one agent report.
 *
 * Pure, total, and deterministic: equal arguments always yield an equal result,
 * and no input throws. No clock, no randomness, no I/O, no global mutation, no
 * identifier generation.
 *
 * Binding is taken from `invocation` alone. Candidate claims contribute an
 * artifact type, a reference, and a claimed commit only; a claim that names a
 * different repository, invocation, or commit has no way to change the binding,
 * because those properties are never read from it.
 *
 * `reportedStatus` is what the provider said, never what is true. A
 * `reported-complete` status is not evidence that an artifact exists, was
 * integrated, is validated, or may merge — those are separate records produced
 * by separate layers from independent observations.
 *
 * Duplicates are **preserved, not merged**. Two byte-identical candidates become
 * two claims with distinct stable `claimId`s derived from their payload
 * position, so output is deterministic without any fuzzy matching.
 *
 * @param invocation Trusted binding context supplied by the caller.
 * @param report Untrusted provider output.
 */
export function ingestInvocationReport(
  invocation: AgentInvocation,
  report: AgentReport,
): InvocationReportResult {
  const { normalized, invalidFields } = normalizeInvocation(invocation);
  if (normalized === null) {
    return emptyResult(invalidFields);
  }

  const payload: unknown = report;
  let rawStatus: unknown;
  let rawDetail: unknown;
  let rawArtifacts: unknown;
  if (typeof payload === 'object' && payload !== null) {
    rawStatus = readOwnProperty(payload, 'status');
    rawDetail = readOwnProperty(payload, 'detail');
    rawArtifacts = readOwnProperty(payload, 'artifacts');
  }

  const reportedDetail = readText(rawDetail, INVOCATION_BOUNDS.MAX_DETAIL_LENGTH);
  let truncated =
    typeof rawDetail === 'string' &&
    rawDetail.length > INVOCATION_BOUNDS.MAX_DETAIL_LENGTH;

  // The candidate list is untrusted: it may be absent, a non-array, a Proxy
  // reporting an absurd length, or an array with hostile index getters. The
  // count is bounded *before* iteration so no payload can cause unbounded work.
  let elements: readonly unknown[] | null = null;
  try {
    elements = arrayIsArray(rawArtifacts) ? (rawArtifacts as readonly unknown[]) : null;
  } catch {
    elements = null;
  }

  const claims: ClaimedArtifact[] = [];
  const rejectedClaims: RejectedClaim[] = [];

  if (elements !== null) {
    let rawLength: unknown;
    try {
      rawLength = elements.length;
    } catch {
      rawLength = 0;
    }
    const declared =
      typeof rawLength === 'number' && numberIsInteger(rawLength) && rawLength >= 0
        ? rawLength
        : 0;
    const limit =
      declared > INVOCATION_BOUNDS.MAX_CLAIMS ? INVOCATION_BOUNDS.MAX_CLAIMS : declared;
    if (limit < declared) {
      truncated = true;
    }

    for (let index = 0; index < limit; index += 1) {
      let candidate: unknown;
      try {
        candidate = elements[index];
      } catch {
        candidate = undefined;
      }
      const outcome = normalizeClaim(candidate, index, normalized);
      if (outcome.claim !== null) {
        append(claims, outcome.claim);
        if (outcome.claim.truncated) {
          truncated = true;
        }
      } else if (outcome.rejection !== null) {
        append(rejectedClaims, outcome.rejection);
      }
    }
  }

  const ingested: ReportOutcome = REPORT_OUTCOME.INGESTED;
  return objectFreeze({
    outcome: ingested,
    invocationId: normalized.invocationId,
    repositoryId: normalized.repositoryId,
    pullRequestId: normalized.pullRequestId,
    targetCommitSha: normalized.targetCommitSha,
    providerId: normalized.providerId,
    agentId: normalized.agentId,
    purpose: normalized.purpose,
    reportedStatus: readReportStatus(rawStatus),
    reportedDetail,
    claims: objectFreeze(claims),
    rejectedClaims: objectFreeze(rejectedClaims),
    invalidInvocationFields: objectFreeze([]),
    truncated,
  });
}
