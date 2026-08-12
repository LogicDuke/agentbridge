/**
 * Deterministic transitions over immutable Autoflow workflow state.
 *
 *     trusted workflow binding + one already-normalized event
 *         -> immutable WorkflowState | rejection
 *
 * PR 007 scope: state transition only. Nothing here invokes an agent, calls
 * GitHub, Claude, OpenAI, or CodeRabbit, opens a socket, reads a clock, touches
 * the filesystem, spawns a process, persists anything, verifies an artifact,
 * detects integration, judges freshness, selects a provider or reviewer,
 * retries, backs off, schedules, polls, counts cost, or makes a merge decision.
 * Both exported functions are pure functions of their arguments.
 *
 * The epistemic ladder from PR 006 is unchanged, and PR 007 adds no rung:
 *
 *   1. requested            <- PR 006 AgentInvocation, tracked here
 *   2. reported complete    <- PR 006 reportedStatus, carried here
 *   3. artifact claimed     <- PR 006 ClaimedArtifact, never read here
 *   4. remotely observed    -> adapter observation recorded as PR 004 evidence
 *   5. integrated           -> PR 004 freshness against a new trusted HEAD
 *   6. validated            -> PR 004 + PR 005
 *   7. authorized           -> PR 003 gate + human approval
 *
 * **There is no code path from `INVOCATION_REPORTED` into any admission list.**
 * A claim reaches rung 4 only through a *new record built from an independent
 * observation*, arriving as a separate `EVIDENCE_ADMITTED` event. Promotion is
 * structurally impossible, not merely absent.
 *
 * Fixed evaluation precedence — the first failure returns, and the order never
 * varies, so rejection reasons are deterministic:
 *
 *    1  state readable                  WORKFLOW_UNREADABLE
 *    2  event readable                  EVENT_UNREADABLE
 *    3  kind recognised                 EVENT_KIND_UNKNOWN
 *    4  status is not CLOSED            WORKFLOW_CLOSED
 *    5  payload slot well-formed        EVENT_PAYLOAD_INVALID (shallow)
 *    6  status posture                  WORKFLOW_AWAITING_HUMAN / HUMAN_GATE_ALREADY_OPEN
 *    7  upstream outcome                INPUT_NOT_INGESTED / EVIDENCE_NOT_CURRENT
 *    8  payload fields                  EVENT_PAYLOAD_INVALID (deep)
 *    9  binding                         BINDING_MISMATCH / HEAD_UNCHANGED
 *   10  identity and replay             DUPLICATE_* / UNKNOWN_INVOCATION / INVOCATION_ALREADY_REPORTED
 *   11  capacity                        CAPACITY_EXCEEDED
 *   12  apply
 *
 * Two events depart from that order, deliberately:
 *
 * - `INVOCATION_REPORTED` checks binding *after* identity, because the SHA it
 *   compares against comes from the tracked invocation rather than from the
 *   workflow.
 * - `HUMAN_GATE_OPENED` checks status posture *before* its payload, so an
 *   already-open gate returns `HUMAN_GATE_ALREADY_OPEN` without `atCommitSha`
 *   being read at all. A request to open a gate that is already open is
 *   answered by the gate, never by the shape of the payload accompanying it.
 *
 * Each order is fixed per event kind, so rejection reasons stay deterministic.
 */

import { EVIDENCE_KIND, EVIDENCE_KINDS, EVIDENCE_SOURCES } from './evidence.js';
import { FRESHNESS, FRESHNESS_REASON } from './evidence-freshness.js';
import { INGESTION_OUTCOME } from './review.js';
import {
  AGENT_REPORT_STATUSES,
  INVOCATION_PURPOSES,
  REPORT_OUTCOME,
  type AgentReportStatus,
  type InvocationPurpose,
} from './agent-invocation.js';
import {
  type AdmittedEvidence,
  type AdmittedReview,
  append,
  INVOCATION_STATE,
  INVOCATION_STATES,
  isVocabularyMember,
  isWorkflowClosure,
  isWorkflowEventKind,
  isWorkflowStatus,
  readCount,
  readExactIdentifier,
  readOwnProperty,
  REQUIRED_BINDING_FIELDS,
  type TrackedInvocation,
  TRANSITION_OUTCOME,
  TRANSITION_REJECTION,
  type TransitionRejection,
  type TransitionResult,
  WORKFLOW_BOUNDS,
  WORKFLOW_EVENT_KIND,
  WORKFLOW_STATUS,
  type WorkflowBinding,
  type WorkflowClosure,
  type WorkflowEvent,
  type WorkflowOpenResult,
  type WorkflowState,
  type WorkflowStatus,
} from './workflow.js';

/**
 * Intrinsics captured at module load, before any untrusted property access.
 * Array handling avoids `push`, `filter`, `map`, spread over untrusted values,
 * and ordinary indexed assignment, so neither poisoned prototype methods nor
 * inherited index setters are on the path.
 */
const objectFreeze = Object.freeze;
const objectHasOwn = Object.hasOwn;
const arrayIsArray = Array.isArray;
const objectDefineProperty = Object.defineProperty;
const objectIsFrozen = Object.isFrozen;
const reflectIsExtensible = Reflect.isExtensible;
const reflectOwnKeys = Reflect.ownKeys;

/** Shared frozen empty list, so an empty result is byte-identical every time. */
const NO_FIELDS: readonly string[] = objectFreeze([]);

/**
 * The validated, self-consistent view of a caller-supplied state.
 *
 * A state is rebuilt from this snapshot on every applied transition, so any
 * extra property a caller attached is dropped rather than carried forward.
 */
interface WorkflowSnapshot {
  readonly workflowId: string;
  readonly repositoryId: string;
  readonly pullRequestId: string | null;
  readonly boundCommitSha: string;
  readonly revision: number;
  readonly sequence: number;
  readonly status: WorkflowStatus;
  readonly closureReason: WorkflowClosure | null;
  readonly humanGateOpenedAtRevision: number | null;
  readonly invocations: readonly TrackedInvocation[];
  readonly evidence: readonly AdmittedEvidence[];
  readonly reviews: readonly AdmittedReview[];
}

/**
 * Narrow an untrusted value to a plain object.
 *
 * Arrays are excluded: an array is `typeof 'object'` but is never a plausible
 * record, and keeping the rejection reasons honest matters for audit.
 * `Array.isArray` itself throws on a revoked Proxy, so even that call is
 * guarded and a throw fails closed.
 */
function asRecord(value: unknown): object | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  let isArray = true;
  try {
    isArray = arrayIsArray(value);
  } catch {
    return null;
  }
  return isArray ? null : value;
}

/**
 * Read an optional own property that may legitimately be absent.
 *
 * `Object.hasOwn` itself throws on a revoked Proxy, so the failure is reported
 * separately from a genuine absence: a read that threw must never look like a
 * field the caller simply did not send.
 */
function readOptionalOwn(target: object, key: string): {
  readonly value: unknown;
  readonly failed: boolean;
} {
  try {
    if (!objectHasOwn(target, key)) {
      return { value: undefined, failed: false };
    }
    return { value: (target as Record<string, unknown>)[key], failed: false };
  } catch {
    return { value: undefined, failed: true };
  }
}

/**
 * Is this value **provably** an empty list under the hostile-runtime model?
 *
 * Used to check the `invalidFields` of a verdict claiming `CURRENT`. PR 004
 * only ever emits an empty list alongside `CURRENT`, so a populated,
 * non-array, or unprovable value marks a verdict PR 004 could not have
 * produced.
 *
 * **Reading `length` is not proof.** A Proxy over an *extensible* array can
 * report `length` as `0` while the target holds entries, and can lie just as
 * consistently through `ownKeys`, `getOwnPropertyDescriptor`, and `hasOwn` —
 * no amount of reflection can contradict it. Emptiness is therefore proved the
 * only way the engine underwrites:
 *
 * 1. it is an array (`Array.isArray` pierces a Proxy to its target);
 * 2. it is **non-extensible** — the `isExtensible` trap is required to agree
 *    with the target, so this cannot be faked;
 * 3. its own keys are exactly `['length']` — for a non-extensible target the
 *    `ownKeys` trap must return exactly the target's own keys, so an element
 *    cannot be hidden;
 * 4. `length` still reads as `0`, as a redundant cross-check.
 *
 * Step 2 is what turns steps 3 and 4 from assertions into proof. PR 004 freezes
 * every result list, so a genuine verdict satisfies this; anything that cannot
 * prove it fails closed. Every read is guarded, so a throwing or revoked value
 * is rejected rather than raised.
 */
function isProvablyEmptyList(value: unknown): boolean {
  let isArray = false;
  try {
    isArray = arrayIsArray(value);
  } catch {
    return false;
  }
  if (!isArray) {
    return false;
  }

  let extensible = true;
  try {
    extensible = reflectIsExtensible(value as object);
  } catch {
    return false;
  }
  if (extensible) {
    return false;
  }

  let keys: readonly (string | symbol)[];
  try {
    keys = reflectOwnKeys(value as object);
  } catch {
    return false;
  }
  if (keys.length !== 1 || keys[0] !== 'length') {
    return false;
  }

  let rawLength: unknown;
  try {
    rawLength = (value as readonly unknown[]).length;
  } catch {
    return false;
  }
  return readCount(rawLength, 0) === 0;
}

/**
 * Claim one transition sequence stamp, reporting a collision.
 *
 * Every applied transition advances `sequence` exactly once, and stamps at most
 * one record with the new value: `INVOCATION_REQUESTED` stamps a request,
 * `INVOCATION_REPORTED` a report, and the two admission events an admission.
 * `HEAD_OBSERVED`, `HUMAN_GATE_OPENED`, and `CLOSE_REQUESTED` advance the
 * sequence without stamping anything. **No two retained stamps can therefore
 * share a value**, across every collection — some sequence values simply have
 * no stamp at all.
 *
 * Derived transiently during validation; no timeline is stored. Uses an indexed
 * scan rather than a `Set`, so no prototype method is on the path.
 */
function claimSequence(seen: number[], stamp: number): boolean {
  for (let index = 0; index < seen.length; index += 1) {
    if (seen[index] === stamp) {
      return false;
    }
  }
  append(seen, stamp);
  return true;
}

/**
 * Record one revision-to-commit binding, reporting a contradiction.
 *
 * No workflow history can bind a single revision to two commits: every entry
 * stamped at revision R was created while `boundCommitSha` held one value. The
 * mapping is derived **transiently** during validation from the per-entry
 * commits the model already retains — nothing is stored, no field is added,
 * and no revision-to-commit ledger is introduced.
 *
 * Parallel indexed arrays are used rather than a `Map`, so no prototype method
 * is on the path, matching the accumulation strategy used elsewhere here.
 *
 * This says nothing about whether a historical commit is *genuine*; that stays
 * recoverable only through external reconciliation against the retained
 * per-entry commit. Only internal contradiction is detectable here.
 */
function bindRevisionCommit(
  revisions: number[],
  commits: string[],
  revision: number,
  commit: string,
): boolean {
  for (let index = 0; index < revisions.length; index += 1) {
    if (revisions[index] === revision) {
      return commits[index] === commit;
    }
  }
  append(revisions, revision);
  append(commits, commit);
  return true;
}

/**
 * Note that revision `revision` covers sequence slot `sequence`.
 *
 * Revision never decreases, so ordering every stamped record by sequence must
 * produce non-decreasing revisions. Tracking the lowest and highest slot each
 * revision covers reduces that to a comparison between revision *bands*, which
 * the caller checks once at the end. Derived transiently; nothing is stored.
 */
function noteRevisionSpan(
  revisions: number[],
  lowest: number[],
  highest: number[],
  revision: number,
  sequence: number,
): void {
  for (let index = 0; index < revisions.length; index += 1) {
    if (revisions[index] === revision) {
      const low = lowest[index];
      const high = highest[index];
      if (low !== undefined && sequence < low) {
        objectDefineProperty(lowest, index, {
          value: sequence,
          writable: true,
          enumerable: true,
          configurable: true,
        });
      }
      if (high !== undefined && sequence > high) {
        objectDefineProperty(highest, index, {
          value: sequence,
          writable: true,
          enumerable: true,
          configurable: true,
        });
      }
      return;
    }
  }
  append(revisions, revision);
  append(lowest, sequence);
  append(highest, sequence);
}

/**
 * Do the recorded revision bands respect chronology?
 *
 * Each applied transition consumes exactly one sequence slot, and advancing
 * from revision `r1` to `r2` costs `r2 - r1` `HEAD_OBSERVED` transitions that
 * stamp nothing. Those transitions need slots of their own, so two stamped
 * records cannot merely be ordered — they must leave room between them:
 *
 *     later stamp at (r2, s2) after an earlier stamp at (r1, s1), r1 < r2
 *       => s2 - s1 > r2 - r1
 *
 * The intervening HEAD transitions occupy distinct slots strictly between `s1`
 * and `s2`, of which there are `s2 - s1 - 1`. Only the highest slot of the
 * earlier revision against the lowest slot of the later one has to be checked;
 * every other cross pair leaves a wider gap. This subsumes the plain ordering
 * rule, because the gap is always at least two slots when revisions differ.
 *
 * The same accounting applies after the last stamp: reaching the aggregate's
 * `revision` from a band's revision costs that many further HEAD transitions,
 * each needing a slot up to and including the aggregate's `sequence`:
 *
 *     band at (r, high)  =>  sequence - high >= revision - r
 *
 * That bound is inclusive, because the aggregate's own final slot may itself be
 * one of those HEAD transitions. The origin needs no separate case: measured
 * against the opening `(0, 0)`, the pairwise rule reduces to
 * `recordedSequence > recordedRevision`, which is already enforced per record.
 */
function revisionBandsOrdered(
  revisions: readonly number[],
  lowest: readonly number[],
  highest: readonly number[],
  revision: number,
  sequence: number,
): boolean {
  for (let a = 0; a < revisions.length; a += 1) {
    const earlier = revisions[a];
    const earlierHigh = highest[a];
    if (earlier === undefined || earlierHigh === undefined) {
      return false;
    }
    if (sequence - earlierHigh < revision - earlier) {
      return false;
    }
    for (let b = 0; b < revisions.length; b += 1) {
      const later = revisions[b];
      const laterLow = lowest[b];
      if (later === undefined || laterLow === undefined) {
        return false;
      }
      if (earlier < later && laterLow - earlierHigh <= later - earlier) {
        return false;
      }
    }
  }
  return true;
}

/**
 * Materialise an untrusted list with guarded reads and a hard length cap.
 *
 * A throwing element read returns `null` rather than dropping the element:
 * silently shortening orchestration history is exactly the outcome this layer
 * refuses. Iteration avoids the collection's own `map`, because an array can
 * carry an own non-function `map`, a throwing `map` getter, or inherit a
 * poisoned `Array.prototype.map`.
 */
function readList(value: unknown, limit: number): readonly unknown[] | null {
  let elements: readonly unknown[] | null = null;
  try {
    elements = arrayIsArray(value) ? (value as readonly unknown[]) : null;
  } catch {
    return null;
  }
  if (elements === null) {
    return null;
  }

  // **Every content signal a Proxy exposes is one the same Proxy controls.**
  // Over an *extensible* target it may report a short `length`, return a
  // matching `ownKeys`, and deny the hidden indices — all consistently.
  // Corroborating one trapped channel with another proves nothing when one
  // adversary owns both, so a real own record could be hidden and then silently
  // deleted from the durable snapshot by the next applied transition.
  //
  // Non-extensibility alone is not enough. A *sealed* array's elements stay
  // writable, and the `get` invariant binds a Proxy only for a non-configurable
  // **and non-writable** data property — so a sealed view can keep `length`,
  // `ownKeys`, and `hasOwn` perfectly compliant while substituting an arbitrary
  // record for an index, erasing the real entry and freeing its identity.
  //
  // Frozen-ness is what the engine underwrites end to end: `isExtensible` must
  // agree with the target, `ownKeys` must then return exactly the target's own
  // keys, and every element — now non-configurable and non-writable — must read
  // back as its true value. `Object.isFrozen` cannot be faked either, because a
  // non-configurable writable property may not be reported as non-writable.
  //
  // Every list this layer emits is frozen by `freezeState`, so a state produced
  // here always satisfies this. A caller that rebuilds a state from JSON must
  // freeze the three collections before handing it back.
  let frozen = false;
  try {
    frozen = objectIsFrozen(elements);
  } catch {
    return null;
  }
  if (!frozen) {
    return null;
  }

  let rawLength: unknown;
  try {
    rawLength = elements.length;
  } catch {
    return null;
  }
  const length = readCount(rawLength, limit);
  if (length === null) {
    return null;
  }

  // A reported length is not, on its own, a statement about what the list
  // holds: a Proxy can report a *smaller* length than the own indices actually
  // present, and iterating to that length would silently drop the excess —
  // precisely the shortening of orchestration history this layer refuses.
  //
  // The own-key structure is therefore required to agree with the reported
  // cardinality. A genuine array of `n` elements has exactly `n + 1` own keys:
  // one per index, plus `length`. Any surplus key — a hidden element past the
  // claimed range, a stray property, a symbol — breaks the equality, and any
  // missing index is caught by the per-index ownership check below. Together
  // they pin the structure exactly rather than trusting either signal alone.
  let keys: readonly (string | symbol)[];
  try {
    keys = reflectOwnKeys(elements);
  } catch {
    return null;
  }
  if (keys.length !== length + 1) {
    return null;
  }

  const materialised: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    let element: unknown;
    try {
      if (!objectHasOwn(elements, index)) {
        return null;
      }
      element = elements[index];
    } catch {
      return null;
    }
    append(materialised, element);
  }
  return materialised;
}

/**
 * Validate one tracked invocation from a caller-supplied state.
 *
 * Recorded revisions and sequences must not exceed the workflow's own, and the
 * reported trio must be all-null or all-present in step with `state`. A forged
 * aggregate that violates either is unreadable rather than partially trusted.
 */
function readTrackedInvocation(
  candidate: unknown,
  revision: number,
  sequence: number,
): TrackedInvocation | null {
  const record = asRecord(candidate);
  if (record === null) {
    return null;
  }

  const invocationId = readExactIdentifier(readOwnProperty(record, 'invocationId'));
  const targetCommitSha = readExactIdentifier(readOwnProperty(record, 'targetCommitSha'));
  const rawPurpose = readOwnProperty(record, 'purpose');
  const providerId = readExactIdentifier(readOwnProperty(record, 'providerId'));
  const agentId = readExactIdentifier(readOwnProperty(record, 'agentId'));
  const requestedAtRevision = readCount(
    readOwnProperty(record, 'requestedAtRevision'),
    revision,
  );
  const requestedAtSequence = readCount(
    readOwnProperty(record, 'requestedAtSequence'),
    sequence,
  );
  const rawState = readOwnProperty(record, 'state');
  const rawReportedStatus = readOwnProperty(record, 'reportedStatus');
  const rawReportedAtRevision = readOwnProperty(record, 'reportedAtRevision');
  const rawReportedAtSequence = readOwnProperty(record, 'reportedAtSequence');

  if (
    invocationId === null ||
    targetCommitSha === null ||
    providerId === null ||
    agentId === null ||
    requestedAtRevision === null ||
    requestedAtSequence === null ||
    requestedAtSequence < 1 ||
    // Reaching revision R costs R applied HEAD_OBSERVED transitions, each
    // consuming a distinct sequence slot, so the R-th advance sat at slot >= R
    // and any record stamped at revision R was created later still.
    requestedAtSequence <= requestedAtRevision ||
    !isVocabularyMember<InvocationPurpose>(INVOCATION_PURPOSES, rawPurpose) ||
    !isVocabularyMember(INVOCATION_STATES, rawState)
  ) {
    return null;
  }

  let reportedStatus: AgentReportStatus | null = null;
  let reportedAtRevision: number | null = null;
  let reportedAtSequence: number | null = null;

  if (rawState === INVOCATION_STATE.REPORTED) {
    if (!isVocabularyMember<AgentReportStatus>(AGENT_REPORT_STATUSES, rawReportedStatus)) {
      return null;
    }
    reportedStatus = rawReportedStatus;
    reportedAtRevision = readCount(rawReportedAtRevision, revision);
    reportedAtSequence = readCount(rawReportedAtSequence, sequence);
    if (
      reportedAtRevision === null ||
      reportedAtSequence === null ||
      reportedAtRevision < requestedAtRevision ||
      reportedAtSequence <= requestedAtSequence ||
      reportedAtSequence <= reportedAtRevision
    ) {
      return null;
    }
  } else if (
    rawReportedStatus !== null ||
    rawReportedAtRevision !== null ||
    rawReportedAtSequence !== null
  ) {
    return null;
  }

  return objectFreeze({
    invocationId,
    targetCommitSha,
    purpose: rawPurpose,
    providerId,
    agentId,
    requestedAtRevision,
    requestedAtSequence,
    state: rawState,
    reportedStatus,
    reportedAtRevision,
    reportedAtSequence,
  });
}

/** Validate one evidence admission from a caller-supplied state. */
function readAdmittedEvidence(
  candidate: unknown,
  revision: number,
  sequence: number,
): AdmittedEvidence | null {
  const record = asRecord(candidate);
  if (record === null) {
    return null;
  }

  const evidenceId = readExactIdentifier(readOwnProperty(record, 'evidenceId'));
  const rawKind = readOwnProperty(record, 'kind');
  const admittedAtCommitSha = readExactIdentifier(
    readOwnProperty(record, 'admittedAtCommitSha'),
  );
  const admittedAtRevision = readCount(readOwnProperty(record, 'admittedAtRevision'), revision);
  const admittedAtSequence = readCount(readOwnProperty(record, 'admittedAtSequence'), sequence);

  if (
    evidenceId === null ||
    admittedAtCommitSha === null ||
    admittedAtRevision === null ||
    admittedAtSequence === null ||
    admittedAtSequence < 1 ||
    admittedAtSequence <= admittedAtRevision ||
    !isVocabularyMember(EVIDENCE_KINDS, rawKind)
  ) {
    return null;
  }

  return objectFreeze({
    evidenceId,
    kind: rawKind,
    admittedAtCommitSha,
    admittedAtRevision,
    admittedAtSequence,
  });
}

/** Validate one review admission from a caller-supplied state. */
function readAdmittedReview(
  candidate: unknown,
  revision: number,
  sequence: number,
): AdmittedReview | null {
  const record = asRecord(candidate);
  if (record === null) {
    return null;
  }

  const reviewId = readExactIdentifier(readOwnProperty(record, 'reviewId'));
  const admittedAtCommitSha = readExactIdentifier(
    readOwnProperty(record, 'admittedAtCommitSha'),
  );
  const admittedAtRevision = readCount(readOwnProperty(record, 'admittedAtRevision'), revision);
  const admittedAtSequence = readCount(readOwnProperty(record, 'admittedAtSequence'), sequence);

  if (
    reviewId === null ||
    admittedAtCommitSha === null ||
    admittedAtRevision === null ||
    admittedAtSequence === null ||
    admittedAtSequence < 1 ||
    admittedAtSequence <= admittedAtRevision
  ) {
    return null;
  }

  return objectFreeze({
    reviewId,
    admittedAtCommitSha,
    admittedAtRevision,
    admittedAtSequence,
  });
}

/**
 * Validate and snapshot a caller-supplied state.
 *
 * Every field is read **exactly once** into a local: a getter can return a
 * different value on each read, so validating one read and storing another
 * would let a state pass validation with one identity and be rebuilt under a
 * different one.
 *
 * Structural invariants enforced here, each of which a state this layer
 * produced always satisfies:
 *
 * - `closureReason` is non-null exactly when `status` is `CLOSED`;
 * - `humanGateOpenedAtRevision` is `null` while `OPEN`, and otherwise equals
 *   `revision` — a HEAD advance clears the gate, so a gate can never outlive
 *   the revision it was opened at;
 * - `AWAITING_HUMAN_DECISION` always carries an open gate;
 * - every recorded revision and sequence is within the workflow's own;
 * - **everything stamped at the current revision is bound to the current
 *   commit**, symmetrically across all three collections: a tracked invocation
 *   whose `requestedAtRevision` equals `revision` targets `boundCommitSha`, and
 *   an evidence or review admission whose `admittedAtRevision` equals
 *   `revision` was admitted at `boundCommitSha`. Entries from earlier revisions
 *   keep their own historical commit and are never rewritten;
 * - every **represented** revision maps to exactly one commit across all three
 *   collections, because every entry stamped at revision R was created while
 *   `boundCommitSha` held one value. Derived transiently here; nothing is
 *   stored. Whether a historical commit is *genuine* stays recoverable only by
 *   external reconciliation, and revisions with no entries are unconstrained;
 * - `revision <= sequence`, since every revision advance is itself an applied
 *   transition;
 * - no admission identity — the value pair (id, revision) — appears twice;
 * - no two retained transition sequence stamps share a value, since every
 *   applied transition advances `sequence` once and stamps at most one record;
 * - every stamped record satisfies `recordedSequence > recordedRevision`:
 *   reaching revision R costs R applied `HEAD_OBSERVED` transitions, each
 *   consuming a distinct sequence slot, so the R-th advance sat at slot >= R
 *   and the record stamped at revision R was created by a later transition
 *   still. The bound is tight — open, one HEAD advance at slot 1, then a
 *   request at slot 2 stamps revision 1 with sequence 2;
 * - ordering every stamped record by sequence yields non-decreasing revisions,
 *   since a revision never decreases once a HEAD transition advances it, and
 *   consecutive stamps leave room for the `HEAD_OBSERVED` transitions between
 *   their revisions — each of which consumes a sequence slot of its own.
 */
function snapshotWorkflow(state: WorkflowState): WorkflowSnapshot | null {
  const record = asRecord(state);
  if (record === null) {
    return null;
  }

  const workflowId = readExactIdentifier(readOwnProperty(record, 'workflowId'));
  const repositoryId = readExactIdentifier(readOwnProperty(record, 'repositoryId'));
  const rawPullRequestId = readOwnProperty(record, 'pullRequestId');
  const boundCommitSha = readExactIdentifier(readOwnProperty(record, 'boundCommitSha'));
  const revision = readCount(readOwnProperty(record, 'revision'), WORKFLOW_BOUNDS.MAX_REVISION);
  const sequence = readCount(readOwnProperty(record, 'sequence'), WORKFLOW_BOUNDS.MAX_SEQUENCE);
  const rawStatus = readOwnProperty(record, 'status');
  const rawClosureReason = readOwnProperty(record, 'closureReason');
  const rawHumanGate = readOwnProperty(record, 'humanGateOpenedAtRevision');
  const rawInvocations = readOwnProperty(record, 'invocations');
  const rawEvidence = readOwnProperty(record, 'evidence');
  const rawReviews = readOwnProperty(record, 'reviews');

  if (
    workflowId === null ||
    repositoryId === null ||
    boundCommitSha === null ||
    revision === null ||
    sequence === null ||
    !isWorkflowStatus(rawStatus)
  ) {
    return null;
  }

  // Both counters start at 0, every revision advance happens inside an applied
  // `HEAD_OBSERVED` that also advances the sequence, and other events advance
  // the sequence alone. `revision > sequence` is therefore unreachable, and an
  // aggregate claiming it is not one this layer could have produced.
  if (revision > sequence) {
    return null;
  }

  const pullRequestId =
    rawPullRequestId === null ? null : readExactIdentifier(rawPullRequestId);
  if (rawPullRequestId !== null && pullRequestId === null) {
    return null;
  }

  const closureReason = rawClosureReason === null ? null : rawClosureReason;
  if (closureReason !== null && !isWorkflowClosure(closureReason)) {
    return null;
  }
  if ((closureReason !== null) !== (rawStatus === WORKFLOW_STATUS.CLOSED)) {
    return null;
  }

  const humanGateOpenedAtRevision =
    rawHumanGate === null ? null : readCount(rawHumanGate, WORKFLOW_BOUNDS.MAX_REVISION);
  if (rawHumanGate !== null && humanGateOpenedAtRevision === null) {
    return null;
  }
  if (humanGateOpenedAtRevision !== null && humanGateOpenedAtRevision !== revision) {
    return null;
  }
  if (rawStatus === WORKFLOW_STATUS.OPEN && humanGateOpenedAtRevision !== null) {
    return null;
  }
  if (
    rawStatus === WORKFLOW_STATUS.AWAITING_HUMAN_DECISION &&
    humanGateOpenedAtRevision === null
  ) {
    return null;
  }

  const invocationCandidates = readList(
    rawInvocations,
    WORKFLOW_BOUNDS.MAX_TRACKED_INVOCATIONS,
  );
  const evidenceCandidates = readList(rawEvidence, WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE);
  const reviewCandidates = readList(rawReviews, WORKFLOW_BOUNDS.MAX_ADMITTED_REVIEWS);
  if (
    invocationCandidates === null ||
    evidenceCandidates === null ||
    reviewCandidates === null
  ) {
    return null;
  }

  const invocations: TrackedInvocation[] = [];
  for (let index = 0; index < invocationCandidates.length; index += 1) {
    const tracked = readTrackedInvocation(invocationCandidates[index], revision, sequence);
    if (
      tracked === null ||
      (tracked.requestedAtRevision === revision &&
        tracked.targetCommitSha !== boundCommitSha)
    ) {
      return null;
    }
    for (let priorIndex = 0; priorIndex < invocations.length; priorIndex += 1) {
      if (invocations[priorIndex]?.invocationId === tracked.invocationId) {
        return null;
      }
    }
    append(invocations, tracked);
  }

  const evidence: AdmittedEvidence[] = [];
  for (let index = 0; index < evidenceCandidates.length; index += 1) {
    const admitted = readAdmittedEvidence(evidenceCandidates[index], revision, sequence);
    if (
      admitted === null ||
      (admitted.admittedAtRevision === revision &&
        admitted.admittedAtCommitSha !== boundCommitSha)
    ) {
      return null;
    }
    // Admission identity is the value pair (id, revision), exactly as the
    // admission handlers enforce it. A duplicate already present in state
    // would consume capacity and shadow a legitimate admission of the same id.
    for (let priorIndex = 0; priorIndex < evidence.length; priorIndex += 1) {
      const prior = evidence[priorIndex];
      if (
        prior !== undefined &&
        prior.evidenceId === admitted.evidenceId &&
        prior.admittedAtRevision === admitted.admittedAtRevision
      ) {
        return null;
      }
    }
    append(evidence, admitted);
  }

  const reviews: AdmittedReview[] = [];
  for (let index = 0; index < reviewCandidates.length; index += 1) {
    const admitted = readAdmittedReview(reviewCandidates[index], revision, sequence);
    if (
      admitted === null ||
      (admitted.admittedAtRevision === revision &&
        admitted.admittedAtCommitSha !== boundCommitSha)
    ) {
      return null;
    }
    for (let priorIndex = 0; priorIndex < reviews.length; priorIndex += 1) {
      const prior = reviews[priorIndex];
      if (
        prior !== undefined &&
        prior.reviewId === admitted.reviewId &&
        prior.admittedAtRevision === admitted.admittedAtRevision
      ) {
        return null;
      }
    }
    append(reviews, admitted);
  }

  // Two aggregate-wide invariants, derived transiently from entries already
  // validated above. Nothing is stored.
  //
  // 1. Every represented revision maps to exactly one commit across all three
  //    collections, because every entry stamped at revision R was created while
  //    `boundCommitSha` held one value.
  // 2. No two retained transition sequence stamps share a value, because every
  //    applied transition advances `sequence` once and stamps at most one
  //    record with the new value.
  const seenRevisions: number[] = [];
  const seenCommits: string[] = [];
  const seenSequences: number[] = [];
  const spanRevisions: number[] = [];
  const spanLowest: number[] = [];
  const spanHighest: number[] = [];
  for (let index = 0; index < invocations.length; index += 1) {
    const tracked = invocations[index];
    if (
      tracked === undefined ||
      !bindRevisionCommit(
        seenRevisions,
        seenCommits,
        tracked.requestedAtRevision,
        tracked.targetCommitSha,
      ) ||
      !claimSequence(seenSequences, tracked.requestedAtSequence) ||
      (tracked.reportedAtSequence !== null &&
        !claimSequence(seenSequences, tracked.reportedAtSequence))
    ) {
      return null;
    }
    noteRevisionSpan(
      spanRevisions,
      spanLowest,
      spanHighest,
      tracked.requestedAtRevision,
      tracked.requestedAtSequence,
    );
    if (tracked.reportedAtRevision !== null && tracked.reportedAtSequence !== null) {
      noteRevisionSpan(
        spanRevisions,
        spanLowest,
        spanHighest,
        tracked.reportedAtRevision,
        tracked.reportedAtSequence,
      );
    }
  }
  for (let index = 0; index < evidence.length; index += 1) {
    const admitted = evidence[index];
    if (
      admitted === undefined ||
      !bindRevisionCommit(
        seenRevisions,
        seenCommits,
        admitted.admittedAtRevision,
        admitted.admittedAtCommitSha,
      ) ||
      !claimSequence(seenSequences, admitted.admittedAtSequence)
    ) {
      return null;
    }
    noteRevisionSpan(
      spanRevisions,
      spanLowest,
      spanHighest,
      admitted.admittedAtRevision,
      admitted.admittedAtSequence,
    );
  }
  for (let index = 0; index < reviews.length; index += 1) {
    const admitted = reviews[index];
    if (
      admitted === undefined ||
      !bindRevisionCommit(
        seenRevisions,
        seenCommits,
        admitted.admittedAtRevision,
        admitted.admittedAtCommitSha,
      ) ||
      !claimSequence(seenSequences, admitted.admittedAtSequence)
    ) {
      return null;
    }
    noteRevisionSpan(
      spanRevisions,
      spanLowest,
      spanHighest,
      admitted.admittedAtRevision,
      admitted.admittedAtSequence,
    );
  }

  // Revision never decreases, so ordering every stamped record by sequence must
  // yield non-decreasing revisions.
  if (!revisionBandsOrdered(spanRevisions, spanLowest, spanHighest, revision, sequence)) {
    return null;
  }

  // A status that only a transition can produce means that transition already
  // ran, and it stamps no record — so it needs a sequence slot of its own.
  // `AWAITING_HUMAN_DECISION` comes from `HUMAN_GATE_OPENED` and `CLOSED` from
  // `CLOSE_REQUESTED`; `OPEN` is the opening state and requires nothing.
  //
  // Counting retained stamps alone under-counts the occupied slots: reaching
  // `revision` also cost that many `HEAD_OBSERVED` transitions, and those stamp
  // nothing, so they never appear among the retained stamps. All three groups
  // occupy distinct slots in `[1, sequence]`, hence
  //
  //     sequence >= revision + retained stamps + 1
  if (
    (rawStatus === WORKFLOW_STATUS.AWAITING_HUMAN_DECISION ||
      rawStatus === WORKFLOW_STATUS.CLOSED) &&
    sequence <= revision + seenSequences.length
  ) {
    return null;
  }

  // Counting is not enough on its own: the gate slot must also sit *after* the
  // final `HEAD_OBSERVED` that reached the current revision. That HEAD follows
  // every stamp recorded at an earlier revision, and the gate follows the HEAD,
  // so the gate's slot is at least two past the latest earlier-revision stamp.
  //
  // Only an open gate at revision >= 1 is constrained. A gate that was already
  // cleared — by a HEAD advance or by a human decision — leaves the workflow
  // `OPEN`, and those histories are deliberately left alone.
  if (rawStatus === WORKFLOW_STATUS.AWAITING_HUMAN_DECISION && revision > 0) {
    let latestEarlier = 0;
    for (let index = 0; index < spanRevisions.length; index += 1) {
      const bandRevision = spanRevisions[index];
      const bandHighest = spanHighest[index];
      if (bandRevision === undefined || bandHighest === undefined) {
        return null;
      }
      if (bandRevision < revision && bandHighest > latestEarlier) {
        latestEarlier = bandHighest;
      }
    }
    if (sequence < latestEarlier + 2) {
      return null;
    }
  }

  // At revision 0 with no retained stamp and no status-producing transition,
  // nothing could have consumed a sequence slot: every event either stamps a
  // record, advances the revision, opens the gate, or closes the workflow.
  // Deliberately narrow — no general upper bound is claimed here, because a
  // cleared gate legitimately consumes a slot it leaves no trace of.
  if (
    revision === 0 &&
    rawStatus === WORKFLOW_STATUS.OPEN &&
    seenSequences.length === 0 &&
    sequence > 0
  ) {
    return null;
  }

  return {
    workflowId,
    repositoryId,
    pullRequestId,
    boundCommitSha,
    revision,
    sequence,
    status: rawStatus,
    closureReason,
    humanGateOpenedAtRevision,
    invocations,
    evidence,
    reviews,
  };
}

/** Freeze a state and all three of its lists. Elements are already frozen. */
function freezeState(next: WorkflowSnapshot): WorkflowState {
  return objectFreeze({
    workflowId: next.workflowId,
    repositoryId: next.repositoryId,
    pullRequestId: next.pullRequestId,
    boundCommitSha: next.boundCommitSha,
    revision: next.revision,
    sequence: next.sequence,
    status: next.status,
    closureReason: next.closureReason,
    humanGateOpenedAtRevision: next.humanGateOpenedAtRevision,
    invocations: objectFreeze(next.invocations),
    evidence: objectFreeze(next.evidence),
    reviews: objectFreeze(next.reviews),
  });
}

/** Copy a list and append one element, without prototype methods or spread. */
function appendTo<T>(list: readonly T[], value: T): readonly T[] {
  const next: T[] = [];
  for (let index = 0; index < list.length; index += 1) {
    const element = list[index];
    if (element !== undefined) {
      append(next, element);
    }
  }
  append(next, value);
  return objectFreeze(next);
}

/** Copy a list, replacing one element in place so ordering is preserved. */
function replaceAt<T>(list: readonly T[], target: number, value: T): readonly T[] {
  const next: T[] = [];
  for (let index = 0; index < list.length; index += 1) {
    const element = list[index];
    if (index === target) {
      append(next, value);
    } else if (element !== undefined) {
      append(next, element);
    }
  }
  return objectFreeze(next);
}

/** A rejection echoes the caller's own state object by reference. */
function rejected(
  state: WorkflowState,
  rejection: TransitionRejection,
  invalidFields: readonly string[],
): TransitionResult {
  return objectFreeze({
    outcome: TRANSITION_OUTCOME.REJECTED,
    state,
    rejection,
    invalidFields: objectFreeze(invalidFields),
  });
}

/** An applied transition returns a freshly built, deeply frozen state. */
function applied(state: WorkflowState): TransitionResult {
  return objectFreeze({
    outcome: TRANSITION_OUTCOME.APPLIED,
    state,
    rejection: null,
    invalidFields: NO_FIELDS,
  });
}

/** Every required binding field, for a binding that cannot be read at all. */
function allRequiredBindingFields(): readonly string[] {
  const all: string[] = [];
  for (let index = 0; index < REQUIRED_BINDING_FIELDS.length; index += 1) {
    const field = REQUIRED_BINDING_FIELDS[index];
    if (field !== undefined) {
      append(all, `binding.${field}`);
    }
  }
  return objectFreeze(all);
}

/**
 * Open a workflow against a trusted binding.
 *
 * Pure, total, and deterministic: equal arguments always yield an equal result,
 * and no input throws. No clock, no randomness, no identifier generation — the
 * caller mints `workflowId`, and uniqueness is the caller's obligation.
 *
 * Binding is **all-or-nothing**: a *present* `pullRequestId` that does not
 * validate invalidates the whole binding, exactly as in PR 005 and PR 006.
 * There is no partially accepted binding and no field that degrades silently.
 */
export function openWorkflow(binding: WorkflowBinding): WorkflowOpenResult {
  const record = asRecord(binding);
  if (record === null) {
    return openRejected(
      TRANSITION_REJECTION.WORKFLOW_UNREADABLE,
      allRequiredBindingFields(),
    );
  }

  const workflowId = readExactIdentifier(readOwnProperty(record, 'workflowId'));
  const repositoryId = readExactIdentifier(readOwnProperty(record, 'repositoryId'));
  const pull = readOptionalOwn(record, 'pullRequestId');
  const pullRequestId = pull.value === undefined ? null : readExactIdentifier(pull.value);
  const boundCommitSha = readExactIdentifier(readOwnProperty(record, 'boundCommitSha'));

  const invalid: string[] = [];
  if (workflowId === null) {
    append(invalid, 'binding.workflowId');
  }
  if (repositoryId === null) {
    append(invalid, 'binding.repositoryId');
  }
  if (pull.failed || (pull.value !== undefined && pullRequestId === null)) {
    append(invalid, 'binding.pullRequestId');
  }
  if (boundCommitSha === null) {
    append(invalid, 'binding.boundCommitSha');
  }

  if (
    workflowId === null ||
    repositoryId === null ||
    boundCommitSha === null ||
    invalid.length > 0
  ) {
    return openRejected(TRANSITION_REJECTION.WORKFLOW_UNREADABLE, invalid);
  }

  return objectFreeze({
    outcome: TRANSITION_OUTCOME.APPLIED,
    state: freezeState({
      workflowId,
      repositoryId,
      pullRequestId,
      boundCommitSha,
      revision: 0,
      sequence: 0,
      status: WORKFLOW_STATUS.OPEN,
      closureReason: null,
      humanGateOpenedAtRevision: null,
      invocations: [],
      evidence: [],
      reviews: [],
    }),
    rejection: null,
    invalidFields: NO_FIELDS,
  });
}

function openRejected(
  rejection: TransitionRejection,
  invalidFields: readonly string[],
): WorkflowOpenResult {
  return objectFreeze({
    outcome: TRANSITION_OUTCOME.REJECTED,
    state: null,
    rejection,
    invalidFields: objectFreeze(invalidFields),
  });
}

/**
 * Apply one event to a workflow.
 *
 * Pure, total, and deterministic: equal arguments always yield an equal result,
 * and no input of any runtime type throws. No clock, no randomness, no I/O, no
 * global mutation, no identifier generation.
 *
 * **Legality never depends on `providerId`, `agentId`, `purpose`, or
 * `reportedStatus`.** Those are recorded for audit and are read by no branch in
 * this module. No provider is permanently an implementer or a reviewer, no
 * purpose grants authority, and a provider saying it finished is not a fact.
 *
 * On rejection the caller's own state object is returned **by reference**, so a
 * rejection is provably a no-op.
 */
export function applyWorkflowEvent(
  state: WorkflowState,
  event: WorkflowEvent,
): TransitionResult {
  const snapshot = snapshotWorkflow(state);
  if (snapshot === null) {
    return rejected(state, TRANSITION_REJECTION.WORKFLOW_UNREADABLE, ['workflow']);
  }

  const eventRecord = asRecord(event);
  if (eventRecord === null) {
    return rejected(state, TRANSITION_REJECTION.EVENT_UNREADABLE, ['event']);
  }

  const kind = readOwnProperty(eventRecord, 'kind');
  if (!isWorkflowEventKind(kind)) {
    return rejected(state, TRANSITION_REJECTION.EVENT_KIND_UNKNOWN, ['event.kind']);
  }

  if (snapshot.status === WORKFLOW_STATUS.CLOSED) {
    return rejected(state, TRANSITION_REJECTION.WORKFLOW_CLOSED, ['workflow.status']);
  }

  switch (kind) {
    case WORKFLOW_EVENT_KIND.INVOCATION_REQUESTED:
      return applyInvocationRequested(state, snapshot, eventRecord);
    case WORKFLOW_EVENT_KIND.INVOCATION_REPORTED:
      return applyInvocationReported(state, snapshot, eventRecord);
    case WORKFLOW_EVENT_KIND.REVIEW_ADMITTED:
      return applyReviewAdmitted(state, snapshot, eventRecord);
    case WORKFLOW_EVENT_KIND.EVIDENCE_ADMITTED:
      return applyEvidenceAdmitted(state, snapshot, eventRecord);
    case WORKFLOW_EVENT_KIND.HEAD_OBSERVED:
      return applyHeadObserved(state, snapshot, eventRecord);
    case WORKFLOW_EVENT_KIND.HUMAN_GATE_OPENED:
      return applyHumanGateOpened(state, snapshot, eventRecord);
    case WORKFLOW_EVENT_KIND.CLOSE_REQUESTED:
      return applyCloseRequested(state, snapshot, eventRecord);
  }
}

/** True when one more applied transition would exceed the sequence bound. */
function sequenceExhausted(snapshot: WorkflowSnapshot): boolean {
  return snapshot.sequence >= WORKFLOW_BOUNDS.MAX_SEQUENCE;
}

/**
 * Compare an optional input pull request against the workflow's.
 *
 * A workflow without a pull request never consults the field: there is nothing
 * to mismatch against. A workflow with one accepts an absent input field,
 * because an implementation invocation may precede any pull request, and
 * requires an exact match when the field is present.
 */
function pullRequestMismatch(
  snapshot: WorkflowSnapshot,
  candidate: string | null,
): boolean {
  return (
    snapshot.pullRequestId !== null &&
    candidate !== null &&
    candidate !== snapshot.pullRequestId
  );
}

/**
 * Read a pull-request binding that may legitimately be absent.
 *
 * **Absent and unreadable are kept apart.** A field that is present but
 * oversized, blank, non-string, or behind a throwing getter must never be
 * treated as "not sent": doing so would skip the mismatch check and silently
 * discard the exact pull-request binding on a workflow that has one. Only a
 * genuinely absent or `null` field is acceptable, and only then is the
 * comparison skipped.
 */
function readBoundPullRequest(
  record: object,
  key: string,
): { readonly value: string | null; readonly unreadable: boolean } {
  const raw = readOptionalOwn(record, key);
  if (raw.failed) {
    return { value: null, unreadable: true };
  }
  if (raw.value === undefined || raw.value === null) {
    return { value: null, unreadable: false };
  }
  const value = readExactIdentifier(raw.value);
  return value === null ? { value: null, unreadable: true } : { value, unreadable: false };
}

/** True when a present-but-unreadable or mismatched pull request must reject. */
function pullRequestRejects(
  snapshot: WorkflowSnapshot,
  bound: { readonly value: string | null; readonly unreadable: boolean },
): boolean {
  if (snapshot.pullRequestId === null) {
    return false;
  }
  return bound.unreadable || pullRequestMismatch(snapshot, bound.value);
}

/** Index of a tracked invocation, or `-1`. Exact string equality only. */
function indexOfInvocation(snapshot: WorkflowSnapshot, invocationId: string): number {
  for (let index = 0; index < snapshot.invocations.length; index += 1) {
    const tracked = snapshot.invocations[index];
    if (tracked !== undefined && tracked.invocationId === invocationId) {
      return index;
    }
  }
  return -1;
}

function applyInvocationRequested(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  const invocationRecord = asRecord(readOwnProperty(eventRecord, 'invocation'));
  if (invocationRecord === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, [
      'event.invocation',
    ]);
  }

  // Work-initiating: refused while a human gate is open. Recording a fact is
  // always legal; starting new agent work while a human is deciding is not.
  if (snapshot.status === WORKFLOW_STATUS.AWAITING_HUMAN_DECISION) {
    return rejected(original, TRANSITION_REJECTION.WORKFLOW_AWAITING_HUMAN, [
      'workflow.status',
    ]);
  }

  const invocationId = readExactIdentifier(readOwnProperty(invocationRecord, 'invocationId'));
  const repositoryId = readExactIdentifier(readOwnProperty(invocationRecord, 'repositoryId'));
  const pull = readOptionalOwn(invocationRecord, 'pullRequestId');
  const pullRequestId = pull.value === undefined ? null : readExactIdentifier(pull.value);
  const targetCommitSha = readExactIdentifier(
    readOwnProperty(invocationRecord, 'targetCommitSha'),
  );
  const providerId = readExactIdentifier(readOwnProperty(invocationRecord, 'providerId'));
  const agentId = readExactIdentifier(readOwnProperty(invocationRecord, 'agentId'));
  const rawPurpose = readOwnProperty(invocationRecord, 'purpose');
  const purpose = isVocabularyMember<InvocationPurpose>(INVOCATION_PURPOSES, rawPurpose)
    ? rawPurpose
    : null;
  // Validated because trusted context is all-or-nothing, then deliberately not
  // stored: this layer reads no clock and has nothing to compare a timestamp to.
  const requestedAt = readExactIdentifier(readOwnProperty(invocationRecord, 'requestedAt'));

  const invalid: string[] = [];
  if (invocationId === null) {
    append(invalid, 'invocation.invocationId');
  }
  if (repositoryId === null) {
    append(invalid, 'invocation.repositoryId');
  }
  if (pull.failed || (pull.value !== undefined && pullRequestId === null)) {
    append(invalid, 'invocation.pullRequestId');
  }
  if (targetCommitSha === null) {
    append(invalid, 'invocation.targetCommitSha');
  }
  if (providerId === null) {
    append(invalid, 'invocation.providerId');
  }
  if (agentId === null) {
    append(invalid, 'invocation.agentId');
  }
  if (purpose === null) {
    append(invalid, 'invocation.purpose');
  }
  if (requestedAt === null) {
    append(invalid, 'invocation.requestedAt');
  }

  if (
    invocationId === null ||
    repositoryId === null ||
    targetCommitSha === null ||
    providerId === null ||
    agentId === null ||
    purpose === null ||
    requestedAt === null ||
    invalid.length > 0
  ) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, invalid);
  }

  const mismatched: string[] = [];
  if (repositoryId !== snapshot.repositoryId) {
    append(mismatched, 'invocation.repositoryId');
  }
  if (targetCommitSha !== snapshot.boundCommitSha) {
    append(mismatched, 'invocation.targetCommitSha');
  }
  if (pullRequestMismatch(snapshot, pullRequestId)) {
    append(mismatched, 'invocation.pullRequestId');
  }
  if (mismatched.length > 0) {
    return rejected(original, TRANSITION_REJECTION.BINDING_MISMATCH, mismatched);
  }

  // Invocation identity is permanent and workflow-wide, unlike an admission,
  // which is scoped to a revision: a reused invocation id is an attribution
  // hazard, whereas an observation genuinely can be current again later.
  if (indexOfInvocation(snapshot, invocationId) !== -1) {
    return rejected(original, TRANSITION_REJECTION.DUPLICATE_INVOCATION_ID, [
      'invocation.invocationId',
    ]);
  }

  if (
    snapshot.invocations.length >= WORKFLOW_BOUNDS.MAX_TRACKED_INVOCATIONS ||
    sequenceExhausted(snapshot)
  ) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, [
      'workflow.invocations',
    ]);
  }

  const sequence = snapshot.sequence + 1;
  const tracked: TrackedInvocation = objectFreeze({
    invocationId,
    targetCommitSha,
    purpose,
    providerId,
    agentId,
    requestedAtRevision: snapshot.revision,
    requestedAtSequence: sequence,
    state: INVOCATION_STATE.REQUESTED,
    reportedStatus: null,
    reportedAtRevision: null,
    reportedAtSequence: null,
  });

  return applied(
    freezeState({
      ...snapshot,
      sequence,
      invocations: appendTo(snapshot.invocations, tracked),
    }),
  );
}

function applyInvocationReported(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  const reportRecord = asRecord(readOwnProperty(eventRecord, 'report'));
  if (reportRecord === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, ['event.report']);
  }

  if (readOwnProperty(reportRecord, 'outcome') !== REPORT_OUTCOME.INGESTED) {
    return rejected(original, TRANSITION_REJECTION.INPUT_NOT_INGESTED, ['report.outcome']);
  }

  const invocationId = readExactIdentifier(readOwnProperty(reportRecord, 'invocationId'));
  if (invocationId === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, [
      'report.invocationId',
    ]);
  }

  const index = indexOfInvocation(snapshot, invocationId);
  const tracked = index === -1 ? undefined : snapshot.invocations[index];
  if (tracked === undefined) {
    return rejected(original, TRANSITION_REJECTION.UNKNOWN_INVOCATION, [
      'report.invocationId',
    ]);
  }
  if (tracked.state !== INVOCATION_STATE.REQUESTED) {
    return rejected(original, TRANSITION_REJECTION.INVOCATION_ALREADY_REPORTED, [
      'report.invocationId',
    ]);
  }

  // A report binds to its own invocation's commit, not to the workflow's
  // current one. A report arriving after HEAD moved is a true historical fact
  // and is recorded; it admits no evidence, because admission is keyed on the
  // current revision and runs through a different event entirely.
  const repositoryId = readExactIdentifier(readOwnProperty(reportRecord, 'repositoryId'));
  const targetCommitSha = readExactIdentifier(
    readOwnProperty(reportRecord, 'targetCommitSha'),
  );
  const pullRequestId = readBoundPullRequest(reportRecord, 'pullRequestId');

  const mismatched: string[] = [];
  if (repositoryId === null || repositoryId !== snapshot.repositoryId) {
    append(mismatched, 'report.repositoryId');
  }
  if (targetCommitSha === null || targetCommitSha !== tracked.targetCommitSha) {
    append(mismatched, 'report.targetCommitSha');
  }
  if (pullRequestRejects(snapshot, pullRequestId)) {
    append(mismatched, 'report.pullRequestId');
  }
  if (mismatched.length > 0) {
    return rejected(original, TRANSITION_REJECTION.BINDING_MISMATCH, mismatched);
  }

  if (sequenceExhausted(snapshot)) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, ['workflow.sequence']);
  }

  // Carried verbatim from PR 006, re-narrowed defensively and failing closed to
  // `unknown`. It is recorded, never branched on: `reported-complete` and
  // `reported-failed` produce indistinguishable transitions.
  const rawReportedStatus = readOwnProperty(reportRecord, 'reportedStatus');
  const reportedStatus = isVocabularyMember<AgentReportStatus>(
    AGENT_REPORT_STATUSES,
    rawReportedStatus,
  )
    ? rawReportedStatus
    : 'unknown';

  const sequence = snapshot.sequence + 1;
  const next: TrackedInvocation = objectFreeze({
    invocationId: tracked.invocationId,
    targetCommitSha: tracked.targetCommitSha,
    purpose: tracked.purpose,
    providerId: tracked.providerId,
    agentId: tracked.agentId,
    requestedAtRevision: tracked.requestedAtRevision,
    requestedAtSequence: tracked.requestedAtSequence,
    state: INVOCATION_STATE.REPORTED,
    reportedStatus,
    reportedAtRevision: snapshot.revision,
    reportedAtSequence: sequence,
  });

  return applied(
    freezeState({
      ...snapshot,
      sequence,
      invocations: replaceAt(snapshot.invocations, index, next),
    }),
  );
}

function applyReviewAdmitted(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  const reviewRecord = asRecord(readOwnProperty(eventRecord, 'review'));
  if (reviewRecord === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, ['event.review']);
  }

  if (readOwnProperty(reviewRecord, 'outcome') !== INGESTION_OUTCOME.INGESTED) {
    return rejected(original, TRANSITION_REJECTION.INPUT_NOT_INGESTED, ['review.outcome']);
  }

  // PR 005 makes `reviewId` optional; this layer requires it, because an
  // admission nobody can attribute is not worth recording.
  const reviewId = readExactIdentifier(readOwnProperty(reviewRecord, 'reviewId'));
  if (reviewId === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, ['review.reviewId']);
  }

  const repositoryId = readExactIdentifier(readOwnProperty(reviewRecord, 'repositoryId'));
  const reviewedCommitSha = readExactIdentifier(
    readOwnProperty(reviewRecord, 'reviewedCommitSha'),
  );
  const pullRequestId = readBoundPullRequest(reviewRecord, 'pullRequestId');

  const mismatched: string[] = [];
  if (repositoryId === null || repositoryId !== snapshot.repositoryId) {
    append(mismatched, 'review.repositoryId');
  }
  // Old-commit evidence can never advance a current-HEAD workflow.
  if (reviewedCommitSha === null || reviewedCommitSha !== snapshot.boundCommitSha) {
    append(mismatched, 'review.reviewedCommitSha');
  }
  if (pullRequestRejects(snapshot, pullRequestId)) {
    append(mismatched, 'review.pullRequestId');
  }
  if (mismatched.length > 0) {
    return rejected(original, TRANSITION_REJECTION.BINDING_MISMATCH, mismatched);
  }

  for (let index = 0; index < snapshot.reviews.length; index += 1) {
    const admitted = snapshot.reviews[index];
    if (
      admitted !== undefined &&
      admitted.reviewId === reviewId &&
      admitted.admittedAtRevision === snapshot.revision
    ) {
      return rejected(original, TRANSITION_REJECTION.DUPLICATE_ADMISSION, ['review.reviewId']);
    }
  }

  if (
    snapshot.reviews.length >= WORKFLOW_BOUNDS.MAX_ADMITTED_REVIEWS ||
    sequenceExhausted(snapshot)
  ) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, ['workflow.reviews']);
  }

  // Findings are never read. No count, no severity, no text: a derived summary
  // would be a second answer that can drift from PR 005's, and a severity
  // reaching this layer would make findings look like policy.
  //
  // The review need not correspond to a tracked invocation, and admitting it
  // transitions none: it implies nothing about having been requested, about
  // sufficiency, about policy satisfaction, or about authority.
  const sequence = snapshot.sequence + 1;
  const admission: AdmittedReview = objectFreeze({
    reviewId,
    admittedAtCommitSha: snapshot.boundCommitSha,
    admittedAtRevision: snapshot.revision,
    admittedAtSequence: sequence,
  });

  return applied(
    freezeState({
      ...snapshot,
      sequence,
      reviews: appendTo(snapshot.reviews, admission),
    }),
  );
}

function applyEvidenceAdmitted(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  const verdictRecord = asRecord(readOwnProperty(eventRecord, 'verdict'));
  if (verdictRecord === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, ['event.verdict']);
  }

  // Freshness is never re-derived here. PR 004 already answered the question,
  // and its result carries the target it was answered against — so the only
  // thing left to check is that the answer is about *this* workflow's binding.
  // A caller cannot launder stale evidence by judging it against a convenient
  // target and handing over the verdict.
  const notCurrent: string[] = [];
  if (readOwnProperty(verdictRecord, 'state') !== FRESHNESS.CURRENT) {
    append(notCurrent, 'verdict.state');
  }
  if (readOwnProperty(verdictRecord, 'reason') !== FRESHNESS_REASON.BOUND_TO_CURRENT_HEAD) {
    append(notCurrent, 'verdict.reason');
  }
  if (readOwnProperty(verdictRecord, 'repositoryId') !== snapshot.repositoryId) {
    append(notCurrent, 'verdict.repositoryId');
  }
  if (readOwnProperty(verdictRecord, 'commitSha') !== snapshot.boundCommitSha) {
    append(notCurrent, 'verdict.commitSha');
  }
  if (readOwnProperty(verdictRecord, 'targetRepositoryId') !== snapshot.repositoryId) {
    append(notCurrent, 'verdict.targetRepositoryId');
  }
  if (readOwnProperty(verdictRecord, 'targetHeadSha') !== snapshot.boundCommitSha) {
    append(notCurrent, 'verdict.targetHeadSha');
  }
  // A verdict is trusted for its *type*, never for its *value*. PR 004 emits a
  // valid source and an empty invalid-field list alongside every `CURRENT`
  // verdict, so a value missing either is one PR 004 could not have produced —
  // and an impossible verdict must never reach the human-gate path below.
  if (!isVocabularyMember(EVIDENCE_SOURCES, readOwnProperty(verdictRecord, 'source'))) {
    append(notCurrent, 'verdict.source');
  }
  if (!isProvablyEmptyList(readOwnProperty(verdictRecord, 'invalidFields'))) {
    append(notCurrent, 'verdict.invalidFields');
  }
  if (notCurrent.length > 0) {
    return rejected(original, TRANSITION_REJECTION.EVIDENCE_NOT_CURRENT, notCurrent);
  }

  const evidenceId = readExactIdentifier(readOwnProperty(verdictRecord, 'evidenceId'));
  const rawKind = readOwnProperty(verdictRecord, 'kind');
  const invalid: string[] = [];
  if (evidenceId === null) {
    append(invalid, 'verdict.evidenceId');
  }
  if (!isVocabularyMember(EVIDENCE_KINDS, rawKind)) {
    append(invalid, 'verdict.kind');
  }
  if (evidenceId === null || !isVocabularyMember(EVIDENCE_KINDS, rawKind)) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, invalid);
  }

  for (let index = 0; index < snapshot.evidence.length; index += 1) {
    const admitted = snapshot.evidence[index];
    if (
      admitted !== undefined &&
      admitted.evidenceId === evidenceId &&
      admitted.admittedAtRevision === snapshot.revision
    ) {
      return rejected(original, TRANSITION_REJECTION.DUPLICATE_ADMISSION, [
        'verdict.evidenceId',
      ]);
    }
  }

  if (
    snapshot.evidence.length >= WORKFLOW_BOUNDS.MAX_ADMITTED_EVIDENCE ||
    sequenceExhausted(snapshot)
  ) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, ['workflow.evidence']);
  }

  const sequence = snapshot.sequence + 1;
  const admission: AdmittedEvidence = objectFreeze({
    evidenceId,
    kind: rawKind,
    admittedAtCommitSha: snapshot.boundCommitSha,
    admittedAtRevision: snapshot.revision,
    admittedAtSequence: sequence,
  });

  // A human decision clears an open gate. What the human decided is not read,
  // and cannot be: `EvidenceFreshness` carries no verdict field. This records
  // that a decision exists at the bound commit — never what it permits.
  const gateOpen = snapshot.status === WORKFLOW_STATUS.AWAITING_HUMAN_DECISION;
  const clearing = gateOpen && rawKind === EVIDENCE_KIND.HUMAN_DECISION;

  return applied(
    freezeState({
      ...snapshot,
      sequence,
      status: clearing ? WORKFLOW_STATUS.OPEN : snapshot.status,
      humanGateOpenedAtRevision: clearing ? null : snapshot.humanGateOpenedAtRevision,
      evidence: appendTo(snapshot.evidence, admission),
    }),
  );
}

function applyHeadObserved(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  const observedCommitSha = readExactIdentifier(
    readOwnProperty(eventRecord, 'observedCommitSha'),
  );
  if (observedCommitSha === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, [
      'event.observedCommitSha',
    ]);
  }

  if (observedCommitSha === snapshot.boundCommitSha) {
    return rejected(original, TRANSITION_REJECTION.HEAD_UNCHANGED, [
      'event.observedCommitSha',
    ]);
  }

  if (
    snapshot.revision >= WORKFLOW_BOUNDS.MAX_REVISION ||
    sequenceExhausted(snapshot)
  ) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, ['workflow.revision']);
  }

  // Commit ordering is never inferred. A SHA is opaque: there is no parent
  // check, no ancestry test, and no "is this newer". A HEAD that returns to a
  // previous value still advances the revision, so evidence admitted earlier
  // cannot resurrect — revision, not SHA alone, is the admission key.
  //
  // Prior admissions and outstanding invocations are retained unchanged. They
  // remain true at their own revision and commit; they simply stop counting.
  //
  // A human gate is commit-bound orchestration state, not authority, so a HEAD
  // advance clears it. This grants nothing: a decision recorded against the
  // superseded commit is subsequently rejected as not current, and PR 003 plus
  // the human remain the only authority boundary.
  return applied(
    freezeState({
      ...snapshot,
      boundCommitSha: observedCommitSha,
      revision: snapshot.revision + 1,
      sequence: snapshot.sequence + 1,
      status: WORKFLOW_STATUS.OPEN,
      humanGateOpenedAtRevision: null,
    }),
  );
}

function applyHumanGateOpened(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  if (snapshot.status === WORKFLOW_STATUS.AWAITING_HUMAN_DECISION) {
    return rejected(original, TRANSITION_REJECTION.HUMAN_GATE_ALREADY_OPEN, [
      'workflow.status',
    ]);
  }

  const atCommitSha = readExactIdentifier(readOwnProperty(eventRecord, 'atCommitSha'));
  if (atCommitSha === null) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, [
      'event.atCommitSha',
    ]);
  }

  if (atCommitSha !== snapshot.boundCommitSha) {
    return rejected(original, TRANSITION_REJECTION.BINDING_MISMATCH, ['event.atCommitSha']);
  }

  if (sequenceExhausted(snapshot)) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, ['workflow.sequence']);
  }

  return applied(
    freezeState({
      ...snapshot,
      sequence: snapshot.sequence + 1,
      status: WORKFLOW_STATUS.AWAITING_HUMAN_DECISION,
      humanGateOpenedAtRevision: snapshot.revision,
    }),
  );
}

function applyCloseRequested(
  original: WorkflowState,
  snapshot: WorkflowSnapshot,
  eventRecord: object,
): TransitionResult {
  const rawClosureReason = readOwnProperty(eventRecord, 'closureReason');
  if (!isWorkflowClosure(rawClosureReason)) {
    return rejected(original, TRANSITION_REJECTION.EVENT_PAYLOAD_INVALID, [
      'event.closureReason',
    ]);
  }

  if (sequenceExhausted(snapshot)) {
    return rejected(original, TRANSITION_REJECTION.CAPACITY_EXCEEDED, ['workflow.sequence']);
  }

  // `closureReason` is a trusted, inert label. `HUMAN_DECISION_RECORDED` is not
  // verified against an admitted human-decision record: this layer asserts
  // nothing about why a caller closed a workflow, and the label grants nothing.
  //
  // `humanGateOpenedAtRevision` is retained, so a state closed while a human
  // was still deciding stays distinguishable from one closed cleanly.
  return applied(
    freezeState({
      ...snapshot,
      sequence: snapshot.sequence + 1,
      status: WORKFLOW_STATUS.CLOSED,
      closureReason: rawClosureReason,
    }),
  );
}
