/**
 * AutoflowOrchestrator — the single production owner of the Autoflow **write
 * capability** (Autoflow Orchestration Controller / Single-Writer Boundary
 * milestone, Decision 060).
 *
 * This milestone is **NOT autonomous orchestration.** The orchestrator's whole
 * job is to establish exactly one write-authority owner over the one
 * {@link AutoflowRuntime}, and to expose that runtime **read-only** to the
 * Cockpit. Its only production write action is a **startup workflow open** driven
 * by bounded startup configuration; it originates no {@link WorkflowEvent} after
 * startup and drives no event source.
 *
 * ## Single-writer containment (a hard invariant)
 *
 * The write-capable {@link AutoflowRuntime} is held in a private field and is
 * **never** returned, exposed as a public property, passed through outward
 * configuration, or captured in an outward callback/closure. The only capability
 * that crosses out of this object is the read-only {@link AutoflowStateReader}
 * from {@link reader}; the writer verbs (`open`, `openHumanGate`) each take a
 * value / no value and return a value — they never hand out the writer itself.
 * Downstream code (the Cockpit, the RepositoryObserver) therefore cannot reach
 * `open`/`openHumanGate`/`apply`.
 *
 * ## Production authority — structurally narrow (Decision 061)
 *
 * The single production write action added by the Startup-Scripted Human-Gate
 * Progression milestone is {@link openHumanGate}: it originates exactly one
 * `HUMAN_GATE_OPENED` event, minted internally and bound to the workflow's own
 * `boundCommitSha`. There is deliberately **no** generic `apply(event)` surface:
 * *domain legality is not production authority.* The domain recognises seven
 * event kinds; production may originate exactly one. Exposing a generic
 * `apply(event)` would make every kind — including terminal `CLOSE_REQUESTED` —
 * one argument away, so it is intentionally not provided. `CLOSE_REQUESTED` and
 * the other five kinds are structurally unconstructible through this object.
 *
 * Deliberately absent, and out of scope for this milestone: any post-start event
 * adapter, any generic `apply`/event-submission surface, an event loop, a queue,
 * a provider or Policy execution path, and any Git/GitHub/network capability.
 * {@link openHumanGate} is startup-scripted (one synchronous boot call site), not
 * a post-start external event source; that remains a separate authority gate.
 */

import {
  AutoflowRuntime,
  type AutoflowApplyResult,
  type AutoflowOpenResult,
  type AutoflowStateReader,
} from './runtime.js';
import {
  EVIDENCE_KIND,
  EVIDENCE_SOURCE,
  evaluateEvidenceFreshness,
  TRANSITION_OUTCOME,
  WORKFLOW_EVENT_KIND,
  type EvidenceAdmittedEvent,
  type EvidenceRecord,
  type HumanGateOpenedEvent,
  type WorkflowBinding,
} from '../domain/index.js';
import {
  readEvidenceId,
  type RetirementAssessmentEnvelope,
} from '../domain/retirement-assessment.js';

/**
 * The bounded, truthful result of {@link AutoflowOrchestrator.admitRetirementAssessment}
 * when an envelope is refused *before* any domain transition is attempted
 * (Decision 065 — production event origins).
 *
 * A refusal is a provable no-op: no {@link EvidenceRecord} is built, no freshness
 * is evaluated, and `apply` is never reached, so an envelope that was not this
 * runtime's to admit cannot advance or clobber the workflow. The shape mirrors
 * the runtime's other bounded results — `state: null`, `rejection: null`, empty
 * `invalidFields` — so a consumer can switch on `outcome` uniformly.
 */
export const AUTOFLOW_ASSESSMENT_REFUSED = 'RETIREMENT_ASSESSMENT_REFUSED';

/** @see AUTOFLOW_ASSESSMENT_REFUSED */
export interface AutoflowAssessmentRefusedResult {
  readonly outcome: typeof AUTOFLOW_ASSESSMENT_REFUSED;
  readonly state: null;
  readonly rejection: null;
  readonly invalidFields: readonly string[];
}

/** Every result {@link AutoflowOrchestrator.admitRetirementAssessment} can return. */
export type AutoflowAdmitResult = AutoflowApplyResult | AutoflowAssessmentRefusedResult;

const ASSESSMENT_REFUSED_RESULT: AutoflowAssessmentRefusedResult = Object.freeze({
  outcome: AUTOFLOW_ASSESSMENT_REFUSED,
  state: null,
  rejection: null,
  invalidFields: Object.freeze([]),
});

export class AutoflowOrchestrator {
  /**
   * The one write-capable runtime. Private and never exposed: no getter, no
   * public property, and no method returns it. `#runtime` is a true ECMAScript
   * private field, so it is unreachable from outside this class at runtime.
   */
  readonly #runtime: AutoflowRuntime;

  /**
   * The immutable Job #1 candidate ref this runtime may admit an assessment for,
   * or `null` when this composition does not run Job #1.
   *
   * Fixed at construction and never rewritten, so candidate identity is
   * immutable (Decision 065 §2). With `null` — every composition that is not
   * running Job #1 — {@link admitRetirementAssessment} refuses every envelope, so
   * the new event origin stays inert unless deliberately configured.
   */
  readonly #job1CandidateRef: string | null;

  /**
   * Whether an assessment has already been admitted in this runtime.
   *
   * "One workflow instance assesses exactly one candidate" (Decision 065 §1) is
   * guarded here *and* in the assessment store, because the two guard different
   * things: the store refuses a second **body**, this refuses a second
   * **admission event**. A second call is refused, never allowed to clobber the
   * first.
   */
  #assessmentAdmitted = false;

  /**
   * @param runtime The single authoritative {@link AutoflowRuntime}. The
   *   composition root constructs exactly one and hands it here; the Cockpit is
   *   given {@link reader} (or `runtime.reader()`), never the runtime itself.
   * @param job1CandidateRef The immutable Job #1 candidate ref when this
   *   composition runs Job #1. Defaults to `null`: no Job #1, and
   *   {@link admitRetirementAssessment} refuses every envelope.
   */
  constructor(runtime: AutoflowRuntime, job1CandidateRef: string | null = null) {
    this.#runtime = runtime;
    this.#job1CandidateRef = job1CandidateRef;
  }

  /**
   * Open the one startup workflow through the runtime's guarded `open`.
   *
   * This is the milestone's sole production write action. The runtime enforces
   * the at-most-one-active-workflow invariant (an already-active workflow is
   * refused, never clobbered); the domain result is returned verbatim. No event
   * is originated and no external side effect occurs.
   */
  open(binding: WorkflowBinding): AutoflowOpenResult {
    return this.#runtime.open(binding);
  }

  /**
   * Originate exactly one `HUMAN_GATE_OPENED` event against the currently open
   * workflow (Decision 061). This is the milestone's structurally narrow
   * production event surface — there is no generic `apply(event)`.
   *
   * The event is minted **internally** and bound to the workflow's **own**
   * authoritative `boundCommitSha` (read once from the runtime); no external
   * event object and no caller-supplied commit SHA is accepted, so the gate can
   * neither mis-bind nor smuggle in any other event kind. The one owned runtime
   * state is read once and the well-formed event is delegated once to
   * {@link AutoflowRuntime.apply}; the domain result is returned verbatim.
   *
   * With **no** workflow open (`current() === null`) this must not manufacture a
   * workflow: the runtime's `apply` short-circuits to the bounded `NO_WORKFLOW`
   * result and mutates nothing (the `atCommitSha` below is never consulted in
   * that case). A second call against an already-gated workflow is rejected by
   * the domain with `HUMAN_GATE_ALREADY_OPEN` and leaves the state unchanged.
   */
  openHumanGate(): AutoflowApplyResult {
    const current = this.#runtime.current();
    const event: HumanGateOpenedEvent = {
      kind: WORKFLOW_EVENT_KIND.HUMAN_GATE_OPENED,
      atCommitSha: current === null ? '' : current.boundCommitSha,
    };
    return this.#runtime.apply(event);
  }

  /**
   * Originate at most one `EVIDENCE_ADMITTED` event for the Job #1 retirement
   * assessment (Decision 065 — production event origins).
   *
   * This is the second, and last, structurally narrow production event surface.
   * Like {@link openHumanGate} it takes no `WorkflowEvent`: the event is minted
   * **internally** from an envelope whose identity has already been checked, so
   * no other event kind can be smuggled through it and there is still no generic
   * `apply(event)`.
   *
   * Four guards run **before** anything is built, and each returns the bounded
   * {@link AUTOFLOW_ASSESSMENT_REFUSED} no-op:
   *
   * 1. no Job #1 candidate is configured for this runtime;
   * 2. an assessment has already been admitted here (at most one per runtime);
   * 3. the envelope's `evidenceId` is malformed;
   * 4. the envelope's `candidateRef` is **foreign** — not the immutable ref this
   *    runtime was constructed for.
   *
   * Freshness is then evaluated by PR 004's `evaluateEvidenceFreshness` against
   * the workflow's **own** binding, read once from the runtime. This orchestrator
   * neither derives nor asserts freshness: it hands PR 004 a record and hands the
   * domain PR 004's verdict verbatim, and the domain independently refuses any
   * verdict that is not `CURRENT` at the bound commit. A candidate SHA that does
   * not equal the workflow's `boundCommitSha` therefore cannot be admitted — the
   * rejection comes from the domain, not from a second freshness answer here.
   *
   * The admitted-once flag advances only on an `APPLIED` result, so a rejected
   * attempt does not consume the one admission.
   *
   * **This grants nothing.** An admitted `RETIRE_ELIGIBLE` assessment is a
   * recorded observation, not deletion authority; `RETIRE_ELIGIBLE` is not
   * `AUTHORIZED_TO_DELETE` (Decision 065 §8).
   */
  admitRetirementAssessment(envelope: RetirementAssessmentEnvelope): AutoflowAdmitResult {
    const expectedRef = this.#job1CandidateRef;
    if (expectedRef === null || this.#assessmentAdmitted) {
      return ASSESSMENT_REFUSED_RESULT;
    }

    const record: unknown = envelope;
    if (typeof record !== 'object' || record === null) {
      return ASSESSMENT_REFUSED_RESULT;
    }
    const evidenceId = readEvidenceId(envelope.evidenceId);
    if (evidenceId === null || envelope.body.candidateRef !== expectedRef) {
      return ASSESSMENT_REFUSED_RESULT;
    }

    // Read the one owned state exactly once. With no workflow open the empty
    // identities below are never consulted: the runtime's `apply` short-circuits
    // to the bounded `NO_WORKFLOW` result and mutates nothing, exactly as
    // `openHumanGate` relies on. Keeping one path avoids a second construction
    // site for the same event.
    const current = this.#runtime.current();
    const repositoryId = current === null ? '' : current.repositoryId;
    const boundCommitSha = current === null ? '' : current.boundCommitSha;

    const evidence: EvidenceRecord = {
      evidenceId,
      repositoryId,
      commitSha: envelope.body.candidateSha,
      kind: EVIDENCE_KIND.REPOSITORY_STATE,
      source: EVIDENCE_SOURCE.LOCAL_VERIFICATION,
      // The pointer doubles as the source-side reference: the assessment has no
      // external identifier, and inventing one would be a manufactured value.
      reference: evidenceId,
      observedAt: envelope.body.generatedAt,
    };
    const verdict = evaluateEvidenceFreshness(evidence, {
      repositoryId,
      currentHeadSha: boundCommitSha,
    });

    const result = this.#runtime.apply({
      kind: WORKFLOW_EVENT_KIND.EVIDENCE_ADMITTED,
      verdict,
    } satisfies EvidenceAdmittedEvent);

    if (result.outcome === TRANSITION_OUTCOME.APPLIED) {
      this.#assessmentAdmitted = true;
    }
    return result;
  }

  /**
   * The read-only capability for the Cockpit observation path: the runtime's
   * `current()`-only reader, with the write methods genuinely absent at runtime.
   * The writer never crosses this seam.
   */
  reader(): AutoflowStateReader {
    return this.#runtime.reader();
  }
}
