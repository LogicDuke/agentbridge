/**
 * AutoflowRuntime — the sole runtime owner of the current authoritative
 * {@link WorkflowState} (Live Runtime Wiring milestone, Decision 059).
 *
 *     open(binding)  -> real openWorkflow(binding)      -> replace #current on APPLIED
 *     apply(event)   -> real applyWorkflowEvent(current) -> replace #current on APPLIED
 *     current()      -> the one immutable reference, or null
 *
 * This is a thin, single-reference owner over the existing **pure** domain
 * transitions. It holds exactly one current reference and advances it **only**
 * on an `APPLIED` result; a `REJECTED` result leaves the reference unchanged and
 * is surfaced verbatim. A {@link WorkflowState} is never mutated in place — the
 * domain returns deeply-frozen values and each transition **replaces** the
 * reference.
 *
 * Deliberately absent, and never to be added here: a second state cache, an
 * event loop, autonomous orchestration (nothing here decides *which* event to
 * apply), provider execution, Policy authority, or Git/GitHub authority. Autoflow
 * remains the sole workflow source of truth; this class only owns the current
 * value the pure transitions produce.
 *
 * ## Read/write capability split
 *
 * The Cockpit observation path must never reach `open`/`apply`. {@link reader}
 * returns a frozen object exposing **only** `current()` — the write methods are
 * genuinely absent from it at runtime (`'open' in reader === false`), not merely
 * hidden behind a type. The composition root passes that narrowed capability,
 * never the runtime handle, into the observation builder.
 */

import {
  applyWorkflowEvent,
  openWorkflow,
  TRANSITION_OUTCOME,
  type TransitionResult,
  type WorkflowBinding,
  type WorkflowEvent,
  type WorkflowOpenResult,
  type WorkflowState,
} from '../domain/index.js';

/**
 * The read-only capability the Cockpit observation path is allowed to hold: the
 * current authoritative workflow state, or `null` when none is open. It exposes
 * no transition, Policy, provider, or Git/GitHub method — by construction, not by
 * convention.
 */
export interface AutoflowStateReader {
  current(): WorkflowState | null;
}

/**
 * The bounded, truthful result of {@link AutoflowRuntime.apply} when it is called
 * while no workflow is open (`current() === null`).
 *
 * There is no `WorkflowState` to transition, so the domain's
 * `applyWorkflowEvent` (which requires one) is never invoked. Rather than invent
 * a fake state or throw (the domain transitions are total and never throw), the
 * runtime returns this explicit discriminated member. Its shape mirrors
 * {@link TransitionResult} — `state: null`, `rejection: null`, empty
 * `invalidFields` — so a consumer can switch on `outcome` uniformly.
 */
export const AUTOFLOW_APPLY_NO_WORKFLOW = 'NO_WORKFLOW';

/** @see AUTOFLOW_APPLY_NO_WORKFLOW */
export interface AutoflowNoWorkflowResult {
  readonly outcome: typeof AUTOFLOW_APPLY_NO_WORKFLOW;
  readonly state: null;
  readonly rejection: null;
  readonly invalidFields: readonly string[];
}

/** Every result {@link AutoflowRuntime.apply} can return. */
export type AutoflowApplyResult = TransitionResult | AutoflowNoWorkflowResult;

const NO_WORKFLOW_RESULT: AutoflowNoWorkflowResult = Object.freeze({
  outcome: AUTOFLOW_APPLY_NO_WORKFLOW,
  state: null,
  rejection: null,
  invalidFields: Object.freeze([]),
});

/**
 * Sole runtime owner of the current authoritative {@link WorkflowState}.
 *
 * Not autonomous: `open`/`apply` are driven by an external caller (a real
 * production caller, or a test). Constructing one owns no state (`current()` is
 * `null` — the honest "no workflow observed" starting point).
 */
export class AutoflowRuntime implements AutoflowStateReader {
  #current: WorkflowState | null = null;

  /** The one current immutable state, or `null` when no workflow is open. */
  current(): WorkflowState | null {
    return this.#current;
  }

  /**
   * Open a workflow through the real domain `openWorkflow`. On `APPLIED` the
   * single reference is replaced with the returned deeply-frozen state; a
   * `REJECTED` result leaves the reference unchanged. The domain result is
   * returned verbatim.
   */
  open(binding: WorkflowBinding): WorkflowOpenResult {
    const result = openWorkflow(binding);
    if (result.outcome === TRANSITION_OUTCOME.APPLIED && result.state !== null) {
      this.#current = result.state;
    }
    return result;
  }

  /**
   * Apply one event through the real domain `applyWorkflowEvent`. Requires an
   * open workflow: with none, returns {@link NO_WORKFLOW_RESULT} and touches
   * nothing. On `APPLIED` the reference is replaced with the new frozen state; a
   * `REJECTED` result leaves it unchanged. The domain result is returned verbatim.
   */
  apply(event: WorkflowEvent): AutoflowApplyResult {
    const current = this.#current;
    if (current === null) {
      return NO_WORKFLOW_RESULT;
    }
    const result = applyWorkflowEvent(current, event);
    if (result.outcome === TRANSITION_OUTCOME.APPLIED) {
      this.#current = result.state;
    }
    return result;
  }

  /**
   * A frozen, read-only view exposing only `current()`. The write methods
   * (`open`/`apply`) are absent from the returned object at runtime, so nothing
   * downstream of this capability can transition workflow state. Pass this — not
   * the runtime instance — into the Cockpit observation path.
   */
  reader(): AutoflowStateReader {
    return Object.freeze<AutoflowStateReader>({
      current: (): WorkflowState | null => this.current(),
    });
  }
}
