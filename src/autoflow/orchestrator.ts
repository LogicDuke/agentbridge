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
  WORKFLOW_EVENT_KIND,
  type HumanGateOpenedEvent,
  type WorkflowBinding,
} from '../domain/index.js';

export class AutoflowOrchestrator {
  /**
   * The one write-capable runtime. Private and never exposed: no getter, no
   * public property, and no method returns it. `#runtime` is a true ECMAScript
   * private field, so it is unreachable from outside this class at runtime.
   */
  readonly #runtime: AutoflowRuntime;

  /**
   * @param runtime The single authoritative {@link AutoflowRuntime}. The
   *   composition root constructs exactly one and hands it here; the Cockpit is
   *   given {@link reader} (or `runtime.reader()`), never the runtime itself.
   */
  constructor(runtime: AutoflowRuntime) {
    this.#runtime = runtime;
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
   * The read-only capability for the Cockpit observation path: the runtime's
   * `current()`-only reader, with the write methods genuinely absent at runtime.
   * The writer never crosses this seam.
   */
  reader(): AutoflowStateReader {
    return this.#runtime.reader();
  }
}
