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
 * from {@link reader}; `open` is the only writer verb, and it takes a value and
 * returns a value — it never hands out the writer itself. Downstream code
 * (the Cockpit, the RepositoryObserver) therefore cannot reach `open`/`apply`.
 *
 * Deliberately absent, and out of scope for this milestone: any post-start
 * event adapter, any `apply`/event-submission surface, an event loop, a queue, a
 * provider or Policy execution path, and any Git/GitHub/network capability. If a
 * future adapter needs a single-writer insertion point, it is added here under a
 * separate authority gate — not by widening this milestone.
 */

import { AutoflowRuntime, type AutoflowOpenResult, type AutoflowStateReader } from './runtime.js';
import type { WorkflowBinding } from '../domain/index.js';

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
   * The read-only capability for the Cockpit observation path: the runtime's
   * `current()`-only reader, with the write methods genuinely absent at runtime.
   * The writer never crosses this seam.
   */
  reader(): AutoflowStateReader {
    return this.#runtime.reader();
  }
}
