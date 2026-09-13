/**
 * The single narrow write-path capability of the Decision 062 control channel.
 *
 * A {@link ControlDispatcher} holds **only** the capability needed to call
 * {@link AutoflowOrchestrator.openHumanGate} — never `open`, `apply`, the
 * reader, or the runtime. The channel is handed a dispatcher, not the
 * orchestrator, so single-writer containment (Decision 060) is preserved: the
 * one production command maps to the one production verb and nothing else.
 *
 * The dispatcher performs the authoritative critical section **synchronously**:
 * `openHumanGate()` reads the current workflow, mints `HUMAN_GATE_OPENED`
 * internally, and applies it with no intervening `await` (Decision 062 §15 —
 * `REENTRANCY_GUARD_NOT_REQUIRED_NOW`). It originates no `WorkflowEvent`, accepts
 * no caller-supplied event, and manufactures no workflow.
 */

import type { AutoflowOrchestrator } from '../autoflow/orchestrator.js';
import { AUTOFLOW_APPLY_NO_WORKFLOW, type AutoflowApplyResult } from '../autoflow/runtime.js';
import { TRANSITION_OUTCOME, TRANSITION_REJECTION } from '../domain/index.js';
import {
  CONTROL_COMMAND,
  CONTROL_RESULT,
  type ControlCommand,
  type ControlResultStatus,
} from './control-command.js';

/** Project the orchestrator's bounded apply result into the closed vocabulary. */
export function projectApplyResult(result: AutoflowApplyResult): ControlResultStatus {
  if (result.outcome === AUTOFLOW_APPLY_NO_WORKFLOW) {
    return CONTROL_RESULT.NO_WORKFLOW;
  }
  if (result.outcome === TRANSITION_OUTCOME.APPLIED) {
    return CONTROL_RESULT.APPLIED;
  }
  // REJECTED: distinguish the already-open gate (a provable no-op) from any
  // other domain rejection.
  if (result.rejection === TRANSITION_REJECTION.HUMAN_GATE_ALREADY_OPEN) {
    return CONTROL_RESULT.GATE_ALREADY_OPEN;
  }
  return CONTROL_RESULT.REJECTED;
}

/** The one write-path capability the control channel is allowed to hold. */
export interface ControlDispatcher {
  dispatch(command: ControlCommand): ControlResultStatus;
}

/**
 * Build the dispatcher over one orchestrator. The returned object is frozen and
 * exposes only `dispatch`; the orchestrator (and thus the writer) is captured in
 * the closure and never handed out. A single-command handler table drives the
 * dispatch, so the surface can grow no second command by accident.
 */
export function createControlDispatcher(orchestrator: AutoflowOrchestrator): ControlDispatcher {
  const handlers: Readonly<Record<ControlCommand['command'], () => ControlResultStatus>> =
    Object.freeze({
      [CONTROL_COMMAND.OPEN_HUMAN_GATE]: (): ControlResultStatus =>
        projectApplyResult(orchestrator.openHumanGate()),
    });

  return Object.freeze({
    dispatch(command: ControlCommand): ControlResultStatus {
      return handlers[command.command]();
    },
  });
}
