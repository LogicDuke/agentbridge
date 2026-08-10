/**
 * AgentBridge domain kernel.
 *
 * Pure domain models and deterministic classification primitives. No I/O,
 * no subprocesses, no persistence, no network, no configuration loading.
 */

export {
  ALL_ACTION_KINDS,
  HUMAN_GATED_ACTION_KINDS,
  isModeledActionKind,
  MODELED_ACTION_KINDS,
  READ_ONLY_ACTION_KINDS,
  resolveActionKind,
  UNKNOWN_ACTION_KIND,
  type ActionKind,
  type ActionRiskTier,
  type HumanGatedActionKind,
  type ModeledActionKind,
  type ReadOnlyActionKind,
  type UnknownActionKind,
} from './actions.js';

export {
  DECISION,
  DECISIONS,
  isAutonomouslyAllowed,
  REASON_CODE,
  REASON_CODES,
  type Decision,
  type ReasonCode,
} from './decisions.js';

export {
  ACTION_POLICY,
  classifyAction,
  type ActionClassification,
  type ActionPolicyEntry,
} from './classification.js';
