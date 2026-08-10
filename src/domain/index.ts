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

export {
  findInvalidRequestFields,
  REQUIRED_REQUEST_FIELDS,
  type ActionRequest,
  type RequiredRequestField,
} from './action-request.js';

export {
  APPROVAL_STATE,
  APPROVAL_STATES,
  type ApprovalRecord,
  type ApprovalState,
} from './approval.js';

export {
  evaluateActionRequest,
  GATE_OUTCOME,
  GATE_OUTCOMES,
  GATE_REASON,
  GATE_REASONS,
  type GateDecision,
  type GateOutcome,
  type GateReason,
} from './policy-gate.js';

export {
  EVIDENCE_KIND,
  EVIDENCE_KINDS,
  EVIDENCE_SOURCE,
  EVIDENCE_SOURCES,
  isEvidenceKind,
  isEvidenceSource,
  REQUIRED_EVIDENCE_FIELDS,
  type EvidenceKind,
  type EvidenceRecord,
  type EvidenceSource,
} from './evidence.js';

export {
  currentEvidenceOfKind,
  evaluateEvidenceFreshness,
  evaluateEvidenceSet,
  FRESHNESS,
  FRESHNESS_REASON,
  FRESHNESS_REASONS,
  FRESHNESS_STATES,
  type EvidenceFreshness,
  type EvidenceSetEvaluation,
  type EvidenceTarget,
  type FreshnessReason,
  type FreshnessState,
} from './evidence-freshness.js';
