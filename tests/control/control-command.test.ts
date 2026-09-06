import { describe, expect, it } from 'vitest';

import {
  CONTROL_COMMAND,
  CONTROL_COMMANDS,
  CONTROL_RESULT,
  CONTROL_RESULTS,
  isControlCommandKind,
  isControlResultStatus,
} from '../../src/control/control-command.js';

describe('D062 control command vocabulary — exactly one production command', () => {
  it('defines exactly one command: OPEN_HUMAN_GATE', () => {
    expect(CONTROL_COMMANDS).toEqual(['OPEN_HUMAN_GATE']);
    expect(CONTROL_COMMAND.OPEN_HUMAN_GATE).toBe('OPEN_HUMAN_GATE');
    expect(CONTROL_COMMANDS.length).toBe(1);
  });

  it('has no CLOSE_REQUESTED or any other command member', () => {
    const values = Object.values(CONTROL_COMMAND);
    expect(values).not.toContain('CLOSE_REQUESTED');
    expect(values).not.toContain('HEAD_OBSERVED');
    expect(values).not.toContain('INVOCATION_REQUESTED');
    expect(values).not.toContain('EVIDENCE_ADMITTED');
    expect(values).not.toContain('REVIEW_ADMITTED');
    expect(values.length).toBe(1);
  });

  it('recognises only the one command literal', () => {
    expect(isControlCommandKind('OPEN_HUMAN_GATE')).toBe(true);
    expect(isControlCommandKind('CLOSE_REQUESTED')).toBe(false);
    expect(isControlCommandKind('')).toBe(false);
    expect(isControlCommandKind(null)).toBe(false);
    expect(isControlCommandKind({ command: 'OPEN_HUMAN_GATE' })).toBe(false);
  });

  it('the command vocabulary object is frozen', () => {
    expect(Object.isFrozen(CONTROL_COMMAND)).toBe(true);
    expect(Object.isFrozen(CONTROL_COMMANDS)).toBe(true);
  });
});

describe('D062 control result vocabulary — bounded, closed distinctions', () => {
  it('distinguishes applied / no-workflow / gate-already-open / rejected / auth-failed / malformed / unavailable', () => {
    expect(CONTROL_RESULT.APPLIED).toBe('APPLIED');
    expect(CONTROL_RESULT.NO_WORKFLOW).toBe('NO_WORKFLOW');
    expect(CONTROL_RESULT.GATE_ALREADY_OPEN).toBe('GATE_ALREADY_OPEN');
    expect(CONTROL_RESULT.REJECTED).toBe('REJECTED');
    expect(CONTROL_RESULT.AUTH_FAILED).toBe('AUTH_FAILED');
    expect(CONTROL_RESULT.MALFORMED).toBe('MALFORMED');
    expect(CONTROL_RESULT.UNAVAILABLE).toBe('UNAVAILABLE');
  });

  it('isControlResultStatus accepts members and rejects non-members', () => {
    for (const status of CONTROL_RESULTS) {
      expect(isControlResultStatus(status)).toBe(true);
    }
    expect(isControlResultStatus('APPLIED_MAYBE')).toBe(false);
    expect(isControlResultStatus(undefined)).toBe(false);
    expect(isControlResultStatus(1)).toBe(false);
  });
});
