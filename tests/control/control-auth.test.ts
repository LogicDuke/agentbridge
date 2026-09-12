import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  canonicalTranscript,
  computeClientMac,
  computeServerMac,
  macEqual,
  MAC_BYTES,
  NONCE_BYTES,
} from '../../src/control/control-auth.js';

const token = randomBytes(32);
const nonceS = randomBytes(NONCE_BYTES);
const nonceC = randomBytes(NONCE_BYTES);
const cmd = Buffer.from('OPEN_HUMAN_GATE', 'utf8');
const result = Buffer.from('APPLIED', 'utf8');

describe('D062 canonical transcript — byte-unambiguous, length-framed', () => {
  it('is length-unambiguous: shifting a byte across a field boundary changes the transcript', () => {
    const a = canonicalTranscript([Buffer.from('a'), Buffer.from('bc')]);
    const b = canonicalTranscript([Buffer.from('ab'), Buffer.from('c')]);
    expect(a.equals(b)).toBe(false);
  });

  it('binds exact bytes: any field change changes the transcript', () => {
    const base = canonicalTranscript([nonceS, nonceC, cmd]);
    const changed = canonicalTranscript([nonceS, nonceC, Buffer.from('OPEN_HUMAN_GATEX', 'utf8')]);
    expect(base.equals(changed)).toBe(false);
  });
});

describe('D062 mutual HMAC primitives', () => {
  it('client and server MACs are 32 bytes', () => {
    expect(computeClientMac(token, nonceS, nonceC, cmd).length).toBe(MAC_BYTES);
    expect(computeServerMac(token, nonceS, nonceC, cmd, result).length).toBe(MAC_BYTES);
  });

  it('client and server MACs differ (role domain separation)', () => {
    const macC = computeClientMac(token, nonceS, nonceC, cmd);
    // Server MAC over the same nonces+command, empty result, still differs by role tag.
    const macS = computeServerMac(token, nonceS, nonceC, cmd, Buffer.alloc(0));
    expect(macEqual(macC, macS)).toBe(false);
  });

  it('is deterministic for identical inputs', () => {
    const first = computeClientMac(token, nonceS, nonceC, cmd);
    const second = computeClientMac(token, nonceS, nonceC, cmd);
    expect(macEqual(first, second)).toBe(true);
  });

  it('a replayed client MAC does not verify under a fresh server nonce', () => {
    const macOld = computeClientMac(token, nonceS, nonceC, cmd);
    const freshNonceS = randomBytes(NONCE_BYTES);
    const expectedUnderFresh = computeClientMac(token, freshNonceS, nonceC, cmd);
    expect(macEqual(macOld, expectedUnderFresh)).toBe(false);
  });

  it('a tampered command after signing does not verify', () => {
    const signed = computeClientMac(token, nonceS, nonceC, cmd);
    const tampered = computeClientMac(token, nonceS, nonceC, Buffer.from('CLOSE_REQUESTED', 'utf8'));
    expect(macEqual(signed, tampered)).toBe(false);
  });

  it('a tampered result after signing does not verify (server MAC)', () => {
    const signed = computeServerMac(token, nonceS, nonceC, cmd, Buffer.from('APPLIED', 'utf8'));
    const tampered = computeServerMac(token, nonceS, nonceC, cmd, Buffer.from('NO_WORKFLOW', 'utf8'));
    expect(macEqual(signed, tampered)).toBe(false);
  });

  it('a wrong token does not verify', () => {
    const good = computeClientMac(token, nonceS, nonceC, cmd);
    const wrong = computeClientMac(randomBytes(32), nonceS, nonceC, cmd);
    expect(macEqual(good, wrong)).toBe(false);
  });

  it('macEqual returns false for length mismatch and true only for identical bytes', () => {
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(16, 1))).toBe(false);
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 1))).toBe(true);
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 2))).toBe(false);
  });
});
