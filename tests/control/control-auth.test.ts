import { randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  canonicalTranscript,
  computeClientMac,
  generateRuntimeKeyPair,
  macEqual,
  publicKeyFromVerifyKey,
  serverTranscript,
  signServerResult,
  verifyServerResult,
  MAC_BYTES,
  NONCE_BYTES,
  SIG_BYTES,
  VERIFY_KEY_BYTES,
  type ChannelIdentity,
} from '../../src/control/control-auth.js';

const token = randomBytes(32);
const nonceS = randomBytes(NONCE_BYTES);
const nonceC = randomBytes(NONCE_BYTES);
const cmd = Buffer.from('OPEN_HUMAN_GATE', 'utf8');
const result = Buffer.from('APPLIED', 'utf8');

const runtime = generateRuntimeKeyPair();
const identity: ChannelIdentity = {
  runtimeId: 'a'.repeat(32),
  pipeName: `agentbridge-control-${'a'.repeat(32)}`,
  verifyKey: runtime.verifyKey,
};

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

  it('binds the attested verify key: the same session under a different key differs', () => {
    const other = generateRuntimeKeyPair();
    const a = serverTranscript(identity, nonceS, nonceC, cmd, result);
    const b = serverTranscript(
      { ...identity, verifyKey: other.verifyKey },
      nonceS,
      nonceC,
      cmd,
      result,
    );
    expect(a.equals(b)).toBe(false);
  });

  it('binds the runtime id and pipe name', () => {
    const base = serverTranscript(identity, nonceS, nonceC, cmd, result);
    expect(
      serverTranscript(
        { ...identity, runtimeId: 'b'.repeat(32) },
        nonceS,
        nonceC,
        cmd,
        result,
      ).equals(base),
    ).toBe(false);
    expect(
      serverTranscript(
        { ...identity, pipeName: 'agentbridge-control-other' },
        nonceS,
        nonceC,
        cmd,
        result,
      ).equals(base),
    ).toBe(false);
  });
});

describe('D062 client-to-server HMAC (the only token-authenticated direction)', () => {
  it('the client MAC is 32 bytes', () => {
    expect(computeClientMac(token, identity, nonceS, nonceC, cmd).length).toBe(MAC_BYTES);
  });

  it('is deterministic for identical inputs', () => {
    const first = computeClientMac(token, identity, nonceS, nonceC, cmd);
    const second = computeClientMac(token, identity, nonceS, nonceC, cmd);
    expect(macEqual(first, second)).toBe(true);
  });

  it('a replayed client MAC does not verify under a fresh server nonce', () => {
    const macOld = computeClientMac(token, identity, nonceS, nonceC, cmd);
    const freshNonceS = randomBytes(NONCE_BYTES);
    const expectedUnderFresh = computeClientMac(token, identity, freshNonceS, nonceC, cmd);
    expect(macEqual(macOld, expectedUnderFresh)).toBe(false);
  });

  it('a tampered command after signing does not verify', () => {
    const signed = computeClientMac(token, identity, nonceS, nonceC, cmd);
    const tampered = computeClientMac(
      token,
      identity,
      nonceS,
      nonceC,
      Buffer.from('CLOSE_REQUESTED', 'utf8'),
    );
    expect(macEqual(signed, tampered)).toBe(false);
  });

  it('a wrong token does not verify', () => {
    const good = computeClientMac(token, identity, nonceS, nonceC, cmd);
    const wrong = computeClientMac(randomBytes(32), identity, nonceS, nonceC, cmd);
    expect(macEqual(good, wrong)).toBe(false);
  });

  it('a different runtime identity does not verify', () => {
    const good = computeClientMac(token, identity, nonceS, nonceC, cmd);
    const other = generateRuntimeKeyPair();
    const wrong = computeClientMac(
      token,
      { ...identity, verifyKey: other.verifyKey },
      nonceS,
      nonceC,
      cmd,
    );
    expect(macEqual(good, wrong)).toBe(false);
  });

  it('macEqual returns false for length mismatch and true only for identical bytes', () => {
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(16, 1))).toBe(false);
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 1))).toBe(true);
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 2))).toBe(false);
  });
});

describe('D062 server-to-client Ed25519 (no token-authenticated result path exists)', () => {
  it('the control-auth module exports no server MAC primitive', async () => {
    const auth = (await import('../../src/control/control-auth.js')) as Record<string, unknown>;
    expect(Object.hasOwn(auth, 'computeServerMac')).toBe(false);
    expect(auth['computeServerMac']).toBeUndefined();
  });

  it('mints a 32-byte raw verify key and signs 64-byte signatures', () => {
    expect(runtime.verifyKey.length).toBe(VERIFY_KEY_BYTES);
    const sig = signServerResult(runtime.privateKey, identity, nonceS, nonceC, cmd, result);
    expect(sig.length).toBe(SIG_BYTES);
  });

  it('mints a FRESH keypair per call (per runtime start)', () => {
    const a = generateRuntimeKeyPair();
    const b = generateRuntimeKeyPair();
    expect(a.verifyKey.equals(b.verifyKey)).toBe(false);
  });

  it('a genuine signature verifies under the attested key', () => {
    const sig = signServerResult(runtime.privateKey, identity, nonceS, nonceC, cmd, result);
    expect(verifyServerResult(identity, nonceS, nonceC, cmd, result, sig)).toBe(true);
  });

  it('a signature from ANOTHER keypair does not verify (a public key is not a capability)', () => {
    const attacker = generateRuntimeKeyPair();
    const sig = signServerResult(attacker.privateKey, identity, nonceS, nonceC, cmd, result);
    expect(verifyServerResult(identity, nonceS, nonceC, cmd, result, sig)).toBe(false);
  });

  it('a tampered result after signing does not verify', () => {
    const sig = signServerResult(runtime.privateKey, identity, nonceS, nonceC, cmd, result);
    expect(
      verifyServerResult(identity, nonceS, nonceC, cmd, Buffer.from('NO_WORKFLOW', 'utf8'), sig),
    ).toBe(false);
  });

  it('a signature is not replayable under a fresh client nonce', () => {
    const sig = signServerResult(runtime.privateKey, identity, nonceS, nonceC, cmd, result);
    const freshNonceC = randomBytes(NONCE_BYTES);
    expect(verifyServerResult(identity, nonceS, freshNonceC, cmd, result, sig)).toBe(false);
  });

  it('a signature made for one runtime does not verify as another runtime', () => {
    const sig = signServerResult(runtime.privateKey, identity, nonceS, nonceC, cmd, result);
    const relayed: ChannelIdentity = { ...identity, runtimeId: 'b'.repeat(32) };
    expect(verifyServerResult(relayed, nonceS, nonceC, cmd, result, sig)).toBe(false);
  });

  it('a wrong-width signature and a malformed verify key both fail closed', () => {
    const sig = signServerResult(runtime.privateKey, identity, nonceS, nonceC, cmd, result);
    expect(verifyServerResult(identity, nonceS, nonceC, cmd, result, sig.subarray(0, 63))).toBe(
      false,
    );
    expect(
      verifyServerResult(
        { ...identity, verifyKey: Buffer.alloc(31) },
        nonceS,
        nonceC,
        cmd,
        result,
        sig,
      ),
    ).toBe(false);
  });

  it('publicKeyFromVerifyKey accepts exactly 32 raw bytes and rejects other widths', () => {
    expect(publicKeyFromVerifyKey(runtime.verifyKey)).not.toBeNull();
    expect(publicKeyFromVerifyKey(Buffer.alloc(31))).toBeNull();
    expect(publicKeyFromVerifyKey(Buffer.alloc(33))).toBeNull();
  });
});
