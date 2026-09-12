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

const ID_A: ChannelIdentity = {
  runtimeId: 'a'.repeat(32),
  pipeName: `agentbridge-control-${'a'.repeat(32)}`,
};
const ID_B: ChannelIdentity = {
  runtimeId: 'b'.repeat(32),
  pipeName: `agentbridge-control-${'b'.repeat(32)}`,
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

  it('binds runtime identity: two runtimes never share a server transcript', () => {
    const a = serverTranscript(ID_A, nonceS, nonceC, cmd, result);
    const b = serverTranscript(ID_B, nonceS, nonceC, cmd, result);
    expect(a.equals(b)).toBe(false);
  });

  it('NEGATIVE CONTROL: dropping the identity fields makes the two transcripts collide', () => {
    // The pre-amendment shape carried no runtimeId/pipeName. Reconstructed here
    // only to prove that the identity binding — not something else — is what
    // stops one runtime's signature being replayed as another's.
    const legacy = (): Buffer =>
      canonicalTranscript([Buffer.from('S', 'utf8'), nonceS, nonceC, cmd, result]);
    expect(legacy().equals(legacy())).toBe(true);
    expect(serverTranscript(ID_A, nonceS, nonceC, cmd, result).equals(legacy())).toBe(false);
  });
});

describe('D062 client MAC — token possession, command authorization only', () => {
  it('is 32 bytes', () => {
    expect(computeClientMac(token, ID_A, nonceS, nonceC, cmd).length).toBe(MAC_BYTES);
  });

  it('is deterministic for identical inputs', () => {
    const first = computeClientMac(token, ID_A, nonceS, nonceC, cmd);
    const second = computeClientMac(token, ID_A, nonceS, nonceC, cmd);
    expect(macEqual(first, second)).toBe(true);
  });

  it('a replayed client MAC does not verify under a fresh server nonce', () => {
    const macOld = computeClientMac(token, ID_A, nonceS, nonceC, cmd);
    const expectedUnderFresh = computeClientMac(
      token,
      ID_A,
      randomBytes(NONCE_BYTES),
      nonceC,
      cmd,
    );
    expect(macEqual(macOld, expectedUnderFresh)).toBe(false);
  });

  it('a tampered command after signing does not verify', () => {
    const signed = computeClientMac(token, ID_A, nonceS, nonceC, cmd);
    const tampered = computeClientMac(
      token,
      ID_A,
      nonceS,
      nonceC,
      Buffer.from('CLOSE_REQUESTED', 'utf8'),
    );
    expect(macEqual(signed, tampered)).toBe(false);
  });

  it('a wrong token does not verify', () => {
    const good = computeClientMac(token, ID_A, nonceS, nonceC, cmd);
    const wrong = computeClientMac(randomBytes(32), ID_A, nonceS, nonceC, cmd);
    expect(macEqual(good, wrong)).toBe(false);
  });

  it('the same token under a different runtime identity does not verify', () => {
    const forA = computeClientMac(token, ID_A, nonceS, nonceC, cmd);
    const forB = computeClientMac(token, ID_B, nonceS, nonceC, cmd);
    expect(macEqual(forA, forB)).toBe(false);
  });

  it('macEqual returns false for length mismatch and true only for identical bytes', () => {
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(16, 1))).toBe(false);
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 1))).toBe(true);
    expect(macEqual(Buffer.alloc(32, 1), Buffer.alloc(32, 2))).toBe(false);
  });
});

describe('D062 ephemeral runtime keypair', () => {
  it('mints a 32-byte raw verify key and a private key that is not a Buffer', () => {
    const kp = generateRuntimeKeyPair();
    expect(kp.verifyKey.length).toBe(VERIFY_KEY_BYTES);
    expect(Buffer.isBuffer(kp.privateKey)).toBe(false);
    expect(kp.privateKey.type).toBe('private');
    expect(kp.privateKey.asymmetricKeyType).toBe('ed25519');
  });

  it('mints a fresh key every call', () => {
    expect(generateRuntimeKeyPair().verifyKey.equals(generateRuntimeKeyPair().verifyKey)).toBe(
      false,
    );
  });

  it('round-trips a raw verify key into a usable public key', () => {
    const kp = generateRuntimeKeyPair();
    const publicKey = publicKeyFromVerifyKey(kp.verifyKey);
    expect(publicKey).not.toBeNull();
    expect(publicKey?.asymmetricKeyType).toBe('ed25519');
  });

  it('rejects a wrong-width or non-key verify key instead of throwing', () => {
    expect(publicKeyFromVerifyKey(Buffer.alloc(31))).toBeNull();
    expect(publicKeyFromVerifyKey(Buffer.alloc(33))).toBeNull();
    expect(publicKeyFromVerifyKey(Buffer.alloc(0))).toBeNull();
  });
});

describe('D062 server-result signature — ephemeral Ed25519, never a bearer credential', () => {
  const kpA = generateRuntimeKeyPair();
  const kpB = generateRuntimeKeyPair();

  const signA = (
    identity: ChannelIdentity = ID_A,
    s: Buffer = nonceS,
    c: Buffer = nonceC,
    command: Buffer = cmd,
    res: Buffer = result,
  ): Buffer => signServerResult(kpA.privateKey, identity, s, c, command, res);

  it('is 64 bytes and verifies under the matching verify key', () => {
    const sig = signA();
    expect(sig.length).toBe(SIG_BYTES);
    expect(verifyServerResult(kpA.verifyKey, ID_A, nonceS, nonceC, cmd, result, sig)).toBe(true);
  });

  it('CROSS-RUNTIME: runtime A signature does not verify under runtime B verify key', () => {
    expect(verifyServerResult(kpB.verifyKey, ID_A, nonceS, nonceC, cmd, result, signA())).toBe(
      false,
    );
  });

  it('CROSS-RUNTIME: runtime A signature replayed as runtime B identity fails', () => {
    expect(verifyServerResult(kpA.verifyKey, ID_B, nonceS, nonceC, cmd, result, signA())).toBe(
      false,
    );
  });

  it('TAMPER: a different result does not verify', () => {
    const sig = signA();
    for (const other of ['NO_WORKFLOW', 'AUTH_FAILED', 'MALFORMED', 'UNAVAILABLE']) {
      expect(
        verifyServerResult(
          kpA.verifyKey,
          ID_A,
          nonceS,
          nonceC,
          cmd,
          Buffer.from(other, 'utf8'),
          sig,
        ),
      ).toBe(false);
    }
  });

  it('TAMPER: one flipped command byte invalidates the signature', () => {
    const sig = signA();
    const flipped = Buffer.from(cmd);
    flipped[0] = (flipped[0] ?? 0) ^ 0x01;
    expect(verifyServerResult(kpA.verifyKey, ID_A, nonceS, nonceC, flipped, result, sig)).toBe(
      false,
    );
  });

  it('TAMPER: one flipped signature byte invalidates it', () => {
    const sig = signA();
    sig[10] = (sig[10] ?? 0) ^ 0x01;
    expect(verifyServerResult(kpA.verifyKey, ID_A, nonceS, nonceC, cmd, result, sig)).toBe(false);
  });

  it('FRESH NONCE: a harvested signature fails against every fresh client nonce', () => {
    const harvested = signA();
    for (let index = 0; index < 32; index += 1) {
      expect(
        verifyServerResult(
          kpA.verifyKey,
          ID_A,
          nonceS,
          randomBytes(NONCE_BYTES),
          cmd,
          result,
          harvested,
        ),
      ).toBe(false);
    }
  });

  it('FRESH NONCE: a harvested signature fails against a fresh server nonce', () => {
    expect(
      verifyServerResult(
        kpA.verifyKey,
        ID_A,
        randomBytes(NONCE_BYTES),
        nonceC,
        cmd,
        result,
        signA(),
      ),
    ).toBe(false);
  });

  it('fails closed on a wrong-width signature without throwing', () => {
    for (const width of [0, 32, 63, 65, 128]) {
      expect(
        verifyServerResult(kpA.verifyKey, ID_A, nonceS, nonceC, cmd, result, randomBytes(width)),
      ).toBe(false);
    }
  });

  it('fails closed on a malformed or wrong verify key without throwing', () => {
    const sig = signA();
    expect(verifyServerResult(Buffer.alloc(31), ID_A, nonceS, nonceC, cmd, result, sig)).toBe(
      false,
    );
    expect(verifyServerResult(randomBytes(32), ID_A, nonceS, nonceC, cmd, result, sig)).toBe(false);
  });

  it('the verify key alone cannot produce a signature — it is public, not a credential', () => {
    // Everything a descriptor copier holds: the verifyKey bytes. There is no
    // exported path from a verify key to a signing key.
    const publicKey = publicKeyFromVerifyKey(kpA.verifyKey);
    expect(publicKey?.type).toBe('public');
    expect(() => signServerResult(publicKey as never, ID_A, nonceS, nonceC, cmd, result)).toThrow();
  });
});
