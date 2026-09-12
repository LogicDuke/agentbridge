/**
 * Decision 062 control-path authentication
 * (AGENTBRIDGE_DECISION_062_AMENDMENT_RUNTIME_AUTHENTICATION_2026-09-12; DDR-D062-A).
 *
 * The two directions are authenticated by **different** primitives, because they
 * answer different questions:
 *
 *   1. server generates a fresh 256-bit `nonceS` and sends it;
 *   2. client generates a fresh 256-bit `nonceC` and sends, with the command,
 *      `macC = HMAC(token, T("C", runtimeId, pipeName, nonceS, nonceC, command))`;
 *   3. server verifies `macC` with a constant-time compare before any dispatch;
 *   4. server returns the result with
 *      `sigS = Ed25519(sk, T("S", runtimeId, pipeName, nonceS, nonceC, command, result))`;
 *   5. the CLI verifies `sigS` against the `verifyKey` published in the SAME
 *      descriptor it discovered, and refuses to trust the result otherwise.
 *
 * ## Why the server no longer MACs with the token
 *
 * The token lives, by necessity, in the on-disk descriptor. A bearer credential
 * at rest is copyable, so ACL/pathname inspection can never decide whether a
 * given `{token}` is a genuine runtime's or a replay of bytes someone copied
 * earlier — that is a predicate over history, not over state at time t. The
 * server-side authenticator is therefore an **ephemeral Ed25519 private key**
 * that exists only in the live runtime's process memory and is never serialized:
 * copied descriptor bytes alone carry no signing capability, so a squatter on a
 * freed pipe cannot produce `sigS` (CI-2, unconditional).
 *
 * The token is RETAINED, scope-reduced, as the client-to-server authorizer only
 * (CI-3): possession still means "could read the descriptor inside the hardened
 * anchor". Deleting it would leave the command direction unauthenticated.
 *
 * Authority over WHICH `verifyKey` may be believed is not in this module and is
 * not cryptographic: it is the kernel-enforced anchor OWNER/DACL gate plus the
 * held-handle read. The keypair supplies freshness and non-exportability, never
 * authority. Same-SID, Administrator and SYSTEM principals are out of scope
 * whether the genuine runtime is alive or dead.
 *
 * ## Canonical transcript `T(...)` — byte-unambiguous by construction
 *
 * The transcript is **not** a re-serialized semantic JSON (re-serialization can
 * reorder keys or renormalize whitespace, breaking exact-byte binding). It is a
 * length-framed concatenation of the exact byte fields:
 *
 *   T(fields) = LP(DOMAIN) ++ LP(field_0) ++ ... ++ LP(field_n)
 *   LP(b)     = uint32be(b.length) ++ b
 *
 * A fixed domain-separation tag leads every transcript; the role tag (`"C"`/
 * `"S"`) is the first field, so a client transcript can never equal a server
 * transcript; `runtimeId` and `pipeName` follow, so one runtime's signature can
 * never be relayed as another runtime's answer; the two nonces are fixed 32-byte
 * fields; the command and result are the **exact wire bytes** the peer sent.
 * Because every field carries an explicit length, no shifting of bytes across a
 * field boundary can produce the same transcript — length ambiguity is
 * structurally impossible.
 *
 * Freshness rests entirely on `nonceC`: it is client-generated, 256-bit, from a
 * CSPRNG, and fresh per connection, so a signature harvested from a live runtime
 * is useless against any later connection once that runtime is gone.
 */

import {
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  sign as signOneShot,
  timingSafeEqual,
  verify as verifyOneShot,
  type KeyObject,
} from 'node:crypto';

/** Length in bytes of every nonce (256-bit) and every MAC tag (HMAC-SHA256). */
export const NONCE_BYTES = 32;
export const MAC_BYTES = 32;
/** Raw Ed25519 public key and signature widths. */
export const VERIFY_KEY_BYTES = 32;
export const SIG_BYTES = 64;

const HMAC_ALGORITHM = 'sha256';

/** Fixed domain-separation tag; leads every transcript, framed like any field. */
const DOMAIN_TAG = Buffer.from('AGENTBRIDGE-CONTROL-HANDSHAKE-V2', 'utf8');
/** Role tags — distinct first field, so client and server transcripts differ. */
const ROLE_CLIENT = Buffer.from('C', 'utf8');
const ROLE_SERVER = Buffer.from('S', 'utf8');

/**
 * The fixed 12-byte SPKI DER header of an Ed25519 public key. Prepending it to
 * the raw 32-byte key yields the exact DER a `KeyObject` accepts, so a descriptor
 * can publish the raw key with no ambiguity about encoding.
 */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const createHmacFn = createHmac;
const timingSafeEqualFn = timingSafeEqual;

/** The per-runtime ephemeral identity: a signing key and its publishable half. */
export interface RuntimeKeyPair {
  /** Process-memory only. NEVER serialized, logged, or passed to a subprocess. */
  readonly privateKey: KeyObject;
  /** Raw 32-byte Ed25519 public key — the descriptor's `verifyKey`. */
  readonly verifyKey: Buffer;
}

/**
 * Mint one runtime's ephemeral identity. Ed25519 (not ECDSA): signing is
 * deterministic, so there is no per-signature nonce that could leak the key.
 */
export function generateRuntimeKeyPair(): RuntimeKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    privateKey,
    verifyKey: Buffer.from(spki.subarray(spki.length - VERIFY_KEY_BYTES)),
  };
}

/** A raw 32-byte `verifyKey` as a usable public key, or `null` (fail closed). */
export function publicKeyFromVerifyKey(verifyKey: Buffer): KeyObject | null {
  if (verifyKey.length !== VERIFY_KEY_BYTES) {
    return null;
  }
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, verifyKey]),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return null;
  }
}

/** `uint32be(length) ++ bytes` — one length-prefixed field. */
function lengthPrefixed(bytes: Buffer): Buffer {
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([prefix, bytes]);
}

/** Build `T(DOMAIN, ...fields)` — the canonical, length-framed transcript. */
export function canonicalTranscript(fields: readonly Buffer[]): Buffer {
  const parts: Buffer[] = [lengthPrefixed(DOMAIN_TAG)];
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    if (field === undefined) {
      // Unreachable for a dense array; fail closed rather than frame a gap.
      throw new Error('control-auth: undefined transcript field.');
    }
    parts.push(lengthPrefixed(field));
  }
  return Buffer.concat(parts);
}

/** The runtime identity both transcripts bind, so signatures cannot be relayed. */
export interface ChannelIdentity {
  readonly runtimeId: string;
  readonly pipeName: string;
}

function identityFields(identity: ChannelIdentity): readonly Buffer[] {
  return [Buffer.from(identity.runtimeId, 'utf8'), Buffer.from(identity.pipeName, 'utf8')];
}

/** `macC = HMAC(token, T("C", runtimeId, pipeName, nonceS, nonceC, command))`. */
export function computeClientMac(
  token: Buffer,
  identity: ChannelIdentity,
  nonceS: Buffer,
  nonceC: Buffer,
  commandBytes: Buffer,
): Buffer {
  const transcript = canonicalTranscript([
    ROLE_CLIENT,
    ...identityFields(identity),
    nonceS,
    nonceC,
    commandBytes,
  ]);
  return createHmacFn(HMAC_ALGORITHM, token).update(transcript).digest();
}

/** The exact bytes an Ed25519 server signature covers. */
export function serverTranscript(
  identity: ChannelIdentity,
  nonceS: Buffer,
  nonceC: Buffer,
  commandBytes: Buffer,
  resultBytes: Buffer,
): Buffer {
  return canonicalTranscript([
    ROLE_SERVER,
    ...identityFields(identity),
    nonceS,
    nonceC,
    commandBytes,
    resultBytes,
  ]);
}

/**
 * `sigS = Ed25519(sk, T("S", runtimeId, pipeName, nonceS, nonceC, command, result))`.
 * The private key never leaves this call; nothing derived from it is returned
 * except the signature itself.
 */
export function signServerResult(
  privateKey: KeyObject,
  identity: ChannelIdentity,
  nonceS: Buffer,
  nonceC: Buffer,
  commandBytes: Buffer,
  resultBytes: Buffer,
): Buffer {
  return signOneShot(
    null,
    serverTranscript(identity, nonceS, nonceC, commandBytes, resultBytes),
    privateKey,
  );
}

/**
 * Verify a server result signature against the `verifyKey` of the descriptor the
 * client discovered. Any malformed key, wrong-width signature, or verification
 * error is `false` — there is no partial trust and no error path that could be
 * mistaken for success.
 */
export function verifyServerResult(
  verifyKey: Buffer,
  identity: ChannelIdentity,
  nonceS: Buffer,
  nonceC: Buffer,
  commandBytes: Buffer,
  resultBytes: Buffer,
  signature: Buffer,
): boolean {
  if (signature.length !== SIG_BYTES) {
    return false;
  }
  const publicKey = publicKeyFromVerifyKey(verifyKey);
  if (publicKey === null) {
    return false;
  }
  try {
    return verifyOneShot(
      null,
      serverTranscript(identity, nonceS, nonceC, commandBytes, resultBytes),
      publicKey,
      signature,
    );
  } catch {
    return false;
  }
}

/**
 * Constant-time MAC comparison. A length mismatch short-circuits to `false`
 * (`timingSafeEqual` throws on unequal lengths); equal-length tags are compared
 * without a data-dependent early exit.
 */
export function macEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqualFn(a, b);
}
