/**
 * Mutual HMAC-SHA256 token-possession authentication for the Decision 062
 * control path.
 *
 * Neither party ever transmits the token. Possession is proved over a
 * per-connection challenge:
 *
 *   1. server generates a fresh 256-bit `nonceS` and sends it;
 *   2. client generates a fresh 256-bit `nonceC` and sends, with the command,
 *      `macC = HMAC(token, T("C", nonceS, nonceC, command))`;
 *   3. server verifies `macC` with a constant-time compare before any dispatch;
 *   4. server returns the result with
 *      `macS = HMAC(token, T("S", nonceS, nonceC, command, result))`;
 *   5. the CLI verifies `macS` and refuses to trust the result otherwise.
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
 * transcript; the two nonces are fixed 32-byte fields; the command and result
 * are the **exact wire bytes** the peer sent. Because every field carries an
 * explicit length, no shifting of bytes across a field boundary can produce the
 * same transcript — length ambiguity is structurally impossible.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

/** Length in bytes of every nonce (256-bit) and every MAC tag (HMAC-SHA256). */
export const NONCE_BYTES = 32;
export const MAC_BYTES = 32;

const HMAC_ALGORITHM = 'sha256';

/** Fixed domain-separation tag; leads every transcript, framed like any field. */
const DOMAIN_TAG = Buffer.from('AGENTBRIDGE-CONTROL-HANDSHAKE-V1', 'utf8');
/** Role tags — distinct first field, so client and server transcripts differ. */
const ROLE_CLIENT = Buffer.from('C', 'utf8');
const ROLE_SERVER = Buffer.from('S', 'utf8');

const createHmacFn = createHmac;
const timingSafeEqualFn = timingSafeEqual;

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

/** `macC = HMAC(token, T("C", nonceS, nonceC, command))`. */
export function computeClientMac(
  token: Buffer,
  nonceS: Buffer,
  nonceC: Buffer,
  commandBytes: Buffer,
): Buffer {
  const transcript = canonicalTranscript([ROLE_CLIENT, nonceS, nonceC, commandBytes]);
  return createHmacFn(HMAC_ALGORITHM, token).update(transcript).digest();
}

/** `macS = HMAC(token, T("S", nonceS, nonceC, command, result))`. */
export function computeServerMac(
  token: Buffer,
  nonceS: Buffer,
  nonceC: Buffer,
  commandBytes: Buffer,
  resultBytes: Buffer,
): Buffer {
  const transcript = canonicalTranscript([ROLE_SERVER, nonceS, nonceC, commandBytes, resultBytes]);
  return createHmacFn(HMAC_ALGORITHM, token).update(transcript).digest();
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
