/**
 * Small, strict base64url codecs for the fixed-length secrets and nonces the
 * Decision 062 control path exchanges.
 *
 * Every decode is **exact-length** and **round-trip verified**: a value is
 * accepted only if it re-encodes to the identical input, so trailing padding,
 * non-canonical alphabets, embedded whitespace, or an off-by-one length all fail
 * closed rather than silently truncating a secret or a nonce.
 *
 * Only module-load-captured intrinsics are used, so a later prototype poisoning
 * cannot redirect `Buffer.from`/`toString`.
 */

const bufferFrom = Buffer.from.bind(Buffer);

/** Encode raw bytes as base64url (no padding). */
export function encodeBase64Url(bytes: Buffer): string {
  return bytes.toString('base64url');
}

/**
 * Decode a base64url string that must represent **exactly** `expectedLength`
 * bytes, or return `null`.
 *
 * The re-encode check rejects any input that is not the canonical base64url of
 * its own bytes (padding, alternate alphabet, whitespace), closing the door on
 * ambiguous encodings of the same secret.
 */
export function decodeBase64UrlExact(value: unknown, expectedLength: number): Buffer | null {
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  let decoded: Buffer;
  try {
    decoded = bufferFrom(value, 'base64url');
  } catch {
    return null;
  }
  if (decoded.length !== expectedLength) {
    return null;
  }
  if (decoded.toString('base64url') !== value) {
    return null;
  }
  return decoded;
}
