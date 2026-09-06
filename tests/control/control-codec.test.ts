import { describe, expect, it } from 'vitest';

import { decodeBase64UrlExact, encodeBase64Url } from '../../src/control/control-codec.js';

describe('D062 base64url codec — exact-length, round-trip verified', () => {
  it('round-trips 32-byte buffers', () => {
    const bytes = Buffer.from(Array.from({ length: 32 }, (_v, index) => index % 256));
    const encoded = encodeBase64Url(bytes);
    const decoded = decodeBase64UrlExact(encoded, 32);
    expect(decoded).not.toBeNull();
    expect(decoded?.equals(bytes)).toBe(true);
  });

  it('rejects a value whose decoded length differs from expected', () => {
    const bytes = Buffer.alloc(16, 7);
    const encoded = encodeBase64Url(bytes);
    expect(decodeBase64UrlExact(encoded, 32)).toBeNull();
    expect(decodeBase64UrlExact(encoded, 16)).not.toBeNull();
  });

  it('rejects non-canonical encodings (padding / standard base64 alphabet)', () => {
    const bytes = Buffer.alloc(32, 255); // encodes with '_' in base64url, '/' in base64
    const b64url = encodeBase64Url(bytes);
    const b64standard = bytes.toString('base64'); // '+' '/' and '=' padding
    expect(decodeBase64UrlExact(b64url, 32)).not.toBeNull();
    // Standard base64 of the same 32 bytes is not canonical base64url → rejected.
    expect(decodeBase64UrlExact(b64standard, 32)).toBeNull();
  });

  it('rejects empty string, non-string, and whitespace-tainted input', () => {
    expect(decodeBase64UrlExact('', 32)).toBeNull();
    expect(decodeBase64UrlExact(null, 32)).toBeNull();
    expect(decodeBase64UrlExact(123, 32)).toBeNull();
    const bytes = Buffer.alloc(32, 1);
    expect(decodeBase64UrlExact(` ${encodeBase64Url(bytes)}`, 32)).toBeNull();
  });
});
