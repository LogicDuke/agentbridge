/*
 * Canonical owner-helper provenance format — the single producer of the
 * provenance bytes for Decision 062 / PR #84.
 *
 * This module owns ONE canonical representation of the generated provenance
 * ES-module. Both the trusted build (tools/control-owner/build.mjs) and the
 * launch-time provisioning gate (tools/control-owner/ensure-helper.mjs) use this
 * exact encoder, so there is a single source of truth: the build publishes exactly
 * `encodeProvenance(sha256)` and the gate accepts a pair iff the on-disk provenance
 * bytes equal `encodeProvenance(sha256(helper))`. No second template, no parser.
 *
 * It is pure: no filesystem reads, no environment reads, no time/randomness, no
 * mutable global state, no side effects. The output is deterministic UTF-8 text
 * (LF line endings) — there is deliberately no timestamp or host-specific field,
 * so whole-file byte equality is a stable acceptance predicate. The format is the
 * exact ES module the runtime (src/control/control-store.ts) imports; this module
 * factors it out verbatim rather than redefining it.
 */

/** The one native helper's filename (also its on-disk basename under dist/…/native). */
export const OWNER_HELPER_BASENAME = 'agentbridge-win-owner.exe';

/** The generated provenance module's basename under dist/control/native/. */
export const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

/** The canonical (runtime-consumed) SHA-256 digest shape: lowercase 64-hex. */
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Encode the canonical provenance ES-module text for a helper whose SHA-256 digest
 * is `sha256Hex` (lowercase 64-hex). Deterministic and side-effect-free. Throws a
 * TypeError if the digest is not a lowercase 64-hex string, so a malformed digest
 * can never be encoded.
 *
 * @param {string} sha256Hex
 * @returns {string}
 */
export function encodeProvenance(sha256Hex) {
  if (typeof sha256Hex !== 'string' || !SHA256_PATTERN.test(sha256Hex)) {
    throw new TypeError('encodeProvenance: sha256 must be a lowercase 64-hex string.');
  }
  return (
    '// GENERATED BUILD METADATA — do not edit.\n' +
    '// Produced by tools/control-owner/build.mjs from the exact compiled binary.\n' +
    '// This is the runtime trust root for the owner helper (SHA-256 of the binary).\n' +
    'export const OWNER_HELPER_PROVENANCE = {\n' +
    `  filename: ${JSON.stringify(OWNER_HELPER_BASENAME)},\n` +
    `  sha256: ${JSON.stringify(sha256Hex)},\n` +
    '  built: true,\n' +
    '};\n'
  );
}
