/*
 * Canonical native-artifact provenance formats — the single producer of the
 * provenance bytes for Decision 062 / PR #84.
 *
 * This module owns ONE canonical representation per artifact of the generated
 * provenance ES-module. Both the trusted build (tools/control-owner/build.mjs) and
 * the launch-time provisioning gate (tools/control-owner/ensure-helper.mjs) use these
 * exact encoders, so there is a single source of truth: the build publishes exactly
 * `encodeProvenance(sha256)` / `encodeCreatorProvenance(sha256)` and the gate accepts
 * a pair iff the on-disk provenance bytes equal the encoder output for the artifact's
 * own hash. No second template, no parser.
 *
 * There are TWO native artifacts with SEPARATE identities and SEPARATE provenance
 * (Decision 062 Amendment C). They are never interchangeable and never share a
 * provenance module:
 *
 *   - agentbridge-win-owner.exe            READ-ONLY  → OWNER_HELPER_PROVENANCE
 *   - agentbridge-win-descriptor-create.exe CREATE-ONLY → DESCRIPTOR_CREATOR_PROVENANCE
 *
 * Each generated module exports a DISTINCT binding name, so a swapped or
 * cross-wired provenance file cannot satisfy the other artifact's runtime gate: the
 * consumer looks up its own binding by name and fails closed when it is absent.
 *
 * It is pure: no filesystem reads, no environment reads, no time/randomness, no
 * mutable global state, no side effects. The output is deterministic UTF-8 text
 * (LF line endings) — there is deliberately no timestamp or host-specific field,
 * so whole-file byte equality is a stable acceptance predicate. The format is the
 * exact ES module the runtime (src/control/control-store.ts) imports; this module
 * factors it out verbatim rather than redefining it.
 */

/** The read-only owner/ACL helper's filename (its basename under dist/…/native). */
export const OWNER_HELPER_BASENAME = 'agentbridge-win-owner.exe';

/** The generated owner-helper provenance module's basename under dist/control/native/. */
export const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

/** The descriptor-creator's filename (its basename under dist/…/native). */
export const DESCRIPTOR_CREATOR_BASENAME = 'agentbridge-win-descriptor-create.exe';

/** The generated creator provenance module's basename under dist/control/native/. */
export const CREATOR_PROVENANCE_BASENAME = 'descriptor-creator-provenance.js';

/** The canonical (runtime-consumed) SHA-256 digest shape: lowercase 64-hex. */
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The one provenance-module shape, parameterized by the exported binding name, the
 * artifact filename, its prose label, and the artifact's digest. Every generated
 * provenance module in the tree is exactly this text; there is no second template.
 * The owner helper's bytes are unchanged from before the creator existed.
 *
 * @param {string} binding
 * @param {string} filename
 * @param {string} label
 * @param {string} sha256Hex
 * @returns {string}
 */
function encodeModule(binding, filename, label, sha256Hex) {
  if (typeof sha256Hex !== 'string' || !SHA256_PATTERN.test(sha256Hex)) {
    throw new TypeError('encodeProvenance: sha256 must be a lowercase 64-hex string.');
  }
  return (
    '// GENERATED BUILD METADATA — do not edit.\n' +
    '// Produced by tools/control-owner/build.mjs from the exact compiled binary.\n' +
    `// This is the runtime trust root for ${label} (SHA-256 of the binary).\n` +
    `export const ${binding} = {\n` +
    `  filename: ${JSON.stringify(filename)},\n` +
    `  sha256: ${JSON.stringify(sha256Hex)},\n` +
    '  built: true,\n' +
    '};\n'
  );
}

/**
 * Encode the canonical provenance ES-module text for the READ-ONLY owner helper whose
 * SHA-256 digest is `sha256Hex` (lowercase 64-hex). Deterministic and side-effect-free.
 * Throws a TypeError if the digest is not a lowercase 64-hex string, so a malformed
 * digest can never be encoded.
 *
 * @param {string} sha256Hex
 * @returns {string}
 */
export function encodeProvenance(sha256Hex) {
  return encodeModule(
    'OWNER_HELPER_PROVENANCE',
    OWNER_HELPER_BASENAME,
    'the owner helper',
    sha256Hex,
  );
}

/**
 * Encode the canonical provenance ES-module text for the descriptor CREATOR whose
 * SHA-256 digest is `sha256Hex`. A separate binding name and a separate filename from
 * {@link encodeProvenance}, so the two artifacts' trust roots can never be confused.
 *
 * @param {string} sha256Hex
 * @returns {string}
 */
export function encodeCreatorProvenance(sha256Hex) {
  return encodeModule(
    'DESCRIPTOR_CREATOR_PROVENANCE',
    DESCRIPTOR_CREATOR_BASENAME,
    'the descriptor creator',
    sha256Hex,
  );
}
