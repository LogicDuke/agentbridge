/*
 * Canonical native-artifact provenance formats — the single producer of the
 * provenance bytes for Decision 062 / PR #84.
 *
 * This module owns ONE canonical representation per artifact of the generated
 * provenance ES-module. Both the trusted build (tools/control-owner/build.mjs) and
 * the launch-time provisioning gate (tools/control-owner/ensure-helper.mjs) use these
 * exact encoders, so there is a single source of truth: the build publishes exactly
 * `encodeProvenance(sha256, sourceId)` / `encodeCreatorProvenance(sha256, sourceId)`
 * and the gate accepts a pair iff the on-disk provenance bytes equal the encoder output
 * for the artifact's own hash and the CURRENT reviewed source. No second template, no
 * parser.
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
 * Each encoding binds TWO identities: the SHA-256 of the exact published binary and
 * `sourceId`, the SHA-256 of the exact reviewed C source that build compiled. The
 * pair identity is therefore (binary bytes, source bytes), not the binary alone. A
 * binary built from an older reviewed source can no longer be canonical merely
 * because its own provenance matches itself: the current encoding names the current
 * source, so a stale pair fails byte-equality and provisioning rebuilds it. This is
 * what makes lifecycle validity imply compatibility with the runtime's current
 * snapshot protocol (`AGENTBRIDGE-ACL-V2`), whose only definition is that source.
 *
 * It is pure: no filesystem reads, no environment reads, no time/randomness, no
 * mutable global state, no side effects — `sourceId` is supplied by the caller
 * (helper-pair.mjs owns the one filesystem read). The output is deterministic UTF-8
 * text (LF line endings) — there is deliberately no timestamp or host-specific
 * field, so whole-file byte equality is a stable acceptance predicate. The format is
 * the exact ES module the runtime (src/control/control-store.ts) imports; this module
 * factors it out verbatim rather than redefining it. The runtime reads only
 * `filename` and `sha256` and ignores every other field, so `sourceId` is lifecycle
 * metadata only and grants no trust the runtime would otherwise deny.
 */

/** The read-only owner/ACL helper's filename (its basename under dist/…/native). */
export const OWNER_HELPER_BASENAME = 'agentbridge-win-owner.exe';

/** The read-only owner/ACL helper's reviewed C source basename (under this directory). */
export const OWNER_HELPER_SOURCE_BASENAME = 'agentbridge-win-owner.c';

/** The generated owner-helper provenance module's basename under dist/control/native/. */
export const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

/** The descriptor-creator's filename (its basename under dist/…/native). */
export const DESCRIPTOR_CREATOR_BASENAME = 'agentbridge-win-descriptor-create.exe';

/** The descriptor-creator's reviewed C source basename (under this directory). */
export const DESCRIPTOR_CREATOR_SOURCE_BASENAME = 'agentbridge-win-descriptor-create.c';

/** The generated creator provenance module's basename under dist/control/native/. */
export const CREATOR_PROVENANCE_BASENAME = 'descriptor-creator-provenance.js';

/** The canonical (runtime-consumed) SHA-256 digest shape: lowercase 64-hex. */
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The one provenance-module shape, parameterized by the exported binding name, the
 * artifact filename, its prose label, the artifact's digest, and the digest of the
 * reviewed C source it was compiled from. Every generated provenance module in the
 * tree is exactly this text; there is no second template.
 *
 * `sourceId` is part of the canonical bytes, so the accepted identity is the PAIR
 * (binary, reviewed source). An older binary carries an older `sourceId` and can
 * never equal the current encoding, which is what forces provisioning to rebuild a
 * canonical-but-stale pair instead of skipping it.
 *
 * @param {string} binding
 * @param {string} filename
 * @param {string} label
 * @param {string} sha256Hex
 * @param {string} sourceId
 * @returns {string}
 */
function encodeModule(binding, filename, label, sha256Hex, sourceId) {
  if (typeof sha256Hex !== 'string' || !SHA256_PATTERN.test(sha256Hex)) {
    throw new TypeError('encodeProvenance: sha256 must be a lowercase 64-hex string.');
  }
  if (typeof sourceId !== 'string' || !SHA256_PATTERN.test(sourceId)) {
    throw new TypeError('encodeProvenance: sourceId must be a lowercase 64-hex string.');
  }
  return (
    '// GENERATED BUILD METADATA — do not edit.\n' +
    '// Produced by tools/control-owner/build.mjs from the exact compiled binary.\n' +
    `// This is the runtime trust root for ${label} (SHA-256 of the binary).\n` +
    '// sourceId is the SHA-256 of the reviewed C source that binary was built from.\n' +
    `export const ${binding} = {\n` +
    `  filename: ${JSON.stringify(filename)},\n` +
    `  sha256: ${JSON.stringify(sha256Hex)},\n` +
    `  sourceId: ${JSON.stringify(sourceId)},\n` +
    '  built: true,\n' +
    '};\n'
  );
}

/**
 * Encode the canonical provenance ES-module text for the READ-ONLY owner helper whose
 * SHA-256 digest is `sha256Hex` and which was compiled from the reviewed source whose
 * SHA-256 digest is `sourceId` (both lowercase 64-hex). Deterministic and
 * side-effect-free. Throws a TypeError if either digest is not a lowercase 64-hex
 * string, so a malformed identity can never be encoded.
 *
 * @param {string} sha256Hex
 * @param {string} sourceId
 * @returns {string}
 */
export function encodeProvenance(sha256Hex, sourceId) {
  return encodeModule(
    'OWNER_HELPER_PROVENANCE',
    OWNER_HELPER_BASENAME,
    'the owner helper',
    sha256Hex,
    sourceId,
  );
}

/**
 * Encode the canonical provenance ES-module text for the descriptor CREATOR whose
 * SHA-256 digest is `sha256Hex` and whose reviewed source digest is `sourceId`. A
 * separate binding name and a separate filename from {@link encodeProvenance}, so the
 * two artifacts' trust roots can never be confused — and a separate `sourceId`, so
 * each artifact tracks its own reviewed source independently.
 *
 * @param {string} sha256Hex
 * @param {string} sourceId
 * @returns {string}
 */
export function encodeCreatorProvenance(sha256Hex, sourceId) {
  return encodeModule(
    'DESCRIPTOR_CREATOR_PROVENANCE',
    DESCRIPTOR_CREATOR_BASENAME,
    'the descriptor creator',
    sha256Hex,
    sourceId,
  );
}
