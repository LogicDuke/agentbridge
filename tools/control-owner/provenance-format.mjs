/*
 * Canonical native-artifact provenance formats — the single producer of the
 * provenance bytes for Decision 062 / PR #84.
 *
 * This module owns ONE canonical representation per native artifact of the
 * generated provenance ES-module. Both the trusted build (build.mjs) and the
 * launch-time provisioning gate (ensure-helper.mjs, via helper-pair.mjs) use these
 * exact encoders, so there is a single source of truth: the build publishes exactly
 * `encode(sha256(binary), sourceId(source))` and the gate accepts a pair iff the
 * on-disk provenance bytes equal that encoding for the artifact's own binary hash
 * and the CURRENT reviewed source. No second template, no parser.
 *
 * TWO native artifacts exist, with SEPARATE identities and SEPARATE provenance:
 *
 *   agentbridge-win-owner.exe             READ-ONLY   -> OWNER_HELPER_PROVENANCE
 *   agentbridge-win-descriptor-create.exe CREATE-ONLY -> DESCRIPTOR_CREATOR_PROVENANCE
 *
 * Each generated module exports a DISTINCT binding name and names a DISTINCT
 * filename, so a swapped or cross-wired provenance module can never satisfy the
 * other artifact's runtime gate: each consumer looks up its own binding by name and
 * fails closed when it is absent.
 *
 * SOURCE BINDING. Every encoding carries `sourceId`, the SHA-256 of the exact
 * reviewed C source bytes the artifact was compiled from. The lifecycle identity of
 * a pair is therefore (binary bytes, reviewed source bytes), never the binary alone.
 * This is what makes the provisioning invariant hold:
 *
 *     SUPPORTED_PROVISIONING_SUCCESS => NATIVE_ARTIFACT_RUNTIME_COMPATIBLE
 *
 * A binary that is internally self-consistent with its own provenance but was built
 * from an OLDER reviewed source cannot equal the current encoding (which names the
 * current source digest), so provisioning rebuilds it instead of skipping it. The
 * runtime reads only `filename` and `sha256` from a provenance module and ignores
 * every other field, so `sourceId` is lifecycle metadata only: it grants no trust the
 * runtime would otherwise deny.
 *
 * It is pure: no filesystem reads, no environment reads, no time/randomness, no
 * mutable global state, no side effects (`sourceId` is supplied by the caller;
 * helper-pair.mjs owns the one filesystem read). The output is deterministic UTF-8
 * text (LF line endings) with no timestamp or host-specific field, so whole-file
 * byte equality is a stable acceptance predicate.
 */

/** The read-only owner/ACL helper's filename (its basename under dist/.../native). */
export const OWNER_HELPER_BASENAME = 'agentbridge-win-owner.exe';

/** The read-only owner/ACL helper's reviewed C source basename (this directory). */
export const OWNER_HELPER_SOURCE_BASENAME = 'agentbridge-win-owner.c';

/** The generated owner-helper provenance module's basename under dist/control/native/. */
export const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

/** The create-only descriptor creator's filename (its basename under dist/.../native). */
export const DESCRIPTOR_CREATOR_BASENAME = 'agentbridge-win-descriptor-create.exe';

/** The descriptor creator's reviewed C source basename (this directory). */
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
 * side-effect-free. Throws a TypeError if either digest is malformed, so a malformed
 * identity can never be encoded.
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
 * Encode the canonical provenance ES-module text for the CREATE-ONLY descriptor
 * creator: a separate binding name, a separate filename, and its own reviewed-source
 * digest, so the two artifacts' trust roots can never be confused.
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
