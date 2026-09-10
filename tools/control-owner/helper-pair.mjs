/*
 * Canonical helper/provenance PAIR validity — the single importable decision used
 * by the provisioning gate (ensure-helper.mjs) and its regression tests.
 *
 * This is a plain module with NO entry-point behavior: importing it runs nothing
 * and provisions nothing. It exists so the gate script can execute its main body
 * unconditionally (no alias-sensitive `import.meta.url === argv[1]` entry guard,
 * which silently skipped provisioning when invoked through a junction/symlink)
 * while tests still import the REAL validator and canonical encoder from one seam.
 *
 * Not runtime authority: the runtime's own provenance-shape + hash-before-exec
 * verification (src/control/control-store.ts) is unchanged and remains the
 * security gate. This only decides skip-vs-rebuild for the lifecycle.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DESCRIPTOR_CREATOR_SOURCE_BASENAME,
  OWNER_HELPER_SOURCE_BASENAME,
  encodeCreatorProvenance,
  encodeProvenance,
} from './provenance-format.mjs';

// Re-export the canonical producers so tests import everything from one module.
export {
  CREATOR_PROVENANCE_BASENAME,
  DESCRIPTOR_CREATOR_BASENAME,
  DESCRIPTOR_CREATOR_SOURCE_BASENAME,
  OWNER_HELPER_BASENAME,
  OWNER_HELPER_SOURCE_BASENAME,
  PROVENANCE_BASENAME,
  encodeCreatorProvenance,
  encodeProvenance,
} from './provenance-format.mjs';

const here = dirname(fileURLToPath(import.meta.url));

/** The reviewed C source each native artifact is compiled from, resolved
 *  module-relative so the builder, the provisioning gate, and the tests all name the
 *  SAME file. This is the one artifact→source mapping. */
export const OWNER_HELPER_SOURCE_PATH = join(here, OWNER_HELPER_SOURCE_BASENAME);
export const DESCRIPTOR_CREATOR_SOURCE_PATH = join(here, DESCRIPTOR_CREATOR_SOURCE_BASENAME);

/**
 * The canonical build-source identity: the SHA-256 (lowercase hex) of the exact
 * reviewed C source bytes, or `null` when the source cannot be read.
 *
 * Whole-file bytes, never a scan: nothing is parsed out of the source, no version
 * literal is extracted, and no regex is applied. Two builds share an identity iff
 * they compiled byte-identical source.
 */
export function sourceIdFor(sourcePath) {
  try {
    return createHash('sha256').update(readFileSync(sourcePath)).digest('hex');
  } catch {
    return null;
  }
}

/** The current owner-helper build-source identity, or `null` if unreadable. */
export function ownerHelperSourceId() {
  return sourceIdFor(OWNER_HELPER_SOURCE_PATH);
}

/** The current descriptor-creator build-source identity, or `null` if unreadable. */
export function descriptorCreatorSourceId() {
  return sourceIdFor(DESCRIPTOR_CREATOR_SOURCE_PATH);
}

/**
 * Decide, for LIFECYCLE purposes only, whether the helper/provenance pair on disk
 * is the canonical pair — enough to choose skip vs rebuild.
 *
 * Mechanism: helper bytes → SHA-256, current reviewed source bytes → SHA-256, both
 * through the single canonical encoder → the exact expected complete provenance
 * bytes. The pair is VALID iff the on-disk provenance bytes equal
 * `encodeProvenance(sha256(helper bytes), sourceId(current source))`, byte-for-byte.
 * There is no other positive path: no field extraction, no regex acceptance, no JS
 * import/parse, and no normalization of whitespace, line endings, casing, comments,
 * property order, or duplicate fields. Any representation not emitted verbatim by the
 * encoder — missing/partial/truncated/malformed/duplicated/augmented/re-formatted/torn
 * — is INVALID and rebuilds.
 *
 * The source digest is read fresh from the repository on every call, and nothing is
 * ever read OUT of the on-disk provenance: a stale helper's own self-consistent
 * provenance is never consulted for its version and can never vote for itself. A pair
 * built from an older reviewed source therefore rebuilds instead of being skipped,
 * which is what makes lifecycle validity imply compatibility with the runtime's
 * current snapshot protocol.
 *
 * Returns `{ valid: boolean, reason: string }`.
 */
export function validateHelperPair({ exePath, provenancePath }) {
  return validateArtifactPair({
    exePath,
    provenancePath,
    encode: encodeProvenance,
    sourceId: ownerHelperSourceId(),
  });
}

/**
 * The same canonical-pair decision for the DESCRIPTOR CREATOR, against its OWN
 * encoder. The creator and the owner helper are separate artifacts with separate
 * provenance; a pair is valid only against its own canonical encoding, so a
 * cross-wired or swapped provenance module is never accepted.
 *
 * Returns `{ valid: boolean, reason: string }`.
 */
export function validateCreatorPair({ exePath, provenancePath }) {
  return validateArtifactPair({
    exePath,
    provenancePath,
    encode: encodeCreatorProvenance,
    sourceId: descriptorCreatorSourceId(),
  });
}

/**
 * The one pair-validity mechanism, parameterized by the artifact's canonical encoder
 * and its current build-source identity. Both artifacts decide skip-vs-rebuild through
 * exactly this function.
 *
 * An unreadable reviewed source is NOT valid: without the current source identity the
 * gate cannot prove compatibility, and a rebuild (which needs that same source) is the
 * correct loud outcome rather than a silent skip.
 */
function validateArtifactPair({ exePath: exe, provenancePath: prov, encode, sourceId }) {
  if (!existsSync(prov)) {
    return { valid: false, reason: 'provenance-missing' };
  }
  if (!existsSync(exe)) {
    return { valid: false, reason: 'helper-missing' };
  }
  if (sourceId === null) {
    return { valid: false, reason: 'source-unreadable' };
  }
  let bytes;
  try {
    bytes = readFileSync(exe);
  } catch {
    return { valid: false, reason: 'helper-unreadable' };
  }
  const expected = encode(createHash('sha256').update(bytes).digest('hex'), sourceId);
  let actual;
  try {
    actual = readFileSync(prov, 'utf8');
  } catch {
    return { valid: false, reason: 'provenance-unreadable' };
  }
  if (actual !== expected) {
    return { valid: false, reason: 'not-canonical' };
  }
  return { valid: true, reason: 'valid' };
}
