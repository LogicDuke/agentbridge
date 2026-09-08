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

import { encodeProvenance } from './provenance-format.mjs';

// Re-export the canonical producers so tests import everything from one module.
export { OWNER_HELPER_BASENAME, PROVENANCE_BASENAME, encodeProvenance } from './provenance-format.mjs';

/**
 * Decide, for LIFECYCLE purposes only, whether the helper/provenance pair on disk
 * is the canonical pair — enough to choose skip vs rebuild.
 *
 * Mechanism: helper bytes → SHA-256 → the single canonical encoder → the exact
 * expected complete provenance bytes. The pair is VALID iff the on-disk provenance
 * bytes equal `encodeProvenance(sha256(helper bytes))`, byte-for-byte. There is no
 * other positive path: no field extraction, no regex acceptance, no JS import/parse,
 * and no normalization of whitespace, line endings, casing, comments, property
 * order, or duplicate fields. Any representation not emitted verbatim by the encoder
 * — missing/partial/truncated/malformed/duplicated/augmented/re-formatted/torn — is
 * INVALID and rebuilds. This never binds to the C source revision.
 *
 * Returns `{ valid: boolean, reason: string }`.
 */
export function validateHelperPair({ exePath: exe, provenancePath: prov }) {
  if (!existsSync(prov)) {
    return { valid: false, reason: 'provenance-missing' };
  }
  if (!existsSync(exe)) {
    return { valid: false, reason: 'helper-missing' };
  }
  let bytes;
  try {
    bytes = readFileSync(exe);
  } catch {
    return { valid: false, reason: 'helper-unreadable' };
  }
  const expected = encodeProvenance(createHash('sha256').update(bytes).digest('hex'));
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
