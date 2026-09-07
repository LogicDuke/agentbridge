/*
 * Launch-time provisioning gate for the Decision 062 / PR #84 owner-SID helper.
 *
 * The supported Windows production launch scripts (`npm run control`,
 * `npm run cockpit:live`) must not silently omit the mandatory native helper and
 * its generated provenance: without a VALID pair `defaultLoadProvenance()` /
 * the runtime hash gate fail closed (HELPER_PROVENANCE_MISSING / HELPER_MISSING /
 * HELPER_HASH_MISMATCH) and the control channel is unavailable. Those scripts run
 * this orchestrator between the TypeScript build and the Node launch so a clean —
 * or a partially/torn-provisioned — checkout is made coherent before control-anchor
 * verification runs.
 *
 * The idempotent skip is taken ONLY when the helper and provenance form the
 * CANONICAL pair (see validateHelperPair): the on-disk provenance bytes must equal
 * `encodeProvenance(sha256(helper bytes))` exactly. Existence — or fields found
 * somewhere in the text — is NOT sufficient: an interrupted `build.mjs` can leave a
 * new executable beside stale provenance (a torn pair), or a truncated/duplicated/
 * augmented provenance module. Any representation not emitted verbatim by the shared
 * encoder triggers a rebuild through the existing trusted builder, after which the
 * pair is validated again; if it is still not canonical the launch fails loud/closed.
 *
 * This is a BUILD-TIME / provisioning tool, not part of the runtime trust path and
 * not runtime process authority: it only decides skip-vs-rebuild and invokes the
 * already-trusted `build.mjs`, which alone compiles the reviewed C source and emits
 * the provenance from the exact helper bytes via the SAME canonical encoder. It uses
 * no shell — the one external program (the same Node) is invoked by absolute path
 * with an explicit argv (execFileSync, shell:false). Provenance is compared as bytes
 * against the encoder output; it is never imported or JS-parsed, so a malformed
 * module cannot run code here and no ESM module cache can mask a rebuild.
 *
 * The runtime's own provenance-shape + hash-before-exec verification is unchanged
 * and remains the security gate; this lifecycle validation is a self-healing
 * convenience that never grants trust the runtime would deny.
 *
 * Scope note: this deliberately does NOT bind the pair to the current C source
 * revision. A binary/provenance pair that is internally valid but built from an
 * older reviewed source is NOT rebuilt — same-revision binding is not the adopted
 * invariant (the runtime trusts binary<->provenance integrity, not source age).
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  OWNER_HELPER_BASENAME,
  PROVENANCE_BASENAME,
  encodeProvenance,
} from './provenance-format.mjs';

// Re-export the canonical producers so the strict-TypeScript lifecycle regression
// imports the REAL encoder + validator from one module (a single declaration seam).
export { OWNER_HELPER_BASENAME, encodeProvenance } from './provenance-format.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const buildScript = join(here, 'build.mjs');

const outDir = join(repoRoot, 'dist', 'control', 'native');
const exePath = join(outDir, OWNER_HELPER_BASENAME);
const provenancePath = join(outDir, PROVENANCE_BASENAME);

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

function note(message) {
  process.stderr.write(`ensure-helper: ${message}\n`);
}

function main() {
  if (process.platform !== 'win32') {
    // The owner helper builds only on Windows and the control channel is a Windows
    // feature; on other platforms it degrades closed. Skipping keeps cross-platform
    // launches (e.g. the read-only cockpit on Linux/macOS) working without MSVC.
    note(`non-Windows platform (${process.platform}); owner helper not required, skipping.`);
    process.exit(0);
  }

  const before = validateHelperPair({ exePath, provenancePath });
  if (before.valid) {
    // Already provisioned with a VALID pair: do not recompile on every launch. The
    // runtime still hashes the binary against the generated provenance before use.
    note('valid helper/provenance pair already present; skipping build.');
    process.exit(0);
  }

  note(`helper/provenance pair not valid (${before.reason}); rebuilding via build.mjs.`);
  try {
    execFileSync(process.execPath, [buildScript], { stdio: ['ignore', 'inherit', 'inherit'] });
  } catch {
    // Fail loud and closed: a supported Windows launch must not proceed into a
    // failed-closed control channel because provisioning silently failed (e.g. MSVC
    // absent). Surface it as an intentional launch prerequisite.
    process.stderr.write(
      'ensure-helper: FAILED to build the owner helper. The D062 control channel ' +
        'requires it. Ensure MSVC + the Windows SDK are installed, then re-run.\n',
    );
    process.exit(1);
  }

  const after = validateHelperPair({ exePath, provenancePath });
  if (!after.valid) {
    // Rebuild reported success but the pair is still not valid — never launch into a
    // fail-closed channel; stop loudly so the operator resolves the build.
    process.stderr.write(
      `ensure-helper: build completed but the helper/provenance pair is still invalid (${after.reason}).\n`,
    );
    process.exit(1);
  }
  note('owner helper provisioned (valid pair).');
}

const entry = process.argv[1];
const isEntry = entry !== undefined && import.meta.url === pathToFileURL(entry).href;
if (isEntry) {
  main();
}
