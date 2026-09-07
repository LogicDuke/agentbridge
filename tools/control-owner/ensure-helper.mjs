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
 * The idempotent skip is taken ONLY when the helper and provenance form a VALID
 * pair (see validateHelperPair). Existence alone is NOT sufficient: an interrupted
 * `build.mjs` can leave a new executable beside stale provenance (a torn pair),
 * which the runtime would reject with HELPER_HASH_MISMATCH. Any invalid state
 * (missing, partial, malformed provenance, wrong filename, bad hash shape, or hash
 * mismatch) triggers a rebuild through the existing trusted builder, after which
 * the pair is validated again; if it is still invalid the launch fails loud/closed.
 *
 * This is a BUILD-TIME / provisioning tool, not part of the runtime trust path and
 * not runtime process authority: it only decides skip-vs-rebuild and invokes the
 * already-trusted `build.mjs`, which alone compiles the reviewed C source and emits
 * the provenance from the exact helper bytes. It uses no shell — the one external
 * program (the same Node) is invoked by absolute path with an explicit argv
 * (execFileSync, shell:false). Provenance is parsed as text (never executed) so a
 * malformed module cannot run code here and no ESM module cache can mask a rebuild.
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

const HELPER_BASENAME = 'agentbridge-win-owner.exe';
const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

/** Lifecycle mirror of the runtime's accepted SHA-256 shape (lowercase 64-hex). */
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const buildScript = join(here, 'build.mjs');

const outDir = join(repoRoot, 'dist', 'control', 'native');
const exePath = join(outDir, HELPER_BASENAME);
const provenancePath = join(outDir, PROVENANCE_BASENAME);

/**
 * Decide, for LIFECYCLE purposes only, whether the helper/provenance pair on disk
 * is a valid pair the runtime would accept — enough to choose skip vs rebuild.
 *
 * Returns `{ valid: boolean, reason: string }`. It mirrors (does not re-own) the
 * runtime's acceptance criteria: provenance present + readable + of the generated
 * shape, `filename` equal to the expected helper basename, `sha256` a lowercase
 * 64-hex digest, the helper present + readable, and `sha256(helper bytes)` exactly
 * equal to the recorded digest. Provenance is read as text and never executed.
 */
export function validateHelperPair({ exePath: exe, provenancePath: prov, expectedFilename }) {
  if (!existsSync(prov)) {
    return { valid: false, reason: 'provenance-missing' };
  }
  if (!existsSync(exe)) {
    return { valid: false, reason: 'helper-missing' };
  }
  let text;
  try {
    text = readFileSync(prov, 'utf8');
  } catch {
    return { valid: false, reason: 'provenance-unreadable' };
  }
  if (!/OWNER_HELPER_PROVENANCE/.test(text)) {
    return { valid: false, reason: 'provenance-shape' };
  }
  const filenameMatch = /filename\s*:\s*["']([^"']*)["']/.exec(text);
  const sha256Match = /sha256\s*:\s*["']([^"']*)["']/.exec(text);
  if (filenameMatch === null || sha256Match === null) {
    return { valid: false, reason: 'provenance-fields-missing' };
  }
  if (filenameMatch[1] !== expectedFilename) {
    return { valid: false, reason: 'provenance-wrong-filename' };
  }
  const recorded = sha256Match[1];
  if (!SHA256_PATTERN.test(recorded)) {
    return { valid: false, reason: 'provenance-bad-hash-shape' };
  }
  let bytes;
  try {
    bytes = readFileSync(exe);
  } catch {
    return { valid: false, reason: 'helper-unreadable' };
  }
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== recorded) {
    return { valid: false, reason: 'hash-mismatch' };
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

  const before = validateHelperPair({ exePath, provenancePath, expectedFilename: HELPER_BASENAME });
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

  const after = validateHelperPair({ exePath, provenancePath, expectedFilename: HELPER_BASENAME });
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
