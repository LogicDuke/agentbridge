/*
 * Explicit provisioning gate for the Decision 062 / PR #84 owner-SID helper.
 *
 * This gate is a prerequisite of the CONTROL-ORIENTED operator flow ONLY
 * (`npm run control`: TypeScript build → this gate → control CLI). It is
 * deliberately NOT wired into `npm run cockpit` or `npm run cockpit:live`:
 * helper provisioning must never be a prerequisite for read-only Cockpit
 * availability (CONTROL_PROVISION_FAILURE ⇏ COCKPIT_FAILURE). The live runtime
 * attempts the control channel only after the Cockpit is serving, and any
 * control fault there fails closed while the Cockpit stays up and read-only.
 *
 * The explicit control launch must not silently omit the mandatory native helper
 * and its generated provenance: without a VALID pair `defaultLoadProvenance()` /
 * the runtime hash gate fail closed (HELPER_PROVENANCE_MISSING / HELPER_MISSING /
 * HELPER_HASH_MISMATCH) and the control channel is unavailable. The control script
 * runs this orchestrator between the TypeScript build and the Node launch so a
 * clean — or a partially/torn-provisioned — checkout is made coherent before
 * control-anchor verification runs; a provisioning failure is loud and nonzero.
 *
 * The idempotent skip is taken ONLY when the helper and provenance form the
 * CANONICAL pair (see validateHelperPair in helper-pair.mjs): the on-disk provenance bytes must equal
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
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { OWNER_HELPER_BASENAME, PROVENANCE_BASENAME, validateHelperPair } from './helper-pair.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const buildScript = join(here, 'build.mjs');

const outDir = join(repoRoot, 'dist', 'control', 'native');
const exePath = join(outDir, OWNER_HELPER_BASENAME);
const provenancePath = join(outDir, PROVENANCE_BASENAME);

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
    // Fail loud and closed: the explicit control launch must not proceed into a
    // failed-closed control channel because provisioning silently failed (e.g. MSVC
    // absent). Surface it as an intentional control-launch prerequisite. The
    // read-only Cockpit launches never run this gate, so this failure cannot
    // take the Cockpit down.
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

// ENTRY SCRIPT — no exports, no entry guard. This file is only ever executed
// (`npm run control` / `control:provision`), never imported; the reusable validator
// lives in helper-pair.mjs. A guard comparing import.meta.url with the argv[1] file
// URL is alias-sensitive on Windows (Node realpaths the loaded module but argv keeps
// a junction/symlink alias), which made this gate exit 0 silently without provisioning.
// Explicit provisioning must never silently succeed: run unconditionally, exactly
// as build.mjs does.
main();
