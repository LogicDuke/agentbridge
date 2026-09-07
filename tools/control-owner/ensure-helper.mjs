/*
 * Launch-time provisioning gate for the Decision 062 / PR #84 owner-SID helper.
 *
 * The supported Windows production launch scripts (`npm run control`,
 * `npm run cockpit:live`) must not silently omit the mandatory native helper and
 * its generated provenance: without them `defaultLoadProvenance()` returns null
 * and the control channel fails closed with HELPER_PROVENANCE_MISSING. Those
 * scripts run this orchestrator between the TypeScript build and the Node launch
 * so a clean checkout is provisioned before control-anchor verification runs.
 *
 * This is a BUILD-TIME / provisioning tool, not part of the runtime trust path
 * and not runtime process authority: it only decides whether to invoke the
 * already-trusted `build.mjs`, which alone compiles the reviewed C source and
 * emits the provenance from the exact helper bytes. It uses no shell — the one
 * external program (the same Node) is invoked by absolute path with an explicit
 * argv (execFileSync, shell:false).
 *
 * Idempotent: once the helper + provenance exist, launches skip the compile, so
 * steady-state startup is never coupled to the presence of a compiler; only the
 * first clean-checkout provisioning needs MSVC. On non-Windows the helper cannot
 * and need not be built (the control channel is Windows-only and degrades
 * closed), so this skips cleanly and never fails a Linux/macOS launch.
 */

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HELPER_BASENAME = 'agentbridge-win-owner.exe';
const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const buildScript = join(here, 'build.mjs');

const outDir = join(repoRoot, 'dist', 'control', 'native');
const exePath = join(outDir, HELPER_BASENAME);
const provenancePath = join(outDir, PROVENANCE_BASENAME);

function note(message) {
  process.stderr.write(`ensure-helper: ${message}\n`);
}

if (process.platform !== 'win32') {
  // The owner helper builds only on Windows and the control channel is a Windows
  // feature; on other platforms it degrades closed. Skipping keeps cross-platform
  // launches (e.g. the read-only cockpit on Linux/macOS) working without MSVC.
  note(`non-Windows platform (${process.platform}); owner helper not required, skipping.`);
  process.exit(0);
}

if (existsSync(exePath) && existsSync(provenancePath)) {
  // Already provisioned: do not recompile on every launch. The runtime still
  // hashes the binary against the generated provenance before executing it.
  note('owner helper and provenance already present; skipping build.');
  process.exit(0);
}

note('owner helper or provenance missing; building via build.mjs.');
try {
  execFileSync(process.execPath, [buildScript], { stdio: ['ignore', 'inherit', 'inherit'] });
} catch {
  // Fail loud and closed: a supported Windows launch must not proceed into a
  // HELPER_PROVENANCE_MISSING control channel because provisioning silently
  // failed (e.g. MSVC absent). Surface it as an intentional launch prerequisite.
  process.stderr.write(
    'ensure-helper: FAILED to build the owner helper. The D062 control channel ' +
      'requires it. Ensure MSVC + the Windows SDK are installed, then re-run.\n',
  );
  process.exit(1);
}

if (!existsSync(exePath) || !existsSync(provenancePath)) {
  process.stderr.write('ensure-helper: build reported success but artifacts are missing.\n');
  process.exit(1);
}
note('owner helper provisioned.');
