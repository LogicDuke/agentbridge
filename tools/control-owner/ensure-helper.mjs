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
 * The explicit control launch must not silently omit the mandatory native artifacts
 * and their generated provenance. There are TWO, each with its own provenance and its
 * own runtime hash gate (Decision 062 Amendment C):
 *
 *   agentbridge-win-owner.exe             READ-ONLY   owner/DACL snapshot probe
 *   agentbridge-win-descriptor-create.exe CREATE-ONLY runtime-descriptor primitive
 *
 * Without a VALID pair the corresponding runtime gate fails closed
 * (HELPER_PROVENANCE_MISSING / HELPER_MISSING / HELPER_HASH_MISMATCH, and the creator's
 * CREATOR_* equivalents) and the control channel is unavailable. The control script
 * runs this orchestrator between the TypeScript build and the Node launch so a
 * clean — or a partially/torn-provisioned — checkout is made coherent before
 * control-anchor verification runs; a provisioning failure is loud and nonzero.
 *
 * The idempotent skip is taken ONLY when EVERY artifact and its provenance form the
 * CANONICAL pair (validateHelperPair / validateCreatorPair in helper-pair.mjs, each
 * against its own encoder AND its own reviewed source): the on-disk provenance bytes
 * must equal that artifact's `encode(sha256(binary bytes), sourceId(source))` exactly. Existence — or fields found
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
 * Same-revision binding IS the adopted invariant. The canonical encoding names both
 * the binary's SHA-256 and `sourceId`, the SHA-256 of the exact reviewed C source the
 * build compiled, so a pair that is internally self-consistent but built from an OLDER
 * reviewed source is not canonical and IS rebuilt. This closes the family in which a
 * stale-but-self-consistent helper survived a rollback or mixed-cache restore, made
 * this gate report success forever, and left the runtime rejecting the helper's output
 * as SNAPSHOT_MALFORMED because the runtime parser had moved on to a newer snapshot
 * protocol. Nothing is read out of the on-disk provenance to decide this: the source
 * digest is recomputed from the repository, so a stale helper never votes on its own
 * currency.
 */

import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CREATOR_PROVENANCE_BASENAME,
  DESCRIPTOR_CREATOR_BASENAME,
  OWNER_HELPER_BASENAME,
  PROVENANCE_BASENAME,
  validateCreatorPair,
  validateHelperPair,
} from './helper-pair.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const buildScript = join(here, 'build.mjs');

const outDir = join(repoRoot, 'dist', 'control', 'native');

/**
 * Every native artifact the control launch requires, each with its OWN canonical
 * pair validator. The launch is provisioned only when ALL pairs are canonical: a
 * missing or torn creator pair fails the runtime's creator hash gate exactly as a
 * missing owner-helper pair fails its own, so neither may be skipped.
 */
const ARTIFACTS = [
  {
    label: 'owner helper',
    exePath: join(outDir, OWNER_HELPER_BASENAME),
    provenancePath: join(outDir, PROVENANCE_BASENAME),
    validate: validateHelperPair,
  },
  {
    label: 'descriptor creator',
    exePath: join(outDir, DESCRIPTOR_CREATOR_BASENAME),
    provenancePath: join(outDir, CREATOR_PROVENANCE_BASENAME),
    validate: validateCreatorPair,
  },
];

/** The first artifact whose on-disk pair is not canonical, or null when all are. */
function firstInvalidPair() {
  for (const artifact of ARTIFACTS) {
    const result = artifact.validate({
      exePath: artifact.exePath,
      provenancePath: artifact.provenancePath,
    });
    if (!result.valid) {
      return { artifact, result };
    }
  }
  return null;
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

  const before = firstInvalidPair();
  if (before === null) {
    // Already provisioned with VALID pairs: do not recompile on every launch. The
    // runtime still hashes each binary against its generated provenance before use.
    note('valid helper/provenance pairs already present; skipping build.');
    process.exit(0);
  }

  note(
    `${before.artifact.label} pair not valid (${before.result.reason}); rebuilding via build.mjs.`,
  );
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

  const after = firstInvalidPair();
  if (after !== null) {
    // Rebuild reported success but a pair is still not valid — never launch into a
    // fail-closed channel; stop loudly so the operator resolves the build.
    process.stderr.write(
      `ensure-helper: build completed but the ${after.artifact.label} pair is still invalid (${after.result.reason}).\n`,
    );
    process.exit(1);
  }
  note('native control artifacts provisioned (valid pairs).');
}

// ENTRY SCRIPT — no exports, no entry guard. This file is only ever executed
// (`npm run control` / `control:provision`), never imported; the reusable validator
// lives in helper-pair.mjs. A guard comparing import.meta.url with the argv[1] file
// URL is alias-sensitive on Windows (Node realpaths the loaded module but argv keeps
// a junction/symlink alias), which made this gate exit 0 silently without provisioning.
// Explicit provisioning must never silently succeed: run unconditionally, exactly
// as build.mjs does.
main();
