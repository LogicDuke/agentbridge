/*
 * Trusted Windows build for the Decision 062 / PR #84 native control artifacts.
 *
 * Reconciles the exact installed MSVC + Windows SDK via vswhere (never PATH), then
 * compiles EACH reviewed C source to a deterministic module-relative runtime
 * location under dist/, computes the SHA-256 of the exact produced binary AND of the
 * exact reviewed source it compiled, and emits both as GENERATED BUILD METADATA — a
 * small JS module consumed by the trusted runtime (which reads only the filename and
 * the binary hash). An expected hash is never a manually committed literal, an
 * env/argv/registry value, nor a mutable .sha256 sidecar.
 *
 * Publishing the source digest (`sourceId`) beside the binary digest is what lets
 * the provisioning gate distinguish "canonical" from "canonical AND built from the
 * current reviewed source": a pair built from an older source no longer satisfies
 * the gate and is rebuilt. The source identity function is the ONE shared with the
 * gate (helper-pair.mjs), so producer and acceptor cannot drift.
 *
 * TWO artifacts are built, with SEPARATE identities and SEPARATE provenance modules.
 * Neither can stand in for the other: each generated module exports its own binding
 * name, and each runtime consumer hashes its own binary against its own provenance
 * before executing it.
 *
 *   agentbridge-win-owner.c             -> agentbridge-win-owner.exe
 *                                          owner-helper-provenance.js
 *                                          (READ-ONLY security-descriptor probe)
 *   agentbridge-win-descriptor-create.c -> agentbridge-win-descriptor-create.exe
 *                                          descriptor-creator-provenance.js
 *                                          (CREATE-ONLY identity-named descriptor)
 *
 * Every artifact is compiled inside the SAME private, per-invocation workspace but in
 * its OWN object directory and to its OWN private executable path, so no mutable
 * compilation state is shared — neither between concurrent builders nor between the
 * two artifacts of one builder. Publication stays atomic and idempotent per artifact.
 *
 * This build script is not part of the runtime trust path; it is a build tool.
 * It uses no shell: every external program is invoked by absolute path with an
 * explicit argv (execFileSync, shell:false).
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CREATOR_PROVENANCE_BASENAME,
  DESCRIPTOR_CREATOR_BASENAME,
  OWNER_HELPER_BASENAME,
  PROVENANCE_BASENAME,
  encodeCreatorProvenance,
  encodeProvenance,
} from './provenance-format.mjs';
// The ONE build-source identity function, shared with the provisioning gate so the
// producer and the acceptor can never derive it with different semantics.
import {
  DESCRIPTOR_CREATOR_SOURCE_PATH,
  OWNER_HELPER_SOURCE_PATH,
  sourceIdFor,
} from './helper-pair.mjs';
import { compileArgsFor, compileEnvFor, resolveBuildToolchain } from './msvc-toolchain.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');

/** Deterministic module-relative runtime output: dist/control/native/. */
const outDir = join(repoRoot, 'dist', 'control', 'native');

/**
 * The complete set of native artifacts this build publishes. Each entry is fully
 * self-describing: reviewed source, published basename, its OWN provenance module
 * basename, and its OWN canonical encoder. Adding an artifact here is the only place
 * the build learns about it.
 */
const ARTIFACTS = [
  {
    key: 'owner',
    label: 'owner helper',
    source: OWNER_HELPER_SOURCE_PATH,
    basename: OWNER_HELPER_BASENAME,
    provenanceBasename: PROVENANCE_BASENAME,
    encode: encodeProvenance,
  },
  {
    key: 'creator',
    label: 'descriptor creator',
    source: DESCRIPTOR_CREATOR_SOURCE_PATH,
    basename: DESCRIPTOR_CREATOR_BASENAME,
    provenanceBasename: CREATOR_PROVENANCE_BASENAME,
    encode: encodeCreatorProvenance,
  },
];

function fail(message) {
  process.stderr.write(`owner-helper build: ${message}\n`);
  process.exit(1);
}

/** Map a toolchain-resolution rejection to the builder's exact failure message. */
function toolchainRejectionMessage(resolution) {
  switch (resolution.reason) {
    case 'vswhere-missing':
      return `vswhere.exe not found at ${resolution.vswhere}`;
    case 'vc-installation-missing':
      return 'no Visual Studio installation with the VC x64 toolset was found.';
    case 'toolset-file-missing':
      return `MSVC toolset version file missing: ${resolution.toolsetFile}`;
    case 'cl-missing':
      return `cl.exe not found: ${resolution.cl}`;
    case 'sdk-roots-missing':
      return `Windows SDK not found under ${resolution.sdkRoot}`;
    case 'sdk-version-missing':
      return 'no usable Windows SDK version (with ucrt headers) found.';
    default:
      return `unusable MSVC/Windows SDK toolchain (${resolution.reason}).`;
  }
}

if (process.platform !== 'win32') {
  fail('the native control artifacts build only on Windows (MSVC + Windows SDK required).');
}

/* ---- 1. Reconcile MSVC + Windows SDK via the shared authoritative resolver ---
 * The detection/selection algorithm — vswhere VC workload, MSVC toolset + cl, the
 * Windows SDK roots, the selected SDK version, and the exact ucrt/um/shared include
 * and ucrt/um x64 lib paths cl.exe consumes — lives in msvc-toolchain.mjs so the
 * build regression gate derives eligibility from the SAME source and cannot drift
 * to weaker semantics. The builder proceeds exactly when a plan resolves, and
 * rejects with the same messages otherwise. */

const resolved = resolveBuildToolchain();
if (!resolved.ok) {
  fail(toolchainRejectionMessage(resolved));
}
const { cl, toolset, sdkVersion } = resolved.plan;

process.stderr.write(
  `owner-helper build: MSVC ${toolset}, Windows SDK ${sdkVersion}\n` +
    `owner-helper build: cl=${cl}\n`,
);

/* ---- 2. Compile + link inside a private, per-invocation workspace -------- */

// Isolate ALL mutable compilation state so concurrent builders never share an
// object directory or an executable output path. mkdtempSync yields a
// collision-safe unique directory (not a predictable PID-only name); nothing
// under it is ever authoritative — the runtime and the launch gate read only the
// final published paths under outDir. This closes the concurrent-rebuild race:
// two builders compile into disjoint private workspaces and cannot delete,
// replace, or lock each other's compiler intermediates or output. Within one
// builder, each artifact additionally gets its own object directory and its own
// private executable path, so the two compilations never share state either.
mkdirSync(outDir, { recursive: true });
const workspace = mkdtempSync(join(outDir, '.build-'));

/** Best-effort removal of ONLY this invocation's private workspace. Never fails
 *  the build: a cleanup error must not invalidate a published canonical pair, and
 *  an abandoned `.build-*` directory is never authoritative. */
function cleanupWorkspace() {
  try {
    rmSync(workspace, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}
/** Clean the private workspace, then fail loud/closed. */
function failClean(message) {
  cleanupWorkspace();
  fail(message);
}

// The compiler environment and the compile/link argument shape are the SHARED
// ones from msvc-toolchain.mjs — the same the eligibility probe uses — so the
// builder and the test gate cannot drift in env, include/lib paths, or flags.
const clEnv = compileEnvFor(resolved.plan);

/** SHA-256 (lowercase hex) of a file, or null if it cannot be read. */
function sha256File(path) {
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Compile one reviewed source in its own private object directory, publish the exact
 * binary atomically, then publish its OWN provenance derived from the FINAL published
 * bytes and the exact reviewed source. Returns the published digest. Any failure
 * cleans the workspace and exits.
 */
function buildArtifact(artifact) {
  const srcC = artifact.source;
  // Bind the published pair to the EXACT reviewed source being compiled. The gate
  // recomputes this from the same file, so a pair built from an older source can
  // never be accepted as canonical later.
  const sourceId = sourceIdFor(srcC);
  if (sourceId === null) {
    failClean(`reviewed ${artifact.label} source is missing or unreadable: ${srcC}`);
  }
  const workObjDir = join(workspace, `obj-${artifact.key}`);
  const workExe = join(workspace, artifact.basename);
  const publishedExe = join(outDir, artifact.basename);
  const publishedProvenance = join(outDir, artifact.provenanceBasename);
  mkdirSync(workObjDir, { recursive: true });

  const clArgs = compileArgsFor({ source: srcC, exe: workExe, objDir: workObjDir });
  try {
    execFileSync(cl, clArgs, {
      cwd: workObjDir,
      env: clEnv,
      stdio: ['ignore', 'inherit', 'inherit'],
    });
  } catch {
    failClean(`cl.exe failed to build the ${artifact.label}.`);
  }
  if (!existsSync(workExe)) {
    failClean(`cl.exe reported success but the ${artifact.label} binary is missing.`);
  }

  // Validate the private binary and compute its digest before publication.
  const privateBytes = readFileSync(workExe);
  const privateSha = createHash('sha256').update(privateBytes).digest('hex');

  /* ---- Idempotent atomic publication ------------------------------------- */

  // Publish the completed private binary to the authoritative path. Because the
  // build is deterministic (/Brepro), concurrent builders produce byte-identical
  // binaries; a builder that finds the final binary already equal to its own
  // validated bytes treats publication as satisfied and neither clobbers nor fails.
  if (sha256File(publishedExe) !== privateSha) {
    try {
      renameSync(workExe, publishedExe);
    } catch {
      // A concurrent builder may have published first; converge only if the final
      // binary is byte-identical to our validated private build. A differing final
      // binary is never silently accepted.
      if (sha256File(publishedExe) !== privateSha) {
        failClean(
          `failed to publish ${artifact.label} (rename) and final binary is not the built one.`,
        );
      }
    }
  }

  // Derive provenance from the FINAL authoritative bytes (not the private
  // pre-publication assumption), so the canonical pair holds under any concurrent
  // publication interleaving.
  const finalSha = sha256File(publishedExe);
  if (finalSha === null) {
    failClean(`authoritative ${artifact.label} missing after publication.`);
  }
  const provenance = artifact.encode(finalSha, sourceId);

  // Publish provenance atomically: write the complete canonical bytes to a temp file
  // inside this private workspace (same volume as the final path), then rename/replace
  // onto the final path. Node's renameSync uses MoveFileExW(REPLACE_EXISTING) on
  // Windows, atomic within the volume. A concurrent builder writing the identical
  // canonical bytes is benign: convergence, not failure.
  const tmpProvenance = join(workspace, `${artifact.provenanceBasename}.tmp`);
  writeFileSync(tmpProvenance, provenance, { encoding: 'utf8' });
  try {
    renameSync(tmpProvenance, publishedProvenance);
  } catch {
    try {
      rmSync(tmpProvenance, { force: true });
    } catch {
      /* best-effort */
    }
    let current = null;
    try {
      current = readFileSync(publishedProvenance, 'utf8');
    } catch {
      current = null;
    }
    if (current !== provenance) {
      failClean(
        `failed to publish ${artifact.label} provenance (rename) and it is not canonical.`,
      );
    }
  }

  // Post-build canonicality: re-read the AUTHORITATIVE pair and require it valid.
  // "Our private build succeeded" is never sufficient — the final state governs.
  const checkSha = sha256File(publishedExe);
  let checkProvenance = null;
  try {
    checkProvenance = readFileSync(publishedProvenance, 'utf8');
  } catch {
    checkProvenance = null;
  }
  if (checkSha === null || checkProvenance !== artifact.encode(checkSha, sourceId)) {
    failClean(`post-build authoritative ${artifact.label} pair is not canonical.`);
  }

  return { finalSha, size: privateBytes.length, publishedExe, publishedProvenance };
}

const summary = ARTIFACTS.map((artifact) => ({ artifact, result: buildArtifact(artifact) }));

cleanupWorkspace();

for (const { artifact, result } of summary) {
  process.stderr.write(
    `owner-helper build: wrote ${result.publishedExe} (${String(result.size)} bytes)\n` +
      `owner-helper build: ${artifact.label} sha256 ${result.finalSha}\n` +
      `owner-helper build: wrote ${result.publishedProvenance}\n`,
  );
}
