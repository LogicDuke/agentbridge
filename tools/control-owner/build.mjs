/*
 * Trusted Windows build for the Decision 062 / PR #84 F1 owner-SID helper.
 *
 * Reconciles the exact installed MSVC + Windows SDK via vswhere (never PATH),
 * compiles tools/control-owner/agentbridge-win-owner.c to a deterministic
 * module-relative runtime location under dist/, then computes the SHA-256 of the
 * exact produced binary and emits it as GENERATED BUILD METADATA — a small JS
 * module consumed by the trusted runtime. The expected hash is never a manually
 * committed literal, an env/argv/registry value, nor a mutable .sha256 sidecar.
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
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  OWNER_HELPER_BASENAME,
  PROVENANCE_BASENAME,
  encodeProvenance,
} from './provenance-format.mjs';

const HELPER_BASENAME = OWNER_HELPER_BASENAME;

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..');
const srcC = join(here, 'agentbridge-win-owner.c');

/** Deterministic module-relative runtime output: dist/control/native/. */
const outDir = join(repoRoot, 'dist', 'control', 'native');
const exePath = join(outDir, HELPER_BASENAME);
const provenancePath = join(outDir, PROVENANCE_BASENAME);

function fail(message) {
  process.stderr.write(`owner-helper build: ${message}\n`);
  process.exit(1);
}

if (process.platform !== 'win32') {
  fail('the owner helper builds only on Windows (MSVC + Windows SDK required).');
}

/* ---- 1. Reconcile MSVC + Windows SDK via vswhere (not PATH) ------------- */

const programFilesX86 = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
const vswhere = join(programFilesX86, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
if (!existsSync(vswhere)) {
  fail(`vswhere.exe not found at ${vswhere}`);
}

function vswhereProp(prop) {
  return execFileSync(
    vswhere,
    [
      '-latest',
      '-products',
      '*',
      '-requires',
      'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
      '-property',
      prop,
    ],
    { encoding: 'utf8' },
  ).trim();
}

const vsRoot = vswhereProp('installationPath');
if (vsRoot.length === 0 || !existsSync(vsRoot)) {
  fail('no Visual Studio installation with the VC x64 toolset was found.');
}

const toolsetFile = join(vsRoot, 'VC', 'Auxiliary', 'Build', 'Microsoft.VCToolsVersion.default.txt');
if (!existsSync(toolsetFile)) {
  fail(`MSVC toolset version file missing: ${toolsetFile}`);
}
const toolset = readFileSync(toolsetFile, 'utf8').trim();
const msvcRoot = join(vsRoot, 'VC', 'Tools', 'MSVC', toolset);
const hostBin = join(msvcRoot, 'bin', 'Hostx64', 'x64');
const cl = join(hostBin, 'cl.exe');
if (!existsSync(cl)) {
  fail(`cl.exe not found: ${cl}`);
}

const sdkRoot = join(programFilesX86, 'Windows Kits', '10');
const sdkIncludeRoot = join(sdkRoot, 'Include');
const sdkLibRoot = join(sdkRoot, 'Lib');
if (!existsSync(sdkIncludeRoot) || !existsSync(sdkLibRoot)) {
  fail(`Windows SDK not found under ${sdkRoot}`);
}
// Highest installed SDK version directory that provides ucrt headers.
const sdkVersions = readdirSync(sdkIncludeRoot)
  .filter((name) => /^10\.\d+\.\d+\.\d+$/.test(name))
  .filter((name) => existsSync(join(sdkIncludeRoot, name, 'ucrt')))
  .sort();
const sdkVersion = sdkVersions[sdkVersions.length - 1];
if (sdkVersion === undefined) {
  fail('no usable Windows SDK version (with ucrt headers) found.');
}

const includeDirs = [
  join(msvcRoot, 'include'),
  join(sdkIncludeRoot, sdkVersion, 'ucrt'),
  join(sdkIncludeRoot, sdkVersion, 'um'),
  join(sdkIncludeRoot, sdkVersion, 'shared'),
];
const libDirs = [
  join(msvcRoot, 'lib', 'x64'),
  join(sdkLibRoot, sdkVersion, 'ucrt', 'x64'),
  join(sdkLibRoot, sdkVersion, 'um', 'x64'),
];

process.stderr.write(
  `owner-helper build: MSVC ${toolset}, Windows SDK ${sdkVersion}\n` +
    `owner-helper build: cl=${cl}\n`,
);

/* ---- 2. Compile + link inside a private, per-invocation workspace -------- */

// Isolate ALL mutable compilation state so concurrent builders never share an
// object directory or the executable output path. mkdtempSync yields a
// collision-safe unique directory (not a predictable PID-only name); nothing
// under it is ever authoritative — the runtime and the launch gate read only the
// final paths (exePath / provenancePath). This closes the concurrent-rebuild
// race: two builders compile into disjoint private workspaces and cannot delete,
// replace, or lock each other's compiler intermediates or output.
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

const workObjDir = join(workspace, 'obj');
const workExe = join(workspace, HELPER_BASENAME);
mkdirSync(workObjDir, { recursive: true });

const clEnv = {
  SystemRoot: process.env['SystemRoot'] ?? 'C:\\Windows',
  windir: process.env['windir'] ?? 'C:\\Windows',
  PATH: `${hostBin};${process.env['SystemRoot'] ?? 'C:\\Windows'}\\System32`,
  INCLUDE: includeDirs.join(';'),
  LIB: libDirs.join(';'),
};

const clArgs = [
  '/nologo',
  '/W3',
  '/O2',
  '/GS',
  '/utf-8',
  '/std:c17',
  '/DUNICODE',
  '/D_UNICODE',
  '/Brepro',
  srcC,
  `/Fe:${workExe}`,
  `/Fo:${workObjDir}\\`,
  '/link',
  '/Brepro',
  '/SUBSYSTEM:CONSOLE',
  'advapi32.lib',
];

try {
  execFileSync(cl, clArgs, {
    cwd: workObjDir,
    env: clEnv,
    stdio: ['ignore', 'inherit', 'inherit'],
  });
} catch {
  failClean('cl.exe failed to build the owner helper.');
}

if (!existsSync(workExe)) {
  failClean('cl.exe reported success but the helper binary is missing.');
}

// Validate the private helper and compute its digest before publication.
const privateBytes = readFileSync(workExe);
const privateSha = createHash('sha256').update(privateBytes).digest('hex');

/* ---- 3. Idempotent atomic publication ------------------------------------ */

/** SHA-256 (lowercase hex) of a file, or null if it cannot be read. */
function sha256File(path) {
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch {
    return null;
  }
}

// Publish the completed private helper to the authoritative path. Because the
// build is deterministic (/Brepro), concurrent builders produce byte-identical
// helpers; a builder that finds the final helper already equal to its own
// validated bytes treats publication as satisfied and neither clobbers nor fails.
if (sha256File(exePath) !== privateSha) {
  try {
    renameSync(workExe, exePath);
  } catch {
    // A concurrent builder may have published first; converge only if the final
    // helper is byte-identical to our validated private build. A differing final
    // helper is never silently accepted.
    if (sha256File(exePath) !== privateSha) {
      failClean('failed to publish helper (rename) and final helper is not the built binary.');
    }
  }
}

// Derive provenance from the FINAL authoritative helper bytes (not the private
// pre-publication assumption), so the canonical pair holds under any concurrent
// publication interleaving.
const finalSha = sha256File(exePath);
if (finalSha === null) {
  failClean('authoritative helper missing after publication.');
}
const provenance = encodeProvenance(finalSha);

// Publish provenance atomically: write the complete canonical bytes to a temp file
// inside this private workspace (same volume as the final path), then rename/replace
// onto the final path. Node's renameSync uses MoveFileExW(REPLACE_EXISTING) on
// Windows, atomic within the volume. A concurrent builder writing the identical
// canonical bytes is benign: convergence, not failure.
const tmpProvenance = join(workspace, `${PROVENANCE_BASENAME}.tmp`);
writeFileSync(tmpProvenance, provenance, { encoding: 'utf8' });
try {
  renameSync(tmpProvenance, provenancePath);
} catch {
  try {
    rmSync(tmpProvenance, { force: true });
  } catch {
    /* best-effort */
  }
  let current = null;
  try {
    current = readFileSync(provenancePath, 'utf8');
  } catch {
    current = null;
  }
  if (current !== provenance) {
    failClean('failed to publish provenance (rename) and final provenance is not canonical.');
  }
}

// Post-build canonicality: re-read the AUTHORITATIVE pair and require it valid.
// "Our private build succeeded" is never sufficient — the final state governs.
const checkSha = sha256File(exePath);
let checkProvenance = null;
try {
  checkProvenance = readFileSync(provenancePath, 'utf8');
} catch {
  checkProvenance = null;
}
if (checkSha === null || checkProvenance !== encodeProvenance(checkSha)) {
  failClean('post-build authoritative helper/provenance pair is not canonical.');
}

cleanupWorkspace();

process.stderr.write(
  `owner-helper build: wrote ${exePath} (${String(privateBytes.length)} bytes)\n` +
    `owner-helper build: sha256 ${finalSha}\n` +
    `owner-helper build: wrote ${provenancePath}\n`,
);
