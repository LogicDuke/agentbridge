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

/* ---- 2. Compile + link to the deterministic runtime location ------------ */

mkdirSync(outDir, { recursive: true });
const objDir = join(outDir, 'obj');
rmSync(objDir, { recursive: true, force: true });
mkdirSync(objDir, { recursive: true });
rmSync(exePath, { force: true });

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
  `/Fe:${exePath}`,
  `/Fo:${objDir}\\`,
  '/link',
  '/Brepro',
  '/SUBSYSTEM:CONSOLE',
  'advapi32.lib',
];

try {
  execFileSync(cl, clArgs, {
    cwd: objDir,
    env: clEnv,
    stdio: ['ignore', 'inherit', 'inherit'],
  });
} catch {
  fail('cl.exe failed to build the owner helper.');
}

if (!existsSync(exePath)) {
  fail('cl.exe reported success but the helper binary is missing.');
}

// Remove build intermediates so only the trusted binary remains under native/.
rmSync(objDir, { recursive: true, force: true });

/* ---- 3. Generate the provenance metadata (trusted built JS artifact) ---- */

const bytes = readFileSync(exePath);
const sha256 = createHash('sha256').update(bytes).digest('hex');

// One canonical representation, produced by the shared encoder. The launch-time
// provisioning gate accepts a pair iff the on-disk provenance equals exactly this.
const provenance = encodeProvenance(sha256);

// Publish atomically: write the complete canonical bytes to a same-directory temp
// file, then rename/replace onto the final path. On Windows Node's renameSync uses
// MoveFileExW(REPLACE_EXISTING), atomic within the volume; same directory ⇒ same
// volume. This shrinks the window in which a truncated provenance is observable. It
// is defense-in-depth only: canonical byte-equality (gate) is the correctness
// mechanism, and it does NOT make helper+provenance jointly transactional. A reader
// never treats the temp file as authoritative — only provenancePath is consumed.
const tmpProvenance = `${provenancePath}.tmp-${String(process.pid)}`;
writeFileSync(tmpProvenance, provenance, { encoding: 'utf8' });
try {
  renameSync(tmpProvenance, provenancePath);
} catch {
  rmSync(tmpProvenance, { force: true });
  fail('failed to publish provenance atomically (rename).');
}

process.stderr.write(
  `owner-helper build: wrote ${exePath} (${String(bytes.length)} bytes)\n` +
    `owner-helper build: sha256 ${sha256}\n` +
    `owner-helper build: wrote ${provenancePath}\n`,
);
