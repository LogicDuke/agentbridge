/*
 * Authoritative MSVC + Windows SDK toolchain resolution for the Decision 062 /
 * PR #84 owner-SID helper build.
 *
 * SINGLE SOURCE OF TRUTH. Both the trusted builder (build.mjs) and its regression
 * gate (tests/control/launch-lifecycle.test.ts) decide build eligibility ONLY
 * through this module, so a test can never independently claim "the builder can
 * proceed / will succeed" using weaker semantics than the builder actually uses.
 * The recurring MSVC-gate drift — vswhere existence → VC workload → SDK roots →
 * the exact per-version ucrt/um/shared include and ucrt/um lib paths cl.exe
 * consumes — is eliminated as a CLASS: there is one detection + selection
 * algorithm, imported by both. Adding another builder prerequisite here updates
 * the builder and the gate at once; neither can drift from the other.
 *
 * It also owns the ONE compiler environment (`compileEnvFor`) and the ONE
 * compile/link argument shape (`compileArgsFor`) the builder hands cl.exe, and the
 * eligibility PROBE (`probeBuildToolchain`): a minimal translation unit exercising
 * exactly the owner helper's dependency surface (windows.h/aclapi.h/sddl.h/fcntl.h/
 * io.h/stdio.h/string.h/wchar.h + advapi32.lib) is compiled AND linked through the
 * exact resolved cl.exe, environment, include/lib paths and flags, inside a private
 * temp workspace. `isBuildEligible` therefore means "this toolchain can actually
 * build the helper", not "some directories exist" — missing link.exe, compiler
 * DLLs, headers inside an existing include dir, or advapi32.lib inside an existing
 * lib dir all make the probe fail and the gate skip, so that class is closed.
 *
 * Side effects are limited to the vswhere query and the probe compile (both
 * absolute-path execFileSync, shell:false — no shell; the probe never touches
 * dist/, publishes nothing and provisions nothing). Callers may inject
 * `vcInstallationPath` (or `queryVcInstallation`) and `runCompiler` to make
 * resolution and eligibility deterministic, which the fixture tests rely on. This
 * module has NO runtime, control, provisioning, cockpit, or compiler authority: it
 * only computes which toolchain the builder will use and whether it can build.
 */

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** The exact VC workload component the builder requires from vswhere. */
export const VC_TOOLS_COMPONENT = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64';

/** Absolute path to vswhere.exe for a given ProgramFiles(x86) root. */
export function vswherePathFor(programFilesX86) {
  return join(programFilesX86, 'Microsoft Visual Studio', 'Installer', 'vswhere.exe');
}

/**
 * installationPath of the newest Visual Studio providing the VC x64 toolset, via
 * the exact vswhere binary + query the builder uses. Impure (runs vswhere by
 * absolute path, shell:false). Returns the trimmed installationPath (possibly '').
 */
export function queryVcInstallationPath(programFilesX86) {
  return execFileSync(
    vswherePathFor(programFilesX86),
    ['-latest', '-products', '*', '-requires', VC_TOOLS_COMPONENT, '-property', 'installationPath'],
    { encoding: 'utf8' },
  ).trim();
}

/**
 * The exact Windows SDK version the builder selects: the highest (sort()[last])
 * `10.x.x.x` version directory under `sdkIncludeRoot` that provides ucrt headers.
 * Returns the version string or undefined. This IS the builder's selection rule —
 * lexicographic-sort quirks included — so the gate never picks a different one.
 */
export function selectSdkVersion(sdkIncludeRoot) {
  const versions = readdirSync(sdkIncludeRoot)
    .filter((name) => /^10\.\d+\.\d+\.\d+$/.test(name))
    .filter((name) => existsSync(join(sdkIncludeRoot, name, 'ucrt')))
    .sort();
  return versions[versions.length - 1];
}

/**
 * Resolve the EXACT build plan the trusted builder uses, or the first precondition
 * that makes the builder reject before compilation. build.mjs consumes the returned
 * plan verbatim (identical cl / INCLUDE / LIB), so any eligibility derived from this
 * result cannot drift from what the builder actually does.
 *
 * options:
 *   programFilesX86     — root (default: env ProgramFiles(x86) or the standard path)
 *   vcInstallationPath  — inject the VC installationPath (skips vswhere; '' or null
 *                         models "no VC installation")
 *   queryVcInstallation — inject a vswhere runner (programFilesX86 → installationPath)
 *
 * Returns { ok: true, plan } | { ok: false, reason, ...context }.
 */
export function resolveBuildToolchain(options = {}) {
  const programFilesX86 =
    options.programFilesX86 ?? process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)';
  const vswhere = vswherePathFor(programFilesX86);

  // 1. Visual Studio installation with the VC x64 toolset (vswhere, or injected).
  let vsRoot;
  if ('vcInstallationPath' in options) {
    vsRoot = options.vcInstallationPath ?? '';
  } else if (!existsSync(vswhere)) {
    return { ok: false, reason: 'vswhere-missing', vswhere };
  } else {
    const runner = options.queryVcInstallation ?? queryVcInstallationPath;
    vsRoot = runner(programFilesX86);
  }
  if (vsRoot.length === 0 || !existsSync(vsRoot)) {
    return { ok: false, reason: 'vc-installation-missing' };
  }

  // 2. MSVC toolset + the x64 host/target cl.exe.
  const toolsetFile = join(
    vsRoot,
    'VC',
    'Auxiliary',
    'Build',
    'Microsoft.VCToolsVersion.default.txt',
  );
  if (!existsSync(toolsetFile)) {
    return { ok: false, reason: 'toolset-file-missing', toolsetFile };
  }
  const toolset = readFileSync(toolsetFile, 'utf8').trim();
  const msvcRoot = join(vsRoot, 'VC', 'Tools', 'MSVC', toolset);
  const hostBin = join(msvcRoot, 'bin', 'Hostx64', 'x64');
  const cl = join(hostBin, 'cl.exe');
  if (!existsSync(cl)) {
    return { ok: false, reason: 'cl-missing', cl };
  }

  // 3. Windows SDK roots, the selected version, and EVERY include/lib dir the
  //    compile consumes for THAT version (ucrt/um/shared includes; ucrt/um x64 libs).
  const sdkRoot = join(programFilesX86, 'Windows Kits', '10');
  const sdkIncludeRoot = join(sdkRoot, 'Include');
  const sdkLibRoot = join(sdkRoot, 'Lib');
  if (!existsSync(sdkIncludeRoot) || !existsSync(sdkLibRoot)) {
    return { ok: false, reason: 'sdk-roots-missing', sdkRoot };
  }
  const sdkVersion = selectSdkVersion(sdkIncludeRoot);
  if (sdkVersion === undefined) {
    return { ok: false, reason: 'sdk-version-missing' };
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

  return {
    ok: true,
    plan: {
      programFilesX86,
      vswhere,
      vsRoot,
      toolset,
      msvcRoot,
      hostBin,
      cl,
      sdkRoot,
      sdkIncludeRoot,
      sdkLibRoot,
      sdkVersion,
      includeDirs,
      libDirs,
    },
  };
}

/* ---- Shared compiler environment + argument shape (builder AND probe) ------- */

/** The exact cl.exe compile flags the builder uses (before the source file). */
export const CL_COMPILE_FLAGS = Object.freeze([
  '/nologo',
  '/W3',
  '/O2',
  '/GS',
  '/utf-8',
  '/std:c17',
  '/DUNICODE',
  '/D_UNICODE',
  '/Brepro',
]);

/** The exact linker flags + import libraries the builder passes after `/link`. */
export const CL_LINK_FLAGS = Object.freeze(['/Brepro', '/SUBSYSTEM:CONSOLE', 'advapi32.lib']);

/**
 * The ONE controlled environment cl.exe/link.exe run under: host bin + System32 on
 * PATH (never the inherited PATH), and INCLUDE/LIB from the resolved plan. Pure.
 */
export function compileEnvFor(plan, env = process.env) {
  const systemRoot = env['SystemRoot'] ?? 'C:\\Windows';
  return {
    SystemRoot: systemRoot,
    windir: env['windir'] ?? 'C:\\Windows',
    PATH: `${plan.hostBin};${systemRoot}\\System32`,
    INCLUDE: plan.includeDirs.join(';'),
    LIB: plan.libDirs.join(';'),
  };
}

/**
 * The ONE compile+link argv shape: shared flags, the source, private /Fe (exe) and
 * /Fo (object dir, trailing backslash), then `/link` + shared link flags. Pure.
 */
export function compileArgsFor({ source, exe, objDir }) {
  return [...CL_COMPILE_FLAGS, source, `/Fe:${exe}`, `/Fo:${objDir}\\`, '/link', ...CL_LINK_FLAGS];
}

/**
 * Default compiler runner: direct execution of the resolved cl.exe (absolute path,
 * explicit argv, shell:false). Output is captured and discarded; a nonzero exit or
 * spawn failure throws.
 */
export function defaultRunCompiler(cl, args, { cwd, env }) {
  execFileSync(cl, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
}

/* ---- Eligibility probe -------------------------------------------------------- */

/**
 * Minimal translation unit exercising exactly the dependency surface of EVERY native
 * artifact the builder publishes: the same headers (the union of what
 * `agentbridge-win-owner.c` and `agentbridge-win-descriptor-create.c` include) and the
 * same advapi32/kernel32 imports both need — the read-only probe's
 * GetNamedSecurityInfoW/ConvertSidToStringSidW plus the creator's
 * ConvertStringSidToSidW, SetEntriesInAclW, AllocateAndInitializeSid,
 * OpenProcessToken/GetTokenInformation, and SetFileInformationByHandle. A header
 * missing inside an existing include dir, or an import library missing inside an
 * existing lib dir, fails the probe exactly as it would fail the real build, for both
 * artifacts. `wmain` + /SUBSYSTEM:CONSOLE matches their entry/link shape.
 */
export const PROBE_SOURCE =
  '#include <windows.h>\n' +
  '#include <aclapi.h>\n' +
  '#include <sddl.h>\n' +
  '#include <fcntl.h>\n' +
  '#include <io.h>\n' +
  '#include <stdio.h>\n' +
  '#include <string.h>\n' +
  '#include <wchar.h>\n' +
  'int wmain(int argc, wchar_t **argv) {\n' +
  '  PSECURITY_DESCRIPTOR sd = NULL;\n' +
  '  PSID owner = NULL;\n' +
  '  PSID parsed = NULL;\n' +
  '  PSID system = NULL;\n' +
  '  PACL acl = NULL;\n' +
  '  HANDLE token = NULL;\n' +
  '  DWORD needed = 0;\n' +
  '  LPWSTR sid = NULL;\n' +
  '  EXPLICIT_ACCESSW entry;\n' +
  '  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;\n' +
  '  FILE_DISPOSITION_INFO disposition;\n' +
  '  wchar_t buf[8];\n' +
  '  (void)_setmode(_fileno(stdout), _O_BINARY);\n' +
  '  memset(buf, 0, sizeof buf);\n' +
  '  ZeroMemory(&entry, sizeof entry);\n' +
  '  ZeroMemory(&disposition, sizeof disposition);\n' +
  '  if (argc > 1 && wcslen(argv[1]) > 0 &&\n' +
  '      GetNamedSecurityInfoW(argv[1], SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,\n' +
  '                            &owner, NULL, NULL, NULL, &sd) == ERROR_SUCCESS &&\n' +
  '      ConvertSidToStringSidW(owner, &sid)) {\n' +
  '    (void)wprintf(L"%ls\\n", sid);\n' +
  '    LocalFree(sid);\n' +
  '  }\n' +
  '  if (sd != NULL) LocalFree(sd);\n' +
  '  if (argc > 2 && ConvertStringSidToSidW(argv[2], &parsed)) {\n' +
  '    if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0,\n' +
  '                                 0, 0, &system)) {\n' +
  '      entry.grfAccessPermissions = FILE_ALL_ACCESS;\n' +
  '      entry.grfAccessMode = SET_ACCESS;\n' +
  '      entry.grfInheritance = NO_INHERITANCE;\n' +
  '      entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;\n' +
  '      entry.Trustee.ptstrName = (LPWSTR)parsed;\n' +
  '      if (SetEntriesInAclW(1, &entry, NULL, &acl) == ERROR_SUCCESS && acl != NULL) {\n' +
  '        LocalFree(acl);\n' +
  '      }\n' +
  '      FreeSid(system);\n' +
  '    }\n' +
  '    LocalFree(parsed);\n' +
  '  }\n' +
  '  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {\n' +
  '    (void)GetTokenInformation(token, TokenUser, NULL, 0, &needed);\n' +
  '    CloseHandle(token);\n' +
  '  }\n' +
  '  (void)SetFileInformationByHandle(GetStdHandle(STD_OUTPUT_HANDLE),\n' +
  '                                   FileDispositionInfo, &disposition,\n' +
  '                                   sizeof disposition);\n' +
  '  return 0;\n' +
  '}\n';

/**
 * Compile AND link the probe through the exact plan (same cl, env, include/lib
 * paths and flags the builder uses) inside a private mkdtemp workspace under the OS
 * temp dir, then remove it. Never touches dist/, publishes nothing, provisions
 * nothing. Returns { ok: true } | { ok: false, reason }.
 *
 * options: runCompiler (inject the compiler runner; default direct cl.exe),
 *          probeRoot (parent dir for the private workspace; default os.tmpdir()),
 *          env (source of SystemRoot/windir; default process.env).
 */
export function probeBuildToolchain(plan, options = {}) {
  const runCompiler = options.runCompiler ?? defaultRunCompiler;
  let workspace;
  try {
    workspace = mkdtempSync(join(options.probeRoot ?? tmpdir(), 'ab-toolchain-probe-'));
  } catch {
    return { ok: false, reason: 'probe-workspace-unavailable' };
  }
  try {
    const objDir = join(workspace, 'obj');
    const source = join(workspace, 'probe.c');
    const exe = join(workspace, 'probe.exe');
    mkdirSync(objDir, { recursive: true });
    writeFileSync(source, PROBE_SOURCE, { encoding: 'utf8' });
    try {
      runCompiler(plan.cl, compileArgsFor({ source, exe, objDir }), {
        cwd: objDir,
        env: compileEnvFor(plan, options.env ?? process.env),
      });
    } catch {
      return { ok: false, reason: 'probe-compile-failed' };
    }
    if (!existsSync(exe)) {
      return { ok: false, reason: 'probe-output-missing' };
    }
    return { ok: true };
  } finally {
    try {
      rmSync(workspace, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
}

/**
 * TEST-FACING build eligibility — the ONE authoritative run-vs-skip predicate for
 * every real-compilation test: the builder will PROCEED (a plan resolves), every
 * include/lib directory it hands cl.exe exists, AND the exact toolchain actually
 * compiles+links the helper's dependency surface (`probeBuildToolchain`). It never
 * throws (any failure is "not eligible"). Options are those of
 * `resolveBuildToolchain` plus `runCompiler` / `probeRoot`.
 */
export function isBuildEligible(options = {}) {
  let resolved;
  try {
    resolved = resolveBuildToolchain(options);
  } catch {
    return false;
  }
  if (!resolved.ok) {
    return false;
  }
  if (![...resolved.plan.includeDirs, ...resolved.plan.libDirs].every((dir) => existsSync(dir))) {
    return false;
  }
  try {
    return probeBuildToolchain(resolved.plan, options).ok;
  } catch {
    return false;
  }
}
