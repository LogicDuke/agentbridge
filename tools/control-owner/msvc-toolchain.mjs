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
 * Pure and side-effect-free except for the injected vswhere query (an
 * absolute-path execFileSync, shell:false — no shell). Callers may inject
 * `vcInstallationPath` (or `queryVcInstallation`) to make resolution a total
 * function of the filesystem, which the deterministic fixture tests rely on. This
 * module has NO runtime, control, provisioning, cockpit, or compiler authority: it
 * only computes which toolchain paths the builder will use and whether they exist.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
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

/**
 * TEST-FACING build eligibility: the builder will PROCEED and SUCCEED — it resolves
 * a plan AND every include/lib directory it passes to cl.exe exists. This is the
 * authoritative predicate the regression gate uses to decide run-vs-skip; it never
 * throws (a vswhere/query failure is treated as "not eligible").
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
  return [...resolved.plan.includeDirs, ...resolved.plan.libDirs].every((dir) => existsSync(dir));
}
