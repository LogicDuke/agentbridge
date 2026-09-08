/*
 * Type declaration for the authoritative MSVC + Windows SDK toolchain resolver, so
 * the strict-TypeScript lifecycle regression can import and exercise the REAL
 * detection/selection the trusted builder (build.mjs) uses — not a copy. The module
 * itself (msvc-toolchain.mjs) lives under tools/ and is plain Node ESM.
 */

/** The exact VC workload component the builder requires from vswhere. */
export declare const VC_TOOLS_COMPONENT: string;

/** Absolute path to vswhere.exe for a given ProgramFiles(x86) root. */
export declare function vswherePathFor(programFilesX86: string): string;

/** installationPath of the newest VS with the VC x64 toolset (runs vswhere). */
export declare function queryVcInstallationPath(programFilesX86: string): string;

/**
 * The exact Windows SDK version the builder selects: highest `10.x.x.x` version
 * directory under the SDK include root that provides ucrt headers, or undefined.
 */
export declare function selectSdkVersion(sdkIncludeRoot: string): string | undefined;

/** The exact toolchain paths the builder passes to cl.exe. */
export interface BuildPlan {
  readonly programFilesX86: string;
  readonly vswhere: string;
  readonly vsRoot: string;
  readonly toolset: string;
  readonly msvcRoot: string;
  readonly hostBin: string;
  readonly cl: string;
  readonly sdkRoot: string;
  readonly sdkIncludeRoot: string;
  readonly sdkLibRoot: string;
  readonly sdkVersion: string;
  readonly includeDirs: readonly string[];
  readonly libDirs: readonly string[];
}

/** Discriminated resolution: the plan the builder uses, or the rejecting reason. */
export type BuildToolchainResolution =
  | { readonly ok: true; readonly plan: BuildPlan }
  | {
      readonly ok: false;
      readonly reason: string;
      readonly vswhere?: string;
      readonly toolsetFile?: string;
      readonly cl?: string;
      readonly sdkRoot?: string;
    };

/** Options for resolution; inject `vcInstallationPath` for pure filesystem tests. */
export interface ResolveOptions {
  readonly programFilesX86?: string;
  readonly vcInstallationPath?: string | null;
  readonly queryVcInstallation?: (programFilesX86: string) => string;
}

/** Resolve the exact build plan, or the first precondition the builder rejects on. */
export declare function resolveBuildToolchain(options?: ResolveOptions): BuildToolchainResolution;

/** The builder will proceed AND succeed: a plan resolves and every path exists. */
export declare function isBuildEligible(options?: ResolveOptions): boolean;
