/*
 * Type declaration for the authoritative MSVC + Windows SDK toolchain resolver,
 * shared compiler env/flags, and eligibility probe, so the strict-TypeScript
 * lifecycle regression can import and exercise the REAL detection/selection/
 * compilation the trusted builder (build.mjs) uses — not a copy. The module itself
 * (msvc-toolchain.mjs) lives under tools/ and is plain Node ESM.
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

/** The exact cl.exe compile flags (before the source) and `/link` flags the builder uses. */
export declare const CL_COMPILE_FLAGS: readonly string[];
export declare const CL_LINK_FLAGS: readonly string[];

/** The one controlled compiler environment derived from a plan (PATH/INCLUDE/LIB). */
export interface CompileEnv {
  readonly SystemRoot: string;
  readonly windir: string;
  readonly PATH: string;
  readonly INCLUDE: string;
  readonly LIB: string;
}
export declare function compileEnvFor(plan: BuildPlan, env?: NodeJS.ProcessEnv): CompileEnv;

/** The one compile+link argv shape (shared flags, source, /Fe, /Fo, /link flags). */
export interface CompileTargets {
  readonly source: string;
  readonly exe: string;
  readonly objDir: string;
}
export declare function compileArgsFor(targets: CompileTargets): string[];

/** Direct cl.exe runner (absolute path, explicit argv, shell:false); throws on failure. */
export type CompilerRunner = (
  cl: string,
  args: readonly string[],
  options: { readonly cwd: string; readonly env: CompileEnv },
) => void;
export declare function defaultRunCompiler(
  cl: string,
  args: readonly string[],
  options: { readonly cwd: string; readonly env: CompileEnv },
): void;

/** The probe translation unit exercising the owner helper's dependency surface. */
export declare const PROBE_SOURCE: string;

/** Options for the eligibility probe (in addition to resolution options). */
export interface ProbeOptions {
  readonly runCompiler?: CompilerRunner;
  readonly probeRoot?: string;
  readonly env?: NodeJS.ProcessEnv;
}

/** Compile+link the probe through the exact plan in a private temp workspace. */
export declare function probeBuildToolchain(
  plan: BuildPlan,
  options?: ProbeOptions,
): { readonly ok: true } | { readonly ok: false; readonly reason: string };

/**
 * The ONE run-vs-skip predicate for real-compilation tests: a plan resolves, every
 * builder path exists, AND the exact toolchain compiles+links the probe.
 */
export declare function isBuildEligible(options?: ResolveOptions & ProbeOptions): boolean;
