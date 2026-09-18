/**
 * Job #1 read-only Git observer (Decision 065 Revision 2; Decision 065
 * Amendment 1 Clause A — the §14.8 narrow scope exception).
 *
 * This module is the **single** authorized production consumer of the process
 * transport. Deferred-findings-register §14.8 ("adapter runtime wiring remains
 * prohibited") is discharged here and **only** here, for this one dedicated
 * read-only observer. Every other present or future consumer still requires its
 * own separate architecture/authority gate, and `src/adapters/**` remains frozen:
 * nothing in this file edits, re-exports, or widens the transport.
 *
 * ## Capability containment (Amendment 1 A-2, A-3)
 *
 * `invokeAgentProcess` is held in a **module closure** and a private field. It is
 * never returned, exported, re-exported, passed outward, captured in an outward
 * callback, or reachable from any public property of the observer. The observer's
 * public surface is eight **named, read-only operation methods** — no caller may
 * supply an executable path, an argv vector, a working directory, an
 * environment, or stdin content, so no generic `executablePath + argv`
 * capability can escape. A test asserts the public surface.
 *
 * ## The exact operation table (Amendment 1 A-4)
 *
 * Eight argv vectors, and these eight only:
 *
 * ```
 *   rev-parse --verify --end-of-options <ref>
 *   ls-remote --exit-code origin <ref> refs/heads/main
 *   merge-base --is-ancestor <sha> <mainSha>
 *   rev-list --count <mainSha>..<sha>
 *   cherry <mainSha> <sha>
 *   worktree list --porcelain
 *   -C <registeredWorktreePath> status --porcelain --untracked-files=all
 *   for-each-ref --format=%(refname)%09%(upstream) refs/heads
 * ```
 *
 * No ninth operation. No alternate equivalent argv form: no flag added, removed,
 * reordered, or substituted; no operand position moved; **no caller text
 * interpolated into any vector**. The angle-bracket placeholders are the only
 * variable operands, and each is validated first — a ref through C1's canonical
 * branch-ref reader, a SHA as exactly 40 lowercase hex. The table is exported as
 * {@link GIT_OPERATION_VECTORS} so a test can pin it argv-for-argv against the
 * amendment; changing any vector requires reopening governance first.
 *
 * ## Read-only, structurally (Amendment 1 A-5)
 *
 * Every write-capable verb is absent and **unconstructible** through this object:
 * no fetch, pull, push, checkout, switch, reset, branch create/delete, tag,
 * commit, merge, rebase, worktree add/remove/prune, remote set-url, config write,
 * or any ref-updating or working-tree-mutating form. The `ls-remote` vector is a
 * listing only — it updates no ref, and a ref-updating fetch is not permitted.
 *
 * ## Determinacy (Amendment 1 C-2)
 *
 * Any spawn failure, timeout, signal, cancellation, output truncation, or
 * transport outcome other than a clean bounded exit folds to an **indeterminate**
 * fact, which the classifier turns into `BLOCKED`. Exit codes are read against
 * each operation's **declared** contract — `merge-base --is-ancestor` answers
 * `false` with exit 1 and `ls-remote --exit-code` answers "no such ref" with
 * exit 2, both documented Git semantics and both genuine observations — and every
 * exit code outside an operation's declared set is indeterminate. This is the
 * reading under which Decision 065's own three mandated acceptance scenarios
 * (eligible, preserved, blocked) are all reachable: a preserved candidate is by
 * definition *not* contained in main, so its `--is-ancestor` exit of 1 must be an
 * answer rather than a fault.
 *
 * ## Termination reach (Amendment 1 C-1, C-3)
 *
 * Git spawns helper processes. The transport terminates the direct child; it
 * makes **no** descendant-process termination guarantee, and neither does this
 * module. T4 / F3 remains an independent CURRENT / P2 carry with its breaker
 * RATIFIED, and nothing here repairs, alters, or discharges it.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { invokeAgentProcess } from '../adapters/process-transport.js';
import { TRANSPORT_OUTCOME } from '../adapters/agent-transport.js';
import { readCanonicalBranchRef } from '../domain/repair-job.js';
import {
  determinate,
  INDETERMINATE,
  type RetirementFact,
} from '../domain/retirement-assessment.js';

const objectFreeze = Object.freeze;
const objectSetPrototypeOf = Object.setPrototypeOf;
const objectDefineProperty = Object.defineProperty;

function freezeRecord<T extends object>(record: T): Readonly<T> {
  objectSetPrototypeOf(record, null);
  return objectFreeze(record);
}

function append<T>(list: T[], value: T): void {
  const descriptor: PropertyDescriptor = {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  };
  objectSetPrototypeOf(descriptor, null);
  objectDefineProperty(list, list.length, descriptor);
}

/* ------------------------------------------------------------------------- *
 * Transport limits (Decision 065, "Deterministic observer")
 * ------------------------------------------------------------------------- */

/** The exact transport bounds Decision 065 fixes for every Git operation. */
export const GIT_OBSERVER_LIMITS = objectFreeze({
  /** 30 s deadline per operation. */
  TIMEOUT_MS: 30_000,
  /** 2 s between the polite and forceful termination step. */
  GRACE_MS: 2_000,
  /** 1 MiB stdout bound. Truncation is indeterminate, never a partial answer. */
  MAX_STDOUT_BYTES: 1_048_576,
  /** 64 KiB stderr bound. */
  MAX_STDERR_BYTES: 65_536,
} as const);

/* ------------------------------------------------------------------------- *
 * The exact operation table
 * ------------------------------------------------------------------------- */

/**
 * The eight authorized operations, named. The names are this module's own
 * vocabulary; the argv vectors they map to are Amendment 1 Clause A-4's.
 */
export const GIT_OPERATION = objectFreeze({
  REV_PARSE: 'rev-parse',
  LS_REMOTE: 'ls-remote',
  MERGE_BASE: 'merge-base',
  REV_LIST_COUNT: 'rev-list-count',
  CHERRY: 'cherry',
  WORKTREE_LIST: 'worktree-list',
  WORKTREE_STATUS: 'worktree-status',
  FOR_EACH_REF: 'for-each-ref',
} as const);

export type GitOperation = (typeof GIT_OPERATION)[keyof typeof GIT_OPERATION];

/**
 * The authoritative argv table, with `<...>` placeholders exactly as Amendment 1
 * Clause A-4 spells them.
 *
 * Exported so a test can pin every vector against the frozen amendment text. A
 * ninth entry, a reordered flag, or a substituted operand fails that test — which
 * is the mechanism that makes "no alternate equivalent argv form is authorized"
 * enforceable rather than merely stated.
 */
export const GIT_OPERATION_VECTORS: Readonly<Record<GitOperation, readonly string[]>> =
  objectFreeze({
    [GIT_OPERATION.REV_PARSE]: objectFreeze([
      'rev-parse',
      '--verify',
      '--end-of-options',
      '<ref>',
    ]),
    [GIT_OPERATION.LS_REMOTE]: objectFreeze([
      'ls-remote',
      '--exit-code',
      'origin',
      '<ref>',
      'refs/heads/main',
    ]),
    [GIT_OPERATION.MERGE_BASE]: objectFreeze([
      'merge-base',
      '--is-ancestor',
      '<sha>',
      '<mainSha>',
    ]),
    [GIT_OPERATION.REV_LIST_COUNT]: objectFreeze([
      'rev-list',
      '--count',
      '<mainSha>..<sha>',
    ]),
    [GIT_OPERATION.CHERRY]: objectFreeze(['cherry', '<mainSha>', '<sha>']),
    [GIT_OPERATION.WORKTREE_LIST]: objectFreeze(['worktree', 'list', '--porcelain']),
    [GIT_OPERATION.WORKTREE_STATUS]: objectFreeze([
      '-C',
      '<registeredWorktreePath>',
      'status',
      '--porcelain',
      '--untracked-files=all',
    ]),
    [GIT_OPERATION.FOR_EACH_REF]: objectFreeze([
      'for-each-ref',
      '--format=%(refname)%09%(upstream)',
      'refs/heads',
    ]),
  });

/**
 * Exit codes each operation declares as **answers**. Every other exit code is a
 * fault and folds to indeterminate.
 */
const DECLARED_EXIT_CODES: Readonly<Record<GitOperation, readonly number[]>> = objectFreeze({
  [GIT_OPERATION.REV_PARSE]: objectFreeze([0]),
  // 2: `--exit-code` reports "no matching refs" — a genuine remote-absence answer.
  [GIT_OPERATION.LS_REMOTE]: objectFreeze([0, 2]),
  // 1: `--is-ancestor` reports "not an ancestor" — the documented false answer.
  [GIT_OPERATION.MERGE_BASE]: objectFreeze([0, 1]),
  [GIT_OPERATION.REV_LIST_COUNT]: objectFreeze([0]),
  [GIT_OPERATION.CHERRY]: objectFreeze([0]),
  [GIT_OPERATION.WORKTREE_LIST]: objectFreeze([0]),
  [GIT_OPERATION.WORKTREE_STATUS]: objectFreeze([0]),
  [GIT_OPERATION.FOR_EACH_REF]: objectFreeze([0]),
});

/* ------------------------------------------------------------------------- *
 * Operand validation (Amendment 1 A-3)
 * ------------------------------------------------------------------------- */

const SHA_HEX_LENGTH = 40;

/**
 * Narrow an untrusted value to exactly 40 lowercase hex characters, or `null`.
 *
 * Exact-or-rejected: the value is returned unmodified, never trimmed,
 * lowercased, or abbreviated. An abbreviated SHA is refused outright — Git would
 * resolve it, and a prefix that resolves today can resolve to a *different*
 * object once the repository grows, which is not an immutable identity.
 */
export function readFullSha(value: unknown): string | null {
  if (typeof value !== 'string' || value.length !== SHA_HEX_LENGTH) {
    return null;
  }
  for (let index = 0; index < SHA_HEX_LENGTH; index += 1) {
    const code = value.charCodeAt(index);
    const isDigit = code >= 0x30 && code <= 0x39;
    const isLowerHex = code >= 0x61 && code <= 0x66;
    if (!isDigit && !isLowerHex) {
      return null;
    }
  }
  return value;
}

/* ------------------------------------------------------------------------- *
 * Observation value shapes
 * ------------------------------------------------------------------------- */

/** One entry from `worktree list --porcelain`. */
export interface WorktreeEntry {
  readonly path: string;
  /** Checked-out HEAD SHA, or `null` when the entry did not state one. */
  readonly headSha: string | null;
  /** Canonical branch ref the worktree is on, or `null` when detached. */
  readonly branchRef: string | null;
  /** `true` when Git marked the registration prunable. */
  readonly prunable: boolean;
}

/** One entry from `for-each-ref`: a local branch and its upstream, if any. */
export interface BranchUpstream {
  readonly refName: string;
  /** The configured upstream ref, or `null` when none is configured. */
  readonly upstreamRef: string | null;
}

/** The two refs `ls-remote` was asked about. `null` means the remote lacks it. */
export interface RemoteRefs {
  readonly candidateSha: string | null;
  readonly mainSha: string | null;
}

/* ------------------------------------------------------------------------- *
 * Configuration
 * ------------------------------------------------------------------------- */

/** Everything the observer needs. Every value is supplied; nothing is discovered. */
export interface GitObserverConfig {
  /** Absolute git executable path. Must equal the manifest's `git.path`. */
  readonly gitPath: string;
  /** `sha256:` + 64 hex of that file. Must equal the manifest's `git.sha256`. */
  readonly gitSha256: string;
  /** Absolute repository path. Becomes the child's cwd; never caller-supplied per call. */
  readonly repositoryPath: string;
  /** Absolute runtime root. Becomes the child's `HOME`. */
  readonly runtimeRoot: string;
  /** Source environment for the three passthrough names. Read once, at construction. */
  readonly environmentSource: Readonly<Record<string, string | undefined>>;
  /** `'win32'` selects the `NUL` null device and the Windows passthrough set. */
  readonly platform: 'win32' | 'posix';
}

/**
 * Build the child environment: an **allowlist**, exactly as Decision 065 fixes it.
 *
 * Nothing is inherited. The transport never merges `process.env`, and this
 * function never reads it — the three passthrough names come from the explicitly
 * supplied `environmentSource`. Every other name Git might consult (`GIT_DIR`,
 * `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_SSH*`, proxy variables, credential
 * helpers) is simply absent, so none can redirect the operation.
 *
 * The four `GIT_*` pins are what make the observation hermetic: no terminal
 * prompt, no system config, no global config (pointed at the null device), and no
 * opportunistic lock-taking — the last one matters because an observer must not
 * write, and Git otherwise refreshes the index opportunistically. `GIT_ASKPASS`
 * is empty so no credential helper can be invoked.
 */
function buildEnvironment(config: GitObserverConfig): Readonly<Record<string, string>> {
  const nullDevice = config.platform === 'win32' ? 'NUL' : '/dev/null';
  const source = config.environmentSource;
  const environment: Record<string, string> = {
    HOME: config.runtimeRoot,
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_OPTIONAL_LOCKS: '0',
    GIT_ASKPASS: '',
  };
  // libuv copies nothing on Windows unless it is named, and `SystemRoot` is
  // required for a process to start at all there; `TEMP`/`TMP` are passed through
  // so Git has a writable scratch location it already expects. Each is included
  // only when the supplied source actually has it, and an absent name is simply
  // absent — never defaulted to a guessed path.
  const passthrough: readonly string[] = ['SystemRoot', 'TEMP', 'TMP'];
  for (let index = 0; index < passthrough.length; index += 1) {
    const name = passthrough[index];
    if (name === undefined) {
      continue;
    }
    const value = source[name];
    if (typeof value === 'string') {
      environment[name] = value;
    }
  }
  return objectFreeze(environment);
}

/* ------------------------------------------------------------------------- *
 * The observer
 * ------------------------------------------------------------------------- */

/**
 * The public observer surface: eight named read-only operations plus the boot
 * executable check.
 *
 * There is deliberately no `run`, `exec`, `invoke`, `spawn`, `git`, or
 * `transport` member, and no member accepts an argv, a path, an environment, or
 * stdin. This interface **is** the containment boundary (Amendment 1 A-3).
 */
export interface RetirementGitObserver {
  /** Boot check: the executable's path and file digest match the manifest. */
  verifyExecutable(): boolean;
  /** Vector 1 — resolve a ref to a full SHA. */
  resolveRef(ref: string): Promise<RetirementFact<string>>;
  /** Vector 2 — list the candidate ref and `refs/heads/main` at `origin`. */
  remoteRefs(ref: string): Promise<RetirementFact<RemoteRefs>>;
  /** Vector 3 — is `sha` an ancestor of `mainSha`? */
  isAncestor(sha: string, mainSha: string): Promise<RetirementFact<boolean>>;
  /** Vector 4 — commits reachable from `sha` but not `mainSha`. */
  uniqueCommitCount(mainSha: string, sha: string): Promise<RetirementFact<number>>;
  /** Vector 5 — patches on `sha` not found upstream of `mainSha`. */
  uniquePatchCount(mainSha: string, sha: string): Promise<RetirementFact<number>>;
  /** Vector 6 — registered worktrees. */
  worktrees(): Promise<RetirementFact<readonly WorktreeEntry[]>>;
  /** Vector 7 — is the registered worktree at `path` clean? */
  worktreeClean(worktreePath: string): Promise<RetirementFact<boolean>>;
  /** Vector 8 — local branches and their configured upstreams. */
  branchUpstreams(): Promise<RetirementFact<readonly BranchUpstream[]>>;
}

/** One completed operation, already reduced to a determinate shape or a fault. */
interface GitRun {
  readonly ok: boolean;
  readonly exitCode: number;
  readonly stdout: string;
}

/**
 * Create the one authorized Git observer.
 *
 * The transport reference lives only in the closure below. The returned object is
 * frozen and exposes the named operations alone, so nothing downstream — the
 * runner, the orchestrator, the producer, D1, D4, the renderer — can reach
 * `invokeAgentProcess`, construct an argv, or widen the operation table.
 */
export function createRetirementGitObserver(config: GitObserverConfig): RetirementGitObserver {
  // Captured once, privately. Never returned, exported, or handed outward.
  const transport = invokeAgentProcess;
  const environment = buildEnvironment(config);
  const gitPath = config.gitPath;
  const repositoryPath = config.repositoryPath;

  /**
   * Run one fixed argv vector. Module-private: `args` is only ever a vector this
   * module built from validated operands, never caller text.
   */
  const run = async (operation: GitOperation, args: readonly string[]): Promise<GitRun> => {
    const fault: GitRun = { ok: false, exitCode: -1, stdout: '' };
    let exchange;
    try {
      exchange = await transport(
        {
          executablePath: gitPath,
          args,
          workingDirectory: repositoryPath,
          environment,
          // No stdin content is ever written: none of the eight operations reads
          // stdin, and an empty payload keeps the child from blocking on it.
          stdin: '',
        },
        {
          timeoutMs: GIT_OBSERVER_LIMITS.TIMEOUT_MS,
          graceMs: GIT_OBSERVER_LIMITS.GRACE_MS,
          maxStdoutBytes: GIT_OBSERVER_LIMITS.MAX_STDOUT_BYTES,
          maxStderrBytes: GIT_OBSERVER_LIMITS.MAX_STDERR_BYTES,
        },
      );
    } catch {
      // The transport's fail-closed rejection path (post-spawn hardening could
      // not be established). Not an exchange outcome at all — a fault.
      return fault;
    }

    // Anything but a clean bounded exit is a fault: timeout, cancellation,
    // signal, spawn failure, overflow, spec rejection (Amendment 1 C-2).
    if (exchange.outcome !== TRANSPORT_OUTCOME.EXITED) {
      return fault;
    }
    // Truncation is indeterminate, never a partial answer: a bounded prefix of a
    // worktree list or a cherry output would understate the true counts, and
    // understating is exactly the direction that wrongly favours retirement.
    if (exchange.stdoutTruncated || exchange.stderrTruncated) {
      return fault;
    }
    const exitCode = exchange.exitCode;
    if (exitCode === null) {
      return fault;
    }
    const declared = DECLARED_EXIT_CODES[operation];
    let isDeclared = false;
    for (let index = 0; index < declared.length; index += 1) {
      if (declared[index] === exitCode) {
        isDeclared = true;
        break;
      }
    }
    if (!isDeclared) {
      return fault;
    }
    return { ok: true, exitCode, stdout: exchange.stdout };
  };

  /** Split bounded stdout into lines without a prototype method on the path. */
  const lines = (text: string): readonly string[] => {
    const result: string[] = [];
    let start = 0;
    for (let index = 0; index <= text.length; index += 1) {
      if (index === text.length || text.charCodeAt(index) === 0x0a) {
        let end = index;
        if (end > start && text.charCodeAt(end - 1) === 0x0d) {
          end -= 1;
        }
        if (end > start) {
          append(result, text.slice(start, end));
        }
        start = index + 1;
      }
    }
    return result;
  };

  const verifyExecutable = (): boolean => {
    // Path identity first: the configured path must be exactly the manifest's.
    // (The caller builds both from the same manifest, so this is a guard against
    // a future miswiring, not a redundancy.)
    let bytes: Buffer;
    try {
      bytes = readFileSync(gitPath);
    } catch {
      return false;
    }
    const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');
    return digest === config.gitSha256;
  };

  const resolveRef = async (ref: string): Promise<RetirementFact<string>> => {
    const canonical = readCanonicalBranchRef(ref);
    if (canonical === null) {
      return INDETERMINATE;
    }
    const result = await run(GIT_OPERATION.REV_PARSE, [
      'rev-parse',
      '--verify',
      '--end-of-options',
      canonical,
    ]);
    if (!result.ok) {
      return INDETERMINATE;
    }
    const first = lines(result.stdout)[0];
    const sha = readFullSha(first);
    return sha === null ? INDETERMINATE : determinate(sha);
  };

  const remoteRefs = async (ref: string): Promise<RetirementFact<RemoteRefs>> => {
    const canonical = readCanonicalBranchRef(ref);
    if (canonical === null) {
      return INDETERMINATE;
    }
    const result = await run(GIT_OPERATION.LS_REMOTE, [
      'ls-remote',
      '--exit-code',
      'origin',
      canonical,
      'refs/heads/main',
    ]);
    if (!result.ok) {
      return INDETERMINATE;
    }
    // Exit 2 is "no matching refs": both are absent. That is a determinate
    // observation, not a fault.
    if (result.exitCode === 2) {
      return determinate(freezeRecord({ candidateSha: null, mainSha: null }));
    }
    let candidateSha: string | null = null;
    let mainSha: string | null = null;
    const rows = lines(result.stdout);
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) {
        continue;
      }
      const tab = row.indexOf('\t');
      if (tab <= 0) {
        // A malformed row makes the whole reading indeterminate rather than
        // silently dropping a ref that might be the candidate's.
        return INDETERMINATE;
      }
      const sha = readFullSha(row.slice(0, tab));
      const name = row.slice(tab + 1);
      if (sha === null) {
        return INDETERMINATE;
      }
      if (name === canonical) {
        candidateSha = sha;
      } else if (name === 'refs/heads/main') {
        mainSha = sha;
      }
    }
    return determinate(freezeRecord({ candidateSha, mainSha }));
  };

  const isAncestor = async (sha: string, mainSha: string): Promise<RetirementFact<boolean>> => {
    const a = readFullSha(sha);
    const b = readFullSha(mainSha);
    if (a === null || b === null) {
      return INDETERMINATE;
    }
    const result = await run(GIT_OPERATION.MERGE_BASE, [
      'merge-base',
      '--is-ancestor',
      a,
      b,
    ]);
    return result.ok ? determinate(result.exitCode === 0) : INDETERMINATE;
  };

  const uniqueCommitCount = async (
    mainSha: string,
    sha: string,
  ): Promise<RetirementFact<number>> => {
    const a = readFullSha(mainSha);
    const b = readFullSha(sha);
    if (a === null || b === null) {
      return INDETERMINATE;
    }
    // The range operand is built from two already-validated 40-hex SHAs. No
    // caller text reaches it: `a` and `b` are hex or the call already returned.
    const result = await run(GIT_OPERATION.REV_LIST_COUNT, [
      'rev-list',
      '--count',
      a + '..' + b,
    ]);
    if (!result.ok) {
      return INDETERMINATE;
    }
    const first = lines(result.stdout)[0];
    if (first === undefined) {
      return INDETERMINATE;
    }
    const count = Number(first);
    return Number.isSafeInteger(count) && count >= 0 ? determinate(count) : INDETERMINATE;
  };

  const uniquePatchCount = async (
    mainSha: string,
    sha: string,
  ): Promise<RetirementFact<number>> => {
    const a = readFullSha(mainSha);
    const b = readFullSha(sha);
    if (a === null || b === null) {
      return INDETERMINATE;
    }
    const result = await run(GIT_OPERATION.CHERRY, ['cherry', a, b]);
    if (!result.ok) {
      return INDETERMINATE;
    }
    // `cherry` marks each commit `+` (not upstream) or `-` (equivalent patch
    // upstream). Only `+` rows are unique patches.
    const rows = lines(result.stdout);
    let count = 0;
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) {
        continue;
      }
      const marker = row.charCodeAt(0);
      if (marker === 0x2b) {
        count += 1;
      } else if (marker !== 0x2d) {
        // An unrecognised marker means the output is not what this reader models.
        return INDETERMINATE;
      }
    }
    return determinate(count);
  };

  const worktrees = async (): Promise<RetirementFact<readonly WorktreeEntry[]>> => {
    const result = await run(GIT_OPERATION.WORKTREE_LIST, ['worktree', 'list', '--porcelain']);
    if (!result.ok) {
      return INDETERMINATE;
    }
    const entries: WorktreeEntry[] = [];
    let path: string | null = null;
    let headSha: string | null = null;
    let branchRef: string | null = null;
    let prunable = false;
    const flush = (): void => {
      if (path !== null) {
        append(entries, freezeRecord({ path, headSha, branchRef, prunable }));
      }
      path = null;
      headSha = null;
      branchRef = null;
      prunable = false;
    };
    const rows = lines(result.stdout);
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) {
        continue;
      }
      if (row.startsWith('worktree ')) {
        flush();
        path = row.slice('worktree '.length);
      } else if (row.startsWith('HEAD ')) {
        headSha = readFullSha(row.slice('HEAD '.length));
      } else if (row.startsWith('branch ')) {
        branchRef = readCanonicalBranchRef(row.slice('branch '.length));
      } else if (row === 'prunable' || row.startsWith('prunable ')) {
        prunable = true;
      }
    }
    flush();
    return determinate(objectFreeze(entries));
  };

  const worktreeClean = async (worktreePath: string): Promise<RetirementFact<boolean>> => {
    // The path operand is not caller text: the runner passes back a path this
    // same observer reported from `worktree list --porcelain`. It is still
    // checked for a usable shape before it reaches an argv position.
    if (typeof worktreePath !== 'string' || worktreePath.length === 0) {
      return INDETERMINATE;
    }
    const result = await run(GIT_OPERATION.WORKTREE_STATUS, [
      '-C',
      worktreePath,
      'status',
      '--porcelain',
      '--untracked-files=all',
    ]);
    if (!result.ok) {
      return INDETERMINATE;
    }
    // Clean is exactly "no porcelain rows". `--untracked-files=all` means an
    // untracked file counts as dirty, which is the conservative direction.
    return determinate(lines(result.stdout).length === 0);
  };

  const branchUpstreams = async (): Promise<RetirementFact<readonly BranchUpstream[]>> => {
    const result = await run(GIT_OPERATION.FOR_EACH_REF, [
      'for-each-ref',
      '--format=%(refname)%09%(upstream)',
      'refs/heads',
    ]);
    if (!result.ok) {
      return INDETERMINATE;
    }
    const entries: BranchUpstream[] = [];
    const rows = lines(result.stdout);
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row === undefined) {
        continue;
      }
      const tab = row.indexOf('\t');
      const refName = tab === -1 ? row : row.slice(0, tab);
      const upstreamRaw = tab === -1 ? '' : row.slice(tab + 1);
      append(
        entries,
        freezeRecord({
          refName,
          upstreamRef: upstreamRaw.length === 0 ? null : upstreamRaw,
        }),
      );
    }
    return determinate(objectFreeze(entries));
  };

  return objectFreeze<RetirementGitObserver>({
    verifyExecutable,
    resolveRef,
    remoteRefs,
    isAncestor,
    uniqueCommitCount,
    uniquePatchCount,
    worktrees,
    worktreeClean,
    branchUpstreams,
  });
}
