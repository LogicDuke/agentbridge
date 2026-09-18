import { describe, expect, it, vi, beforeEach } from 'vitest';

/**
 * The fake git: every `invokeAgentProcess` call is recorded and answered from a
 * scripted queue, so the **exact argv** the observer emits is observable without
 * a real git binary. This is the fake-git request proof Decision 065 requires.
 *
 * `vi.mock` is hoisted, so the recorder lives in a hoisted binding.
 */
const gitCalls = vi.hoisted(() => [] as {
  spec: {
    executablePath: string;
    args: readonly string[];
    workingDirectory: string;
    environment: Readonly<Record<string, string>>;
    stdin: string;
  };
  limits: { timeoutMs: number; graceMs: number; maxStdoutBytes: number; maxStderrBytes: number };
}[]);

const scripted = vi.hoisted(() => ({
  queue: [] as {
    outcome: string;
    exitCode: number | null;
    stdout: string;
    stdoutTruncated?: boolean;
    stderrTruncated?: boolean;
  }[],
}));

vi.mock('../../src/adapters/process-transport.js', () => ({
  invokeAgentProcess: (spec: never, limits: never): Promise<unknown> => {
    gitCalls.push({ spec, limits } as never);
    const next = scripted.queue.shift() ?? {
      outcome: 'EXITED',
      exitCode: 0,
      stdout: '',
    };
    return Promise.resolve({
      outcome: next.outcome,
      rejection: null,
      exitCode: next.exitCode,
      terminatingSignal: null,
      stdout: next.stdout,
      stderr: '',
      stdoutTruncated: next.stdoutTruncated ?? false,
      stderrTruncated: next.stderrTruncated ?? false,
      stdoutBytes: 0,
      stderrBytes: 0,
      terminationScope: 'DIRECT_CHILD',
    });
  },
}));

const { createRetirementGitObserver, GIT_OBSERVER_LIMITS, GIT_OPERATION_VECTORS, readFullSha } =
  await import('../../src/runtime/retirement-git-observer.js');

const CANDIDATE_REF = 'refs/heads/repair/example';
const CANDIDATE_SHA = 'a'.repeat(40);
const MAIN_SHA = 'c'.repeat(40);

function observer(): ReturnType<typeof createRetirementGitObserver> {
  return createRetirementGitObserver({
    gitPath: 'C:\\git\\git.exe',
    gitSha256: 'sha256:' + '3'.repeat(64),
    repositoryPath: 'C:\\repo',
    runtimeRoot: 'C:\\runtime',
    environmentSource: { SystemRoot: 'C:\\Windows', TEMP: 'C:\\Temp', PATH: '/should/not/appear' },
    platform: 'win32',
  });
}

function script(...responses: (typeof scripted.queue)[number][]): void {
  scripted.queue.splice(0, scripted.queue.length, ...responses);
}

beforeEach(() => {
  gitCalls.length = 0;
  scripted.queue.length = 0;
});

/* ------------------------------------------------------------------------- *
 * The exact operation table (Amendment 1 Clause A-4)
 * ------------------------------------------------------------------------- */

describe('the exact Git operation table is pinned to Decision 065 Amendment 1 A-4', () => {
  /**
   * The eight vectors, transcribed from the frozen amendment text. If this
   * literal and the module's table ever diverge, this test fails — which is the
   * mechanism that makes "no ninth operation, no alternate argv form" real
   * rather than aspirational.
   */
  const AMENDMENT_A4: readonly (readonly string[])[] = [
    ['rev-parse', '--verify', '--end-of-options', '<ref>'],
    ['ls-remote', '--exit-code', 'origin', '<ref>', 'refs/heads/main'],
    ['merge-base', '--is-ancestor', '<sha>', '<mainSha>'],
    ['rev-list', '--count', '<mainSha>..<sha>'],
    ['cherry', '<mainSha>', '<sha>'],
    ['worktree', 'list', '--porcelain'],
    ['-C', '<registeredWorktreePath>', 'status', '--porcelain', '--untracked-files=all'],
    ['for-each-ref', '--format=%(refname)%09%(upstream)', 'refs/heads'],
  ];

  it('declares exactly eight operations — no ninth', () => {
    expect(Object.keys(GIT_OPERATION_VECTORS)).toHaveLength(8);
  });

  it('matches the amendment argv-for-argv, in order', () => {
    expect(Object.values(GIT_OPERATION_VECTORS).map((vector) => [...vector])).toEqual(
      AMENDMENT_A4.map((vector) => [...vector]),
    );
  });

  it('contains no write-capable verb anywhere in the table', () => {
    const forbidden = [
      'fetch',
      'pull',
      'push',
      'checkout',
      'switch',
      'reset',
      'branch',
      'tag',
      'commit',
      'merge',
      'rebase',
      'add',
      'remove',
      'prune',
      'set-url',
      'config',
      'update-ref',
      'gc',
      'clean',
    ];
    const flat = Object.values(GIT_OPERATION_VECTORS).flat();
    for (const verb of forbidden) {
      expect(flat, `write-capable verb reachable: ${verb}`).not.toContain(verb);
    }
  });

  it('pins the transport limits Decision 065 fixes', () => {
    expect({ ...GIT_OBSERVER_LIMITS }).toEqual({
      TIMEOUT_MS: 30_000,
      GRACE_MS: 2_000,
      MAX_STDOUT_BYTES: 1_048_576,
      MAX_STDERR_BYTES: 65_536,
    });
  });
});

/* ------------------------------------------------------------------------- *
 * Emitted argv, proven against the fake git
 * ------------------------------------------------------------------------- */

describe('emitted argv matches the table exactly', () => {
  it('rev-parse', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: CANDIDATE_SHA + '\n' });
    await observer().resolveRef(CANDIDATE_REF);
    expect(gitCalls[0]?.spec.args).toEqual([
      'rev-parse',
      '--verify',
      '--end-of-options',
      CANDIDATE_REF,
    ]);
  });

  it('ls-remote', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().remoteRefs(CANDIDATE_REF);
    expect(gitCalls[0]?.spec.args).toEqual([
      'ls-remote',
      '--exit-code',
      'origin',
      CANDIDATE_REF,
      'refs/heads/main',
    ]);
  });

  it('merge-base', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().isAncestor(CANDIDATE_SHA, MAIN_SHA);
    expect(gitCalls[0]?.spec.args).toEqual([
      'merge-base',
      '--is-ancestor',
      CANDIDATE_SHA,
      MAIN_SHA,
    ]);
  });

  it('rev-list --count, with the range built from two validated SHAs', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '0\n' });
    await observer().uniqueCommitCount(MAIN_SHA, CANDIDATE_SHA);
    expect(gitCalls[0]?.spec.args).toEqual(['rev-list', '--count', `${MAIN_SHA}..${CANDIDATE_SHA}`]);
  });

  it('cherry', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().uniquePatchCount(MAIN_SHA, CANDIDATE_SHA);
    expect(gitCalls[0]?.spec.args).toEqual(['cherry', MAIN_SHA, CANDIDATE_SHA]);
  });

  it('worktree list --porcelain', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().worktrees();
    expect(gitCalls[0]?.spec.args).toEqual(['worktree', 'list', '--porcelain']);
  });

  it('-C <path> status --porcelain --untracked-files=all', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().worktreeClean('C:\\wt');
    expect(gitCalls[0]?.spec.args).toEqual([
      '-C',
      'C:\\wt',
      'status',
      '--porcelain',
      '--untracked-files=all',
    ]);
  });

  it('for-each-ref', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().branchUpstreams();
    expect(gitCalls[0]?.spec.args).toEqual([
      'for-each-ref',
      '--format=%(refname)%09%(upstream)',
      'refs/heads',
    ]);
  });
});

/* ------------------------------------------------------------------------- *
 * Containment and the hermetic environment
 * ------------------------------------------------------------------------- */

describe('capability containment (Amendment 1 A-2, A-3)', () => {
  it('exposes only named read-only operations — no argv, path, env, or transport', () => {
    expect(Object.keys(observer()).sort()).toEqual([
      'branchUpstreams',
      'isAncestor',
      'remoteRefs',
      'resolveRef',
      'uniqueCommitCount',
      'uniquePatchCount',
      'verifyExecutable',
      'worktreeClean',
      'worktrees',
    ]);
  });

  it('is frozen, and exposes no transport-shaped member', () => {
    const instance = observer();
    expect(Object.isFrozen(instance)).toBe(true);
    for (const forbidden of ['run', 'exec', 'invoke', 'spawn', 'git', 'transport', 'args']) {
      expect(Object.hasOwn(instance, forbidden), forbidden).toBe(false);
    }
  });

  it('never lets a caller choose the executable, cwd, or stdin', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().worktrees();
    const spec = gitCalls[0]?.spec;
    expect(spec?.executablePath).toBe('C:\\git\\git.exe');
    expect(spec?.workingDirectory).toBe('C:\\repo');
    expect(spec?.stdin).toBe('');
  });

  it('builds the environment as an allowlist and inherits nothing else', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().worktrees();
    const environment = gitCalls[0]?.spec.environment ?? {};
    expect(environment).toEqual({
      HOME: 'C:\\runtime',
      GIT_TERMINAL_PROMPT: '0',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: 'NUL',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_ASKPASS: '',
      SystemRoot: 'C:\\Windows',
      TEMP: 'C:\\Temp',
    });
    // Anything not on the allowlist — PATH included — is simply absent.
    expect(Object.hasOwn(environment, 'PATH')).toBe(false);
    expect(Object.hasOwn(environment, 'GIT_DIR')).toBe(false);
    expect(Object.hasOwn(environment, 'GIT_SSH_COMMAND')).toBe(false);
  });

  it('uses the POSIX null device on posix', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await createRetirementGitObserver({
      gitPath: '/usr/bin/git',
      gitSha256: 'sha256:' + '3'.repeat(64),
      repositoryPath: '/repo',
      runtimeRoot: '/runtime',
      environmentSource: {},
      platform: 'posix',
    }).worktrees();
    expect(gitCalls[0]?.spec.environment['GIT_CONFIG_GLOBAL']).toBe('/dev/null');
  });

  it('applies the fixed limits to every operation', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    await observer().worktrees();
    expect(gitCalls[0]?.limits).toEqual({
      timeoutMs: 30_000,
      graceMs: 2_000,
      maxStdoutBytes: 1_048_576,
      maxStderrBytes: 65_536,
    });
  });
});

/* ------------------------------------------------------------------------- *
 * Operand validation
 * ------------------------------------------------------------------------- */

describe('operand validation (Amendment 1 A-3)', () => {
  it('readFullSha accepts exactly 40 lowercase hex', () => {
    expect(readFullSha(CANDIDATE_SHA)).toBe(CANDIDATE_SHA);
    for (const value of ['a'.repeat(39), 'a'.repeat(41), 'A'.repeat(40), 'g'.repeat(40), '', null]) {
      expect(readFullSha(value), String(value)).toBeNull();
    }
  });

  it('refuses a non-canonical ref without spawning anything', async () => {
    for (const ref of ['repair/example', '--upload-pack=evil', 'refs/heads/..', '']) {
      const fact = await observer().resolveRef(ref);
      expect(fact.determinate, ref).toBe(false);
    }
    expect(gitCalls).toHaveLength(0);
  });

  it('refuses an abbreviated or malformed SHA without spawning anything', async () => {
    expect((await observer().isAncestor('abc1234', MAIN_SHA)).determinate).toBe(false);
    expect((await observer().uniqueCommitCount(MAIN_SHA, 'abc1234')).determinate).toBe(false);
    expect(gitCalls).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------------- *
 * Determinacy (Amendment 1 C-2)
 * ------------------------------------------------------------------------- */

describe('determinacy folding', () => {
  it('folds a timeout, a signal, a cancellation, and a spawn failure to indeterminate', async () => {
    for (const outcome of ['TIMED_OUT', 'SIGNALLED', 'CANCELLED', 'SPAWN_FAILED', 'SPEC_REJECTED']) {
      script({ outcome, exitCode: null, stdout: '' });
      const fact = await observer().worktrees();
      expect(fact.determinate, outcome).toBe(false);
    }
  });

  it('folds truncated output to indeterminate rather than a partial answer', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: 'worktree /a\n', stdoutTruncated: true });
    expect((await observer().worktrees()).determinate).toBe(false);
  });

  it('folds an undeclared exit code to indeterminate', async () => {
    script({ outcome: 'EXITED', exitCode: 128, stdout: '' });
    expect((await observer().worktrees()).determinate).toBe(false);
  });

  it('reads merge-base exit 1 as a determinate FALSE — the documented answer', async () => {
    script({ outcome: 'EXITED', exitCode: 1, stdout: '' });
    const fact = await observer().isAncestor(CANDIDATE_SHA, MAIN_SHA);
    expect(fact).toEqual({ determinate: true, value: false });
  });

  it('reads merge-base exit 0 as a determinate TRUE', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    expect(await observer().isAncestor(CANDIDATE_SHA, MAIN_SHA)).toEqual({
      determinate: true,
      value: true,
    });
  });

  it('reads ls-remote exit 2 as determinate remote absence', async () => {
    script({ outcome: 'EXITED', exitCode: 2, stdout: '' });
    const fact = await observer().remoteRefs(CANDIDATE_REF);
    expect(fact.determinate).toBe(true);
    expect(fact.determinate ? fact.value : null).toEqual({ candidateSha: null, mainSha: null });
  });

  it('folds a malformed ls-remote row to indeterminate', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: 'garbage-without-a-tab\n' });
    expect((await observer().remoteRefs(CANDIDATE_REF)).determinate).toBe(false);
  });

  it('folds an unrecognised cherry marker to indeterminate', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '? deadbeef\n' });
    expect((await observer().uniquePatchCount(MAIN_SHA, CANDIDATE_SHA)).determinate).toBe(false);
  });
});

/* ------------------------------------------------------------------------- *
 * Output parsing
 * ------------------------------------------------------------------------- */

describe('output parsing', () => {
  it('parses ls-remote into the two requested refs', async () => {
    script({
      outcome: 'EXITED',
      exitCode: 0,
      stdout: `${CANDIDATE_SHA}\t${CANDIDATE_REF}\n${MAIN_SHA}\trefs/heads/main\n`,
    });
    const fact = await observer().remoteRefs(CANDIDATE_REF);
    expect(fact.determinate ? fact.value : null).toEqual({
      candidateSha: CANDIDATE_SHA,
      mainSha: MAIN_SHA,
    });
  });

  it('counts only "+" rows from cherry', async () => {
    script({
      outcome: 'EXITED',
      exitCode: 0,
      stdout: '+ aaaa\n- bbbb\n+ cccc\n',
    });
    const fact = await observer().uniquePatchCount(MAIN_SHA, CANDIDATE_SHA);
    expect(fact.determinate ? fact.value : null).toBe(2);
  });

  it('parses worktree porcelain entries including prunable', async () => {
    script({
      outcome: 'EXITED',
      exitCode: 0,
      stdout: [
        'worktree C:/repo',
        `HEAD ${MAIN_SHA}`,
        'branch refs/heads/main',
        '',
        'worktree C:/wt',
        `HEAD ${CANDIDATE_SHA}`,
        `branch ${CANDIDATE_REF}`,
        'prunable gitdir file points to non-existent location',
        '',
      ].join('\n'),
    });
    const fact = await observer().worktrees();
    const entries = fact.determinate ? fact.value : [];
    expect(entries).toHaveLength(2);
    expect(entries[1]).toEqual({
      path: 'C:/wt',
      headSha: CANDIDATE_SHA,
      branchRef: CANDIDATE_REF,
      prunable: true,
    });
  });

  it('treats any porcelain status row as dirty, and no rows as clean', async () => {
    script({ outcome: 'EXITED', exitCode: 0, stdout: '' });
    expect(await observer().worktreeClean('C:\\wt')).toEqual({ determinate: true, value: true });

    script({ outcome: 'EXITED', exitCode: 0, stdout: '?? untracked.txt\n' });
    expect(await observer().worktreeClean('C:\\wt')).toEqual({ determinate: true, value: false });
  });

  it('parses for-each-ref, distinguishing no upstream from one', async () => {
    script({
      outcome: 'EXITED',
      exitCode: 0,
      stdout: `refs/heads/main\trefs/remotes/origin/main\nrefs/heads/local-only\t\n`,
    });
    const fact = await observer().branchUpstreams();
    expect(fact.determinate ? fact.value : []).toEqual([
      { refName: 'refs/heads/main', upstreamRef: 'refs/remotes/origin/main' },
      { refName: 'refs/heads/local-only', upstreamRef: null },
    ]);
  });
});

describe('executable identity (Amendment 1 A-6)', () => {
  it('refuses when the executable cannot be read', () => {
    expect(observer().verifyExecutable()).toBe(false);
  });
});
