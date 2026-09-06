import { describe, expect, it } from 'vitest';

import {
  CONTROL_ANCHOR_REJECTION,
  createRuntimeDescriptor,
  enumeratePathComponents,
  evaluateAnchorAcl,
  evaluatePathSafety,
  parseDescriptor,
  parseIcaclsEntries,
  parseOwnerHelperSid,
  parseWhoamiUser,
  pipePathFromName,
  resolveControlAnchorPath,
  serializeDescriptor,
  verifyAnchorOwner,
  verifyControlAnchor,
  type LstatProbe,
  type OperatorIdentity,
  type OwnerVerifierDeps,
  type ProcessResult,
  type ProcessRunner,
} from '../../src/control/control-store.js';

const WHOAMI = [
  '',
  'USER INFORMATION',
  '----------------',
  '',
  'User Name         SID',
  '================= =============================================',
  'desktop-x\\dell    S-1-5-21-111-222-333-1001',
  '',
].join('\r\n');

const ANCHOR = 'C:\\Anchor';

function icacls(lines: readonly string[]): string {
  return [...lines, 'Successfully processed 1 files; Failed processing 0 files', ''].join('\r\n');
}

const GOOD_ICACLS = icacls([
  `${ANCHOR} NT AUTHORITY\\SYSTEM:(OI)(CI)(F)`,
  '        desktop-x\\dell:(OI)(CI)(F)',
]);

describe('D062 whoami/icacls parsing', () => {
  it('parses the operator name and SID from whoami /user', () => {
    const user = parseWhoamiUser(WHOAMI);
    expect(user).not.toBeNull();
    expect(user?.name).toBe('desktop-x\\dell');
    expect(user?.sid).toBe('s-1-5-21-111-222-333-1001');
  });

  it('returns null when no SID is present', () => {
    expect(parseWhoamiUser('no sid here')).toBeNull();
  });

  it('parses icacls entries with the anchor prefix stripped, flags inheritance', () => {
    const entries = parseIcaclsEntries(GOOD_ICACLS, ANCHOR);
    expect(entries).not.toBeNull();
    expect(entries).toEqual([
      { principal: 'nt authority\\system', inherited: false },
      { principal: 'desktop-x\\dell', inherited: false },
    ]);
  });

  it('marks a standalone (I) group as inherited but not (OI)/(CI)/(IO)', () => {
    const entries = parseIcaclsEntries(
      icacls([`${ANCHOR} desktop-x\\dell:(I)(OI)(CI)(F)`]),
      ANCHOR,
    );
    expect(entries?.[0]?.inherited).toBe(true);
    const notInherited = parseIcaclsEntries(icacls([`${ANCHOR} desktop-x\\dell:(OI)(CI)(F)`]), ANCHOR);
    expect(notInherited?.[0]?.inherited).toBe(false);
  });

  it('fails closed on icacls output without a summary line', () => {
    expect(parseIcaclsEntries(`${ANCHOR} desktop-x\\dell:(F)\r\n`, ANCHOR)).toBeNull();
  });
});

describe('D062 anchor ACL evaluation — exactly runtime + SYSTEM, none inherited', () => {
  const operator = { name: 'desktop-x\\dell', sid: 's-1-5-21-111-222-333-1001' };

  it('accepts runtime + SYSTEM, non-inherited', () => {
    const entries = parseIcaclsEntries(GOOD_ICACLS, ANCHOR);
    expect(entries).not.toBeNull();
    expect(evaluateAnchorAcl(operator, entries ?? []).ok).toBe(true);
  });

  it('rejects a foreign principal', () => {
    const entries = parseIcaclsEntries(
      icacls([
        `${ANCHOR} NT AUTHORITY\\SYSTEM:(F)`,
        '        BUILTIN\\Administrators:(F)',
        '        desktop-x\\dell:(F)',
      ]),
      ANCHOR,
    );
    const evaluation = evaluateAnchorAcl(operator, entries ?? []);
    expect(evaluation.ok).toBe(false);
    if (!evaluation.ok) {
      expect(evaluation.reason).toBe(CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL);
    }
  });

  it('rejects an inherited principal', () => {
    const entries = parseIcaclsEntries(
      icacls([`${ANCHOR} desktop-x\\dell:(I)(F)`, '        NT AUTHORITY\\SYSTEM:(F)']),
      ANCHOR,
    );
    const evaluation = evaluateAnchorAcl(operator, entries ?? []);
    expect(evaluation.ok).toBe(false);
    if (!evaluation.ok) {
      expect(evaluation.reason).toBe(CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL);
    }
  });

  it('rejects when the runtime principal is absent (SYSTEM only)', () => {
    const entries = parseIcaclsEntries(icacls([`${ANCHOR} NT AUTHORITY\\SYSTEM:(F)`]), ANCHOR);
    const evaluation = evaluateAnchorAcl(operator, entries ?? []);
    expect(evaluation.ok).toBe(false);
    if (!evaluation.ok) {
      expect(evaluation.reason).toBe(CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT);
    }
  });

  it('accepts a SID-form runtime principal', () => {
    const entries = parseIcaclsEntries(
      icacls([`${ANCHOR} S-1-5-21-111-222-333-1001:(F)`, '        NT AUTHORITY\\SYSTEM:(F)']),
      ANCHOR,
    );
    expect(evaluateAnchorAcl(operator, entries ?? []).ok).toBe(true);
  });
});

describe('D062 path reparse/symlink safety', () => {
  it('accepts a chain with no symlink/reparse component', () => {
    const probe: LstatProbe = () => ({ isSymbolicLink: false, isReparsePoint: false });
    const result = evaluatePathSafety(['C:\\', 'C:\\Anchor'], probe);
    expect(result.ok).toBe(true);
  });

  it('rejects a symlink component', () => {
    const probe: LstatProbe = (p) =>
      p === 'C:\\Anchor'
        ? { isSymbolicLink: true, isReparsePoint: false }
        : { isSymbolicLink: false, isReparsePoint: false };
    const result = evaluatePathSafety(['C:\\', 'C:\\Anchor'], probe);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.REPARSE_POINT);
    }
  });

  it('rejects a reparse-point component', () => {
    const probe: LstatProbe = (p) =>
      p === 'C:\\Anchor'
        ? { isSymbolicLink: false, isReparsePoint: true }
        : { isSymbolicLink: false, isReparsePoint: false };
    const result = evaluatePathSafety(['C:\\', 'C:\\Anchor'], probe);
    expect(result.ok).toBe(false);
  });

  it('fails closed on an unreadable component', () => {
    const probe: LstatProbe = () => null;
    const result = evaluatePathSafety(['C:\\'], probe);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.COMPONENT_UNREADABLE);
    }
  });

  it('enumerates ancestors root-first', () => {
    const components = enumeratePathComponents(ANCHOR);
    expect(components.length).toBeGreaterThanOrEqual(2);
    expect(components[components.length - 1]).toContain('Anchor');
  });
});

describe('D062 descriptor lifecycle', () => {
  it('mints a 256-bit token and an unpredictable pipe name', () => {
    const { descriptor, token } = createRuntimeDescriptor(4242);
    expect(token.length).toBe(32); // 256-bit
    expect(descriptor.pipeName).toMatch(/^agentbridge-control-[0-9a-f]{32}$/);
    expect(descriptor.pid).toBe(4242);
    expect(descriptor.version).toBe(1);
  });

  it('rotates the token and pipe name every mint', () => {
    const a = createRuntimeDescriptor(1);
    const b = createRuntimeDescriptor(1);
    expect(a.token.equals(b.token)).toBe(false);
    expect(a.descriptor.pipeName).not.toBe(b.descriptor.pipeName);
    expect(a.descriptor.token).not.toBe(b.descriptor.token);
  });

  it('round-trips a descriptor through serialize/parse with the same token', () => {
    const { descriptor, token } = createRuntimeDescriptor(7);
    const parsed = parseDescriptor(serializeDescriptor(descriptor));
    expect(parsed).not.toBeNull();
    expect(parsed?.token.equals(token)).toBe(true);
    expect(parsed?.descriptor.pipeName).toBe(descriptor.pipeName);
  });

  it('rejects malformed / stale / oversized descriptors', () => {
    expect(parseDescriptor('not json')).toBeNull();
    expect(parseDescriptor('[]')).toBeNull();
    expect(parseDescriptor(JSON.stringify({ version: 1, pid: 1, pipeName: 'x', token: 'y' }))).toBeNull();
    const { descriptor } = createRuntimeDescriptor(1);
    // Extra field.
    expect(
      parseDescriptor(JSON.stringify({ ...descriptor, extra: 1 })),
    ).toBeNull();
    // Wrong version.
    expect(parseDescriptor(JSON.stringify({ ...descriptor, version: 2 }))).toBeNull();
    // Short token (16 bytes).
    expect(
      parseDescriptor(
        JSON.stringify({ ...descriptor, token: Buffer.alloc(16, 1).toString('base64url') }),
      ),
    ).toBeNull();
    expect(parseDescriptor('x'.repeat(5000))).toBeNull();
  });

  it('builds the Windows named-pipe path from a pipe name', () => {
    expect(pipePathFromName('agentbridge-control-abc')).toBe('\\\\.\\pipe\\agentbridge-control-abc');
  });

  it('resolves the anchor under LOCALAPPDATA and null without it', () => {
    expect(resolveControlAnchorPath({ LOCALAPPDATA: 'C:\\Users\\x\\AppData\\Local' })).toContain(
      'AgentBridge',
    );
    expect(resolveControlAnchorPath({})).toBeNull();
  });
});

describe('D062 verifyControlAnchor — end-to-end with injected OS adapters', () => {
  const okLstat: LstatProbe = () => ({ isSymbolicLink: false, isReparsePoint: false });

  // The operator SID as reported by the owner helper (matches WHOAMI, uppercased).
  const OPERATOR_SID = 'S-1-5-21-111-222-333-1001';
  // A fixed expected/actual digest so the hash gate passes without a real binary.
  const OWNER_SHA = 'a'.repeat(64);
  const passingOwnerDeps = {
    loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
      Promise.resolve({ filename: 'owner-helper', sha256: OWNER_SHA }),
    resolveHelperPath: (): string => 'C:\\Program\\owner-helper',
    readHelperBytes: (): Buffer => Buffer.from('helper-bytes'),
    hashBytes: (): string => OWNER_SHA,
  };

  function runnerFor(icaclsStdout: string, ownerSid: string = OPERATOR_SID): ProcessRunner {
    return (exe: string): Promise<ProcessResult> => {
      if (exe.toLowerCase().includes('whoami')) {
        return Promise.resolve({ ok: true, stdout: WHOAMI });
      }
      if (exe.toLowerCase().includes('icacls')) {
        return Promise.resolve({ ok: true, stdout: icaclsStdout });
      }
      // The owner helper (any other absolute exe) returns the owner SID.
      return Promise.resolve({ ok: true, stdout: `${ownerSid}\n` });
    };
  }

  it('accepts a well-formed anchor with operator owner + valid DACL', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(GOOD_ICACLS),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result.ok).toBe(true);
  });

  it('rejects a valid DACL whose anchor OWNER is SYSTEM', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(GOOD_ICACLS, 'S-1-5-18'),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM);
    }
  });

  it('rejects a valid DACL whose anchor OWNER is a foreign SID (DACL membership is insufficient)', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(GOOD_ICACLS, 'S-1-5-21-999-888-777-2002'),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    }
  });

  it('rejects a foreign ACL principal', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(
        icacls([`${ANCHOR} BUILTIN\\Administrators:(F)`, '        desktop-x\\dell:(F)']),
      ),
      lstat: okLstat,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL);
    }
  });

  it('rejects a reparse/symlink path component before running any subprocess', async () => {
    let processCalls = 0;
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: () => {
        processCalls += 1;
        return Promise.resolve({ ok: true, stdout: WHOAMI });
      },
      lstat: () => ({ isSymbolicLink: true, isReparsePoint: false }),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.REPARSE_POINT);
    }
    expect(processCalls).toBe(0);
  });

  it('fails closed when whoami fails', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: () => Promise.resolve({ ok: false }),
      lstat: okLstat,
    });
    expect(result.ok).toBe(false);
  });
});

describe('D062 owner-SID gate — verifyAnchorOwner (F1, Amendment A)', () => {
  const OPERATOR: OperatorIdentity = { name: 'desktop-x\\dell', sid: 's-1-5-21-111-222-333-1001' };
  const ANCHOR_PATH = 'C:\\Users\\x\\AppData\\Local\\AgentBridge\\control';
  const HELPER_ABS = 'C:\\app\\dist\\control\\native\\agentbridge-win-owner.exe';
  const HELPER_BYTES = Buffer.from('trusted-helper-bytes');
  const GOOD_SHA = 'b'.repeat(64);

  /** Owner deps that pass the provenance + hash gate and resolve a fixed path. */
  function ownerDeps(overrides: Partial<OwnerVerifierDeps> = {}): OwnerVerifierDeps {
    return {
      loadProvenance: () =>
        Promise.resolve({ filename: 'agentbridge-win-owner.exe', sha256: GOOD_SHA }),
      resolveHelperPath: () => HELPER_ABS,
      readHelperBytes: () => HELPER_BYTES,
      hashBytes: () => GOOD_SHA,
      ...overrides,
    };
  }

  const sidRunner =
    (stdout: string, ok = true): ProcessRunner =>
    () =>
      Promise.resolve(ok ? { ok: true, stdout } : { ok: false });

  it('accepts when the anchor owner SID equals the operator SID', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-111-222-333-1001\n'),
      ownerDeps(),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ownerSid).toBe('s-1-5-21-111-222-333-1001');
    }
  });

  it('rejects a SYSTEM owner even though SYSTEM is an allowed DACL principal', async () => {
    const result = await verifyAnchorOwner(OPERATOR, ANCHOR_PATH, sidRunner('S-1-5-18\n'), ownerDeps());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM);
    }
  });

  it('rejects a foreign owner SID', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-999-888-777-2002\n'),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    }
  });

  it('fails closed when the helper binary is missing', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-111-222-333-1001\n'),
      ownerDeps({ readHelperBytes: () => null }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_MISSING);
    }
  });

  it('fails closed on a helper hash mismatch (a swapped binary)', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-111-222-333-1001\n'),
      ownerDeps({ hashBytes: () => 'c'.repeat(64) }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH);
    }
  });

  it('fails closed when provenance is absent', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-111-222-333-1001\n'),
      ownerDeps({ loadProvenance: () => Promise.resolve(null) }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('fails closed when provenance hash is not a 64-hex digest', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-111-222-333-1001\n'),
      ownerDeps({ loadProvenance: () => Promise.resolve({ filename: 'h', sha256: 'not-a-hash' }) }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('the expected hash comes only from the generated provenance module (never env/argv/sidecar)', async () => {
    // With no injected provenance loader, the default (module-relative import of
    // the generated build metadata) is used. In this src test context that module
    // does not exist, so the gate fails closed — the hash is never sourced from
    // the environment, argv, a sidecar, or any ambient value.
    const result = await verifyAnchorOwner(OPERATOR, ANCHOR_PATH, sidRunner('S-1-5-18\n'), {
      resolveHelperPath: () => HELPER_ABS,
      readHelperBytes: () => HELPER_BYTES,
      hashBytes: () => GOOD_SHA,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('fails closed on non-zero helper exit / timeout (runner failure)', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('', false),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_QUERY_FAILED);
    }
  });

  it('fails closed on malformed helper output', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('not-a-sid\n'),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_SID_MALFORMED);
    }
  });

  it('fails closed on extra stdout beyond a single SID line', async () => {
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('S-1-5-21-111-222-333-1001\nEXTRA\n'),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_SID_MALFORMED);
    }
  });

  it('an owner display name can never satisfy the SID comparison', async () => {
    // The operator's account name, not its SID, is not canonical -> malformed.
    const result = await verifyAnchorOwner(
      OPERATOR,
      ANCHOR_PATH,
      sidRunner('desktop-x\\dell\n'),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_SID_MALFORMED);
    }
  });

  it('invokes the helper by exact absolute path with exactly one anchor-path arg', async () => {
    const calls: { exe: string; args: readonly string[] }[] = [];
    const recordingRunner: ProcessRunner = (exe, args) => {
      calls.push({ exe, args });
      return Promise.resolve({ ok: true, stdout: 'S-1-5-21-111-222-333-1001\n' });
    };
    const result = await verifyAnchorOwner(OPERATOR, ANCHOR_PATH, recordingRunner, ownerDeps());
    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.exe).toBe(HELPER_ABS);
    expect(calls[0]?.args).toEqual([ANCHOR_PATH]);
  });

  it('parseOwnerHelperSid accepts exactly one canonical SID and nothing else', () => {
    expect(parseOwnerHelperSid('S-1-5-21-1-2-3-1001\n')).toBe('s-1-5-21-1-2-3-1001');
    expect(parseOwnerHelperSid('S-1-5-18\r\n')).toBe('s-1-5-18');
    expect(parseOwnerHelperSid('S-1-5-18')).toBe('s-1-5-18');
    expect(parseOwnerHelperSid('')).toBeNull();
    expect(parseOwnerHelperSid('nope')).toBeNull();
    expect(parseOwnerHelperSid(' S-1-5-18\n')).toBeNull();
    expect(parseOwnerHelperSid('S-1-5-18\nS-1-5-19\n')).toBeNull();
    expect(parseOwnerHelperSid('desktop-x\\dell\n')).toBeNull();
  });
});
