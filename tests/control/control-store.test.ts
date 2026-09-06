import { describe, expect, it } from 'vitest';

import {
  CONTROL_ANCHOR_REJECTION,
  createRuntimeDescriptor,
  enumeratePathComponents,
  evaluateAnchorAcl,
  evaluatePathSafety,
  parseDescriptor,
  parseIcaclsEntries,
  parseWhoamiUser,
  pipePathFromName,
  resolveControlAnchorPath,
  serializeDescriptor,
  verifyControlAnchor,
  type LstatProbe,
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

  function runnerFor(icaclsStdout: string): ProcessRunner {
    return (exe: string): Promise<ProcessResult> => {
      if (exe.toLowerCase().includes('whoami')) {
        return Promise.resolve({ ok: true, stdout: WHOAMI });
      }
      if (exe.toLowerCase().includes('icacls')) {
        return Promise.resolve({ ok: true, stdout: icaclsStdout });
      }
      return Promise.resolve({ ok: false });
    };
  }

  it('accepts a well-formed anchor', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(GOOD_ICACLS),
      lstat: okLstat,
    });
    expect(result.ok).toBe(true);
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
