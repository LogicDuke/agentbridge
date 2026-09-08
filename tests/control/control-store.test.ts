import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  CONTROL_ANCHOR_REJECTION,
  createRuntimeDescriptor,
  enumeratePathComponents,
  evaluateAnchorSnapshot,
  evaluateDescriptorSnapshot,
  evaluatePathSafety,
  parseAclSnapshot,
  parseDescriptor,
  parseOwnerHelperSid,
  parseWhoamiUser,
  pipePathFromName,
  resolveControlAnchorPath,
  serializeDescriptor,
  writeDescriptorFile,
  verifyAnchorSnapshot,
  verifyControlAnchor,
  verifyDescriptorSnapshot,
  type AclSnapshotAce,
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

/** The operator SID as canonically reported by the helper (matches WHOAMI). */
const OPERATOR_SID = 'S-1-5-21-111-222-333-1001';
const SYSTEM_SID = 'S-1-5-18';

interface AceSpec {
  readonly type?: 'ALLOW' | 'DENY';
  readonly flags?: string;
  readonly mask?: string;
  readonly sid: string;
}

/** Build a canonical `--acl` snapshot exactly as the native helper would emit it. */
function snapshot(
  owner: string,
  aces: readonly AceSpec[],
  daclState: 'PRESENT' | 'NULL' | 'ABSENT' = 'PRESENT',
  daclProtected = true,
): string {
  const lines = [
    'AGENTBRIDGE-ACL-V2',
    `OWNER ${owner}`,
    `DACL ${daclState} ${daclProtected ? 'PROTECTED' : 'UNPROTECTED'}`,
    `ACES ${String(aces.length)}`,
  ];
  for (const ace of aces) {
    lines.push(
      `ACE ${ace.type ?? 'ALLOW'} ${ace.flags ?? '0x03'} ${
        ace.mask ?? '0x001F01FF'
      } ${ace.sid}`,
    );
  }
  return lines.join('\n') + '\n';
}

const GOOD_SNAPSHOT = snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }, { sid: OPERATOR_SID }]);

describe('D062 whoami parsing', () => {
  it('parses the operator name and SID from whoami /user', () => {
    const user = parseWhoamiUser(WHOAMI);
    expect(user).not.toBeNull();
    expect(user?.name).toBe('desktop-x\\dell');
    expect(user?.sid).toBe('s-1-5-21-111-222-333-1001');
  });

  it('returns null when no SID is present', () => {
    expect(parseWhoamiUser('no sid here')).toBeNull();
  });
});

describe('D062 canonical ACL snapshot parsing (Amendment B)', () => {
  it('parses owner, DACL presence, and every ACE by canonical SID', () => {
    const parsed = parseAclSnapshot(
      snapshot(OPERATOR_SID, [
        { type: 'ALLOW', flags: '0x03', mask: '0x001F01FF', sid: SYSTEM_SID },
        { type: 'DENY', flags: '0x01', mask: '0x00000004', sid: OPERATOR_SID },
      ]),
    );
    expect(parsed).not.toBeNull();
    expect(parsed?.ownerSid).toBe('s-1-5-21-111-222-333-1001');
    expect(parsed?.daclState).toBe('PRESENT');
    expect(parsed?.daclProtected).toBe(true);
    expect(parsed?.aces).toEqual<readonly AclSnapshotAce[]>([
      { type: 'ALLOW', flags: 0x03, mask: 0x001f01ff, sid: 's-1-5-18' },
      { type: 'DENY', flags: 0x01, mask: 0x00000004, sid: 's-1-5-21-111-222-333-1001' },
    ]);
  });

  it('preserves exact supported ACE flags independently of the allow/deny type', () => {
    const parsed = parseAclSnapshot(
      snapshot(OPERATOR_SID, [{ flags: '0x13', sid: OPERATOR_SID }]),
    );
    expect(parsed?.aces[0]?.flags).toBe(0x13);
    const direct = parseAclSnapshot(snapshot(OPERATOR_SID, [{ flags: '0x03', sid: OPERATOR_SID }]));
    expect(direct?.aces[0]?.flags).toBe(0x03);
  });

  it('represents a NULL DACL distinctly with zero ACEs', () => {
    const parsed = parseAclSnapshot(snapshot(OPERATOR_SID, [], 'NULL'));
    expect(parsed).not.toBeNull();
    expect(parsed?.daclState).toBe('NULL');
    expect(parsed?.aces).toEqual([]);
  });

  it('is total and fails closed on malformed snapshots', () => {
    expect(parseAclSnapshot('')).toBeNull();
    expect(parseAclSnapshot('not a snapshot\n')).toBeNull();
    // Wrong magic.
    expect(parseAclSnapshot('AGENTBRIDGE-ACL-V1\nOWNER S-1-5-18\nDACL PRESENT PROTECTED\nACES 0\n')).toBeNull();
    // Non-canonical owner (a display name can never enter authorization).
    expect(
      parseAclSnapshot('AGENTBRIDGE-ACL-V2\nOWNER desktop-x\\dell\nDACL PRESENT PROTECTED\nACES 0\n'),
    ).toBeNull();
    // ACE count mismatch (claims 2, supplies 1).
    expect(
      parseAclSnapshot(
        `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL PRESENT PROTECTED\nACES 2\nACE ALLOW 0x03 0x00000001 ${SYSTEM_SID}\n`,
      ),
    ).toBeNull();
    // Unknown ACE type token (audit/alarm/object/callback → unrepresentable).
    expect(
      parseAclSnapshot(
        `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL PRESENT PROTECTED\nACES 1\nACE AUDIT 0x03 0x00000001 ${SYSTEM_SID}\n`,
      ),
    ).toBeNull();
    // Non-canonical ACE SID.
    expect(
      parseAclSnapshot(
        `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL PRESENT PROTECTED\nACES 1\nACE ALLOW 0x03 0x00000001 BUILTIN\\Administrators\n`,
      ),
    ).toBeNull();
    // Malformed mask (not 0x + 8 hex).
    expect(
      parseAclSnapshot(
        `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL PRESENT PROTECTED\nACES 1\nACE ALLOW 0x03 1F01FF ${SYSTEM_SID}\n`,
      ),
    ).toBeNull();
    // NULL DACL that nonetheless carries an ACE.
    expect(
      parseAclSnapshot(
        `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL NULL PROTECTED\nACES 1\nACE ALLOW 0x03 0x00000001 ${SYSTEM_SID}\n`,
      ),
    ).toBeNull();
    // Trailing garbage after the final newline.
    expect(parseAclSnapshot(GOOD_SNAPSHOT + 'extra')).toBeNull();
    // Unknown DACL-control state and unknown ACE flag bits.
    expect(
      parseAclSnapshot(
        GOOD_SNAPSHOT.replace('DACL PRESENT PROTECTED', 'DACL PRESENT MAYBE_PROTECTED'),
      ),
    ).toBeNull();
    expect(parseAclSnapshot(GOOD_SNAPSHOT.replace('DACL PRESENT PROTECTED', 'DACL PRESENT'))).toBeNull();
    expect(parseAclSnapshot(GOOD_SNAPSHOT.replace('ACE ALLOW 0x03', 'ACE ALLOW 0x23'))).toBeNull();
    expect(parseAclSnapshot(GOOD_SNAPSHOT.replace('ACE ALLOW 0x03', 'ACE ALLOW 0xGG'))).toBeNull();
    // Extra token on an ACE line.
    expect(
      parseAclSnapshot(
        `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL PRESENT PROTECTED\nACES 1\nACE ALLOW 0x03 0x00000001 ${SYSTEM_SID} extra\n`,
      ),
    ).toBeNull();
  });
});

describe('D062 anchor snapshot evaluation — exactly operator + SYSTEM by SID', () => {
  const operator: OperatorIdentity = { name: 'desktop-x\\dell', sid: 's-1-5-21-111-222-333-1001' };

  function evaluate(text: string): ReturnType<typeof evaluateAnchorSnapshot> {
    const parsed = parseAclSnapshot(text);
    if (parsed === null) {
      throw new Error('snapshot unexpectedly failed to parse');
    }
    return evaluateAnchorSnapshot(operator, parsed);
  }

  it('accepts operator owner + a DACL of operator + SYSTEM, non-inherited', () => {
    expect(evaluate(GOOD_SNAPSHOT).ok).toBe(true);
  });

  it('accepts a DENY operator ACE as satisfying operator presence (invariant unchanged)', () => {
    // The pre-Amendment-B icacls check counted the operator principal regardless
    // of allow/deny; that invariant is deliberately preserved.
    const text = snapshot(OPERATOR_SID, [
      { type: 'DENY', mask: '0x00000004', sid: OPERATOR_SID },
      { type: 'ALLOW', sid: SYSTEM_SID },
    ]);
    expect(evaluate(text).ok).toBe(true);
  });

  it('rejects a SYSTEM owner (an owner can rewrite the DACL)', () => {
    const result = evaluate(snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }]));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM);
    }
  });

  it('rejects a foreign owner even with a valid DACL (DACL membership is insufficient)', () => {
    const result = evaluate(snapshot('S-1-5-21-999-888-777-2002', [{ sid: OPERATOR_SID }]));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    }
  });

  it('rejects a NULL DACL', () => {
    const result = evaluate(snapshot(OPERATOR_SID, [], 'NULL'));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.DACL_ABSENT);
    }
  });

  it('rejects an empty (present) DACL', () => {
    const result = evaluate(snapshot(OPERATOR_SID, []));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.NO_ENTRIES);
    }
  });

  it('rejects an unprotected DACL', () => {
    const result = evaluate(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }], 'PRESENT', false));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED);
    }
  });

  it('rejects a direct ACE without file inheritance', () => {
    const result = evaluate(
      snapshot(OPERATOR_SID, [{ flags: '0x00', sid: OPERATOR_SID }, { sid: SYSTEM_SID }]),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.FILE_INHERITANCE_ABSENT);
    }
  });

  it('rejects an inherited ACE', () => {
    const result = evaluate(
      snapshot(OPERATOR_SID, [{ flags: '0x13', sid: OPERATOR_SID }, { sid: SYSTEM_SID }]),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL);
    }
  });

  it('rejects a foreign ACE SID (e.g. Administrators)', () => {
    const result = evaluate(
      snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: 'S-1-5-32-544' }]),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL);
    }
  });

  it('rejects when the operator SID is absent (SYSTEM only)', () => {
    const result = evaluate(snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }]));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT);
    }
  });

  it('a localized display name is irrelevant — only canonical SIDs are compared', () => {
    // SYSTEM is authorized solely by S-1-5-18, never by "NT AUTHORITY\\SYSTEM";
    // the snapshot never carries a name, so localization cannot affect the result.
    const localized = parseAclSnapshot(
      `AGENTBRIDGE-ACL-V2\nOWNER ${OPERATOR_SID}\nDACL PRESENT PROTECTED\nACES 2\nACE ALLOW 0x03 0x001F01FF NT AUTHORITY\\SYSTEM\nACE ALLOW 0x03 0x001F01FF ${OPERATOR_SID}\n`,
    );
    expect(localized).toBeNull(); // a name is not a canonical SID → unparseable
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

describe('D062 descriptor ACL evaluation', () => {
  const operator: OperatorIdentity = { name: 'desktop-x\\dell', sid: OPERATOR_SID.toLowerCase() };

  it('accepts the actual file result with exactly operator + SYSTEM', () => {
    const parsed = parseAclSnapshot(
      snapshot(OPERATOR_SID, [
        { flags: '0x10', sid: OPERATOR_SID },
        { flags: '0x10', sid: SYSTEM_SID },
      ], 'PRESENT', false),
    );
    expect(parsed).not.toBeNull();
    if (parsed !== null) {
      expect(evaluateDescriptorSnapshot(operator, parsed)).toEqual({ ok: true });
    }
  });

  it('rejects a resulting file ACL that exposes the token to Everyone', () => {
    const parsed = parseAclSnapshot(
      snapshot(OPERATOR_SID, [
        { flags: '0x10', sid: OPERATOR_SID },
        { flags: '0x10', sid: SYSTEM_SID },
        { flags: '0x10', mask: '0x00120089', sid: 'S-1-1-0' },
      ], 'PRESENT', false),
    );
    expect(parsed).not.toBeNull();
    if (parsed !== null) {
      expect(evaluateDescriptorSnapshot(operator, parsed)).toEqual({
        ok: false,
        reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL,
      });
    }
  });

  it('uses the provenanced native snapshot query for the actual descriptor path', async () => {
    const ownerDeps: OwnerVerifierDeps = {
      loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
        Promise.resolve({ filename: 'owner-helper', sha256: 'a'.repeat(64) }),
      resolveHelperPath: (): string => 'C:\\Program\\owner-helper',
      readHelperBytes: (): Buffer => Buffer.from('helper-bytes'),
      hashBytes: (): string => 'a'.repeat(64),
    };
    let queriedPath: string | null = null;
    const runner: ProcessRunner = (_exe, args): Promise<ProcessResult> => {
      expect(args[0]).toBe('--acl');
      queriedPath = args[1] ?? null;
      return Promise.resolve({ ok: true, stdout: GOOD_SNAPSHOT });
    };
    const descriptorPath = 'C:\\Anchor\\runtime-descriptor.json';
    const result = await verifyDescriptorSnapshot(operator, descriptorPath, runner, ownerDeps);
    expect(result).toEqual({ ok: true });
    expect(queriedPath).toBe(descriptorPath);
  });

  it('uses exclusive creation and cannot overwrite an unexpected existing pathname', () => {
    const anchor = mkdtempSync(join(tmpdir(), 'abctl-exclusive-'));
    const path = join(anchor, 'runtime-descriptor.json');
    const existing = 'stale descriptor bytes';
    writeFileSync(path, existing, 'utf8');
    try {
      expect(() => {
        writeDescriptorFile(anchor, createRuntimeDescriptor(1).descriptor);
      }).toThrow();
      expect(readFileSync(path, 'utf8')).toBe(existing);
    } finally {
      rmSync(anchor, { recursive: true, force: true });
    }
  });
});

describe('D062 verifyControlAnchor — end-to-end with injected OS adapters', () => {
  const okLstat: LstatProbe = () => ({ isSymbolicLink: false, isReparsePoint: false });

  // A fixed expected/actual digest so the hash gate passes without a real binary.
  const OWNER_SHA = 'a'.repeat(64);
  const passingOwnerDeps: OwnerVerifierDeps = {
    loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
      Promise.resolve({ filename: 'owner-helper', sha256: OWNER_SHA }),
    resolveHelperPath: (): string => 'C:\\Program\\owner-helper',
    readHelperBytes: (): Buffer => Buffer.from('helper-bytes'),
    hashBytes: (): string => OWNER_SHA,
  };

  /** A runner that answers whoami and returns the given `--acl` snapshot. */
  function runnerFor(snapshotStdout: string): ProcessRunner {
    return (exe: string, args: readonly string[]): Promise<ProcessResult> => {
      if (exe.toLowerCase().includes('whoami')) {
        return Promise.resolve({ ok: true, stdout: WHOAMI });
      }
      // The owner+DACL helper — assert it is always invoked in --acl mode.
      expect(args[0]).toBe('--acl');
      return Promise.resolve({ ok: true, stdout: snapshotStdout });
    };
  }

  it('accepts a well-formed anchor with operator owner + valid DACL', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(GOOD_SNAPSHOT),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result.ok).toBe(true);
  });

  it('rejects a valid DACL whose anchor OWNER is SYSTEM', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }])),
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
      runProcess: runnerFor(snapshot('S-1-5-21-999-888-777-2002', [{ sid: OPERATOR_SID }])),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    }
  });

  it('rejects a foreign DACL principal', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: 'S-1-5-32-544' }])),
      lstat: okLstat,
      owner: passingOwnerDeps,
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

describe('D062 owner+DACL snapshot gate — verifyAnchorSnapshot (Amendment B)', () => {
  const OPERATOR: OperatorIdentity = { name: 'desktop-x\\dell', sid: 's-1-5-21-111-222-333-1001' };
  const ANCHOR_PATH = 'C:\\Users\\x\\AppData\\Local\\AgentBridge\\control';
  const HELPER_ABS = 'C:\\app\\dist\\control\\native\\agentbridge-win-owner.exe';
  const HELPER_BYTES = Buffer.from('trusted-helper-bytes');
  const GOOD_SHA = 'b'.repeat(64);

  /** Deps that pass the provenance + hash gate and resolve a fixed path. */
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

  const snapshotRunner =
    (stdout: string, ok = true): ProcessRunner =>
    () =>
      Promise.resolve(ok ? { ok: true, stdout } : { ok: false });

  it('accepts when the owner SID and DACL SIDs are exactly operator + SYSTEM', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(GOOD_SNAPSHOT),
      ownerDeps(),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ownerSid).toBe('s-1-5-21-111-222-333-1001');
    }
  });

  it('rejects a SYSTEM owner even though SYSTEM is an allowed DACL principal', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }])),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM);
    }
  });

  it('rejects a foreign owner SID', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(snapshot('S-1-5-21-999-888-777-2002', [{ sid: OPERATOR_SID }])),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    }
  });

  it('rejects a foreign DACL SID', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: 'S-1-5-32-544' }])),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL);
    }
  });

  it('rejects a NULL DACL', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(snapshot(OPERATOR_SID, [], 'NULL')),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.DACL_ABSENT);
    }
  });

  it('rejects an inherited DACL ACE', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(snapshot(OPERATOR_SID, [{ flags: '0x13', sid: OPERATOR_SID }, { sid: SYSTEM_SID }])),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL);
    }
  });

  it('rejects when the operator ACE is missing', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }])),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT);
    }
  });

  it('fails closed on malformed helper output', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner('garbage\n'),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED);
    }
  });

  it('fails closed when the helper binary is missing', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(GOOD_SNAPSHOT),
      ownerDeps({ readHelperBytes: () => null }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_MISSING);
    }
  });

  it('fails closed on a helper hash mismatch (a swapped binary)', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(GOOD_SNAPSHOT),
      ownerDeps({ hashBytes: () => 'c'.repeat(64) }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH);
    }
  });

  it('fails closed when provenance is absent', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(GOOD_SNAPSHOT),
      ownerDeps({ loadProvenance: () => Promise.resolve(null) }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('fails closed when provenance hash is not a 64-hex digest', async () => {
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner(GOOD_SNAPSHOT),
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
    const result = await verifyAnchorSnapshot(OPERATOR, ANCHOR_PATH, snapshotRunner(GOOD_SNAPSHOT), {
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
    const result = await verifyAnchorSnapshot(
      OPERATOR,
      ANCHOR_PATH,
      snapshotRunner('', false),
      ownerDeps(),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.SNAPSHOT_QUERY_FAILED);
    }
  });

  it('invokes the helper by exact absolute path with exactly --acl + anchor path', async () => {
    const calls: { exe: string; args: readonly string[] }[] = [];
    const recordingRunner: ProcessRunner = (exe, args) => {
      calls.push({ exe, args });
      return Promise.resolve({ ok: true, stdout: GOOD_SNAPSHOT });
    };
    const result = await verifyAnchorSnapshot(OPERATOR, ANCHOR_PATH, recordingRunner, ownerDeps());
    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.exe).toBe(HELPER_ABS);
    expect(calls[0]?.args).toEqual(['--acl', ANCHOR_PATH]);
  });

  it('parseOwnerHelperSid accepts exactly one canonical SID and nothing else', () => {
    // Retained for the owner-only helper mode (F1 backward compatibility).
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
