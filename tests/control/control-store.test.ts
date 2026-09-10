import net from 'node:net';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  CONTROL_ANCHOR_REJECTION,
  DESCRIPTOR_CREATION_REJECTION,
  DISCOVERY_UNAVAILABLE,
  MAX_DESCRIPTOR_BYTES,
  MAX_DESCRIPTOR_CANDIDATES,
  createDescriptorFileNative,
  createRuntimeDescriptor,
  defaultPipeProbe,
  descriptorFilenameFor,
  descriptorPathFor,
  discoverControlRuntime,
  enumeratePathComponents,
  enumerateDescriptorCandidates,
  evaluateAnchorSnapshot,
  evaluateDescriptorSnapshot,
  evaluatePathSafety,
  isRuntimeId,
  parseAclSnapshot,
  parseDescriptor,
  parseOwnerHelperSid,
  parseWhoamiUser,
  pipeNameForRuntimeId,
  pipePathFromName,
  readDescriptorCandidate,
  resolveControlAnchorPath,
  runtimeIdFromDescriptorFilename,
  runtimeIdFromPipeName,
  serializeDescriptor,
  sweepStaleDescriptors,
  verifyAnchorSnapshot,
  verifyControlAnchor,
  verifyDescriptorAcl,
  verifyDescriptorSnapshot,
  type AclSnapshotAce,
  type CreatorRunner,
  type DescriptorCreatorDeps,
  type LstatProbe,
  type OperatorIdentity,
  type OwnerVerifierDeps,
  type ProcessResult,
  type ProcessRunner,
} from '../../src/control/control-store.js';
import { FAKE_ANCHOR, allAbsentProbe, closeServer, memAnchor, tableProbe } from './support.js';

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
const OPERATOR: OperatorIdentity = { name: 'desktop-x\\dell', sid: 's-1-5-21-111-222-333-1001' };

interface AceSpec {
  readonly type?: 'ALLOW' | 'DENY';
  readonly flags?: number;
  readonly mask?: string;
  readonly sid: string;
}

/** Build a canonical V2 `--acl` snapshot exactly as the native helper would emit it. */
function snapshot(
  owner: string,
  aces: readonly AceSpec[],
  dacl: 'PRESENT' | 'NULL' | 'ABSENT' = 'PRESENT',
  daclProtected = true,
): string {
  const lines = [
    'AGENTBRIDGE-ACL-V2',
    `OWNER ${owner}`,
    `DACL ${dacl} ${daclProtected ? 'PROTECTED' : 'UNPROTECTED'}`,
    `ACES ${String(aces.length)}`,
  ];
  for (const ace of aces) {
    const flags = (ace.flags ?? 0).toString(16).toUpperCase().padStart(2, '0');
    lines.push(`ACE ${ace.type ?? 'ALLOW'} 0x${flags} ${ace.mask ?? '0x001F01FF'} ${ace.sid}`);
  }
  return lines.join('\n') + '\n';
}

const GOOD_SNAPSHOT = snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }, { sid: OPERATOR_SID }]);

const HEX32 = '0123456789abcdef0123456789abcdef';

describe('D062 whoami parsing', () => {
  it('parses the operator name and SID from whoami /user', () => {
    const user = parseWhoamiUser(WHOAMI);
    expect(user).not.toBeNull();
    expect(user?.name).toBe('desktop-x\\dell');
    expect(user?.sid).toBe('s-1-5-21-111-222-333-1001');
  });

  it('returns null when no SID is present', () => {
    expect(parseWhoamiUser('nothing here')).toBeNull();
  });
});

/* ---- runtime identity ------------------------------------------------------- */

describe('D062 runtime identity — strict [0-9a-f]{32}', () => {
  it('accepts exactly 32 lowercase hex characters', () => {
    expect(isRuntimeId(HEX32)).toBe(true);
    expect(isRuntimeId('0'.repeat(32))).toBe(true);
  });

  it('rejects every other shape (length, case, separators, traversal, unicode, controls)', () => {
    const bad: unknown[] = [
      '',
      HEX32.slice(0, 31),
      `${HEX32}0`,
      HEX32.toUpperCase(),
      `${HEX32.slice(0, 31)}g`,
      `..\\${HEX32.slice(3)}`,
      `../${HEX32.slice(3)}`,
      `${HEX32.slice(0, 16)}\\${HEX32.slice(17)}`,
      `${HEX32.slice(0, 16)}/${HEX32.slice(17)}`,
      `${HEX32.slice(0, 16)}.${HEX32.slice(17)}`,
      `${HEX32.slice(0, 16)}:${HEX32.slice(17)}`,
      `${HEX32.slice(0, 16)} ${HEX32.slice(17)}`,
      `${HEX32.slice(0, 31)}\u0000`,
      `${HEX32.slice(0, 31)}\n`,
      `${HEX32.slice(0, 31)}\u0661`, // Arabic-Indic digit one
      `${HEX32.slice(0, 31)}\uff10`, // fullwidth zero
      42,
      null,
      undefined,
      {},
    ];
    for (const value of bad) {
      expect(isRuntimeId(value), JSON.stringify(value)).toBe(false);
    }
  });

  it('derives the filename and pipe name only from a valid id, and throws otherwise', () => {
    expect(descriptorFilenameFor(HEX32)).toBe(`runtime-descriptor-${HEX32}.json`);
    expect(pipeNameForRuntimeId(HEX32)).toBe(`agentbridge-control-${HEX32}`);
    expect(descriptorPathFor(ANCHOR, HEX32)).toBe(join(ANCHOR, `runtime-descriptor-${HEX32}.json`));
    for (const bad of ['', '..', `..\\${HEX32}`, HEX32.toUpperCase(), 'runtime-descriptor.json']) {
      expect(() => descriptorFilenameFor(bad)).toThrow(TypeError);
      expect(() => pipeNameForRuntimeId(bad)).toThrow(TypeError);
      expect(() => descriptorPathFor(ANCHOR, bad)).toThrow(TypeError);
    }
  });

  it('recognises only exact identity-named basenames as candidates', () => {
    expect(runtimeIdFromDescriptorFilename(`runtime-descriptor-${HEX32}.json`)).toBe(HEX32);
    for (const name of [
      'runtime-descriptor.json', // the abandoned fixed name
      `runtime-descriptor-${HEX32.toUpperCase()}.json`,
      `runtime-descriptor-${HEX32}.json.bak`,
      `runtime-descriptor-${HEX32}.JSON`,
      `runtime-descriptor-${HEX32.slice(1)}.json`,
      `xruntime-descriptor-${HEX32}.json`,
      `runtime-descriptor-${HEX32}`,
      `..\\runtime-descriptor-${HEX32}.json`,
      '',
    ]) {
      expect(runtimeIdFromDescriptorFilename(name), name).toBeNull();
    }
  });

  it('extracts the id from a pipe name and rejects malformed pipe names', () => {
    expect(runtimeIdFromPipeName(`agentbridge-control-${HEX32}`)).toBe(HEX32);
    expect(runtimeIdFromPipeName(`agentbridge-control-${HEX32.toUpperCase()}`)).toBeNull();
    expect(runtimeIdFromPipeName('agentbridge-control-abc')).toBeNull();
    expect(runtimeIdFromPipeName(`other-${HEX32}`)).toBeNull();
  });
});

/* ---- descriptor model v2 ---------------------------------------------------- */

describe('D062 descriptor model v2', () => {
  it('mints a 256-bit token, a 128-bit runtime id, and a pipe name carrying that id — no PID', () => {
    const { descriptor, token, runtimeId } = createRuntimeDescriptor();
    expect(token.length).toBe(32);
    expect(isRuntimeId(runtimeId)).toBe(true);
    expect(descriptor.pipeName).toBe(`agentbridge-control-${runtimeId}`);
    expect(descriptor.version).toBe(2);
    expect(Object.keys(descriptor)).toEqual(['version', 'pipeName', 'token']);
    expect('pid' in descriptor).toBe(false);
  });

  it('rotates the token and runtime id every mint', () => {
    const a = createRuntimeDescriptor();
    const b = createRuntimeDescriptor();
    expect(a.token.equals(b.token)).toBe(false);
    expect(a.runtimeId).not.toBe(b.runtimeId);
    expect(a.descriptor.token).not.toBe(b.descriptor.token);
  });

  it('round-trips through serialize/parse with the same token and derived id', () => {
    const { descriptor, token, runtimeId } = createRuntimeDescriptor();
    const parsed = parseDescriptor(serializeDescriptor(descriptor));
    expect(parsed).not.toBeNull();
    expect(parsed?.token.equals(token)).toBe(true);
    expect(parsed?.descriptor.pipeName).toBe(descriptor.pipeName);
    expect(parsed?.runtimeId).toBe(runtimeId);
  });

  it('rejects malformed / legacy / oversized descriptors', () => {
    const { descriptor } = createRuntimeDescriptor();
    expect(parseDescriptor('not json')).toBeNull();
    expect(parseDescriptor('[]')).toBeNull();
    expect(parseDescriptor(JSON.stringify({ version: 2, pipeName: 'x', token: 'y' }))).toBeNull();
    // Legacy v1 shape (pid-bearing) is not a v2 descriptor.
    expect(parseDescriptor(JSON.stringify({ version: 1, pid: 1, pipeName: descriptor.pipeName, token: descriptor.token }))).toBeNull();
    // Extra field.
    expect(parseDescriptor(JSON.stringify({ ...descriptor, pid: 7 }))).toBeNull();
    // Wrong version.
    expect(parseDescriptor(JSON.stringify({ ...descriptor, version: 1 }))).toBeNull();
    // Malformed pipe name (uppercase id).
    expect(parseDescriptor(JSON.stringify({ ...descriptor, pipeName: descriptor.pipeName.toUpperCase() }))).toBeNull();
    // Short token (16 bytes).
    expect(parseDescriptor(JSON.stringify({ ...descriptor, token: Buffer.alloc(16, 1).toString('base64url') }))).toBeNull();
    expect(parseDescriptor('x'.repeat(5000))).toBeNull();
  });

  it('builds the Windows named-pipe path from a pipe name', () => {
    expect(pipePathFromName('agentbridge-control-abc')).toBe('\\\\.\\pipe\\agentbridge-control-abc');
  });

  it('resolves the anchor under LOCALAPPDATA and null without it', () => {
    expect(resolveControlAnchorPath({ LOCALAPPDATA: 'C:\\Users\\x\\AppData\\Local' })).toContain('AgentBridge');
    expect(resolveControlAnchorPath({})).toBeNull();
  });
});

/* ---- snapshot V2 parsing ---------------------------------------------------- */

describe('D062 canonical ACL snapshot parsing (grammar V2)', () => {
  it('parses owner, DACL state + protection, and every ACE by canonical SID with exact flags', () => {
    const parsed = parseAclSnapshot(
      snapshot(OPERATOR_SID, [
        { sid: SYSTEM_SID, flags: 0x03 },
        { type: 'DENY', sid: OPERATOR_SID, flags: 0x10, mask: '0x00010040' },
      ]),
    );
    expect(parsed).not.toBeNull();
    expect(parsed?.ownerSid).toBe('s-1-5-21-111-222-333-1001');
    expect(parsed?.daclState).toBe('PRESENT');
    expect(parsed?.daclProtected).toBe(true);
    expect(parsed?.aces).toEqual<AclSnapshotAce[]>([
      { type: 'ALLOW', flags: 0x03, mask: 0x001f01ff, sid: 's-1-5-18' },
      { type: 'DENY', flags: 0x10, mask: 0x00010040, sid: 's-1-5-21-111-222-333-1001' },
    ]);
  });

  it('represents NULL and ABSENT DACLs and the UNPROTECTED state', () => {
    expect(parseAclSnapshot(snapshot(OPERATOR_SID, [], 'NULL'))?.daclState).toBe('NULL');
    expect(parseAclSnapshot(snapshot(OPERATOR_SID, [], 'ABSENT'))?.daclState).toBe('ABSENT');
    expect(parseAclSnapshot(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }], 'PRESENT', false))?.daclProtected).toBe(false);
  });

  it('is total and fails closed on malformed snapshots', () => {
    const good = GOOD_SNAPSHOT;
    const cases: readonly [string, string][] = [
      ['empty', ''],
      ['V1 magic', good.replace('AGENTBRIDGE-ACL-V2', 'AGENTBRIDGE-ACL-V1')],
      ['no protection token', good.replace('PRESENT PROTECTED', 'PRESENT')],
      ['unknown protection token', good.replace('PROTECTED', 'SEALED')],
      ['V1 inheritance word instead of flags', good.replace('0x00 0x001F01FF S-1-5-18', 'DIRECT 0x001F01FF S-1-5-18')],
      ['flags out of the supported mask', good.replace('0x00 0x001F01FF S-1-5-18', '0x40 0x001F01FF S-1-5-18')],
      ['one-digit flags', good.replace('0x00 0x001F01FF S-1-5-18', '0x0 0x001F01FF S-1-5-18')],
      ['non-canonical owner', good.replace(`OWNER ${OPERATOR_SID}`, 'OWNER NT AUTHORITY\\SYSTEM')],
      ['non-canonical ACE sid', good.replace('S-1-5-18\n', 'BUILTIN\\Users\n')],
      ['count mismatch', good.replace('ACES 2', 'ACES 1')],
      ['NULL DACL with ACEs', good.replace('PRESENT PROTECTED', 'NULL PROTECTED')],
      ['missing trailing LF', good.slice(0, -1)],
      ['trailing garbage', `${good}extra\n`],
      ['CRLF', good.replace(/\n/g, '\r\n')],
      ['unknown ACE type', good.replace('ACE ALLOW', 'ACE AUDIT')],
      ['short mask', good.replace('0x001F01FF', '0x1F01FF')],
      ['over-long', `${good}${'ACE ALLOW 0x00 0x001F01FF S-1-5-18\n'.repeat(5000)}`],
    ];
    for (const [label, text] of cases) {
      expect(parseAclSnapshot(text), label).toBeNull();
    }
  });
});

/* ---- evaluators ------------------------------------------------------------- */

describe('D062 anchor snapshot evaluation — owner + protected DACL within {operator, SYSTEM}', () => {
  const evaluate = (text: string): ReturnType<typeof evaluateAnchorSnapshot> => {
    const parsed = parseAclSnapshot(text);
    if (parsed === null) {
      throw new Error('fixture must parse');
    }
    return evaluateAnchorSnapshot(OPERATOR, parsed);
  };
  const reason = (text: string): string => {
    const result = evaluate(text);
    return result.ok ? 'OK' : result.reason;
  };

  it('accepts operator owner + protected DACL of operator + SYSTEM, direct', () => {
    expect(evaluate(GOOD_SNAPSHOT)).toEqual({ ok: true });
  });
  it('accepts an operator-only protected DACL (SYSTEM permitted, not required)', () => {
    expect(evaluate(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }]))).toEqual({ ok: true });
  });
  it('places no file-inheritance requirement on the anchor (flags 0x00 and 0x03 both accepted)', () => {
    expect(evaluate(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID, flags: 0x03 }, { sid: SYSTEM_SID, flags: 0x00 }]))).toEqual({ ok: true });
  });
  it('accepts a DENY operator ACE as satisfying operator presence (invariant unchanged)', () => {
    expect(evaluate(snapshot(OPERATOR_SID, [{ type: 'DENY', sid: OPERATOR_SID }, { sid: SYSTEM_SID }]))).toEqual({ ok: true });
  });
  it('rejects a SYSTEM owner', () => {
    expect(reason(snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM);
  });
  it('rejects a foreign owner even with a valid DACL', () => {
    expect(reason(snapshot('S-1-5-21-999-888-777-2002', [{ sid: OPERATOR_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
  });
  it('rejects a NULL or ABSENT DACL', () => {
    expect(reason(snapshot(OPERATOR_SID, [], 'NULL'))).toBe(CONTROL_ANCHOR_REJECTION.DACL_ABSENT);
    expect(reason(snapshot(OPERATOR_SID, [], 'ABSENT'))).toBe(CONTROL_ANCHOR_REJECTION.DACL_ABSENT);
  });
  it('rejects an UNPROTECTED DACL, even one whose principals are otherwise exact', () => {
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }], 'PRESENT', false))).toBe(CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED);
  });
  it('rejects an empty (present) DACL', () => {
    expect(reason(snapshot(OPERATOR_SID, []))).toBe(CONTROL_ANCHOR_REJECTION.NO_ENTRIES);
  });
  it('rejects an inherited ACE (INHERITED_ACE flag)', () => {
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID, flags: 0x10 }, { sid: SYSTEM_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL);
  });
  it('rejects a foreign ACE SID (e.g. Administrators)', () => {
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: 'S-1-5-32-544' }]))).toBe(CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL);
  });
  it('rejects when the operator SID is absent (SYSTEM only)', () => {
    expect(reason(snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT);
  });
});

describe('D062 descriptor snapshot evaluation — the creator\'s exact shape', () => {
  const reason = (text: string): string => {
    const parsed = parseAclSnapshot(text);
    if (parsed === null) {
      throw new Error('fixture must parse');
    }
    const result = evaluateDescriptorSnapshot(OPERATOR, parsed);
    return result.ok ? 'OK' : result.reason;
  };
  it('accepts exactly what the creator produces: operator owner, PROTECTED, two direct ALLOW ACEs (operator + SYSTEM)', () => {
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]))).toBe('OK');
  });
  it('rejects a descriptor missing SYSTEM (not creator-made)', () => {
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.SYSTEM_PRINCIPAL_ABSENT);
  });
  it('rejects wrong owner, SYSTEM owner, unprotected, inherited, foreign, and operator-absent descriptors', () => {
    expect(reason(snapshot('S-1-5-32-544', [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    expect(reason(snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM);
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }], 'PRESENT', false))).toBe(CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED);
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID, flags: 0x10 }, { sid: SYSTEM_SID, flags: 0x10 }]))).toBe(CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL);
    expect(reason(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }, { sid: 'S-1-1-0' }]))).toBe(CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL);
    expect(reason(snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }]))).toBe(CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT);
    expect(reason(snapshot(OPERATOR_SID, [], 'NULL'))).toBe(CONTROL_ANCHOR_REJECTION.DACL_ABSENT);
  });
});

/* ---- path safety ------------------------------------------------------------ */

describe('D062 path reparse/symlink safety', () => {
  it('accepts a chain with no symlink/reparse component', () => {
    const probe: LstatProbe = () => ({ isSymbolicLink: false, isReparsePoint: false });
    expect(evaluatePathSafety(enumeratePathComponents(ANCHOR), probe)).toEqual({ ok: true });
  });
  it('rejects a symlink component', () => {
    const components = enumeratePathComponents(ANCHOR);
    const target = components[components.length - 1] ?? '';
    const probe: LstatProbe = (path) => ({ isSymbolicLink: path === target, isReparsePoint: false });
    const result = evaluatePathSafety(components, probe);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.REPARSE_POINT);
    }
  });
  it('fails closed on an unreadable component', () => {
    const result = evaluatePathSafety(enumeratePathComponents(ANCHOR), () => null);
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

/* ---- gates with injected OS adapters ---------------------------------------- */

const okLstat: LstatProbe = () => ({ isSymbolicLink: false, isReparsePoint: false });
const OWNER_SHA = 'a'.repeat(64);
const passingOwnerDeps: OwnerVerifierDeps = {
  loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
    Promise.resolve({ filename: 'owner-helper', sha256: OWNER_SHA }),
  resolveHelperPath: (): string => 'C:\\Program\\owner-helper',
  readHelperBytes: (): Buffer => Buffer.from('helper-bytes'),
  hashBytes: (): string => OWNER_SHA,
};
/** A runner that answers whoami and returns the given `--acl` snapshot. */
function runnerFor(snapshotStdout: string, calls: { exe: string; args: readonly string[] }[] = []): ProcessRunner {
  return (exe: string, args: readonly string[]): Promise<ProcessResult> => {
    calls.push({ exe, args });
    if (exe.toLowerCase().includes('whoami')) {
      return Promise.resolve({ ok: true, stdout: WHOAMI });
    }
    expect(args[0]).toBe('--acl');
    return Promise.resolve({ ok: true, stdout: snapshotStdout });
  };
}

describe('D062 verifyControlAnchor — end-to-end with injected OS adapters', () => {
  it('accepts a well-formed anchor with operator owner + protected valid DACL', async () => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(GOOD_SNAPSHOT),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: true, anchorPath: ANCHOR });
  });

  it.each([
    ['SYSTEM owner', snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }]), CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM],
    ['foreign owner', snapshot('S-1-5-21-999-888-777-2002', [{ sid: OPERATOR_SID }]), CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH],
    ['foreign principal', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: 'S-1-5-32-544' }]), CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL],
    ['unprotected', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }], 'PRESENT', false), CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED],
  ])('rejects %s', async (_label, stdout, expected) => {
    const result = await verifyControlAnchor({
      anchorPath: ANCHOR,
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(stdout),
      lstat: okLstat,
      owner: passingOwnerDeps,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(expected);
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

describe('D062 owner+DACL snapshot gate — verifyAnchorSnapshot', () => {
  const ANCHOR_PATH = 'C:\\Users\\x\\AppData\\Local\\AgentBridge\\control';
  const HELPER_ABS = 'C:\\app\\dist\\control\\native\\agentbridge-win-owner.exe';
  const HELPER_BYTES = Buffer.from('trusted-helper-bytes');
  const GOOD_SHA = 'b'.repeat(64);

  function ownerDeps(overrides: Partial<OwnerVerifierDeps> = {}): OwnerVerifierDeps {
    return {
      loadProvenance: () => Promise.resolve({ filename: 'agentbridge-win-owner.exe', sha256: GOOD_SHA }),
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

  it('accepts when the owner SID and protected DACL SIDs are exactly operator + SYSTEM', async () => {
    const result = await verifyAnchorSnapshot(OPERATOR, ANCHOR_PATH, snapshotRunner(GOOD_SNAPSHOT), ownerDeps());
    expect(result).toEqual({ ok: true, ownerSid: 's-1-5-21-111-222-333-1001' });
  });

  it.each([
    ['malformed helper output', 'garbage\n', ownerDeps(), CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED],
    ['helper binary missing', GOOD_SNAPSHOT, ownerDeps({ readHelperBytes: () => null }), CONTROL_ANCHOR_REJECTION.HELPER_MISSING],
    ['hash mismatch (swapped binary)', GOOD_SNAPSHOT, ownerDeps({ hashBytes: () => 'c'.repeat(64) }), CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH],
    ['provenance absent', GOOD_SNAPSHOT, ownerDeps({ loadProvenance: () => Promise.resolve(null) }), CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING],
    ['provenance hash not 64-hex', GOOD_SNAPSHOT, ownerDeps({ loadProvenance: () => Promise.resolve({ filename: 'h', sha256: 'not-a-hash' }) }), CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING],
    ['provenance filename with a separator', GOOD_SNAPSHOT, ownerDeps({ loadProvenance: () => Promise.resolve({ filename: '..\\evil.exe', sha256: GOOD_SHA }) }), CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING],
  ])('fails closed: %s', async (_label, stdout, deps, expected) => {
    const result = await verifyAnchorSnapshot(OPERATOR, ANCHOR_PATH, snapshotRunner(stdout), deps);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(expected);
    }
  });

  it('the expected hash comes only from the generated provenance module (never env/argv/sidecar)', async () => {
    // With no injected provenance loader, the default (module-relative import of
    // the generated build metadata) is used. In this src test context that module
    // does not exist, so the gate fails closed.
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
    const result = await verifyAnchorSnapshot(OPERATOR, ANCHOR_PATH, snapshotRunner('', false), ownerDeps());
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
    expect(calls).toEqual([{ exe: HELPER_ABS, args: ['--acl', ANCHOR_PATH] }]);
  });

  it('parseOwnerHelperSid accepts exactly one canonical SID and nothing else', () => {
    expect(parseOwnerHelperSid('S-1-5-21-1-2-3-1001\n')).toBe('s-1-5-21-1-2-3-1001');
    expect(parseOwnerHelperSid('S-1-5-18\r\n')).toBe('s-1-5-18');
    expect(parseOwnerHelperSid('')).toBeNull();
    expect(parseOwnerHelperSid(' S-1-5-18\n')).toBeNull();
    expect(parseOwnerHelperSid('S-1-5-18\nS-1-5-19\n')).toBeNull();
    expect(parseOwnerHelperSid('desktop-x\\dell\n')).toBeNull();
  });
});

describe('D062 descriptor ACL gate — verifyDescriptorSnapshot / verifyDescriptorAcl', () => {
  const DESCRIPTOR_PATH = descriptorPathFor(ANCHOR, HEX32);
  const DESCRIPTOR_SNAPSHOT = snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]);

  it('verifyDescriptorSnapshot points the hash-verified helper at exactly the descriptor path', async () => {
    const calls: { exe: string; args: readonly string[] }[] = [];
    const result = await verifyDescriptorSnapshot(OPERATOR, DESCRIPTOR_PATH, runnerFor(DESCRIPTOR_SNAPSHOT, calls), passingOwnerDeps);
    expect(result).toEqual({ ok: true });
    expect(calls).toEqual([{ exe: 'C:\\Program\\owner-helper', args: ['--acl', DESCRIPTOR_PATH] }]);
  });

  it('verifyDescriptorAcl resolves the operator through whoami, then evaluates the descriptor policy', async () => {
    const calls: { exe: string; args: readonly string[] }[] = [];
    const result = await verifyDescriptorAcl(DESCRIPTOR_PATH, {
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(DESCRIPTOR_SNAPSHOT, calls),
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: true });
    expect(calls.map((call) => call.args)).toEqual([['/user'], ['--acl', DESCRIPTOR_PATH]]);
    expect(calls[0]?.exe).toBe(join('C:\\Windows', 'System32', 'whoami.exe'));
  });

  it('verifyDescriptorAcl fails closed when whoami fails, before touching the helper', async () => {
    let helperCalls = 0;
    const result = await verifyDescriptorAcl(DESCRIPTOR_PATH, {
      systemRoot: 'C:\\Windows',
      runProcess: (exe) => {
        if (exe.toLowerCase().includes('whoami')) {
          return Promise.resolve({ ok: false });
        }
        helperCalls += 1;
        return Promise.resolve({ ok: true, stdout: DESCRIPTOR_SNAPSHOT });
      },
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: false, reason: CONTROL_ANCHOR_REJECTION.WHOAMI_FAILED });
    expect(helperCalls).toBe(0);
  });

  it('applies the descriptor policy (SYSTEM required), not the anchor policy', async () => {
    const result = await verifyDescriptorAcl(DESCRIPTOR_PATH, {
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }])),
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: false, reason: CONTROL_ANCHOR_REJECTION.SYSTEM_PRINCIPAL_ABSENT });
  });
});

/* ---- enumeration, sweep, discovery (pure, injected probe) ------------------- */

function seeded(count: number): { anchor: ReturnType<typeof memAnchor>; ids: string[]; pipes: string[] } {
  const anchor = memAnchor(ANCHOR);
  const ids: string[] = [];
  const pipes: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const minted = createRuntimeDescriptor();
    anchor.set(minted.runtimeId, serializeDescriptor(minted.descriptor));
    ids.push(minted.runtimeId);
    pipes.push(pipePathFromName(minted.descriptor.pipeName));
  }
  return { anchor, ids, pipes };
}

describe('D062 candidate enumeration — bounded, exact-name, deterministic', () => {
  it('lists only identity-named files, sorted by id, and reports the cap as truncation', () => {
    const { anchor, ids } = seeded(3);
    anchor.setRaw('runtime-descriptor.json', '{}');
    anchor.setRaw('notes.txt', 'x');
    anchor.setRaw(`runtime-descriptor-${HEX32.toUpperCase()}.json`, '{}');
    const result = enumerateDescriptorCandidates(ANCHOR, anchor.deps);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(false);
    expect(result.candidates.map((candidate) => candidate.runtimeId)).toEqual([...ids].sort());
    expect(result.candidates.map((candidate) => candidate.path)).toEqual(
      [...ids].sort().map((id) => descriptorPathFor(ANCHOR, id)),
    );
  });

  it('caps the candidate set and flags truncation', () => {
    const { anchor } = seeded(MAX_DESCRIPTOR_CANDIDATES + 1);
    const result = enumerateDescriptorCandidates(ANCHOR, anchor.deps);
    expect(result.ok && result.truncated).toBe(true);
    expect(result.ok && result.candidates.length).toBe(MAX_DESCRIPTOR_CANDIDATES);
  });

  it('an unlistable anchor is a failure, not an empty set', () => {
    expect(enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => { throw new Error('EACCES'); } })).toEqual({ ok: false });
  });

  it('readDescriptorCandidate requires name/content consistency', () => {
    const { anchor, ids } = seeded(2);
    const [a, b] = ids;
    if (a === undefined || b === undefined) {
      return;
    }
    // Put B's contents under A's name.
    anchor.set(a, anchor.get(b) ?? '');
    const candidate = { runtimeId: a, filename: descriptorFilenameFor(a), path: descriptorPathFor(ANCHOR, a) };
    expect(readDescriptorCandidate(candidate, anchor.deps).kind).toBe('malformed');
    const good = { runtimeId: b, filename: descriptorFilenameFor(b), path: descriptorPathFor(ANCHOR, b) };
    expect(readDescriptorCandidate(good, anchor.deps).kind).toBe('valid');
  });
});

describe('D062 stale sweep — only ABSENT pipes authorize removal of exactly that file', () => {
  it('removes dead files, keeps PRESENT/UNKNOWN/malformed files, skips the own id', async () => {
    const { anchor, ids, pipes } = seeded(4);
    const [dead, live, unknown, own] = ids;
    const [deadPipe, livePipe, unknownPipe] = pipes;
    if (dead === undefined || live === undefined || unknown === undefined || own === undefined) {
      return;
    }
    anchor.setRaw(descriptorFilenameFor('a'.repeat(32)), '{ nope');
    const removed: string[] = [];
    const deps = { ...anchor.deps, removeFile: (path: string): void => { removed.push(path); anchor.deps.removeFile?.(path); } };
    const result = await sweepStaleDescriptors(
      ANCHOR,
      own,
      tableProbe({ [deadPipe ?? '']: 'ABSENT', [livePipe ?? '']: 'PRESENT', [unknownPipe ?? '']: 'UNKNOWN' }, 'ABSENT'),
      deps,
    );
    expect(result.examined).toBe(4); // dead, live, unknown, malformed — never own
    expect(result.removed).toEqual([dead]);
    expect([...result.retained].sort()).toEqual([live, unknown].sort());
    expect(result.malformed).toEqual(['a'.repeat(32)]);
    expect(result.unremovable).toEqual([]);
    expect(removed).toEqual([descriptorPathFor(ANCHOR, dead)]);
    expect(anchor.get(own)).not.toBeNull();
    expect(anchor.get(live)).not.toBeNull();
    expect(anchor.get(unknown)).not.toBeNull();
  });

  it('reports a dead file whose unlink fails as unremovable and leaves it', async () => {
    const { anchor, ids } = seeded(1);
    const result = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, { ...anchor.deps, removeFile: () => { throw new Error('EACCES'); } });
    expect(result.unremovable).toEqual(ids);
    expect(result.removed).toEqual([]);
  });

  it('an unlistable anchor sweeps nothing', async () => {
    const result = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, { listAnchor: () => { throw new Error('EACCES'); } });
    expect(result).toEqual({ examined: 0, removed: [], retained: [], malformed: [], unremovable: [] });
  });

  it('never probes a malformed or mismatched file (no pipe to prove dead, nothing to delete)', async () => {
    const { anchor, ids } = seeded(2);
    const [a, b] = ids;
    if (a === undefined || b === undefined) {
      return;
    }
    anchor.set(a, anchor.get(b) ?? ''); // mismatch under A's name
    const probed: string[] = [];
    const result = await sweepStaleDescriptors(ANCHOR, null, (path) => { probed.push(path); return Promise.resolve('ABSENT'); }, anchor.deps);
    expect(probed).toEqual([pipePathFromName(pipeNameForRuntimeId(b))]);
    expect(result.malformed).toEqual([a]);
    expect(result.removed).toEqual([b]);
    expect(anchor.get(a)).not.toBeNull();
  });
});

describe('D062 discovery — deterministic selection over bounded candidates', () => {
  it('zero candidates → UNAVAILABLE NO_CANDIDATES', async () => {
    const anchor = memAnchor(ANCHOR);
    const result = await discoverControlRuntime(ANCHOR, allAbsentProbe, anchor.deps);
    expect(result).toEqual({ kind: 'UNAVAILABLE', reason: DISCOVERY_UNAVAILABLE.NO_CANDIDATES, counts: { candidates: 0, malformed: 0, live: 0, dead: 0, unknown: 0 } });
  });

  it('exactly one live candidate → FOUND with that descriptor and token', async () => {
    const { anchor, ids, pipes } = seeded(1);
    const result = await discoverControlRuntime(ANCHOR, tableProbe({ [pipes[0] ?? '']: 'PRESENT' }), anchor.deps);
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.runtimeId).toBe(ids[0]);
      expect(result.parsed.token.equals(parseDescriptor(anchor.get(ids[0] ?? ''))?.token ?? Buffer.alloc(0))).toBe(true);
    }
  });

  it('two live candidates → AMBIGUOUS, none chosen', async () => {
    const { anchor, ids } = seeded(2);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), anchor.deps);
    expect(result.kind).toBe('AMBIGUOUS');
    if (result.kind === 'AMBIGUOUS') {
      expect([...result.live].sort()).toEqual([...ids].sort());
    }
  });

  it('stale + live → the live one; dead candidates are counted, never chosen, never removed', async () => {
    const { anchor, ids, pipes } = seeded(3);
    const result = await discoverControlRuntime(ANCHOR, tableProbe({ [pipes[1] ?? '']: 'PRESENT' }, 'ABSENT'), anchor.deps);
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.runtimeId).toBe(ids[1]);
      expect(result.counts).toEqual({ candidates: 3, malformed: 0, live: 1, dead: 2, unknown: 0 });
    }
    expect(anchor.removeCalls()).toBe(0);
  });

  it('malformed + live → the live one; malformed never blocks', async () => {
    const { anchor, ids, pipes } = seeded(1);
    anchor.setRaw(descriptorFilenameFor('0'.repeat(32)), '{ nope');
    anchor.setRaw(descriptorFilenameFor('1'.repeat(32)), anchor.get(ids[0] ?? '') ?? ''); // mismatch
    const result = await discoverControlRuntime(ANCHOR, tableProbe({ [pipes[0] ?? '']: 'PRESENT' }), anchor.deps);
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.counts.malformed).toBe(2);
    }
  });

  it('only UNKNOWN candidates → UNAVAILABLE NO_LIVE_CANDIDATES (never a guess)', async () => {
    const { anchor } = seeded(2);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('UNKNOWN'), anchor.deps);
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.NO_LIVE_CANDIDATES);
      expect(result.counts.unknown).toBe(2);
    }
  });

  it('one PRESENT + one UNKNOWN → AMBIGUOUS, never FOUND (UNKNOWN is not proven dead)', async () => {
    const { anchor, pipes } = seeded(2);
    const result = await discoverControlRuntime(
      ANCHOR,
      tableProbe({ [pipes[0] ?? '']: 'PRESENT', [pipes[1] ?? '']: 'UNKNOWN' }),
      anchor.deps,
    );
    expect(result.kind).toBe('AMBIGUOUS');
    expect(result.counts.live).toBe(1);
    expect(result.counts.unknown).toBe(1);
  });

  it('one PRESENT + multiple UNKNOWN → AMBIGUOUS, never FOUND', async () => {
    const { anchor, pipes } = seeded(3);
    const result = await discoverControlRuntime(
      ANCHOR,
      tableProbe(
        { [pipes[0] ?? '']: 'PRESENT', [pipes[1] ?? '']: 'UNKNOWN', [pipes[2] ?? '']: 'UNKNOWN' },
      ),
      anchor.deps,
    );
    expect(result.kind).toBe('AMBIGUOUS');
    expect(result.counts.live).toBe(1);
    expect(result.counts.unknown).toBe(2);
  });

  it('one PRESENT with every other candidate proven ABSENT → FOUND (unique path intact)', async () => {
    const { anchor, ids, pipes } = seeded(3);
    const result = await discoverControlRuntime(
      ANCHOR,
      tableProbe({ [pipes[1] ?? '']: 'PRESENT' }, 'ABSENT'),
      anchor.deps,
    );
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.runtimeId).toBe(ids[1]);
      expect(result.counts).toEqual({ candidates: 3, malformed: 0, live: 1, dead: 2, unknown: 0 });
    }
  });

  it('two PRESENT (no UNKNOWN) → AMBIGUOUS (existing multi-live behavior unchanged)', async () => {
    const { anchor, ids } = seeded(2);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), anchor.deps);
    expect(result.kind).toBe('AMBIGUOUS');
    if (result.kind === 'AMBIGUOUS') {
      expect([...result.live].sort()).toEqual([...ids].sort());
      expect(result.counts.unknown).toBe(0);
    }
  });

  it('only UNKNOWN (no PRESENT) → UNAVAILABLE NO_LIVE_CANDIDATES (zero-live behavior preserved)', async () => {
    const { anchor } = seeded(1);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('UNKNOWN'), anchor.deps);
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.NO_LIVE_CANDIDATES);
      expect(result.counts.unknown).toBe(1);
    }
  });

  it('an unreadable anchor → UNAVAILABLE ANCHOR_UNREADABLE', async () => {
    const result = await discoverControlRuntime(ANCHOR, allAbsentProbe, { listAnchor: () => { throw new Error('EACCES'); } });
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.ANCHOR_UNREADABLE);
    }
  });

  it('more candidates than the cap → UNAVAILABLE TOO_MANY_CANDIDATES before any probe', async () => {
    const { anchor } = seeded(MAX_DESCRIPTOR_CANDIDATES + 1);
    let probes = 0;
    const result = await discoverControlRuntime(ANCHOR, () => { probes += 1; return Promise.resolve('PRESENT'); }, anchor.deps);
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.TOO_MANY_CANDIDATES);
    }
    expect(probes).toBe(0);
  });

  it('selection is independent of file order, mtime, and lexicographic position', async () => {
    const { anchor, ids, pipes } = seeded(3);
    // Reverse the listing order; the chosen runtime is still the live one.
    const reversed = { ...anchor.deps, listAnchor: (dir: string): readonly string[] => [...(anchor.deps.listAnchor?.(dir) ?? [])].reverse() };
    for (const index of [0, 1, 2]) {
      const result = await discoverControlRuntime(ANCHOR, tableProbe({ [pipes[index] ?? '']: 'PRESENT' }, 'ABSENT'), reversed);
      expect(result.kind).toBe('FOUND');
      if (result.kind === 'FOUND') {
        expect(result.parsed.runtimeId).toBe(ids[index]);
      }
    }
  });
});

/* ---- real pipe probe -------------------------------------------------------- */

const servers: net.Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => closeServer(server)));
});

describe('D062 defaultPipeProbe — kernel pipe namespace liveness', () => {
  it('answers ABSENT for a pipe nobody serves and PRESENT for a real listener', async () => {
    const probe = defaultPipeProbe(1500);
    const minted = createRuntimeDescriptor();
    const pipePath = pipePathFromName(minted.descriptor.pipeName);
    expect(await probe(pipePath)).toBe('ABSENT');
    const server = net.createServer((socket) => {
      socket.on('error', () => {
        /* ignore */
      });
    });
    servers.push(server);
    await new Promise<void>((resolvePromise) => {
      server.listen(pipePath, resolvePromise);
    });
    expect(await probe(pipePath)).toBe('PRESENT');
    await closeServer(server);
    servers.splice(servers.indexOf(server), 1);
    expect(await probe(pipePath)).toBe('ABSENT');
  });
});

/* ---- creator gate (injected runner) ----------------------------------------- */

describe('D062 descriptor creator gate — createDescriptorFileNative (injected)', () => {
  const CREATOR_SHA = 'e'.repeat(64);
  const CREATOR_ABS = 'C:\\app\\dist\\control\\native\\agentbridge-win-descriptor-create.exe';
  const CREATOR_BYTES = Buffer.from('creator-bytes');
  interface RecordedRun {
    readonly exe: string;
    readonly args: readonly string[];
    readonly input: Buffer;
  }
  function creatorDeps(runs: RecordedRun[] = [], overrides: Partial<DescriptorCreatorDeps> = {}): DescriptorCreatorDeps {
    const runCreator: CreatorRunner = (exe, args, input) => {
      runs.push({ exe, args, input });
      return Promise.resolve({ ok: true });
    };
    return {
      loadProvenance: () => Promise.resolve({ filename: 'agentbridge-win-descriptor-create.exe', sha256: CREATOR_SHA }),
      resolveCreatorPath: () => CREATOR_ABS,
      readCreatorBytes: () => CREATOR_BYTES,
      hashBytes: () => CREATOR_SHA,
      runCreator,
      ...overrides,
    };
  }
  const minted = createRuntimeDescriptor();
  const payload = Buffer.from(serializeDescriptor(minted.descriptor), 'utf8');

  it('runs the hash-verified creator with exactly [anchor, runtimeId] and the bytes on stdin — the token is never an argument', async () => {
    const runs: RecordedRun[] = [];
    const result = await createDescriptorFileNative(FAKE_ANCHOR, minted.runtimeId, payload, creatorDeps(runs));
    expect(result).toEqual({ ok: true });
    expect(runs).toHaveLength(1);
    expect(runs[0]?.exe).toBe(CREATOR_ABS);
    expect(runs[0]?.args).toEqual([FAKE_ANCHOR, minted.runtimeId]);
    expect(runs[0]?.input.equals(payload)).toBe(true);
    expect(runs[0]?.args.join(' ')).not.toContain(minted.descriptor.token);
  });

  it('4/5. rejects a malformed runtime id before loading provenance or running anything', async () => {
    for (const bad of ['', 'runtime-descriptor.json', `..\\${HEX32.slice(3)}`, HEX32.toUpperCase(), `${HEX32}/x`]) {
      let loads = 0;
      const runs: RecordedRun[] = [];
      const result = await createDescriptorFileNative(FAKE_ANCHOR, bad, payload, creatorDeps(runs, {
        loadProvenance: () => { loads += 1; return Promise.resolve({ filename: 'x.exe', sha256: CREATOR_SHA }); },
      }));
      expect(result, bad).toEqual({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.RUNTIME_ID_MALFORMED });
      expect(loads).toBe(0);
      expect(runs).toHaveLength(0);
    }
  });

  it('rejects an empty or over-cap payload before running anything', async () => {
    const runs: RecordedRun[] = [];
    expect(await createDescriptorFileNative(FAKE_ANCHOR, minted.runtimeId, Buffer.alloc(0), creatorDeps(runs))).toEqual({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.DESCRIPTOR_TOO_LARGE });
    expect(await createDescriptorFileNative(FAKE_ANCHOR, minted.runtimeId, Buffer.alloc(MAX_DESCRIPTOR_BYTES + 1, 1), creatorDeps(runs))).toEqual({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.DESCRIPTOR_TOO_LARGE });
    expect(runs).toHaveLength(0);
  });

  it.each([
    ['provenance absent', { loadProvenance: () => Promise.resolve(null) }, DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING],
    ['provenance hash malformed', { loadProvenance: () => Promise.resolve({ filename: 'x.exe', sha256: 'nope' }) }, DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING],
    ['provenance filename with separator', { loadProvenance: () => Promise.resolve({ filename: '..\\x.exe', sha256: CREATOR_SHA }) }, DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING],
    ['creator missing', { readCreatorBytes: () => null }, DESCRIPTOR_CREATION_REJECTION.CREATOR_MISSING],
    ['hash mismatch', { hashBytes: () => 'f'.repeat(64) }, DESCRIPTOR_CREATION_REJECTION.CREATOR_HASH_MISMATCH],
  ] as const)('fails closed without running: %s', async (_label, overrides, expected) => {
    const runs: RecordedRun[] = [];
    const result = await createDescriptorFileNative(FAKE_ANCHOR, minted.runtimeId, payload, creatorDeps(runs, overrides));
    expect(result).toEqual({ ok: false, reason: expected });
    expect(runs).toHaveLength(0);
  });

  it('passes the runner\'s failure reason through unchanged', async () => {
    for (const reason of [
      DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED,
      DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT,
      DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
    ] as const) {
      const result = await createDescriptorFileNative(FAKE_ANCHOR, minted.runtimeId, payload, creatorDeps([], {
        runCreator: () => Promise.resolve({ ok: false, reason }),
      }));
      expect(result).toEqual({ ok: false, reason });
    }
  });

  it('the creator provenance comes only from its own generated module (never the owner helper\'s, env, or a sidecar)', async () => {
    // No injected loader: the default module-relative creator provenance import is
    // used; in this src test context it does not exist, so the gate fails closed.
    const result = await createDescriptorFileNative(FAKE_ANCHOR, minted.runtimeId, payload, {
      resolveCreatorPath: () => CREATOR_ABS,
      readCreatorBytes: () => CREATOR_BYTES,
      hashBytes: () => CREATOR_SHA,
      runCreator: () => Promise.resolve({ ok: true }),
    });
    expect(result).toEqual({ ok: false, reason: DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING });
  });
});
