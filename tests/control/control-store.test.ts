import { closeSync, mkdtempSync, openSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  publicKeyFromVerifyKey,
  signServerResult,
  verifyServerResult,
} from '../../src/control/control-auth.js';
import {
  CONTROL_ANCHOR_REJECTION,
  DESCRIPTOR_CREATION_REJECTION,
  DISCOVERY_UNAVAILABLE,
  MAX_ANCHOR_ENTRIES,
  MAX_DESCRIPTOR_BYTES,
  MAX_DESCRIPTOR_CANDIDATES,
  createDescriptorFileNative,
  createRuntimeDescriptor,
  defaultCreatorRunner,
  defaultOpenDescriptor,
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
  type ControlAnchorRejection,
  type CreatorRunner,
  type DescriptorAclVerification,
  type DescriptorCreatorDeps,
  type DescriptorFileDeps,
  type DescriptorHandle,
  type LstatProbe,
  type OperatorIdentity,
  type OwnerVerifierDeps,
  type ProcessResult,
  type ProcessRunner,
} from '../../src/control/control-store.js';
import {
  FAKE_ANCHOR,
  allAbsentProbe,
  closeServer,
  memAnchor,
  mintRuntime,
  tableProbe,
} from './support.js';

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

describe('D062 descriptor model v3', () => {
  const mint = (): ReturnType<typeof mintRuntime> => mintRuntime();

  it('mints a 256-bit token, a 128-bit runtime id, a pipe name carrying that id, and a verify key — no PID', () => {
    const { parsed, keyPair } = mint();
    const { descriptor, token, runtimeId, verifyKey } = parsed;
    expect(token.length).toBe(32);
    expect(isRuntimeId(runtimeId)).toBe(true);
    expect(descriptor.pipeName).toBe(`agentbridge-control-${runtimeId}`);
    expect(descriptor.version).toBe(3);
    expect(Object.keys(descriptor)).toEqual(['version', 'pipeName', 'token', 'verifyKey']);
    expect('pid' in descriptor).toBe(false);
    expect('proof' in descriptor).toBe(false);
    expect(verifyKey.equals(keyPair.verifyKey)).toBe(true);
  });

  it('refuses to mint around a malformed verify key', () => {
    expect(() => createRuntimeDescriptor(Buffer.alloc(31))).toThrow(TypeError);
    expect(() => createRuntimeDescriptor(Buffer.alloc(33))).toThrow(TypeError);
  });

  it('rotates the token and runtime id every mint', () => {
    const a = mint().parsed;
    const b = mint().parsed;
    expect(a.token.equals(b.token)).toBe(false);
    expect(a.runtimeId).not.toBe(b.runtimeId);
    expect(a.descriptor.token).not.toBe(b.descriptor.token);
  });

  it('round-trips through serialize/parse with the same token, verify key and derived id', () => {
    const { descriptor, token, runtimeId, verifyKey } = mint().parsed;
    const parsed = parseDescriptor(serializeDescriptor(descriptor));
    expect(parsed).not.toBeNull();
    expect(parsed?.token.equals(token)).toBe(true);
    expect(parsed?.verifyKey.equals(verifyKey)).toBe(true);
    expect(parsed?.descriptor.pipeName).toBe(descriptor.pipeName);
    expect(parsed?.runtimeId).toBe(runtimeId);
  });

  it('REJECTS a version-2 descriptor — no downgrade, no dual-accept', () => {
    const { descriptor } = mint().parsed;
    // The exact pre-amendment shape.
    expect(
      parseDescriptor(
        JSON.stringify({
          version: 2,
          pipeName: descriptor.pipeName,
          token: descriptor.token,
        }),
      ),
    ).toBeNull();
    // v2 carrying the withdrawn anchor-secret proof binding.
    expect(
      parseDescriptor(
        JSON.stringify({
          version: 2,
          pipeName: descriptor.pipeName,
          token: descriptor.token,
          proof: Buffer.alloc(32, 3).toString('base64url'),
        }),
      ),
    ).toBeNull();
    // A v3-shaped body whose version is anything but 3.
    for (const version of [1, 2, 4, '3', null, true]) {
      expect(parseDescriptor(JSON.stringify({ ...descriptor, version }))).toBeNull();
    }
  });

  it('rejects malformed / legacy / oversized descriptors', () => {
    const { descriptor } = mint().parsed;
    expect(parseDescriptor('not json')).toBeNull();
    expect(parseDescriptor('[]')).toBeNull();
    expect(parseDescriptor(JSON.stringify({ version: 3, pipeName: 'x', token: 'y', verifyKey: 'z' }))).toBeNull();
    // Legacy v1 shape (pid-bearing).
    expect(
      parseDescriptor(
        JSON.stringify({ version: 1, pid: 1, pipeName: descriptor.pipeName, token: descriptor.token }),
      ),
    ).toBeNull();
    // Extra field / missing field.
    expect(parseDescriptor(JSON.stringify({ ...descriptor, pid: 7 }))).toBeNull();
    expect(parseDescriptor(JSON.stringify({ ...descriptor, proof: 'x' }))).toBeNull();
    const withoutKey: Record<string, unknown> = { ...descriptor };
    delete withoutKey['verifyKey'];
    expect(parseDescriptor(JSON.stringify(withoutKey))).toBeNull();
    // Malformed pipe name (uppercase id).
    expect(
      parseDescriptor(JSON.stringify({ ...descriptor, pipeName: descriptor.pipeName.toUpperCase() })),
    ).toBeNull();
    // Short token (16 bytes) and wrong-width verify key.
    expect(
      parseDescriptor(JSON.stringify({ ...descriptor, token: Buffer.alloc(16, 1).toString('base64url') })),
    ).toBeNull();
    for (const width of [0, 16, 31, 33, 64]) {
      expect(
        parseDescriptor(
          JSON.stringify({ ...descriptor, verifyKey: Buffer.alloc(width, 1).toString('base64url') }),
        ),
      ).toBeNull();
    }
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
      lstat: okLstat,
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
      lstat: okLstat,
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
      lstat: okLstat,
      runProcess: runnerFor(snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }])),
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: false, reason: CONTROL_ANCHOR_REJECTION.SYSTEM_PRINCIPAL_ABSENT });
  });

  it('F2. rejects a symlink/reparse descriptor before running any subprocess (the helper follows links)', async () => {
    let processCalls = 0;
    const result = await verifyDescriptorAcl(DESCRIPTOR_PATH, {
      systemRoot: 'C:\\Windows',
      lstat: () => ({ isSymbolicLink: true, isReparsePoint: false }),
      runProcess: () => {
        processCalls += 1;
        return Promise.resolve({ ok: true, stdout: WHOAMI });
      },
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: false, reason: CONTROL_ANCHOR_REJECTION.REPARSE_POINT });
    expect(processCalls).toBe(0);
  });

  it('F2. fails closed (never open) when the descriptor path cannot be lstat-ed', async () => {
    const result = await verifyDescriptorAcl(DESCRIPTOR_PATH, {
      systemRoot: 'C:\\Windows',
      lstat: () => null,
      runProcess: runnerFor(DESCRIPTOR_SNAPSHOT),
      owner: passingOwnerDeps,
    });
    expect(result).toEqual({ ok: false, reason: CONTROL_ANCHOR_REJECTION.COMPONENT_UNREADABLE });
  });
});

/* ---- enumeration, sweep, discovery (pure, injected probe) ------------------- */

function seeded(count: number): { anchor: ReturnType<typeof memAnchor>; ids: string[]; pipes: string[] } {
  const anchor = memAnchor(ANCHOR);
  const ids: string[] = [];
  const pipes: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const minted = mintRuntime().parsed;
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

  /**
   * A lazily yielded list of `count` distinct identity-named filenames whose
   * iteration is metered, so a test can prove enumeration stops early rather than
   * consuming and materializing every matching name. Typed as the array the deps
   * expect; it is only ever iterated by the function under test.
   */
  function countingDescriptorNames(count: number, meter: { consumed: number }): readonly string[] {
    return {
      [Symbol.iterator](): Iterator<string> {
        let index = 0;
        return {
          next(): IteratorResult<string> {
            if (index >= count) {
              return { done: true, value: undefined };
            }
            meter.consumed += 1;
            const id = index.toString(16).padStart(32, '0');
            index += 1;
            return { done: false, value: `runtime-descriptor-${id}.json` };
          },
        };
      },
    } as unknown as readonly string[];
  }

  it('EXACT CAP: exactly MAX matching filenames is not truncated and returns them all', () => {
    const { anchor } = seeded(MAX_DESCRIPTOR_CANDIDATES);
    const result = enumerateDescriptorCandidates(ANCHOR, anchor.deps);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(false);
    expect(result.candidates.length).toBe(MAX_DESCRIPTOR_CANDIDATES);
  });

  it('CAP + 1: truncated with the returned set bounded at MAX', () => {
    const { anchor } = seeded(MAX_DESCRIPTOR_CANDIDATES + 1);
    const result = enumerateDescriptorCandidates(ANCHOR, anchor.deps);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(true);
    expect(result.candidates.length).toBeLessThanOrEqual(MAX_DESCRIPTOR_CANDIDATES);
  });

  it('bounds the WORK: a very large matching input stops after the truncation witness', () => {
    const meter = { consumed: 0 };
    const huge = MAX_DESCRIPTOR_CANDIDATES * 1000;
    const result = enumerateDescriptorCandidates(ANCHOR, {
      listAnchor: () => countingDescriptorNames(huge, meter),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(true);
    expect(result.candidates.length).toBeLessThanOrEqual(MAX_DESCRIPTOR_CANDIDATES);
    // The collection/sort never touched more than MAX + 1 matching candidates:
    // iteration stopped at the truncation witness, not at `huge`.
    expect(meter.consumed).toBeLessThanOrEqual(MAX_DESCRIPTOR_CANDIDATES + 1);
  });

  it('non-matching noise never consumes candidate capacity', () => {
    const noise: string[] = [];
    for (let i = 0; i < MAX_DESCRIPTOR_CANDIDATES * 10; i += 1) {
      noise.push(`not-a-descriptor-${String(i)}.txt`);
    }
    const realIds = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
    const listed = [...noise, ...realIds.map((id) => descriptorFilenameFor(id))];
    const result = enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => listed });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(false);
    expect(result.candidates.map((candidate) => candidate.runtimeId).sort()).toEqual([...realIds].sort());
  });

  it('DETERMINISTIC ORDER: a within-cap set is returned sorted by runtime id', () => {
    const { anchor, ids } = seeded(5);
    const result = enumerateDescriptorCandidates(ANCHOR, anchor.deps);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(false);
    expect(result.candidates.map((candidate) => candidate.runtimeId)).toEqual([...ids].sort());
  });

  it('an unlistable anchor is a failure, not an empty set', () => {
    expect(enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => { throw new Error('EACCES'); } })).toEqual({ ok: false, reason: 'unreadable' });
  });

  it('a listing error mid-iteration still fails closed as unreadable', () => {
    // The incremental listing throws after a few entries (models a directory that
    // becomes unreadable while being read); enumeration must fail closed, not
    // return a partial candidate set.
    function* throwingAfter(count: number): IterableIterator<string> {
      for (let i = 0; i < count; i += 1) {
        yield `not-a-descriptor-${String(i)}.txt`;
      }
      throw new Error('EIO');
    }
    expect(enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => throwingAfter(3) })).toEqual({
      ok: false,
      reason: 'unreadable',
    });
  });

  it('FINDING 2 — huge non-matching directory fails closed (overfull) with bounded scan', () => {
    const meter = { consumed: 0 };
    // Far more entries than the total-entry cap, none matching.
    const huge = MAX_ANCHOR_ENTRIES * 100;
    function* names(): IterableIterator<string> {
      for (let i = 0; i < huge; i += 1) {
        meter.consumed += 1;
        yield `junk-${String(i)}`;
      }
    }
    const result = enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => names() });
    expect(result).toEqual({ ok: false, reason: 'overfull' });
    // Bounded WORK: the scan stopped at the total-entry witness, not at `huge`.
    expect(meter.consumed).toBeLessThanOrEqual(MAX_ANCHOR_ENTRIES + 1);
  });

  it('FINDING 2 — huge mixed directory still stops at the total-entry bound', () => {
    const meter = { consumed: 0 };
    const huge = MAX_ANCHOR_ENTRIES * 100;
    // A few valid candidates buried far beyond the total-entry cap.
    const realIds = ['a'.repeat(32), 'b'.repeat(32)];
    function* names(): IterableIterator<string> {
      for (let i = 0; i < huge; i += 1) {
        meter.consumed += 1;
        yield `junk-${String(i)}`;
      }
      for (const id of realIds) {
        meter.consumed += 1;
        yield descriptorFilenameFor(id);
      }
    }
    const result = enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => names() });
    expect(result).toEqual({ ok: false, reason: 'overfull' });
    expect(meter.consumed).toBeLessThanOrEqual(MAX_ANCHOR_ENTRIES + 1);
  });

  it('FINDING 2 — a directory within the total-entry cap enumerates normally', () => {
    const noise: string[] = [];
    for (let i = 0; i < MAX_ANCHOR_ENTRIES - 10; i += 1) {
      noise.push(`junk-${String(i)}.txt`);
    }
    const realIds = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
    const listed = [...noise, ...realIds.map((id) => descriptorFilenameFor(id))];
    const result = enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => listed });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(false);
    expect(result.candidates.map((candidate) => candidate.runtimeId).sort()).toEqual([...realIds].sort());
  });

  it('FINDING 2 — the candidate cap still trips before the total-entry cap when matches dominate', () => {
    // MAX + 1 matching candidates (well under the total-entry cap): still truncated.
    const listed: string[] = [];
    for (let i = 0; i < MAX_DESCRIPTOR_CANDIDATES + 1; i += 1) {
      listed.push(descriptorFilenameFor(i.toString(16).padStart(32, '0')));
    }
    const result = enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => listed });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.truncated).toBe(true);
    expect(result.candidates.length).toBeLessThanOrEqual(MAX_DESCRIPTOR_CANDIDATES);
  });

  it('FINDING 2 — discovery fails closed (ANCHOR_OVERFULL) without probing an over-full anchor', async () => {
    let probes = 0;
    const huge = MAX_ANCHOR_ENTRIES * 100;
    function* names(): IterableIterator<string> {
      for (let i = 0; i < huge; i += 1) {
        yield `junk-${String(i)}`;
      }
    }
    const result = await discoverControlRuntime(
      ANCHOR,
      () => {
        probes += 1;
        return Promise.resolve('PRESENT');
      },
      { listAnchor: () => names() },
    );
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.ANCHOR_OVERFULL);
    }
    expect(probes).toBe(0);
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

  it('an unlistable anchor sweeps nothing and reports enumeration unreadable', async () => {
    const result = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, { listAnchor: () => { throw new Error('EACCES'); } });
    expect(result).toEqual({ enumeration: 'unreadable', scanned: 0, examined: 0, removed: [], retained: [], malformed: [], unremovable: [] });
  });

  it('FINDING 2 — enumeration reports the exact scanned entry count and the sweep propagates it', async () => {
    // Complete enumeration: `scanned` equals the exact directory entries consumed.
    const noise: string[] = [];
    for (let index = 0; index < 5; index += 1) {
      noise.push(`junk-${String(index)}.txt`);
    }
    const realIds = ['a'.repeat(32), 'b'.repeat(32), 'c'.repeat(32)];
    const listed = [...noise, ...realIds.map((id) => descriptorFilenameFor(id))];
    const enumeration = enumerateDescriptorCandidates(ANCHOR, { listAnchor: () => listed });
    expect(enumeration.ok).toBe(true);
    if (enumeration.ok) {
      expect(enumeration.truncated).toBe(false);
      expect(enumeration.scanned).toBe(listed.length); // 5 junk + 3 candidates = 8
    }
    // The sweep carries the SAME scanned count out of the one pass (no re-enumeration).
    const anchor = memAnchor(ANCHOR);
    for (const id of realIds) {
      anchor.set(
        id,
        serializeDescriptor({
          version: 3,
          pipeName: pipeNameForRuntimeId(id),
          token: 'x',
          verifyKey: 'y',
        }),
      );
    }
    for (const name of noise) {
      anchor.setRaw(name, 'x');
    }
    const sweep = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, anchor.deps);
    expect(sweep.enumeration).toBe('complete');
    expect(sweep.scanned).toBe(listed.length); // + the reserved anchor secret entry (never a candidate)
    // Incomplete branches report scanned = 0; callers never rely on it there.
    const unreadable = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, { listAnchor: () => { throw new Error('EACCES'); } });
    expect(unreadable.scanned).toBe(0);
    const truncated = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, seeded(MAX_DESCRIPTOR_CANDIDATES + 1).anchor.deps);
    expect(truncated.enumeration).toBe('truncated');
    expect(truncated.scanned).toBe(0);
  });

  it('exposes enumeration completeness: unreadable vs truncated vs complete', async () => {
    // Unreadable anchor → enumeration 'unreadable', nothing swept.
    const unreadable = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, { listAnchor: () => { throw new Error('EACCES'); } });
    expect(unreadable.enumeration).toBe('unreadable');
    expect(unreadable.examined).toBe(0);

    // Over the candidate cap → enumeration 'truncated', and NOTHING is removed
    // (the visible set is not the whole anchor, so no deadness decision is made).
    const big = seeded(MAX_DESCRIPTOR_CANDIDATES + 1).anchor;
    const truncated = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, big.deps);
    expect(truncated.enumeration).toBe('truncated');
    expect(truncated.examined).toBe(0);
    expect(truncated.removed).toEqual([]);
    expect(big.removeCalls()).toBe(0);

    // Readable and within the cap → enumeration 'complete', normal sweep runs.
    const small = seeded(2).anchor;
    const complete = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, small.deps);
    expect(complete.enumeration).toBe('complete');
    expect(complete.examined).toBe(2);
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
    expect(result).toEqual({ kind: 'UNAVAILABLE', reason: DISCOVERY_UNAVAILABLE.NO_CANDIDATES, counts: { candidates: 0, unverified: 0, malformed: 0, live: 0, dead: 0, unknown: 0 } });
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
      expect(result.counts).toEqual({ candidates: 3, unverified: 0, malformed: 0, live: 1, dead: 2, unknown: 0 });
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
      expect(result.counts).toEqual({ candidates: 3, unverified: 0, malformed: 0, live: 1, dead: 2, unknown: 0 });
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
    const minted = mintRuntime().parsed;
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
  const minted = mintRuntime().parsed;
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
      DESCRIPTOR_CREATION_REJECTION.CREATOR_WROTE_THEN_FAILED,
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

/* ------------------------------------------------------------------------- *
 * The production creator runner — terminal-cause precedence
 *
 * `defaultCreatorRunner` owns the ONE `execFile` call of the create path and
 * maps its settlement to a fail-closed reason. Only `CREATOR_WROTE_THEN_FAILED`
 * ever authorizes the runtime to unlink its own minted descriptor path, so the
 * mapping is security-relevant and is exercised here through the real runner
 * with `execFile` itself stubbed at the module seam (no production surface is
 * widened for this). The shapes below are exactly what Node hands the callback.
 * ------------------------------------------------------------------------- */

type ExecFileCallback = (error: Error | null, stdout: Buffer, stderr: Buffer) => void;
interface FakeStdin {
  on(event: string, listener: (error: Error) => void): FakeStdin;
  end(input: Buffer): void;
}
interface FakeChild {
  readonly stdin: FakeStdin | null;
}
type FakeExecFile = (
  exe: string,
  args: readonly string[],
  options: Record<string, unknown>,
  callback: ExecFileCallback,
) => FakeChild;

const childProcessSeam = vi.hoisted(() => ({ execFile: null as FakeExecFile | null }));

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  const passthrough = actual.execFile as unknown as (...params: unknown[]) => unknown;
  return {
    ...actual,
    execFile: (...params: unknown[]): unknown => {
      const override = childProcessSeam.execFile;
      if (override === null) {
        return passthrough(...params);
      }
      const [exe, args, options, callback] = params as Parameters<FakeExecFile>;
      return override(exe, args, options, callback);
    },
  };
});

describe('D062 creator runner — terminal-cause precedence (real runner, execFile settlement stubbed)', () => {
  interface Recorded {
    exe: string;
    args: readonly string[];
    options: Record<string, unknown>;
    input: Buffer | null;
  }
  type Settlement = Record<string, unknown> | null;

  afterEach(() => {
    childProcessSeam.execFile = null;
  });

  /**
   * Install a settlement: the fake child accepts stdin, then settles the callback
   * asynchronously (as a real child would) with `null` or an Error carrying the
   * given fields. `throwSync` models Windows rejecting the image synchronously.
   */
  const arm = (settlement: Settlement, mode: { throwSync?: boolean; noStdin?: boolean } = {}): Recorded => {
    const recorded: Recorded = { exe: '', args: [], options: {}, input: null };
    childProcessSeam.execFile = (exe, args, options, callback) => {
      recorded.exe = exe;
      recorded.args = args;
      recorded.options = options;
      if (mode.throwSync === true) {
        throw new Error('spawn EINVAL');
      }
      const stdin: FakeStdin = {
        on: () => stdin,
        end: (input: Buffer): void => {
          recorded.input = input;
        },
      };
      queueMicrotask(() => {
        callback(settlement === null ? null : Object.assign(new Error('settled'), settlement), Buffer.alloc(0), Buffer.alloc(0));
      });
      return { stdin: mode.noStdin === true ? null : stdin };
    };
    return recorded;
  };

  const EXE = 'C:\\app\\dist\\control\\native\\agentbridge-win-descriptor-create.exe';
  const runner = defaultCreatorRunner('C:\\Windows');
  const minted = mintRuntime().parsed;
  const payload = Buffer.from(serializeDescriptor(minted.descriptor), 'utf8');
  const MAXBUFFER = 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER';
  const R = DESCRIPTOR_CREATION_REJECTION;

  it('uses the bounded, shell-free transport and delivers the descriptor on stdin only', async () => {
    const recorded = arm(null);
    expect(await runner(EXE, [FAKE_ANCHOR, minted.runtimeId], payload)).toEqual({ ok: true });
    expect(recorded.exe).toBe(EXE);
    expect(recorded.args).toEqual([FAKE_ANCHOR, minted.runtimeId]);
    expect(recorded.args.join(' ')).not.toContain(minted.descriptor.token);
    expect(recorded.input?.equals(payload)).toBe(true);
    expect(recorded.options['shell']).toBe(false);
    expect(recorded.options['windowsHide']).toBe(true);
    expect(recorded.options['encoding']).toBe('buffer');
    expect(recorded.options['cwd']).toBe(join('C:\\Windows', 'System32'));
    expect(recorded.options['env']).toEqual({ SystemRoot: 'C:\\Windows', windir: 'C:\\Windows' });
    const timeout = recorded.options['timeout'];
    const maxBuffer = recorded.options['maxBuffer'];
    expect(typeof timeout === 'number' && Number.isFinite(timeout) && timeout > 0).toBe(true);
    expect(typeof maxBuffer === 'number' && Number.isFinite(maxBuffer) && maxBuffer > 0).toBe(true);
  });

  it.each<[string, Settlement, string]>([
    // 1. an output overrun is an output fault, whatever else is set
    ['maxBuffer overrun', { code: MAXBUFFER }, R.CREATOR_FAILED],
    ['maxBuffer overrun with the deadline flag also set', { code: MAXBUFFER, killed: true, signal: 'SIGTERM' }, R.CREATOR_FAILED],
    // 2. a numeric exit is the child's own final word — BEFORE the deadline flag
    ['exit 6, not killed', { code: 6, killed: false, signal: null }, R.CREATOR_WROTE_THEN_FAILED],
    ['FINDING — exit 6 with killed=true (exit landed while this loop was stalled across the deadline)', { code: 6, killed: true, signal: null }, R.CREATOR_WROTE_THEN_FAILED],
    ['exit 5 (CREATE_NEW collision), not killed', { code: 5, killed: false, signal: null }, R.CREATOR_FAILED],
    ['exit 5 with killed=true', { code: 5, killed: true, signal: null }, R.CREATOR_FAILED],
    ['exit 1 with killed=true', { code: 1, killed: true, signal: null }, R.CREATOR_FAILED],
    ['exit 4 (stdin refused)', { code: 4, killed: false, signal: null }, R.CREATOR_FAILED],
    // 3. killed on the deadline without a numeric exit
    ['deadline kill (Windows shape)', { code: null, killed: true, signal: 'SIGTERM' }, R.CREATOR_TIMEOUT],
    ['deadline kill, minimal shape', { killed: true }, R.CREATOR_TIMEOUT],
    // 4. a foreign signal without a numeric exit proves nothing
    ['foreign SIGKILL', { code: null, killed: false, signal: 'SIGKILL' }, R.CREATOR_FAILED],
    // 5. the process never started
    ['spawn ENOENT', { code: 'ENOENT', syscall: 'spawn', errno: -4058 }, R.CREATOR_SPAWN_FAILED],
    ['spawn EACCES', { code: 'EACCES', syscall: 'spawn' }, R.CREATOR_SPAWN_FAILED],
    ['bare error', {}, R.CREATOR_SPAWN_FAILED],
  ])('%s', async (_label, settlement, expected) => {
    arm(settlement);
    expect(await runner(EXE, [FAKE_ANCHOR, minted.runtimeId], payload)).toEqual({ ok: false, reason: expected });
  });

  it('a synchronous spawn rejection is a spawn failure, never a throw', async () => {
    arm(null, { throwSync: true });
    expect(await runner(EXE, [FAKE_ANCHOR, minted.runtimeId], payload)).toEqual({ ok: false, reason: R.CREATOR_SPAWN_FAILED });
  });

  it('a child without a stdin pipe is still judged by its own settlement', async () => {
    arm({ code: 4, killed: false, signal: null }, { noStdin: true });
    expect(await runner(EXE, [FAKE_ANCHOR, minted.runtimeId], payload)).toEqual({ ok: false, reason: R.CREATOR_FAILED });
  });

  it('only exit 6 maps to the one reason that authorizes cleanup of the minted path', async () => {
    for (let code = 0; code <= 8; code += 1) {
      arm({ code, killed: code % 2 === 0, signal: null });
      const result = await runner(EXE, [FAKE_ANCHOR, minted.runtimeId], payload);
      if (code === 6) {
        expect(result).toEqual({ ok: false, reason: R.CREATOR_WROTE_THEN_FAILED });
      } else {
        expect(result, `exit ${String(code)}`).toEqual({ ok: false, reason: R.CREATOR_FAILED });
      }
    }
  });
});

describe('D062 F2 — discovery security-verifies each candidate before its token is read', () => {
  const DESCRIPTOR_OK = snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]);
  type Gate = (path: string) => Promise<DescriptorAclVerification>;

  /**
   * Deps that log every CANDIDATE gate call and read, in order. The reserved
   * anchor secret (a genuine creator-born file in every fixture here) passes the
   * gate and is not logged, so each assertion below is about the candidate only;
   */
  function logged(anchor: ReturnType<typeof memAnchor>, gate: Gate, log: string[]): DescriptorFileDeps {
    return {
      ...anchor.deps,
      readFile: (path: string): string => {
        log.push(`read:${path}`);
        return anchor.deps.readFile?.(path) ?? '';
      },
      verifyDescriptor: (path: string): Promise<DescriptorAclVerification> => {
        log.push(`verify:${path}`);
        return gate(path);
      },
    };
  }

  /** The REAL gate (`verifyDescriptorAcl`) fed a fixed helper snapshot. */
  function realGate(stdout: string, lstat: LstatProbe = okLstat): Gate {
    return (path: string): Promise<DescriptorAclVerification> =>
      verifyDescriptorAcl(path, { systemRoot: 'C:\\Windows', lstat, runProcess: runnerFor(stdout), owner: passingOwnerDeps });
  }

  /** A gate rejecting exactly `badPath` with `reason`, passing everything else. */
  function rejecting(badPath: string, reason: ControlAnchorRejection): Gate {
    return (path: string): Promise<DescriptorAclVerification> =>
      Promise.resolve(path === badPath ? { ok: false, reason } : { ok: true });
  }

  it('1/7/12. a valid-ACL live descriptor is discovered through the real gate, in the order verify → read → probe', async () => {
    const { anchor, ids, pipes } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const log: string[] = [];
    const probe = (pipePath: string): Promise<'PRESENT'> => {
      log.push(`probe:${pipePath}`);
      return Promise.resolve('PRESENT');
    };
    const result = await discoverControlRuntime(ANCHOR, probe, logged(anchor, realGate(DESCRIPTOR_OK), log));
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.runtimeId).toBe(ids[0]);
      expect(result.counts).toEqual({ candidates: 1, unverified: 0, malformed: 0, live: 1, dead: 0, unknown: 0 });
    }
    expect(log).toEqual([`verify:${path}`, `read:${path}`, `probe:${pipes[0] ?? ''}`]);
  });

  it.each([
    ['2. foreign owner', snapshot('S-1-5-21-999-888-777-2002', [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }])],
    ['2b. SYSTEM owner', snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }])],
    ['3. unprotected DACL', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }], 'PRESENT', false)],
    ['3b. NULL DACL', snapshot(OPERATOR_SID, [], 'NULL')],
    ['4. foreign principal', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }, { sid: 'S-1-1-0' }])],
    ['4b. inherited ACE', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID, flags: 0x10 }, { sid: SYSTEM_SID }])],
    ['4c. SYSTEM absent (not creator-made)', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }])],
    ['4d. malformed helper output', 'garbage\n'],
  ])('%s → unverified: never read, never probed, NO_VERIFIED_CANDIDATES', async (_label, stdout) => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const log: string[] = [];
    let probes = 0;
    const result = await discoverControlRuntime(
      ANCHOR,
      () => {
        probes += 1;
        return Promise.resolve('PRESENT'); // the attacker IS serving the pipe
      },
      logged(anchor, realGate(stdout), log),
    );
    expect(result).toEqual({
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.NO_VERIFIED_CANDIDATES,
      counts: { candidates: 1, unverified: 1, malformed: 0, live: 0, dead: 0, unknown: 0 },
    });
    expect(log).toEqual([`verify:${path}`]); // the gate ran; the token was never read
    expect(probes).toBe(0);
    expect(anchor.removeCalls()).toBe(0);
  });

  it('5. a symlink/reparse descriptor is rejected by the real gate before any subprocess, read, or probe', async () => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const log: string[] = [];
    let processCalls = 0;
    const gate: Gate = (candidate: string) =>
      verifyDescriptorAcl(candidate, {
        systemRoot: 'C:\\Windows',
        lstat: () => ({ isSymbolicLink: true, isReparsePoint: false }),
        runProcess: () => {
          processCalls += 1;
          return Promise.resolve({ ok: true, stdout: WHOAMI });
        },
        owner: passingOwnerDeps,
      });
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), logged(anchor, gate, log));
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.NO_VERIFIED_CANDIDATES);
      expect(result.counts.unverified).toBe(1);
    }
    expect(log).toEqual([`verify:${path}`]);
    expect(processCalls).toBe(0);
  });

  it('6/10. a protocol-valid bad-ACL descriptor with a PRESENT pipe is never a live runtime and never suppresses the verified one', async () => {
    const { anchor, ids } = seeded(2);
    const [bad, good] = ids;
    const badPath = descriptorPathFor(ANCHOR, bad ?? '');
    const goodPath = descriptorPathFor(ANCHOR, good ?? '');
    const log: string[] = [];
    // Both pipes PRESENT: pre-repair this was AMBIGUOUS (attacker DoS) or, alone, FOUND (attacker chosen).
    const result = await discoverControlRuntime(
      ANCHOR,
      () => Promise.resolve('PRESENT'),
      logged(anchor, rejecting(badPath, CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH), log),
    );
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.runtimeId).toBe(good);
      expect(result.parsed.token.equals(parseDescriptor(anchor.get(good ?? ''))?.token ?? Buffer.alloc(0))).toBe(true);
      expect(result.counts).toEqual({ candidates: 2, unverified: 1, malformed: 0, live: 1, dead: 0, unknown: 0 });
    }
    expect(log.filter((entry) => entry.endsWith(badPath))).toEqual([`verify:${badPath}`]);
    expect(log.filter((entry) => entry.endsWith(goodPath))).toEqual([`verify:${goodPath}`, `read:${goodPath}`]);
  });

  it('8. two verified live candidates remain AMBIGUOUS', async () => {
    const { anchor, ids } = seeded(2);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), logged(anchor, realGate(DESCRIPTOR_OK), []));
    expect(result.kind).toBe('AMBIGUOUS');
    if (result.kind === 'AMBIGUOUS') {
      expect([...result.live].sort()).toEqual([...ids].sort());
      expect(result.counts.unverified).toBe(0);
    }
  });

  it('9. an unverified candidate beside a verified DEAD one → NO_LIVE_CANDIDATES, nothing removed', async () => {
    const { anchor, ids } = seeded(2);
    const badPath = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const result = await discoverControlRuntime(
      ANCHOR,
      allAbsentProbe,
      logged(anchor, rejecting(badPath, CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED), []),
    );
    expect(result).toEqual({
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.NO_LIVE_CANDIDATES,
      counts: { candidates: 2, unverified: 1, malformed: 0, live: 0, dead: 1, unknown: 0 },
    });
    expect(anchor.removeCalls()).toBe(0);
  });

  it('11. UNKNOWN stays fail-closed: verified PRESENT + verified UNKNOWN → AMBIGUOUS; unverified + UNKNOWN → UNAVAILABLE', async () => {
    const { anchor, ids, pipes } = seeded(2);
    const firstPath = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const probe = tableProbe({ [pipes[0] ?? '']: 'PRESENT', [pipes[1] ?? '']: 'UNKNOWN' });
    const allVerified = await discoverControlRuntime(ANCHOR, probe, logged(anchor, realGate(DESCRIPTOR_OK), []));
    expect(allVerified.kind).toBe('AMBIGUOUS');
    const mixed = await discoverControlRuntime(
      ANCHOR,
      probe,
      logged(anchor, rejecting(firstPath, CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH), []),
    );
    expect(mixed).toEqual({
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.NO_LIVE_CANDIDATES,
      counts: { candidates: 2, unverified: 1, malformed: 0, live: 0, dead: 0, unknown: 1 },
    });
  });

  it('the gate cannot be bypassed by omission: no injected verifier ⇒ the real fail-closed gate runs and nothing is read', async () => {
    const { anchor } = seeded(1);
    const { verifyDescriptor: omitted, ...withoutGate } = anchor.deps;
    void omitted;
    const reads: string[] = [];
    let probes = 0;
    const result = await discoverControlRuntime(
      ANCHOR,
      () => {
        probes += 1;
        return Promise.resolve('PRESENT');
      },
      {
        ...withoutGate,
        readFile: (path: string): string => {
          reads.push(path);
          return withoutGate.readFile?.(path) ?? '';
        },
      },
    );
    // No real file exists at the fake paths, so the real gate fails closed at
    // lstat — first on the anchor secret, before any candidate is even gated.
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.NO_VERIFIED_CANDIDATES);
    }
    expect(reads).toEqual([]);
    expect(probes).toBe(0);
  });

  it('stale sweep semantics are distinct and unchanged: the sweep never consults the gate and still removes only ABSENT files', async () => {
    const { anchor, ids } = seeded(2);
    const log: string[] = [];
    const gate: Gate = () => Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH });
    const result = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, logged(anchor, gate, log));
    expect(log.some((entry) => entry.startsWith('verify:'))).toBe(false);
    expect([...result.removed].sort()).toEqual([...ids].sort());
  });
});

describe('D062 F2 stable object — the gate and the read share ONE held descriptor handle', () => {
  type Gate = (path: string) => Promise<DescriptorAclVerification>;
  interface HeldStore {
    readonly deps: DescriptorFileDeps;
    readonly log: string[];
    /** Overwrite a stored file "from outside" (the attacker's retained writer). */
    overwrite(path: string, text: string): void;
    openCount(path: string): number;
    closeCount(path: string): number;
  }

  /**
   * An opener that models exclusive holding faithfully: the handle's contents are
   * fixed at open time (nothing can write to a held file), the store logs
   * open/verify/read/close in order, and `busy` paths cannot be held (EBUSY).
   */
  function heldStore(anchor: ReturnType<typeof memAnchor>, gate: Gate, busy: readonly string[] = []): HeldStore {
    const log: string[] = [];
    const opens = new Map<string, number>();
    const closes = new Map<string, number>();
    const bump = (map: Map<string, number>, path: string): void => {
      map.set(path, (map.get(path) ?? 0) + 1);
    };
    const { readFile: storeRead, ...rest } = anchor.deps;
    const readNow = (path: string): string => storeRead?.(path) ?? '';
    return {
      log,
      overwrite: (path: string, text: string): void => {
        anchor.setRaw(basename(path), text);
      },
      openCount: (path: string): number => opens.get(path) ?? 0,
      closeCount: (path: string): number => closes.get(path) ?? 0,
      deps: {
        ...rest,
        // No readFile: discovery MUST go through the opener; the sweep still may not.
        openDescriptor: (path: string): DescriptorHandle => {
          if (busy.includes(path)) {
            const error = new Error('EBUSY: resource busy or locked') as NodeJS.ErrnoException;
            error.code = 'EBUSY';
            throw error;
          }
          bump(opens, path);
          log.push(`open:${path}`);
          const held = readNow(path); // the bytes of the object being held
          return {
            read: (): string => {
              log.push(`read:${path}`);
              return held;
            },
            close: (): void => {
              bump(closes, path);
              log.push(`close:${path}`);
            },
          };
        },
        verifyDescriptor: (path: string): Promise<DescriptorAclVerification> => {
          log.push(`verify:${path}`);
          return gate(path);
        },
      },
    };
  }

  const pass: Gate = () => Promise.resolve({ ok: true });
  /** The anchor secret is held → gated → read → released FIRST, before any candidate. */
  /** A gate applying `verdict` to exactly one candidate path and passing the secret. */
  const only = (path: string, verdict: () => Promise<DescriptorAclVerification>): Gate => (p: string) =>
    p === path ? verdict() : Promise.resolve({ ok: true });

  it('holds the candidate across the gate: open → verify → read → close, exactly once, then probe', async () => {
    const { anchor, ids, pipes } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const store = heldStore(anchor, pass);
    const result = await discoverControlRuntime(
      ANCHOR,
      (pipePath: string) => {
        store.log.push(`probe:${pipePath}`);
        return Promise.resolve('PRESENT');
      },
      store.deps,
    );
    expect(result.kind).toBe('FOUND');
    expect(store.log).toEqual([`open:${path}`, `verify:${path}`, `read:${path}`, `close:${path}`, `probe:${pipes[0] ?? ''}`]);
    expect(store.openCount(path)).toBe(1);
    expect(store.closeCount(path)).toBe(1);
  });

  it('the token used is the held object\'s, not a later pathname lookup: an overwrite after the ACL check is never trusted', async () => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const genuine = parseDescriptor(anchor.get(ids[0] ?? ''));
    const forged = mintRuntime().parsed;
    // A forged descriptor under the SAME runtime id / pipe name but a different token.
    const forgedText = serializeDescriptor({ ...forged.descriptor, pipeName: genuine?.descriptor.pipeName ?? '' });
    let store: HeldStore | null = null;
    const gate: Gate = (gatedPath: string) => {
      // The attacker "passes" the check on the candidate, then rewrites the pathname's contents.
      if (gatedPath === path) {
        store?.overwrite(path, forgedText);
      }
      return Promise.resolve({ ok: true });
    };
    store = heldStore(anchor, gate);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), store.deps);
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.token.equals(genuine?.token ?? Buffer.alloc(0))).toBe(true);
      expect(result.parsed.token.equals(parseDescriptor(forgedText)?.token ?? Buffer.alloc(0))).toBe(false);
    }
    // And the pathname really does hold the forged bytes now — only the held object was trusted.
    expect(anchor.get(ids[0] ?? '')).toBe(forgedText);
  });

  it('the pre-repair verify-then-reopen sequence is gone: after a passing gate the read comes from the held handle, never readFile', async () => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const store = heldStore(anchor, pass);
    let pathReads = 0;
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), {
      ...store.deps,
      readFile: (): string => {
        pathReads += 1;
        throw new Error('a fresh pathname read must never happen after the gate');
      },
    });
    expect(result.kind).toBe('FOUND');
    expect(pathReads).toBe(0);
    expect(store.log).toEqual([`open:${path}`, `verify:${path}`, `read:${path}`, `close:${path}`]);
  });

  it('a candidate that cannot be held (EBUSY) is unverified: no gate, no read, no probe, NO_VERIFIED_CANDIDATES', async () => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const store = heldStore(anchor, pass, [path]);
    let probes = 0;
    const result = await discoverControlRuntime(
      ANCHOR,
      () => {
        probes += 1;
        return Promise.resolve('PRESENT');
      },
      store.deps,
    );
    expect(result).toEqual({
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.NO_VERIFIED_CANDIDATES,
      counts: { candidates: 1, unverified: 1, malformed: 0, live: 0, dead: 0, unknown: 0 },
    });
    expect(store.log).toEqual([]); // the candidate itself: no gate, no read, no close
    expect(probes).toBe(0);
    expect(anchor.removeCalls()).toBe(0);
  });

  it('a failed gate closes the held handle without reading it: the token is never taken from an unverified object', async () => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const store = heldStore(anchor, only(path, () => Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH })));
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), store.deps);
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.reason).toBe(DISCOVERY_UNAVAILABLE.NO_VERIFIED_CANDIDATES);
    }
    expect(store.log).toEqual([`open:${path}`, `verify:${path}`, `close:${path}`]);
  });

  it('a gate that throws still releases the handle (finally), and the error propagates as before', async () => {
    const { anchor, ids } = seeded(1);
    const path = descriptorPathFor(ANCHOR, ids[0] ?? '');
    const store = heldStore(anchor, only(path, () => Promise.reject(new Error('helper transport failed'))));
    await expect(discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), store.deps)).rejects.toThrow(
      'helper transport failed',
    );
    expect(store.closeCount(path)).toBe(1);
  });

  it('a held read that fails is malformed (never a live runtime), and the handle is released', async () => {
    const { anchor } = seeded(1);
    const store = heldStore(anchor, pass);
    let closed = 0;
    const heldOpener = store.deps.openDescriptor;
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), {
      ...store.deps,
      openDescriptor: (): DescriptorHandle => {
        void heldOpener;
        return {
          read: (): string => {
            throw new Error('EIO');
          },
          close: (): void => {
            closed += 1;
          },
        };
      },
    });
    expect(result).toEqual({
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.NO_LIVE_CANDIDATES,
      counts: { candidates: 1, unverified: 0, malformed: 1, live: 0, dead: 0, unknown: 0 },
    });
    expect(closed).toBe(1);
  });

  it('held contents whose runtime id disagrees with the filename are still malformed (validity rule unchanged)', async () => {
    const { anchor, ids } = seeded(2);
    const [first, second] = ids;
    // Put the second runtime\'s (valid) text under the first runtime\'s filename.
    anchor.set(first ?? '', anchor.get(second ?? '') ?? '');
    anchor.remove(second ?? '');
    const store = heldStore(anchor, pass);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), store.deps);
    expect(result.kind).toBe('UNAVAILABLE');
    if (result.kind === 'UNAVAILABLE') {
      expect(result.counts).toEqual({ candidates: 1, unverified: 0, malformed: 1, live: 0, dead: 0, unknown: 0 });
    }
  });

  it('two held, verified, live candidates remain AMBIGUOUS; each opened and closed exactly once', async () => {
    const { anchor, ids } = seeded(2);
    const store = heldStore(anchor, pass);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), store.deps);
    expect(result.kind).toBe('AMBIGUOUS');
    if (result.kind === 'AMBIGUOUS') {
      expect([...result.live].sort()).toEqual([...ids].sort());
    }
    for (const id of ids) {
      const path = descriptorPathFor(ANCHOR, id);
      expect(store.openCount(path)).toBe(1);
      expect(store.closeCount(path)).toBe(1);
    }
  });

  it('a busy candidate beside a held live one: the live one is FOUND, the busy one counted unverified', async () => {
    const { anchor, ids } = seeded(2);
    const [busy, good] = ids;
    const store = heldStore(anchor, pass, [descriptorPathFor(ANCHOR, busy ?? '')]);
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), store.deps);
    expect(result.kind).toBe('FOUND');
    if (result.kind === 'FOUND') {
      expect(result.parsed.runtimeId).toBe(good);
      expect(result.counts).toEqual({ candidates: 2, unverified: 1, malformed: 0, live: 1, dead: 0, unknown: 0 });
    }
  });

  it('the opener cannot be bypassed by omission: no opener and no readFile ⇒ the real exclusive opener, and a passing gate is never even consulted for an unholdable path', async () => {
    const { anchor } = seeded(1);
    const { readFile: omittedRead, verifyDescriptor: omittedGate, ...rest } = anchor.deps;
    void omittedRead;
    void omittedGate;
    let gateCalls = 0;
    const result = await discoverControlRuntime(ANCHOR, () => Promise.resolve('PRESENT'), {
      ...rest,
      verifyDescriptor: (): Promise<DescriptorAclVerification> => {
        gateCalls += 1;
        return Promise.resolve({ ok: true });
      },
    });
    // No real file exists at the fake paths: the real opener throws ENOENT on the
    // anchor secret first, so discovery fails closed before any candidate is held.
    expect(result).toEqual({
      kind: 'UNAVAILABLE',
      reason: DISCOVERY_UNAVAILABLE.NO_VERIFIED_CANDIDATES,
      counts: { candidates: 1, unverified: 1, malformed: 0, live: 0, dead: 0, unknown: 0 },
    });
    expect(gateCalls).toBe(0);
  });

  it('stale sweep semantics unchanged: the sweep never opens through the opener and still removes only ABSENT files', async () => {
    const { anchor, ids } = seeded(2);
    let opens = 0;
    const result = await sweepStaleDescriptors(ANCHOR, null, allAbsentProbe, {
      ...anchor.deps,
      openDescriptor: (): DescriptorHandle => {
        opens += 1;
        throw new Error('the sweep must not use the discovery opener');
      },
    });
    expect(opens).toBe(0);
    expect([...result.removed].sort()).toEqual([...ids].sort());
  });

  describe('defaultOpenDescriptor — the real handle', () => {
    let dir: string | null = null;
    afterEach(() => {
      if (dir !== null) {
        rmSync(dir, { recursive: true, force: true });
        dir = null;
      }
    });
    const file = (text: string): string => {
      dir = mkdtempSync(join(tmpdir(), 'ab-held-'));
      const path = join(dir, 'runtime-descriptor-00000000000000000000000000000001.json');
      writeFileSync(path, text);
      return path;
    };

    it('reads the held file\'s bounded contents and throws ENOENT for an absent path (never a silent empty read)', () => {
      const path = file('{"held":true}');
      const handle = defaultOpenDescriptor(path);
      try {
        expect(handle.read()).toBe('{"held":true}');
      } finally {
        handle.close();
      }
      expect(() => defaultOpenDescriptor(join(dir ?? '', 'missing.json'))).toThrow(/ENOENT/);
    });

    it('is bounded like the plain reader: at most MAX_DESCRIPTOR_BYTES + 1 bytes are ever read', () => {
      const path = file('x'.repeat(MAX_DESCRIPTOR_BYTES + 100));
      const handle = defaultOpenDescriptor(path);
      try {
        expect(handle.read().length).toBe(MAX_DESCRIPTOR_BYTES + 1);
      } finally {
        handle.close();
      }
    });

    it.skipIf(process.platform !== 'win32')(
      'win32: a retained writer handle makes the open fail (EBUSY) — the legacy-ACL overwrite race cannot start',
      () => {
        const path = file('{"v":1}');
        const writer = openSync(path, 'r+');
        try {
          expect(() => defaultOpenDescriptor(path)).toThrow(/EBUSY/);
        } finally {
          closeSync(writer);
        }
        // Released ⇒ holdable again.
        defaultOpenDescriptor(path).close();
      },
    );

    it.skipIf(process.platform !== 'win32')(
      'win32: while held, no one can open the file for write or read, or unlink it; its bytes are fixed until close',
      () => {
        const path = file('{"v":1}');
        const handle = defaultOpenDescriptor(path);
        try {
          expect(() => openSync(path, 'r+')).toThrow(/EBUSY/);
          expect(() => openSync(path, 'r')).toThrow(/EBUSY/);
          expect(() => { unlinkSync(path); }).toThrow(/EBUSY/);
          expect(() => { writeFileSync(path, '{"v":2}'); }).toThrow(/EBUSY/);
          expect(handle.read()).toBe('{"v":1}');
        } finally {
          handle.close();
        }
        writeFileSync(path, '{"v":2}');
        const again = defaultOpenDescriptor(path);
        try {
          expect(again.read()).toBe('{"v":2}');
        } finally {
          again.close();
        }
      },
    );
  });
});

/* ---- runtime authentication: the descriptor publishes an identity, not a proof ---- */

describe('D062 runtime authentication — the descriptor carries a public identity only', () => {
  it('a descriptor is a hint, not a credential: everything in it is safe to read', () => {
    const { parsed, keyPair } = mintRuntime();
    const text = serializeDescriptor(parsed.descriptor);
    // The only secret in the file is the token (client-to-server authorization).
    // The verify key is public by construction and the private key is absent.
    expect(text).toContain(parsed.descriptor.verifyKey);
    expect(text).not.toContain('PRIVATE');
    const exported = keyPair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64url');
    expect(text).not.toContain(exported);
  });

  it('a COPIED descriptor yields no signing capability — CI-2, unconditional', () => {
    const { parsed, keyPair } = mintRuntime();
    // Exactly what a copier gets: the serialized bytes, re-parsed.
    const copy = parseDescriptor(serializeDescriptor(parsed.descriptor));
    expect(copy).not.toBeNull();
    expect(copy?.verifyKey.equals(keyPair.verifyKey)).toBe(true);
    const identity = {
      runtimeId: parsed.runtimeId,
      pipeName: parsed.descriptor.pipeName,
    };
    const nonceS = Buffer.alloc(32, 1);
    const nonceC = Buffer.alloc(32, 2);
    const command = Buffer.from('OPEN_HUMAN_GATE', 'utf8');
    const result = Buffer.from('APPLIED', 'utf8');
    // The genuine holder can sign; the copy can only verify.
    const genuine = signServerResult(keyPair.privateKey, identity, nonceS, nonceC, command, result);
    expect(
      verifyServerResult(copy?.verifyKey ?? Buffer.alloc(0), identity, nonceS, nonceC, command, result, genuine),
    ).toBe(true);
    // Nothing derivable from the copy produces a second valid signature.
    const asPublic = publicKeyFromVerifyKey(copy?.verifyKey ?? Buffer.alloc(0));
    expect(asPublic?.type).toBe('public');
    expect(() =>
      signServerResult(asPublic as never, identity, nonceS, nonceC, command, result),
    ).toThrow();
  });

  it('two runtimes in one anchor publish independent identities', () => {
    const a = mintRuntime().parsed;
    const b = mintRuntime().parsed;
    expect(a.verifyKey.equals(b.verifyKey)).toBe(false);
    expect(a.token.equals(b.token)).toBe(false);
    expect(a.runtimeId).not.toBe(b.runtimeId);
  });

  it('discovery has no anchor-secret failure mode left', () => {
    expect(Object.keys(DISCOVERY_UNAVAILABLE)).toEqual([
      'ANCHOR_UNREADABLE',
      'NO_CANDIDATES',
      'NO_LIVE_CANDIDATES',
      'NO_VERIFIED_CANDIDATES',
      'TOO_MANY_CANDIDATES',
      'ANCHOR_OVERFULL',
    ]);
  });
});
