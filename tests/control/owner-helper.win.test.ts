/**
 * Real Windows integration for the Decision 062 control-anchor helper.
 *
 * Unlike the pure/injected tests in control-store.test.ts, this exercises the
 * ACTUAL compiled helper binary through the production code path: it imports the
 * built `dist/control/control-store.js` and calls `verifyAnchorSnapshot` with no
 * injected deps, so the default provenance load (the generated JS metadata beside
 * the binary), the SHA-256 hash gate, and the real bounded `execFile` transport
 * all run for real against `dist/control/native/agentbridge-win-owner.exe`.
 *
 * It proves both helper modes on the real binary: the F1 owner-only mode
 * (backward compatible) and the Amendment B `--acl` canonical OWNER + DACL
 * snapshot — whose SIDs are canonical and therefore locale-independent (SYSTEM
 * appears as S-1-5-18, never the localized "NT AUTHORITY\SYSTEM").
 *
 * It is gated to win32 with a built dist + helper. On Linux CI, or before
 * `npm run build && npm run helper:build`, the whole suite is skipped — its
 * behaviour cannot be proven cross-platform and is not asserted there.
 */

import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import type {
  AclSnapshot,
  OperatorIdentity,
  ProcessRunner,
} from '../../src/control/control-store.js';
import { newOrchestrator } from './support.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const distStore = join(repoRoot, 'dist', 'control', 'control-store.js');
const distRuntime = join(repoRoot, 'dist', 'control', 'control-runtime.js');
const exePath = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-owner.exe');
const provPath = join(repoRoot, 'dist', 'control', 'native', 'owner-helper-provenance.js');

const creatorPath = join(
  repoRoot,
  'dist',
  'control',
  'native',
  'agentbridge-win-descriptor-create.exe',
);
const creatorProvPath = join(
  repoRoot,
  'dist',
  'control',
  'native',
  'descriptor-creator-provenance.js',
);

const ready =
  process.platform === 'win32' &&
  existsSync(distStore) &&
  existsSync(distRuntime) &&
  existsSync(exePath) &&
  existsSync(provPath);

/** The creator suite additionally needs the create-only artifact and its provenance. */
const creatorReady = ready && existsSync(creatorPath) && existsSync(creatorProvPath);

type StoreModule = typeof import('../../src/control/control-store.js');
type RuntimeModule = typeof import('../../src/control/control-runtime.js');

const CANONICAL_SID = /^s-1-\d+(?:-\d+)+$/;
const SYSTEM_SID = 's-1-5-18';
/** BUILTIN\Administrators — the default owner an ELEVATED token hands a new file. */
const ADMINISTRATORS_SID = 's-1-5-32-544';

describe.skipIf(!ready)('D062 control helper — real Windows binary integration', () => {
  const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
  let store!: StoreModule;
  let runtime!: RuntimeModule;
  let operator!: OperatorIdentity;
  let runner!: ProcessRunner;

  const readNativeAclSnapshot = async (target: string): Promise<AclSnapshot> => {
    const result = await runner(exePath, ['--acl', target]);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(`native ACL snapshot failed for ${target}`);
    }
    const snapshot = store.parseAclSnapshot(result.stdout);
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      throw new Error(`native ACL snapshot was malformed for ${target}`);
    }
    return snapshot;
  };

  const establishAnchorAcl = async (
    anchor: string,
    operatorAccess: 'F' | 'M',
  ): Promise<AclSnapshot> => {
    const icacls = join(systemRoot, 'System32', 'icacls.exe');
    const ownerSet = await runner(icacls, [anchor, '/setowner', `*${operator.sid}`]);
    expect(ownerSet.ok).toBe(true);

    const inheritanceRemoved = await runner(icacls, [anchor, '/inheritance:r']);
    expect(inheritanceRemoved.ok).toBe(true);

    // /grant:r only replaces ALLOW entries for the named principal. Discover and
    // remove every surviving explicit ALLOW or DENY entry by canonical SID so an
    // ambient explicit temp-directory ACE cannot leak into this fixture.
    const inheritedAcl = await readNativeAclSnapshot(anchor);
    expect(inheritedAcl.ownerSid).toBe(operator.sid);
    expect(inheritedAcl.daclProtected).toBe(true);
    expect(inheritedAcl.aces.every((ace) => (ace.flags & 0x10) === 0)).toBe(true);
    const removals = new Map<string, { readonly type: 'ALLOW' | 'DENY'; readonly sid: string }>();
    for (const ace of inheritedAcl.aces) {
      removals.set(`${ace.type}:${ace.sid}`, { type: ace.type, sid: ace.sid });
    }
    for (const removal of [...removals.values()].sort((left, right) =>
      `${left.type}:${left.sid}`.localeCompare(`${right.type}:${right.sid}`),
    )) {
      const removed = await runner(icacls, [
        anchor,
        removal.type === 'ALLOW' ? '/remove:g' : '/remove:d',
        `*${removal.sid}`,
      ]);
      expect(removed.ok).toBe(true);
    }

    const granted = await runner(icacls, [
      anchor,
      '/grant:r',
      `*${operator.sid}:(OI)(CI)${operatorAccess}`,
      '*S-1-5-18:(OI)(CI)F',
    ]);
    expect(granted.ok).toBe(true);

    const finalAcl = await readNativeAclSnapshot(anchor);
    expect(finalAcl.ownerSid).toBe(operator.sid);
    expect(finalAcl.daclState).toBe('PRESENT');
    expect(finalAcl.daclProtected).toBe(true);
    expect(finalAcl.aces).toHaveLength(2);
    expect(new Set(finalAcl.aces.map((ace) => ace.sid))).toEqual(
      new Set([operator.sid, SYSTEM_SID]),
    );
    expect(finalAcl.aces.every((ace) => ace.type === 'ALLOW')).toBe(true);
    expect(finalAcl.aces.every((ace) => ace.flags === 0x03)).toBe(true);
    expect(store.evaluateAnchorSnapshot(operator, finalAcl)).toEqual({ ok: true });
    return finalAcl;
  };

  beforeAll(async () => {
    store = (await import(pathToFileURL(distStore).href)) as StoreModule;
    runtime = (await import(pathToFileURL(distRuntime).href)) as RuntimeModule;
    runner = store.defaultProcessRunner(systemRoot);
    const whoami = await runner(join(systemRoot, 'System32', 'whoami.exe'), ['/user']);
    if (!whoami.ok) {
      throw new Error('whoami failed in integration setup');
    }
    const parsed = store.parseWhoamiUser(whoami.stdout);
    if (parsed === null) {
      throw new Error('could not parse operator identity in integration setup');
    }
    operator = parsed;
  });

  it('generated provenance hash matches the exact compiled binary (no sidecar, no env)', () => {
    const actual = createHash('sha256').update(readFileSync(exePath)).digest('hex');
    const provText = readFileSync(provPath, 'utf8');
    const match = /sha256:\s*"([0-9a-f]{64})"/.exec(provText);
    expect(match?.[1]).toBe(actual);
  });

  it('F1 owner-only mode still returns exactly one canonical owner SID', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-owner-'));
    const owned = await runner(exePath, [dir]);
    expect(owned.ok).toBe(true);
    if (owned.ok) {
      const sid = store.parseOwnerHelperSid(owned.stdout);
      expect(sid).not.toBeNull();
      expect(sid).toMatch(CANONICAL_SID);
    }
  });

  it('--acl mode returns a canonical OWNER + DACL snapshot (locale-independent)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-acl-'));

    // Both modes read the same object; cross-check that the --acl owner equals the
    // owner-only mode's SID (one security truth source, two views agree).
    const ownerOnly = await runner(exePath, [dir]);
    expect(ownerOnly.ok).toBe(true);
    const ownerOnlySid = ownerOnly.ok ? store.parseOwnerHelperSid(ownerOnly.stdout) : null;

    const acl = await runner(exePath, ['--acl', dir]);
    expect(acl.ok).toBe(true);
    if (!acl.ok) {
      return;
    }
    const snapshot = store.parseAclSnapshot(acl.stdout);
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      return;
    }

    // Owner: canonical, and identical to the owner-only mode.
    expect(snapshot.ownerSid).toMatch(CANONICAL_SID);
    expect(snapshot.ownerSid).toBe(ownerOnlySid);

    // A real temp directory has a present, non-empty DACL.
    expect(snapshot.daclState).toBe('PRESENT');
    expect(typeof snapshot.daclProtected).toBe('boolean');
    expect(snapshot.aces.length).toBeGreaterThanOrEqual(1);

    for (const ace of snapshot.aces) {
      // F3 core property: EVERY principal is a canonical SID — never a localized
      // account name — so authorization is identical on any Windows locale.
      expect(ace.sid).toMatch(CANONICAL_SID);
      // Structure preserved: representable type, exact supported ACE flags,
      // and a 32-bit access mask.
      expect(['ALLOW', 'DENY']).toContain(ace.type);
      expect(Number.isInteger(ace.flags)).toBe(true);
      expect(ace.flags).toBeGreaterThanOrEqual(0);
      expect(ace.flags).toBeLessThanOrEqual(0x1f);
      expect(Number.isInteger(ace.mask)).toBe(true);
      expect(ace.mask).toBeGreaterThanOrEqual(0);
      expect(ace.mask).toBeLessThanOrEqual(0xffffffff);
    }

    // SYSTEM is present on an inherited %TEMP% ACL and MUST appear as its canonical
    // SID S-1-5-18 — the exact locale-independence the parser-only fix could not
    // achieve (default icacls shows only the localized "NT AUTHORITY\\SYSTEM").
    const systemAce = snapshot.aces.find((ace) => ace.sid === SYSTEM_SID);
    expect(systemAce, 'temp DACL should carry SYSTEM as canonical S-1-5-18').toBeDefined();
    // The inherited flag is preserved for real inherited ACEs.
    expect(snapshot.aces.some((ace) => (ace.flags & 0x10) !== 0)).toBe(true);
  });

  it('a protected file-inheritable anchor stays narrow and creates a genuinely restricted descriptor', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'abctl-protected-'));
    const anchor = join(parent, 'control');
    mkdirSync(anchor);
    const icacls = join(systemRoot, 'System32', 'icacls.exe');

    try {
      const anchorSnapshot = await establishAnchorAcl(anchor, 'F');

      // Widen the parent after validation. SE_DACL_PROTECTED prevents this new
      // inheritable Everyone ACE from entering the anchor or its later child.
      const widenedParent = await runner(icacls, [parent, '/grant', '*S-1-1-0:(OI)(CI)R']);
      expect(widenedParent.ok).toBe(true);
      const afterParentChange = await runner(exePath, ['--acl', anchor]);
      expect(afterParentChange.ok).toBe(true);
      const stable = afterParentChange.ok ? store.parseAclSnapshot(afterParentChange.stdout) : null;
      expect(stable).toEqual(anchorSnapshot);

      // The PRODUCTION creation path: the build-provenanced create-only artifact,
      // resolved and hash-verified module-relative with no injected deps.
      const { descriptor } = store.createRuntimeDescriptor(process.pid);
      expect(await store.createDescriptorFileNative(anchor, descriptor)).toEqual({ ok: true });
      const descriptorAcl = await runner(exePath, ['--acl', store.descriptorPathFor(anchor)]);
      expect(descriptorAcl.ok).toBe(true);
      const fileSnapshot = descriptorAcl.ok ? store.parseAclSnapshot(descriptorAcl.stdout) : null;
      expect(fileSnapshot).not.toBeNull();
      if (fileSnapshot === null) {
        return;
      }

      // Inspect the actual created token-bearing file, not merely the parent
      // policy: the owner is the exact operator SID, the DACL is real, non-NULL,
      // PROTECTED, direct (nothing inherited), and no principal beyond operator +
      // SYSTEM appears.
      expect(fileSnapshot.ownerSid).toBe(operator.sid);
      expect(fileSnapshot.daclState).toBe('PRESENT');
      expect(fileSnapshot.daclProtected).toBe(true);
      expect(new Set(fileSnapshot.aces.map((ace) => ace.sid))).toEqual(
        new Set([operator.sid, SYSTEM_SID]),
      );
      expect(fileSnapshot.aces).toHaveLength(2);
      expect(fileSnapshot.aces.every((ace) => ace.type === 'ALLOW')).toBe(true);
      expect(fileSnapshot.aces.every((ace) => (ace.flags & 0x10) === 0)).toBe(true);
      expect(fileSnapshot.aces.some((ace) => ace.sid === 's-1-1-0')).toBe(false);
      // The file the creator says it made is verified INDEPENDENTLY, by the
      // read-only helper through the production descriptor gate.
      expect(
        await store.verifyDescriptorSnapshot(
          operator,
          store.descriptorPathFor(anchor),
          runner,
        ),
      ).toEqual({ ok: true });
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('a weak stale descriptor that ACLs prevent deleting blocks startup without receiving a fresh token', async () => {
    const parent = mkdtempSync(join(tmpdir(), 'abctl-stale-acl-'));
    const anchor = join(parent, 'control');
    mkdirSync(anchor);
    const descriptorPath = store.descriptorPathFor(anchor);
    const icacls = join(systemRoot, 'System32', 'icacls.exe');
    const oldSerialized = store.serializeDescriptor(store.createRuntimeDescriptor(31337).descriptor);
    let serverCreates = 0;

    try {
      // This anchor still passes the V2 policy: it is protected and every direct
      // ACE is file-inheritable and limited to operator/SYSTEM. The operator may
      // create/write, but deny DELETE + DELETE_CHILD makes stale unlink fail.
      await establishAnchorAcl(anchor, 'M');
      const denied = await runner(icacls, [
        anchor,
        '/deny',
        `*${operator.sid}:(OI)(CI)(D,DC)`,
      ]);
      expect(denied.ok).toBe(true);
      const deniedAcl = await readNativeAclSnapshot(anchor);
      const intentionalDenies = deniedAcl.aces.filter(
        (ace) =>
          ace.type === 'DENY' &&
          ace.sid === operator.sid &&
          (ace.flags & 0x03) === 0x03 &&
          (ace.mask & 0x00010040) === 0x00010040,
      );
      expect(intentionalDenies).toHaveLength(1);
      expect(new Set(deniedAcl.aces.map((ace) => ace.sid))).toEqual(
        new Set([operator.sid, SYSTEM_SID]),
      );
      const anchorResult = await store.verifyAnchorSnapshot(operator, anchor, runner);
      expect(anchorResult.ok).toBe(true);

      writeFileSync(descriptorPath, oldSerialized, 'utf8');
      const widened = await runner(icacls, [descriptorPath, '/grant', '*S-1-1-0:R']);
      expect(widened.ok).toBe(true);
      const staleAcl = await runner(exePath, ['--acl', descriptorPath]);
      expect(staleAcl.ok).toBe(true);
      const staleSnapshot = staleAcl.ok ? store.parseAclSnapshot(staleAcl.stdout) : null;
      expect(staleSnapshot?.aces.some((ace) => ace.sid === 's-1-1-0')).toBe(true);
      expect(
        staleSnapshot?.aces.some(
          (ace) =>
            ace.type === 'DENY' &&
            ace.sid === operator.sid &&
            (ace.mask & 0x00010040) === 0x00010040,
        ),
      ).toBe(true);

      const handle = await runtime.startControlChannel({
        // Startup must stop before the orchestrator or server is used.
        orchestrator: {} as Parameters<typeof runtime.startControlChannel>[0]['orchestrator'],
        verify: (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
          Promise.resolve({ ok: true, anchorPath: anchor }),
        createServer: (() => {
          serverCreates += 1;
          throw new Error('pipe construction must not be reached');
        }) as NonNullable<Parameters<typeof runtime.startControlChannel>[0]['createServer']>,
        logger: (): void => {
          /* silent */
        },
      });

      expect(handle).toBeNull();
      expect(serverCreates).toBe(0);
      expect(readFileSync(descriptorPath, 'utf8')).toBe(oldSerialized);
    } finally {
      if (existsSync(descriptorPath)) {
        await runner(icacls, [
          descriptorPath,
          '/inheritance:r',
          '/remove:d',
          `*${operator.sid}`,
          '/grant:r',
          `*${operator.sid}:F`,
          '*S-1-5-18:F',
        ]);
      }
      await runner(icacls, [
        anchor,
        '/inheritance:r',
        '/remove:d',
        `*${operator.sid}`,
        '/grant:r',
        `*${operator.sid}:(OI)(CI)F`,
        '*S-1-5-18:(OI)(CI)F',
      ]);
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('--acl rejects malformed args, relative paths, and extra argv (fail closed)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-args-'));
    // Relative path in either mode.
    expect((await runner(exePath, ['relative\\path'])).ok).toBe(false);
    expect((await runner(exePath, ['--acl', 'relative\\path'])).ok).toBe(false);
    // Extra trailing argv in either mode.
    expect((await runner(exePath, [dir, 'extra'])).ok).toBe(false);
    expect((await runner(exePath, ['--acl', dir, 'extra'])).ok).toBe(false);
    // Unknown flag.
    expect((await runner(exePath, ['--nope', dir])).ok).toBe(false);
  });

  it('verifyAnchorSnapshot fails closed when the expected operator SID differs from the real owner', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-mismatch-'));
    const foreign: OperatorIdentity = { name: operator.name, sid: 's-1-5-21-0-0-0-4242' };
    const result = await store.verifyAnchorSnapshot(foreign, dir, runner);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Real owner is never the fabricated foreign SID: OWNER_MISMATCH, or
      // OWNER_IS_SYSTEM if an elevated runner made SYSTEM the owner.
      expect([
        store.CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH,
        store.CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM,
      ]).toContain(result.reason);
    }
  });

  it('verifyAnchorSnapshot fails closed against a swapped binary (hash mismatch) on the real path', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-swap-'));
    const result = await store.verifyAnchorSnapshot(operator, dir, runner, {
      // Real provenance + real binary, but a tampered expected hash.
      loadProvenance: () =>
        Promise.resolve({ filename: 'agentbridge-win-owner.exe', sha256: 'd'.repeat(64) }),
      resolveHelperPath: () => exePath,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(store.CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH);
    }
  });
});

/**
 * Real Windows integration for the Decision 062 Amendment C descriptor CREATOR.
 *
 * Unlike the injected cases in control-store.test.ts, every assertion below runs the
 * ACTUAL compiled `agentbridge-win-descriptor-create.exe` through the production code
 * path (module-relative provenance, the SHA-256 gate, the real bounded spawn
 * transport), and reads the result back with the ACTUAL read-only helper.
 *
 * The defect this closes: Windows — not the caller — chooses a new file's OWNER
 * (from the creating token's DEFAULT owner, `BUILTIN\Administrators` under elevation)
 * and its DACL (from the parent's inheritable ACEs). `writeFileSync` therefore cannot
 * produce a descriptor that satisfies the exact-owner gate. The elevation half of that
 * divergence needs an elevated token to observe; the inheritance half is observable on
 * any account, and is asserted directly below as the same class of defect.
 */
describe.skipIf(!creatorReady)('D062 descriptor creator — real Windows binary integration', () => {
  const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
  let store!: StoreModule;
  let runtimeModule!: RuntimeModule;
  let operator!: OperatorIdentity;
  let runner!: ProcessRunner;

  const snapshotOf = async (target: string): Promise<AclSnapshot> => {
    const result = await runner(exePath, ['--acl', target]);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(`native ACL snapshot failed for ${target}`);
    }
    const snapshot = store.parseAclSnapshot(result.stdout);
    expect(snapshot).not.toBeNull();
    if (snapshot === null) {
      throw new Error(`native ACL snapshot was malformed for ${target}`);
    }
    return snapshot;
  };

  /**
   * A protected anchor owned by the operator, granting operator + SYSTEM + an EXTRA
   * inheritable principal (Everyone). The extra principal makes the OS's own choice
   * of a created file's DACL directly observable.
   */
  const makeWideningAnchor = async (): Promise<{ parent: string; anchor: string }> => {
    const parent = mkdtempSync(join(tmpdir(), 'abctl-create-'));
    const anchor = join(parent, 'control');
    mkdirSync(anchor);
    const icacls = join(systemRoot, 'System32', 'icacls.exe');
    expect((await runner(icacls, [anchor, '/setowner', `*${operator.sid}`])).ok).toBe(true);
    expect((await runner(icacls, [anchor, '/inheritance:r'])).ok).toBe(true);
    const current = await snapshotOf(anchor);
    const removals = new Map<string, { readonly type: 'ALLOW' | 'DENY'; readonly sid: string }>();
    for (const ace of current.aces) {
      removals.set(`${ace.type}:${ace.sid}`, { type: ace.type, sid: ace.sid });
    }
    for (const removal of removals.values()) {
      expect(
        (
          await runner(icacls, [
            anchor,
            removal.type === 'ALLOW' ? '/remove:g' : '/remove:d',
            `*${removal.sid}`,
          ])
        ).ok,
      ).toBe(true);
    }
    expect(
      (
        await runner(icacls, [
          anchor,
          '/grant:r',
          `*${operator.sid}:(OI)(CI)F`,
          '*S-1-5-18:(OI)(CI)F',
          '*S-1-1-0:(OI)(CI)R',
        ])
      ).ok,
    ).toBe(true);
    return { parent, anchor };
  };

  /** Run the real creator directly, so argv/stdin/stdout/stderr are all observable. */
  const runCreatorRaw = (
    args: readonly string[],
    input: Buffer,
  ): { status: number | null; stdout: Buffer; stderr: Buffer } => {
    const result = spawnSync(creatorPath, [...args], { input, windowsHide: true });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  };

  beforeAll(async () => {
    store = (await import(pathToFileURL(distStore).href)) as StoreModule;
    runtimeModule = (await import(pathToFileURL(distRuntime).href)) as RuntimeModule;
    runner = store.defaultProcessRunner(systemRoot);
    const whoami = await runner(join(systemRoot, 'System32', 'whoami.exe'), ['/user']);
    if (!whoami.ok) {
      throw new Error('whoami failed in creator integration setup');
    }
    const parsed = store.parseWhoamiUser(whoami.stdout);
    if (parsed === null) {
      throw new Error('could not parse operator identity in creator integration setup');
    }
    operator = parsed;
  });

  it('generated creator provenance hash matches the exact compiled binary', () => {
    const actual = createHash('sha256').update(readFileSync(creatorPath)).digest('hex');
    const provText = readFileSync(creatorProvPath, 'utf8');
    expect(provText).toContain('DESCRIPTOR_CREATOR_PROVENANCE');
    const match = /sha256:\s*"([0-9a-f]{64})"/.exec(provText);
    expect(match?.[1]).toBe(actual);
    // Two distinct trust roots: the owner helper's provenance names a different
    // binding and a different binary, so neither can stand in for the other.
    expect(readFileSync(provPath, 'utf8')).not.toContain('DESCRIPTOR_CREATOR_PROVENANCE');
    expect(provText).not.toContain('OWNER_HELPER_PROVENANCE');
  });

  it('creates a descriptor owned by the EXACT operator with a protected 2-principal DACL', async () => {
    const { parent, anchor } = await makeWideningAnchor();
    try {
      const { descriptor } = store.createRuntimeDescriptor(process.pid);
      const created = await store.createDescriptorFileNative(anchor, descriptor);
      expect(created).toEqual({ ok: true });

      const descriptorPath = store.descriptorPathFor(anchor);
      // The bytes on disk are exactly what was sent on stdin — nothing truncated,
      // nothing appended, no BOM, no newline translation.
      expect(readFileSync(descriptorPath, 'utf8')).toBe(store.serializeDescriptor(descriptor));

      const snapshot = await snapshotOf(descriptorPath);
      // Owner is the exact runtime operator SID (never the token's default owner).
      expect(snapshot.ownerSid).toBe(operator.sid);
      expect(snapshot.ownerSid).not.toBe(SYSTEM_SID);
      // DACL present, non-NULL, and PROTECTED.
      expect(snapshot.daclState).toBe('PRESENT');
      expect(snapshot.daclProtected).toBe(true);
      // Exactly two principals: the operator and SYSTEM.
      expect(snapshot.aces).toHaveLength(2);
      expect(new Set(snapshot.aces.map((ace) => ace.sid))).toEqual(
        new Set([operator.sid, SYSTEM_SID]),
      );
      expect(snapshot.aces.every((ace) => ace.type === 'ALLOW')).toBe(true);
      // No Everyone, despite the anchor granting Everyone an INHERITABLE ACE.
      expect(snapshot.aces.some((ace) => ace.sid === 's-1-1-0')).toBe(false);
      // No BUILTIN\Administrators foreign principal (it is not this TokenUser).
      if (operator.sid !== ADMINISTRATORS_SID) {
        expect(snapshot.aces.some((ace) => ace.sid === ADMINISTRATORS_SID)).toBe(false);
      }
      // Nothing inherited: every ACE is direct.
      expect(snapshot.aces.every((ace) => (ace.flags & 0x10) === 0)).toBe(true);

      // The INDEPENDENT read-only helper verifies the file that actually exists.
      expect(await store.verifyDescriptorSnapshot(operator, descriptorPath, runner)).toEqual({
        ok: true,
      });
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('the OS — not the caller — picks a writeFileSync descriptor security: the creator does not', async () => {
    // The defect class, reproduced on any account: inside the SAME anchor, Node's
    // exclusive write inherits the parent's principals and produces an UNPROTECTED
    // DACL, so a later-widened parent leaks straight into the token-bearing file.
    // Under an elevated token the same mechanism also hands the file to
    // BUILTIN\Administrators as OWNER, which is the reported CI failure.
    const { parent, anchor } = await makeWideningAnchor();
    try {
      const legacy = store.createRuntimeDescriptor(1).descriptor;
      store.writeDescriptorFile(anchor, legacy);
      const legacyPath = store.descriptorPathFor(anchor);
      const legacySnapshot = await snapshotOf(legacyPath);
      // Everyone leaked in, purely by inheritance; the DACL is not protected.
      expect(legacySnapshot.aces.some((ace) => ace.sid === 's-1-1-0')).toBe(true);
      expect(legacySnapshot.daclProtected).toBe(false);
      expect(legacySnapshot.aces.every((ace) => (ace.flags & 0x10) !== 0)).toBe(true);
      // And the production gate refuses it — fail-closed is the invariant here. The
      // exact reason is legitimately token-dependent: on an elevated runner the same
      // writeFileSync also takes OWNER from the token default (BUILTIN\Administrators),
      // which the evaluator correctly rejects as OWNER_MISMATCH before it ever reaches
      // DACL_UNPROTECTED. Exact evaluator precedence is pinned deterministically, on
      // synthetic snapshots, in control-store.test.ts — not on a real OS-chosen ACL.
      expect((await store.verifyDescriptorSnapshot(operator, legacyPath, runner)).ok).toBe(false);

      // The creator, in the same anchor, is unaffected by all of it.
      rmSync(legacyPath, { force: true });
      const { descriptor } = store.createRuntimeDescriptor(2);
      expect(await store.createDescriptorFileNative(anchor, descriptor)).toEqual({ ok: true });
      const fixed = await snapshotOf(legacyPath);
      expect(fixed.daclProtected).toBe(true);
      expect(fixed.aces.some((ace) => ace.sid === 's-1-1-0')).toBe(false);
      expect(await store.verifyDescriptorSnapshot(operator, legacyPath, runner)).toEqual({
        ok: true,
      });
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('CREATE_NEW: an existing descriptor is never opened, overwritten, re-owned, or re-ACLd', async () => {
    const { parent, anchor } = await makeWideningAnchor();
    try {
      const first = store.createRuntimeDescriptor(1).descriptor;
      expect(await store.createDescriptorFileNative(anchor, first)).toEqual({ ok: true });
      const descriptorPath = store.descriptorPathFor(anchor);
      const before = readFileSync(descriptorPath);
      const beforeAcl = await snapshotOf(descriptorPath);

      const second = store.createRuntimeDescriptor(2).descriptor;
      expect(second.token).not.toBe(first.token);
      const retry = await store.createDescriptorFileNative(anchor, second);
      expect(retry).toEqual({
        ok: false,
        reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
      });

      // Byte-identical and ACL-identical: the second token never reached the disk.
      expect(readFileSync(descriptorPath).equals(before)).toBe(true);
      expect(readFileSync(descriptorPath, 'utf8')).not.toContain(second.token);
      expect(await snapshotOf(descriptorPath)).toEqual(beforeAcl);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('rejects invalid argc, relative anchors, and traversal components (fail closed)', async () => {
    const { parent, anchor } = await makeWideningAnchor();
    const body = Buffer.from('{"probe":1}', 'utf8');
    try {
      for (const args of [
        [],
        [anchor, 'extra'],
        [anchor, `*${operator.sid}`],
        ['relative\\path'],
        ['runtime-descriptor.json'],
        [''],
        [`${anchor}\\..`],
        [`${anchor}\\..\\control`],
        [`${anchor}\\.`],
      ]) {
        const run = runCreatorRaw(args, body);
        expect(run.status, `argv ${JSON.stringify(args)} must be rejected`).not.toBe(0);
        expect(run.stdout.length).toBe(0);
      }
      // Nothing was created anywhere, inside or outside the anchor.
      expect(existsSync(store.descriptorPathFor(anchor))).toBe(false);
      expect(existsSync(store.descriptorPathFor(parent))).toBe(false);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('stdin is bounded: empty and >4096 bytes are refused, exactly 4096 is accepted', async () => {
    const { parent, anchor } = await makeWideningAnchor();
    try {
      const descriptorPath = store.descriptorPathFor(anchor);

      expect(runCreatorRaw([anchor], Buffer.alloc(0)).status).not.toBe(0);
      expect(existsSync(descriptorPath)).toBe(false);

      expect(runCreatorRaw([anchor], Buffer.alloc(4097, 0x61)).status).not.toBe(0);
      expect(existsSync(descriptorPath)).toBe(false);

      // Far over the cap, to prove the refusal is not a truncation.
      expect(runCreatorRaw([anchor], Buffer.alloc(65536, 0x61)).status).not.toBe(0);
      expect(existsSync(descriptorPath)).toBe(false);

      const exact = Buffer.alloc(4096, 0x62);
      expect(runCreatorRaw([anchor], exact).status).toBe(0);
      expect(readFileSync(descriptorPath).equals(exact)).toBe(true);
      const snapshot = await snapshotOf(descriptorPath);
      expect(snapshot.ownerSid).toBe(operator.sid);
      expect(snapshot.daclProtected).toBe(true);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('the descriptor token never appears in argv, stdout, stderr, or any log line', async () => {
    const { parent, anchor } = await makeWideningAnchor();
    const logged: string[] = [];
    try {
      const { descriptor } = store.createRuntimeDescriptor(process.pid);
      const payload = Buffer.from(store.serializeDescriptor(descriptor), 'utf8');

      // argv is exactly the anchor; the secret travels only on stdin.
      const run = runCreatorRaw([anchor], payload);
      expect(run.status).toBe(0);
      // The creator writes NOTHING to stdout, and stderr is silent on success.
      expect(run.stdout.length).toBe(0);
      expect(run.stderr.length).toBe(0);
      expect(run.stdout.toString('utf8')).not.toContain(descriptor.token);
      expect(run.stderr.toString('utf8')).not.toContain(descriptor.token);

      // A failing invocation is equally silent about the payload: its stderr is one
      // bounded ASCII token, and it names neither the path nor the secret.
      const failed = runCreatorRaw([anchor], payload); // CREATE_NEW now fails
      expect(failed.status).not.toBe(0);
      expect(failed.stdout.length).toBe(0);
      const stderrText = failed.stderr.toString('utf8');
      expect(stderrText.trim()).toMatch(/^ERR_[A-Z_]+$/);
      expect(stderrText.length).toBeLessThan(64);
      expect(stderrText).not.toContain(descriptor.token);
      expect(stderrText).not.toContain(descriptor.pipeName);
      expect(stderrText).not.toContain(anchor);

      // And the runtime's own logging of a real creation failure carries no secret.
      // An absent anchor makes the creator's CREATE_NEW fail for real, so startup
      // takes the creation-failure branch and logs it.
      const absentAnchor = join(parent, `absent-${randomBytes(8).toString('hex')}`);
      const handle = await runtimeModule.startControlChannel({
        orchestrator: {} as Parameters<
          typeof runtimeModule.startControlChannel
        >[0]['orchestrator'],
        verify: (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
          Promise.resolve({ ok: true, anchorPath: absentAnchor }),
        createServer: (() => {
          throw new Error('pipe construction must not be reached');
        }) as NonNullable<Parameters<typeof runtimeModule.startControlChannel>[0]['createServer']>,
        logger: (message: string): void => {
          logged.push(message);
        },
      });
      expect(handle).toBeNull();
      expect(existsSync(store.descriptorPathFor(absentAnchor))).toBe(false);
      const allLogs = logged.join('\n');
      expect(allLogs).toContain('exclusive descriptor creation failed');
      expect(allLogs).toContain(store.DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED);
      // The runtime minted a fresh token for that attempt; no token-shaped run of
      // base64url characters (a 32-byte token is 43 of them) may appear in a log.
      expect(allLogs).not.toMatch(/[A-Za-z0-9_-]{43}/);
      expect(allLogs).not.toContain(descriptor.token);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('fails closed on missing provenance, missing binary, and a hash mismatch', async () => {
    const { parent, anchor } = await makeWideningAnchor();
    const scratch = mkdtempSync(join(tmpdir(), 'abctl-creator-neg-'));
    try {
      const { descriptor } = store.createRuntimeDescriptor(1);
      const descriptorPath = store.descriptorPathFor(anchor);

      // Provenance absent.
      expect(
        await store.createDescriptorFileNative(anchor, descriptor, {
          loadProvenance: (): Promise<null> => Promise.resolve(null),
        }),
      ).toEqual({
        ok: false,
        reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING,
      });

      // Binary absent at the resolved path.
      expect(
        await store.createDescriptorFileNative(anchor, descriptor, {
          resolveCreatorPath: (): string => join(scratch, 'not-here.exe'),
        }),
      ).toEqual({
        ok: false,
        reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_MISSING,
      });

      // Real binary, tampered expected hash: never executed.
      expect(
        await store.createDescriptorFileNative(anchor, descriptor, {
          loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
            Promise.resolve({
              filename: 'agentbridge-win-descriptor-create.exe',
              sha256: 'd'.repeat(64),
            }),
        }),
      ).toEqual({
        ok: false,
        reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_HASH_MISMATCH,
      });

      // A swapped binary whose provenance was updated to match it still cannot run:
      // a non-executable payload fails to spawn.
      const impostor = join(scratch, 'impostor.exe');
      writeFileSync(impostor, 'not a PE image', 'utf8');
      const impostorSha = createHash('sha256').update(readFileSync(impostor)).digest('hex');
      expect(
        await store.createDescriptorFileNative(anchor, descriptor, {
          loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
            Promise.resolve({
              filename: 'agentbridge-win-descriptor-create.exe',
              sha256: impostorSha,
            }),
          resolveCreatorPath: (): string => impostor,
        }),
      ).toEqual({
        ok: false,
        reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED,
      });

      // Every rejection above happened before anything was written.
      expect(existsSync(descriptorPath)).toBe(false);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
      rmSync(parent, { recursive: true, force: true });
    }
  });

  it('a nonzero creator exit fails closed through the real transport', async () => {
    // A real, unmodified creator run against a nonexistent anchor: CREATE_NEW fails,
    // the process exits nonzero, and the gate reports it as a creator failure.
    const missing = join(tmpdir(), `abctl-absent-${randomBytes(8).toString('hex')}`);
    const { descriptor } = store.createRuntimeDescriptor(1);
    expect(await store.createDescriptorFileNative(missing, descriptor)).toEqual({
      ok: false,
      reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
    });
    expect(existsSync(store.descriptorPathFor(missing))).toBe(false);
  });


  it('END TO END: the real flow starts a channel, and CONTROL_AVAILABLE implies every gate passed', async () => {
    // The complete production path with NOTHING injected but the anchor location:
    // verifyControlAnchor (real whoami + real read-only helper) → stale removal →
    // the real create-only artifact → verifyDescriptorAcl (real read-only helper
    // again, independently) → a real named pipe.
    const { parent, anchor } = await makeWideningAnchor();
    // Narrow the anchor to the exact policy the anchor gate requires (operator +
    // SYSTEM only); the widening Everyone ACE above is removed first.
    const icacls = join(systemRoot, 'System32', 'icacls.exe');
    expect((await runner(icacls, [anchor, '/remove:g', '*S-1-1-0'])).ok).toBe(true);

    let handle: Awaited<ReturnType<RuntimeModule['startControlChannel']>> = null;
    try {
      const anchorCheck = await store.verifyControlAnchor({ anchorPath: anchor });
      expect(anchorCheck).toEqual({ ok: true, anchorPath: anchor });

      handle = await runtimeModule.startControlChannel({
        orchestrator: newOrchestrator().orchestrator,
        verify: (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
          Promise.resolve({ ok: true, anchorPath: anchor }),
        logger: (): void => {
          /* silent */
        },
      });
      expect(handle).not.toBeNull();
      if (handle === null) {
        return;
      }

      // The channel is available, so the descriptor on disk must satisfy every
      // descriptor trust gate — proven again here, independently of startup.
      const descriptorPath = store.descriptorPathFor(anchor);
      expect(existsSync(descriptorPath)).toBe(true);
      const snapshot = await snapshotOf(descriptorPath);
      expect(snapshot.ownerSid).toBe(operator.sid);
      expect(snapshot.daclProtected).toBe(true);
      expect(new Set(snapshot.aces.map((ace) => ace.sid))).toEqual(
        new Set([operator.sid, SYSTEM_SID]),
      );
      expect(await store.verifyDescriptorAcl(descriptorPath)).toEqual({ ok: true });

      // The descriptor on disk is the live channel's own identity.
      const parsed = store.parseDescriptor(readFileSync(descriptorPath, 'utf8'));
      expect(parsed).not.toBeNull();
      expect(parsed?.descriptor.pipeName).toBe(handle.pipeName);
    } finally {
      if (handle !== null) {
        await handle.close();
        // An orderly shutdown removes its own descriptor.
        expect(existsSync(store.descriptorPathFor(anchor))).toBe(false);
      }
      rmSync(parent, { recursive: true, force: true });
    }
  }, 30000);

  it('the creator runner enforces a finite deadline, kills the child, and settles once', async () => {
    // A real child that outlives the deadline: the runner must report TIMEOUT (not a
    // kill-induced nonzero exit), terminate it, and resolve exactly one value.
    const runCreator = store.defaultCreatorRunner(systemRoot);
    const ping = join(systemRoot, 'System32', 'PING.EXE');
    const started = Date.now();
    const result = await runCreator(ping, ['-n', '30', '127.0.0.1'], Buffer.from('x'));
    expect(result).toEqual({
      ok: false,
      reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT,
    });
    // It returned on the deadline rather than after the child's natural lifetime.
    expect(Date.now() - started).toBeLessThan(25000);
  }, 40000);
});
