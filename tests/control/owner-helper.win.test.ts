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

import { createHash } from 'node:crypto';
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

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const distStore = join(repoRoot, 'dist', 'control', 'control-store.js');
const distRuntime = join(repoRoot, 'dist', 'control', 'control-runtime.js');
const exePath = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-owner.exe');
const provPath = join(repoRoot, 'dist', 'control', 'native', 'owner-helper-provenance.js');

const ready =
  process.platform === 'win32' &&
  existsSync(distStore) &&
  existsSync(distRuntime) &&
  existsSync(exePath) &&
  existsSync(provPath);

type StoreModule = typeof import('../../src/control/control-store.js');
type RuntimeModule = typeof import('../../src/control/control-runtime.js');

const CANONICAL_SID = /^s-1-\d+(?:-\d+)+$/;
const SYSTEM_SID = 's-1-5-18';

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

      const { descriptor } = store.createRuntimeDescriptor(process.pid);
      store.writeDescriptorFile(anchor, descriptor);
      const descriptorAcl = await runner(exePath, ['--acl', store.descriptorPathFor(anchor)]);
      expect(descriptorAcl.ok).toBe(true);
      const fileSnapshot = descriptorAcl.ok ? store.parseAclSnapshot(descriptorAcl.stdout) : null;
      expect(fileSnapshot).not.toBeNull();
      if (fileSnapshot === null) {
        return;
      }

      // Inspect the actual created token-bearing file, not merely the parent
      // policy: it has a real non-NULL DACL and no principal beyond operator +
      // SYSTEM. Its ACEs are inherited from the two validated OI entries.
      expect(fileSnapshot.ownerSid).toBe(operator.sid);
      expect(fileSnapshot.daclState).toBe('PRESENT');
      expect(new Set(fileSnapshot.aces.map((ace) => ace.sid))).toEqual(
        new Set([operator.sid, SYSTEM_SID]),
      );
      expect(fileSnapshot.aces.length).toBeGreaterThanOrEqual(2);
      expect(fileSnapshot.aces.every((ace) => ace.type === 'ALLOW')).toBe(true);
      expect(fileSnapshot.aces.every((ace) => (ace.flags & 0x10) !== 0)).toBe(true);
      expect(fileSnapshot.aces.some((ace) => ace.sid === 's-1-1-0')).toBe(false);
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
