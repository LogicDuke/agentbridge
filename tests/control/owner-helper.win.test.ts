/**
 * Real Windows integration for the Decision 062 native control artifacts and the
 * descriptor lifecycle v2 (identity-named descriptors, listen-before-publish).
 *
 * Unlike the pure/injected tests in control-store.test.ts and
 * control-runtime.test.ts, this exercises the ACTUAL compiled binaries through the
 * production code path: it imports the built `dist/control/*.js` and calls the
 * runtime with nothing injected but the anchor location, so the default
 * provenance loads (the generated JS metadata beside each binary), the SHA-256
 * hash gates, the real bounded `execFile` transports, the real creator, the real
 * read-only snapshot, the real kernel pipe namespace, and the real filesystem all
 * run for real against `dist/control/native/`.
 *
 * It is gated to win32 with a built dist + both native artifacts. On Linux CI, or
 * before `npm run build && npm run helper:build`, the whole suite is skipped — its
 * behaviour cannot be proven cross-platform and is not asserted there.
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';

import {
  generateRuntimeKeyPair,
  publicKeyFromVerifyKey,
  VERIFY_KEY_BYTES,
} from '../../src/control/control-auth.js';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import type {
  AclSnapshot,
  OperatorIdentity,
  ProcessRunner,
} from '../../src/control/control-store.js';
import type { ControlChannelHandle } from '../../src/control/control-runtime.js';
import { BINDING, newOrchestrator } from './support.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const distStore = join(repoRoot, 'dist', 'control', 'control-store.js');
const distRuntime = join(repoRoot, 'dist', 'control', 'control-runtime.js');
const distCli = join(repoRoot, 'dist', 'control', 'cli.js');
const nativeDir = join(repoRoot, 'dist', 'control', 'native');
const exePath = join(nativeDir, 'agentbridge-win-owner.exe');
const provPath = join(nativeDir, 'owner-helper-provenance.js');
const creatorPath = join(nativeDir, 'agentbridge-win-descriptor-create.exe');
const creatorProvPath = join(nativeDir, 'descriptor-creator-provenance.js');

const ready =
  process.platform === 'win32' &&
  existsSync(distStore) &&
  existsSync(distRuntime) &&
  existsSync(distCli) &&
  existsSync(exePath) &&
  existsSync(provPath) &&
  existsSync(creatorPath) &&
  existsSync(creatorProvPath);

type StoreModule = typeof import('../../src/control/control-store.js');
type RuntimeModule = typeof import('../../src/control/control-runtime.js');
type CliModule = typeof import('../../src/control/cli.js');

const CANONICAL_SID = /^s-1-\d+(?:-\d+)+$/;
const SYSTEM_SID = 's-1-5-18';
const EVERYONE_SID = 's-1-1-0';
const HEX32 = '0123456789abcdef0123456789abcdef';
const INHERITED_ACE = 0x10;

describe.skipIf(!ready)('D062 native artifacts + lifecycle v2 — real Windows integration', () => {
  const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
  const icacls = join(systemRoot, 'System32', 'icacls.exe');
  let store!: StoreModule;
  let runtime!: RuntimeModule;
  let cli!: CliModule;
  let operator!: OperatorIdentity;
  let runner!: ProcessRunner;

  const handles: ControlChannelHandle[] = [];
  const children: ChildProcess[] = [];
  const tempRoots: string[] = [];

  afterEach(async () => {
    await Promise.all(handles.splice(0).map((handle) => handle.close()));
    for (const child of children.splice(0)) {
      child.kill('SIGKILL');
    }
    for (const root of tempRoots.splice(0)) {
      rmSync(root, { recursive: true, force: true });
    }
  });

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
   * A real hardened anchor under a fresh temp parent: owner = operator,
   * PROTECTED, and exactly the given inheritable principals. With `widen`, an
   * extra inheritable Everyone READ ACE makes the OS's own choice of a created
   * file's DACL directly observable (and makes the anchor itself non-compliant).
   */
  const makeAnchor = async (widen = false): Promise<{ parent: string; anchor: string }> => {
    const parent = mkdtempSync(join(tmpdir(), 'abctl-v2-'));
    tempRoots.push(parent);
    const anchor = join(parent, 'control');
    mkdirSync(anchor);
    expect((await runner(icacls, [anchor, '/setowner', `*${operator.sid}`])).ok).toBe(true);
    expect((await runner(icacls, [anchor, '/inheritance:r'])).ok).toBe(true);
    // Remove every surviving explicit entry by canonical SID, so an ambient
    // explicit temp-directory ACE cannot leak into the fixture.
    const current = await snapshotOf(anchor);
    const removals = new Map<string, { readonly type: 'ALLOW' | 'DENY'; readonly sid: string }>();
    for (const ace of current.aces) {
      removals.set(`${ace.type}:${ace.sid}`, { type: ace.type, sid: ace.sid });
    }
    for (const removal of removals.values()) {
      expect(
        (await runner(icacls, [anchor, removal.type === 'ALLOW' ? '/remove:g' : '/remove:d', `*${removal.sid}`])).ok,
      ).toBe(true);
    }
    const grants = [`*${operator.sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F'];
    if (widen) {
      grants.push('*S-1-1-0:(OI)(CI)R');
    }
    expect((await runner(icacls, [anchor, '/grant:r', ...grants])).ok).toBe(true);
    const final = await snapshotOf(anchor);
    expect(final.ownerSid).toBe(operator.sid);
    expect(final.daclState).toBe('PRESENT');
    expect(final.daclProtected).toBe(true);
    expect(final.aces.every((ace) => (ace.flags & INHERITED_ACE) === 0)).toBe(true);
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

  /** Spawn a child node process holding `pipePath` open until killed (a "runtime" that will crash). */
  const spawnPipeHolder = (pipePath: string): Promise<ChildProcess> => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-holder-'));
    tempRoots.push(dir);
    const script = join(dir, 'holder.mjs');
    writeFileSync(
      script,
      "import net from 'node:net';\n" +
        'const name = process.argv[2];\n' +
        "net.createServer(() => {}).listen(name, () => { process.stdout.write('L'); });\n" +
        'setInterval(() => {}, 1000);\n',
      'utf8',
    );
    return new Promise<ChildProcess>((resolvePromise, rejectPromise) => {
      const child = spawn(process.execPath, [script, pipePath], { stdio: ['ignore', 'pipe', 'inherit'] });
      children.push(child);
      child.stdout.once('data', () => {
        resolvePromise(child);
      });
      child.once('error', rejectPromise);
    });
  };

  const silent = (): void => {
    /* silent */
  };
  /**
   * Mint a real v3 descriptor around a genuine ephemeral keypair. The private
   * key stays in this test's scope, exactly as a live runtime keeps its own.
   */
  const mint = (): ReturnType<StoreModule['createRuntimeDescriptor']> =>
    store.createRuntimeDescriptor(generateRuntimeKeyPair().verifyKey);
  beforeAll(async () => {
    store = (await import(pathToFileURL(distStore).href)) as StoreModule;
    runtime = (await import(pathToFileURL(distRuntime).href)) as RuntimeModule;
    cli = (await import(pathToFileURL(distCli).href)) as CliModule;
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

  /* ---- provenance + read-only helper ------------------------------------------ */

  it('each generated provenance hash matches its exact compiled binary; the two trust roots are distinct', () => {
    const ownerSha = createHash('sha256').update(readFileSync(exePath)).digest('hex');
    const ownerProv = readFileSync(provPath, 'utf8');
    expect(/sha256:\s*"([0-9a-f]{64})"/.exec(ownerProv)?.[1]).toBe(ownerSha);
    expect(ownerProv).toContain('OWNER_HELPER_PROVENANCE');
    expect(ownerProv).not.toContain('DESCRIPTOR_CREATOR_PROVENANCE');

    const creatorSha = createHash('sha256').update(readFileSync(creatorPath)).digest('hex');
    const creatorProv = readFileSync(creatorProvPath, 'utf8');
    expect(/sha256:\s*"([0-9a-f]{64})"/.exec(creatorProv)?.[1]).toBe(creatorSha);
    expect(creatorProv).toContain('DESCRIPTOR_CREATOR_PROVENANCE');
    expect(creatorProv).not.toContain('OWNER_HELPER_PROVENANCE');
    expect(creatorSha).not.toBe(ownerSha);
  });

  it('F1 owner-only mode still returns exactly one canonical owner SID', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-owner-'));
    tempRoots.push(dir);
    const owned = await runner(exePath, [dir]);
    expect(owned.ok).toBe(true);
    if (owned.ok) {
      expect(store.parseOwnerHelperSid(owned.stdout)).toMatch(CANONICAL_SID);
    }
  });

  it('--acl V2 reports a real inherited temp directory as UNPROTECTED with INHERITED flags and canonical SIDs', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-acl-'));
    tempRoots.push(dir);
    const ownerOnly = await runner(exePath, [dir]);
    const ownerOnlySid = ownerOnly.ok ? store.parseOwnerHelperSid(ownerOnly.stdout) : null;
    const snapshot = await snapshotOf(dir);
    expect(snapshot.ownerSid).toMatch(CANONICAL_SID);
    expect(snapshot.ownerSid).toBe(ownerOnlySid);
    expect(snapshot.daclState).toBe('PRESENT');
    expect(snapshot.daclProtected).toBe(false);
    expect(snapshot.aces.length).toBeGreaterThanOrEqual(1);
    for (const ace of snapshot.aces) {
      expect(ace.sid).toMatch(CANONICAL_SID);
      expect(['ALLOW', 'DENY']).toContain(ace.type);
      expect(ace.flags).toBeGreaterThanOrEqual(0);
      expect(ace.flags).toBeLessThanOrEqual(0x1f);
      expect(ace.mask).toBeLessThanOrEqual(0xffffffff);
    }
    expect(snapshot.aces.some((ace) => ace.sid === SYSTEM_SID)).toBe(true);
    expect(snapshot.aces.some((ace) => (ace.flags & INHERITED_ACE) !== 0)).toBe(true);
    // The anchor policy correctly rejects an inherited, unprotected directory.
    expect(store.evaluateAnchorSnapshot(operator, snapshot).ok).toBe(false);
  });

  it('--acl rejects malformed args, relative paths, and extra argv (fail closed)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-args-'));
    tempRoots.push(dir);
    expect((await runner(exePath, ['relative\\path'])).ok).toBe(false);
    expect((await runner(exePath, ['--acl', 'relative\\path'])).ok).toBe(false);
    expect((await runner(exePath, [dir, 'extra'])).ok).toBe(false);
    expect((await runner(exePath, ['--acl', dir, 'extra'])).ok).toBe(false);
    expect((await runner(exePath, ['--nope', dir])).ok).toBe(false);
  });

  it('a hardened anchor passes the real anchor gate and stays narrow when its parent is widened afterwards', async () => {
    const { parent, anchor } = await makeAnchor();
    const before = await snapshotOf(anchor);
    expect(await store.verifyAnchorSnapshot(operator, anchor, runner)).toEqual({ ok: true, ownerSid: operator.sid });
    expect(await store.verifyControlAnchor({ anchorPath: anchor })).toEqual({ ok: true, anchorPath: anchor });
    // Widen the parent: SE_DACL_PROTECTED keeps the new inheritable ACE out.
    expect((await runner(icacls, [parent, '/grant', '*S-1-1-0:(OI)(CI)R'])).ok).toBe(true);
    expect(await snapshotOf(anchor)).toEqual(before);
  });

  it('the real anchor gate fails closed on a foreign operator SID and on a swapped helper binary', async () => {
    const { anchor } = await makeAnchor();
    const foreign: OperatorIdentity = { name: operator.name, sid: 's-1-5-21-0-0-0-4242' };
    const mismatch = await store.verifyAnchorSnapshot(foreign, anchor, runner);
    expect(mismatch).toEqual({ ok: false, reason: store.CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH });
    const swapped = await store.verifyAnchorSnapshot(operator, anchor, runner, {
      loadProvenance: () => Promise.resolve({ filename: 'agentbridge-win-owner.exe', sha256: 'd'.repeat(64) }),
      resolveHelperPath: () => exePath,
    });
    expect(swapped).toEqual({ ok: false, reason: store.CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH });
  });

  /* ---- the creator ------------------------------------------------------------- */

  it('4/5/6. the creator derives the filename from one strictly validated runtime id and refuses everything else', async () => {
    const { parent, anchor } = await makeAnchor();
    const body = Buffer.from('{"probe":1}', 'utf8');
    const badArgs: readonly (readonly string[])[] = [
      [],
      [anchor],
      [anchor, HEX32, 'extra'],
      ['relative\\path', HEX32],
      [`${anchor}\\..`, HEX32],
      [`${anchor}\\..\\control`, HEX32],
      [`${anchor}\\.`, HEX32],
      [anchor, ''],
      [anchor, HEX32.toUpperCase()],
      [anchor, HEX32.slice(0, 31)],
      [anchor, `${HEX32}0`],
      [anchor, `..\\${HEX32.slice(3)}`],
      [anchor, `../${HEX32.slice(3)}`],
      [anchor, `${HEX32.slice(0, 16)}\\${HEX32.slice(17)}`],
      [anchor, `${HEX32.slice(0, 16)}/${HEX32.slice(17)}`],
      [anchor, `${HEX32.slice(0, 16)}.${HEX32.slice(17)}`],
      [anchor, `${HEX32.slice(0, 16)}:${HEX32.slice(17)}`],
      [anchor, 'runtime-descriptor.json'],
      [anchor, `runtime-descriptor-${HEX32}.json`],
      [anchor, `${HEX32.slice(0, 31)}\u0661`],
    ];
    for (const args of badArgs) {
      const run = runCreatorRaw(args, body);
      expect(run.status, `argv ${JSON.stringify(args)} must be rejected`).not.toBe(0);
      expect(run.stdout.length).toBe(0);
      expect(run.stderr.toString('utf8').trim()).toMatch(/^ERR_[A-Z_]+$/);
    }
    // Nothing was created anywhere: not in the anchor, not in its parent.
    expect(readdirSync(anchor)).toEqual([]);
    expect(readdirSync(parent)).toEqual(['control']);

    // The one accepted shape creates exactly the identity-named file.
    expect(runCreatorRaw([anchor, HEX32], body).status).toBe(0);
    expect(readdirSync(anchor)).toEqual([`runtime-descriptor-${HEX32}.json`]);
    expect(readFileSync(join(anchor, `runtime-descriptor-${HEX32}.json`)).equals(body)).toBe(true);
  }, 20000);

  it('the creator makes a descriptor owned by the EXACT operator with a PROTECTED two-principal DACL, immune to anchor widening', async () => {
    const { anchor } = await makeAnchor(true);
    const minted = mint();
    const bytes = Buffer.from(store.serializeDescriptor(minted.descriptor), 'utf8');
    expect(await store.createDescriptorFileNative(anchor, minted.runtimeId, bytes)).toEqual({ ok: true });

    const descriptorPath = store.descriptorPathFor(anchor, minted.runtimeId);
    expect(readFileSync(descriptorPath).equals(bytes)).toBe(true);
    const snapshot = await snapshotOf(descriptorPath);
    expect(snapshot.ownerSid).toBe(operator.sid);
    expect(snapshot.ownerSid).not.toBe(SYSTEM_SID);
    expect(snapshot.daclState).toBe('PRESENT');
    expect(snapshot.daclProtected).toBe(true);
    expect(snapshot.aces).toHaveLength(2);
    expect(new Set(snapshot.aces.map((ace) => ace.sid))).toEqual(new Set([operator.sid, SYSTEM_SID]));
    expect(snapshot.aces.every((ace) => ace.type === 'ALLOW' && ace.flags === 0)).toBe(true);
    // No Everyone, despite the anchor granting Everyone an INHERITABLE ACE.
    expect(snapshot.aces.some((ace) => ace.sid === EVERYONE_SID)).toBe(false);
    // The INDEPENDENT read-only helper verifies the file that actually exists.
    expect(await store.verifyDescriptorSnapshot(operator, descriptorPath, runner)).toEqual({ ok: true });
    expect(await store.verifyDescriptorAcl(descriptorPath)).toEqual({ ok: true });
  });

  it('the OS — not the caller — picks a plainly written file\'s security: unprotected + inherited, rejected by the real gate', async () => {
    const { anchor } = await makeAnchor(true);
    const minted = mint();
    const legacyPath = store.descriptorPathFor(anchor, minted.runtimeId);
    writeFileSync(legacyPath, store.serializeDescriptor(minted.descriptor), { encoding: 'utf8', flag: 'wx' });
    const snapshot = await snapshotOf(legacyPath);
    expect(snapshot.daclProtected).toBe(false);
    expect(snapshot.aces.every((ace) => (ace.flags & INHERITED_ACE) !== 0)).toBe(true);
    expect(snapshot.aces.some((ace) => ace.sid === EVERYONE_SID)).toBe(true);
    const verdict = await store.verifyDescriptorAcl(legacyPath);
    expect(verdict.ok).toBe(false);
    // The exact reason is token-dependent only in the elevated case (default owner
    // BUILTIN\Administrators → OWNER_MISMATCH); here the owner is the operator, so
    // the protection check is what fires.
    if (!verdict.ok && snapshot.ownerSid === operator.sid) {
      expect(verdict.reason).toBe(store.CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED);
    }
  });

  it('6. CREATE_NEW: an existing identity-named file is never opened, overwritten, re-owned, or re-ACLd', async () => {
    const { anchor } = await makeAnchor();
    const first = mint();
    const firstBytes = Buffer.from(store.serializeDescriptor(first.descriptor), 'utf8');
    expect(await store.createDescriptorFileNative(anchor, first.runtimeId, firstBytes)).toEqual({ ok: true });
    const descriptorPath = store.descriptorPathFor(anchor, first.runtimeId);
    const beforeAcl = await snapshotOf(descriptorPath);

    // A second descriptor for the SAME id (a different token) must fail.
    const second = mint();
    const secondBytes = Buffer.from(
      store.serializeDescriptor({
        version: 3,
        pipeName: first.descriptor.pipeName,
        token: second.descriptor.token,
        verifyKey: second.descriptor.verifyKey,
      }),
      'utf8',
    );
    expect(await store.createDescriptorFileNative(anchor, first.runtimeId, secondBytes)).toEqual({
      ok: false,
      reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
    });
    expect(readFileSync(descriptorPath).equals(firstBytes)).toBe(true);
    expect(readFileSync(descriptorPath, 'utf8')).not.toContain(second.descriptor.token);
    expect(await snapshotOf(descriptorPath)).toEqual(beforeAcl);
  });

  it('stdin is bounded: empty and >4096 bytes are refused, exactly 4096 is accepted', async () => {
    const { anchor } = await makeAnchor();
    const descriptorPath = store.descriptorPathFor(anchor, HEX32);
    expect(runCreatorRaw([anchor, HEX32], Buffer.alloc(0)).status).not.toBe(0);
    expect(existsSync(descriptorPath)).toBe(false);
    expect(runCreatorRaw([anchor, HEX32], Buffer.alloc(4097, 0x61)).status).not.toBe(0);
    expect(existsSync(descriptorPath)).toBe(false);
    expect(runCreatorRaw([anchor, HEX32], Buffer.alloc(65536, 0x61)).status).not.toBe(0);
    expect(existsSync(descriptorPath)).toBe(false);
    const exact = Buffer.alloc(4096, 0x62);
    expect(runCreatorRaw([anchor, HEX32], exact).status).toBe(0);
    expect(readFileSync(descriptorPath).equals(exact)).toBe(true);
    expect((await snapshotOf(descriptorPath)).daclProtected).toBe(true);
  });

  it('the descriptor token never appears in argv, stdout, stderr, or any runtime log line', async () => {
    const { parent, anchor } = await makeAnchor();
    const minted = mint();
    const payload = Buffer.from(store.serializeDescriptor(minted.descriptor), 'utf8');

    const run = runCreatorRaw([anchor, minted.runtimeId], payload);
    expect(run.status).toBe(0);
    expect(run.stdout.length).toBe(0);
    expect(run.stderr.length).toBe(0);

    // A failing invocation is equally silent about the payload.
    const failed = runCreatorRaw([anchor, minted.runtimeId], payload); // CREATE_NEW now fails
    expect(failed.status).not.toBe(0);
    expect(failed.stdout.length).toBe(0);
    const stderrText = failed.stderr.toString('utf8');
    expect(stderrText.trim()).toMatch(/^ERR_[A-Z_]+$/);
    expect(stderrText.length).toBeLessThan(64);
    expect(stderrText).not.toContain(minted.descriptor.token);
    expect(stderrText).not.toContain(anchor);

    // The runtime's own logging of the fail-closed startup path carries no
    // secret. An absent anchor now fails the descriptor enumeration BEFORE any
    // listen, publish, or creation (CONTROL_START_SUCCESS ⇒
    // INITIAL_DESCRIPTOR_ENUMERATION_COMPLETE), so startup stops early — whatever
    // the reason, no token ever reaches a log line.
    const absentAnchor = join(parent, `absent-${randomBytes(8).toString('hex')}`);
    const logged: string[] = [];
    const handle = await runtime.startControlChannel({
      orchestrator: newOrchestrator().orchestrator,
      verify: () => Promise.resolve({ ok: true, anchorPath: absentAnchor }),
      logger: (message: string): void => {
        logged.push(message);
      },
    });
    expect(handle).toBeNull(); // fails closed: no unsafe success
    expect(existsSync(absentAnchor)).toBe(false); // nothing was created
    const allLogs = logged.join('\n');
    // An absent anchor cannot be enumerated, so the deterministic safe reason is
    // an unreadable enumeration; the channel is disabled before listen/publish.
    expect(allLogs).toContain('descriptor enumeration unreadable');
    // The security invariant: no base64url descriptor token (43 chars) ever
    // appears in any runtime log line.
    expect(allLogs).not.toMatch(/[A-Za-z0-9_-]{43}/);
  });

  it('fails closed on missing provenance, missing binary, a hash mismatch, and an impostor image', async () => {
    const { anchor } = await makeAnchor();
    const scratch = mkdtempSync(join(tmpdir(), 'abctl-creator-neg-'));
    tempRoots.push(scratch);
    const minted = mint();
    const bytes = Buffer.from(store.serializeDescriptor(minted.descriptor), 'utf8');
    const rejection = store.DESCRIPTOR_CREATION_REJECTION;

    expect(await store.createDescriptorFileNative(anchor, minted.runtimeId, bytes, { loadProvenance: () => Promise.resolve(null) }))
      .toEqual({ ok: false, reason: rejection.CREATOR_PROVENANCE_MISSING });
    expect(await store.createDescriptorFileNative(anchor, minted.runtimeId, bytes, { resolveCreatorPath: () => join(scratch, 'not-here.exe') }))
      .toEqual({ ok: false, reason: rejection.CREATOR_MISSING });
    expect(await store.createDescriptorFileNative(anchor, minted.runtimeId, bytes, {
      loadProvenance: () => Promise.resolve({ filename: 'agentbridge-win-descriptor-create.exe', sha256: 'd'.repeat(64) }),
    })).toEqual({ ok: false, reason: rejection.CREATOR_HASH_MISMATCH });
    // The owner helper's provenance can never stand in for the creator's.
    expect(await store.createDescriptorFileNative(anchor, minted.runtimeId, bytes, {
      loadProvenance: () => Promise.resolve({
        filename: 'agentbridge-win-owner.exe',
        sha256: createHash('sha256').update(readFileSync(exePath)).digest('hex'),
      }),
      resolveCreatorPath: () => creatorPath,
    })).toEqual({ ok: false, reason: rejection.CREATOR_HASH_MISMATCH });
    const impostor = join(scratch, 'impostor.exe');
    writeFileSync(impostor, 'not a PE image', 'utf8');
    const impostorSha = createHash('sha256').update(readFileSync(impostor)).digest('hex');
    expect(await store.createDescriptorFileNative(anchor, minted.runtimeId, bytes, {
      loadProvenance: () => Promise.resolve({ filename: 'agentbridge-win-descriptor-create.exe', sha256: impostorSha }),
      resolveCreatorPath: () => impostor,
    })).toEqual({ ok: false, reason: rejection.CREATOR_SPAWN_FAILED });
    expect(readdirSync(anchor)).toEqual([]);
  });

  it('a nonzero creator exit fails closed through the real transport', async () => {
    const missing = join(tmpdir(), `abctl-absent-${randomBytes(8).toString('hex')}`);
    const minted = mint();
    const bytes = Buffer.from(store.serializeDescriptor(minted.descriptor), 'utf8');
    expect(await store.createDescriptorFileNative(missing, minted.runtimeId, bytes)).toEqual({
      ok: false,
      reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
    });
    expect(existsSync(missing)).toBe(false);
  });

  it('the creator runner enforces a finite deadline, kills the child, and settles once', async () => {
    const runCreator = store.defaultCreatorRunner(systemRoot);
    const ping = join(systemRoot, 'System32', 'PING.EXE');
    const started = Date.now();
    const result = await runCreator(ping, ['-n', '30', '127.0.0.1'], Buffer.from('x'));
    expect(result).toEqual({ ok: false, reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT });
    expect(Date.now() - started).toBeLessThan(25000);
  }, 40000);

  it('FINDING — a genuine exit 6 that lands while this event loop is stalled across the deadline is still CREATOR_WROTE_THEN_FAILED (real transport)', async () => {
    const runCreator = store.defaultCreatorRunner(systemRoot);
    const dir = mkdtempSync(join(tmpdir(), 'abctl-exit-'));
    tempRoots.push(dir);
    const script = join(dir, 'exit.mjs');
    writeFileSync(
      script,
      'const mode = process.argv[2];\n' +
        "if (mode === 'hang') { setInterval(() => {}, 1000); } else { process.exit(Number(mode)); }\n",
      'utf8',
    );
    // All three children start now; the two exits land within milliseconds.
    const exit6 = runCreator(process.execPath, [script, '6'], Buffer.from('x'));
    const exit5 = runCreator(process.execPath, [script, '5'], Buffer.from('x'));
    const hang = runCreator(process.execPath, [script, 'hang'], Buffer.from('x'));
    // Stall THIS event loop past the runner's fixed 5 s deadline. When the loop
    // resumes, libuv runs the timers phase before the I/O phase, so execFile's
    // deadline timer fires — setting `killed` — before the already-completed
    // exits are observed. A numeric exit code must still win: exit 6 proves the
    // file was created and authorizes cleanup of exactly this runtime's path;
    // collapsing it into a timeout would leave that residual in place.
    const stallUntil = Date.now() + 5500;
    while (Date.now() < stallUntil) {
      /* deliberate synchronous stall */
    }
    expect(await exit6).toEqual({ ok: false, reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_WROTE_THEN_FAILED });
    expect(await exit5).toEqual({ ok: false, reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED });
    expect(await hang).toEqual({ ok: false, reason: store.DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT });
  }, 30000);

  /* ---- creator lifecycle under forced termination (kernel delete-on-close) ---- */

  /** Spawn the real creator with the descriptor on stdin; resolve with its settlement. */
  const spawnCreator = (
    anchor: string,
    runtimeId: string,
    payload: Buffer,
    stdinMode: 'deliver' | 'hold-open',
  ): { child: ChildProcess; settled: Promise<{ code: number | null; signal: NodeJS.Signals | null }> } => {
    const child = spawn(creatorPath, [anchor, runtimeId], { windowsHide: true, stdio: ['pipe', 'ignore', 'ignore'] });
    children.push(child);
    const settled = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolvePromise) => {
      child.once('exit', (code, signal) => {
        resolvePromise({ code, signal });
      });
      child.once('error', () => {
        resolvePromise({ code: null, signal: null });
      });
    });
    child.stdin.on('error', () => {
      /* a child that never reads (killed) makes the write fail; irrelevant here */
    });
    if (stdinMode === 'deliver') {
      child.stdin.end(payload);
    } else {
      child.stdin.write(payload.subarray(0, 8)); // partial, never EOF: the creator waits pre-create
    }
    return { child, settled };
  };

  const sleep = (ms: number): Promise<void> =>
    new Promise<void>((resolvePromise) => {
      setTimeout(resolvePromise, ms);
    });

  it('S0: a creator killed before CREATE_NEW (stdin never reaches EOF) creates nothing', async () => {
    const { anchor } = await makeAnchor();
    const minted = mint();
    const payload = Buffer.from(store.serializeDescriptor(minted.descriptor), 'utf8');
    const { child, settled } = spawnCreator(anchor, minted.runtimeId, payload, 'hold-open');
    // The creator reads stdin to EOF BEFORE any filesystem mutation; with EOF
    // withheld it cannot advance past S0 no matter how long it runs.
    await sleep(500);
    expect(readdirSync(anchor)).toEqual([]);
    child.kill();
    const outcome = await settled;
    expect(outcome.signal).not.toBeNull();
    expect(readdirSync(anchor)).toEqual([]);
  }, 20000);

  it('S1/S2: a creator terminated at any point can never leave an incomplete descriptor — every surviving file is the complete payload', async () => {
    const { anchor } = await makeAnchor();
    const payload = Buffer.alloc(4096, 0x7b); // the maximum payload: the widest possible write window
    const iterations = 120;
    const spreadMs = 60; // covers process start-up through normal completion on this class of machine
    const outcomes = { killed: 0, completed: 0, other: 0 };
    for (let i = 0; i < iterations; i += 1) {
      const runtimeId = randomBytes(16).toString('hex');
      const descriptorPath = store.descriptorPathFor(anchor, runtimeId);
      const { child, settled } = spawnCreator(anchor, runtimeId, payload, 'deliver');
      // Deterministic stagger (not random): iteration i is killed i/iterations of
      // the way through the spread, so the kill instants sweep the whole lifecycle.
      await sleep((i * spreadMs) / iterations);
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      const outcome = await settled;
      if (outcome.signal !== null) {
        outcomes.killed += 1;
        // THE INVARIANT (deterministic regardless of where the kill landed): a file
        // of this invocation either does not exist (kernel delete-on-close removed
        // it at handle teardown) or is complete and byte-exact (the disposition was
        // cancelled only after a full flushed write). Never empty, never partial.
        if (existsSync(descriptorPath)) {
          expect(readFileSync(descriptorPath).equals(payload), `iteration ${String(i)}: a surviving file must be complete`).toBe(true);
        }
      } else if (outcome.code === 0) {
        outcomes.completed += 1;
        // A normal completion leaves exactly the payload (the cancellation took;
        // delete-on-close did not remove a finished descriptor).
        expect(readFileSync(descriptorPath).equals(payload), `iteration ${String(i)}: exit 0 must leave the exact payload`).toBe(true);
      } else {
        outcomes.other += 1;
      }
    }
    // No iteration may have failed for a reason other than our kill.
    expect(outcomes.other).toBe(0);
    // Sweep the anchor once more: nothing but complete, byte-exact descriptors.
    for (const name of readdirSync(anchor)) {
      expect(readFileSync(join(anchor, name)).equals(payload), `${name} must be complete`).toBe(true);
    }
    // At least one kill landed (a delay of 0 ms is issued before the child can
    // have completed), so the invariant was exercised, not vacuous.
    expect(outcomes.killed).toBeGreaterThan(0);
  }, 120000);

  /* ---- 30. end to end: the real flow, the real anchor, the real CLI ------------ */

  it('END TO END: real anchor → real runtime (listen, create, verify) → real CLI discovery → APPLIED → orderly close', async () => {
    const { anchor } = await makeAnchor();
    const { runtime: autoflow, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const verify = (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
      Promise.resolve({ ok: true, anchorPath: anchor });

    // Nothing injected but the anchor location: real sweep, real pipe, real
    // creator, real read-only verification, real read-back.
    const handle = await runtime.startControlChannel({ orchestrator, verify, logger: silent });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);

    // The real creator made exactly one file: this runtime's descriptor. The
    // anchor holds no reserved file and no durable secret of any kind.
    expect(readdirSync(anchor)).toEqual([`runtime-descriptor-${handle.runtimeId}.json`]);
    const snapshot = await snapshotOf(handle.descriptorPath);
    expect(snapshot.ownerSid).toBe(operator.sid);
    expect(snapshot.daclProtected).toBe(true);
    expect(new Set(snapshot.aces.map((ace) => ace.sid))).toEqual(new Set([operator.sid, SYSTEM_SID]));
    expect(await store.verifyDescriptorAcl(handle.descriptorPath)).toEqual({ ok: true });
    const parsed = store.parseDescriptor(readFileSync(handle.descriptorPath, 'utf8'));
    expect(parsed?.runtimeId).toBe(handle.runtimeId);
    expect(parsed?.descriptor.pipeName).toBe(handle.pipeName);
    expect(await store.defaultPipeProbe()(handle.pipePath)).toBe('PRESENT');

    // The real CLI: real discovery over the real anchor, real probe, real pipe.
    const out: string[] = [];
    const err: string[] = [];
    const run = await cli.runControlCli({ verify, out: (m) => out.push(m), err: (m) => err.push(m) });
    expect(err).toEqual([]);
    expect(run.authenticated).toBe(true);
    expect(run.status).toBe('APPLIED');
    expect(autoflow.current()?.status).toBe('AWAITING_HUMAN_DECISION');

    handles.splice(handles.indexOf(handle), 1);
    await handle.close();
    expect(readdirSync(anchor)).toEqual([]); // own file removed; the anchor holds nothing else
    expect(await store.defaultPipeProbe()(handle.pipePath)).toBe('ABSENT');
    const after = await cli.runControlCli({ verify, out: silent, err: (m) => err.push(m) });
    expect(after.status).toBeNull();
    expect(err.some((line) => line.includes('NO_CANDIDATES'))).toBe(true);
  }, 30000);

  it('21. two real runtimes on one real anchor → two files, ambiguous CLI; one closes → the other is discoverable', async () => {
    const { anchor } = await makeAnchor();
    const a = newOrchestrator();
    const b = newOrchestrator();
    const verify = (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
      Promise.resolve({ ok: true, anchorPath: anchor });
    const first = await runtime.startControlChannel({ orchestrator: a.orchestrator, verify, logger: silent });
    const second = await runtime.startControlChannel({ orchestrator: b.orchestrator, verify, logger: silent });
    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    if (first === null || second === null) {
      return;
    }
    handles.push(second);
    expect(readdirSync(anchor).sort()).toEqual(
      [`runtime-descriptor-${first.runtimeId}.json`, `runtime-descriptor-${second.runtimeId}.json`].sort(),
    );
    const err: string[] = [];
    const ambiguous = await cli.runControlCli({ verify, out: silent, err: (m) => err.push(m) });
    expect(ambiguous.status).toBeNull();
    expect(err.some((line) => line.includes('ambiguous') && line.includes('2 live'))).toBe(true);
    expect(a.runtime.current()).toBeNull();
    expect(b.runtime.current()).toBeNull();

    await first.close();
    expect(readdirSync(anchor)).toEqual([`runtime-descriptor-${second.runtimeId}.json`]);
    const found = await cli.runControlCli({ verify, out: silent, err: silent });
    expect(found.authenticated).toBe(true);
    expect(found.status).toBe('NO_WORKFLOW');
  }, 30000);

  it('15/16. a crashed runtime leaves its real descriptor; the next real runtime sweeps exactly that file', async () => {
    const { anchor } = await makeAnchor();
    const crashed = mint();
    const crashedPipe = store.pipePathFromName(crashed.descriptor.pipeName);
    const holder = await spawnPipeHolder(crashedPipe);
    expect(
      await store.createDescriptorFileNative(anchor, crashed.runtimeId, Buffer.from(store.serializeDescriptor(crashed.descriptor), 'utf8')),
    ).toEqual({ ok: true });
    const crashedFile = `runtime-descriptor-${crashed.runtimeId}.json`;
    const verify = (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
      Promise.resolve({ ok: true, anchorPath: anchor });

    // Alive: a new runtime keeps the peer's file.
    const first = await runtime.startControlChannel({ orchestrator: newOrchestrator().orchestrator, verify, logger: silent });
    expect(first).not.toBeNull();
    if (first === null) {
      return;
    }
    handles.push(first);
    expect(readdirSync(anchor)).toContain(crashedFile);

    // Crash.
    holder.kill('SIGKILL');
    await new Promise<void>((resolvePromise) => {
      holder.once('exit', () => {
        resolvePromise();
      });
    });
    expect(readdirSync(anchor)).toContain(crashedFile);
    expect(await store.defaultPipeProbe()(crashedPipe)).toBe('ABSENT');

    // The next runtime removes exactly the dead file; the live peer's file stays.
    const next = await runtime.startControlChannel({ orchestrator: newOrchestrator().orchestrator, verify, logger: silent });
    expect(next).not.toBeNull();
    if (next === null) {
      return;
    }
    handles.push(next);
    expect(readdirSync(anchor).sort()).toEqual(
      [`runtime-descriptor-${first.runtimeId}.json`, `runtime-descriptor-${next.runtimeId}.json`].sort(),
    );
  }, 30000);

  it('CI-2 ON REAL WINDOWS: a squatter serving a real gate-passing descriptor it did not mint cannot make the CLI exit 0', async () => {
    const { anchor } = await makeAnchor();
    const verify = (): Promise<{ readonly ok: true; readonly anchorPath: string }> =>
      Promise.resolve({ ok: true, anchorPath: anchor });

    // The squatter's file is created by the REAL creator, so its owner and
    // PROTECTED operator+SYSTEM DACL are exactly what the gate wants, and it is
    // a perfectly well-formed v3 descriptor. It is PRESENT on a real pipe. The
    // one thing its holder does not have is the ephemeral private key.
    const squatted = mint();
    expect(
      await store.createDescriptorFileNative(
        anchor,
        squatted.runtimeId,
        Buffer.from(store.serializeDescriptor(squatted.descriptor), 'utf8'),
      ),
    ).toEqual({ ok: true });
    expect(await store.verifyDescriptorAcl(store.descriptorPathFor(anchor, squatted.runtimeId))).toEqual({
      ok: true,
    });
    const squattedPipe = store.pipePathFromName(squatted.descriptor.pipeName);
    await spawnPipeHolder(squattedPipe);
    expect(await store.defaultPipeProbe()(squattedPipe)).toBe('PRESENT');

    // Discovery legitimately FINDS it — nothing about the file or its ACL is
    // wrong. Authentication is what refuses it, and the CLI never reports
    // APPLIED and never exits 0.
    const err: string[] = [];
    const alone = await cli.runControlCli({
      verify,
      out: silent,
      err: (m) => err.push(m),
      timeoutMs: 2000,
    });
    expect(alone.authenticated).toBe(false);
    expect(alone.status).toBeNull();
    expect(alone.exitCode).toBe(1);

    // Beside a genuine runtime, two live pipes are AMBIGUOUS: still fail closed.
    const genuine = await runtime.startControlChannel({
      orchestrator: newOrchestrator().orchestrator,
      verify,
      logger: silent,
    });
    expect(genuine).not.toBeNull();
    if (genuine === null) {
      return;
    }
    handles.push(genuine);
    const both = await cli.runControlCli({ verify, out: silent, err: silent, timeoutMs: 2000 });
    expect(both.exitCode).toBe(1);
    expect(both.status).toBeNull();

    // The genuine runtime published a real public identity and no private key.
    const published = store.parseDescriptor(readFileSync(genuine.descriptorPath, 'utf8'));
    expect(published).not.toBeNull();
    expect(published?.verifyKey.length).toBe(VERIFY_KEY_BYTES);
    expect(publicKeyFromVerifyKey(published?.verifyKey ?? Buffer.alloc(0))).not.toBeNull();
    expect(readFileSync(genuine.descriptorPath, 'utf8')).not.toContain('PRIVATE');
    // The squatted file is never swept while its pipe answers PRESENT.
    expect(readdirSync(anchor)).toContain(`runtime-descriptor-${squatted.runtimeId}.json`);
  }, 30000);

  it('a non-compliant anchor (inheritable Everyone) fails the real anchor gate, so no runtime ever publishes there', async () => {
    const { anchor } = await makeAnchor(true);
    const verdict = await store.verifyControlAnchor({ anchorPath: anchor });
    expect(verdict).toEqual({ ok: false, reason: store.CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL });
    const handle = await runtime.startControlChannel({
      orchestrator: newOrchestrator().orchestrator,
      // The REAL anchor gate, pointed at this anchor.
      verify: () => store.verifyControlAnchor({ anchorPath: anchor }),
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(readdirSync(anchor)).toEqual([]);
  });
});
