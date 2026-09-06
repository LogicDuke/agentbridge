/**
 * Real Windows integration for the Decision 062 / PR #84 F1 owner-SID gate.
 *
 * Unlike the pure/injected tests in control-store.test.ts, this exercises the
 * ACTUAL compiled helper binary through the production code path: it imports the
 * built `dist/control/control-store.js` and calls `verifyAnchorOwner` with no
 * injected deps, so the default provenance load (the generated JS metadata beside
 * the binary), the SHA-256 hash gate, and the real bounded `execFile` transport
 * all run for real against `dist/control/native/agentbridge-win-owner.exe`.
 *
 * It is gated to win32 with a built dist + helper. On Linux CI, or before
 * `npm run build && npm run helper:build`, the whole suite is skipped — its
 * behaviour cannot be proven cross-platform and is not asserted there.
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import type {
  OperatorIdentity,
  ProcessRunner,
} from '../../src/control/control-store.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const distStore = join(repoRoot, 'dist', 'control', 'control-store.js');
const exePath = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-owner.exe');
const provPath = join(repoRoot, 'dist', 'control', 'native', 'owner-helper-provenance.js');

const ready =
  process.platform === 'win32' &&
  existsSync(distStore) &&
  existsSync(exePath) &&
  existsSync(provPath);

type StoreModule = typeof import('../../src/control/control-store.js');

describe.skipIf(!ready)('D062 owner helper — real Windows binary integration', () => {
  const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';
  let store!: StoreModule;
  let operator!: OperatorIdentity;
  let runner!: ProcessRunner;

  beforeAll(async () => {
    store = (await import(pathToFileURL(distStore).href)) as StoreModule;
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

  it('accepts an operator-owned temp dir; fails closed when the runner elevates ownership', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-own-'));

    // A freshly created temp directory is NOT unconditionally operator-owned: in a
    // non-elevated context the operator really owns what it just created, but on an
    // elevated GitHub Actions Windows runner a new directory is owned by the
    // Administrators group (or SYSTEM), i.e. a non-operator SID. So first read the
    // directory's ACTUAL owner SID through the same real, build-provenanced helper
    // binary the production gate uses — test #1 above asserts these exact bytes
    // match the generated provenance hash — then assert the corresponding
    // deterministic gate behaviour. This keeps the case meaningful in both
    // contexts rather than assuming ownership.
    const owned = await runner(exePath, [dir]);
    if (!owned.ok) {
      throw new Error('owner helper failed to report the temp directory owner SID');
    }
    const actualOwnerSid = store.parseOwnerHelperSid(owned.stdout);
    if (actualOwnerSid === null) {
      throw new Error('owner helper returned a non-canonical owner SID');
    }

    const result = await store.verifyAnchorOwner(operator, dir, runner);

    if (actualOwnerSid === operator.sid) {
      // Owner == operator → the gate MUST accept and echo that exact SID.
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.ownerSid).toBe(operator.sid);
      }
    } else {
      // Owner != operator (Administrators/SYSTEM on an elevated runner) → the gate
      // MUST fail closed; a foreign owner can never be treated as success. SYSTEM
      // ownership is rejected as OWNER_IS_SYSTEM (production checks it first); any
      // other foreign owner as OWNER_MISMATCH.
      const SYSTEM_SID = 's-1-5-18';
      const expectedReason =
        actualOwnerSid === SYSTEM_SID
          ? store.CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM
          : store.CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH;
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toBe(expectedReason);
      }
    }
  });

  it('rejects when the expected operator SID differs from the real owner', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-mismatch-'));
    const foreign: OperatorIdentity = { name: operator.name, sid: 's-1-5-21-0-0-0-4242' };
    const result = await store.verifyAnchorOwner(foreign, dir, runner);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(store.CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH);
    }
  });

  it('fails closed against a swapped binary (hash mismatch) using the real helper path', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-swap-'));
    const result = await store.verifyAnchorOwner(operator, dir, runner, {
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
