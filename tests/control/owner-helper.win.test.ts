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

  it('accepts a real operator-owned directory (owner SID == operator SID)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'abctl-own-'));
    const result = await store.verifyAnchorOwner(operator, dir, runner);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.ownerSid).toBe(operator.sid);
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
