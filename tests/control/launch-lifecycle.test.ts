/**
 * D062 supported-launch lifecycle regression (PR #85 helper-build P2).
 *
 * The mandatory owner/DACL helper and its generated provenance are produced only
 * by `tools/control-owner/build.mjs`. Before this fix the supported production
 * launch scripts (`npm run control`, `npm run cockpit:live`) ran only the
 * TypeScript build, so a clean Windows checkout launched into a control channel
 * that failed closed with HELPER_PROVENANCE_MISSING. The only real-binary test
 * (owner-helper.win.test.ts) is gated on the helper *already* existing and CI
 * built it as a separate manual step — so nothing asserted that the supported
 * lifecycle itself provisions the helper. That is exactly the gap these tests pin.
 *
 * The primary invariant here is lifecycle-level and cross-platform: the launch
 * scripts must run the provisioning gate between build and node. It cannot be
 * masked by an auditor manually running `helper:build` first, because it inspects
 * the script definitions, not transient build state.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  CONTROL_ANCHOR_REJECTION,
  verifyAnchorSnapshot,
  type OperatorIdentity,
  type OwnerHelperProvenance,
} from '../../src/control/control-store.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};

const ensureScript = join(repoRoot, 'tools', 'control-owner', 'ensure-helper.mjs');
const exePath = join(repoRoot, 'dist', 'control', 'native', 'agentbridge-win-owner.exe');
const provPath = join(repoRoot, 'dist', 'control', 'native', 'owner-helper-provenance.js');

/** The gate must run between the TypeScript build and the Node launch. */
const GATE = 'node tools/control-owner/ensure-helper.mjs';

describe('D062 supported-launch lifecycle — helper provisioning is part of launch', () => {
  it('the provisioning gate exists', () => {
    expect(existsSync(ensureScript)).toBe(true);
  });

  it.each([
    ['control', 'node dist/control/cli.js'],
    ['cockpit:live', 'node dist/runtime/live-cockpit.js'],
  ])('`npm run %s` builds, then provisions the helper, then launches', (name, launch) => {
    const script = pkg.scripts[name];
    expect(script, `${name} script must exist`).toBeTypeOf('string');
    const steps = (script ?? '').split('&&').map((s) => s.trim());
    const buildIndex = steps.indexOf('npm run build');
    const gateIndex = steps.indexOf(GATE);
    const launchIndex = steps.indexOf(launch);
    // Build first, then the helper gate, then the actual launch — in that order.
    expect(buildIndex, `${name} must run "npm run build"`).toBeGreaterThanOrEqual(0);
    expect(gateIndex, `${name} must run the helper provisioning gate`).toBeGreaterThan(buildIndex);
    expect(launchIndex, `${name} must launch after provisioning`).toBeGreaterThan(gateIndex);
  });

  it('helper:build still points at the trusted build script (unchanged trust root)', () => {
    expect(pkg.scripts['helper:build']).toBe('node tools/control-owner/build.mjs');
  });
});

/* ---- Fail-closed semantics (cross-platform, injected deps, no real binary) --- */

const operator: OperatorIdentity = { name: 'AGENT\\op', sid: 'S-1-5-21-1-2-3-1001' };
const anchorPath = 'C:\\ProgramData\\AgentBridge\\control';
const unusedRunner = (): Promise<never> => {
  throw new Error('runProcess must not be reached when provenance is rejected');
};

describe('D062 supported-launch lifecycle — still fails closed without valid provenance', () => {
  it('absent provenance yields HELPER_PROVENANCE_MISSING (never runs the helper)', async () => {
    const result = await verifyAnchorSnapshot(operator, anchorPath, unusedRunner, {
      loadProvenance: (): Promise<OwnerHelperProvenance | null> => Promise.resolve(null),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('tampered provenance (hash mismatch) fails closed with HELPER_HASH_MISMATCH', async () => {
    const wrongHash = 'a'.repeat(64);
    const result = await verifyAnchorSnapshot(operator, anchorPath, unusedRunner, {
      loadProvenance: (): Promise<OwnerHelperProvenance> =>
        Promise.resolve({ filename: 'agentbridge-win-owner.exe', sha256: wrongHash }),
      readHelperBytes: (): Buffer => Buffer.from('not the real helper'),
      hashBytes: (): string => 'b'.repeat(64),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH);
    }
  });
});

/* ---- Provisioning-gate behaviour (child process, platform-gated) ------------ */

function runGate(): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [ensureScript], { encoding: 'utf8' });
}

describe.skipIf(process.platform === 'win32')(
  'D062 supported-launch lifecycle — gate skips cleanly on non-Windows',
  () => {
    it('exits 0 and requires no compiler (the control channel is Windows-only)', () => {
      const before = existsSync(exePath);
      const run = runGate();
      expect(run.status).toBe(0);
      // It must not attempt (or fake) a native build off Windows.
      expect(existsSync(exePath)).toBe(before);
    });
  },
);

// On Windows the compile part needs MSVC; mirror owner-helper.win.test.ts and gate
// on the artifacts already being present (the state after build + helper:build, as
// the CI Windows lane provisions). Here we prove the gate is idempotent and that
// the generated provenance is loadable and byte-exact.
const winReady =
  process.platform === 'win32' && existsSync(exePath) && existsSync(provPath);

describe.skipIf(!winReady)(
  'D062 supported-launch lifecycle — gate is idempotent once provisioned (Windows)',
  () => {
    it('exits 0 and preserves the existing helper + provenance (no needless recompile)', () => {
      const run = runGate();
      expect(run.status).toBe(0);
      expect(existsSync(exePath)).toBe(true);
      expect(existsSync(provPath)).toBe(true);
    });

    it('the generated provenance is byte-exact and shaped for defaultLoadProvenance', async () => {
      const actual = createHash('sha256').update(readFileSync(exePath)).digest('hex');
      const loaded = (await import(pathToFileURL(provPath).href)) as {
        OWNER_HELPER_PROVENANCE?: { filename?: unknown; sha256?: unknown };
      };
      const prov = loaded.OWNER_HELPER_PROVENANCE;
      expect(typeof prov?.filename).toBe('string');
      expect(typeof prov?.sha256).toBe('string');
      expect(prov?.sha256).toBe(actual);
    });
  },
);
