/**
 * D062 supported-launch lifecycle regression (PR #85 helper-provisioning family).
 *
 * The mandatory owner/DACL helper and its generated provenance are produced only
 * by `tools/control-owner/build.mjs`. The supported production launch scripts
 * (`npm run control`, `npm run cockpit:live`) must ensure a VALID helper/provenance
 * pair exists before control-anchor verification runs — on a clean checkout AND
 * after a partial/torn provisioning. It is not enough that both files merely exist:
 * an interrupted build can leave a new executable beside stale provenance, which
 * the runtime rejects with HELPER_HASH_MISMATCH and which a supported relaunch must
 * self-heal by rebuilding rather than skipping.
 *
 * These tests pin: (1) the pure pair-validity decision across the full artifact
 * state matrix; (2) that the launch scripts and Windows CI run the provisioning
 * gate between build and launch (an invariant that cannot be masked by manually
 * running `helper:build` first); (3) that the runtime still fails closed on absent
 * or mismatched provenance (independent of the gate); and (4), on Windows, that the
 * real gate skips a valid pair and rebuilds an invalid one.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { validateHelperPair } from '../../tools/control-owner/ensure-helper.mjs';
import {
  CONTROL_ANCHOR_REJECTION,
  verifyAnchorSnapshot,
  type OperatorIdentity,
  type OwnerHelperProvenance,
  type ProcessRunner,
} from '../../src/control/control-store.js';

const HELPER_BASENAME = 'agentbridge-win-owner.exe';
const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const ensureScript = join(repoRoot, 'tools', 'control-owner', 'ensure-helper.mjs');
const realExe = join(repoRoot, 'dist', 'control', 'native', HELPER_BASENAME);
const realProv = join(repoRoot, 'dist', 'control', 'native', PROVENANCE_BASENAME);

const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};
const ciYml = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8');

/** Provenance module text in the exact shape build.mjs emits. */
function provenanceText(filename: string, sha256: string): string {
  return (
    '// GENERATED BUILD METADATA — do not edit.\n' +
    'export const OWNER_HELPER_PROVENANCE = {\n' +
    `  filename: ${JSON.stringify(filename)},\n` +
    `  sha256: ${JSON.stringify(sha256)},\n` +
    '  built: true,\n' +
    '};\n'
  );
}

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

interface Pair {
  readonly exePath: string;
  readonly provenancePath: string;
  readonly expectedFilename: string;
}

function tmpPair(): { dir: string; pair: Pair } {
  const dir = mkdtempSync(join(tmpdir(), 'ab-lifecycle-'));
  return {
    dir,
    pair: {
      exePath: join(dir, HELPER_BASENAME),
      provenancePath: join(dir, PROVENANCE_BASENAME),
      expectedFilename: HELPER_BASENAME,
    },
  };
}

/* ---- 1. Pure pair-validity across the full artifact-state matrix ------------ */

describe('D062 launch lifecycle — validateHelperPair covers the artifact-state matrix', () => {
  it('1. neither artifact present → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('provenance-missing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('2. helper only (provenance absent) → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      writeFileSync(pair.exePath, Buffer.from('helper-bytes'));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('provenance-missing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('3. provenance only (helper absent) → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      writeFileSync(pair.provenancePath, provenanceText(HELPER_BASENAME, 'a'.repeat(64)));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('helper-missing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('4. both present + matching hash → VALID (skip)', () => {
    const { dir, pair } = tmpPair();
    try {
      const bytes = Buffer.from('the-real-helper');
      writeFileSync(pair.exePath, bytes);
      writeFileSync(pair.provenancePath, provenanceText(HELPER_BASENAME, sha256Hex(bytes)));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(true);
      expect(r.reason).toBe('valid');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('5/10/11. torn pair — new helper beside stale provenance hash → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      const stale = sha256Hex(Buffer.from('OLD-helper-A'));
      writeFileSync(pair.exePath, Buffer.from('NEW-helper-B')); // different bytes
      writeFileSync(pair.provenancePath, provenanceText(HELPER_BASENAME, stale));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('hash-mismatch');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('6. provenance malformed (no generated shape) → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      writeFileSync(pair.exePath, Buffer.from('x'));
      writeFileSync(pair.provenancePath, 'this is not the generated module {');
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('provenance-shape');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('7. provenance missing required fields → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      writeFileSync(pair.exePath, Buffer.from('x'));
      writeFileSync(pair.provenancePath, 'export const OWNER_HELPER_PROVENANCE = { built: true };\n');
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('provenance-fields-missing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('8. provenance references the wrong helper filename → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      const bytes = Buffer.from('x');
      writeFileSync(pair.exePath, bytes);
      writeFileSync(pair.provenancePath, provenanceText('some-other.exe', sha256Hex(bytes)));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('provenance-wrong-filename');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('9. provenance sha is not a lowercase 64-hex digest → invalid (rebuild)', () => {
    const { dir, pair } = tmpPair();
    try {
      writeFileSync(pair.exePath, Buffer.from('x'));
      writeFileSync(pair.provenancePath, provenanceText(HELPER_BASENAME, 'NOThex'));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('provenance-bad-hash-shape');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('12. provenance tampered (valid shape, hash rewritten) while helper stays → invalid', () => {
    const { dir, pair } = tmpPair();
    try {
      const bytes = Buffer.from('the-real-helper');
      writeFileSync(pair.exePath, bytes);
      writeFileSync(pair.provenancePath, provenanceText(HELPER_BASENAME, 'b'.repeat(64)));
      const r = validateHelperPair(pair);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('hash-mismatch');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/* ---- 2. Supported-launch + CI wiring (cross-platform, definition-level) ----- */

describe('D062 launch lifecycle — provisioning gate is wired into launch and CI', () => {
  it('the provisioning gate exists', () => {
    expect(existsSync(ensureScript)).toBe(true);
  });

  it.each([
    ['control', 'node dist/control/cli.js'],
    ['cockpit:live', 'node dist/runtime/live-cockpit.js'],
  ])('`npm run %s` runs build → gate → launch, in order', (name, launch) => {
    const script = pkg.scripts[name];
    expect(script, `${name} script must exist`).toBeTypeOf('string');
    const steps = (script ?? '').split('&&').map((s) => s.trim());
    const buildIndex = steps.indexOf('npm run build');
    const gateIndex = steps.indexOf('node tools/control-owner/ensure-helper.mjs');
    const launchIndex = steps.indexOf(launch);
    expect(buildIndex, `${name} must run "npm run build"`).toBeGreaterThanOrEqual(0);
    expect(gateIndex, `${name} must run the provisioning gate`).toBeGreaterThan(buildIndex);
    expect(launchIndex, `${name} must launch after provisioning`).toBeGreaterThan(gateIndex);
  });

  it('helper:build still points at the trusted builder (unchanged trust root)', () => {
    expect(pkg.scripts['helper:build']).toBe('node tools/control-owner/build.mjs');
  });

  it('Windows CI exercises the supported gate, not a masking manual helper:build', () => {
    expect(ciYml).toMatch(/node tools\/control-owner\/ensure-helper\.mjs/);
    expect(ciYml).not.toMatch(/run:\s*npm run helper:build/);
  });
});

/* ---- 3. Runtime still fails closed (independent of the gate) ---------------- */

const operator: OperatorIdentity = { name: 'AGENT\\op', sid: 'S-1-5-21-1-2-3-1001' };
const anchorPath = 'C:\\ProgramData\\AgentBridge\\control';
const unusedRunner: ProcessRunner = () => {
  throw new Error('runProcess must not be reached when provenance is rejected');
};

describe('D062 launch lifecycle — runtime fails closed without a valid pair', () => {
  it('absent provenance → HELPER_PROVENANCE_MISSING (helper never executed)', async () => {
    const result = await verifyAnchorSnapshot(operator, anchorPath, unusedRunner, {
      loadProvenance: (): Promise<OwnerHelperProvenance | null> => Promise.resolve(null),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('torn/mismatched pair → HELPER_HASH_MISMATCH (fail closed)', async () => {
    const result = await verifyAnchorSnapshot(operator, anchorPath, unusedRunner, {
      loadProvenance: (): Promise<OwnerHelperProvenance> =>
        Promise.resolve({ filename: HELPER_BASENAME, sha256: 'a'.repeat(64) }),
      readHelperBytes: (): Buffer => Buffer.from('new helper B'),
      hashBytes: (): string => 'b'.repeat(64),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH);
    }
  });
});

/* ---- 4. Real gate on Windows: skip a valid pair, rebuild an invalid one ------ */

function runGate(): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [ensureScript], { encoding: 'utf8' });
}

describe.skipIf(process.platform === 'win32')(
  'D062 launch lifecycle — gate skips cleanly on non-Windows',
  () => {
    it('exits 0 and requires no compiler (control channel is Windows-only)', () => {
      const before = existsSync(realExe);
      const run = runGate();
      expect(run.status).toBe(0);
      expect(existsSync(realExe)).toBe(before);
    });
  },
);

// On Windows, gate on the artifacts already being present (the state after build
// + a prior gate run, as the CI Windows lane provisions). This asserts only the
// NON-mutating idempotent skip against the real pair: it must not rewrite the
// shared generated executable, because owner-helper.win.test.ts executes that same
// binary in a parallel worker and a concurrent rebuild would lock it (EBUSY). The
// real torn-pair → rebuild self-heal is exercised race-free by the CI provisioning
// step (clean checkout, before vitest); the rebuild DECISION is covered by the
// validateHelperPair matrix above.
const winReady = process.platform === 'win32' && existsSync(realExe) && existsSync(realProv);

describe.skipIf(!winReady)(
  'D062 launch lifecycle — real gate is idempotent on a valid Windows pair',
  () => {
    it('a valid pair is skipped without rebuilding, and stays valid', () => {
      const v = validateHelperPair({
        exePath: realExe,
        provenancePath: realProv,
        expectedFilename: HELPER_BASENAME,
      });
      expect(v.valid).toBe(true);

      const run = runGate();
      expect(run.status).toBe(0);
      // The skip message (not a rebuild message) proves no recompilation occurred.
      expect(String(run.stderr)).toContain('skipping build');

      const after = validateHelperPair({
        exePath: realExe,
        provenancePath: realProv,
        expectedFilename: HELPER_BASENAME,
      });
      expect(after.valid).toBe(true);
    });
  },
);
