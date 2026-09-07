/**
 * D062 supported-launch lifecycle regression (PR #85/#90 canonical-provenance).
 *
 * The launch-time provisioning gate (tools/control-owner/ensure-helper.mjs) makes a
 * clean — or partially/torn/malformed — checkout coherent before control-anchor
 * verification, by rebuilding through the trusted build.mjs unless the on-disk pair
 * is CANONICAL. Canonical means exactly one thing:
 *
 *     provenance bytes == encodeProvenance(sha256(helper bytes))
 *
 * produced by the single shared encoder (tools/control-owner/provenance-format.mjs),
 * which build.mjs also uses to publish. The gate does no field extraction, no regex
 * acceptance, no JS import/parse, and no normalization — so the ACCEPTED SET is the
 * singleton {encodeProvenance(sha256(helper))} and the FALSE-VALID SET is empty.
 *
 * These tests drive the REAL encoder and REAL validator over the full adversarial
 * artifact-state matrix (including the exact Codex truncated-module witness and the
 * duplicate-field witness), pin the launch/CI wiring, confirm the runtime still
 * fails closed independently, and (on Windows) confirm the real gate skips a
 * canonical pair without mutating the shared binary.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  validateHelperPair,
  encodeProvenance,
  OWNER_HELPER_BASENAME,
} from '../../tools/control-owner/ensure-helper.mjs';
import {
  CONTROL_ANCHOR_REJECTION,
  verifyAnchorSnapshot,
  type OperatorIdentity,
  type OwnerHelperProvenance,
  type ProcessRunner,
} from '../../src/control/control-store.js';

const PROVENANCE_BASENAME = 'owner-helper-provenance.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const ensureScript = join(repoRoot, 'tools', 'control-owner', 'ensure-helper.mjs');
const realExe = join(repoRoot, 'dist', 'control', 'native', OWNER_HELPER_BASENAME);
const realProv = join(repoRoot, 'dist', 'control', 'native', PROVENANCE_BASENAME);

const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};
const ciYml = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8');

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}
function canonicalFor(bytes: Buffer): string {
  return encodeProvenance(sha256Hex(bytes));
}

interface Pair {
  readonly exePath: string;
  readonly provenancePath: string;
}
function tmpPair(): { dir: string; pair: Pair } {
  const dir = mkdtempSync(join(tmpdir(), 'ab-canon-'));
  return {
    dir,
    pair: { exePath: join(dir, OWNER_HELPER_BASENAME), provenancePath: join(dir, PROVENANCE_BASENAME) },
  };
}
/** Run `fn` against a fresh temp dir, always cleaning up. */
function withPair(fn: (pair: Pair) => void): void {
  const { dir, pair } = tmpPair();
  try {
    fn(pair);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
function writeExe(pair: Pair, bytes: Buffer): void {
  writeFileSync(pair.exePath, bytes);
}

/* ---- 1. Canonical-equality acceptance matrix (cross-platform, real encoder) -- */

const HELPER = Buffer.from('the-real-helper-bytes');

describe('D062 canonical provenance — acceptance matrix (FALSE-VALID set is empty)', () => {
  it('1. canonical valid pair → VALID (skip)', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, canonicalFor(HELPER));
      const r = validateHelperPair(p);
      expect(r).toEqual({ valid: true, reason: 'valid' });
    });
  });

  it('2. neither artifact → INVALID', () => {
    withPair((p) => {
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('3. helper only → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('4. provenance only → INVALID', () => {
    withPair((p) => {
      writeFileSync(p.provenancePath, canonicalFor(HELPER));
      const r = validateHelperPair(p);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe('helper-missing');
    });
  });

  it('5. wrong SHA (canonical-shaped for other bytes) → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, canonicalFor(Buffer.from('different')));
      const r = validateHelperPair(p);
      expect(r).toEqual({ valid: false, reason: 'not-canonical' });
    });
  });

  it('6. torn pair (new helper beside provenance for old bytes) → INVALID', () => {
    withPair((p) => {
      const provForOld = canonicalFor(Buffer.from('OLD-helper'));
      writeExe(p, Buffer.from('NEW-helper'));
      writeFileSync(p.provenancePath, provForOld);
      expect(validateHelperPair(p).reason).toBe('not-canonical');
    });
  });

  it('7. truncated canonical provenance at EVERY byte offset → never VALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const canon = Buffer.from(canonicalFor(HELPER), 'utf8');
      for (let i = 0; i < canon.length; i += 1) {
        writeFileSync(p.provenancePath, canon.subarray(0, i));
        expect(validateHelperPair(p).valid, `prefix len ${String(i)} must be INVALID`).toBe(false);
      }
      // The full length is the only VALID representation.
      writeFileSync(p.provenancePath, canon);
      expect(validateHelperPair(p).valid).toBe(true);
    });
  }, 60000);

  it('7b. exact Codex witness (through the sha256 line, no closing syntax) → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const canon = canonicalFor(HELPER);
      const cut = canon.indexOf('\n', canon.indexOf('sha256:')) + 1; // end of sha256 line
      writeFileSync(p.provenancePath, canon.slice(0, cut));
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('8. duplicate filename field → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const canon = canonicalFor(HELPER);
      const dup = canon.replace(
        /( {2}filename: "[^"]*",\n)/,
        '$1  filename: "agentbridge-win-owner.exe",\n',
      );
      expect(dup).not.toBe(canon);
      writeFileSync(p.provenancePath, dup);
      expect(validateHelperPair(p).reason).toBe('not-canonical');
    });
  });

  it('9. duplicate sha256 field → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const canon = canonicalFor(HELPER);
      const dup = canon.replace(/( {2}sha256: "[^"]*",\n)/, '$1$1');
      expect(dup).not.toBe(canon);
      writeFileSync(p.provenancePath, dup);
      expect(validateHelperPair(p).reason).toBe('not-canonical');
    });
  });

  it('10. leading extra content → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, `\uFEFF${canonicalFor(HELPER)}`);
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('11. trailing extra content → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, `${canonicalFor(HELPER)}// extra\n`);
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('12. injected comment → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const canon = canonicalFor(HELPER);
      writeFileSync(p.provenancePath, canon.replace('export const', '/* x */ export const'));
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('13. alternate whitespace → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, canonicalFor(HELPER).replace('  filename', '    filename'));
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('14. CRLF instead of canonical LF → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, canonicalFor(HELPER).replace(/\n/g, '\r\n'));
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('15. uppercase hash → INVALID (encoder emits lowercase)', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const upper = canonicalFor(HELPER).replace(/(sha256: ")([0-9a-f]{64})(")/, (_m, a: string, h: string, b: string) => a + h.toUpperCase() + b);
      writeFileSync(p.provenancePath, upper);
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('16. malformed UTF-8 / garbage provenance → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, Buffer.from([0xff, 0xfe, 0x00, 0x9f, 0x28]));
      expect(validateHelperPair(p).valid).toBe(false);
    });
  });

  it('17. helper tampered after provenance written → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, canonicalFor(HELPER));
      writeExe(p, Buffer.concat([HELPER, Buffer.from([0])])); // tamper helper
      expect(validateHelperPair(p).reason).toBe('not-canonical');
    });
  });

  it('18. provenance tampered (single byte) at every position → INVALID', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      const canon = Buffer.from(canonicalFor(HELPER), 'utf8');
      for (let i = 0; i < canon.length; i += 1) {
        const m = Buffer.from(canon);
        m[i] = (m[i] ?? 0) ^ 0x01;
        writeFileSync(p.provenancePath, m);
        expect(validateHelperPair(p).valid, `byte ${String(i)} flipped must be INVALID`).toBe(false);
      }
    });
  }, 60000);
});

/* ---- 2. Supported-launch + CI wiring (cross-platform, definition-level) ----- */

describe('D062 canonical provenance — gate wired into launch and CI', () => {
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

  it('helper:build still points at the trusted builder', () => {
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

describe('D062 canonical provenance — runtime fails closed without a valid pair', () => {
  it('absent provenance → HELPER_PROVENANCE_MISSING', async () => {
    const result = await verifyAnchorSnapshot(operator, anchorPath, unusedRunner, {
      loadProvenance: (): Promise<OwnerHelperProvenance | null> => Promise.resolve(null),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING);
    }
  });

  it('mismatched pair → HELPER_HASH_MISMATCH', async () => {
    const result = await verifyAnchorSnapshot(operator, anchorPath, unusedRunner, {
      loadProvenance: (): Promise<OwnerHelperProvenance> =>
        Promise.resolve({ filename: OWNER_HELPER_BASENAME, sha256: 'a'.repeat(64) }),
      readHelperBytes: (): Buffer => Buffer.from('new helper B'),
      hashBytes: (): string => 'b'.repeat(64),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH);
    }
  });
});

/* ---- 4. Real gate on Windows: skip a canonical pair (non-mutating) ---------- */

function runGate(): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [ensureScript], { encoding: 'utf8' });
}

describe.skipIf(process.platform === 'win32')(
  'D062 canonical provenance — gate skips cleanly on non-Windows',
  () => {
    it('exits 0 and requires no compiler', () => {
      const before = existsSync(realExe);
      const run = runGate();
      expect(run.status).toBe(0);
      expect(existsSync(realExe)).toBe(before);
    });
  },
);

// Windows: gate on the artifacts already present (post build + gate, as CI/the
// operator provisions). Non-mutating: assert only the canonical-pair idempotent
// skip — never rewrite the shared exe that owner-helper.win.test.ts executes
// concurrently (a rebuild would lock it, EBUSY). Real absent/torn/truncated →
// rebuild is exercised race-free by the CI provisioning step and the session's
// clean-artifact reproductions.
const winReady = process.platform === 'win32' && existsSync(realExe) && existsSync(realProv);

describe.skipIf(!winReady)('D062 canonical provenance — real gate idempotent on a canonical pair', () => {
  it('the real pair is canonical, and the gate skips it without rebuilding', () => {
    const bytes = readFileSync(realExe);
    expect(readFileSync(realProv, 'utf8')).toBe(encodeProvenance(sha256Hex(bytes)));
    const v = validateHelperPair({ exePath: realExe, provenancePath: realProv });
    expect(v.valid).toBe(true);

    const run = runGate();
    expect(run.status).toBe(0);
    expect(String(run.stderr)).toContain('skipping build');

    expect(validateHelperPair({ exePath: realExe, provenancePath: realProv }).valid).toBe(true);
  });
});
