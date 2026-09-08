/**
 * D062 coherent launch lifecycle regression (PR #85/#90/#91 reconstruction).
 *
 * Two frozen properties are pinned together here:
 *
 * 1. CANONICAL PAIR VALIDITY. The explicit provisioning gate
 *    (tools/control-owner/ensure-helper.mjs) makes a clean — or partially/torn/
 *    malformed — checkout coherent before control-anchor verification, by
 *    rebuilding through the trusted build.mjs unless the on-disk pair is
 *    CANONICAL. Canonical means exactly one thing:
 *
 *        provenance bytes == encodeProvenance(sha256(helper bytes))
 *
 *    produced by the single shared encoder (tools/control-owner/
 *    provenance-format.mjs), which build.mjs also uses to publish. The gate does
 *    no field extraction, no regex acceptance, no JS import/parse, and no
 *    normalization — so the ACCEPTED SET is the singleton
 *    {encodeProvenance(sha256(helper))} and the FALSE-VALID SET is empty.
 *
 * 2. LAUNCH SEPARATION. Provisioning is a prerequisite of the CONTROL-oriented
 *    flow only (`npm run control`); the read-only Cockpit launches (`cockpit`,
 *    `cockpit:live`) and the direct runtime launch (`node
 *    dist/runtime/live-cockpit.js`) never provision, never compile, and never
 *    depend on a provisioning outcome:
 *
 *        CONTROL_PROVISION_FAILURE ⇏ COCKPIT_FAILURE
 *        CONTROL_STARTUP_FAILURE   ⇏ COCKPIT_FAILURE
 *        RUNTIME_COMPILER_AUTHORITY = NONE
 *
 * These tests drive the REAL encoder and REAL validator over the full adversarial
 * artifact-state matrix (including the exact Codex truncated-module witness and
 * the duplicate-field witness), pin the launch wiring, confirm the runtime still
 * fails closed independently, prove a fail-closed control startup leaves the
 * Cockpit serving, and (on Windows) exercise the real gate: idempotent skip on a
 * canonical pair, real clean-checkout provisioning in an isolated tree, loud
 * nonzero failure when the toolchain is unavailable, and concurrent-builder
 * isolation/convergence.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  validateHelperPair,
  encodeProvenance,
  OWNER_HELPER_BASENAME,
} from '../../tools/control-owner/ensure-helper.mjs';
import {
  CONTROL_ANCHOR_REJECTION,
  verifyAnchorSnapshot,
  type ControlAnchorVerification,
  type DescriptorFileDeps,
  type OperatorIdentity,
  type OwnerHelperProvenance,
  type ProcessRunner,
} from '../../src/control/control-store.js';
import { startControlChannel } from '../../src/control/control-runtime.js';
import { startLiveCockpit } from '../../src/runtime/live-cockpit.js';
import { createConfiguredRepositoryObserver } from '../../src/runtime/repository-observer.js';
import { AutoflowRuntime } from '../../src/autoflow/runtime.js';
import { newOrchestrator } from './support.js';

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

/* ---- 2. Coherent launch model (cross-platform, definition-level) ------------- */

describe('D062 coherent launch model — provisioning gates control only, never the Cockpit', () => {
  it('the provisioning gate exists', () => {
    expect(existsSync(ensureScript)).toBe(true);
  });

  it('`npm run control` runs build → explicit provisioning gate → control CLI, in order', () => {
    const script = pkg.scripts['control'];
    expect(script, 'control script must exist').toBeTypeOf('string');
    const steps = (script ?? '').split('&&').map((s) => s.trim());
    const buildIndex = steps.indexOf('npm run build');
    const gateIndex = steps.indexOf('node tools/control-owner/ensure-helper.mjs');
    const launchIndex = steps.indexOf('node dist/control/cli.js');
    expect(buildIndex, 'control must run "npm run build"').toBeGreaterThanOrEqual(0);
    expect(gateIndex, 'control must run the provisioning gate').toBeGreaterThan(buildIndex);
    expect(launchIndex, 'control must launch after provisioning').toBeGreaterThan(gateIndex);
  });

  it('`npm run cockpit` never provisions the native helper', () => {
    const script = pkg.scripts['cockpit'] ?? '';
    expect(script.length).toBeGreaterThan(0);
    expect(script).not.toMatch(/ensure-helper|helper:build|control-owner/);
  });

  it('`npm run cockpit:live` is exactly build → runtime launch, with NO provisioning step', () => {
    // Helper provisioning must not be a prerequisite for read-only Cockpit
    // availability: the known-defect shape `... && ensure-helper && live-cockpit`
    // is forbidden. A control provisioning failure therefore cannot prevent
    // `cockpit:live` from launching — the gate is simply never on its path.
    const script = pkg.scripts['cockpit:live'] ?? '';
    const steps = script.split('&&').map((s) => s.trim());
    expect(steps).toEqual(['npm run build', 'node dist/runtime/live-cockpit.js']);
  });

  it('the direct runtime launch step is plain `node dist/...` — no compiler invocation', () => {
    // `node dist/runtime/live-cockpit.js` runs already-built artifacts. Neither
    // tsc nor the native toolchain appears after the build step of any script.
    for (const name of ['cockpit', 'cockpit:live', 'control'] as const) {
      const steps = (pkg.scripts[name] ?? '').split('&&').map((s) => s.trim());
      for (const step of steps.filter((s) => s !== 'npm run build')) {
        expect(step, `${name} step "${step}" must not invoke a compiler`).not.toMatch(
          /\btsc\b|build\.mjs|cl\.exe/,
        );
      }
    }
  });

  it('helper:build still points at the trusted builder', () => {
    expect(pkg.scripts['helper:build']).toBe('node tools/control-owner/build.mjs');
  });

  it('`npm run control:provision` exists and is exactly the existing validated gate', () => {
    // PR #92 P2 repair: on a clean checkout the live runtime's ONE-SHOT control
    // startup runs before the helper/provenance pair exists and fails closed by
    // design (no retry, no watcher, no polling). The supported operator order is
    // therefore explicit pre-provisioning:
    //
    //     npm run control:provision → npm run cockpit:live → npm run control
    //
    // The command must reuse the one validated gate — no second provisioning
    // mechanism may exist.
    expect(pkg.scripts['control:provision']).toBe('node tools/control-owner/ensure-helper.mjs');
  });

  it('`control:provision` is a single explicit operator step — no build, launch, or server', () => {
    // An OPERATOR command, not runtime behavior: it invokes only the gate. It
    // starts no runtime, compiles no TypeScript, and is never a hidden step of
    // another launch script.
    const steps = (pkg.scripts['control:provision'] ?? '').split('&&').map((s) => s.trim());
    expect(steps).toEqual(['node tools/control-owner/ensure-helper.mjs']);
  });

  it('adding `control:provision` leaves both Cockpit launches provisioning-free', () => {
    // CONTROL_PROVISION_FAILURE ⇏ COCKPIT_FAILURE: the new command must not
    // leak into the read-only Cockpit paths — `cockpit:live` stays the exact
    // frozen build → runtime-launch string with no gate on its path.
    expect(pkg.scripts['cockpit'] ?? '').not.toMatch(/ensure-helper|helper:build|control-owner|control:provision/);
    expect(pkg.scripts['cockpit:live']).toBe('npm run build && node dist/runtime/live-cockpit.js');
  });

  it('Windows CI provisions the helper before the control tests', () => {
    expect(ciYml).toMatch(/npm run helper:build|ensure-helper\.mjs/);
  });

  it('runtime and control sources hold no compiler or provisioning authority', () => {
    // RUNTIME_COMPILER_AUTHORITY = NONE and
    // CONTROL_CLI_IMPLEMENTATION_COMPILER_AUTHORITY = NONE: nothing under
    // src/runtime or src/control references the TypeScript compiler, the native
    // builder, the provisioning gate, or MSVC discovery.
    const readAllSources = (dir: string): string => {
      let out = '';
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, entry.name);
        if (entry.isDirectory()) {
          out += readAllSources(p);
        } else if (entry.name.endsWith('.ts') || entry.name.endsWith('.js')) {
          out += readFileSync(p, 'utf8');
        }
      }
      return out;
    };
    const sources =
      readAllSources(join(repoRoot, 'src', 'runtime')) +
      readAllSources(join(repoRoot, 'src', 'control'));
    expect(sources).not.toMatch(/ensure-helper|build\.mjs|cl\.exe|vswhere|\btsc\b/);
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

/* ---- 4. Control startup failure leaves the Cockpit available ---------------- */

const openServers: http.Server[] = [];
afterEach(async () => {
  await Promise.all(
    openServers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => {
            resolve();
          });
        }),
    ),
  );
});

function waitListening(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    const done = (): void => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        reject(new Error('no port'));
        return;
      }
      resolve(address.port);
    };
    if (server.listening) {
      done();
      return;
    }
    server.once('listening', done);
    server.once('error', reject);
  });
}

function getStatus(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: '/' }, (res) => {
      res.resume();
      res.on('end', () => {
        resolve(res.statusCode ?? 0);
      });
    });
    req.on('error', reject);
    req.end();
  });
}

describe('D062 coherent launch model — CONTROL_STARTUP_FAILURE ⇏ COCKPIT_FAILURE', () => {
  it('a fail-closed control startup (helper trust rejected) leaves the Cockpit serving read-only', async () => {
    // Start the REAL read-only Cockpit host first — exactly the production order.
    const server = startLiveCockpit({
      config: {
        reader: new AutoflowRuntime().reader(),
        observer: createConfiguredRepositoryObserver({
          repositoryId: 'repo-agentbridge',
          observedHeadSha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
          defaultBranchRef: 'refs/heads/main',
        }),
        collectorId: 'agentbridge-live-runtime',
        clock: (): Date => new Date('2026-09-07T12:00:00.000Z'),
      },
      port: 0,
    });
    openServers.push(server);
    const port = await waitListening(server);

    // Then a REAL control-channel startup that fails closed the way an
    // unprovisioned/unusable helper does at launch: verification is rejected.
    let descriptorWrites = 0;
    const descriptorDeps: DescriptorFileDeps = {
      readFile: (): string => {
        throw new Error('ENOENT');
      },
      writeFile: (): void => {
        descriptorWrites += 1;
      },
      removeFile: (): void => {
        /* no-op */
      },
    };
    const { orchestrator } = newOrchestrator();
    const handle = await startControlChannel({
      orchestrator,
      verify: (): Promise<ControlAnchorVerification> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING }),
      descriptorDeps,
    });

    // Control fails CLOSED (null handle, no descriptor) …
    expect(handle).toBeNull();
    expect(descriptorWrites).toBe(0);
    // … and the Cockpit is still up and serving.
    expect(await getStatus(port)).toBe(200);
  });
});

/* ---- 5. Real gate on Windows: skip, provision, and fail loudly --------------- */

function runGate(): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [ensureScript], { encoding: 'utf8' });
}

describe.skipIf(process.platform === 'win32')(
  'D062 canonical provenance — gate skips cleanly on non-Windows',
  () => {
    it('exits 0 and requires no compiler (non-Windows Cockpit launches need no Windows tooling)', () => {
      const before = existsSync(realExe);
      const run = runGate();
      expect(run.status).toBe(0);
      expect(existsSync(realExe)).toBe(before);
    });
  },
);

// Windows: gate on the artifacts already present (post build + provisioning, as
// CI/the operator provisions). Non-mutating: assert only the canonical-pair
// idempotent skip — never rewrite the shared exe that owner-helper.win.test.ts
// executes concurrently (a rebuild would lock it, EBUSY). Real absent/torn →
// rebuild is exercised race-free in the ISOLATED trees below.
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

// Isolated copies of the gate + builder + encoder (+ optionally the C source)
// under a temp tree: the gate resolves everything module-relative, so the copy
// provisions into ITS OWN dist/control/native and never touches the shared dist.
function isolatedGateTree(withSource: boolean): {
  root: string;
  gateScript: string;
  buildScript: string;
  nativeDir: string;
} {
  const root = mkdtempSync(join(tmpdir(), 'ab-gate-'));
  const toolDir = join(root, 'tools', 'control-owner');
  mkdirSync(toolDir, { recursive: true });
  const files = ['ensure-helper.mjs', 'build.mjs', 'provenance-format.mjs'];
  if (withSource) {
    files.push('agentbridge-win-owner.c');
  }
  for (const f of files) {
    cpSync(join(repoRoot, 'tools', 'control-owner', f), join(toolDir, f));
  }
  return {
    root,
    gateScript: join(toolDir, 'ensure-helper.mjs'),
    buildScript: join(toolDir, 'build.mjs'),
    nativeDir: join(root, 'dist', 'control', 'native'),
  };
}

// PR #92 P2 (Codex): vswhere.exe existing is NOT "MSVC available". The Visual
// Studio Installer ships vswhere.exe even when the VC workload is absent (for
// example a .NET-only Visual Studio / Build Tools install); build.mjs then
// queries for the component below, finds no usable installation, and fails
// loudly. The test predicate must therefore apply the SAME component
// requirement the production builder passes to `vswhere -requires`, so the
// unavailable-toolchain configuration SKIPS this describe instead of failing.
const VC_TOOLS_COMPONENT = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64';

const vswherePath = join(
  process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)',
  'Microsoft Visual Studio',
  'Installer',
  'vswhere.exe',
);

/** installationPath of the newest Visual Studio providing `component`, exactly
 *  as build.mjs resolves it (same vswhere binary, same -requires query), or
 *  null when vswhere or a qualifying installation is unavailable. */
function vcInstallationPathFor(component: string): string | null {
  if (process.platform !== 'win32' || !existsSync(vswherePath)) {
    return null;
  }
  const run = spawnSync(
    vswherePath,
    ['-latest', '-products', '*', '-requires', component, '-property', 'installationPath'],
    { encoding: 'utf8' },
  );
  if (run.status !== 0) {
    return null;
  }
  const installationPath = run.stdout.trim();
  return installationPath.length > 0 && existsSync(installationPath) ? installationPath : null;
}

// PR #92 P2 (Codex, follow-up): the VC toolset is necessary but NOT sufficient.
// build.mjs additionally reconciles a Windows SDK under
// %ProgramFiles(x86)%\Windows Kits\10 and fails loudly when it is missing — it
// requires BOTH SDK roots (Include, Lib) AND at least one 10.x.x.x version whose
// Include\<ver>\ucrt headers exist (the ucrt/um/shared include and ucrt/um lib
// dirs the compile consumes). A machine can carry the VC workload with no Windows
// SDK component installed, so the availability gate must mirror this precondition
// too — otherwise the MSVC describe RUNS and then FAILS at the builder's SDK check
// instead of SKIPPING. Filesystem-only mirror (no shell), matching build.mjs.
function windowsSdkAvailable(
  programFilesX86: string = process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)',
): boolean {
  const sdkRoot = join(programFilesX86, 'Windows Kits', '10');
  const sdkIncludeRoot = join(sdkRoot, 'Include');
  const sdkLibRoot = join(sdkRoot, 'Lib');
  if (!existsSync(sdkIncludeRoot) || !existsSync(sdkLibRoot)) {
    return false;
  }
  return readdirSync(sdkIncludeRoot)
    .filter((name) => /^10\.\d+\.\d+\.\d+$/.test(name))
    .some((name) => existsSync(join(sdkIncludeRoot, name, 'ucrt')));
}

/** The MSVC-specific describe may run only when the builder's FULL precondition
 *  holds: the VC toolset (vswhere -requires component) AND the Windows SDK/UCRT.
 *  Either prerequisite absent → the describe skips rather than fails. */
function msvcToolchainAvailable(
  vcInstallationPath: string | null,
  sdkProgramFilesX86?: string,
): boolean {
  return vcInstallationPath !== null && windowsSdkAvailable(sdkProgramFilesX86);
}

const msvcAvailable = msvcToolchainAvailable(vcInstallationPathFor(VC_TOOLS_COMPONENT));

describe.skipIf(!msvcAvailable)('D062 explicit provisioning — MSVC available + helper missing', () => {
  it('the gate compiles the helper and publishes a canonical pair (exit 0)', () => {
    const t = isolatedGateTree(true);
    try {
      const run = spawnSync(process.execPath, [t.gateScript], { encoding: 'utf8' });
      expect(run.status, run.stderr).toBe(0);
      const exe = join(t.nativeDir, OWNER_HELPER_BASENAME);
      const prov = join(t.nativeDir, PROVENANCE_BASENAME);
      expect(existsSync(exe)).toBe(true);
      expect(validateHelperPair({ exePath: exe, provenancePath: prov })).toEqual({
        valid: true,
        reason: 'valid',
      });
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  }, 120000);
});

// PR #92 P2 adversarial coverage: the availability predicate itself, driven
// through the REAL vswhere binary. Both directions of the finding are proven —
// with the required VC workload installed the MSVC describe above may run, and
// with vswhere.exe present but the required workload absent the detection
// yields no installation, so the describe above SKIPS instead of failing.
describe.skipIf(process.platform !== 'win32' || !existsSync(vswherePath))(
  'D062 explicit provisioning — MSVC availability predicate matches the builder requirement',
  () => {
    it('the predicate requires the exact VC workload component build.mjs queries', () => {
      // Single shared requirement: the component id above must be the literal
      // build.mjs passes to `vswhere -requires`, so test predicate and
      // production builder cannot drift apart silently.
      const builderSource = readFileSync(
        join(repoRoot, 'tools', 'control-owner', 'build.mjs'),
        'utf8',
      );
      expect(builderSource).toContain(`'${VC_TOOLS_COMPONENT}',`);
    });

    it('vswhere present but required workload absent → no installation → skip, not fail', () => {
      // Exactly the Codex configuration: the real vswhere.exe answers the real
      // query shape for a component that is never installed and returns no
      // installation — the predicate is false and the MSVC describe skips.
      expect(vcInstallationPathFor('AgentBridge.Test.Component.Never.Installed.x86.x64')).toBeNull();
    });

    it('MSVC-describe gating equals VC-workload-present AND Windows-SDK-present', () => {
      const detected = vcInstallationPathFor(VC_TOOLS_COMPONENT);
      const sdk = windowsSdkAvailable();
      if (detected === null) {
        // VC workload absent on this machine: the MSVC describe must be skipped
        // regardless of whether a Windows SDK is present.
        expect(msvcAvailable).toBe(false);
      } else {
        // VC workload present: the detected root is a real installation path —
        // the same installationPath build.mjs would resolve — and the MSVC
        // describe is allowed to run IFF the Windows SDK/UCRT prerequisite the
        // builder also enforces is present, exactly the compound precondition.
        expect(existsSync(detected)).toBe(true);
        expect(msvcAvailable).toBe(sdk);
      }
    });
  },
);

// PR #92 P2 (Codex) adversarial coverage for the Windows SDK prerequisite. These
// drive the SDK predicate and the combined toolchain gate through synthetic
// %ProgramFiles(x86)% layouts — filesystem only, no shell, deterministic on every
// OS — so both directions of the finding are pinned independently of the runner's
// installed toolchain.
const SDK_VERSION_DIR = '10.0.22621.0';

/** Build a synthetic `Windows Kits\10` tree under a fresh temp ProgramFiles(x86)
 *  root and run `fn` against that root, always cleaning up. */
function withSdkRoot(
  build: (paths: { include: string; lib: string }) => void,
  fn: (programFilesX86: string) => void,
): void {
  const root = mkdtempSync(join(tmpdir(), 'ab-sdk-'));
  try {
    const kits = join(root, 'Windows Kits', '10');
    build({ include: join(kits, 'Include'), lib: join(kits, 'Lib') });
    fn(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function makeUcrtVersion(includeRoot: string, version: string): void {
  mkdirSync(join(includeRoot, version, 'ucrt'), { recursive: true });
}

describe('D062 explicit provisioning — Windows SDK/UCRT gate mirrors the builder', () => {
  it('the SDK predicate mirrors the exact roots + ucrt requirement build.mjs enforces', () => {
    // Source-level pin (like the VC component pin above): the builder discovers
    // the SDK under "Windows Kits"\"10", requires an Include\<ver>\ucrt, and only
    // accepts 10.x.x.x version dirs — the mirror must not drift from those markers.
    const builderSource = readFileSync(
      join(repoRoot, 'tools', 'control-owner', 'build.mjs'),
      'utf8',
    );
    expect(builderSource).toContain("'Windows Kits', '10'");
    expect(builderSource).toContain("'ucrt'");
    expect(builderSource).toContain('/^10\\.\\d+\\.\\d+\\.\\d+$/');
  });

  it('full SDK (Include + Lib + a 10.x.x.x ucrt version) → available', () => {
    withSdkRoot(
      ({ include, lib }) => {
        makeUcrtVersion(include, SDK_VERSION_DIR);
        mkdirSync(lib, { recursive: true });
      },
      (pf86) => {
        expect(windowsSdkAvailable(pf86)).toBe(true);
      },
    );
  });

  it('Include root missing → unavailable', () => {
    withSdkRoot(
      ({ lib }) => {
        mkdirSync(lib, { recursive: true });
      },
      (pf86) => {
        expect(windowsSdkAvailable(pf86)).toBe(false);
      },
    );
  });

  it('Lib root missing → unavailable', () => {
    withSdkRoot(
      ({ include }) => {
        makeUcrtVersion(include, SDK_VERSION_DIR);
      },
      (pf86) => {
        expect(windowsSdkAvailable(pf86)).toBe(false);
      },
    );
  });

  it('SDK roots present but NO version carries ucrt headers → unavailable', () => {
    withSdkRoot(
      ({ include, lib }) => {
        mkdirSync(join(include, SDK_VERSION_DIR, 'um'), { recursive: true }); // no ucrt
        mkdirSync(lib, { recursive: true });
      },
      (pf86) => {
        expect(windowsSdkAvailable(pf86)).toBe(false);
      },
    );
  });

  it('a ucrt dir under a NON-10.x.x.x version name is not accepted → unavailable', () => {
    withSdkRoot(
      ({ include, lib }) => {
        makeUcrtVersion(include, 'wsdk'); // not 10.x.x.x
        mkdirSync(lib, { recursive: true });
      },
      (pf86) => {
        expect(windowsSdkAvailable(pf86)).toBe(false);
      },
    );
  });
});

describe('D062 explicit provisioning — combined MSVC toolchain gate truth table', () => {
  const VC_ROOT = 'C:\\Program Files\\Microsoft Visual Studio\\2022\\Community';
  const fullSdk = ({ include, lib }: { include: string; lib: string }): void => {
    makeUcrtVersion(include, SDK_VERSION_DIR);
    mkdirSync(lib, { recursive: true });
  };
  const noSdk = (): void => {
    /* empty ProgramFiles(x86): no Windows Kits at all */
  };

  it('VC present + SDK present → gate OPEN (MSVC describe may run)', () => {
    withSdkRoot(fullSdk, (pf86) => {
      expect(msvcToolchainAvailable(VC_ROOT, pf86)).toBe(true);
    });
  });

  it('VC present + SDK absent → gate CLOSED (MSVC describe skips, does not fail)', () => {
    withSdkRoot(noSdk, (pf86) => {
      expect(msvcToolchainAvailable(VC_ROOT, pf86)).toBe(false);
    });
  });

  it('VC absent + SDK present → gate CLOSED (existing VC-absent case remains correct)', () => {
    withSdkRoot(fullSdk, (pf86) => {
      expect(msvcToolchainAvailable(null, pf86)).toBe(false);
    });
  });

  it('VC absent + SDK absent → gate CLOSED', () => {
    withSdkRoot(noSdk, (pf86) => {
      expect(msvcToolchainAvailable(null, pf86)).toBe(false);
    });
  });
});

describe.skipIf(process.platform !== 'win32')(
  'D062 explicit provisioning — toolchain unavailable + helper missing fails loudly',
  () => {
    it('the gate exits nonzero with a loud message (and no artifacts appear)', () => {
      // Point MSVC discovery ("ProgramFiles(x86)" → vswhere.exe) at an empty
      // directory: exactly the MSVC-unavailable failure path. The gate must fail
      // LOUD and NONZERO — and, per the launch-model tests above, this failure
      // can only ever stop `npm run control`; `cockpit`/`cockpit:live` never run
      // the gate, so the same failure cannot prevent a Cockpit launch.
      const t = isolatedGateTree(true);
      try {
        const emptyPf86 = join(t.root, 'empty-pf86');
        mkdirSync(emptyPf86, { recursive: true });
        // Windows env keys are case-insensitive: drop every case-variant of the
        // discovery variable before overriding, so the override always wins in
        // the child regardless of the runner's env-key casing.
        const env: NodeJS.ProcessEnv = Object.fromEntries(
          Object.entries(process.env).filter(([key]) => key.toLowerCase() !== 'programfiles(x86)'),
        );
        env['ProgramFiles(x86)'] = emptyPf86;
        const run = spawnSync(process.execPath, [t.gateScript], { encoding: 'utf8', env });
        expect(run.status).toBe(1);
        expect(run.stderr).toContain('FAILED to build the owner helper');
        expect(existsSync(join(t.nativeDir, OWNER_HELPER_BASENAME))).toBe(false);
      } finally {
        rmSync(t.root, { recursive: true, force: true });
      }
    });
  },
);

/* ---- 6. Concurrent helper rebuild — isolation invariant (PR #90/#91) --------- */

// Definition-level (cross-platform): build.mjs must compile into a process-unique
// PRIVATE workspace (mkdtempSync) and target that workspace — never a shared object
// directory or the final executable path — during compilation. This pins the
// isolation mechanism so the concurrent-rebuild race cannot regress silently.
const buildMjs = readFileSync(join(repoRoot, 'tools', 'control-owner', 'build.mjs'), 'utf8');

describe('D062 concurrent rebuild — build.mjs isolates mutable compilation state', () => {
  it('creates a per-invocation private workspace via mkdtempSync', () => {
    expect(buildMjs).toMatch(/mkdtempSync\(/);
  });
  it('compiles /Fe and /Fo into the private workspace, not the final paths', () => {
    expect(buildMjs).toMatch(/\/Fe:\$\{workExe\}/);
    expect(buildMjs).toMatch(/\/Fo:\$\{workObjDir\}/);
    // No shared object directory under the authoritative native dir, and the final
    // exe path is never a compiler output target.
    expect(buildMjs).not.toMatch(/const objDir = join\(outDir, 'obj'\)/);
    expect(buildMjs).not.toMatch(/\/Fe:\$\{exePath\}/);
  });
  it('publishes by atomic rename and cleans the private workspace best-effort', () => {
    expect(buildMjs).toMatch(/renameSync\(/);
    expect(buildMjs).toMatch(/cleanupWorkspace\(/);
  });
});

// Real concurrent builds (Windows) run in an ISOLATED COPY of the build tools under
// a temp tree, so they never touch the shared dist that owner-helper.win.test.ts
// reads/executes. Gated on winReady as a proxy for MSVC availability.
type SpawnResult = ReturnType<typeof spawnSync>;

function runConcurrentBuilds(buildScript: string, n: number): SpawnResult[] {
  // Launch n builders as detached children, then wait — spawnSync is blocking, so
  // start them via a single node driver that runs them concurrently.
  const driver = `
    import { spawn } from 'node:child_process';
    const n = ${String(n)};
    const script = ${JSON.stringify(buildScript)};
    const runs = Array.from({ length: n }, () => new Promise((res) => {
      const c = spawn(process.execPath, [script], { stdio: 'ignore' });
      c.on('exit', (code) => res(code ?? 1));
    }));
    Promise.all(runs).then((codes) => { process.stdout.write(JSON.stringify(codes)); });
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', driver], { encoding: 'utf8' });
  const codes = JSON.parse(r.stdout || '[]') as number[];
  return codes.map((code) => ({ status: code }) as SpawnResult);
}

describe.skipIf(!winReady)('D062 concurrent rebuild — isolated real builds converge (Windows)', () => {
  it.each([2, 4])('%d concurrent builders all succeed and converge on the canonical pair', (n) => {
    const t = isolatedGateTree(true);
    try {
      const results = runConcurrentBuilds(t.buildScript, n);
      expect(results).toHaveLength(n);
      for (const r of results) {
        expect(r.status).toBe(0);
      }
      const exe = join(t.nativeDir, OWNER_HELPER_BASENAME);
      const prov = join(t.nativeDir, PROVENANCE_BASENAME);
      expect(existsSync(exe)).toBe(true);
      expect(existsSync(prov)).toBe(true);
      // Final pair canonical.
      expect(readFileSync(prov, 'utf8')).toBe(encodeProvenance(sha256Hex(readFileSync(exe))));
      // No shared object directory and no private workspace leaked into native/.
      expect(existsSync(join(t.nativeDir, 'obj'))).toBe(false);
      // Every entry under native/ is one of the two authoritative artifacts.
      // (A leaked .build-* dir would violate isolation cleanup.)
      const names = readdirSync(t.nativeDir);
      expect(names.sort()).toEqual([OWNER_HELPER_BASENAME, PROVENANCE_BASENAME].sort());
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  }, 240000);
});
