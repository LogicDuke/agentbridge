/**
 * D062 coherent launch lifecycle regression (PR #85/#90/#91 reconstruction).
 *
 * Two frozen properties are pinned together here:
 *
 * 1. CANONICAL PAIR VALIDITY. The explicit provisioning gate
 *    (tools/control-owner/ensure-helper.mjs) makes a clean — or partially/torn/
 *    malformed/stale — checkout coherent before control-anchor verification, by
 *    rebuilding through the trusted build.mjs unless EVERY on-disk pair (the
 *    read-only owner helper AND the create-only descriptor creator) is
 *    CANONICAL for the CURRENT reviewed source. Canonical means exactly one thing
 *    per artifact:
 *
 *        provenance bytes == encode(sha256(binary bytes), sha256(reviewed source))
 *
 *    produced by the artifact's single shared encoder (tools/control-owner/
 *    provenance-format.mjs), which build.mjs also uses to publish. The gate does
 *    no field extraction, no regex acceptance, no JS import/parse, and no
 *    normalization — so the ACCEPTED SET is the singleton
 *    {encode(sha256(binary), sourceId)} and the FALSE-VALID SET is empty. Because
 *    the source digest is part of the canonical bytes, a self-consistent pair built
 *    from an OLDER reviewed source rebuilds instead of being skipped:
 *
 *        SUPPORTED_PROVISIONING_SUCCESS ⇒ NATIVE_ARTIFACT_RUNTIME_COMPATIBLE
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
 * 3. ONE BUILD-ELIGIBILITY PREDICATE. Every real-compilation test runs or skips
 *    on exactly `isBuildEligible` from tools/control-owner/msvc-toolchain.mjs —
 *    the builder's own resolver PLUS an execution probe that compiles+links the
 *    helper's dependency surface through the exact shared cl/env/paths/flags. No
 *    test re-derives eligibility from filesystem existence or artifact presence.
 *
 * These tests drive the REAL encoder and REAL validator over the full adversarial
 * artifact-state matrix (including the exact Codex truncated-module witness and
 * the duplicate-field witness), pin the launch wiring, confirm the runtime still
 * fails closed independently, prove a fail-closed control startup leaves the
 * Cockpit serving, and (on Windows) exercise the real gate: idempotent skip on a
 * canonical pair, real clean-checkout provisioning in an isolated tree, loud
 * nonzero failure when the toolchain is unavailable, provisioning through a
 * junction/symlink alias, and concurrent-builder isolation/convergence.
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
  rmdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  validateCreatorPair,
  validateHelperPair,
  encodeCreatorProvenance,
  encodeProvenance,
  descriptorCreatorSourceId,
  ownerHelperSourceId,
  sourceIdFor,
  CREATOR_PROVENANCE_BASENAME,
  DESCRIPTOR_CREATOR_BASENAME,
  DESCRIPTOR_CREATOR_SOURCE_PATH,
  OWNER_HELPER_BASENAME,
  OWNER_HELPER_SOURCE_PATH,
} from '../../tools/control-owner/helper-pair.mjs';
import {
  resolveBuildToolchain,
  isBuildEligible,
  probeBuildToolchain,
  compileArgsFor,
  compileEnvFor,
  selectSdkVersion,
  vswherePathFor,
  CL_COMPILE_FLAGS,
  CL_LINK_FLAGS,
  PROBE_SOURCE,
  VC_TOOLS_COMPONENT,
  type BuildPlan,
  type CompilerRunner,
} from '../../tools/control-owner/msvc-toolchain.mjs';
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
const realCreator = join(repoRoot, 'dist', 'control', 'native', DESCRIPTOR_CREATOR_BASENAME);
const realCreatorProv = join(repoRoot, 'dist', 'control', 'native', CREATOR_PROVENANCE_BASENAME);

/** The CURRENT reviewed-source identities (the gate recomputes these on every call). */
const OWNER_SOURCE_ID = ownerHelperSourceId() ?? '';
const CREATOR_SOURCE_ID = descriptorCreatorSourceId() ?? '';
/** Every published native artifact basename (binaries + provenance modules). */
const ALL_NATIVE_BASENAMES = [
  OWNER_HELPER_BASENAME,
  PROVENANCE_BASENAME,
  DESCRIPTOR_CREATOR_BASENAME,
  CREATOR_PROVENANCE_BASENAME,
];

const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};
const ciYml = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8');

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}
function canonicalFor(bytes: Buffer): string {
  return encodeProvenance(sha256Hex(bytes), OWNER_SOURCE_ID);
}
function creatorCanonicalFor(bytes: Buffer): string {
  return encodeCreatorProvenance(sha256Hex(bytes), CREATOR_SOURCE_ID);
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

/* ---- 1b. Source binding: SUPPORTED_PROVISIONING_SUCCESS ⇒ RUNTIME_COMPATIBLE ---- */

describe('D062 canonical provenance — source binding (a canonical-but-stale pair rebuilds)', () => {
  it('the current source identities are SHA-256 of the exact reviewed C source bytes (no scan, no regex)', () => {
    expect(OWNER_SOURCE_ID).toMatch(/^[0-9a-f]{64}$/);
    expect(CREATOR_SOURCE_ID).toMatch(/^[0-9a-f]{64}$/);
    expect(OWNER_SOURCE_ID).toBe(sha256Hex(readFileSync(OWNER_HELPER_SOURCE_PATH)));
    expect(CREATOR_SOURCE_ID).toBe(sha256Hex(readFileSync(DESCRIPTOR_CREATOR_SOURCE_PATH)));
    expect(OWNER_SOURCE_ID).not.toBe(CREATOR_SOURCE_ID);
    expect(sourceIdFor(join(tmpdir(), 'ab-no-such-source.c'))).toBeNull();
  });

  it('28. a pair that is self-consistent but was built from an OLDER reviewed source → INVALID (rebuild)', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      // Exactly the encoder output the old build would have published: same
      // binary hash, the previous source's digest.
      const staleSourceId = sha256Hex(Buffer.from('older reviewed source bytes'));
      writeFileSync(p.provenancePath, encodeProvenance(sha256Hex(HELPER), staleSourceId));
      expect(validateHelperPair(p)).toEqual({ valid: false, reason: 'not-canonical' });
      // Only the CURRENT source's encoding is accepted.
      writeFileSync(p.provenancePath, canonicalFor(HELPER));
      expect(validateHelperPair(p).valid).toBe(true);
    });
  });

  it('29. the encoder names the source id in the canonical bytes, so it cannot be dropped or spoofed', () => {
    const canon = canonicalFor(HELPER);
    expect(canon).toContain(`sourceId: ${JSON.stringify(OWNER_SOURCE_ID)}`);
    expect(() => encodeProvenance(sha256Hex(HELPER), 'not-a-digest')).toThrow(TypeError);
    expect(() => encodeProvenance('not-a-digest', OWNER_SOURCE_ID)).toThrow(TypeError);
    expect(() => encodeCreatorProvenance(sha256Hex(HELPER), 'NOPE')).toThrow(TypeError);
  });

  it('the creator pair validates against ITS OWN encoder and source; a cross-wired provenance is never valid', () => {
    withPair((p) => {
      writeExe(p, HELPER);
      writeFileSync(p.provenancePath, creatorCanonicalFor(HELPER));
      expect(validateCreatorPair(p)).toEqual({ valid: true, reason: 'valid' });
      // The owner helper's canonical encoding of the same bytes is NOT a creator pair …
      writeFileSync(p.provenancePath, canonicalFor(HELPER));
      expect(validateCreatorPair(p)).toEqual({ valid: false, reason: 'not-canonical' });
      // … and the creator's encoding is NOT an owner-helper pair.
      writeFileSync(p.provenancePath, creatorCanonicalFor(HELPER));
      expect(validateHelperPair(p)).toEqual({ valid: false, reason: 'not-canonical' });
      // The creator encoding for an OLDER creator source is stale too.
      writeFileSync(p.provenancePath, encodeCreatorProvenance(sha256Hex(HELPER), 'a'.repeat(64)));
      expect(validateCreatorPair(p)).toEqual({ valid: false, reason: 'not-canonical' });
    });
  });

  it('the two generated modules export distinct bindings and name distinct binaries', () => {
    const owner = canonicalFor(HELPER);
    const creator = creatorCanonicalFor(HELPER);
    expect(owner).toContain('export const OWNER_HELPER_PROVENANCE =');
    expect(owner).toContain(`filename: ${JSON.stringify(OWNER_HELPER_BASENAME)}`);
    expect(owner).not.toContain('DESCRIPTOR_CREATOR_PROVENANCE');
    expect(creator).toContain('export const DESCRIPTOR_CREATOR_PROVENANCE =');
    expect(creator).toContain(`filename: ${JSON.stringify(DESCRIPTOR_CREATOR_BASENAME)}`);
    expect(creator).not.toContain('OWNER_HELPER_PROVENANCE');
  });
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
    let descriptorCreations = 0;
    const descriptorDeps: DescriptorFileDeps = {
      listAnchor: (): readonly string[] => [],
      readFile: (): string => {
        throw new Error('ENOENT');
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
      createDescriptor: () => {
        descriptorCreations += 1;
        return Promise.resolve({ ok: true });
      },
      logger: (): void => {
        /* silent */
      },
    });

    // Control fails CLOSED (null handle, no descriptor) …
    expect(handle).toBeNull();
    expect(descriptorCreations).toBe(0);
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
const winReady =
  process.platform === 'win32' &&
  existsSync(realExe) &&
  existsSync(realProv) &&
  existsSync(realCreator) &&
  existsSync(realCreatorProv);

describe.skipIf(!winReady)('D062 canonical provenance — real gate idempotent on canonical, source-current pairs', () => {
  it('29. both real pairs are canonical for the current sources, and the gate skips them without rebuilding', () => {
    expect(readFileSync(realProv, 'utf8')).toBe(canonicalFor(readFileSync(realExe)));
    expect(readFileSync(realCreatorProv, 'utf8')).toBe(creatorCanonicalFor(readFileSync(realCreator)));
    expect(validateHelperPair({ exePath: realExe, provenancePath: realProv }).valid).toBe(true);
    expect(validateCreatorPair({ exePath: realCreator, provenancePath: realCreatorProv }).valid).toBe(true);

    const run = runGate();
    expect(run.status).toBe(0);
    expect(String(run.stderr)).toContain('skipping build');

    expect(validateHelperPair({ exePath: realExe, provenancePath: realProv }).valid).toBe(true);
    expect(validateCreatorPair({ exePath: realCreator, provenancePath: realCreatorProv }).valid).toBe(true);
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
  const files = [
    'ensure-helper.mjs',
    'helper-pair.mjs',
    'build.mjs',
    'provenance-format.mjs',
    'msvc-toolchain.mjs',
  ];
  if (withSource) {
    files.push('agentbridge-win-owner.c', 'agentbridge-win-descriptor-create.c');
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

/* ---- PR #92 root-cause: single-source MSVC/SDK build eligibility ------------- */
// The recurring MSVC-gate drift — vswhere existence → VC workload → SDK roots →
// the exact per-version ucrt/um/shared include and ucrt/um x64 lib paths cl.exe
// consumes — came from this test RE-DERIVING builder eligibility with its own,
// weaker logic. That duplication is gone: both the trusted builder (build.mjs) and
// this gate resolve eligibility through the ONE authoritative module
// tools/control-owner/msvc-toolchain.mjs. TEST_BUILD_ELIGIBLE is therefore derived
// from exactly the prerequisites that make the real builder proceed AND succeed; it
// cannot claim availability the builder would not, and any new builder prerequisite
// added to the module updates the builder and this gate together.

const vswherePath = vswherePathFor(process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)');

// THE authoritative gate — the only `isBuildEligible` call site in this file:
// the builder resolves a plan (same vswhere VC query, same SDK version selection),
// every include/lib dir it will hand cl.exe exists, AND the exact toolchain
// compiles+links the helper's dependency surface (execution probe). Every real
// compilation below (provisioning AND concurrent builds) is gated on this one value.
const TEST_BUILD_ELIGIBLE = isBuildEligible();

describe.skipIf(!TEST_BUILD_ELIGIBLE)('D062 explicit provisioning — MSVC available + helper missing', () => {
  it('the gate compiles BOTH artifacts and publishes two canonical, source-bound pairs (exit 0)', () => {
    const t = isolatedGateTree(true);
    try {
      const run = spawnSync(process.execPath, [t.gateScript], { encoding: 'utf8' });
      expect(run.status, run.stderr).toBe(0);
      const exe = join(t.nativeDir, OWNER_HELPER_BASENAME);
      const prov = join(t.nativeDir, PROVENANCE_BASENAME);
      const creator = join(t.nativeDir, DESCRIPTOR_CREATOR_BASENAME);
      const creatorProv = join(t.nativeDir, CREATOR_PROVENANCE_BASENAME);
      expect(readdirSync(t.nativeDir).sort()).toEqual([...ALL_NATIVE_BASENAMES].sort());
      // The copied tree's sources are byte-identical to the repo's, so the copied
      // validators (which hash their own module-relative sources) accept exactly
      // the same encodings the repo validators compute.
      expect(readFileSync(prov, 'utf8')).toBe(canonicalFor(readFileSync(exe)));
      expect(readFileSync(creatorProv, 'utf8')).toBe(creatorCanonicalFor(readFileSync(creator)));
      expect(validateHelperPair({ exePath: exe, provenancePath: prov })).toEqual({ valid: true, reason: 'valid' });
      expect(validateCreatorPair({ exePath: creator, provenancePath: creatorProv })).toEqual({ valid: true, reason: 'valid' });
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  }, 180000);

  it('28. source drift: editing a reviewed C source makes the gate REBUILD (not skip) and republish a matching pair', () => {
    const t = isolatedGateTree(true);
    try {
      const first = spawnSync(process.execPath, [t.gateScript], { encoding: 'utf8' });
      expect(first.status, first.stderr).toBe(0);
      const creator = join(t.nativeDir, DESCRIPTOR_CREATOR_BASENAME);
      const creatorProv = join(t.nativeDir, CREATOR_PROVENANCE_BASENAME);
      const beforeProv = readFileSync(creatorProv, 'utf8');

      // A second run with nothing changed skips (idempotent).
      const again = spawnSync(process.execPath, [t.gateScript], { encoding: 'utf8' });
      expect(again.status).toBe(0);
      expect(again.stderr).toContain('skipping build');
      expect(readFileSync(creatorProv, 'utf8')).toBe(beforeProv);

      // Drift the creator's reviewed source by a comment-only edit: the binary may
      // even be byte-identical, yet the pair is no longer canonical for the current
      // source and MUST be rebuilt.
      const sourcePath = join(t.root, 'tools', 'control-owner', 'agentbridge-win-descriptor-create.c');
      writeFileSync(sourcePath, `${readFileSync(sourcePath, 'utf8')}\n/* reviewed-source drift */\n`);
      const drifted = spawnSync(process.execPath, [t.gateScript], { encoding: 'utf8' });
      expect(drifted.status, drifted.stderr).toBe(0);
      expect(drifted.stderr).toContain('descriptor creator pair not valid (not-canonical); rebuilding');
      const afterProv = readFileSync(creatorProv, 'utf8');
      expect(afterProv).not.toBe(beforeProv);
      expect(afterProv).toBe(
        encodeCreatorProvenance(sha256Hex(readFileSync(creator)), sha256Hex(readFileSync(sourcePath))),
      );
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  }, 300000);
});

// The root-cause proof: builder and gate share ONE eligibility source, so the
// detection can no longer be duplicated with weaker semantics. Cross-platform.
describe('D062 explicit provisioning — builder and gate share one eligibility source', () => {
  const readTool = (name: string): string =>
    readFileSync(join(repoRoot, 'tools', 'control-owner', name), 'utf8');

  it('build.mjs consumes the shared resolver and no longer re-implements detection', () => {
    const builder = readTool('build.mjs');
    // The builder imports and uses the shared resolver …
    expect(builder).toContain("from './msvc-toolchain.mjs'");
    expect(builder).toContain('resolveBuildToolchain(');
    // … and no longer inlines the drift-prone detection literals (they moved to the
    // module), so nothing is left in the builder for a test mirror to drift from.
    expect(builder).not.toContain(VC_TOOLS_COMPONENT); // vswhere -requires component
    expect(builder).not.toContain('/^10\\.\\d+\\.\\d+\\.\\d+$/'); // SDK version regex
    expect(builder).not.toContain("'Windows Kits', '10'"); // SDK root discovery
  });

  it('build.mjs consumes the shared compiler environment + argument shape (no second copy of flags)', () => {
    const builder = readTool('build.mjs');
    expect(builder).toContain('compileEnvFor(');
    expect(builder).toContain('compileArgsFor(');
    // No inline compiler flags, link flags, or env construction remain in the
    // builder — the probe and the builder cannot drift in flags, PATH, INCLUDE, LIB.
    for (const flag of [...CL_COMPILE_FLAGS, ...CL_LINK_FLAGS]) {
      expect(builder, `builder must not inline ${flag}`).not.toContain(`'${flag}'`);
    }
    expect(builder).not.toMatch(/INCLUDE:|LIB:|System32/);
  });

  it('the shared argv shape is exactly the builder\'s: flags, source, /Fe, /Fo, /link flags', () => {
    const args = compileArgsFor({ source: 'S.c', exe: 'E.exe', objDir: 'O' });
    expect(args).toEqual([...CL_COMPILE_FLAGS, 'S.c', '/Fe:E.exe', '/Fo:O\\', '/link', ...CL_LINK_FLAGS]);
    expect(CL_LINK_FLAGS).toContain('advapi32.lib');
    expect(CL_LINK_FLAGS).toContain('/SUBSYSTEM:CONSOLE');
  });

  it('the probe exercises BOTH native artifacts\' exact dependency surface', () => {
    // Every header either source includes is included by the probe, and the probe
    // references the same imports both need so the link needs the same libraries.
    for (const source of ['agentbridge-win-owner.c', 'agentbridge-win-descriptor-create.c']) {
      const includes = [...readTool(source).matchAll(/^#include <([^>]+)>/gm)].map((m) => m[1]);
      expect(includes.length).toBeGreaterThan(0);
      for (const header of includes) {
        expect(PROBE_SOURCE, `probe must include <${String(header)}>`).toContain(`#include <${String(header)}>`);
      }
    }
    for (const symbol of [
      'GetNamedSecurityInfoW(',
      'ConvertSidToStringSidW(',
      'GetSecurityDescriptorControl(',
      'SetEntriesInAclW(',
      'AllocateAndInitializeSid(',
      'OpenProcessToken(',
      'GetTokenInformation(',
      'SetFileInformationByHandle(',
      'int wmain(',
    ]) {
      expect(PROBE_SOURCE, `probe must reference ${symbol}`).toContain(symbol);
    }
  });

  it('this file has exactly ONE eligibility call site and gates every real compilation on it', () => {
    // T5 root cause: a second, weaker run/skip proxy (artifact presence) gated the
    // concurrent-build tests. There is one predicate and both real-compile
    // describes use it; no real compilation is gated on `winReady`.
    const self = readFileSync(fileURLToPath(import.meta.url), 'utf8');
    expect(self.match(/isBuildEligible\(\)/g)).toHaveLength(1);
    expect(self).toContain(
      "describe.skipIf(!TEST_BUILD_ELIGIBLE)('D062 explicit provisioning — MSVC available + helper missing'",
    );
    expect(self).toContain(
      "describe.skipIf(!TEST_BUILD_ELIGIBLE)('D062 concurrent rebuild — isolated real builds converge (Windows)'",
    );
    expect(self).not.toMatch(/skipIf\(!winReady\)\('D062 concurrent rebuild/);
  });

  it('the authoritative detection/selection lives in the shared module', () => {
    const mod = readTool('msvc-toolchain.mjs');
    expect(mod).toContain(VC_TOOLS_COMPONENT);
    expect(mod).toContain("'Windows Kits', '10'");
    // Every per-version path category cl.exe consumes is selected in one place.
    expect(mod).toContain("'ucrt'");
    expect(mod).toContain("'um'");
    expect(mod).toContain("'shared'");
  });
});

// On a real Windows machine with vswhere present: the run/skip gate equals the
// shared resolver's verdict and consumes the FULL set of builder paths.
describe.skipIf(process.platform !== 'win32' || !existsSync(vswherePath))(
  'D062 explicit provisioning — real gate equals the builder resolver on this machine',
  () => {
    it('TEST_BUILD_ELIGIBLE is exactly "plan resolves AND every builder path exists AND the probe links"', () => {
      const resolved = resolveBuildToolchain();
      if (!resolved.ok) {
        // Builder would reject before compilation → the gate must be closed.
        expect(TEST_BUILD_ELIGIBLE).toBe(false);
      } else {
        const allPresent = [...resolved.plan.includeDirs, ...resolved.plan.libDirs].every((dir) =>
          existsSync(dir),
        );
        // The gate is open IFF every include/lib path the builder hands cl.exe
        // exists AND the exact toolchain actually compiles+links the probe.
        const probe = allPresent ? probeBuildToolchain(resolved.plan).ok : false;
        expect(TEST_BUILD_ELIGIBLE).toBe(allPresent && probe);
        expect(resolved.plan.includeDirs).toHaveLength(4); // msvc, ucrt, um, shared
        expect(resolved.plan.libDirs).toHaveLength(3); // msvc, ucrt/x64, um/x64
      }
    });

    it('an empty VC installationPath (workload absent) → not eligible (skip, not fail)', () => {
      // The original Codex configuration, via the shared resolver: no VC
      // installation resolved → ineligible, so the MSVC describe skips.
      expect(isBuildEligible({ vcInstallationPath: '' })).toBe(false);
    });
  },
);

// PR #92 root-cause adversarial coverage: synthetic %ProgramFiles(x86)% toolchains
// exercised through the SHARED resolver with an injected VC installationPath (no
// vswhere, no shell), so every builder prerequisite and the exact SDK-version
// SELECTION are proven identical for the gate and the builder, deterministically on
// every OS. A "complete" SDK version carries all include (ucrt/um/shared) and lib
// (ucrt/um → x64) dirs the compile consumes.
const TOOLSET = '14.44.35207';
type IncludePart = 'ucrt' | 'um' | 'shared';
type LibPart = 'ucrt' | 'um';
interface SdkVersionSpec {
  readonly version: string;
  readonly include?: readonly IncludePart[];
  readonly lib?: readonly LibPart[];
}
interface ToolchainSpec {
  readonly vc?: boolean; // create VS toolset + cl + msvc include/lib (default true)
  readonly sdkRoots?: boolean; // create SDK Include & Lib roots (default true)
  readonly sdkVersions?: readonly SdkVersionSpec[];
}
const ALL_INCLUDE: readonly IncludePart[] = ['ucrt', 'um', 'shared'];
const ALL_LIB: readonly LibPart[] = ['ucrt', 'um'];
const completeVersion = (version: string): SdkVersionSpec => ({
  version,
  include: ALL_INCLUDE,
  lib: ALL_LIB,
});

interface ToolchainCtx {
  readonly programFilesX86: string;
  readonly vsRoot: string;
}

/** Build a synthetic toolchain under a fresh temp ProgramFiles(x86) and run `fn`
 *  with { programFilesX86, vsRoot }, always cleaning up. */
function withToolchain(spec: ToolchainSpec, fn: (ctx: ToolchainCtx) => void): void {
  const root = mkdtempSync(join(tmpdir(), 'ab-toolchain-'));
  try {
    const vsRoot = join(root, 'VS');
    if (spec.vc ?? true) {
      const auxBuild = join(vsRoot, 'VC', 'Auxiliary', 'Build');
      mkdirSync(auxBuild, { recursive: true });
      writeFileSync(join(auxBuild, 'Microsoft.VCToolsVersion.default.txt'), `${TOOLSET}\n`);
      const msvcRoot = join(vsRoot, 'VC', 'Tools', 'MSVC', TOOLSET);
      mkdirSync(join(msvcRoot, 'bin', 'Hostx64', 'x64'), { recursive: true });
      writeFileSync(join(msvcRoot, 'bin', 'Hostx64', 'x64', 'cl.exe'), '');
      mkdirSync(join(msvcRoot, 'include'), { recursive: true });
      mkdirSync(join(msvcRoot, 'lib', 'x64'), { recursive: true });
    }
    if (spec.sdkRoots ?? true) {
      const kits = join(root, 'Windows Kits', '10');
      const includeRoot = join(kits, 'Include');
      const libRoot = join(kits, 'Lib');
      mkdirSync(includeRoot, { recursive: true });
      mkdirSync(libRoot, { recursive: true });
      for (const v of spec.sdkVersions ?? []) {
        for (const part of v.include ?? []) {
          mkdirSync(join(includeRoot, v.version, part), { recursive: true });
        }
        for (const part of v.lib ?? []) {
          mkdirSync(join(libRoot, v.version, part, 'x64'), { recursive: true });
        }
      }
    }
    fn({ programFilesX86: root, vsRoot });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** A compiler runner that "succeeds": produces the /Fe output and records the call. */
interface RecordedCompile {
  readonly cl: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Record<string, string>;
}
function recordingCompiler(calls: RecordedCompile[]): CompilerRunner {
  return (cl, args, { cwd, env }): void => {
    calls.push({ cl, args, cwd, env: { ...env } });
    const fe = args.find((a) => a.startsWith('/Fe:'));
    writeFileSync((fe ?? '/Fe:').slice(4), 'probe-output');
  };
}
const succeedingCompiler: CompilerRunner = recordingCompiler([]);
const failingCompiler: CompilerRunner = (): void => {
  throw new Error('cl.exe exited 2');
};

/** Eligibility through the shared resolver with the fixture's VC path and the given
 *  compiler runner (structural fixtures inject a succeeding runner: their cl.exe is
 *  an empty file, so the STRUCTURE is what is under test). */
function eligibleFor(ctx: ToolchainCtx, runCompiler: CompilerRunner = succeedingCompiler): boolean {
  return isBuildEligible({
    programFilesX86: ctx.programFilesX86,
    vcInstallationPath: ctx.vsRoot,
    runCompiler,
  });
}
function planFor(ctx: ToolchainCtx): ReturnType<typeof resolveBuildToolchain> {
  return resolveBuildToolchain({
    programFilesX86: ctx.programFilesX86,
    vcInstallationPath: ctx.vsRoot,
  });
}

describe('D062 explicit provisioning — build eligibility mirrors every builder prerequisite', () => {
  it('VC present + complete SDK (+ working compiler) → eligible', () => {
    withToolchain({ sdkVersions: [completeVersion('10.0.22621.0')] }, (ctx) => {
      expect(eligibleFor(ctx)).toBe(true);
    });
  });

  it('VC present + UCRT-only SDK (no um/shared, no libs) → ineligible', () => {
    withToolchain({ sdkVersions: [{ version: '10.0.22621.0', include: ['ucrt'] }] }, (ctx) => {
      // The builder would PROCEED (a ucrt-include version exists) …
      expect(planFor(ctx).ok).toBe(true);
      // … then fail at cl.exe: the gate must not claim availability → skip.
      expect(eligibleFor(ctx)).toBe(false);
    });
  });

  it('missing um include → ineligible', () => {
    withToolchain(
      { sdkVersions: [{ version: '10.0.22621.0', include: ['ucrt', 'shared'], lib: ALL_LIB }] },
      (ctx) => {
        expect(eligibleFor(ctx)).toBe(false);
      },
    );
  });

  it('missing shared include → ineligible', () => {
    withToolchain(
      { sdkVersions: [{ version: '10.0.22621.0', include: ['ucrt', 'um'], lib: ALL_LIB }] },
      (ctx) => {
        expect(eligibleFor(ctx)).toBe(false);
      },
    );
  });

  it('missing required ucrt lib/x64 → ineligible', () => {
    withToolchain(
      { sdkVersions: [{ version: '10.0.22621.0', include: ALL_INCLUDE, lib: ['um'] }] },
      (ctx) => {
        expect(eligibleFor(ctx)).toBe(false);
      },
    );
  });

  it('missing required um lib/x64 → ineligible', () => {
    withToolchain(
      { sdkVersions: [{ version: '10.0.22621.0', include: ALL_INCLUDE, lib: ['ucrt'] }] },
      (ctx) => {
        expect(eligibleFor(ctx)).toBe(false);
      },
    );
  });

  it('VC absent (no installation) → ineligible even with a complete SDK', () => {
    withToolchain({ vc: false, sdkVersions: [completeVersion('10.0.22621.0')] }, (ctx) => {
      expect(planFor(ctx).ok).toBe(false);
      expect(eligibleFor(ctx)).toBe(false);
    });
  });

  it('SDK roots absent → ineligible', () => {
    withToolchain({ sdkRoots: false }, (ctx) => {
      expect(eligibleFor(ctx)).toBe(false);
    });
  });
});

describe('D062 explicit provisioning — gate and builder select the exact same SDK version', () => {
  it('side-by-side versions: the highest ucrt version is selected, via the builder\'s own rule', () => {
    withToolchain(
      { sdkVersions: [completeVersion('10.0.19041.0'), completeVersion('10.0.22621.0')] },
      (ctx) => {
        const plan = planFor(ctx);
        expect(plan.ok && plan.plan.sdkVersion).toBe('10.0.22621.0');
        // Exactly selectSdkVersion() over the same include root — the SAME function
        // build.mjs → resolveBuildToolchain uses — so the two cannot diverge.
        const includeRoot = join(ctx.programFilesX86, 'Windows Kits', '10', 'Include');
        expect(plan.ok && plan.plan.sdkVersion).toBe(selectSdkVersion(includeRoot));
        expect(eligibleFor(ctx)).toBe(true);
      },
    );
  });

  it('the SELECTED (highest ucrt) version being incomplete → ineligible, NOT rescued by a complete lower version', () => {
    withToolchain(
      {
        sdkVersions: [
          completeVersion('10.0.19041.0'), // complete, but NOT the one selected
          { version: '10.0.22621.0', include: ['ucrt'] }, // highest ucrt → selected, incomplete
        ],
      },
      (ctx) => {
        const plan = planFor(ctx);
        // The builder selects 22621 (highest with ucrt headers) and would fail at
        // cl.exe (no um/shared/libs). The gate must select the SAME version and
        // SKIP — it must never be rescued by the complete-but-unselected 19041.
        expect(plan.ok && plan.plan.sdkVersion).toBe('10.0.22621.0');
        expect(eligibleFor(ctx)).toBe(false);
      },
    );
  });

  it('a ucrt dir under a non-10.x.x.x version name is not selectable → ineligible', () => {
    withToolchain(
      { sdkVersions: [{ version: 'wsdk', include: ALL_INCLUDE, lib: ALL_LIB }] },
      (ctx) => {
        // No 10.x.x.x ucrt version → the builder rejects with sdk-version-missing.
        expect(planFor(ctx).ok).toBe(false);
        expect(eligibleFor(ctx)).toBe(false);
      },
    );
  });
});

/* ---- Terminal toolchain-class closure: eligibility = the toolchain CAN BUILD ---- */
// Existence of directories can never certify compilation (a missing link.exe,
// compiler DLL, header inside an existing include dir, or advapi32.lib inside an
// existing lib dir all pass existence and fail cl.exe). The predicate therefore
// compiles+links a probe through the exact shared plan/env/flags. Deterministic on
// every OS via an injected compiler runner; the real cl.exe is exercised on Windows.
describe('D062 explicit provisioning — eligibility is an execution probe through the shared plan', () => {
  it('structural plan complete + probe compiles → eligible; the probe ran the exact shared cl/args/env', () => {
    withToolchain({ sdkVersions: [completeVersion('10.0.22621.0')] }, (ctx) => {
      const calls: RecordedCompile[] = [];
      expect(eligibleFor(ctx, recordingCompiler(calls))).toBe(true);
      expect(calls).toHaveLength(1);
      const plan = planFor(ctx);
      expect(plan.ok).toBe(true);
      if (!plan.ok) {
        return;
      }
      const call = calls[0];
      expect(call).toBeDefined();
      if (call === undefined) {
        return;
      }
      // Exact resolved compiler, the builder's argv shape, and the builder's env.
      expect(call.cl).toBe(plan.plan.cl);
      const fe = call.args.find((a) => a.startsWith('/Fe:')) ?? '';
      const fo = call.args.find((a) => a.startsWith('/Fo:')) ?? '';
      expect(call.args).toEqual(
        compileArgsFor({ source: join(call.cwd, '..', 'probe.c'), exe: fe.slice(4), objDir: fo.slice(4, -1) }),
      );
      expect(call.env).toEqual(compileEnvFor(plan.plan));
      expect(call.env['INCLUDE']).toBe(plan.plan.includeDirs.join(';'));
      expect(call.env['LIB']).toBe(plan.plan.libDirs.join(';'));
      expect((call.env['PATH'] ?? '').startsWith(`${plan.plan.hostBin};`)).toBe(true);
    });
  });

  it('structural plan complete + compiler invocation fails → ineligible', () => {
    withToolchain({ sdkVersions: [completeVersion('10.0.22621.0')] }, (ctx) => {
      expect(planFor(ctx).ok).toBe(true);
      expect(eligibleFor(ctx, failingCompiler)).toBe(false);
      // Without injection the fixture's cl.exe is an empty file: direct execution
      // fails on every OS, so a structurally complete toolchain that cannot run its
      // compiler is ineligible — never a claimed availability.
      expect(
        isBuildEligible({ programFilesX86: ctx.programFilesX86, vcInstallationPath: ctx.vsRoot }),
      ).toBe(false);
    });
  });

  it('selected (highest ucrt) SDK incomplete → ineligible via the builder\'s selection; the probe never runs', () => {
    withToolchain(
      {
        sdkVersions: [
          completeVersion('10.0.19041.0'), // complete, but NOT the one selected
          { version: '10.0.22621.0', include: ['ucrt'] }, // highest ucrt → selected, incomplete
        ],
      },
      (ctx) => {
        const calls: RecordedCompile[] = [];
        const plan = planFor(ctx);
        expect(plan.ok && plan.plan.sdkVersion).toBe('10.0.22621.0');
        expect(eligibleFor(ctx, recordingCompiler(calls))).toBe(false);
        expect(calls).toHaveLength(0); // rejected before compilation, like the builder
      },
    );
  });

  it('the probe compiles in a private temp workspace, publishes nothing, and cleans up', () => {
    withToolchain({ sdkVersions: [completeVersion('10.0.22621.0')] }, (ctx) => {
      const probeRoot = mkdtempSync(join(tmpdir(), 'ab-probe-root-'));
      try {
        const plan = planFor(ctx);
        expect(plan.ok).toBe(true);
        if (!plan.ok) {
          return;
        }
        for (const runner of [succeedingCompiler, failingCompiler]) {
          const calls: RecordedCompile[] = [];
          const recorded: CompilerRunner = (cl, args, opts): void => {
            calls.push({ cl, args, cwd: opts.cwd, env: { ...opts.env } });
            runner(cl, args, opts);
          };
          const result = probeBuildToolchain(plan.plan, { runCompiler: recorded, probeRoot });
          expect(result.ok).toBe(runner === succeedingCompiler);
          // The compile ran inside the private workspace under probeRoot …
          expect(calls[0]?.cwd.startsWith(probeRoot)).toBe(true);
          // … and nothing is left behind afterwards, success or failure.
          expect(readdirSync(probeRoot)).toEqual([]);
        }
        // Nothing was written anywhere under the synthetic toolchain root either.
        expect(existsSync(join(ctx.programFilesX86, 'dist'))).toBe(false);
      } finally {
        rmSync(probeRoot, { recursive: true, force: true });
      }
    });
  });
});

// Real compiler (Windows with a usable toolchain): the probe detects a required
// header or library missing from an EXISTING directory — the exact class a
// directory-existence gate can never see.
describe.skipIf(!TEST_BUILD_ELIGIBLE)(
  'D062 explicit provisioning — real cl.exe probe rejects unusable-but-present toolchains',
  () => {
    const realPlan = (): BuildPlan => {
      const resolved = resolveBuildToolchain();
      if (!resolved.ok) {
        throw new Error('gate is open, so the plan must resolve');
      }
      return resolved.plan;
    };

    it('positive control: the real plan compiles+links the probe', () => {
      expect(probeBuildToolchain(realPlan()).ok).toBe(true);
    });

    it('required header unavailable (um include dir dropped) → ineligible', () => {
      const plan = realPlan();
      const noUm = plan.includeDirs.filter((dir) => !dir.endsWith('um'));
      expect(noUm).toHaveLength(plan.includeDirs.length - 1);
      expect(probeBuildToolchain({ ...plan, includeDirs: noUm }).ok).toBe(false);
    });

    it('required library unavailable (um lib dir dropped → no advapi32.lib) → ineligible', () => {
      const plan = realPlan();
      const noUmLib = plan.libDirs.filter((dir) => !dir.includes(join('um', 'x64')));
      expect(noUmLib).toHaveLength(plan.libDirs.length - 1);
      expect(probeBuildToolchain({ ...plan, libDirs: noUmLib }).ok).toBe(false);
    });

    it('existing SDK directories with the required headers ABSENT → ineligible through the full gate', () => {
      // Real VS/MSVC root (so cl.exe genuinely runs) + a synthetic %ProgramFiles(x86)%
      // whose Windows Kits dirs all EXIST but are empty: structure and existence
      // pass, the probe fails on <windows.h>, and the gate is closed.
      const plan = realPlan();
      withToolchain({ vc: false, sdkVersions: [completeVersion(plan.sdkVersion)] }, (ctx) => {
        const structural = resolveBuildToolchain({
          programFilesX86: ctx.programFilesX86,
          vcInstallationPath: plan.vsRoot,
        });
        expect(structural.ok).toBe(true);
        expect(
          isBuildEligible({ programFilesX86: ctx.programFilesX86, vcInstallationPath: plan.vsRoot }),
        ).toBe(false);
      });
    });
  },
);

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

/* ---- N1: provisioning through a junction/symlink alias must never silently pass -- */
// Node realpaths the loaded main module but leaves process.argv[1] as the alias, so
// an `import.meta.url === pathToFileURL(argv[1])` entry guard never ran main()
// through a junction: no output, exit 0, nothing provisioned. The gate is now an
// unconditional entry script, so an aliased invocation runs the full lifecycle.
describe('D062 explicit provisioning — the gate runs through a junction/symlink alias (never a silent exit 0)', () => {
  it('invoked via an alias, the gate validates, attempts provisioning, and reports loudly', () => {
    const t = isolatedGateTree(false);
    const aliasRoot = mkdtempSync(join(tmpdir(), 'ab-alias-'));
    const alias = join(aliasRoot, 'link');
    try {
      symlinkSync(t.root, alias, process.platform === 'win32' ? 'junction' : 'dir');
      const aliasedGate = join(alias, 'tools', 'control-owner', 'ensure-helper.mjs');
      expect(existsSync(aliasedGate)).toBe(true);
      const emptyPf86 = join(t.root, 'empty-pf86');
      mkdirSync(emptyPf86, { recursive: true });
      const env: NodeJS.ProcessEnv = Object.fromEntries(
        Object.entries(process.env).filter(([key]) => key.toLowerCase() !== 'programfiles(x86)'),
      );
      env['ProgramFiles(x86)'] = emptyPf86;
      const run = spawnSync(process.execPath, [aliasedGate], { encoding: 'utf8', env });
      // main() ran: the gate always speaks. Never the pre-fix silent `exit 0`.
      expect(run.stderr).toContain('ensure-helper:');
      if (process.platform === 'win32') {
        // Windows: pair missing → rebuild attempted → toolchain hidden → LOUD nonzero.
        expect(run.stderr).toContain('rebuilding via build.mjs');
        expect(run.stderr).toContain('FAILED to build the owner helper');
        expect(run.status).toBe(1);
        expect(existsSync(join(t.nativeDir, OWNER_HELPER_BASENAME))).toBe(false);
      } else {
        expect(run.stderr).toContain('skipping');
        expect(run.status).toBe(0);
      }
    } finally {
      // Remove the reparse point itself (never its target), then the temp trees.
      try {
        rmdirSync(alias);
      } catch {
        /* already gone */
      }
      rmSync(aliasRoot, { recursive: true, force: true });
      rmSync(t.root, { recursive: true, force: true });
    }
  });

  it('the gate is an unconditional entry script: no exports, no alias-sensitive entry guard', () => {
    const gate = readFileSync(ensureScript, 'utf8');
    expect(gate).not.toMatch(/pathToFileURL|isEntry/);
    expect(gate).not.toMatch(/^export /m);
    expect(gate).toMatch(/^main\(\);\s*$/m);
    // The reusable validator lives in the plain (side-effect-free) module.
    expect(gate).toContain("from './helper-pair.mjs'");
  });
});

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
    // The argv shape is the shared compileArgsFor (source, /Fe:exe, /Fo:objDir\);
    // the builder targets ONLY its private workspace exe/obj dir.
    expect(buildMjs).toContain('compileArgsFor({ source: srcC, exe: workExe, objDir: workObjDir })');
    // No shared object directory under the authoritative native dir, and the final
    // exe path is never a compiler output target.
    expect(buildMjs).not.toMatch(/const objDir = join\(outDir, 'obj'\)/);
    expect(buildMjs).not.toMatch(/\/Fe:|exe: exePath|objDir: outDir/);
  });
  it('publishes by atomic rename and cleans the private workspace best-effort', () => {
    expect(buildMjs).toMatch(/renameSync\(/);
    expect(buildMjs).toMatch(/cleanupWorkspace\(/);
  });
});

// Real concurrent builds (Windows) run in an ISOLATED COPY of the build tools under
// a temp tree, so they never touch the shared dist that owner-helper.win.test.ts
// reads/executes. Gated on the ONE authoritative eligibility predicate (T5): artifact
// presence is not toolchain availability.
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

describe.skipIf(!TEST_BUILD_ELIGIBLE)('D062 concurrent rebuild — isolated real builds converge (Windows)', () => {
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
      const creator = join(t.nativeDir, DESCRIPTOR_CREATOR_BASENAME);
      const creatorProv = join(t.nativeDir, CREATOR_PROVENANCE_BASENAME);
      // Both final pairs canonical and source-bound.
      expect(readFileSync(prov, 'utf8')).toBe(canonicalFor(readFileSync(exe)));
      expect(readFileSync(creatorProv, 'utf8')).toBe(creatorCanonicalFor(readFileSync(creator)));
      // No shared object directory and no private workspace leaked into native/.
      expect(existsSync(join(t.nativeDir, 'obj'))).toBe(false);
      // Every entry under native/ is one of the four authoritative artifacts.
      // (A leaked .build-* dir would violate isolation cleanup.)
      const names = readdirSync(t.nativeDir);
      expect(names.sort()).toEqual([...ALL_NATIVE_BASENAMES].sort());
    } finally {
      rmSync(t.root, { recursive: true, force: true });
    }
  }, 240000);
});

/* ---- T5 reproducer: artifacts present, toolchain hidden → skip, not fail -------- */
// Runs THIS file in a child vitest filtered to the concurrent-build tests. With
// %ProgramFiles(x86)% pointed at an empty directory the artifacts still exist
// (winReady) but the toolchain cannot be resolved, so the concurrent-build tests
// must SKIP (child exit 0, zero failures); with the real environment they must RUN
// and pass when this machine is eligible.
interface VitestJson {
  readonly numFailedTests: number;
  readonly numPassedTests: number;
  readonly numPendingTests: number;
}
function childVitest(env: NodeJS.ProcessEnv): { status: number | null; report: VitestJson } {
  const outDir = mkdtempSync(join(tmpdir(), 'ab-t5-'));
  const outFile = join(outDir, 'report.json');
  try {
    const run = spawnSync(
      process.execPath,
      [
        join(repoRoot, 'node_modules', 'vitest', 'vitest.mjs'),
        'run',
        fileURLToPath(import.meta.url),
        '-t',
        'concurrent builders all succeed',
        '--reporter=json',
        `--outputFile=${outFile}`,
      ],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        // A fresh vitest: drop the parent worker's VITEST* markers.
        env: Object.fromEntries(Object.entries(env).filter(([key]) => !key.startsWith('VITEST'))),
        timeout: 180000,
      },
    );
    const report = JSON.parse(readFileSync(outFile, 'utf8')) as VitestJson;
    return { status: run.status, report };
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}

describe.skipIf(!winReady)('D062 T5 — the concurrent-build gate follows toolchain eligibility, not artifact presence', () => {
  it('toolchain unavailable (artifacts present) → the concurrent-build tests skip; nothing fails', () => {
    const emptyPf86 = mkdtempSync(join(tmpdir(), 'ab-empty-pf86-'));
    try {
      const env: NodeJS.ProcessEnv = Object.fromEntries(
        Object.entries(process.env).filter(([key]) => key.toLowerCase() !== 'programfiles(x86)'),
      );
      env['ProgramFiles(x86)'] = emptyPf86;
      const { status, report } = childVitest(env);
      expect(report.numFailedTests).toBe(0);
      expect(report.numPassedTests).toBe(0);
      expect(report.numPendingTests).toBeGreaterThan(0);
      expect(status).toBe(0);
    } finally {
      rmSync(emptyPf86, { recursive: true, force: true });
    }
  }, 200000);

  it.skipIf(!TEST_BUILD_ELIGIBLE)('toolchain available → the concurrent-build tests still run and pass', () => {
    const { status, report } = childVitest(process.env);
    expect(report.numFailedTests).toBe(0);
    expect(report.numPassedTests).toBe(2); // it.each([2, 4])
    expect(status).toBe(0);
  }, 200000);
});
