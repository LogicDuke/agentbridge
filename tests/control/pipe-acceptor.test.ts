/**
 * DDR-D062-C / D062 Revision 2 — the explicit operator-SID control-pipe accept
 * provider (`agentbridge-win-pipe-accept.node`).
 *
 * Two evidence classes, deliberately separated:
 *
 * 1. SOURCE / UNIT evidence (cross-platform, deterministic): the reviewed C
 *    source is scanned for the adopted security-descriptor construction and for
 *    the absence of every forbidden authority; the provenance encoders,
 *    validators, build-argument shapes, and the runtime loader are exercised
 *    directly with injected seams. None of this proves what the KERNEL does.
 *
 * 2. LIVE WINDOWS evidence (skipped unless the addon has been built into
 *    dist/): the real addon is hash-verified and loaded, a SACRIFICIAL pipe is
 *    created, and its live security descriptor is read back through the
 *    provenanced read-only owner helper (canonical SIDs) and independently
 *    through .NET's PipeSecurity (SDDL); the server PID is read with
 *    GetNamedPipeServerProcessId and must be THIS Node process; a same-SID
 *    client connects and round-trips bytes through the adopted `net.Socket`.
 *    Nothing here touches the production anchor, descriptor, task, or pipe.
 */

import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import net from 'node:net';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import * as helperPair from '../../tools/control-owner/helper-pair.mjs';
import {
  ACCEPTOR_PROVENANCE_BASENAME,
  PIPE_ACCEPTOR_BASENAME,
  PIPE_ACCEPTOR_SOURCE_PATH,
  encodeAcceptorProvenance,
  encodeAttestorProvenance,
  pipeAcceptorSourceId,
  validateAcceptorPair,
  validateAttestorPair,
} from '../../tools/control-owner/helper-pair.mjs';
import {
  CL_ADDON_COMPILE_FLAGS,
  CL_ADDON_LINK_FLAGS,
  CL_COMPILE_FLAGS,
  compileAddonArgsFor,
  importLibArgsFor,
} from '../../tools/control-owner/msvc-toolchain.mjs';
import {
  PIPE_ACCEPTOR_REJECTION,
  createRuntimeDescriptor,
  defaultProcessRunner,
  loadPipeAcceptor,
  parseAclSnapshot,
  parseDescriptor,
  parseWhoamiUser,
  type NativePipeServer,
  type OwnerHelperProvenance,
  type PipeAcceptorAddon,
} from '../../src/control/control-store.js';
import { CONTROL_COMMAND } from '../../src/control/control-command.js';
import { createControlChannelServer } from '../../src/control/control-channel.js';
import { startControlChannel } from '../../src/control/control-runtime.js';
import { generateRuntimeKeyPair } from '../../src/control/control-auth.js';
import { memAnchor, newOrchestrator, passingDescriptorVerify, passingVerify } from './support.js';

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const toolsDir = join(repoRoot, 'tools', 'control-owner');
const controlDir = join(repoRoot, 'src', 'control');
const nativeDir = join(repoRoot, 'dist', 'control', 'native');

/** The reviewed native source, comments stripped so scans target code. */
const rawSource = readFileSync(PIPE_ACCEPTOR_SOURCE_PATH, 'utf8');
const source = rawSource.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function controlSource(file: string): string {
  return stripComments(readFileSync(join(controlDir, file), 'utf8'));
}

const silent = (): void => {
  /* silent */
};

/* ---- 1. Reviewed source: the adopted security descriptor ------------------- */

describe('DDR-D062-C reviewed source — exact runtime SID, explicit protected one-ACE DACL', () => {
  it('derives the principal from its OWN process token (TokenUser), never from an input or a name lookup', () => {
    expect(source).toMatch(/OpenProcessToken\(GetCurrentProcess\(\), TOKEN_QUERY/);
    expect(source).toMatch(/GetTokenInformation\(token, TokenUser/);
    // No name-resolved, string-parsed, default-owner, or well-known substitute principal.
    for (const forbidden of [
      /ConvertStringSidToSid/,
      /LookupAccountName/,
      /LookupAccountSid/,
      /CreateWellKnownSid/,
      /AllocateAndInitializeSid/,
      /TokenOwner/,
      /TokenPrimaryGroup/,
      /SECURITY_LOCAL_SYSTEM_RID/,
      /SECURITY_WORLD_RID/,
      /SECURITY_AUTHENTICATED_USER_RID/,
      /SECURITY_ANONYMOUS_LOGON_RID/,
      /SECURITY_BUILTIN_DOMAIN_RID/,
      /DOMAIN_ALIAS_RID_ADMINS/,
      /S-1-\d/,
      /Everyone/,
    ]) {
      expect(source, `source must not match ${String(forbidden)}`).not.toMatch(forbidden);
    }
  });

  it('builds an explicit descriptor: owner = that SID, DACL PRESENT, PROTECTED, exactly ONE ACE', () => {
    expect(source).toMatch(/SetSecurityDescriptorOwner\(&s->sd, s->operator_sid, FALSE\)/);
    expect(source).toMatch(/SetSecurityDescriptorDacl\(&s->sd, TRUE, s->dacl, FALSE\)/);
    expect(source).toMatch(/SetSecurityDescriptorControl\(&s->sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED\)/);
    // Exactly one EXPLICIT_ACCESS entry, passed once, for the operator SID only.
    expect(source.match(/SetEntriesInAclW\(/g)).toHaveLength(1);
    expect(source).toMatch(/SetEntriesInAclW\(1, &entry, NULL, &s->dacl\)/);
    expect(source).toMatch(/EXPLICIT_ACCESSW entry;/);
    expect(source).not.toMatch(/EXPLICIT_ACCESSW \w+\[/);
    expect(source).toMatch(/entry\.Trustee\.ptstrName = \(LPWSTR\)s->operator_sid;/);
    expect(source).toMatch(/entry\.grfInheritance = NO_INHERITANCE;/);
    expect(source).toMatch(/entry\.grfAccessMode = SET_ACCESS;/);
  });

  it('grants exactly FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE = 0x12019F, pinned at compile time', () => {
    expect(source).toMatch(
      /#define PIPE_ACCESS_MASK \(FILE_GENERIC_READ \| FILE_GENERIC_WRITE \| SYNCHRONIZE\)/,
    );
    expect(source).toMatch(/_Static_assert\(PIPE_ACCESS_MASK == 0x12019FUL,/);
    expect(source).toMatch(/entry\.grfAccessPermissions = PIPE_ACCESS_MASK;/);
    // WRITE_DAC / WRITE_OWNER / DELETE are proven absent at compile time, and no
    // broader mask exists anywhere in the source.
    expect(source).toMatch(
      /_Static_assert\(\(PIPE_ACCESS_MASK & \(WRITE_DAC \| WRITE_OWNER \| DELETE\)\) == 0,/,
    );
    expect(source).not.toMatch(
      /\bFILE_ALL_ACCESS\b|\bGENERIC_ALL\b|\bGENERIC_READ\b|\bGENERIC_WRITE\b|\bSTANDARD_RIGHTS_ALL\b/,
    );
    // The arithmetic the assertion pins (a header-independent witness).
    const FILE_GENERIC_READ = 0x120089;
    const FILE_GENERIC_WRITE = 0x120116;
    const SYNCHRONIZE = 0x100000;
    expect((FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE) >>> 0).toBe(0x12019f);
    expect(0x12019f & (0x40000 | 0x80000 | 0x10000)).toBe(0); // WRITE_DAC | WRITE_OWNER | DELETE
  });

  it('creates EVERY server instance through the ONE CreateNamedPipeW call carrying the explicit SECURITY_ATTRIBUTES', () => {
    const calls = source.match(/CreateNamedPipeW\(/g) ?? [];
    expect(calls).toHaveLength(1);
    const call = /CreateNamedPipeW\(([\s\S]*?)\);/.exec(source);
    expect(call).not.toBeNull();
    expect(call?.[1]).toContain('&s->sa');
    expect(source).toMatch(/s->sa\.lpSecurityDescriptor = &s->sd;/);
    expect(source).toMatch(/s->sa\.bInheritHandle = FALSE;/);
    // The first instance claims the name exclusively (collision fails closed);
    // instances are byte-mode, overlapped, and reject remote clients.
    expect(source).toMatch(/FILE_FLAG_FIRST_PIPE_INSTANCE/);
    expect(source).toMatch(/FILE_FLAG_OVERLAPPED/);
    expect(source).toMatch(/PIPE_REJECT_REMOTE_CLIENTS/);
    expect(source).toMatch(/ConnectNamedPipe\(h, &s->ov\)/);
  });
});

/* ---- 2. Reviewed source: no authority beyond accept ------------------------- */

describe('DDR-D062-C reviewed source — the addon holds no protocol, crypto, dispatch, process, or file authority', () => {
  it('reads and writes no pipe bytes, opens no file, spawns nothing, loads nothing, touches no registry or network', () => {
    for (const forbidden of [
      /\bReadFile\(/,
      /\bWriteFile\(/,
      /\bCreateFile[AW]?\(/,
      /\bCreateProcess/,
      /\bShellExecute/,
      /\bWinExec\b/,
      /\bsystem\(/,
      /_popen/,
      /\bLoadLibrary/,
      /\bRegOpenKey/,
      /\bRegQueryValue/,
      /\bRegGetValue/,
      /\bWSAStartup\b/,
      /\bsocket\(/,
      /\bInternetOpen/,
      /\bWinHttp/,
      /\bSetNamedSecurityInfo/,
      /\bSetSecurityInfo\(/,
      /\bSetFileSecurity/,
      /\bSetKernelObjectSecurity/,
      /\bSetFileInformationByHandle/,
      /\bDeleteFile/,
      /\bMoveFile/,
      /\b_wfopen\b|\bfopen\b/,
      /\bgetenv\b|\bGetEnvironmentVariable/,
      /\bfputs\b|\bfwrite\b|\bputs\(|(?<![a-z_])printf\(/,
      /\bstdout\b|\bstderr\b/,
      /HMAC|Ed25519|sha256|SHA256/i,
      /OPEN_HUMAN_GATE|dispatch|WorkflowEvent|AutoflowRuntime|JSON/,
    ]) {
      expect(source, `source must not match ${String(forbidden)}`).not.toMatch(forbidden);
    }
  });

  it('keeps Node as the server process: instances are created and accepted IN-PROCESS, and the handle is adopted through the host image', () => {
    expect(source).toMatch(/ConnectNamedPipe\(/);
    expect(source).toMatch(/RegisterWaitForSingleObject\(/);
    expect(source).toMatch(/napi_create_threadsafe_function\(/);
    // The libuv fd is minted by the host process image that is already
    // executing this addon (no library is loaded, no path is searched).
    expect(source).toMatch(/GetModuleHandleW\(NULL\)/);
    expect(source).toMatch(/GetProcAddress\(host, "uv_open_osfhandle"\)/);
    expect(source).toMatch(/fd = s->open_osfhandle\(h\);/);
  });

  it('exposes exactly createServer / accept / close, and fixes the Node-API floor at 10 in the source', () => {
    const names = [...source.matchAll(/utf8name = "([^"]+)"/g)].map((m) => m[1]);
    expect(names.sort()).toEqual(['accept', 'close', 'createServer']);
    expect(source).toMatch(/#define NAPI_VERSION 10/);
    expect(source).toMatch(/#if NAPI_VERSION < 10\s+#error/);
    expect(source).toMatch(/napi_register_module_v1\(/);
    expect(source).toMatch(/node_api_module_get_api_version_v1\(/);
    // A path is the ONLY caller-controlled input, and only a LOCAL pipe path.
    expect(source).toMatch(/is_local_pipe_path\(s->path, len\)/);
    expect(source).toMatch(/L"\\\\\\\\\.\\\\pipe\\\\"/);
  });
});

/* ---- 3. Provenance discipline and the ratified build policy ----------------- */

describe('DDR-D062-C provenance — the fourth artifact has its own identity; the subprocess set is unchanged', () => {
  it('encodes a distinct binding and a .node filename; a cross-wired provenance is never valid', () => {
    const bytes = Buffer.from('the-addon-bytes');
    const sourceId = pipeAcceptorSourceId();
    expect(sourceId).toBe(sha256Hex(readFileSync(PIPE_ACCEPTOR_SOURCE_PATH)));
    const canon = encodeAcceptorProvenance(sha256Hex(bytes), sourceId ?? '');
    expect(canon).toContain('export const PIPE_ACCEPTOR_PROVENANCE =');
    expect(canon).toContain(`filename: ${JSON.stringify(PIPE_ACCEPTOR_BASENAME)}`);
    expect(PIPE_ACCEPTOR_BASENAME.endsWith('.node')).toBe(true);
    expect(ACCEPTOR_PROVENANCE_BASENAME).toBe('pipe-acceptor-provenance.js');
    expect(canon).not.toContain('PIPE_ATTESTOR_PROVENANCE');
    // The attestor's encoding of the same bytes is not an acceptor pair.
    const other = encodeAttestorProvenance(sha256Hex(bytes), sourceId ?? '');
    expect(other).not.toBe(canon);
  });

  it('the complete subprocess set remains whoami + THREE executables; the acceptor is the ONE in-process artifact', () => {
    const exes = Object.values(helperPair).filter(
      (value): value is string => typeof value === 'string' && value.endsWith('.exe'),
    );
    const addons = Object.values(helperPair).filter(
      (value): value is string => typeof value === 'string' && value.endsWith('.node'),
    );
    expect(exes.sort()).toEqual([
      'agentbridge-win-descriptor-create.exe',
      'agentbridge-win-owner.exe',
      'agentbridge-win-pipe-attest.exe',
    ]);
    expect(addons).toEqual(['agentbridge-win-pipe-accept.node']);
    // Every artifact is provisioned and built by the same shared tooling.
    const build = readFileSync(join(toolsDir, 'build.mjs'), 'utf8');
    const gate = readFileSync(join(toolsDir, 'ensure-helper.mjs'), 'utf8');
    for (const tool of [build, gate]) {
      expect(tool).toContain('PIPE_ACCEPTOR_BASENAME');
      expect(tool).toContain('ACCEPTOR_PROVENANCE_BASENAME');
    }
    expect(gate).toContain('validateAcceptorPair');
    // The validator is the shared canonical-pair mechanism with its own encoder.
    expect(typeof validateAcceptorPair).toBe('function');
    expect(typeof validateAttestorPair).toBe('function');
  });

  it('ratified native build policy: exact-pinned build-only node-api-headers@1.9.0, no node-gyp / binding.gyp / cmake-js / node-addon-api', () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies: Record<string, string>;
    };
    expect(pkg.devDependencies['node-api-headers']).toBe('1.9.0');
    expect(pkg.dependencies?.['node-api-headers']).toBeUndefined();
    const lock = JSON.parse(readFileSync(join(repoRoot, 'package-lock.json'), 'utf8')) as {
      packages: Record<string, { version?: string; integrity?: string; dev?: boolean }>;
    };
    const locked = lock.packages['node_modules/node-api-headers'];
    expect(locked?.version).toBe('1.9.0');
    expect(locked?.dev).toBe(true);
    expect(locked?.integrity).toMatch(/^sha512-/);
    const pkgText = readFileSync(join(repoRoot, 'package.json'), 'utf8');
    expect(pkgText).not.toMatch(/node-gyp|node-addon-api|cmake-js|prebuild/);
    expect(existsSync(join(repoRoot, 'binding.gyp'))).toBe(false);
    expect(existsSync(join(toolsDir, 'binding.gyp'))).toBe(false);
    // Code only (the builder's comments name the forbidden tools to forbid them).
    const build = stripComments(readFileSync(join(toolsDir, 'build.mjs'), 'utf8'));
    expect(build).toContain("const NODE_API_HEADERS_VERSION = '1.9.0';");
    expect(build).toContain("'def', 'node_api.def'");
    expect(build).not.toMatch(/node-gyp|binding\.gyp|cmake-js|node-addon-api/);
  });

  it('the addon compile/link and import-library argv shapes are the shared ones (flags, /LD, /I, /Fe, /Fo, /link, node.lib)', () => {
    const args = compileAddonArgsFor({
      source: 'C:\\src\\a.c',
      out: 'C:\\ws\\a.node',
      objDir: 'C:\\ws\\obj',
      includeDir: 'C:\\repo\\node_modules\\node-api-headers\\include',
      importLib: 'C:\\ws\\node.lib',
    });
    expect(args.slice(0, CL_COMPILE_FLAGS.length)).toEqual([...CL_COMPILE_FLAGS]);
    expect(CL_ADDON_COMPILE_FLAGS).toEqual(['/LD']);
    expect(args).toContain('/LD');
    expect(args).toContain('/IC:\\repo\\node_modules\\node-api-headers\\include');
    expect(args).toContain('/Fe:C:\\ws\\a.node');
    expect(args).toContain('/Fo:C:\\ws\\obj\\');
    const link = args.indexOf('/link');
    expect(link).toBeGreaterThan(0);
    expect(args.slice(link + 1)).toEqual([...CL_ADDON_LINK_FLAGS, 'C:\\ws\\node.lib']);
    expect(CL_ADDON_LINK_FLAGS).toContain('/DLL');
    expect(CL_ADDON_LINK_FLAGS).toContain('/Brepro');
    expect(importLibArgsFor({ def: 'C:\\d\\node_api.def', out: 'C:\\ws\\node.lib' })).toEqual([
      '/nologo',
      '/MACHINE:X64',
      '/DEF:C:\\d\\node_api.def',
      '/OUT:C:\\ws\\node.lib',
    ]);
  });
});

/* ---- 4. Runtime loader: hash-before-load, fail-closed, control-only --------- */

const GOOD_BYTES = Buffer.from('addon-image');
const GOOD_PROVENANCE: OwnerHelperProvenance = {
  filename: PIPE_ACCEPTOR_BASENAME,
  sha256: sha256Hex(GOOD_BYTES),
};

describe('DDR-D062-C runtime loader — verified before load, fail-closed on every fault', () => {
  it('absent / malformed provenance → ACCEPTOR_PROVENANCE_MISSING, and the addon is never read or loaded', async () => {
    let touched = 0;
    const deps = {
      readAcceptorBytes: (): Buffer => {
        touched += 1;
        return GOOD_BYTES;
      },
      loadAddon: (): unknown => {
        touched += 1;
        return {};
      },
    };
    expect(await loadPipeAcceptor({ ...deps, loadProvenance: () => Promise.resolve(null) })).toEqual({
      ok: false,
      reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_PROVENANCE_MISSING,
    });
    expect(
      await loadPipeAcceptor({
        ...deps,
        loadProvenance: () => Promise.resolve({ ...GOOD_PROVENANCE, sha256: GOOD_PROVENANCE.sha256.toUpperCase() }),
      }),
    ).toEqual({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_PROVENANCE_MISSING });
    expect(
      await loadPipeAcceptor({
        ...deps,
        loadProvenance: () => Promise.resolve({ ...GOOD_PROVENANCE, filename: '..\\evil.node' }),
      }),
    ).toEqual({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_PROVENANCE_MISSING });
    expect(touched).toBe(0);
  });

  it('missing addon → ACCEPTOR_MISSING; tampered bytes → ACCEPTOR_HASH_MISMATCH; load is never attempted', async () => {
    let loads = 0;
    const loadAddon = (): unknown => {
      loads += 1;
      return {};
    };
    expect(
      await loadPipeAcceptor({
        loadProvenance: () => Promise.resolve(GOOD_PROVENANCE),
        readAcceptorBytes: () => null,
        loadAddon,
      }),
    ).toEqual({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_MISSING });
    expect(
      await loadPipeAcceptor({
        loadProvenance: () => Promise.resolve(GOOD_PROVENANCE),
        readAcceptorBytes: () => Buffer.concat([GOOD_BYTES, Buffer.from([0])]),
        loadAddon,
      }),
    ).toEqual({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_HASH_MISMATCH });
    expect(loads).toBe(0);
  });

  it('a verified image that fails to load → ACCEPTOR_LOAD_FAILED; a wrong export shape → ACCEPTOR_SHAPE_INVALID', async () => {
    expect(
      await loadPipeAcceptor({
        loadProvenance: () => Promise.resolve(GOOD_PROVENANCE),
        readAcceptorBytes: () => GOOD_BYTES,
        loadAddon: () => {
          throw new Error('not a valid Win32 application');
        },
      }),
    ).toEqual({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_LOAD_FAILED });
    for (const shape of [{}, null, 42, { createServer: 'no' }, { accept: (): void => undefined }]) {
      expect(
        await loadPipeAcceptor({
          loadProvenance: () => Promise.resolve(GOOD_PROVENANCE),
          readAcceptorBytes: () => GOOD_BYTES,
          loadAddon: () => shape,
        }),
      ).toEqual({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_SHAPE_INVALID });
    }
  });

  it('a verified, well-shaped addon is loaded ONLY after the hash matched, and only createServer is projected', async () => {
    const order: string[] = [];
    const native: NativePipeServer = { accept: (): void => undefined, close: (): void => undefined };
    const fake: PipeAcceptorAddon & { extra: () => string } = {
      createServer: (pipePath) => {
        order.push(`createServer:${pipePath}`);
        return native;
      },
      extra: () => 'never reachable',
    };
    const load = await loadPipeAcceptor({
      loadProvenance: () => {
        order.push('provenance');
        return Promise.resolve(GOOD_PROVENANCE);
      },
      readAcceptorBytes: () => {
        order.push('read');
        return GOOD_BYTES;
      },
      hashBytes: (bytes) => {
        order.push('hash');
        return sha256Hex(bytes);
      },
      loadAddon: () => {
        order.push('load');
        return fake;
      },
    });
    expect(load.ok).toBe(true);
    expect(order).toEqual(['provenance', 'read', 'hash', 'load']);
    if (load.ok) {
      expect(Object.keys(load.addon)).toEqual(['createServer']);
      expect(load.addon.createServer('\\\\.\\pipe\\x', silent)).toBe(native);
      expect(order.at(-1)).toBe('createServer:\\\\.\\pipe\\x');
    }
  });
});

/* ---- 5. No fallback transport; failure disables CONTROL only ---------------- */

describe('DDR-D062-C control transport — native provider only, never a default-descriptor pipe', () => {
  it('src/control never creates a net server; the production factory loads the verified provider', () => {
    for (const file of ['control-channel.ts', 'control-runtime.ts', 'control-store.ts', 'cli.ts', 'cli-main.ts']) {
      const text = controlSource(file);
      expect(text, `${file} must not use net.createServer`).not.toMatch(/net\.createServer|createServer\s*\(\s*\(?socket/);
    }
    const channel = controlSource('control-channel.ts');
    expect(channel).toContain('loadPipeAcceptor');
    expect(channel).toMatch(/new net\.Socket\(\{ fd, readable: true, writable: true \}\)/);
    const store = controlSource('control-store.ts');
    expect(store).toContain('pipe-acceptor-provenance');
    expect(store).toMatch(/process\.dlopen\(/);
    expect(store).toMatch(/ACCEPTOR_HASH_MISMATCH/);
  });

  it('a provider that fails verification makes listen() error (no listening callback, no other transport)', async () => {
    const { orchestrator } = newOrchestrator();
    const minted = createRuntimeDescriptor();
    const keyPair = generateRuntimeKeyPair();
    const server = createControlChannelServer({
      identity: { runtimeId: minted.runtimeId, pipeName: minted.descriptor.pipeName, verifyKey: keyPair.verifyKey },
      token: minted.token,
      privateKey: keyPair.privateKey,
      dispatcher: { dispatch: () => 'UNAVAILABLE' },
      loadAcceptor: () =>
        Promise.resolve({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_HASH_MISMATCH }),
    });
    void orchestrator;
    let listening = false;
    const error = await new Promise<Error>((resolve) => {
      server.once('error', resolve);
      server.listen('\\\\.\\pipe\\agentbridge-never-created', () => {
        listening = true;
      });
    });
    expect(listening).toBe(false);
    expect(error.message).toBe('pipe acceptor unavailable (ACCEPTOR_HASH_MISMATCH)');
    await new Promise<void>((resolve) => {
      server.close(resolve);
    });
  });

  it('startControlChannel fails CLOSED before publishing when the provider is unverified — the orchestrator is untouched', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const logged: string[] = [];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      createServer: (options) =>
        createControlChannelServer({
          ...options,
          loadAcceptor: () =>
            Promise.resolve({ ok: false, reason: PIPE_ACCEPTOR_REJECTION.ACCEPTOR_PROVENANCE_MISSING }),
        }),
      logger: (message) => {
        logged.push(message);
      },
    });
    expect(handle).toBeNull();
    expect(anchor.createCalls()).toBe(0);
    expect([...anchor.entries().keys()]).toEqual([]);
    expect(logged.join('\n')).toContain(
      'disabled (pipe unavailable: pipe acceptor unavailable (ACCEPTOR_PROVENANCE_MISSING))',
    );
    expect(runtime.reader().current()).toBeNull();
  });

  it('the DEFAULT factory, run from source (no built provider beside it), also fails closed rather than falling back', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const logged: string[] = [];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      logger: (message) => {
        logged.push(message);
      },
    });
    expect(handle).toBeNull();
    expect(anchor.createCalls()).toBe(0);
    expect(logged.join('\n')).toContain('pipe acceptor unavailable (ACCEPTOR_PROVENANCE_MISSING)');
  });

  it('a provider whose createServer throws (e.g. a name collision) is a listen failure, not a crash', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const addon: PipeAcceptorAddon = {
      createServer: () => {
        throw new Error('ERR_PIPE_CREATE (231)');
      },
    };
    const logged: string[] = [];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      createServer: (options) =>
        createControlChannelServer({ ...options, loadAcceptor: () => Promise.resolve({ ok: true, addon }) }),
      logger: (message) => {
        logged.push(message);
      },
    });
    expect(handle).toBeNull();
    expect(anchor.createCalls()).toBe(0);
    expect(logged.join('\n')).toContain('disabled (pipe unavailable: ERR_PIPE_CREATE (231))');
  });
});

/* ---- 6. Frozen protocol contract ------------------------------------------- */

describe('DDR-D062-C leaves the D062 protocol contract unchanged', () => {
  it('descriptor v4 is exactly { version: 4, pipeName, token } — no verifyKey', () => {
    const minted = createRuntimeDescriptor();
    expect(Object.keys(minted.descriptor)).toEqual(['version', 'pipeName', 'token']);
    expect(minted.descriptor.version).toBe(4);
    const text = JSON.stringify(minted.descriptor);
    expect(parseDescriptor(text)).not.toBeNull();
    const widened = JSON.stringify({ ...minted.descriptor, verifyKey: 'AAAA' });
    expect(parseDescriptor(widened)).toBeNull();
  });

  it('token-HMAC client authentication before dispatch, Ed25519 result signing, no result-HMAC, one production command', () => {
    const channel = controlSource('control-channel.ts');
    const macAt = channel.indexOf('computeClientMac(');
    const dispatchAt = channel.indexOf('ctx.dispatcher.dispatch(');
    expect(macAt).toBeGreaterThan(0);
    expect(dispatchAt).toBeGreaterThan(macAt);
    expect(channel).toContain('macEqual(expectedMac, parsed.mac)');
    expect(channel).toContain('signServerResult(');
    expect(channel).not.toMatch(/computeServerMac|resultMac/);
    expect(Object.keys(CONTROL_COMMAND)).toEqual(['OPEN_HUMAN_GATE']);
  });
});

/* ---- 7. LIVE Windows evidence (built provider required) --------------------- */

const acceptorPath = join(nativeDir, PIPE_ACCEPTOR_BASENAME);
const acceptorProvPath = join(nativeDir, ACCEPTOR_PROVENANCE_BASENAME);
const ownerHelperPath = join(nativeDir, 'agentbridge-win-owner.exe');
const systemRoot = process.env['SystemRoot'] ?? 'C:\\Windows';

const liveReady =
  process.platform === 'win32' &&
  existsSync(acceptorPath) &&
  existsSync(acceptorProvPath) &&
  existsSync(ownerHelperPath);

/** Load the DIST provenance module the build wrote (the runtime's own trust root). */
async function loadDistAcceptorProvenance(): Promise<OwnerHelperProvenance | null> {
  const loaded = (await import(pathToFileURL(acceptorProvPath).href)) as unknown;
  if (typeof loaded !== 'object' || loaded === null) {
    return null;
  }
  const record = (loaded as Record<string, unknown>)['PIPE_ACCEPTOR_PROVENANCE'];
  if (typeof record !== 'object' || record === null) {
    return null;
  }
  const { filename, sha256 } = record as { filename?: unknown; sha256?: unknown };
  return typeof filename === 'string' && typeof sha256 === 'string' ? { filename, sha256 } : null;
}

/**
 * SDDL renders a security descriptor for DISPLAY: Windows is free to abbreviate
 * a well-known SID to an alias (`O:LAD:P(A;;0x12019f;;;LA)`). Alias text is
 * therefore never an identity here — every principal compared below is a
 * canonical numeric SID read back off a .NET `SecurityIdentifier`.
 */
function isCanonicalSid(value: string): boolean {
  return /^S-1-\d+(?:-\d+)+$/i.test(value);
}

describe('DDR-D062-C — SDDL alias text is never trusted as a principal identity', () => {
  it('only canonical numeric SIDs are accepted; every SDDL alias is rejected', () => {
    for (const alias of ['LA', 'BA', 'SY', 'WD', 'AU', 'BU', 'AN', 'IU', 'O:LAD:P(A;;0x12019f;;;LA)', '']) {
      expect(isCanonicalSid(alias)).toBe(false);
    }
    expect(isCanonicalSid('S-1-5-21-1111111111-2222222222-3333333333-500')).toBe(true);
    expect(isCanonicalSid('S-1-5-18')).toBe(true);
  });
});

describe.skipIf(!liveReady)('DDR-D062-C LIVE — sacrificial pipe: kernel security descriptor, server PID, same-SID round trip', () => {
  const opened: NativePipeServer[] = [];
  const sockets: net.Socket[] = [];

  afterEach(() => {
    for (const socket of sockets.splice(0)) {
      socket.destroy();
    }
    for (const native of opened.splice(0)) {
      native.close();
    }
  });

  async function loadReal(): Promise<PipeAcceptorAddon> {
    const load = await loadPipeAcceptor({
      loadProvenance: loadDistAcceptorProvenance,
      resolveAcceptorPath: (filename) => join(nativeDir, filename),
    });
    if (!load.ok) {
      throw new Error(`built provider rejected: ${load.reason}`);
    }
    return load.addon;
  }

  /** An echo server on a fresh sacrificial pipe name; sockets are ordinary net.Sockets. */
  async function sacrificialServer(): Promise<{ pipePath: string; native: NativePipeServer; accepted: () => number }> {
    const addon = await loadReal();
    const pipePath = `\\\\.\\pipe\\agentbridge-d062-sacrificial-${randomBytes(8).toString('hex')}`;
    let accepted = 0;
    let native: NativePipeServer | null = null;
    native = addon.createServer(pipePath, (error, fd) => {
      if (error !== null) {
        return;
      }
      accepted += 1;
      const socket = new net.Socket({ fd, readable: true, writable: true });
      sockets.push(socket);
      socket.on('error', silent);
      socket.on('data', (chunk: Buffer) => {
        socket.write(chunk);
      });
      native?.accept();
    });
    opened.push(native);
    return { pipePath, native, accepted: () => accepted };
  }

  it('the built pair is canonical and the runtime loader accepts it (hash-verified before load)', async () => {
    expect(validateAcceptorPair({ exePath: acceptorPath, provenancePath: acceptorProvPath })).toEqual({
      valid: true,
      reason: 'valid',
    });
    const addon = await loadReal();
    expect(typeof addon.createServer).toBe('function');
  });

  it('the live pipe SD: owner = whoami SID; DACL PRESENT + PROTECTED; exactly one ALLOW ACE, flags 0x00, mask 0x12019F, that SID', async () => {
    const { pipePath } = await sacrificialServer();
    const run = defaultProcessRunner(systemRoot);
    const whoami = await run(join(systemRoot, 'System32', 'whoami.exe'), ['/user']);
    expect(whoami.ok).toBe(true);
    const operator = whoami.ok ? parseWhoamiUser(whoami.stdout) : null;
    expect(operator).not.toBeNull();
    // The provenanced read-only owner helper reads the pipe's OWNER + DACL as
    // canonical SIDs (its CreateFile open is one client connection to the
    // sacrificial pipe, which the echo server simply accepts).
    const snapshot = await run(ownerHelperPath, ['--acl', pipePath]);
    expect(snapshot.ok).toBe(true);
    const acl = snapshot.ok ? parseAclSnapshot(snapshot.stdout) : null;
    expect(acl).not.toBeNull();
    if (acl === null || operator === null) {
      return;
    }
    expect(acl.ownerSid).toBe(operator.sid);
    expect(acl.daclState).toBe('PRESENT');
    expect(acl.daclProtected).toBe(true);
    expect(acl.aces).toHaveLength(1);
    const ace = acl.aces[0];
    expect(ace).toEqual({ type: 'ALLOW', flags: 0x00, mask: 0x12019f, sid: operator.sid });
    // Forbidden principals and rights are absent by construction of the single ACE.
    for (const forbidden of ['s-1-1-0', 's-1-5-7', 's-1-5-32-545', 's-1-5-11', 's-1-5-32-544', 's-1-5-18']) {
      expect(acl.aces.some((entry) => entry.sid === forbidden)).toBe(false);
    }
    expect(ace === undefined ? 0 : ace.mask & (0x40000 | 0x80000 | 0x10000)).toBe(0);
  }, 20000);

  it('GetNamedPipeServerProcessId reports THIS Node process, and .NET reads the same protected one-ACE descriptor', async () => {
    const { pipePath } = await sacrificialServer();
    const name = pipePath.slice('\\\\.\\pipe\\'.length);
    // The probe is a CHILD of this Node process, so its TokenUser SID is this
    // process's TokenUser SID. Every identity it reports is read off a .NET
    // SecurityIdentifier and emitted as a canonical numeric SID; the SDDL
    // display form is carried alongside as diagnostics only.
    const script = [
      "$ErrorActionPreference = 'Stop'",
      'Add-Type -Namespace AB -Name P -MemberDefinition \'[DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(IntPtr h, out uint pid);\'',
      `$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', '${name}', [System.IO.Pipes.PipeDirection]::InOut)`,
      '$c.Connect(5000)',
      '[uint32]$serverPid = 0',
      '[void][AB.P]::GetNamedPipeServerProcessId($c.SafePipeHandle.DangerousGetHandle(), [ref]$serverPid)',
      '$sidType = [System.Security.Principal.SecurityIdentifier]',
      '$sd = $c.GetAccessControl()',
      'Write-Output "PID|$serverPid"',
      'Write-Output ("TOKENUSER|" + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)',
      'Write-Output ("OWNER|" + $sd.GetOwner($sidType).Value)',
      'Write-Output ("PROTECTED|" + $sd.AreAccessRulesProtected)',
      'Write-Output ("SDDL|" + $sd.GetSecurityDescriptorSddlForm(\'Owner,Access\'))',
      '$sd.GetAccessRules($true, $true, $sidType) | ForEach-Object { Write-Output ("ACE|" + $_.AccessControlType + "|" + $_.IdentityReference.Value + "|" + [int]$_.PipeAccessRights + "|" + [int]$_.InheritanceFlags + "|" + [int]$_.PropagationFlags) }',
      '$c.Dispose()',
    ].join('\n');
    const powershell = join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const result = spawnSync(
      powershell,
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { encoding: 'utf8', timeout: 15000, windowsHide: true },
    );
    expect(result.status, result.stderr).toBe(0);
    const lines = result.stdout
      .split(/\r?\n/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    const diag = lines.join(' / ');
    const field = (key: string): string | null => {
      const hit = lines.find((entry) => entry.startsWith(`${key}|`));
      return hit === undefined ? null : hit.slice(key.length + 1);
    };
    const aces = lines.filter((entry) => entry.startsWith('ACE|')).map((entry) => entry.split('|'));

    // IDENTITY AUTHORITY: the running process's own TokenUser SID, canonical.
    const tokenUser = field('TOKENUSER');
    expect(tokenUser, diag).not.toBeNull();
    expect(isCanonicalSid(tokenUser ?? ''), diag).toBe(true);

    expect(Number(field('PID')), diag).toBe(process.pid); // Node is the server process
    expect(field('OWNER'), diag).toBe(tokenUser); // owner IS that exact runtime SID
    expect(field('PROTECTED'), diag).toBe('True'); // DACL PRESENT + PROTECTED
    expect(aces, diag).toHaveLength(1); // exactly ONE ACE
    const [, aceType, aceSid, aceMask, aceInherit, acePropagate] = aces[0] ?? [];
    expect(aceType, diag).toBe('Allow');
    expect(isCanonicalSid(aceSid ?? ''), diag).toBe(true); // an alias string can never satisfy this
    expect(aceSid, diag).toBe(tokenUser); // the sole ACE names that exact runtime SID
    expect(aceSid, diag).toBe(field('OWNER')); // owner and ACE are the same identity
    expect(Number(aceMask), diag).toBe(0x12019f); // exact mask, pinned
    expect(Number(aceMask) & (0x40000 | 0x80000 | 0x10000), diag).toBe(0); // no WRITE_DAC/WRITE_OWNER/DELETE
    expect(`${aceInherit ?? ''}/${acePropagate ?? ''}`, diag).toBe('0/0');
    for (const forbidden of ['S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545']) {
      expect(
        aces.some((entry) => (entry[2] ?? '').toUpperCase() === forbidden),
        diag,
      ).toBe(false);
    }
    // Supplemental diagnostics only — NEVER the source of identity: whatever
    // representation Windows chose, the SD still shows one ALLOW ACE under a
    // protected DACL and no DENY ACE.
    const sddl = field('SDDL') ?? '';
    expect((sddl.match(/\(A;/g) ?? []).length, diag).toBe(1);
    expect(sddl, diag).toMatch(/D:P/);
    expect(sddl, diag).not.toMatch(/\(D;/);
  }, 30000);

  it('an ordinary same-SID client connects and round-trips bytes through the adopted net.Socket; the name is held exclusively', async () => {
    const { pipePath, accepted } = await sacrificialServer();
    const echoed = await new Promise<string>((resolve, reject) => {
      const client = net.connect(pipePath);
      sockets.push(client);
      client.setTimeout(5000, () => {
        reject(new Error('timeout'));
      });
      client.on('error', reject);
      client.on('connect', () => {
        client.write('ping-d062');
      });
      client.on('data', (chunk: Buffer) => {
        resolve(chunk.toString('utf8'));
      });
    });
    expect(echoed).toBe('ping-d062');
    expect(accepted()).toBeGreaterThanOrEqual(1);
    // A second server on the SAME name fails closed (FILE_FLAG_FIRST_PIPE_INSTANCE).
    const addon = await loadReal();
    expect(() => addon.createServer(pipePath, silent)).toThrow(/ERR_PIPE_CREATE/);
  }, 20000);
});
