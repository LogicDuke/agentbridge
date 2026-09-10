/**
 * D062 descriptor lifecycle v2 — identity-named descriptors, listen-before-publish.
 *
 * Every test here drives the REAL `startControlChannel` over a REAL named pipe;
 * only the anchor verification, the descriptor ACL verification, the creator, the
 * pipe probe, and the anchor filesystem are injected. The in-memory anchor models
 * exactly the primitive operations the production filesystem provides (list, read
 * one exact path, unlink one exact path, CREATE_NEW one exact path), so what is
 * proven here is the runtime's ORDERING and TARGETING, not filesystem semantics.
 */

import { EventEmitter } from 'node:events';
import net from 'node:net';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { WORKFLOW_STATUS } from '../../src/domain/index.js';
import { createControlChannelServer } from '../../src/control/control-channel.js';
import {
  CONTROL_COMMAND,
  CONTROL_RESULT,
  type ControlCommand,
} from '../../src/control/control-command.js';
import { createControlDispatcher, type ControlDispatcher } from '../../src/control/control-dispatch.js';
import {
  CONTROL_ANCHOR_REJECTION,
  DESCRIPTOR_CREATION_REJECTION,
  MAX_ANCHOR_ENTRIES,
  MAX_DESCRIPTOR_CANDIDATES,
  createRuntimeDescriptor,
  defaultPipeProbe,
  descriptorFilenameFor,
  descriptorPathFor,
  discoverControlRuntime,
  parseDescriptor,
  pipeNameForRuntimeId,
  pipePathFromName,
  runtimeIdFromDescriptorFilename,
  serializeDescriptor,
  verifyDescriptorAcl,
  type ControlAnchorVerification,
  type DescriptorAclVerification,
  type OwnerVerifierDeps,
  type PipeProbe,
  type ProcessResult,
  type ProcessRunner,
} from '../../src/control/control-store.js';
import {
  startControlChannel,
  type ControlChannelHandle,
  type DescriptorCreatorFn,
} from '../../src/control/control-runtime.js';
import {
  BINDING,
  FAKE_ANCHOR,
  allAbsentProbe,
  closeServer,
  memAnchor,
  newOrchestrator,
  passingDescriptorVerify,
  passingVerify,
  startServer,
  startSilentServer,
  tableProbe,
  type MemAnchor,
} from './support.js';

const handles: ControlChannelHandle[] = [];
const servers: net.Server[] = [];
const children: ChildProcess[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
  await Promise.all(servers.splice(0).map((server) => closeServer(server)));
  for (const child of children.splice(0)) {
    child.kill('SIGKILL');
  }
});

const silent = (): void => {
  /* silent */
};

/** The real probe, so liveness in these tests reflects the real kernel pipe namespace. */
const realProbe = defaultPipeProbe(1500);

/** Every identity-named file currently in the anchor. */
function filesIn(anchor: MemAnchor): string[] {
  return [...anchor.entries().keys()].sort();
}

/**
 * A createControlChannelServer stand-in whose listen() always fails, invoking
 * `beforeFailure` first — deterministic listen-failure without pipe timing.
 */
function failingServerFactory(beforeFailure: () => void = silent): typeof createControlChannelServer {
  return ((): net.Server => {
    const emitter = new EventEmitter();
    const fake = {
      once: (event: string, listener: (...args: unknown[]) => void): net.Server => {
        emitter.once(event, listener);
        return fake as unknown as net.Server;
      },
      removeListener: (event: string, listener: (...args: unknown[]) => void): net.Server => {
        emitter.removeListener(event, listener);
        return fake as unknown as net.Server;
      },
      on: (event: string, listener: (...args: unknown[]) => void): net.Server => {
        emitter.on(event, listener);
        return fake as unknown as net.Server;
      },
      listen: (): net.Server => {
        beforeFailure();
        emitter.emit('error', new Error('EADDRINUSE'));
        return fake as unknown as net.Server;
      },
      close: (callback?: () => void): net.Server => {
        callback?.();
        return fake as unknown as net.Server;
      },
    };
    return fake as unknown as net.Server;
  }) as typeof createControlChannelServer;
}

/** A valid foreign descriptor text for a fresh runtime id. */
function foreignDescriptor(): { runtimeId: string; text: string; pipePath: string } {
  const minted = createRuntimeDescriptor();
  return {
    runtimeId: minted.runtimeId,
    text: serializeDescriptor(minted.descriptor),
    pipePath: pipePathFromName(minted.descriptor.pipeName),
  };
}

/* ---- 1–3, 7: startup ordering ---------------------------------------------- */

describe('D062 lifecycle v2 — startup ordering (listen before publish)', () => {
  it('1. a successful runtime publishes exactly one unique identity-named descriptor', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const a = await startServer(orchestrator, anchor);
    handles.push(a);
    const b = await startServer(orchestrator, anchor);
    handles.push(b);

    expect(a.runtimeId).not.toBe(b.runtimeId);
    expect(filesIn(anchor)).toEqual(
      [descriptorFilenameFor(a.runtimeId), descriptorFilenameFor(b.runtimeId)].sort(),
    );
    for (const handle of [a, b]) {
      expect(handle.descriptorPath).toBe(descriptorPathFor(FAKE_ANCHOR, handle.runtimeId));
      expect(handle.pipeName).toBe(pipeNameForRuntimeId(handle.runtimeId));
      const parsed = parseDescriptor(anchor.get(handle.runtimeId));
      expect(parsed?.runtimeId).toBe(handle.runtimeId);
      expect(parsed?.descriptor.pipeName).toBe(handle.pipeName);
      // Live: the kernel reports the pipe present.
      expect(await realProbe(handle.pipePath)).toBe('PRESENT');
    }
  });

  it('2. the descriptor is published only AFTER the pipe listen has succeeded', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const observed: { listenedAtCreate: boolean | null; pipeAtCreate: string | null } = {
      listenedAtCreate: null,
      pipeAtCreate: null,
    };
    let listening = false;
    const createServer: typeof createControlChannelServer = (options) => {
      const server = createControlChannelServer(options);
      server.once('listening', () => {
        listening = true;
      });
      return server;
    };
    const create: DescriptorCreatorFn = async (dir, runtimeId, bytes) => {
      observed.listenedAtCreate = listening;
      // The pipe for THIS id is already live when creation is requested.
      observed.pipeAtCreate = await realProbe(pipePathFromName(pipeNameForRuntimeId(runtimeId)));
      return anchor.create(dir, runtimeId, bytes);
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: create,
      createServer,
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
    }
    expect(observed.listenedAtCreate).toBe(true);
    expect(observed.pipeAtCreate).toBe('PRESENT');
  });

  it('3. a failed pipe listen publishes nothing and exposes no handle', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      createServer: failingServerFactory((): void => {
        expect(anchor.createCalls()).toBe(0);
      }),
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(anchor.createCalls()).toBe(0);
    expect(filesIn(anchor)).toEqual([]);
    expect(anchor.removeCalls()).toBe(0);
  });

  it('3b. a real same-name pipe collision fails closed before anything is published', async () => {
    // Force the minted pipe name to collide with a pipe we hold open: the server
    // factory is the real one; we pre-listen on the exact path the runtime will
    // use by seeing the id it hands the creator... which never happens, because
    // listen fails first. So instead hold the name open via a deterministic id.
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    // Wrap createServer so we can learn the pipe path at listen time and squat it.
    let squatted: net.Server | null = null;
    const createServer: typeof createControlChannelServer = (options) => {
      const server = createControlChannelServer(options);
      const originalListen = server.listen.bind(server);
      // Squat the same path synchronously before the real listen proceeds.
      (server as { listen: unknown }).listen = ((path: string, cb?: () => void): net.Server => {
        squatted = net.createServer();
        servers.push(squatted);
        squatted.listen(path, () => {
          originalListen(path, cb);
        });
        return server;
      }) as typeof server.listen;
      return server;
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      createServer,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(squatted).not.toBeNull();
    expect(anchor.createCalls()).toBe(0);
    expect(filesIn(anchor)).toEqual([]);
  });

  it('an unverified anchor disables the channel: no sweep, no listen, no creation', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const stale = foreignDescriptor();
    anchor.set(stale.runtimeId, stale.text);
    let serverCreates = 0;
    const handle = await startControlChannel({
      orchestrator,
      verify: (): Promise<ControlAnchorVerification> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL }),
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: allAbsentProbe,
      createServer: (() => {
        serverCreates += 1;
        throw new Error('must not be reached');
      }) as typeof createControlChannelServer,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(serverCreates).toBe(0);
    expect(anchor.createCalls()).toBe(0);
    // Even a dead foreign descriptor is untouched: nothing runs before the anchor verifies.
    expect(anchor.get(stale.runtimeId)).toBe(stale.text);
  });

  it('7. the runtime verifies the EXACT descriptor file it created, then reads it back', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const verified: string[] = [];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (path): Promise<DescriptorAclVerification> => {
        verified.push(path);
        // The file must already exist with the minted contents when verified.
        const id = runtimeIdFromDescriptorFilename(path.slice(FAKE_ANCHOR.length + 1));
        expect(id).not.toBeNull();
        expect(anchor.get(id ?? '')).not.toBeNull();
        return Promise.resolve({ ok: true });
      },
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    expect(verified).toEqual([handle.descriptorPath]);
    expect(handle.descriptorPath).toBe(descriptorPathFor(FAKE_ANCHOR, handle.runtimeId));
  });
});

/* ---- 4–6 are creator tests (control-store / real Windows); 8–11: verification --- */

const OPERATOR_SID = 'S-1-5-21-111-222-333-1001';
const SYSTEM_SID = 'S-1-5-18';
const WHOAMI = [
  'User Name         SID',
  '================= =============================================',
  `desktop-x\\dell    ${OPERATOR_SID}`,
  '',
].join('\r\n');

interface AceSpec {
  readonly type?: 'ALLOW' | 'DENY';
  readonly flags?: number;
  readonly sid: string;
}
function snapshot(
  owner: string,
  aces: readonly AceSpec[],
  dacl: 'PRESENT' | 'NULL' | 'ABSENT' = 'PRESENT',
  daclProtected = true,
): string {
  const lines = [
    'AGENTBRIDGE-ACL-V2',
    `OWNER ${owner}`,
    `DACL ${dacl} ${daclProtected ? 'PROTECTED' : 'UNPROTECTED'}`,
    `ACES ${String(aces.length)}`,
  ];
  for (const ace of aces) {
    const flags = (ace.flags ?? 0).toString(16).toUpperCase().padStart(2, '0');
    lines.push(`ACE ${ace.type ?? 'ALLOW'} 0x${flags} 0x001F01FF ${ace.sid}`);
  }
  return lines.join('\n') + '\n';
}
const OWNER_SHA = 'a'.repeat(64);
const passingOwnerDeps: OwnerVerifierDeps = {
  loadProvenance: (): Promise<{ filename: string; sha256: string }> =>
    Promise.resolve({ filename: 'owner-helper', sha256: OWNER_SHA }),
  resolveHelperPath: (): string => 'C:\\Program\\owner-helper',
  readHelperBytes: (): Buffer => Buffer.from('helper-bytes'),
  hashBytes: (): string => OWNER_SHA,
};
/** A runner answering whoami and returning the given `--acl` snapshot for any path. */
function runnerFor(snapshotStdout: string, seen: string[] = []): ProcessRunner {
  return (exe: string, args: readonly string[]): Promise<ProcessResult> => {
    if (exe.toLowerCase().includes('whoami')) {
      return Promise.resolve({ ok: true, stdout: WHOAMI });
    }
    expect(args[0]).toBe('--acl');
    seen.push(args[1] ?? '');
    return Promise.resolve({ ok: true, stdout: snapshotStdout });
  };
}
/** The REAL descriptor ACL gate with an injected snapshot source. */
function realDescriptorGate(
  snapshotStdout: string,
  seen: string[] = [],
): (path: string) => Promise<DescriptorAclVerification> {
  return (path: string): Promise<DescriptorAclVerification> =>
    verifyDescriptorAcl(path, {
      systemRoot: 'C:\\Windows',
      runProcess: runnerFor(snapshotStdout, seen),
      owner: passingOwnerDeps,
    });
}
const GOOD_DESCRIPTOR_SNAPSHOT = snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]);

describe('D062 lifecycle v2 — descriptor verification fails closed (real evaluator, injected snapshot)', () => {
  /** Start with a live peer already published, so cleanup targeting is observable. */
  async function startWithPeer(
    gate: (path: string) => Promise<DescriptorAclVerification>,
  ): Promise<{ anchor: MemAnchor; peer: ControlChannelHandle; handle: ControlChannelHandle | null }> {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const peer = await startServer(orchestrator, anchor);
    handles.push(peer);
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: gate,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: realProbe,
      logger: silent,
    });
    return { anchor, peer, handle };
  }

  it('positive control: a protected operator+SYSTEM descriptor snapshot passes the real gate', async () => {
    const seen: string[] = [];
    const { anchor, peer, handle } = await startWithPeer(realDescriptorGate(GOOD_DESCRIPTOR_SNAPSHOT, seen));
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    // The helper was pointed at the exact identity-named file, nothing else.
    expect(seen).toEqual([handle.descriptorPath]);
    expect(filesIn(anchor)).toEqual(
      [descriptorFilenameFor(peer.runtimeId), descriptorFilenameFor(handle.runtimeId)].sort(),
    );
  });

  const rejected: readonly [string, string, string][] = [
    ['8. wrong owner', snapshot('S-1-5-21-9-9-9-2002', [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]), CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH],
    ['8b. SYSTEM owner', snapshot(SYSTEM_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }]), CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM],
    ['9. unprotected DACL', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }], 'PRESENT', false), CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED],
    ['9b. NULL DACL', snapshot(OPERATOR_SID, [], 'NULL'), CONTROL_ANCHOR_REJECTION.DACL_ABSENT],
    ['10. inherited ACE', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID, flags: 0x10 }, { sid: SYSTEM_SID }]), CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL],
    ['10b. foreign principal', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }, { sid: SYSTEM_SID }, { sid: 'S-1-1-0' }]), CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL],
    ['10c. SYSTEM absent (not creator-made)', snapshot(OPERATOR_SID, [{ sid: OPERATOR_SID }]), CONTROL_ANCHOR_REJECTION.SYSTEM_PRINCIPAL_ABSENT],
    ['10d. operator absent', snapshot(OPERATOR_SID, [{ sid: SYSTEM_SID }]), CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT],
    ['11a. malformed snapshot', 'garbage\n', CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED],
  ];

  it.each(rejected)('%s → no handle, own file removed, peer untouched, own pipe closed', async (_label, stdout) => {
    const seen: string[] = [];
    const { anchor, peer, handle } = await startWithPeer(realDescriptorGate(stdout, seen));
    expect(handle).toBeNull();
    // Two creations happened (the peer's, then ours) and exactly one removal (ours).
    expect(anchor.createCalls()).toBe(2);
    expect(seen).toHaveLength(1);
    const ownPath = seen[0] ?? '';
    expect(anchor.removeCalls()).toBe(1);
    // The peer survives, exactly as published; only our file is gone.
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(peer.runtimeId)]);
    expect(await realProbe(peer.pipePath)).toBe('PRESENT');
    // Our pipe is closed: the kernel no longer knows the name.
    const ownId = runtimeIdFromDescriptorFilename(ownPath.slice(FAKE_ANCHOR.length + 1)) ?? '';
    expect(ownId).not.toBe('');
    expect(await realProbe(pipePathFromName(pipeNameForRuntimeId(ownId)))).toBe('ABSENT');
  });

  it('a verification that THROWS is contained: own file removed, peer untouched', async () => {
    const { anchor, peer, handle } = await startWithPeer(
      (): Promise<DescriptorAclVerification> => Promise.reject(new Error('helper crashed')),
    );
    expect(handle).toBeNull();
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(peer.runtimeId)]);
  });

  it('11. a malformed / foreign-content descriptor read back after creation fails closed', async () => {
    const cases: readonly [string, (id: string, bytes: Buffer) => string][] = [
      ['not JSON', (): string => '{ not json'],
      ['different token', (id): string => serializeDescriptor({ version: 2, pipeName: pipeNameForRuntimeId(id), token: Buffer.alloc(32, 7).toString('base64url') })],
      ['different pipe name', (_id, bytes): string => {
        const parsed = JSON.parse(bytes.toString('utf8')) as { token: string };
        return serializeDescriptor({ version: 2, pipeName: pipeNameForRuntimeId('f'.repeat(32)), token: parsed.token });
      }],
      ['legacy v1 shape with pid', (_id, bytes): string => {
        const parsed = JSON.parse(bytes.toString('utf8')) as { pipeName: string; token: string };
        return JSON.stringify({ version: 1, pid: 4242, pipeName: parsed.pipeName, token: parsed.token });
      }],
    ];
    for (const [label, corrupt] of cases) {
      const { orchestrator } = newOrchestrator();
      const anchor = memAnchor();
      const peer = await startServer(orchestrator, anchor);
      handles.push(peer);
      // A creator that "succeeds" but leaves different bytes on disk.
      const create: DescriptorCreatorFn = async (dir, id, bytes) => {
        const result = await anchor.create(dir, id, bytes);
        anchor.set(id, corrupt(id, bytes));
        return result;
      };
      const handle = await startControlChannel({
        orchestrator,
        verify: passingVerify,
        verifyDescriptor: passingDescriptorVerify,
        descriptorDeps: anchor.deps,
        createDescriptor: create,
        probePipe: realProbe,
        logger: silent,
      });
      expect(handle, label).toBeNull();
      expect(filesIn(anchor), label).toEqual([descriptorFilenameFor(peer.runtimeId)]);
    }
  });
});

/* ---- readiness gate: the write path is inert until every trust gate passes ---- */

describe('D062 lifecycle v2 — dispatcher is inert until armed (control readiness)', () => {
  const OPEN_GATE: ControlCommand = { command: CONTROL_COMMAND.OPEN_HUMAN_GATE };

  /** Wrap the orchestrator so openHumanGate calls are counted (own-property shadow). */
  function countOpenHumanGate(orchestrator: ReturnType<typeof newOrchestrator>['orchestrator']): {
    count: () => number;
  } {
    let calls = 0;
    const real = orchestrator.openHumanGate.bind(orchestrator);
    orchestrator.openHumanGate = (): ReturnType<typeof real> => {
      calls += 1;
      return real();
    };
    return { count: (): number => calls };
  }

  /** A createServer that records the exact dispatcher the runtime armed the server with. */
  function capturingServer(sink: { dispatcher: ControlDispatcher | null }): typeof createControlChannelServer {
    return ((options) => {
      sink.dispatcher = options.dispatcher;
      return createControlChannelServer(options);
    }) as typeof createControlChannelServer;
  }

  it('1. the armed dispatcher returns UNAVAILABLE before verification and APPLIED only after it passes', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const gateCalls = countOpenHumanGate(orchestrator);
    const anchor = memAnchor();
    const sink: { dispatcher: ControlDispatcher | null } = { dispatcher: null };

    // Hold verification open so the captured gate can be observed mid-window.
    let releaseVerify: (v: DescriptorAclVerification) => void = () => {};
    let reachedResolve: () => void = () => {};
    const reached = new Promise<void>((resolvePromise) => {
      reachedResolve = resolvePromise;
    });
    const verifyDescriptor = (): Promise<DescriptorAclVerification> => {
      reachedResolve();
      return new Promise<DescriptorAclVerification>((resolvePromise) => {
        releaseVerify = resolvePromise;
      });
    };

    const startPromise = startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      createServer: capturingServer(sink),
      probePipe: realProbe,
      logger: silent,
    });
    await reached; // descriptor published, pipe listening, verification pending

    expect(sink.dispatcher).not.toBeNull();
    // Pre-ready: the gate is inert and the orchestrator is never touched.
    expect(sink.dispatcher?.dispatch(OPEN_GATE)).toBe(CONTROL_RESULT.UNAVAILABLE);
    expect(gateCalls.count()).toBe(0);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);

    // Verification succeeds → startup arms the SAME dispatcher object.
    releaseVerify({ ok: true });
    const handle = await startPromise;
    expect(handle).not.toBeNull();
    handles.push(handle as ControlChannelHandle);

    expect(sink.dispatcher?.dispatch(OPEN_GATE)).toBe(CONTROL_RESULT.APPLIED);
    expect(gateCalls.count()).toBe(1);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
  });

  it('2. a failed descriptor ACL verification never arms the write path', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const gateCalls = countOpenHumanGate(orchestrator);
    const anchor = memAnchor();
    const sink: { dispatcher: ControlDispatcher | null } = { dispatcher: null };

    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (): Promise<DescriptorAclVerification> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED }),
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      createServer: capturingServer(sink),
      probePipe: realProbe,
      logger: silent,
    });

    expect(handle).toBeNull();
    expect(sink.dispatcher).not.toBeNull();
    expect(sink.dispatcher?.dispatch(OPEN_GATE)).toBe(CONTROL_RESULT.UNAVAILABLE);
    expect(gateCalls.count()).toBe(0);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('3. a failed descriptor read-back never arms the write path', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const gateCalls = countOpenHumanGate(orchestrator);
    const anchor = memAnchor();
    const sink: { dispatcher: ControlDispatcher | null } = { dispatcher: null };
    // Creator "succeeds" but leaves foreign bytes, so the read-back check fails.
    const create: DescriptorCreatorFn = async (dir, id, bytes) => {
      const result = await anchor.create(dir, id, bytes);
      anchor.set(id, '{ not a valid descriptor');
      return result;
    };

    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: create,
      createServer: capturingServer(sink),
      probePipe: realProbe,
      logger: silent,
    });

    expect(handle).toBeNull();
    expect(sink.dispatcher?.dispatch(OPEN_GATE)).toBe(CONTROL_RESULT.UNAVAILABLE);
    expect(gateCalls.count()).toBe(0);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('negative control: the eager real dispatcher WOULD apply mid-window — the gate assertions have teeth', () => {
    // This proves the readiness tests above are not tautological: the ONLY thing
    // standing between an in-window command and a real state change is the gate.
    // The old eager wiring attached exactly this dispatcher before verification.
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const eager = createControlDispatcher(orchestrator);
    expect(eager.dispatch(OPEN_GATE)).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
  });
});

/* ---- creation failures -------------------------------------------------------- */

describe('D062 lifecycle v2 — creation failures after listen', () => {
  const causes = [
    DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_MISSING,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_HASH_MISMATCH,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
  ] as const;

  it.each(causes)('%s → no handle, nothing removed, pipe closed', async (reason) => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const peer = await startServer(orchestrator, anchor);
    handles.push(peer);
    let ownPipe = '';
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: (_dir, id) => {
        ownPipe = pipePathFromName(pipeNameForRuntimeId(id));
        return Promise.resolve({ ok: false, reason });
      },
      probePipe: realProbe,
      logger: silent,
    });
    expect(handle).toBeNull();
    // Nothing was created by us, so nothing is removed — the peer is untouched.
    expect(anchor.removeCalls()).toBe(0);
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(peer.runtimeId)]);
    expect(await realProbe(ownPipe)).toBe('ABSENT');
    expect(await realProbe(peer.pipePath)).toBe('PRESENT');
  });

  it('a creator that throws is contained; the channel disables, nothing propagates', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: () => Promise.reject(new Error('boom')),
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(filesIn(anchor)).toEqual([]);
  });

  it('the creator receives exactly [anchor, runtimeId] and the descriptor bytes; the token is never an argument', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const calls: { dir: string; id: string; bytes: Buffer }[] = [];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: (dir, id, bytes) => {
        calls.push({ dir, id, bytes });
        return anchor.create(dir, id, bytes);
      },
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.dir).toBe(FAKE_ANCHOR);
    expect(call?.id).toBe(handle.runtimeId);
    const parsed = parseDescriptor(call?.bytes.toString('utf8'));
    expect(parsed?.runtimeId).toBe(handle.runtimeId);
    // The token appears in the payload only — never in the id or the anchor argument.
    expect(call?.id).not.toContain(parsed?.descriptor.token ?? 'x');
    expect(call?.dir).not.toContain(parsed?.descriptor.token ?? 'x');
  });
});

/* ---- 12–14, 17: cleanup targeting -------------------------------------------- */

describe('D062 lifecycle v2 — cleanup removes only the runtime\'s own identity-named file', () => {
  it('13/14. A.close() removes only A; B stays published and live; B.close() removes B', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const a = await startServer(orchestrator, anchor);
    const b = await startServer(orchestrator, anchor);
    handles.push(b);
    const bText = anchor.get(b.runtimeId);

    await a.close();
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(b.runtimeId)]);
    expect(anchor.get(b.runtimeId)).toBe(bText);
    expect(await realProbe(b.pipePath)).toBe('PRESENT');
    expect(await realProbe(a.pipePath)).toBe('ABSENT');

    handles.splice(handles.indexOf(b), 1);
    await b.close();
    expect(filesIn(anchor)).toEqual([]);
  });

  it('12. own startup failure after publication removes only the own file', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const peer = await startServer(orchestrator, anchor);
    handles.push(peer);
    const removedPaths: string[] = [];
    const deps = {
      ...anchor.deps,
      removeFile: (path: string): void => {
        removedPaths.push(path);
        anchor.deps.removeFile?.(path);
      },
    };
    let ownId = '';
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (): Promise<DescriptorAclVerification> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED }),
      descriptorDeps: deps,
      createDescriptor: (dir, id, bytes) => {
        ownId = id;
        return anchor.create(dir, id, bytes);
      },
      probePipe: realProbe,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(removedPaths).toEqual([descriptorPathFor(FAKE_ANCHOR, ownId)]);
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(peer.runtimeId)]);
  });

  it('close() with its own file already gone is harmless and never touches another file', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const peer = await startServer(orchestrator, anchor);
    handles.push(peer);
    const handle = await startServer(orchestrator, anchor);
    anchor.remove(handle.runtimeId);
    const before = anchor.removeCalls();
    await handle.close();
    // One attempted unlink of its own exact path (ENOENT, swallowed); the peer intact.
    expect(anchor.removeCalls()).toBe(before + 1);
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(peer.runtimeId)]);
  });

  it('a malformed file under a runtime\'s own name is still only that runtime\'s file to remove', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const peer = await startServer(orchestrator, anchor);
    handles.push(peer);
    const handle = await startServer(orchestrator, anchor);
    anchor.set(handle.runtimeId, '{ tampered');
    await handle.close();
    expect(filesIn(anchor)).toEqual([descriptorFilenameFor(peer.runtimeId)]);
  });
});

/* ---- 15–18: stale sweep, PID irrelevance, deterministic multi-file handling ---- */

describe('D062 lifecycle v2 — startup sweep of foreign descriptors', () => {
  it('16/18. dead (ABSENT) foreign files are removed; PRESENT, UNKNOWN, malformed, and mismatched files are kept', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const dead = foreignDescriptor();
    const live = foreignDescriptor();
    const unknown = foreignDescriptor();
    const mismatch = foreignDescriptor();
    anchor.set(dead.runtimeId, dead.text);
    anchor.set(live.runtimeId, live.text);
    anchor.set(unknown.runtimeId, unknown.text);
    // Name says one id, contents name another live pipe: malformed, never removed.
    anchor.set(mismatch.runtimeId, live.text);
    anchor.setRaw('runtime-descriptor-' + 'g'.repeat(32) + '.json', dead.text); // not a candidate
    anchor.setRaw('runtime-descriptor.json', dead.text); // the abandoned fixed name: not a candidate
    anchor.setRaw('runtime-descriptor-' + 'a'.repeat(32) + '.json', '{ not json');
    const probe = tableProbe({ [dead.pipePath]: 'ABSENT', [live.pipePath]: 'PRESENT', [unknown.pipePath]: 'UNKNOWN' });

    const handle = await startServer(orchestrator, anchor, { probePipe: probe });
    handles.push(handle);

    const remaining = filesIn(anchor);
    expect(remaining).not.toContain(descriptorFilenameFor(dead.runtimeId));
    expect(remaining).toContain(descriptorFilenameFor(live.runtimeId));
    expect(remaining).toContain(descriptorFilenameFor(unknown.runtimeId));
    expect(remaining).toContain(descriptorFilenameFor(mismatch.runtimeId));
    expect(remaining).toContain('runtime-descriptor-' + 'g'.repeat(32) + '.json');
    expect(remaining).toContain('runtime-descriptor.json');
    expect(remaining).toContain('runtime-descriptor-' + 'a'.repeat(32) + '.json');
    expect(remaining).toContain(descriptorFilenameFor(handle.runtimeId));
    // Exactly one unlink happened, for the dead file.
    expect(anchor.removeCalls()).toBe(1);
  });

  it('17. PID reuse cannot affect cleanup: descriptors carry no PID and the decision is the pipe probe alone', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const dead = foreignDescriptor();
    expect(Object.keys(JSON.parse(dead.text) as object)).toEqual(['version', 'pipeName', 'token']);
    // A descriptor claiming THIS live process's pid (legacy shape) is malformed, not a liveness claim.
    const legacy = JSON.stringify({ version: 1, pid: process.pid, pipeName: pipeNameForRuntimeId('b'.repeat(32)), token: Buffer.alloc(32, 1).toString('base64url') });
    anchor.set(dead.runtimeId, dead.text);
    anchor.set('b'.repeat(32), legacy);
    const probed: string[] = [];
    const probe: PipeProbe = (path) => {
      probed.push(path);
      return Promise.resolve('ABSENT');
    };
    const handle = await startServer(orchestrator, anchor, { probePipe: probe });
    handles.push(handle);
    // The dead file was removed purely because its PIPE was absent …
    expect(probed).toEqual([dead.pipePath]);
    expect(anchor.get(dead.runtimeId)).toBeNull();
    // … and the legacy pid-bearing file was never probed nor removed.
    expect(anchor.get('b'.repeat(32))).toBe(legacy);
  });

  it('an unreadable anchor enumeration fails startup closed before listen or publish', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const deps = { ...anchor.deps, listAnchor: (): readonly string[] => { throw new Error('EACCES'); } };
    let serverCreated = false;
    let created = 0;
    const createServer: typeof createControlChannelServer = ((options) => {
      serverCreated = true;
      return createControlChannelServer(options);
    }) as typeof createControlChannelServer;
    const create: DescriptorCreatorFn = async (dir, id, bytes) => {
      created += 1;
      return anchor.create(dir, id, bytes);
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: deps,
      createDescriptor: create,
      createServer,
      probePipe: allAbsentProbe,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(serverCreated).toBe(false); // never reached the server / listen
    expect(created).toBe(0); // never published a descriptor
    expect(anchor.removeCalls()).toBe(0);
    expect(filesIn(anchor)).toEqual([]);
  });

  it('a truncated candidate enumeration (> cap) fails startup closed before listen or publish', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    for (let index = 0; index < MAX_DESCRIPTOR_CANDIDATES + 1; index += 1) {
      const id = index.toString(16).padStart(32, '0');
      anchor.set(
        id,
        serializeDescriptor({
          version: 2,
          pipeName: pipeNameForRuntimeId(id),
          token: Buffer.alloc(32, index % 251).toString('base64url'),
        }),
      );
    }
    const before = filesIn(anchor).length;
    let serverCreated = false;
    let created = 0;
    const createServer: typeof createControlChannelServer = ((options) => {
      serverCreated = true;
      return createControlChannelServer(options);
    }) as typeof createControlChannelServer;
    const create: DescriptorCreatorFn = async (dir, id, bytes) => {
      created += 1;
      return anchor.create(dir, id, bytes);
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: create,
      createServer,
      probePipe: allAbsentProbe,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(serverCreated).toBe(false);
    expect(created).toBe(0);
    expect(anchor.removeCalls()).toBe(0);
    expect(filesIn(anchor).length).toBe(before); // nothing published, nothing removed
  });

  it('a readable EMPTY anchor is complete → startup proceeds and publishes', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: allAbsentProbe,
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
      expect(anchor.get(handle.runtimeId)).not.toBeNull();
    }
  });

  it('a readable within-cap anchor is complete → the sweep runs and startup proceeds', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const dead = foreignDescriptor();
    anchor.set(dead.runtimeId, dead.text);
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: allAbsentProbe, // the seeded foreign file's pipe is ABSENT
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
    }
    expect(anchor.removeCalls()).toBe(1); // the dead file was swept as before
    expect(anchor.get(dead.runtimeId)).toBeNull();
  });

  /** Seed `count` valid identity-named descriptors; return their pipe paths. */
  function seedSurvivors(anchor: MemAnchor, count: number): string[] {
    const pipePaths: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const minted = createRuntimeDescriptor();
      anchor.set(minted.runtimeId, serializeDescriptor(minted.descriptor));
      pipePaths.push(pipePathFromName(minted.descriptor.pipeName));
    }
    return pipePaths;
  }

  it('FINDING 1 — exactly MAX surviving descriptors leaves no slot: startup fails closed before listen/publish', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    seedSurvivors(anchor, MAX_DESCRIPTOR_CANDIDATES);
    const before = filesIn(anchor).length;
    let serverCreated = false;
    let created = 0;
    const createServer: typeof createControlChannelServer = ((options) => {
      serverCreated = true;
      return createControlChannelServer(options);
    }) as typeof createControlChannelServer;
    const create: DescriptorCreatorFn = async (dir, id, bytes) => {
      created += 1;
      return anchor.create(dir, id, bytes);
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: create,
      createServer,
      probePipe: () => Promise.resolve('UNKNOWN'), // every survivor is retained, none removed
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(serverCreated).toBe(false); // never reached the server / listen
    expect(created).toBe(0); // never published our own descriptor
    expect(before).toBe(MAX_DESCRIPTOR_CANDIDATES);
    expect(filesIn(anchor).length).toBe(before); // still exactly MAX; nothing published
  });

  it('FINDING 1 — MAX-1 survivors leaves one slot: startup proceeds and publishes to MAX total', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    seedSurvivors(anchor, MAX_DESCRIPTOR_CANDIDATES - 1);
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: () => Promise.resolve('UNKNOWN'),
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
      expect(anchor.get(handle.runtimeId)).not.toBeNull(); // own descriptor published
    }
    expect(filesIn(anchor).length).toBe(MAX_DESCRIPTOR_CANDIDATES); // (MAX-1) survivors + own = MAX
  });

  it('FINDING 1 — a removable ABSENT descriptor frees a slot: startup proceeds, republishing to MAX', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const pipePaths = seedSurvivors(anchor, MAX_DESCRIPTOR_CANDIDATES);
    const deadPipe = pipePaths[0];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: (path) => Promise.resolve(path === deadPipe ? 'ABSENT' : 'UNKNOWN'),
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
    }
    expect(anchor.removeCalls()).toBe(1); // one proven-ABSENT descriptor removed
    expect(filesIn(anchor).length).toBe(MAX_DESCRIPTOR_CANDIDATES); // (MAX-1 remaining) + own = MAX
  });

  it('FINDING 2 — an over-full anchor fails startup closed before listen or publish', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const huge = MAX_ANCHOR_ENTRIES * 100;
    function* names(): IterableIterator<string> {
      for (let index = 0; index < huge; index += 1) {
        yield `junk-${String(index)}`;
      }
    }
    const deps = { ...anchor.deps, listAnchor: () => names() };
    let serverCreated = false;
    let created = 0;
    const createServer: typeof createControlChannelServer = ((options) => {
      serverCreated = true;
      return createControlChannelServer(options);
    }) as typeof createControlChannelServer;
    const create: DescriptorCreatorFn = async (dir, id, bytes) => {
      created += 1;
      return anchor.create(dir, id, bytes);
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: deps,
      createDescriptor: create,
      createServer,
      probePipe: allAbsentProbe,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(serverCreated).toBe(false);
    expect(created).toBe(0);
  });

  /**
   * The coherence oracle: after an admitted startup, official discovery over the
   * post-publication anchor must find this runtime WITHOUT failing over-full.
   */
  async function expectDiscoverableNotOverfull(deps: MemAnchor['deps'], runtimeId: string): Promise<void> {
    const discovery = await discoverControlRuntime(FAKE_ANCHOR, realProbe, deps);
    expect(discovery.kind).toBe('FOUND');
    if (discovery.kind === 'FOUND') {
      expect(discovery.parsed.runtimeId).toBe(runtimeId);
    }
  }

  it('FINDING 2 — exactly MAX_ANCHOR_ENTRIES entries leaves no entry slot: startup fails closed before listen/publish', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    for (let index = 0; index < MAX_ANCHOR_ENTRIES; index += 1) {
      anchor.setRaw(`junk-${String(index)}.txt`, 'x');
    }
    let serverCreated = false;
    let created = 0;
    const createServer: typeof createControlChannelServer = ((options) => {
      serverCreated = true;
      return createControlChannelServer(options);
    }) as typeof createControlChannelServer;
    const create: DescriptorCreatorFn = async (dir, id, bytes) => {
      created += 1;
      return anchor.create(dir, id, bytes);
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: create,
      createServer,
      probePipe: allAbsentProbe,
      logger: silent,
    });
    expect(handle).toBeNull();
    expect(serverCreated).toBe(false); // never reached the server / listen
    expect(created).toBe(0); // nothing published
    expect(anchor.entries().size).toBe(MAX_ANCHOR_ENTRIES); // still exactly the cap
  });

  it('FINDING 2 — MAX_ANCHOR_ENTRIES-1 entries leaves one entry slot: startup proceeds to exactly MAX and stays discoverable', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    for (let index = 0; index < MAX_ANCHOR_ENTRIES - 1; index += 1) {
      anchor.setRaw(`junk-${String(index)}.txt`, 'x');
    }
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: allAbsentProbe,
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
      expect(anchor.entries().size).toBe(MAX_ANCHOR_ENTRIES); // (MAX-1 junk) + own = MAX
      await expectDiscoverableNotOverfull(anchor.deps, handle.runtimeId);
    }
  });

  it('FINDING 2 — a removable ABSENT descriptor frees entry room: startup proceeds to exactly MAX and stays discoverable', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    for (let index = 0; index < MAX_ANCHOR_ENTRIES - 1; index += 1) {
      anchor.setRaw(`junk-${String(index)}.txt`, 'x');
    }
    const dead = foreignDescriptor(); // valid foreign descriptor; +1 → exactly MAX total
    anchor.set(dead.runtimeId, dead.text);
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      probePipe: (path) => Promise.resolve(path === dead.pipePath ? 'ABSENT' : 'ABSENT'),
      logger: silent,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
      expect(anchor.removeCalls()).toBe(1); // the ABSENT foreign descriptor was removed
      expect(anchor.entries().size).toBe(MAX_ANCHOR_ENTRIES); // (MAX-1 junk) + own = MAX
      await expectDiscoverableNotOverfull(anchor.deps, handle.runtimeId);
    }
  });

  it('a stale file whose unlink fails is reported, not fatal; startup still succeeds', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const dead = foreignDescriptor();
    anchor.set(dead.runtimeId, dead.text);
    const logs: string[] = [];
    const deps = { ...anchor.deps, removeFile: (): void => { throw new Error('EACCES'); } };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: deps,
      createDescriptor: anchor.create,
      probePipe: allAbsentProbe,
      logger: (message): void => {
        logs.push(message);
      },
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
    }
    expect(anchor.get(dead.runtimeId)).toBe(dead.text);
    expect(logs.some((line) => line.includes('could not remove 1'))).toBe(true);
    // No token-shaped run of base64url characters ever reaches a log line.
    expect(logs.join('\n')).not.toMatch(/[A-Za-z0-9_-]{43}/);
  });
});

/* ---- 15/16: a crashed runtime — real kernel pipe semantics (Windows) ---------- */

/** Spawn a child node process that listens on `pipePath` and stays alive until killed. */
function spawnPipeHolder(pipePath: string): Promise<ChildProcess> {
  const dir = mkdtempSync(join(tmpdir(), 'ab-pipe-holder-'));
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
    child.once('exit', () => {
      rmSync(dir, { recursive: true, force: true });
    });
    child.stdout.once('data', () => {
      resolvePromise(child);
    });
    child.once('error', rejectPromise);
  });
}

describe.skipIf(process.platform !== 'win32')('D062 lifecycle v2 — crashed runtime (real kernel pipe namespace)', () => {
  it('15/16. a crashed runtime leaves its descriptor but its pipe disappears; the next runtime identifies and removes it', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const crashed = foreignDescriptor();
    anchor.set(crashed.runtimeId, crashed.text);

    const holder = await spawnPipeHolder(crashed.pipePath);
    expect(await realProbe(crashed.pipePath)).toBe('PRESENT');

    // While "alive", a new runtime keeps the peer file.
    const first = await startServer(orchestrator, anchor, { probePipe: realProbe });
    handles.push(first);
    expect(anchor.get(crashed.runtimeId)).toBe(crashed.text);

    // Crash: SIGKILL, no cleanup. The descriptor stays; the kernel drops the pipe.
    holder.kill('SIGKILL');
    await new Promise<void>((resolvePromise) => {
      holder.once('exit', () => {
        resolvePromise();
      });
    });
    expect(anchor.get(crashed.runtimeId)).toBe(crashed.text);
    expect(await realProbe(crashed.pipePath)).toBe('ABSENT');

    // The next runtime proves it dead by the pipe alone and removes exactly that file.
    const next = await startServer(orchestrator, anchor, { probePipe: realProbe });
    handles.push(next);
    expect(anchor.get(crashed.runtimeId)).toBeNull();
    expect(filesIn(anchor)).toEqual(
      [descriptorFilenameFor(first.runtimeId), descriptorFilenameFor(next.runtimeId)].sort(),
    );
  }, 20000);

  it('a live pipe that speaks no protocol is NOT treated as dead (no handshake-failure deletion)', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const squatter = foreignDescriptor();
    anchor.set(squatter.runtimeId, squatter.text);
    servers.push(await startSilentServer(squatter.pipePath));

    const handle = await startServer(orchestrator, anchor, { probePipe: realProbe });
    handles.push(handle);
    expect(anchor.get(squatter.runtimeId)).toBe(squatter.text);
  });
});

/* ---- Negative controls: the abandoned fixed-path lifecycle violates these properties -- */

/**
 * A minimal in-test reconstruction of the PR #84 fixed-path lifecycle: one shared
 * `runtime-descriptor.json`, written BEFORE listen, rotated (overwritten) by every
 * starter, and removed on close only while it still names the closer's pipe. It
 * exists only to show that the properties proven above DISCRIMINATE — they fail
 * against the old design — using scratch seams, never tracked production code.
 */
async function legacyFixedPathStart(
  anchor: MemAnchor,
  listenSucceeds: boolean,
): Promise<{ pipeName: string; close: () => Promise<void> } | null> {
  const minted = createRuntimeDescriptor();
  const legacyText = JSON.stringify({ version: 1, pid: process.pid, pipeName: minted.descriptor.pipeName, token: minted.descriptor.token });
  // Rotate then write — BEFORE the pipe exists.
  anchor.setRaw('runtime-descriptor.json', legacyText);
  if (!listenSucceeds) {
    return null; // the legacy code removed its own descriptor only if it still matched
  }
  const server = net.createServer();
  servers.push(server);
  await new Promise<void>((resolvePromise) => {
    server.listen(pipePathFromName(minted.descriptor.pipeName), resolvePromise);
  });
  return {
    pipeName: minted.descriptor.pipeName,
    close: async (): Promise<void> => {
      const current = anchor.entries().get('runtime-descriptor.json');
      if (current !== undefined && (JSON.parse(current) as { pipeName: string }).pipeName === minted.descriptor.pipeName) {
        anchor.setRaw('runtime-descriptor.json', '');
      }
      await closeServer(server);
    },
  };
}

describe('D062 lifecycle v2 — negative controls against the reconstructed fixed-path lifecycle', () => {
  it('NC-2/3. the legacy design publishes BEFORE listening (a listen failure still left a descriptor)', async () => {
    const anchor = memAnchor();
    const result = await legacyFixedPathStart(anchor, false);
    expect(result).toBeNull();
    // Property 3 ("failed listen publishes nothing") is VIOLATED by the legacy model:
    expect(anchor.entries().has('runtime-descriptor.json')).toBe(true);
    // … and it is HELD by the new lifecycle (proven in test 3 above).
  });

  it('NC-14. the legacy design lets a second starter overwrite a live peer (last-writer-wins)', async () => {
    const anchor = memAnchor();
    const a = await legacyFixedPathStart(anchor, true);
    const b = await legacyFixedPathStart(anchor, true);
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    if (a === null || b === null) {
      return;
    }
    const current = anchor.entries().get('runtime-descriptor.json') ?? '';
    // A is live, yet no descriptor identifies it: CONTROL_START_SUCCESS ⇏ DISCOVERABLE.
    expect(await realProbe(pipePathFromName(a.pipeName))).toBe('PRESENT');
    expect(current).not.toContain(a.pipeName);
    expect(current).toContain(b.pipeName);
    await a.close();
    await b.close();
  });

  it('NC-1. the legacy fixed name is not an identity-named candidate and can never be discovered or swept', () => {
    expect(runtimeIdFromDescriptorFilename('runtime-descriptor.json')).toBeNull();
  });
});
