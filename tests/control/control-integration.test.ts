/**
 * D062 control channel end to end via the official CLI, over REAL named pipes,
 * with discovery over the identity-named descriptor anchor (lifecycle v2).
 *
 * Discovery properties proven here (19–23): zero live candidates ⇒ unavailable;
 * exactly one live candidate ⇒ discoverable and the command is applied; two or
 * more live candidates ⇒ ambiguous, fail closed, NO command dispatched; a stale
 * (dead-pipe) candidate beside a live one never blocks and is never chosen; a
 * malformed candidate beside a live one never blocks; the CLI never deletes.
 */

import net from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { WORKFLOW_STATUS } from '../../src/domain/index.js';
import { CONTROL_ANCHOR_REJECTION } from '../../src/control/control-store.js';
import { CONTROL_RESULT } from '../../src/control/control-command.js';
import {
  startControlChannel,
  type ControlChannelHandle,
} from '../../src/control/control-runtime.js';
import {
  MAX_DESCRIPTOR_CANDIDATES,
  anchorSecretPathFor,
  createRuntimeDescriptor,
  descriptorFilenameFor,
  descriptorPathFor,
  pipeNameForRuntimeId,
  pipePathFromName,
  serializeDescriptor,
  type DescriptorAclVerification,
  type DescriptorFileDeps,
} from '../../src/control/control-store.js';
import {
  BINDING,
  callCli,
  closeServer,
  descriptorFacts,
  memAnchor,
  mintBound,
  newOrchestrator,
  passingVerify,
  startRogueServer,
  startServer,
  withTamperedToken,
  type MemAnchor,
} from './support.js';

const handles: ControlChannelHandle[] = [];
const rogues: net.Server[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
  await Promise.all(rogues.splice(0).map((server) => closeServer(server)));
});

/** Seed a valid descriptor whose runtime never existed (its pipe is ABSENT). */
function seedStale(anchor: MemAnchor): string {
  const minted = createRuntimeDescriptor();
  anchor.set(minted.runtimeId, serializeDescriptor(minted.descriptor));
  return minted.runtimeId;
}

describe('D062 control channel — end-to-end via the official CLI', () => {
  it('20. OPEN_HUMAN_GATE on an open workflow → APPLIED, progressing the real orchestrator', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    handles.push(await startServer(orchestrator, anchor));

    const run = await callCli(anchor);
    expect(run.outcome.authenticated).toBe(true);
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(run.outcome.exitCode).toBe(0);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(true);
  });

  it('no workflow → NO_WORKFLOW, and no workflow is manufactured', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    handles.push(await startServer(orchestrator, anchor));

    const run = await callCli(anchor);
    expect(run.outcome.authenticated).toBe(true);
    expect(run.outcome.status).toBe(CONTROL_RESULT.NO_WORKFLOW);
    expect(run.outcome.exitCode).toBe(1);
    expect(runtime.current()).toBeNull();
  });

  it('a duplicate open → GATE_ALREADY_OPEN, state unchanged', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    handles.push(await startServer(orchestrator, anchor));

    const first = await callCli(anchor);
    expect(first.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    const gated = runtime.current();
    const second = await callCli(anchor);
    expect(second.outcome.status).toBe(CONTROL_RESULT.GATE_ALREADY_OPEN);
    expect(runtime.current()).toBe(gated);
  });

  it('repeated connections are served cleanly (no leaked server state)', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    handles.push(await startServer(orchestrator, anchor));

    for (let index = 0; index < 3; index += 1) {
      const run = await callCli(anchor);
      expect(run.outcome.authenticated).toBe(true);
      expect(run.outcome.status).toBe(CONTROL_RESULT.NO_WORKFLOW);
    }
  });

  it('a wrong client token → server rejects; the CLI never reports APPLIED; state unchanged', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    handles.push(handle);

    // A second anchor view holding the same identity-named file with a tampered token.
    const tampered = memAnchor();
    tampered.set(handle.runtimeId, withTamperedToken(anchor.get(handle.runtimeId) ?? ''));
    const run = await callCli(anchor, { descriptorDeps: tampered.deps });

    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
    // Domain state must be untouched by a rejected control attempt.
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('a rogue server returning APPLIED with a bad server MAC → the CLI refuses to trust it', async () => {
    const anchor = memAnchor();
    const { orchestrator } = newOrchestrator();
    const handle = await startServer(orchestrator, anchor);
    const facts = descriptorFacts(anchor, handle);
    // Preserve the descriptor the CLI will trust before stopping the genuine
    // server (close() removes it), so the CLI still holds the correct token.
    const preserved = memAnchor();
    preserved.set(handle.runtimeId, anchor.get(handle.runtimeId) ?? '');
    // Stop the genuine server so the rogue can claim the pipe name.
    await handle.close();
    const rogue = await startRogueServer(facts.pipePath, CONTROL_RESULT.APPLIED);
    rogues.push(rogue);

    const run = await callCli(anchor, { descriptorDeps: preserved.deps });
    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
    expect(run.err.some((line) => line.toLowerCase().includes('authentication'))).toBe(true);
  });
});

describe('D062 discovery — identity-named candidates over real pipes (19–23)', () => {
  it('19. no descriptor at all → unavailable (NO_CANDIDATES)', async () => {
    const anchor = memAnchor(); // empty
    const run = await callCli(anchor);
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('NO_CANDIDATES'))).toBe(true);
  });

  it('19b. only a stale descriptor (dead pipe) → unavailable, and the CLI never deletes it', async () => {
    const anchor = memAnchor();
    const stale = seedStale(anchor);
    const run = await callCli(anchor);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('NO_LIVE_CANDIDATES'))).toBe(true);
    expect(anchor.get(stale)).not.toBeNull();
    expect(anchor.removeCalls()).toBe(0);
  });

  it('19c. only malformed descriptors → unavailable', async () => {
    const anchor = memAnchor();
    anchor.setRaw(descriptorFilenameFor('c'.repeat(32)), '{ not a valid descriptor');
    anchor.setRaw('runtime-descriptor.json', '{}');
    const run = await callCli(anchor);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('NO_LIVE_CANDIDATES'))).toBe(true);
  });

  it('21. two live authenticating runtimes → ambiguous, fail closed, NO command dispatched to either', async () => {
    const first = newOrchestrator();
    const second = newOrchestrator();
    first.orchestrator.open(BINDING);
    second.orchestrator.open(BINDING);
    const anchor = memAnchor();
    handles.push(await startServer(first.orchestrator, anchor));
    handles.push(await startServer(second.orchestrator, anchor));

    const run = await callCli(anchor);
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.outcome.authenticated).toBe(false);
    expect(run.err.some((line) => line.includes('ambiguous') && line.includes('2 live'))).toBe(true);
    // Neither runtime received the command.
    expect(first.runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
    expect(second.runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
    expect(anchor.removeCalls()).toBe(0);
  });

  it('22. stale + live mixed set → only the live authenticating runtime is chosen', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const staleA = seedStale(anchor);
    const handle = await startServer(orchestrator, anchor, { probePipe: () => Promise.resolve('PRESENT') });
    handles.push(handle);
    const staleB = seedStale(anchor);
    // Both stale files survive (the runtime's sweep was told everything is PRESENT).
    expect(anchor.get(staleA)).not.toBeNull();
    expect(anchor.get(staleB)).not.toBeNull();

    const run = await callCli(anchor);
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    // The CLI only reads: stale files are left for the runtime's sweep.
    expect(anchor.get(staleA)).not.toBeNull();
    expect(anchor.get(staleB)).not.toBeNull();
    expect(anchor.removeCalls()).toBe(0);
  });

  it('23. malformed + live mixed set → the live runtime is discovered; malformed never blocks', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    handles.push(handle);
    anchor.setRaw(descriptorFilenameFor('0'.repeat(32)), '{ not json');
    anchor.setRaw(descriptorFilenameFor('1'.repeat(32)), JSON.stringify({ version: 1, pid: 1, pipeName: handle.pipeName, token: 'x' }));
    // Name/content mismatch that points at the LIVE pipe: malformed, never a second live vote.
    anchor.setRaw(descriptorFilenameFor('2'.repeat(32)), anchor.get(handle.runtimeId) ?? '');
    anchor.setRaw('runtime-descriptor.json', anchor.get(handle.runtimeId) ?? '');

    const run = await callCli(anchor);
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
  });

  it('a descriptor whose pipe name does not match any listener → unavailable (no APPLIED)', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    handles.push(handle);
    // Point the CLI at a valid-shaped descriptor whose pipe nobody serves.
    const other = memAnchor();
    const minted = createRuntimeDescriptor();
    other.set(minted.runtimeId, serializeDescriptor(minted.descriptor));
    const run = await callCli(anchor, { descriptorDeps: other.deps, timeoutMs: 1000 });
    expect(run.outcome.status).toBeNull();
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
  });

  it('an anomalous anchor with more than the bounded candidate cap → unavailable (fail closed)', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    handles.push(await startServer(orchestrator, anchor));
    for (let index = 0; index < MAX_DESCRIPTOR_CANDIDATES; index += 1) {
      const id = index.toString(16).padStart(32, '0');
      anchor.set(id, serializeDescriptor({ version: 2, pipeName: pipeNameForRuntimeId(id), token: 'x' }));
    }
    const run = await callCli(anchor);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('TOO_MANY_CANDIDATES'))).toBe(true);
  });

  it('handle.close() removes only its own descriptor and stops the listener; discovery then finds nothing', async () => {
    const { orchestrator } = newOrchestrator();
    const anchor = memAnchor();
    const handle = await startServer(orchestrator, anchor);
    expect(anchor.get(handle.runtimeId)).not.toBeNull();
    await handle.close();
    expect(anchor.get(handle.runtimeId)).toBeNull();
    // The pipe is gone as well.
    const probe = await new Promise<string>((resolvePromise) => {
      const socket = net.connect(pipePathFromName(handle.pipeName));
      socket.on('connect', () => {
        socket.destroy();
        resolvePromise('PRESENT');
      });
      socket.on('error', (error: NodeJS.ErrnoException) => {
        resolvePromise(error.code ?? 'ERR');
      });
    });
    expect(probe).toBe('ENOENT');
    const run = await callCli(anchor);
    expect(run.outcome.status).toBeNull();
    expect(run.err.some((line) => line.includes('NO_CANDIDATES'))).toBe(true);
  });
});

describe('D062 control channel — the write path is inert during the verification window', () => {
  /**
   * Start the channel but pause inside descriptor verification, so the descriptor
   * is already published and the pipe is already live while the runtime is still
   * proving the file. `reached` resolves once verification is pending; `release`
   * completes it with the given verdict.
   */
  function startWithHeldVerification(
    orchestrator: ReturnType<typeof newOrchestrator>['orchestrator'],
    anchor: MemAnchor,
  ): {
    handlePromise: Promise<ControlChannelHandle | null>;
    reached: Promise<void>;
    release: (verdict: DescriptorAclVerification) => void;
  } {
    let release: (verdict: DescriptorAclVerification) => void = () => {};
    let reachedResolve: () => void = () => {};
    const reached = new Promise<void>((resolvePromise) => {
      reachedResolve = resolvePromise;
    });
    const verifyDescriptor = (): Promise<DescriptorAclVerification> => {
      reachedResolve();
      return new Promise<DescriptorAclVerification>((resolvePromise) => {
        release = resolvePromise;
      });
    };
    const handlePromise = startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor,
      descriptorDeps: anchor.deps,
      createDescriptor: anchor.create,
      logger: (): void => {
        /* silent */
      },
    });
    // `release` is reassigned when verifyDescriptor is entered; wrap it so callers
    // invoke the live resolver, not the initial no-op captured at return time.
    return {
      handlePromise,
      reached,
      release: (verdict): void => {
        release(verdict);
      },
    };
  }

  it('24. an authenticated CLI in the window gets UNAVAILABLE; only after arming does it get APPLIED', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const started = startWithHeldVerification(orchestrator, anchor);
    await started.reached; // descriptor published, pipe live, verification pending

    // The official CLI discovers the live runtime and authenticates, but the
    // channel is not armed → UNAVAILABLE and the workflow does not advance.
    const during = await callCli(anchor);
    expect(during.outcome.authenticated).toBe(true);
    expect(during.outcome.status).toBe(CONTROL_RESULT.UNAVAILABLE);
    expect(during.outcome.exitCode).not.toBe(0);
    expect(during.out.some((line) => line.includes('APPLIED'))).toBe(false);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);

    // Verification passes → the channel arms exactly once.
    started.release({ ok: true });
    const handle = await started.handlePromise;
    expect(handle).not.toBeNull();
    handles.push(handle as ControlChannelHandle);

    const after = await callCli(anchor);
    expect(after.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
  });

  it('25. if verification fails after the window, no command was applied and the own descriptor is cleaned up', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const started = startWithHeldVerification(orchestrator, anchor);
    await started.reached;
    expect(anchor.entries().size).toBe(2); // the anchor secret + own descriptor published during the window

    // A CLI in the window is denied and mutates nothing.
    const during = await callCli(anchor);
    expect(during.outcome.status).toBe(CONTROL_RESULT.UNAVAILABLE);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);

    // Verification then FAILS → startup returns null and the own file is removed.
    started.release({ ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED });
    const handle = await started.handlePromise;
    expect(handle).toBeNull();
    expect(anchor.entries().size).toBe(1); // own descriptor cleaned up; the anchor secret stays
    expect(anchor.removeCalls()).toBe(1);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });
});

describe('D062 F2 — a discovered descriptor is security-verified BEFORE its token is trusted', () => {
  /**
   * The attack shape: a protocol-valid identity-named descriptor that predates
   * anchor hardening keeps an attacker-readable ACL (hardening the parent never
   * retrofits a child). The attacker reads its token and serves its pipe, so it
   * can answer a correctly HMAC-signed APPLIED. With no genuine runtime present
   * the CLI must still fail closed: EXIT 0 ⇒ APPLIED by a runtime identified
   * through a CURRENTLY verified descriptor.
   */
  function plantLeakedDescriptor(anchor: MemAnchor): { path: string; pipePath: string; token: Buffer } {
    // Bound to the anchor secret: models a genuine creator-born descriptor whose
    // ACL the operator later widened, so ONLY the security gate stands between
    // its leaked token and the CLI (the unbound/legacy case is covered elsewhere).
    const leaked = mintBound();
    anchor.set(leaked.runtimeId, serializeDescriptor(leaked.descriptor));
    return {
      path: descriptorPathFor(anchor.anchorPath, leaked.runtimeId),
      pipePath: pipePathFromName(leaked.descriptor.pipeName),
      token: leaked.token,
    };
  }

  /**
   * Deps whose security gate rejects exactly `badPath`, logging every CANDIDATE
   * verify/read in order. The reserved anchor secret passes and is not logged
   * (its own gate path is proven in control-store.test.ts).
   */
  function gatedDeps(anchor: MemAnchor, badPath: string, log: string[]): DescriptorFileDeps {
    const secretPath = anchorSecretPathFor(anchor.anchorPath);
    return {
      ...anchor.deps,
      readFile: (path: string): string => {
        if (path !== secretPath) {
          log.push(`read:${path}`);
        }
        return anchor.deps.readFile?.(path) ?? '';
      },
      verifyDescriptor: (path: string): Promise<DescriptorAclVerification> => {
        if (path === secretPath) {
          return Promise.resolve({ ok: true });
        }
        log.push(`verify:${path}`);
        return Promise.resolve(
          path === badPath ? { ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED } : { ok: true },
        );
      },
    };
  }

  it('negative control: with the gate (wrongly) passing, the attacker pipe DOES produce an authenticated APPLIED', async () => {
    const anchor = memAnchor();
    const leaked = plantLeakedDescriptor(anchor);
    rogues.push(await startRogueServer(leaked.pipePath, CONTROL_RESULT.APPLIED, leaked.token));
    const run = await callCli(anchor); // memAnchor's default gate passes everything
    expect(run.outcome.authenticated).toBe(true);
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(run.outcome.exitCode).toBe(0);
  });

  it('F2. bad-ACL descriptor + attacker pipe holding its token → rejected BEFORE the token is read; never APPLIED, never exit 0', async () => {
    const anchor = memAnchor();
    const leaked = plantLeakedDescriptor(anchor);
    rogues.push(await startRogueServer(leaked.pipePath, CONTROL_RESULT.APPLIED, leaked.token));
    const log: string[] = [];
    let probes = 0;
    const run = await callCli(anchor, {
      descriptorDeps: gatedDeps(anchor, leaked.path, log),
      probePipe: (pipePath: string) => {
        probes += 1;
        return Promise.resolve(pipePath === leaked.pipePath ? 'PRESENT' : 'ABSENT');
      },
    });
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
    expect(run.outcome.authenticated).toBe(false);
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
    expect(run.err.some((line) => line.includes('NO_VERIFIED_CANDIDATES'))).toBe(true);
    // Exactly where it failed closed: the gate ran on the candidate, and its
    // token was never read, its pipe never probed, no connection ever made.
    expect(log).toEqual([`verify:${leaked.path}`]);
    expect(probes).toBe(0);
    expect(anchor.removeCalls()).toBe(0);
  });

  it('F2b. genuine runtime beside the leaked descriptor → only the verified runtime is chosen and APPLIED', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const anchor = memAnchor();
    const leaked = plantLeakedDescriptor(anchor);
    rogues.push(await startRogueServer(leaked.pipePath, CONTROL_RESULT.APPLIED, leaked.token));
    const handle = await startServer(orchestrator, anchor, { probePipe: () => Promise.resolve('PRESENT') });
    handles.push(handle);
    expect(anchor.get(handle.runtimeId)).not.toBeNull();
    const log: string[] = [];
    const run = await callCli(anchor, { descriptorDeps: gatedDeps(anchor, leaked.path, log) });
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(run.outcome.exitCode).toBe(0);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    // Ordering proof per candidate: verify precedes read; the rejected file is never read.
    const genuinePath = descriptorPathFor(anchor.anchorPath, handle.runtimeId);
    expect(log.filter((entry) => entry.endsWith(leaked.path))).toEqual([`verify:${leaked.path}`]);
    expect(log.filter((entry) => entry.endsWith(genuinePath))).toEqual([`verify:${genuinePath}`, `read:${genuinePath}`]);
  });
});
