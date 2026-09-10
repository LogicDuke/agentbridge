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
import { CONTROL_RESULT } from '../../src/control/control-command.js';
import type { ControlChannelHandle } from '../../src/control/control-runtime.js';
import {
  MAX_DESCRIPTOR_CANDIDATES,
  createRuntimeDescriptor,
  descriptorFilenameFor,
  pipeNameForRuntimeId,
  pipePathFromName,
  serializeDescriptor,
} from '../../src/control/control-store.js';
import {
  BINDING,
  callCli,
  closeServer,
  descriptorFacts,
  memAnchor,
  newOrchestrator,
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
