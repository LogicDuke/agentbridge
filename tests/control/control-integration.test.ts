import net from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { WORKFLOW_STATUS } from '../../src/domain/index.js';
import { CONTROL_RESULT } from '../../src/control/control-command.js';
import type { ControlChannelHandle } from '../../src/control/control-runtime.js';
import {
  BINDING,
  callCli,
  closeServer,
  descriptorFacts,
  fixedDescriptorDeps,
  memStore,
  newOrchestrator,
  startRogueServer,
  startServer,
  withTamperedToken,
} from './support.js';

const handles: ControlChannelHandle[] = [];
const rogues: net.Server[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
  await Promise.all(rogues.splice(0).map((server) => closeServer(server)));
});

describe('D062 control channel — end-to-end via the official CLI', () => {
  it('OPEN_HUMAN_GATE on an open workflow → APPLIED, progressing the real orchestrator', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memStore();
    handles.push(await startServer(orchestrator, store));

    const run = await callCli(store);
    expect(run.outcome.authenticated).toBe(true);
    expect(run.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    expect(run.outcome.exitCode).toBe(0);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(true);
  });

  it('no workflow → NO_WORKFLOW, and no workflow is manufactured', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    const store = memStore();
    handles.push(await startServer(orchestrator, store));

    const run = await callCli(store);
    expect(run.outcome.authenticated).toBe(true);
    expect(run.outcome.status).toBe(CONTROL_RESULT.NO_WORKFLOW);
    expect(run.outcome.exitCode).toBe(1);
    expect(runtime.current()).toBeNull();
  });

  it('a duplicate open → GATE_ALREADY_OPEN, state unchanged', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memStore();
    handles.push(await startServer(orchestrator, store));

    const first = await callCli(store);
    expect(first.outcome.status).toBe(CONTROL_RESULT.APPLIED);
    const gated = runtime.current();
    const second = await callCli(store);
    expect(second.outcome.status).toBe(CONTROL_RESULT.GATE_ALREADY_OPEN);
    expect(runtime.current()).toBe(gated);
  });

  it('repeated connections are served cleanly (no leaked server state)', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    handles.push(await startServer(orchestrator, store));

    for (let index = 0; index < 3; index += 1) {
      const run = await callCli(store);
      expect(run.outcome.authenticated).toBe(true);
      expect(run.outcome.status).toBe(CONTROL_RESULT.NO_WORKFLOW);
    }
  });

  it('a wrong client token → server rejects; the CLI never reports APPLIED; state unchanged', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memStore();
    handles.push(await startServer(orchestrator, store));

    const serialized = store.get();
    expect(serialized).not.toBeNull();
    const tampered = fixedDescriptorDeps(withTamperedToken(serialized ?? ''));
    const run = await callCli(store, { descriptorDeps: tampered });

    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
    // Domain state must be untouched by a rejected control attempt.
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('a rogue server returning APPLIED with a bad server MAC → the CLI refuses to trust it', async () => {
    // A descriptor the CLI trusts (its own token), pointing at a rogue pipe.
    const store = memStore();
    // Seed a real descriptor by starting (then discarding) a server would reuse
    // a pipe; instead mint one via the store using a genuine server, then point
    // the rogue at that pipe name with the same token the CLI will hold.
    const { orchestrator } = newOrchestrator();
    const handle = await startServer(orchestrator, store);
    const facts = descriptorFacts(store);
    // Preserve the descriptor the CLI will trust before stopping the genuine
    // server (close() removes it), so the CLI still holds the correct token.
    const serialized = store.get() ?? '';
    // Stop the genuine server so the rogue can claim the pipe name.
    await handle.close();
    const rogue = await startRogueServer(facts.pipePath, CONTROL_RESULT.APPLIED);
    rogues.push(rogue);

    const run = await callCli(store, { descriptorDeps: fixedDescriptorDeps(serialized) });
    expect(run.outcome.authenticated).toBe(false);
    expect(run.outcome.status).toBeNull();
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
    expect(run.err.some((line) => line.toLowerCase().includes('authentication'))).toBe(true);
  });

  it('a missing descriptor → CLI reports unavailable', async () => {
    const store = memStore(); // empty
    const run = await callCli(store);
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
  });

  it('a malformed/stale descriptor → CLI reports unavailable', async () => {
    const store = memStore();
    store.set('{ not a valid descriptor');
    const run = await callCli(store);
    expect(run.outcome.exitCode).toBe(1);
    expect(run.outcome.status).toBeNull();
  });

  it('a descriptor whose pipe name does not match any listener → CLI fails (no APPLIED)', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    // Point the CLI at a valid-shaped descriptor with a nonexistent pipe.
    const serialized = store.get() ?? '';
    const parsed = JSON.parse(serialized) as { pipeName: string };
    const mismatched = serialized.replace(
      parsed.pipeName,
      `agentbridge-control-${'0'.repeat(32)}`,
    );
    const run = await callCli(store, {
      descriptorDeps: fixedDescriptorDeps(mismatched),
      timeoutMs: 1000,
    });
    expect(run.outcome.status).toBeNull();
    expect(run.out.some((line) => line.includes('APPLIED'))).toBe(false);
  });

  it('handle.close() removes the descriptor and stops the listener', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    const handle = await startServer(orchestrator, store);
    expect(store.get()).not.toBeNull();
    await handle.close();
    expect(store.get()).toBeNull();
    // A fresh call now finds no descriptor.
    const run = await callCli(store);
    expect(run.outcome.status).toBeNull();
  });
});
