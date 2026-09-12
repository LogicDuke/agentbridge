import net from 'node:net';
import { randomBytes } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { WORKFLOW_STATUS } from '../../src/domain/index.js';
import { computeClientMac, NONCE_BYTES } from '../../src/control/control-auth.js';
import {
  buildRequestBody,
  frameMessage,
  parseHelloBody,
} from '../../src/control/control-channel.js';
import { CONTROL_COMMAND, CONTROL_RESULT } from '../../src/control/control-command.js';
import type { ControlChannelHandle } from '../../src/control/control-runtime.js';
import {
  BINDING,
  delay,
  descriptorFacts,
  memAnchor,
  newOrchestrator,
  rawClient,
  startServer,
} from './support.js';

const CMD = Buffer.from(CONTROL_COMMAND.OPEN_HUMAN_GATE, 'utf8');
const handles: ControlChannelHandle[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
});

describe('D062 control channel — server-level adversarial (real named pipe)', () => {
  it('a replayed client MAC (bound to a stale server nonce) is rejected AUTH_FAILED, no mutation', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { token, identity, pipePath } = descriptorFacts(store, handle);

    const outcome = await rawClient(pipePath, {
      onHello: (): Buffer => {
        const staleNonceS = randomBytes(NONCE_BYTES);
        const nonceC = randomBytes(NONCE_BYTES);
        const mac = computeClientMac(token, identity, staleNonceS, nonceC, CMD);
        return frameMessage(buildRequestBody(nonceC, CONTROL_COMMAND.OPEN_HUMAN_GATE, mac));
      },
    });
    expect(outcome.kind).toBe('result');
    if (outcome.kind === 'result') {
      expect(outcome.result).toBe(CONTROL_RESULT.AUTH_FAILED);
    }
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('a wrong client MAC is rejected before any mutation', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { identity, pipePath } = descriptorFacts(store, handle);

    const outcome = await rawClient(pipePath, {
      onHello: (nonceS: Buffer): Buffer => {
        const nonceC = randomBytes(NONCE_BYTES);
        // MAC with a random wrong token.
        const mac = computeClientMac(randomBytes(32), identity, nonceS, nonceC, CMD);
        return frameMessage(buildRequestBody(nonceC, CONTROL_COMMAND.OPEN_HUMAN_GATE, mac));
      },
    });
    expect(outcome.kind).toBe('result');
    if (outcome.kind === 'result') {
      expect(outcome.result).toBe(CONTROL_RESULT.AUTH_FAILED);
    }
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('an authenticated but unknown command is rejected MALFORMED, no mutation', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { token, identity, pipePath } = descriptorFacts(store, handle);

    const outcome = await rawClient(pipePath, {
      onHello: (nonceS: Buffer): Buffer => {
        const nonceC = randomBytes(NONCE_BYTES);
        const badCmd = Buffer.from('CLOSE_REQUESTED', 'utf8');
        const mac = computeClientMac(token, identity, nonceS, nonceC, badCmd);
        return frameMessage(buildRequestBody(nonceC, 'CLOSE_REQUESTED', mac));
      },
    });
    expect(outcome.kind).toBe('result');
    if (outcome.kind === 'result') {
      expect(outcome.result).toBe(CONTROL_RESULT.MALFORMED);
    }
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('an oversized frame is rejected (connection dropped), no mutation', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { pipePath } = descriptorFacts(store, handle);

    const outcome = await rawClient(pipePath, {
      onHello: (): Buffer => {
        const prefix = Buffer.alloc(4);
        prefix.writeUInt32BE(5000, 0); // > 4096
        return Buffer.concat([prefix, Buffer.alloc(10)]);
      },
    });
    expect(outcome.kind).toBe('closed');
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('a zero-length frame is rejected (connection dropped), no mutation', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { pipePath } = descriptorFacts(store, handle);

    const outcome = await rawClient(pipePath, {
      onHello: (): Buffer => Buffer.from([0, 0, 0, 0]),
    });
    expect(outcome.kind).toBe('closed');
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('a connection that never sends a request times out and is dropped, no mutation', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store, { timeoutMs: 150 });
    handles.push(handle);
    const { pipePath } = descriptorFacts(store, handle);

    const outcome = await rawClient(pipePath, {
      onHello: (): Buffer | null => null, // hold, never send
      waitMs: 2000,
    });
    expect(outcome.kind).toBe('closed');
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
  });

  it('a client that disconnects mid-frame does not crash the server or mutate; the server keeps serving', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { identity, pipePath } = descriptorFacts(store, handle);

    await new Promise<void>((resolvePromise) => {
      const socket = net.connect(pipePath);
      socket.on('error', () => {
        /* ignore */
      });
      let carry = Buffer.alloc(0);
      socket.on('data', (chunk: Buffer) => {
        carry = Buffer.concat([carry, chunk]);
        if (carry.length < 4) {
          return;
        }
        const length = carry.readUInt32BE(0);
        if (carry.length < 4 + length) {
          return;
        }
        // Received the hello; send a truncated frame then disconnect.
        const prefix = Buffer.alloc(4);
        prefix.writeUInt32BE(50, 0);
        socket.write(Buffer.concat([prefix, Buffer.from('partial', 'utf8')]));
        setTimeout(() => {
          socket.destroy();
          resolvePromise();
        }, 30);
      });
    });

    await delay(50);
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.OPEN);
    // The server is still alive and correctly rejects a stale-nonce replay.
    const { token } = descriptorFacts(store, handle);
    const followUp = await rawClient(pipePath, {
      onHello: (): Buffer => {
        const nonceC = randomBytes(NONCE_BYTES);
        const mac = computeClientMac(token, identity, randomBytes(NONCE_BYTES), nonceC, CMD);
        return frameMessage(buildRequestBody(nonceC, CONTROL_COMMAND.OPEN_HUMAN_GATE, mac));
      },
    });
    expect(followUp.kind).toBe('result');
  });

  it('a client that disconnects after dispatch but before reading the result: the mutation still stands', async () => {
    const { runtime, orchestrator } = newOrchestrator();
    orchestrator.open(BINDING);
    const store = memAnchor();
    const handle = await startServer(orchestrator, store);
    handles.push(handle);
    const { token, identity, pipePath } = descriptorFacts(store, handle);

    await new Promise<void>((resolvePromise) => {
      const socket = net.connect(pipePath);
      socket.on('error', () => {
        /* ignore */
      });
      let carry = Buffer.alloc(0);
      socket.on('data', (chunk: Buffer) => {
        carry = Buffer.concat([carry, chunk]);
        if (carry.length < 4) {
          return;
        }
        const length = carry.readUInt32BE(0);
        if (carry.length < 4 + length) {
          return;
        }
        const nonceS = parseHelloBody(carry.subarray(4, 4 + length));
        if (nonceS === null) {
          socket.destroy();
          resolvePromise();
          return;
        }
        const nonceC = randomBytes(NONCE_BYTES);
        const mac = computeClientMac(token, identity, nonceS, nonceC, CMD);
        socket.write(frameMessage(buildRequestBody(nonceC, CONTROL_COMMAND.OPEN_HUMAN_GATE, mac)));
        // Give the server time to receive + dispatch, then vanish before result.
        setTimeout(() => {
          socket.destroy();
          resolvePromise();
        }, 80);
      });
    });

    await delay(60);
    // The authoritative gate transition applied even though the client left.
    expect(runtime.current()?.status).toBe(WORKFLOW_STATUS.AWAITING_HUMAN_DECISION);
  });
});
