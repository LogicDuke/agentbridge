import net from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { createControlChannelServer } from '../../src/control/control-channel.js';
import { createControlDispatcher } from '../../src/control/control-dispatch.js';
import {
  createRuntimeDescriptor,
  pipePathFromName,
  type ControlAnchorVerification,
  type DescriptorFileDeps,
} from '../../src/control/control-store.js';
import { startControlChannel, type ControlChannelHandle } from '../../src/control/control-runtime.js';
import { CONTROL_ANCHOR_REJECTION } from '../../src/control/control-store.js';
import { FAKE_ANCHOR, newOrchestrator } from './support.js';

const handles: ControlChannelHandle[] = [];
const servers: net.Server[] = [];

afterEach(async () => {
  await Promise.all(handles.splice(0).map((handle) => handle.close()));
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolvePromise) => {
          server.close(() => {
            resolvePromise();
          });
        }),
    ),
  );
});

function listen(server: net.Server, pipePath: string): Promise<void> {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    server.once('error', rejectPromise);
    server.listen(pipePath, () => {
      server.removeListener('error', rejectPromise);
      resolvePromise();
    });
  });
}

describe('D062 startControlChannel — fail closed', () => {
  it('an unverified anchor disables the channel and writes no descriptor', async () => {
    const { orchestrator } = newOrchestrator();
    let writeCalls = 0;
    const deps: DescriptorFileDeps = {
      readFile: (): string => {
        throw new Error('ENOENT');
      },
      writeFile: (): void => {
        writeCalls += 1;
      },
      removeFile: (): void => {
        /* no-op */
      },
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: (): Promise<ControlAnchorVerification> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL }),
      descriptorDeps: deps,
    });
    expect(handle).toBeNull();
    expect(writeCalls).toBe(0);
  });

  it('writes the descriptor only AFTER anchor verification succeeds', async () => {
    const { orchestrator } = newOrchestrator();
    const state = { verified: false, wroteBeforeVerify: false, stored: null as string | null };
    const deps: DescriptorFileDeps = {
      readFile: (): string => {
        if (state.stored === null) {
          throw new Error('ENOENT');
        }
        return state.stored;
      },
      writeFile: (_path: string, value: string): void => {
        if (!state.verified) {
          state.wroteBeforeVerify = true;
        }
        state.stored = value;
      },
      removeFile: (): void => {
        state.stored = null;
      },
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: (): Promise<ControlAnchorVerification> => {
        state.verified = true;
        return Promise.resolve({ ok: true, anchorPath: FAKE_ANCHOR });
      },
      descriptorDeps: deps,
    });
    expect(handle).not.toBeNull();
    if (handle !== null) {
      handles.push(handle);
    }
    expect(state.wroteBeforeVerify).toBe(false);
    expect(state.stored).not.toBeNull();
  });

  it('a descriptor write failure disables the channel', async () => {
    const { orchestrator } = newOrchestrator();
    const deps: DescriptorFileDeps = {
      readFile: (): string => {
        throw new Error('ENOENT');
      },
      writeFile: (): void => {
        throw new Error('EACCES');
      },
      removeFile: (): void => {
        /* no-op */
      },
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: (): Promise<ControlAnchorVerification> =>
        Promise.resolve({ ok: true, anchorPath: FAKE_ANCHOR }),
      descriptorDeps: deps,
    });
    expect(handle).toBeNull();
  });

  it('close() removes the descriptor', async () => {
    const { orchestrator } = newOrchestrator();
    const state = { stored: null as string | null };
    const deps: DescriptorFileDeps = {
      readFile: (): string => {
        if (state.stored === null) {
          throw new Error('ENOENT');
        }
        return state.stored;
      },
      writeFile: (_path: string, value: string): void => {
        state.stored = value;
      },
      removeFile: (): void => {
        state.stored = null;
      },
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: (): Promise<ControlAnchorVerification> =>
        Promise.resolve({ ok: true, anchorPath: FAKE_ANCHOR }),
      descriptorDeps: deps,
    });
    expect(state.stored).not.toBeNull();
    if (handle !== null) {
      await handle.close();
    }
    expect(state.stored).toBeNull();
  });
});

describe('D062 named-pipe collision fails closed', () => {
  it('a second listener on the same pipe name is refused', async () => {
    const { orchestrator } = newOrchestrator();
    const token = createRuntimeDescriptor(1).token;
    const dispatcher = createControlDispatcher(orchestrator);
    const pipePath = pipePathFromName(`agentbridge-control-${'a'.repeat(32)}`);

    const first = createControlChannelServer({ token, dispatcher });
    servers.push(first);
    await listen(first, pipePath);

    const second = createControlChannelServer({ token, dispatcher });
    servers.push(second);
    await expect(listen(second, pipePath)).rejects.toThrow();
  });
});
