import { EventEmitter } from 'node:events';
import net from 'node:net';

import { afterEach, describe, expect, it } from 'vitest';

import { createControlChannelServer } from '../../src/control/control-channel.js';
import { createControlDispatcher } from '../../src/control/control-dispatch.js';
import {
  DESCRIPTOR_CREATION_REJECTION,
  createRuntimeDescriptor,
  parseDescriptor,
  pipePathFromName,
  serializeDescriptor,
  type ControlAnchorVerification,
  type DescriptorCreation,
  type DescriptorFileDeps,
} from '../../src/control/control-store.js';
import { startControlChannel, type ControlChannelHandle } from '../../src/control/control-runtime.js';
import { CONTROL_ANCHOR_REJECTION } from '../../src/control/control-store.js';
import {
  FAKE_ANCHOR,
  memStore,
  newOrchestrator,
  passingDescriptorVerify,
  passingVerify,
  type MemStore,
} from './support.js';

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
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: deps,
    });
    expect(handle).toBeNull();
    expect(writeCalls).toBe(0);
  });

  it('a stale descriptor that cannot be removed blocks startup and keeps its old token', async () => {
    const { orchestrator } = newOrchestrator();
    const stale = serializeDescriptor(createRuntimeDescriptor(77).descriptor);
    const stored = stale;
    let writeCalls = 0;
    let aclChecks = 0;
    let serverCreates = 0;
    const descriptorDeps: DescriptorFileDeps = {
      readFile: (): string => stored,
      writeFile: (): void => {
        writeCalls += 1;
      },
      removeFile: (): void => {
        const denied = new Error('access denied') as NodeJS.ErrnoException;
        denied.code = 'EACCES';
        throw denied;
      },
    };

    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (): Promise<{ readonly ok: true }> => {
        aclChecks += 1;
        return Promise.resolve({ ok: true });
      },
      descriptorDeps,
      createServer: ((...args: Parameters<typeof createControlChannelServer>) => {
        serverCreates += 1;
        return createControlChannelServer(...args);
      }) as typeof createControlChannelServer,
      logger: (): void => {
        /* silent */
      },
    });

    expect(handle).toBeNull();
    expect(stored).toBe(stale);
    expect(writeCalls).toBe(0);
    expect(aclChecks).toBe(0);
    expect(serverCreates).toBe(0);
  });

  it('an unexpected pathname appearing before exclusive creation is never overwritten', async () => {
    const { orchestrator } = newOrchestrator();
    const unexpected = serializeDescriptor(createRuntimeDescriptor(88).descriptor);
    let stored: string | null = null;
    const descriptorDeps: DescriptorFileDeps = {
      readFile: (): string => {
        if (stored === null) {
          throw new Error('ENOENT');
        }
        return stored;
      },
      removeFile: (): void => {
        stored = unexpected;
      },
      writeFile: (): void => {
        if (stored !== null) {
          const exists = new Error('already exists') as NodeJS.ErrnoException;
          exists.code = 'EEXIST';
          throw exists;
        }
      },
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps,
      logger: (): void => {
        /* silent */
      },
    });
    expect(handle).toBeNull();
    expect(stored).toBe(unexpected);
  });

  it('successfully removes a stale descriptor before exclusive new creation', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    const stale = serializeDescriptor(createRuntimeDescriptor(99).descriptor);
    store.set(stale);
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
    });
    expect(handle).not.toBeNull();
    expect(store.get()).not.toBe(stale);
    if (handle !== null) {
      expect(storedPipeName(store)).toBe(handle.pipeName);
      handles.push(handle);
    }
  });

  it('verifies the created descriptor ACL before constructing or listening on the pipe', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    let resolveAcl!: (result: { readonly ok: true }) => void;
    const aclResult = new Promise<{ readonly ok: true }>((resolvePromise) => {
      resolveAcl = resolvePromise;
    });
    let aclSawDescriptor = false;
    let serverCreates = 0;
    const started = startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (): Promise<{ readonly ok: true }> => {
        aclSawDescriptor = store.get() !== null;
        return aclResult;
      },
      descriptorDeps: store.deps,
      createServer: ((...args: Parameters<typeof createControlChannelServer>) => {
        serverCreates += 1;
        return createControlChannelServer(...args);
      }) as typeof createControlChannelServer,
    });

    // Drain every pending microtask while the ACL result is still unresolved. This
    // is tick-count independent on purpose: descriptor creation is asynchronous
    // (the build-provenanced native creator), so counting `await`s would pin an
    // implementation detail rather than the ordering invariant being proven —
    // the descriptor exists when the ACL check runs, and no pipe exists yet.
    await new Promise<void>((resolveFlush) => {
      setImmediate(resolveFlush);
    });
    expect(aclSawDescriptor).toBe(true);
    expect(serverCreates).toBe(0);
    resolveAcl({ ok: true });
    const handle = await started;
    expect(handle).not.toBeNull();
    expect(serverCreates).toBe(1);
    if (handle !== null) {
      handles.push(handle);
    }
  });

  it('a bad resulting descriptor ACL is removed and startup fails before pipe creation', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    let serverCreates = 0;
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (): Promise<{ readonly ok: false; readonly reason: typeof CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL }> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL }),
      descriptorDeps: store.deps,
      createServer: ((...args: Parameters<typeof createControlChannelServer>) => {
        serverCreates += 1;
        return createControlChannelServer(...args);
      }) as typeof createControlChannelServer,
      logger: (): void => {
        /* silent */
      },
    });
    expect(handle).toBeNull();
    expect(store.get()).toBeNull();
    expect(serverCreates).toBe(0);
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
      verifyDescriptor: passingDescriptorVerify,
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
      verifyDescriptor: passingDescriptorVerify,
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
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: deps,
    });
    expect(state.stored).not.toBeNull();
    if (handle !== null) {
      await handle.close();
    }
    expect(state.stored).toBeNull();
  });
});

/** The pipeName of the descriptor currently in the store (must be valid). */
function storedPipeName(store: MemStore): string {
  const serialized = store.get();
  expect(serialized).not.toBeNull();
  const parsed = parseDescriptor(serialized);
  expect(parsed).not.toBeNull();
  if (serialized === null || parsed === null) {
    throw new Error('no valid descriptor in store');
  }
  return parsed.descriptor.pipeName;
}

/** An in-memory store whose removeFile calls are counted (rotation + cleanup alike). */
function countingStore(): { store: MemStore; removes: () => number } {
  let data: string | null = null;
  let removeCalls = 0;
  const store: MemStore = {
    deps: {
      readFile: (): string => {
        if (data === null) {
          throw new Error('ENOENT');
        }
        return data;
      },
      writeFile: (_path: string, value: string): void => {
        data = value;
      },
      removeFile: (): void => {
        removeCalls += 1;
        data = null;
      },
    },
    get: (): string | null => data,
    set: (value: string | null): void => {
      data = value;
    },
  };
  return { store, removes: (): number => removeCalls };
}

/**
 * A createControlChannelServer stand-in whose listen() always fails, invoking
 * `beforeFailure` first — deterministic listen-failure without pipe timing.
 */
function failingServerFactory(beforeFailure: () => void): typeof createControlChannelServer {
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

describe('D062 F2 descriptor ownership — cleanup unlinks only its own descriptor', () => {
  it('overlap: A.close() does not delete the successor descriptor; B stays discoverable and B.close() still cleans up', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();

    const handleA = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
    });
    expect(handleA).not.toBeNull();
    if (handleA === null) {
      return;
    }
    handles.push(handleA);
    expect(storedPipeName(store)).toBe(handleA.pipeName);

    // B starts before A closes: rotation replaces the fixed descriptor with B's.
    const handleB = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
    });
    expect(handleB).not.toBeNull();
    if (handleB === null) {
      return;
    }
    handles.push(handleB);
    expect(handleB.pipeName).not.toBe(handleA.pipeName);
    expect(storedPipeName(store)).toBe(handleB.pipeName);

    // A closes late: descriptor B must survive, exactly as written.
    await handleA.close();
    expect(storedPipeName(store)).toBe(handleB.pipeName);

    // B is still the owner: its own close removes the descriptor normally.
    await handleB.close();
    expect(store.get()).toBeNull();
  });

  it('missing descriptor during close() is harmless and triggers no unlink', async () => {
    const { orchestrator } = newOrchestrator();
    const { store, removes } = countingStore();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    store.set(null);
    const removesBeforeClose = removes();
    await handle.close();
    expect(removes()).toBe(removesBeforeClose);
    expect(store.get()).toBeNull();
  });

  it('a malformed descriptor is never deleted by close()', async () => {
    const { orchestrator } = newOrchestrator();
    const { store, removes } = countingStore();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    store.set('{not json');
    const removesBeforeClose = removes();
    await handle.close();
    expect(removes()).toBe(removesBeforeClose);
    expect(store.get()).toBe('{not json');
  });

  it('an unreadable descriptor is never deleted by close()', async () => {
    const { orchestrator } = newOrchestrator();
    let data: string | null = null;
    let unreadable = false;
    let removeCalls = 0;
    const deps: DescriptorFileDeps = {
      readFile: (): string => {
        if (unreadable || data === null) {
          throw new Error(unreadable ? 'EACCES' : 'ENOENT');
        }
        return data;
      },
      writeFile: (_path: string, value: string): void => {
        data = value;
      },
      removeFile: (): void => {
        removeCalls += 1;
        data = null;
      },
    };
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: deps,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    unreadable = true;
    const removesBeforeClose = removeCalls;
    await handle.close();
    expect(removeCalls).toBe(removesBeforeClose);
    expect(data).not.toBeNull();
  });

  it('close() does not use pid as identity: same pid, different pipeName is foreign', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      pid: 4242,
      descriptorDeps: store.deps,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    const foreign = createRuntimeDescriptor(4242).descriptor;
    expect(foreign.pid).toBe(4242);
    expect(foreign.pipeName).not.toBe(handle.pipeName);
    store.set(serializeDescriptor(foreign));
    await handle.close();
    expect(storedPipeName(store)).toBe(foreign.pipeName);
  });

  it('listen-failure cleanup does not delete a descriptor belonging to another runtime', async () => {
    const { orchestrator } = newOrchestrator();
    const { store, removes } = countingStore();
    const foreign = createRuntimeDescriptor(999).descriptor;
    let removesAfterWrite = 0;
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
      createServer: failingServerFactory((): void => {
        // The successor replaces the descriptor before our listen fails.
        store.set(serializeDescriptor(foreign));
        removesAfterWrite = removes();
      }),
      logger: (): void => {
        /* silent */
      },
    });
    expect(handle).toBeNull();
    expect(removes()).toBe(removesAfterWrite);
    expect(storedPipeName(store)).toBe(foreign.pipeName);
  });

  it('listen-failure cleanup still removes the runtime own matching descriptor', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      descriptorDeps: store.deps,
      createServer: failingServerFactory((): void => {
        expect(store.get()).not.toBeNull();
      }),
      logger: (): void => {
        /* silent */
      },
    });
    expect(handle).toBeNull();
    expect(store.get()).toBeNull();
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

/* ------------------------------------------------------------------ *
 * Descriptor CREATION failure (Decision 062 Amendment C) fails closed
 * ------------------------------------------------------------------ *
 *
 * Startup now creates the descriptor through the build-provenanced create-only
 * native artifact instead of `writeFileSync`, because Windows — not the caller —
 * chooses a new file's owner and DACL. Every creator fault must stop startup before
 * any pipe exists, and must never leave the Cockpit's availability depending on it.
 */
describe('D062 startControlChannel — native descriptor creation fails closed', () => {
  const CREATION_CAUSES = [
    DESCRIPTOR_CREATION_REJECTION.CREATOR_PROVENANCE_MISSING,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_MISSING,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_HASH_MISMATCH,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_SPAWN_FAILED,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_TIMEOUT,
    DESCRIPTOR_CREATION_REJECTION.CREATOR_FAILED,
    DESCRIPTOR_CREATION_REJECTION.DESCRIPTOR_TOO_LARGE,
  ] as const;

  it.each(CREATION_CAUSES)(
    'creation rejected with %s: no ACL check, no pipe, no descriptor, no throw',
    async (reason) => {
      const { orchestrator } = newOrchestrator();
      const store = memStore();
      let aclChecks = 0;
      let serverCreates = 0;
      const logged: string[] = [];

      const handle = await startControlChannel({
        orchestrator,
        verify: passingVerify,
        verifyDescriptor: (): Promise<{ readonly ok: true }> => {
          aclChecks += 1;
          return Promise.resolve({ ok: true });
        },
        createDescriptor: (): Promise<DescriptorCreation> => Promise.resolve({ ok: false, reason }),
        descriptorDeps: store.deps,
        createServer: ((): never => {
          serverCreates += 1;
          throw new Error('pipe construction must not be reached');
        }) as typeof createControlChannelServer,
        logger: (message: string): void => {
          logged.push(message);
        },
      });

      expect(handle).toBeNull();
      expect(aclChecks).toBe(0);
      expect(serverCreates).toBe(0);
      expect(store.get()).toBeNull();
      // The cause is surfaced, and no secret ever reaches a log line.
      expect(logged.join('\n')).toContain(reason);
    },
  );

  it('a creator that throws is contained: the channel disables, it never propagates', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    let serverCreates = 0;
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      createDescriptor: (): Promise<DescriptorCreation> => {
        throw new Error('creator exploded');
      },
      descriptorDeps: store.deps,
      createServer: ((): never => {
        serverCreates += 1;
        throw new Error('pipe construction must not be reached');
      }) as typeof createControlChannelServer,
      logger: (): void => {
        /* silent */
      },
    });
    expect(handle).toBeNull();
    expect(serverCreates).toBe(0);
    expect(store.get()).toBeNull();
  });

  it('the token is never an argument: creation receives only the verified anchor', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    const seen: { anchor: string; token: string; pipeName: string }[] = [];
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: passingDescriptorVerify,
      createDescriptor: (anchorPath, descriptor): Promise<DescriptorCreation> => {
        seen.push({
          anchor: anchorPath,
          token: descriptor.token,
          pipeName: descriptor.pipeName,
        });
        // Mirror the native creator's effect so startup can continue.
        store.set(serializeDescriptor(descriptor));
        return Promise.resolve({ ok: true });
      },
      descriptorDeps: store.deps,
    });
    expect(handle).not.toBeNull();
    if (handle === null) {
      return;
    }
    handles.push(handle);
    expect(seen).toHaveLength(1);
    const call = seen[0];
    expect(call).toBeDefined();
    if (call === undefined) {
      return;
    }
    // The anchor is the only path-shaped value creation is given, and it carries
    // no part of the secret.
    expect(call.anchor).toBe(FAKE_ANCHOR);
    expect(call.anchor).not.toContain(call.token);
    expect(call.pipeName).toBe(handle.pipeName);
  });

  it('creation succeeds but the descriptor ACL is rejected: still no pipe', async () => {
    const { orchestrator } = newOrchestrator();
    const store = memStore();
    let serverCreates = 0;
    const handle = await startControlChannel({
      orchestrator,
      verify: passingVerify,
      verifyDescriptor: (): Promise<{ readonly ok: false; readonly reason: 'OWNER_MISMATCH' }> =>
        Promise.resolve({ ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH }),
      createDescriptor: (_anchorPath, descriptor): Promise<DescriptorCreation> => {
        store.set(serializeDescriptor(descriptor));
        return Promise.resolve({ ok: true });
      },
      descriptorDeps: store.deps,
      createServer: ((): never => {
        serverCreates += 1;
        throw new Error('pipe construction must not be reached');
      }) as typeof createControlChannelServer,
      logger: (): void => {
        /* silent */
      },
    });
    expect(handle).toBeNull();
    expect(serverCreates).toBe(0);
    // The rejected descriptor is removed rather than left carrying a live token.
    expect(store.get()).toBeNull();
  });
});
