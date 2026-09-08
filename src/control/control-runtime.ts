/**
 * Bounded live-runtime composition wiring for the Decision 062 control channel.
 *
 * This is the composition root that turns the parts into a running channel,
 * invoked **after** the read-only Cockpit host is available (§17). It:
 *
 *   1. verifies the hardened control anchor (read-only, fail closed);
 *   2. removes any stale descriptor, failing closed if it cannot be removed;
 *   3. mints a fresh token and exclusively creates its descriptor;
 *   4. verifies the created file's actual ACL through the native snapshot path;
 *   5. builds the one narrow dispatcher over the orchestrator writer;
 *   6. listens on the unpredictable per-process pipe; a same-name collision or
 *      any listen error fails the channel **closed**.
 *
 * A failure at any step disables the control channel and returns `null`; it never
 * throws into the Cockpit path and never converts the Cockpit into a writer. The
 * Cockpit remains available and read-only. The token is never logged, never put
 * in an environment variable, argv, or an error message.
 */

import type { AutoflowOrchestrator } from '../autoflow/orchestrator.js';
import { createControlChannelServer } from './control-channel.js';
import { createControlDispatcher } from './control-dispatch.js';
import {
  createRuntimeDescriptor,
  descriptorPathFor,
  pipePathFromName,
  readDescriptorFile,
  removeDescriptorFile,
  removeStaleDescriptorFile,
  verifyControlAnchor,
  verifyDescriptorAcl,
  writeDescriptorFile,
  type ControlAnchorVerification,
  type DescriptorAclVerification,
  type DescriptorFileDeps,
  type VerifyControlAnchorDeps,
} from './control-store.js';

/**
 * Remove the fixed descriptor only while it still identifies THIS runtime
 * instance (exact pipeName match — the per-process 128-bit-random identity; a
 * pid can be reused, a pipeName cannot). If the descriptor is missing,
 * malformed, unreadable, or was replaced by a successor runtime, it is left
 * untouched so the successor stays discoverable. Read-compare-unlink is not
 * atomic; the residual window is the sub-millisecond gap between the match and
 * the unlink, not the successor's whole lifetime.
 */
function removeOwnDescriptorFile(
  anchorPath: string,
  ownPipeName: string,
  deps?: DescriptorFileDeps,
): void {
  const current = readDescriptorFile(anchorPath, deps);
  if (current === null || current.descriptor.pipeName !== ownPipeName) {
    return;
  }
  removeDescriptorFile(anchorPath, deps);
}

/** A running control channel; `close()` stops it and removes its own descriptor. */
export interface ControlChannelHandle {
  readonly pipeName: string;
  readonly pipePath: string;
  close(): Promise<void>;
}

export interface StartControlChannelDeps {
  readonly orchestrator: AutoflowOrchestrator;
  readonly env?: NodeJS.ProcessEnv;
  readonly pid?: number;
  readonly timeoutMs?: number;
  /** Injection seams (tests); production defaults verify and use the real fs/pipe. */
  readonly verify?: (deps: VerifyControlAnchorDeps) => Promise<ControlAnchorVerification>;
  readonly verifyDescriptor?: (
    descriptorPath: string,
    deps: VerifyControlAnchorDeps,
  ) => Promise<DescriptorAclVerification>;
  readonly descriptorDeps?: DescriptorFileDeps;
  readonly createServer?: typeof createControlChannelServer;
  readonly logger?: (message: string) => void;
}

/**
 * Start the control channel, or return `null` if it cannot be started safely.
 * Never throws for an expected fail-closed condition (unverified anchor,
 * descriptor write failure, pipe collision).
 */
export async function startControlChannel(
  deps: StartControlChannelDeps,
): Promise<ControlChannelHandle | null> {
  const env = deps.env ?? process.env;
  const pid = deps.pid ?? process.pid;
  const verify = deps.verify ?? verifyControlAnchor;
  const verifyDescriptor = deps.verifyDescriptor ?? verifyDescriptorAcl;
  const createServer = deps.createServer ?? createControlChannelServer;
  const log = deps.logger ?? ((message: string): void => {
    console.error(message);
  });

  const verification = await verify({ env });
  if (!verification.ok) {
    log(`AgentBridge control channel: disabled (anchor not verified: ${verification.reason}).`);
    return null;
  }
  const anchorPath = verification.anchorPath;

  // A stale pathname must be gone before minting or writing a new token. Only
  // ENOENT is harmless; access denied/locking and every other failure stop here.
  if (!removeStaleDescriptorFile(anchorPath, deps.descriptorDeps)) {
    log('AgentBridge control channel: disabled (stale descriptor removal failed).');
    return null;
  }

  const { descriptor, token } = createRuntimeDescriptor(pid);
  try {
    writeDescriptorFile(anchorPath, descriptor, deps.descriptorDeps);
  } catch {
    log('AgentBridge control channel: disabled (exclusive descriptor creation failed).');
    return null;
  }
  let descriptorAcl: DescriptorAclVerification;
  try {
    descriptorAcl = await verifyDescriptor(descriptorPathFor(anchorPath), { env });
  } catch {
    removeDescriptorFile(anchorPath, deps.descriptorDeps);
    log('AgentBridge control channel: disabled (descriptor ACL verification failed).');
    return null;
  }
  if (!descriptorAcl.ok) {
    removeDescriptorFile(anchorPath, deps.descriptorDeps);
    log(`AgentBridge control channel: disabled (descriptor ACL not verified: ${descriptorAcl.reason}).`);
    return null;
  }

  const dispatcher = createControlDispatcher(deps.orchestrator);
  const server = createServer(
    deps.timeoutMs === undefined
      ? { token, dispatcher }
      : { token, dispatcher, timeoutMs: deps.timeoutMs },
  );
  const pipePath = pipePathFromName(descriptor.pipeName);

  try {
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const onError = (error: unknown): void => {
        rejectPromise(error instanceof Error ? error : new Error('listen failed'));
      };
      server.once('error', onError);
      server.listen(pipePath, () => {
        server.removeListener('error', onError);
        resolvePromise();
      });
    });
  } catch {
    // A same-name collision or any listen failure fails closed. Remove only our
    // own descriptor: a successor may already have replaced it.
    removeOwnDescriptorFile(anchorPath, descriptor.pipeName, deps.descriptorDeps);
    log('AgentBridge control channel: disabled (pipe unavailable).');
    return null;
  }

  // Post-listen errors must not crash the process; log and keep the Cockpit up.
  server.on('error', () => {
    log('AgentBridge control channel: transport error (channel continues).');
  });

  return {
    pipeName: descriptor.pipeName,
    pipePath,
    close: (): Promise<void> =>
      new Promise<void>((resolvePromise) => {
        // Remove only our own descriptor: a successor runtime may have rotated
        // the fixed path already, and deleting its descriptor would make the
        // live successor undiscoverable.
        removeOwnDescriptorFile(anchorPath, descriptor.pipeName, deps.descriptorDeps);
        server.close(() => {
          resolvePromise();
        });
      }),
  };
}
