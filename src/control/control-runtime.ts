/**
 * Bounded live-runtime composition wiring for the Decision 062 control channel.
 *
 * This is the composition root that turns the parts into a running channel,
 * invoked **after** the read-only Cockpit host is available (§17). It:
 *
 *   1. verifies the hardened control anchor (read-only, fail closed);
 *   2. mints a fresh per-process descriptor + rotating 256-bit token;
 *   3. rotates any stale crash descriptor, then writes the new one — only after
 *      verification succeeds;
 *   4. builds the one narrow dispatcher over the orchestrator writer;
 *   5. listens on the unpredictable per-process pipe; a same-name collision or
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
  pipePathFromName,
  removeDescriptorFile,
  verifyControlAnchor,
  writeDescriptorFile,
  type ControlAnchorVerification,
  type DescriptorFileDeps,
  type VerifyControlAnchorDeps,
} from './control-store.js';

/** A running control channel; `close()` stops it and removes its descriptor. */
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

  // Rotate: replace any stale crash descriptor before serving.
  removeDescriptorFile(anchorPath, deps.descriptorDeps);

  const { descriptor, token } = createRuntimeDescriptor(pid);
  try {
    writeDescriptorFile(anchorPath, descriptor, deps.descriptorDeps);
  } catch {
    log('AgentBridge control channel: disabled (descriptor write failed).');
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
    // A same-name collision or any listen failure fails closed.
    removeDescriptorFile(anchorPath, deps.descriptorDeps);
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
        removeDescriptorFile(anchorPath, deps.descriptorDeps);
        server.close(() => {
          resolvePromise();
        });
      }),
  };
}
