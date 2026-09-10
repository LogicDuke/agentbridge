/**
 * Bounded live-runtime composition wiring for the Decision 062 control channel
 * (descriptor lifecycle v2: identity-named, listen-before-publish).
 *
 * This is the composition root that turns the parts into a running channel,
 * invoked **after** the read-only Cockpit host has bound its loopback port (§17).
 * The lifecycle is structurally ordered so that a descriptor can only ever
 * describe a runtime whose pipe is already live, and so that no runtime ever
 * touches another runtime's descriptor except to remove one proven dead:
 *
 *   1. verify the hardened control anchor (read-only, fail closed);
 *   2. sweep foreign descriptors whose pipe the kernel reports ABSENT (best
 *      effort; nothing PRESENT/UNKNOWN/malformed is ever removed);
 *   3. mint this runtime's identity: a 128-bit random runtime id, its pipe name,
 *      and a rotating 256-bit token;
 *   4. listen on the identity-named pipe — the kernel-owned exclusivity/liveness
 *      claim; a same-name collision or any listen error fails **closed** and
 *      nothing has been published;
 *   5. only after the pipe is live, publish `runtime-descriptor-<id>.json`
 *      through the build-provenanced create-only native creator (CREATE_NEW,
 *      exact operator owner, protected operator+SYSTEM DACL, bytes on stdin);
 *   6. verify the exact file just created: its actual owner + DACL through the
 *      independent read-only helper, and its contents by read-back — the parsed
 *      runtime id, pipe name, and token must equal what this runtime minted;
 *   7. expose the control handle only after every gate above passed.
 *
 * There is no shared fixed pathname, no rotation, no ownership recheck, no PID,
 * no lease, and no polling. A failure at any step disables the control channel
 * and returns `null`; it never throws into the Cockpit path and never converts
 * the Cockpit into a writer. The token is never logged, never put in an
 * environment variable, argv, or an error message.
 */

import { timingSafeEqual } from 'node:crypto';
import type net from 'node:net';

import type { AutoflowOrchestrator } from '../autoflow/orchestrator.js';
import { CONTROL_RESULT, type ControlCommand, type ControlResultStatus } from './control-command.js';
import { createControlChannelServer } from './control-channel.js';
import { createControlDispatcher, type ControlDispatcher } from './control-dispatch.js';
import {
  createDescriptorFileNative,
  createRuntimeDescriptor,
  defaultPipeProbe,
  descriptorPathFor,
  pipePathFromName,
  readDescriptorFile,
  removeDescriptorFile,
  serializeDescriptor,
  sweepStaleDescriptors,
  verifyControlAnchor,
  verifyDescriptorAcl,
  type ControlAnchorVerification,
  type DescriptorAclVerification,
  type DescriptorCreation,
  type DescriptorCreatorDeps,
  type DescriptorFileDeps,
  type PipeProbe,
  type VerifyControlAnchorDeps,
} from './control-store.js';

/** A running control channel; `close()` removes its own descriptor, then stops it. */
export interface ControlChannelHandle {
  readonly runtimeId: string;
  readonly pipeName: string;
  readonly pipePath: string;
  readonly descriptorPath: string;
  close(): Promise<void>;
}

/** Create one identity-named descriptor file; the production default is the native creator. */
export type DescriptorCreatorFn = (
  anchorPath: string,
  runtimeId: string,
  descriptorBytes: Buffer,
) => Promise<DescriptorCreation>;

export interface StartControlChannelDeps {
  readonly orchestrator: AutoflowOrchestrator;
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
  /** Injection seams (tests); production defaults verify and use the real fs/pipe. */
  readonly verify?: (deps: VerifyControlAnchorDeps) => Promise<ControlAnchorVerification>;
  readonly verifyDescriptor?: (
    descriptorPath: string,
    deps: VerifyControlAnchorDeps,
  ) => Promise<DescriptorAclVerification>;
  readonly descriptorDeps?: DescriptorFileDeps;
  readonly creatorDeps?: DescriptorCreatorDeps;
  readonly createDescriptor?: DescriptorCreatorFn;
  readonly probePipe?: PipeProbe;
  readonly createServer?: typeof createControlChannelServer;
  readonly logger?: (message: string) => void;
}

/** Close a server, resolving once it has stopped (never rejecting). */
function closeServer(server: net.Server): Promise<void> {
  return new Promise<void>((resolvePromise) => {
    server.close(() => {
      resolvePromise();
    });
  });
}

/** Listen once; resolve on success, reject on the first listen error. */
function listen(server: net.Server, pipePath: string): Promise<void> {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    const onError = (error: unknown): void => {
      rejectPromise(error instanceof Error ? error : new Error('listen failed'));
    };
    server.once('error', onError);
    server.listen(pipePath, () => {
      server.removeListener('error', onError);
      resolvePromise();
    });
  });
}

/**
 * Start the control channel, or return `null` if it cannot be started safely.
 * Never throws for an expected fail-closed condition (unverified anchor, pipe
 * collision, creation failure, descriptor verification failure).
 */
export async function startControlChannel(
  deps: StartControlChannelDeps,
): Promise<ControlChannelHandle | null> {
  const env = deps.env ?? process.env;
  const verify = deps.verify ?? verifyControlAnchor;
  const verifyDescriptor = deps.verifyDescriptor ?? verifyDescriptorAcl;
  const createDescriptor: DescriptorCreatorFn =
    deps.createDescriptor ??
    ((anchorPath, runtimeId, descriptorBytes): Promise<DescriptorCreation> =>
      createDescriptorFileNative(anchorPath, runtimeId, descriptorBytes, deps.creatorDeps));
  const probePipe = deps.probePipe ?? defaultPipeProbe();
  const createServer = deps.createServer ?? createControlChannelServer;
  const log = deps.logger ?? ((message: string): void => {
    console.error(message);
  });

  // 1. Anchor prerequisites.
  const verification = await verify({ env });
  if (!verification.ok) {
    log(`AgentBridge control channel: disabled (anchor not verified: ${verification.reason}).`);
    return null;
  }
  const anchorPath = verification.anchorPath;

  // 2. Best-effort sweep of foreign descriptors proven dead by the kernel pipe
  //    namespace. Nothing PRESENT, UNKNOWN, or malformed is ever removed.
  const sweep = await sweepStaleDescriptors(anchorPath, null, probePipe, deps.descriptorDeps);
  // Fail closed BEFORE listening or publishing if the initial descriptor
  // enumeration was not complete. An unreadable anchor or an over-cap candidate
  // set is exactly what CLI discovery rejects (ANCHOR_UNREADABLE /
  // TOO_MANY_CANDIDATES), so a channel started here could never be discovered:
  // CONTROL_START_SUCCESS ⇒ INITIAL_DESCRIPTOR_ENUMERATION_COMPLETE.
  if (sweep.enumeration !== 'complete') {
    log(`AgentBridge control channel: disabled (descriptor enumeration ${sweep.enumeration}).`);
    return null;
  }
  if (sweep.removed.length > 0 || sweep.unremovable.length > 0) {
    log(
      `AgentBridge control channel: stale descriptor sweep removed ${String(sweep.removed.length)}, ` +
        `could not remove ${String(sweep.unremovable.length)}.`,
    );
  }

  // 3. Mint this runtime's identity.
  const minted = createRuntimeDescriptor();
  const { runtimeId } = minted;
  const pipePath = pipePathFromName(minted.descriptor.pipeName);
  const descriptorPath = descriptorPathFor(anchorPath, runtimeId);

  // 4. Kernel-owned exclusivity/liveness: listen BEFORE anything is published.
  //    The server is armed with an INERT gate dispatcher, never the real one:
  //    the real dispatcher (the sole write-path capability) is created and
  //    slotted in only after every descriptor trust gate below has passed. An
  //    authenticated client that reaches the pipe during the publish→verify
  //    window therefore gets UNAVAILABLE and the orchestrator is never touched,
  //    preserving CONTROL_COMMAND_APPLIED ⇒ ALL_TRUST_GATES_PASSED. `live` moves
  //    NOT_READY(null) → READY(real dispatcher) exactly once and never back.
  let live: ControlDispatcher | null = null;
  const gate: ControlDispatcher = Object.freeze({
    dispatch(command: ControlCommand): ControlResultStatus {
      return live === null ? CONTROL_RESULT.UNAVAILABLE : live.dispatch(command);
    },
  });
  const server = createServer(
    deps.timeoutMs === undefined
      ? { token: minted.token, dispatcher: gate }
      : { token: minted.token, dispatcher: gate, timeoutMs: deps.timeoutMs },
  );
  try {
    await listen(server, pipePath);
  } catch {
    log('AgentBridge control channel: disabled (pipe unavailable).');
    return null;
  }

  // Post-listen errors must not crash the process; log and keep the Cockpit up.
  server.on('error', () => {
    log('AgentBridge control channel: transport error (channel continues).');
  });

  /** Fail closed after listening: remove ONLY this runtime's file (if it published), stop the pipe. */
  const failAfterListen = async (message: string, published: boolean): Promise<null> => {
    if (published) {
      removeDescriptorFile(descriptorPath, deps.descriptorDeps);
    }
    await closeServer(server);
    log(message);
    return null;
  };

  // 5. Publish this runtime's identity-named descriptor, only now that the pipe
  //    is live. CREATE_NEW: an existing pathname for OUR fresh 128-bit id can
  //    only be a collision or a planted file; either way we did not create it,
  //    so nothing is removed on this path.
  const descriptorBytes = Buffer.from(serializeDescriptor(minted.descriptor), 'utf8');
  let creation: DescriptorCreation;
  try {
    creation = await createDescriptor(anchorPath, runtimeId, descriptorBytes);
  } catch {
    return failAfterListen(
      'AgentBridge control channel: disabled (descriptor creation failed).',
      false,
    );
  }
  if (!creation.ok) {
    return failAfterListen(
      `AgentBridge control channel: disabled (descriptor creation failed: ${creation.reason}).`,
      false,
    );
  }

  // 6a. Verify the EXACT file just created through the independent read-only
  //     helper: owner, DACL present + protected, direct operator+SYSTEM only.
  let acl: DescriptorAclVerification;
  try {
    acl = await verifyDescriptor(descriptorPath, { env });
  } catch {
    return failAfterListen(
      'AgentBridge control channel: disabled (descriptor verification failed).',
      true,
    );
  }
  if (!acl.ok) {
    return failAfterListen(
      `AgentBridge control channel: disabled (descriptor not verified: ${acl.reason}).`,
      true,
    );
  }

  // 6b. Read back the exact file and require that it describes THIS runtime:
  //     the parsed runtime id, pipe name, and token must equal what was minted.
  const readBack = readDescriptorFile(descriptorPath, deps.descriptorDeps);
  if (
    readBack === null ||
    readBack.runtimeId !== runtimeId ||
    readBack.descriptor.pipeName !== minted.descriptor.pipeName ||
    readBack.token.length !== minted.token.length ||
    !timingSafeEqual(readBack.token, minted.token)
  ) {
    return failAfterListen(
      'AgentBridge control channel: disabled (descriptor contents do not identify this runtime).',
      true,
    );
  }

  // 7. Every trust gate passed. Arm the write path with NO intervening await
  //    between the final successful read-back check above and this assignment,
  //    so no command can be dispatched to the real orchestrator until exactly
  //    here. This is the one and only NOT_READY → READY transition.
  live = createControlDispatcher(deps.orchestrator);

  // 8. Expose the handle.
  return {
    runtimeId,
    pipeName: minted.descriptor.pipeName,
    pipePath,
    descriptorPath,
    close: async (): Promise<void> => {
      // Own identity-named file first, so no discoverer can select a runtime
      // that is shutting down; then the pipe. A client already mid-handshake is
      // unaffected because the pipe is still up until the descriptor is gone.
      // If the unlink fails the file is stale by construction (its pipe is about
      // to be ABSENT) and a later runtime's sweep removes it.
      removeDescriptorFile(descriptorPath, deps.descriptorDeps);
      await closeServer(server);
    },
  };
}
