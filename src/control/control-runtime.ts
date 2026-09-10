/**
 * Bounded live-runtime composition wiring for the Decision 062 control channel.
 *
 * This is the composition root that turns the parts into a running channel,
 * invoked **after** the read-only Cockpit host is available (§17). It:
 *
 *   1. verifies the hardened control anchor (read-only, fail closed);
 *   2. removes any stale descriptor, failing closed if it cannot be removed;
 *   3. mints a fresh token and exclusively creates its descriptor through the
 *      build-provenanced create-only native artifact — `CREATE_NEW`, owner = the
 *      exact runtime operator SID, protected operator+SYSTEM DACL — with the
 *      secret bytes delivered on stdin, never in argv;
 *   4. verifies the file that ACTUALLY exists through the INDEPENDENT read-only
 *      native snapshot path (creation is never trusted on its own word);
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
  createDescriptorFile,
  createRuntimeDescriptor,
  descriptorPathFor,
  pipePathFromName,
  readDescriptorFile,
  removeDescriptorFile,
  removeStaleDescriptorFile,
  verifyControlAnchor,
  verifyDescriptorAcl,
  type ControlAnchorVerification,
  type DescriptorAclVerification,
  type DescriptorCreation,
  type DescriptorCreatorDeps,
  type DescriptorFileDeps,
  type RuntimeDescriptor,
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
  if (!descriptorIsOurs(anchorPath, ownPipeName, deps)) {
    return;
  }
  removeDescriptorFile(anchorPath, deps);
}

/**
 * Whether the fixed descriptor currently identifies THIS runtime instance. The ONE
 * ownership predicate: both the cleanup paths and the pre-listen ownership proof
 * decide through exactly this function, so they cannot drift apart.
 *
 * A missing, malformed, or unreadable descriptor is NOT ours: ownership must be
 * proven, never assumed. Only the token-bearing pipeName is compared, and the token
 * read alongside it is never logged, returned, or otherwise observed.
 */
function descriptorIsOurs(
  anchorPath: string,
  ownPipeName: string,
  deps?: DescriptorFileDeps,
): boolean {
  const current = readDescriptorFile(anchorPath, deps);
  return current !== null && current.descriptor.pipeName === ownPipeName;
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
  /** Seams for the build-provenanced create-only native descriptor creator. */
  readonly creatorDeps?: DescriptorCreatorDeps;
  readonly createDescriptor?: (
    anchorPath: string,
    descriptor: RuntimeDescriptor,
  ) => Promise<DescriptorCreation>;
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
  const createDescriptor =
    deps.createDescriptor ??
    ((anchorPath: string, descriptor: RuntimeDescriptor): Promise<DescriptorCreation> =>
      createDescriptorFile(anchorPath, descriptor, deps.descriptorDeps, deps.creatorDeps));
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
  // Exclusive creation through the build-provenanced create-only native artifact:
  // owner = the exact runtime operator SID, protected operator+SYSTEM DACL, CREATE_NEW.
  // The token travels on the creator's stdin and is never an argument or a log line.
  let creation: DescriptorCreation;
  try {
    creation = await createDescriptor(anchorPath, descriptor);
  } catch {
    log('AgentBridge control channel: disabled (exclusive descriptor creation failed).');
    return null;
  }
  if (!creation.ok) {
    log(
      `AgentBridge control channel: disabled (exclusive descriptor creation failed: ${creation.reason}).`,
    );
    return null;
  }
  // Post-creation cleanup is ALWAYS ownership-checked. Between our exclusive creation
  // and this verification a successor runtime can have removed and recreated the fixed
  // descriptor; unlinking the pathname blindly would delete the successor's descriptor
  // and make its live channel undiscoverable. `removeOwnDescriptorFile` removes the
  // file only while it still names our own minted pipeName — the same rule the
  // listen-failure and close() paths already apply — so a missing, malformed, or
  // successor-owned descriptor is left untouched. Startup still fails closed either way.
  let descriptorAcl: DescriptorAclVerification;
  try {
    descriptorAcl = await verifyDescriptor(descriptorPathFor(anchorPath), { env });
  } catch {
    removeOwnDescriptorFile(anchorPath, descriptor.pipeName, deps.descriptorDeps);
    log('AgentBridge control channel: disabled (descriptor ACL verification failed).');
    return null;
  }
  if (!descriptorAcl.ok) {
    removeOwnDescriptorFile(anchorPath, descriptor.pipeName, deps.descriptorDeps);
    log(`AgentBridge control channel: disabled (descriptor ACL not verified: ${descriptorAcl.reason}).`);
    return null;
  }

  // The verification above is ASYNCHRONOUS and path-based: the helper re-opens
  // whatever file sits at the fixed path when it runs. A successor runtime can rotate
  // that path during the await (its stale-descriptor removal plus its own exclusive
  // creation), in which case the helper validated the SUCCESSOR's descriptor and
  // returned ok. Listening now would report a successful startup for a channel no
  // descriptor points at: undiscoverable while it runs, and leaving nothing behind at
  // all once the successor closes. Prove the stored descriptor is still ours first.
  //
  // Nothing is removed on this path. The only way to reach the failure branch is for
  // the descriptor to be absent, unprovable, or a successor's — and deleting any of
  // those is precisely the successor-clobbering this ownership rule exists to prevent.
  // A later runtime's stale-descriptor removal reclaims an orphaned pathname.
  if (!descriptorIsOurs(anchorPath, descriptor.pipeName, deps.descriptorDeps)) {
    log('AgentBridge control channel: disabled (descriptor no longer identifies this runtime).');
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
