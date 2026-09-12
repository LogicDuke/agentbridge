/**
 * The Decision 062 control channel: a Windows-first local named-pipe server that
 * performs mutual HMAC authentication, parses exactly one bounded framed request
 * per connection, and dispatches the one production command synchronously.
 *
 * ## Framing (§13)
 *
 *   frame = uint32be(bodyLength) ++ body(JSON, UTF-8)   bodyLength ∈ [1, 4096]
 *
 * Exactly one request per connection. Partial reads are accumulated; a zero or
 * oversized length, a truncated frame, or **any extra byte past the one frame**
 * fails closed. Invalid UTF-8, malformed JSON, a non-object, an array, an unknown
 * field, or a missing field are rejected. A parsed hostile object is projected
 * into a **fresh** trusted {@link ControlCommand}; the caller's object never
 * reaches the dispatch layer.
 *
 * ## Handshake (§12)
 *
 *   S->C  hello   { v, nonceS }
 *   C->S  request { v, nonceC, command, mac }
 *           mac = HMAC(token, T("C", runtimeId, pipeName, nonceS, nonceC, command))
 *   S->C  result  { v, result, sig }
 *           sig = Ed25519(sk, T("S", runtimeId, pipeName, nonceS, nonceC, command, result))
 *
 * The server verifies `macC` with a constant-time compare **before** any
 * dispatch. Both transcripts bind the **exact command bytes received**, not a
 * re-serialized JSON, so tampering with the command after signing fails
 * authentication rather than slipping through; the result signature additionally
 * binds the exact result bytes, so a signature is never a reusable coupon for an
 * arbitrary outcome.
 *
 * The result is signed with the runtime's EPHEMERAL Ed25519 private key, which
 * exists only in this process's memory and is never serialized. A party holding
 * nothing but a copied descriptor therefore cannot answer a client, even after
 * the genuine runtime has exited and its pipe name has been freed.
 *
 * ## Limitations preserved (§11)
 *
 * The pipe name is unpredictable per process but **not secret**. This layer does
 * not inspect or assert the pipe's security descriptor, does not claim to prove
 * remote-pipe rejection or other-user rejection, and does not rely on
 * `FILE_FLAG_FIRST_PIPE_INSTANCE`. A same-name collision fails closed at listen
 * time (the caller surfaces the listen error). Command authorization rests on
 * token possession, never on pipe-ACL assumptions.
 *
 * ## Reentrancy (§15)
 *
 * The authoritative section — read current workflow, mint the event, apply — runs
 * **synchronously** inside {@link ControlDispatcher.dispatch}, with no `await`
 * between authentication and dispatch and none inside the critical section, so
 * `REENTRANCY_GUARD_NOT_REQUIRED_NOW` holds and no queue/replay is introduced.
 */

import net from 'node:net';
import { randomBytes, type KeyObject } from 'node:crypto';

import {
  computeClientMac,
  macEqual,
  signServerResult,
  MAC_BYTES,
  NONCE_BYTES,
  SIG_BYTES,
  type ChannelIdentity,
} from './control-auth.js';
import { decodeBase64UrlExact, encodeBase64Url } from './control-codec.js';
import {
  CONTROL_COMMAND,
  CONTROL_RESULT,
  type ControlCommand,
  type ControlResultStatus,
} from './control-command.js';
import type { ControlDispatcher } from './control-dispatch.js';

/** Wire constants. */
export const LENGTH_PREFIX_BYTES = 4;
export const MAX_BODY_BYTES = 4096;
export const MAX_FRAME_BYTES = LENGTH_PREFIX_BYTES + MAX_BODY_BYTES;
export const PROTOCOL_VERSION = 2;
export const DEFAULT_CONNECTION_TIMEOUT_MS = 5000;

const randomBytesFn = randomBytes;

/* ------------------------------------------------------------------ *
 * Framing (pure)
 * ------------------------------------------------------------------ */

export const FRAME_ERROR = Object.freeze({
  ZERO_LENGTH: 'ZERO_LENGTH',
  OVERSIZED: 'OVERSIZED',
  EXTRA_DATA: 'EXTRA_DATA',
} as const);

export type FrameError = (typeof FRAME_ERROR)[keyof typeof FRAME_ERROR];

export type FrameOutcome =
  | { readonly kind: 'incomplete' }
  | { readonly kind: 'frame'; readonly body: Buffer }
  | { readonly kind: 'error'; readonly reason: FrameError };

/**
 * Accumulates bytes across partial reads and yields **exactly one** frame.
 * Rejects a zero/oversized declared length and any surplus byte past the single
 * frame; anything short of a complete frame stays `incomplete`.
 */
export class FrameAccumulator {
  #buffer: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): void {
    this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
  }

  tryRead(): FrameOutcome {
    const buffer = this.#buffer;
    if (buffer.length < LENGTH_PREFIX_BYTES) {
      return { kind: 'incomplete' };
    }
    const bodyLength = buffer.readUInt32BE(0);
    if (bodyLength === 0) {
      return { kind: 'error', reason: FRAME_ERROR.ZERO_LENGTH };
    }
    if (bodyLength > MAX_BODY_BYTES) {
      return { kind: 'error', reason: FRAME_ERROR.OVERSIZED };
    }
    const total = LENGTH_PREFIX_BYTES + bodyLength;
    if (buffer.length < total) {
      return { kind: 'incomplete' };
    }
    if (buffer.length > total) {
      // A second request's bytes on the same connection — one request only.
      return { kind: 'error', reason: FRAME_ERROR.EXTRA_DATA };
    }
    return { kind: 'frame', body: buffer.subarray(LENGTH_PREFIX_BYTES, total) };
  }
}

/** Prepend the 4-byte big-endian length to a body, producing a wire frame. */
export function frameMessage(body: Buffer): Buffer {
  const prefix = Buffer.alloc(LENGTH_PREFIX_BYTES);
  prefix.writeUInt32BE(body.length, 0);
  return Buffer.concat([prefix, body]);
}

/* ------------------------------------------------------------------ *
 * Message bodies (pure)
 * ------------------------------------------------------------------ */

/** Build the server hello body `{ v, nonceS }`. */
export function buildHelloBody(nonceS: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({ v: PROTOCOL_VERSION, nonceS: encodeBase64Url(nonceS) }),
    'utf8',
  );
}

/** Build the client request body `{ v, nonceC, command, mac }`. */
export function buildRequestBody(nonceC: Buffer, command: string, mac: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({
      v: PROTOCOL_VERSION,
      nonceC: encodeBase64Url(nonceC),
      command,
      mac: encodeBase64Url(mac),
    }),
    'utf8',
  );
}

/** Build the server result body `{ v, result, sig }`. */
export function buildResultBody(status: ControlResultStatus, sigS: Buffer): Buffer {
  return Buffer.from(
    JSON.stringify({ v: PROTOCOL_VERSION, result: status, sig: encodeBase64Url(sigS) }),
    'utf8',
  );
}

/** Parse the server hello `{ v, nonceS }` and return the raw nonce, or `null`. */
export function parseHelloBody(body: Buffer): Buffer | null {
  const record = decodeJsonObject(body, ['v', 'nonceS']);
  if (record === null || record['v'] !== PROTOCOL_VERSION) {
    return null;
  }
  return decodeBase64UrlExact(record['nonceS'], NONCE_BYTES);
}

/**
 * Parse the server result `{ v, result, sig }`, or `null`. A protocol-version-1
 * body carries `mac`, not `sig`, so it fails the exact-key check here: there is
 * deliberately no downgrade branch.
 */
export function parseResultBody(body: Buffer): {
  readonly result: string;
  readonly sig: Buffer;
} | null {
  const record = decodeJsonObject(body, ['v', 'result', 'sig']);
  if (record === null || record['v'] !== PROTOCOL_VERSION) {
    return null;
  }
  const result = record['result'];
  const sig = decodeBase64UrlExact(record['sig'], SIG_BYTES);
  if (typeof result !== 'string' || sig === null) {
    return null;
  }
  return { result, sig };
}

/* ------------------------------------------------------------------ *
 * Client-request parsing (pure, hostile input)
 * ------------------------------------------------------------------ */

export type ParsedClientRequest =
  | {
      readonly ok: true;
      readonly nonceC: Buffer;
      readonly command: string;
      readonly commandBytes: Buffer;
      readonly mac: Buffer;
    }
  | { readonly ok: false };

/**
 * Decode a body as a UTF-8 JSON **plain object** whose own keys are exactly the
 * expected set, guarding against invalid UTF-8, non-objects, arrays, and any
 * missing/extra/inherited key (a `__proto__` key becomes a surplus own key and
 * is rejected here). Returns a plain record of the raw values, or `null`.
 */
function decodeJsonObject(
  body: Buffer,
  expectedKeys: readonly string[],
): Record<string, unknown> | null {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const keys = Object.keys(parsed);
  if (keys.length !== expectedKeys.length) {
    return null;
  }
  for (let index = 0; index < expectedKeys.length; index += 1) {
    const key = expectedKeys[index];
    if (key === undefined || !Object.hasOwn(parsed, key)) {
      return null;
    }
  }
  const source = parsed as Record<string, unknown>;
  const projected: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (let index = 0; index < expectedKeys.length; index += 1) {
    const key = expectedKeys[index];
    if (key !== undefined) {
      projected[key] = source[key];
    }
  }
  return projected;
}

/** Parse and validate a client request body; hostile input, fail closed. */
export function parseClientRequest(body: Buffer): ParsedClientRequest {
  const record = decodeJsonObject(body, ['v', 'nonceC', 'command', 'mac']);
  if (record === null || record['v'] !== PROTOCOL_VERSION) {
    return { ok: false };
  }
  const nonceC = decodeBase64UrlExact(record['nonceC'], NONCE_BYTES);
  const command = record['command'];
  const mac = decodeBase64UrlExact(record['mac'], MAC_BYTES);
  if (nonceC === null || typeof command !== 'string' || mac === null) {
    return { ok: false };
  }
  return { ok: true, nonceC, command, commandBytes: Buffer.from(command, 'utf8'), mac };
}

/* ------------------------------------------------------------------ *
 * Connection service
 * ------------------------------------------------------------------ */

/** A minimal duplex the connection service needs — real sockets satisfy it. */
export interface ControlSocket {
  setTimeout(ms: number): void;
  write(data: Buffer): void;
  end(data: Buffer): void;
  destroy(): void;
  on(event: 'data', listener: (chunk: Buffer) => void): void;
  on(event: 'timeout' | 'error' | 'close', listener: () => void): void;
}

export interface ServeConnectionContext {
  /** Bound into both transcripts so a signature cannot be relayed as another runtime's. */
  readonly identity: ChannelIdentity;
  /** Client-to-server command authorization only. */
  readonly token: Buffer;
  /** Ephemeral Ed25519 signing key; process memory only, never serialized. */
  readonly privateKey: KeyObject;
  readonly dispatcher: ControlDispatcher;
  readonly nonceGen: () => Buffer;
  readonly timeoutMs: number;
}

/**
 * Drive one connection: send the hello, read one framed request, authenticate,
 * dispatch synchronously, and return one authenticated result. Structural
 * framing/parse failures (which cannot be authenticated) drop the connection;
 * an authenticated-but-bad command or a failed MAC returns a bounded, MAC'd
 * result so a legitimate CLI always learns the outcome.
 */
export function serveConnection(socket: ControlSocket, ctx: ServeConnectionContext): void {
  const accumulator = new FrameAccumulator();
  const nonceS = ctx.nonceGen();
  let settled = false;

  socket.setTimeout(ctx.timeoutMs);
  socket.on('timeout', () => {
    if (!settled) {
      settled = true;
      socket.destroy();
    }
  });
  // A socket 'error' must have a listener or it throws; the connection is
  // already broken, so nothing more to do but mark it settled.
  socket.on('error', () => {
    settled = true;
  });
  socket.on('close', () => {
    settled = true;
  });

  const respond = (status: ControlResultStatus, nonceC: Buffer, commandBytes: Buffer): void => {
    const resultBytes = Buffer.from(status, 'utf8');
    const sigS = signServerResult(
      ctx.privateKey,
      ctx.identity,
      nonceS,
      nonceC,
      commandBytes,
      resultBytes,
    );
    try {
      socket.end(frameMessage(buildResultBody(status, sigS)));
    } catch {
      // Peer vanished after we dispatched; the result is lost but any state
      // change already stands. Retrying OPEN_HUMAN_GATE is safe (§15).
    }
  };

  socket.on('data', (chunk: Buffer) => {
    if (settled) {
      return;
    }
    accumulator.push(chunk);
    const outcome = accumulator.tryRead();
    if (outcome.kind === 'incomplete') {
      return;
    }
    settled = true;
    if (outcome.kind === 'error') {
      socket.destroy();
      return;
    }

    const parsed = parseClientRequest(outcome.body);
    if (!parsed.ok) {
      // Structural failure cannot be authenticated — drop the connection.
      socket.destroy();
      return;
    }

    const expectedMac = computeClientMac(
      ctx.token,
      ctx.identity,
      nonceS,
      parsed.nonceC,
      parsed.commandBytes,
    );
    if (!macEqual(expectedMac, parsed.mac)) {
      respond(CONTROL_RESULT.AUTH_FAILED, parsed.nonceC, parsed.commandBytes);
      return;
    }
    if (parsed.command !== CONTROL_COMMAND.OPEN_HUMAN_GATE) {
      respond(CONTROL_RESULT.MALFORMED, parsed.nonceC, parsed.commandBytes);
      return;
    }

    // Fresh trusted command — no hostile object crosses into dispatch.
    const command: ControlCommand = { command: CONTROL_COMMAND.OPEN_HUMAN_GATE };
    const status = ctx.dispatcher.dispatch(command);
    respond(status, parsed.nonceC, parsed.commandBytes);
  });

  socket.write(frameMessage(buildHelloBody(nonceS)));
}

/* ------------------------------------------------------------------ *
 * Named-pipe server
 * ------------------------------------------------------------------ */

export interface CreateControlChannelServerOptions {
  readonly identity: ChannelIdentity;
  readonly token: Buffer;
  readonly privateKey: KeyObject;
  readonly dispatcher: ControlDispatcher;
  readonly nonceGen?: () => Buffer;
  readonly timeoutMs?: number;
}

/** Create the (not-yet-listening) named-pipe server. */
export function createControlChannelServer(
  options: CreateControlChannelServerOptions,
): net.Server {
  const ctx: ServeConnectionContext = {
    identity: options.identity,
    token: options.token,
    privateKey: options.privateKey,
    dispatcher: options.dispatcher,
    nonceGen: options.nonceGen ?? ((): Buffer => randomBytesFn(NONCE_BYTES)),
    timeoutMs: options.timeoutMs ?? DEFAULT_CONNECTION_TIMEOUT_MS,
  };
  return net.createServer((socket: net.Socket) => {
    serveConnection(socket, ctx);
  });
}
