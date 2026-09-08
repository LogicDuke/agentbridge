/**
 * Decision 062 Windows control-anchor security model and per-process descriptor
 * lifecycle.
 *
 * ## Verify-before-use, fail-closed
 *
 * Before a descriptor is written or read, the deployment-anchored control
 * directory (conceptually `%LOCALAPPDATA%\AgentBridge\control\`) is verified:
 *
 * - every path component is `lstat`-checked and any symlink/reparse condition is
 *   rejected;
 * - the current operator identity comes from `whoami /user` (the trusted operator
 *   SID);
 * - one build-provenanced native helper reads a single OWNER + DACL
 *   security-descriptor snapshot (Decision 062 Amendment B). Its bytes are
 *   SHA-256-verified against generated build metadata before it is ever run; the
 *   snapshot is emitted as **canonical SIDs only** (never localized account
 *   names). From that one snapshot:
 *     - the anchor **OWNER SID** must equal the exact runtime operator SID. SYSTEM
 *       is an allowed DACL principal but **never** an allowed owner, because an
 *       owner can rewrite the DACL;
 *     - the DACL must be present/non-NULL and protected, and its principals must
 *       be **exactly** the runtime operator plus SYSTEM by canonical SID; every
 *       ACE must be direct and file-inheritable so the token descriptor receives
 *       the same restricted principal set. Any unsupported state fails closed.
 *   A display name can never satisfy any comparison (Amendment B removed the
 *   earlier localized-`icacls` DACL read entirely: it failed closed on non-English
 *   Windows because `icacls` reports localized account names and never exposes
 *   SYSTEM's canonical SID). There is one security truth source, not two.
 *
 * This gate is **implementation only**: it never mutates ACLs and never
 * provisions the production directory (a later, separate authority gate). It also
 * makes **no atomic pathname proof** — the snapshot is a single read (a
 * sub-millisecond check-to-use TOCTOU window remains), and Node's `lstat`
 * distinguishes a symlink but not every reparse tag. These limitations are
 * preserved deliberately; authorization never depends on them alone — token
 * possession (mutual HMAC) is the actual authenticator.
 *
 * ## Token / descriptor lifecycle
 *
 * The runtime token is 256 bits from {@link crypto.randomBytes}, process-lifetime
 * only, rotated every start, and represented base64url **only** inside the
 * hardened descriptor file. It is never an environment variable, argv, Scheduled
 * Task field, log line, error message, and is never sent raw over the pipe (it is
 * an HMAC key). A stale crash descriptor must be removed before an exclusively
 * created replacement is written; the replacement's actual ACL is then verified
 * before serving. An orderly shutdown removes it best-effort.
 */

import { execFile } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { lstatSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { decodeBase64UrlExact, encodeBase64Url } from './control-codec.js';

const randomBytesFn = randomBytes;

/** 256-bit runtime token. */
const TOKEN_BYTES = 32;
/** 128-bit pipe-name randomness, rendered as 32 lowercase hex characters. */
const PIPE_ID_BYTES = 16;
/** Hard cap on a descriptor file we are willing to parse. */
const MAX_DESCRIPTOR_BYTES = 4096;
/** Finite deadline and output cap for the two allowed read-only subprocesses. */
const PROCESS_TIMEOUT_MS = 5000;
const PROCESS_MAX_BUFFER = 1024 * 1024;
/** Defensive cap on path depth while enumerating ancestors. */
const MAX_PATH_DEPTH = 64;

/**
 * Well-known SYSTEM principal, by canonical SID only. Under Amendment B every
 * principal enters authorization as a SID from the native snapshot, so the
 * localized display name ("NT AUTHORITY\SYSTEM") is never consulted.
 */
const SYSTEM_SID = 's-1-5-18';

/** The current descriptor's fixed filename inside the anchor directory. */
const DESCRIPTOR_FILENAME = 'runtime-descriptor.json';

/* ------------------------------------------------------------------ *
 * Anchor path resolution
 * ------------------------------------------------------------------ */

/** Resolve the conceptual `%LOCALAPPDATA%\AgentBridge\control\`, or `null`. */
export function resolveControlAnchorPath(env: NodeJS.ProcessEnv): string | null {
  const base = env['LOCALAPPDATA'];
  if (typeof base !== 'string' || base.trim().length === 0) {
    return null;
  }
  return join(base, 'AgentBridge', 'control');
}

/** The descriptor file path inside an anchor directory. */
export function descriptorPathFor(anchorPath: string): string {
  return join(anchorPath, DESCRIPTOR_FILENAME);
}

/** The Windows named-pipe path for a descriptor's pipe name. */
export function pipePathFromName(pipeName: string): string {
  return `\\\\.\\pipe\\${pipeName}`;
}

/* ------------------------------------------------------------------ *
 * Descriptor model
 * ------------------------------------------------------------------ */

/** The hardened per-process descriptor written into the verified anchor. */
export interface RuntimeDescriptor {
  readonly version: 1;
  readonly pid: number;
  readonly pipeName: string;
  /** base64url of the 256-bit token — hardened storage only, never elsewhere. */
  readonly token: string;
}

const PIPE_NAME_PATTERN = /^agentbridge-control-[0-9a-f]{32}$/;

/**
 * Mint a fresh descriptor and its raw token. The token rotates every call
 * (fresh `randomBytes`), the pipe name is per-process unpredictable (128-bit),
 * and the raw token is returned separately so the caller can key HMAC without
 * re-decoding it.
 */
export function createRuntimeDescriptor(pid: number): {
  readonly descriptor: RuntimeDescriptor;
  readonly token: Buffer;
} {
  const token = randomBytesFn(TOKEN_BYTES);
  const pipeName = `agentbridge-control-${randomBytesFn(PIPE_ID_BYTES).toString('hex')}`;
  const descriptor: RuntimeDescriptor = {
    version: 1,
    pid,
    pipeName,
    token: encodeBase64Url(token),
  };
  return { descriptor, token };
}

/** Serialize a descriptor to its on-disk JSON form. */
export function serializeDescriptor(descriptor: RuntimeDescriptor): string {
  return JSON.stringify(descriptor);
}

/**
 * Parse and validate an untrusted descriptor text into a trusted descriptor plus
 * its raw token, or `null`. Bounded, exact-key, and round-trip-verified for the
 * token and pipe name; a stale, truncated, or malformed descriptor fails closed.
 */
export function parseDescriptor(text: unknown): {
  readonly descriptor: RuntimeDescriptor;
  readonly token: Buffer;
} | null {
  if (typeof text !== 'string' || text.length === 0 || text.length > MAX_DESCRIPTOR_BYTES) {
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
  if (keys.length !== 4) {
    return null;
  }
  const record = parsed as Record<string, unknown>;
  const version = record['version'];
  const pid = record['pid'];
  const pipeName = record['pipeName'];
  const token = record['token'];
  if (
    version !== 1 ||
    typeof pid !== 'number' ||
    !Number.isInteger(pid) ||
    pid < 0 ||
    typeof pipeName !== 'string' ||
    !PIPE_NAME_PATTERN.test(pipeName) ||
    typeof token !== 'string'
  ) {
    return null;
  }
  const rawToken = decodeBase64UrlExact(token, TOKEN_BYTES);
  if (rawToken === null) {
    return null;
  }
  return {
    descriptor: { version: 1, pid, pipeName, token },
    token: rawToken,
  };
}

/* ------------------------------------------------------------------ *
 * Pure ACL / path evaluation
 * ------------------------------------------------------------------ */

/** An ACE type the snapshot can represent: an allow or a deny entry. */
export type AceType = 'ALLOW' | 'DENY';

/** One DACL ACE from the native snapshot, addressed by canonical SID. */
export interface AclSnapshotAce {
  readonly type: AceType;
  /** Exact supported ACE_HEADER AceFlags propagation/inheritance bitset. */
  readonly flags: number;
  /** The ACCESS_MASK as an unsigned 32-bit value. */
  readonly mask: number;
  /** The principal's canonical SID (normalized lowercase). */
  readonly sid: string;
}

/** A canonical OWNER + DACL snapshot as parsed from the native `--acl` helper. */
export interface AclSnapshot {
  readonly ownerSid: string;
  readonly daclState: 'PRESENT' | 'NULL' | 'ABSENT';
  /** True only when SE_DACL_PROTECTED was set in the snapshotted descriptor. */
  readonly daclProtected: boolean;
  readonly aces: readonly AclSnapshotAce[];
}

/** The current operator, from `whoami /user`: an account name and its SID. */
export interface OperatorIdentity {
  readonly name: string;
  readonly sid: string;
}

export const CONTROL_ANCHOR_REJECTION = Object.freeze({
  ANCHOR_PATH_UNRESOLVED: 'ANCHOR_PATH_UNRESOLVED',
  COMPONENT_UNREADABLE: 'COMPONENT_UNREADABLE',
  REPARSE_POINT: 'REPARSE_POINT',
  WHOAMI_FAILED: 'WHOAMI_FAILED',
  OPERATOR_UNREADABLE: 'OPERATOR_UNREADABLE',
  // Owner + DACL snapshot gate (Decision 062 Amendment B): one build-provenanced
  // native helper reads a canonical-SID OWNER + DACL snapshot; every invariant
  // below is proven over SIDs, never localized account names.
  HELPER_PROVENANCE_MISSING: 'HELPER_PROVENANCE_MISSING',
  HELPER_MISSING: 'HELPER_MISSING',
  HELPER_HASH_MISMATCH: 'HELPER_HASH_MISMATCH',
  SNAPSHOT_QUERY_FAILED: 'SNAPSHOT_QUERY_FAILED',
  SNAPSHOT_MALFORMED: 'SNAPSHOT_MALFORMED',
  // Owner policy: the anchor OWNER must be the exact runtime operator SID.
  OWNER_IS_SYSTEM: 'OWNER_IS_SYSTEM',
  OWNER_MISMATCH: 'OWNER_MISMATCH',
  // DACL policy: exactly operator + SYSTEM by SID, protected, none inherited,
  // file-inheritable, present/non-NULL, and the operator SID present.
  DACL_ABSENT: 'DACL_ABSENT',
  DACL_UNPROTECTED: 'DACL_UNPROTECTED',
  NO_ENTRIES: 'NO_ENTRIES',
  INHERITED_PRINCIPAL: 'INHERITED_PRINCIPAL',
  FILE_INHERITANCE_ABSENT: 'FILE_INHERITANCE_ABSENT',
  FOREIGN_PRINCIPAL: 'FOREIGN_PRINCIPAL',
  RUNTIME_PRINCIPAL_ABSENT: 'RUNTIME_PRINCIPAL_ABSENT',
  SYSTEM_PRINCIPAL_ABSENT: 'SYSTEM_PRINCIPAL_ABSENT',
} as const);

export type ControlAnchorRejection =
  (typeof CONTROL_ANCHOR_REJECTION)[keyof typeof CONTROL_ANCHOR_REJECTION];

/** Case/space-normalized principal for comparison. */
function normalizePrincipal(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Parse `whoami /user` output into the operator's name and SID. The SID column
 * is the stable signal; the account name is the first token on the SID's line.
 */
export function parseWhoamiUser(stdout: string): OperatorIdentity | null {
  const sidPattern = /\bS-1-\d+(?:-\d+)+\b/;
  const lines = stdout.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === undefined) {
      continue;
    }
    const match = sidPattern.exec(line);
    if (match === null) {
      continue;
    }
    const sid = match[0];
    const parts = line.trim().split(/\s+/);
    const name = parts[0];
    if (name !== undefined && name.length > 0 && name !== sid) {
      return { name: normalizePrincipal(name), sid: normalizePrincipal(sid) };
    }
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Canonical OWNER + DACL snapshot (Amendment B)
 * ------------------------------------------------------------------ *
 *
 * The native helper's `--acl <path>` mode emits a bounded, deterministic,
 * locale-independent snapshot (see tools/control-owner/agentbridge-win-owner.c):
 *
 *     AGENTBRIDGE-ACL-V2\n
 *     OWNER <sid>\n
 *     DACL <PRESENT|NULL|ABSENT> <PROTECTED|UNPROTECTED>\n
 *     ACES <count>\n
 *     ACE <ALLOW|DENY> 0xXX 0xXXXXXXXX <sid>\n   (x count, PRESENT)
 *
 * Every SID is canonical (ConvertSidToStringSidW); no account name ever appears.
 * The parser below is total and bounded: any deviation — wrong magic, a
 * non-canonical SID, an unhandled ACE token, a count mismatch, a NULL DACL with
 * ACEs, trailing bytes, or over-length input — yields `null` (fail closed).
 */

const SNAPSHOT_MAGIC = 'AGENTBRIDGE-ACL-V2';
/** Hard cap on a snapshot we are willing to parse (the runner also caps output). */
const MAX_SNAPSHOT_BYTES = 128 * 1024;
/** Hard cap on ACE lines, matching the helper's own ACL_MAX_ACES. */
const MAX_SNAPSHOT_ACES = 256;
/** An 8-hex-digit access mask with the exact `0x` prefix the helper emits. */
const ACE_MASK_PATTERN = /^0x[0-9A-Fa-f]{8}$/;
const ACE_FLAGS_PATTERN = /^0x[0-9A-Fa-f]{2}$/;
const SUPPORTED_ACE_FLAGS = 0x1f;
const OBJECT_INHERIT_ACE = 0x01;
const INHERITED_ACE = 0x10;

/** Parse one `ACE <type> <flags> <mask> <sid>` line, or `null` (fail closed). */
function parseAceLine(line: string): AclSnapshotAce | null {
  const parts = line.split(' ');
  if (parts.length !== 5 || parts[0] !== 'ACE') {
    return null;
  }
  const [, typeToken, flagsToken, maskToken, sidToken] = parts;
  if (typeToken !== 'ALLOW' && typeToken !== 'DENY') {
    return null;
  }
  if (flagsToken === undefined || !ACE_FLAGS_PATTERN.test(flagsToken)) {
    return null;
  }
  const flags = Number.parseInt(flagsToken, 16);
  if (!Number.isInteger(flags) || (flags & ~SUPPORTED_ACE_FLAGS) !== 0) {
    return null;
  }
  if (maskToken === undefined || !ACE_MASK_PATTERN.test(maskToken)) {
    return null;
  }
  const mask = Number.parseInt(maskToken, 16);
  if (!Number.isInteger(mask)) {
    return null;
  }
  if (sidToken === undefined || !CANONICAL_SID_PATTERN.test(sidToken)) {
    return null;
  }
  return {
    type: typeToken,
    flags,
    mask,
    sid: normalizePrincipal(sidToken),
  };
}

/**
 * Parse the native `--acl` snapshot into a trusted {@link AclSnapshot}, or `null`
 * (fail closed). Total and bounded: exact grammar, canonical SIDs only, an exact
 * ACE-count match, and a rejected trailing byte.
 */
export function parseAclSnapshot(stdout: string): AclSnapshot | null {
  if (typeof stdout !== 'string' || stdout.length === 0 || stdout.length > MAX_SNAPSHOT_BYTES) {
    return null;
  }
  const lines = stdout.split('\n');
  // The helper terminates every line with LF, so the final split element must be
  // exactly the empty string; anything else is trailing garbage.
  if (lines[lines.length - 1] !== '') {
    return null;
  }
  lines.pop();
  // Four header lines are mandatory: magic, OWNER, DACL, ACES.
  if (lines.length < 4) {
    return null;
  }
  if (lines[0] !== SNAPSHOT_MAGIC) {
    return null;
  }

  const ownerLine = lines[1] ?? '';
  if (!ownerLine.startsWith('OWNER ')) {
    return null;
  }
  const ownerSidRaw = ownerLine.slice('OWNER '.length);
  if (!CANONICAL_SID_PATTERN.test(ownerSidRaw)) {
    return null;
  }
  const ownerSid = normalizePrincipal(ownerSidRaw);

  const daclMatch = /^DACL (PRESENT|NULL|ABSENT) (PROTECTED|UNPROTECTED)$/.exec(lines[2] ?? '');
  if (daclMatch === null) {
    return null;
  }
  const daclState = daclMatch[1] as AclSnapshot['daclState'];
  const daclProtected = daclMatch[2] === 'PROTECTED';

  const acesLine = lines[3] ?? '';
  if (!acesLine.startsWith('ACES ')) {
    return null;
  }
  const countToken = acesLine.slice('ACES '.length);
  if (!/^\d+$/.test(countToken)) {
    return null;
  }
  const count = Number(countToken);
  if (!Number.isInteger(count) || count < 0 || count > MAX_SNAPSHOT_ACES) {
    return null;
  }

  const aceLines = lines.slice(4);
  if (aceLines.length !== count) {
    return null;
  }
  // A NULL DACL must carry no ACEs; a present DACL may be empty.
  if (daclState !== 'PRESENT' && count !== 0) {
    return null;
  }

  const aces: AclSnapshotAce[] = [];
  for (let index = 0; index < aceLines.length; index += 1) {
    const line = aceLines[index];
    if (line === undefined) {
      return null;
    }
    const ace = parseAceLine(line);
    if (ace === null) {
      return null;
    }
    aces.push(ace);
  }

  return { ownerSid, daclState, daclProtected, aces };
}

/**
 * Decide whether a canonical snapshot is acceptable, fail-closed over SIDs only.
 *
 * Owner: the OWNER SID must equal the exact runtime operator SID; SYSTEM (which
 * may own then rewrite the DACL) and any foreign owner are rejected.
 *
 * DACL: it must be present, non-empty, and protected; no ACE may be inherited,
 * every ACE must propagate to files, every principal must be the operator or
 * SYSTEM by canonical SID, and the operator SID must be present. Deliberately
 * unchanged from the pre-Amendment-B invariant,
 * the allow/deny type and access mask are carried in the snapshot but do NOT gate
 * authorization — an operator ACE counts as present regardless of allow/deny,
 * exactly as the previous icacls-name check did. Token possession (mutual HMAC)
 * remains the actual authenticator.
 */
export function evaluateAnchorSnapshot(
  operator: OperatorIdentity,
  snapshot: AclSnapshot,
): { readonly ok: true } | { readonly ok: false; readonly reason: ControlAnchorRejection } {
  if (snapshot.ownerSid === SYSTEM_SID) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM };
  }
  if (snapshot.ownerSid !== operator.sid) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH };
  }
  if (snapshot.daclState !== 'PRESENT') {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_ABSENT };
  }
  if (!snapshot.daclProtected) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_UNPROTECTED };
  }
  if (snapshot.aces.length === 0) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.NO_ENTRIES };
  }
  let operatorPresent = false;
  for (let index = 0; index < snapshot.aces.length; index += 1) {
    const ace = snapshot.aces[index];
    if (ace === undefined) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED };
    }
    if ((ace.flags & INHERITED_ACE) !== 0) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.INHERITED_PRINCIPAL };
    }
    const isOperator = ace.sid === operator.sid;
    const isSystem = ace.sid === SYSTEM_SID;
    if (!isOperator && !isSystem) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL };
    }
    if ((ace.flags & OBJECT_INHERIT_ACE) === 0) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.FILE_INHERITANCE_ABSENT };
    }
    if (isOperator) {
      operatorPresent = true;
    }
  }
  if (!operatorPresent) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT };
  }
  return { ok: true };
}

/**
 * Evaluate the resulting descriptor file ACL. File ACEs may be inherited and
 * need not themselves carry propagation flags, but the owner must be the
 * operator and the complete principal set must be exactly operator + SYSTEM.
 */
export function evaluateDescriptorSnapshot(
  operator: OperatorIdentity,
  snapshot: AclSnapshot,
): { readonly ok: true } | { readonly ok: false; readonly reason: ControlAnchorRejection } {
  if (snapshot.ownerSid === SYSTEM_SID) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_IS_SYSTEM };
  }
  if (snapshot.ownerSid !== operator.sid) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OWNER_MISMATCH };
  }
  if (snapshot.daclState !== 'PRESENT') {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.DACL_ABSENT };
  }
  if (snapshot.aces.length === 0) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.NO_ENTRIES };
  }
  let operatorPresent = false;
  let systemPresent = false;
  for (const ace of snapshot.aces) {
    if (ace.sid === operator.sid) {
      operatorPresent = true;
    } else if (ace.sid === SYSTEM_SID) {
      systemPresent = true;
    } else {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.FOREIGN_PRINCIPAL };
    }
  }
  if (!operatorPresent) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.RUNTIME_PRINCIPAL_ABSENT };
  }
  if (!systemPresent) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SYSTEM_PRINCIPAL_ABSENT };
  }
  return { ok: true };
}

/** One path component's `lstat` view; `null` when it could not be read. */
export interface PathProbe {
  readonly isSymbolicLink: boolean;
  readonly isReparsePoint: boolean;
}

export type LstatProbe = (path: string) => PathProbe | null;

/** Enumerate a path's ancestors, root-first, bounded by {@link MAX_PATH_DEPTH}. */
export function enumeratePathComponents(anchorPath: string): string[] {
  const components: string[] = [];
  let current = resolve(anchorPath);
  for (let depth = 0; depth < MAX_PATH_DEPTH; depth += 1) {
    components.push(current);
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  components.reverse();
  return components;
}

/**
 * Reject the path if any component is unreadable or a symlink/reparse point.
 * Fails closed: an unreadable component is treated as a rejection, not absence.
 */
export function evaluatePathSafety(
  components: readonly string[],
  probe: LstatProbe,
): { readonly ok: true } | { readonly ok: false; readonly reason: ControlAnchorRejection } {
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    if (component === undefined) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.COMPONENT_UNREADABLE };
    }
    const info = probe(component);
    if (info === null) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.COMPONENT_UNREADABLE };
    }
    if (info.isSymbolicLink || info.isReparsePoint) {
      return { ok: false, reason: CONTROL_ANCHOR_REJECTION.REPARSE_POINT };
    }
  }
  return { ok: true };
}

/* ------------------------------------------------------------------ *
 * OS adapters (execFile / fs) — narrow and injectable
 * ------------------------------------------------------------------ */

export type ProcessResult =
  | { readonly ok: true; readonly stdout: string }
  | { readonly ok: false };

/** Runs one absolute executable with an explicit argv; never a shell. */
export type ProcessRunner = (exe: string, args: readonly string[]) => Promise<ProcessResult>;

/**
 * The production process runner: `child_process.execFile`, `shell:false`,
 * absolute exe path (no PATH lookup, no PowerShell, no cmd), explicit trusted
 * argv and cwd, controlled minimal environment, finite timeout, bounded output,
 * and a required exit code 0.
 */
export function defaultProcessRunner(systemRoot: string): ProcessRunner {
  const system32 = join(systemRoot, 'System32');
  return (exe: string, args: readonly string[]): Promise<ProcessResult> =>
    new Promise<ProcessResult>((resolvePromise) => {
      execFile(
        exe,
        [...args],
        {
          cwd: system32,
          env: { SystemRoot: systemRoot, windir: systemRoot },
          timeout: PROCESS_TIMEOUT_MS,
          maxBuffer: PROCESS_MAX_BUFFER,
          windowsHide: true,
          shell: false,
          encoding: 'utf8',
        },
        (error: unknown, stdout: string) => {
          if (error !== null && error !== undefined) {
            resolvePromise({ ok: false });
            return;
          }
          resolvePromise({ ok: true, stdout });
        },
      );
    });
}

/** The production `lstat` probe. Detects a symlink; other reparse tags are not distinguished. */
export function defaultLstatProbe(path: string): PathProbe | null {
  try {
    const stats = lstatSync(path);
    return { isSymbolicLink: stats.isSymbolicLink(), isReparsePoint: false };
  } catch {
    return null;
  }
}

/**
 * Absolute path of `whoami.exe` — the only hardcoded system executable. The
 * build-provenanced owner+DACL helper is the one other executable, but its
 * filename is read from generated build metadata (never a source literal).
 */
function whoamiPath(systemRoot: string): string {
  return join(systemRoot, 'System32', 'whoami.exe');
}

/* ------------------------------------------------------------------ *
 * Owner + DACL snapshot gate — the build-provenanced read-only executable
 * ------------------------------------------------------------------ *
 *
 * The path scan proves the anchor is reached without a symlink/reparse; it does
 * not prove who owns or may access the anchor. Decision 062 Amendment B closes
 * that gap with ONE snapshot: the anchor OWNER SID must equal the exact runtime
 * operator SID (SYSTEM is an allowed DACL principal but never an allowed owner,
 * because an owner can rewrite the DACL), and the protected, file-inheritable
 * DACL principals must be exactly operator + SYSTEM by canonical SID.
 *
 * The snapshot is read by a single, minimal, source-in-repo native helper built
 * from reviewed C by the trusted Windows build (`tools/control-owner/`). Its
 * identity and integrity are rooted in GENERATED BUILD METADATA — the helper's
 * filename and the SHA-256 of the exact compiled binary — emitted as a built JS
 * module beside the binary and loaded module-relative here. There is no committed
 * hash literal, no `.sha256` sidecar, and no env/argv/registry/network authority.
 * Before the helper is ever executed its bytes are hashed and compared to that
 * expected hash; any absence, mismatch, query failure, or non-canonical result
 * fails closed. Together with `whoami` this is two executables, and no more.
 */

/** The build-generated provenance of the owner helper (its trust root). */
export interface OwnerHelperProvenance {
  readonly filename: string;
  readonly sha256: string;
}

/** Injection seams for the owner gate; production defaults use the real build output. */
export interface OwnerVerifierDeps {
  readonly loadProvenance?: () => Promise<OwnerHelperProvenance | null>;
  readonly resolveHelperPath?: (filename: string) => string;
  readonly readHelperBytes?: (helperPath: string) => Buffer | null;
  readonly hashBytes?: (bytes: Buffer) => string;
}

export type AnchorSnapshotVerification =
  | { readonly ok: true; readonly ownerSid: string }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

export type DescriptorAclVerification =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

/** A lowercase 64-hex SHA-256 digest. */
const HELPER_SHA256_PATTERN = /^[0-9a-f]{64}$/;
/** A safe helper basename: no path separators, drive letters, or traversal. */
const HELPER_FILENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** A single canonical SID and nothing else. */
const CANONICAL_SID_PATTERN = /^S-1-\d+(?:-\d+)+$/;

/** SHA-256 of bytes as lowercase hex. */
function sha256Hex(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Constant-time equality of two same-form lowercase hex digests. */
function digestsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  try {
    return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Load the generated owner-helper provenance module that the trusted build wrote
 * beside the binary (module-relative to this compiled runtime). Any failure or
 * shape violation yields `null`, which the caller treats as fail-closed.
 */
async function defaultLoadProvenance(): Promise<OwnerHelperProvenance | null> {
  try {
    const href = new URL('./native/owner-helper-provenance.js', import.meta.url).href;
    const loaded = (await import(href)) as unknown;
    if (typeof loaded !== 'object' || loaded === null) {
      return null;
    }
    const provenance = (loaded as { OWNER_HELPER_PROVENANCE?: unknown }).OWNER_HELPER_PROVENANCE;
    if (typeof provenance !== 'object' || provenance === null) {
      return null;
    }
    const record = provenance as { filename?: unknown; sha256?: unknown };
    if (typeof record.filename !== 'string' || typeof record.sha256 !== 'string') {
      return null;
    }
    return { filename: record.filename, sha256: record.sha256 };
  } catch {
    return null;
  }
}

/** Resolve the helper's absolute path from the trusted runtime module location. */
function defaultResolveHelperPath(filename: string): string {
  return fileURLToPath(new URL(`./native/${filename}`, import.meta.url));
}

/** Read the helper's exact bytes, or `null` if it is absent/unreadable. */
function defaultReadHelperBytes(helperPath: string): Buffer | null {
  try {
    return readFileSync(helperPath);
  } catch {
    return null;
  }
}

/**
 * Parse the helper's stdout as exactly one canonical SID, normalized. Any extra
 * output, extra lines, or non-canonical text fails closed (`null`).
 */
export function parseOwnerHelperSid(stdout: string): string | null {
  const trimmed = stdout.replace(/\r?\n$/, '');
  if (!CANONICAL_SID_PATTERN.test(trimmed)) {
    return null;
  }
  return normalizePrincipal(trimmed);
}

/**
 * Verify the anchor OWNER + DACL from a single canonical snapshot, fail-closed.
 * The helper is resolved module-relative, hash-verified against generated
 * provenance, then run read-only via the supplied bounded runner with exactly the
 * `--acl <anchor-path>` arguments. Its output is parsed totally (canonical SIDs
 * only) and evaluated: the OWNER must be the exact operator SID (SYSTEM and any
 * foreign owner rejected), and the DACL must be protected, present/non-NULL,
 * exactly operator + SYSTEM by SID, direct and file-inheritable, with the operator
 * present. A display name can never satisfy any comparison.
 */
export async function verifyAnchorSnapshot(
  operator: OperatorIdentity,
  anchorPath: string,
  runProcess: ProcessRunner,
  deps: OwnerVerifierDeps = {},
): Promise<AnchorSnapshotVerification> {
  const provenance = await (deps.loadProvenance ?? defaultLoadProvenance)();
  if (
    provenance === null ||
    !HELPER_SHA256_PATTERN.test(provenance.sha256) ||
    !HELPER_FILENAME_PATTERN.test(provenance.filename)
  ) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING };
  }

  const helperPath = (deps.resolveHelperPath ?? defaultResolveHelperPath)(provenance.filename);
  const bytes = (deps.readHelperBytes ?? defaultReadHelperBytes)(helperPath);
  if (bytes === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_MISSING };
  }

  const actualHash = (deps.hashBytes ?? sha256Hex)(bytes);
  if (!digestsEqual(actualHash, provenance.sha256)) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH };
  }

  const query = await runProcess(helperPath, ['--acl', anchorPath]);
  if (!query.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_QUERY_FAILED };
  }

  const snapshot = parseAclSnapshot(query.stdout);
  if (snapshot === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED };
  }

  const evaluation = evaluateAnchorSnapshot(operator, snapshot);
  if (!evaluation.ok) {
    return { ok: false, reason: evaluation.reason };
  }
  return { ok: true, ownerSid: snapshot.ownerSid };
}

/** Verify one created descriptor through the same provenanced ACL snapshot path. */
export async function verifyDescriptorSnapshot(
  operator: OperatorIdentity,
  descriptorPath: string,
  runProcess: ProcessRunner,
  deps: OwnerVerifierDeps = {},
): Promise<DescriptorAclVerification> {
  const provenance = await (deps.loadProvenance ?? defaultLoadProvenance)();
  if (
    provenance === null ||
    !HELPER_SHA256_PATTERN.test(provenance.sha256) ||
    !HELPER_FILENAME_PATTERN.test(provenance.filename)
  ) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_PROVENANCE_MISSING };
  }

  const helperPath = (deps.resolveHelperPath ?? defaultResolveHelperPath)(provenance.filename);
  const bytes = (deps.readHelperBytes ?? defaultReadHelperBytes)(helperPath);
  if (bytes === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_MISSING };
  }
  const actualHash = (deps.hashBytes ?? sha256Hex)(bytes);
  if (!digestsEqual(actualHash, provenance.sha256)) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.HELPER_HASH_MISMATCH };
  }

  const query = await runProcess(helperPath, ['--acl', descriptorPath]);
  if (!query.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_QUERY_FAILED };
  }
  const snapshot = parseAclSnapshot(query.stdout);
  if (snapshot === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.SNAPSHOT_MALFORMED };
  }
  return evaluateDescriptorSnapshot(operator, snapshot);
}

/** Resolve the operator and verify the created descriptor's actual ACL read-only. */
export async function verifyDescriptorAcl(
  descriptorPath: string,
  deps: VerifyControlAnchorDeps = {},
): Promise<DescriptorAclVerification> {
  const env = deps.env ?? process.env;
  const systemRoot = deps.systemRoot ?? env['SystemRoot'] ?? 'C:\\Windows';
  const runProcess = deps.runProcess ?? defaultProcessRunner(systemRoot);
  const whoami = await runProcess(whoamiPath(systemRoot), ['/user']);
  if (!whoami.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.WHOAMI_FAILED };
  }
  const operator = parseWhoamiUser(whoami.stdout);
  if (operator === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OPERATOR_UNREADABLE };
  }
  return verifyDescriptorSnapshot(operator, descriptorPath, runProcess, deps.owner);
}

export interface VerifyControlAnchorDeps {
  readonly env?: NodeJS.ProcessEnv;
  readonly anchorPath?: string;
  readonly systemRoot?: string;
  readonly runProcess?: ProcessRunner;
  readonly lstat?: LstatProbe;
  readonly owner?: OwnerVerifierDeps;
}

export type ControlAnchorVerification =
  | { readonly ok: true; readonly anchorPath: string }
  | { readonly ok: false; readonly reason: ControlAnchorRejection };

/**
 * Verify the control anchor end to end, read-only and fail-closed. Never mutates
 * ACLs and never creates the directory. Uses only the two authorized read-only
 * subprocesses (whoami and the build-provenanced owner+DACL helper) and `lstat`.
 */
export async function verifyControlAnchor(
  deps: VerifyControlAnchorDeps = {},
): Promise<ControlAnchorVerification> {
  const env = deps.env ?? process.env;
  const anchorPath = deps.anchorPath ?? resolveControlAnchorPath(env);
  if (anchorPath === null || anchorPath.trim().length === 0) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.ANCHOR_PATH_UNRESOLVED };
  }
  const systemRoot = deps.systemRoot ?? env['SystemRoot'] ?? 'C:\\Windows';
  const runProcess = deps.runProcess ?? defaultProcessRunner(systemRoot);
  const lstat = deps.lstat ?? defaultLstatProbe;

  // 1. No symlink/reparse component on the path to the anchor.
  const pathSafety = evaluatePathSafety(enumeratePathComponents(anchorPath), lstat);
  if (!pathSafety.ok) {
    return { ok: false, reason: pathSafety.reason };
  }

  // 2. Current operator identity (the trusted operator SID, from whoami /user).
  const whoami = await runProcess(whoamiPath(systemRoot), ['/user']);
  if (!whoami.ok) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.WHOAMI_FAILED };
  }
  const operator = parseWhoamiUser(whoami.stdout);
  if (operator === null) {
    return { ok: false, reason: CONTROL_ANCHOR_REJECTION.OPERATOR_UNREADABLE };
  }

  // 3. One canonical OWNER + DACL snapshot from the build-provenanced helper is
  //    the single security truth source: the OWNER must be the exact operator SID
  //    (SYSTEM/foreign owner rejected), and the DACL must be exactly operator +
  //    SYSTEM by canonical SID, protected, present/non-NULL, direct and
  //    file-inheritable, with the operator present.
  const snapshot = await verifyAnchorSnapshot(operator, anchorPath, runProcess, deps.owner);
  if (!snapshot.ok) {
    return { ok: false, reason: snapshot.reason };
  }

  return { ok: true, anchorPath };
}

/* ------------------------------------------------------------------ *
 * Descriptor file I/O — write only after verification
 * ------------------------------------------------------------------ */

export interface DescriptorFileDeps {
  readonly readFile?: (path: string) => string;
  readonly writeFile?: (path: string, data: string) => void;
  readonly removeFile?: (path: string) => void;
}

function defaultReadFile(path: string): string {
  return readFileSync(path, { encoding: 'utf8' });
}
function defaultWriteFile(path: string, data: string): void {
  writeFileSync(path, data, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}
function defaultRemoveFile(path: string): void {
  unlinkSync(path);
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}

/**
 * Exclusively create the descriptor inside the already verified anchor. `wx`
 * makes an unexpected existing pathname fatal instead of overwriting a file
 * whose old Windows DACL would survive. Throws on every I/O failure.
 */
export function writeDescriptorFile(
  anchorPath: string,
  descriptor: RuntimeDescriptor,
  deps: DescriptorFileDeps = {},
): void {
  const write = deps.writeFile ?? defaultWriteFile;
  write(descriptorPathFor(anchorPath), serializeDescriptor(descriptor));
}

/** Read and validate the current descriptor, or `null` if absent/malformed. */
export function readDescriptorFile(
  anchorPath: string,
  deps: DescriptorFileDeps = {},
): { readonly descriptor: RuntimeDescriptor; readonly token: Buffer } | null {
  const read = deps.readFile ?? defaultReadFile;
  let text: string;
  try {
    text = read(descriptorPathFor(anchorPath));
  } catch {
    return null;
  }
  return parseDescriptor(text);
}

/** Best-effort removal of the descriptor (orderly shutdown / failure cleanup). */
export function removeDescriptorFile(anchorPath: string, deps: DescriptorFileDeps = {}): void {
  const remove = deps.removeFile ?? defaultRemoveFile;
  try {
    remove(descriptorPathFor(anchorPath));
  } catch {
    // Best-effort only; a missing or locked descriptor is not fatal here.
  }
}

/**
 * Remove a stale descriptor before startup. Absence is success; every other
 * unlink failure is fatal so a fresh token can never overwrite stale ACL state.
 */
export function removeStaleDescriptorFile(
  anchorPath: string,
  deps: DescriptorFileDeps = {},
): boolean {
  const remove = deps.removeFile ?? defaultRemoveFile;
  try {
    remove(descriptorPathFor(anchorPath));
    return true;
  } catch (error: unknown) {
    return isErrnoException(error) && error.code === 'ENOENT';
  }
}
