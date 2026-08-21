/**
 * The repair job authority envelope (Cockpit C1).
 *
 * A repair job is a **bounded capability envelope**: the complete statement of
 * what a future Cockpit execution layer may be authorized to do on behalf of one
 * bounded autonomous repair, and nothing else.
 *
 *     trusted job configuration + exact operation operands -> authority
 *
 * Nothing here executes. There is no filesystem, no git, no subprocess, no
 * network, no clock, no persistence, and no identifier generation. This module
 * models and validates; `job-authorization.ts` decides.
 *
 * ## The V1 read-only boundary is preserved
 *
 * The frozen V1 architecture keeps managed repositories read-only from
 * AgentBridge, and C1 does not change that. It states the *shape* a narrowly
 * scoped write authority would have to take before any such capability is
 * built. Outside a valid repair-job authorization envelope the existing
 * read-only boundary is untouched, and inside one nothing is granted that the
 * envelope does not name exactly.
 *
 * ## Authority comes from configuration, never from the requester
 *
 * The job is **trusted configuration**, supplied by an operator-controlled
 * boundary that does not exist yet. The operation request is **untrusted**.
 * Agent identity, provider name, rationale, prose, metadata, claimed success,
 * and privileged-sounding labels cannot appear in this envelope at all: there is
 * no field typed to accept them, so there is nothing for a widening value to
 * flow into.
 *
 * `repairAgentId` and `findingSource` are recorded for audit and are inert as
 * authority. Naming an agent `root`, `system`, `admin`, or
 * `agentbridge-internal` changes no outcome anywhere in C1.
 *
 * ## Relationship to the existing layers
 *
 * PR 002's taxonomy, PR 003's policy gate, PR 004's freshness kernel, PR 005's
 * review ingestion, and PR 006's invocation boundary are unchanged and
 * un-imported. C1 sits beside them: it answers "what may *this job* do?", not
 * "what is this action?" (PR 002/003), "is this evidence current?" (PR 004), or
 * "what did a reviewer or agent say?" (PR 005/006).
 *
 * This module is self-contained on purpose and imports nothing, following the
 * boundary-independence convention recorded in PR 006. The three other C1
 * modules import their hostile-input readers from here because they are one
 * boundary, not four.
 */

/**
 * Intrinsics captured at module load, before any untrusted property access is
 * possible. A hostile getter or Proxy trap runs mid-validation and could
 * otherwise repoint the prototype methods this module would rely on afterwards.
 * Same pattern as PR 004, PR 005, and PR 006.
 */
const objectFreeze = Object.freeze;
const objectDefineProperty = Object.defineProperty;
const objectHasOwn = Object.hasOwn;
const arrayIsArray = Array.isArray;
const numberIsInteger = Number.isInteger;
const reflectApply = Reflect.apply;
// Captured unbound on purpose and invoked through `Reflect.apply`, so neither a
// poisoned prototype method nor a poisoned `Function.prototype.call` is on the
// path. `this` is supplied explicitly at every call site.
/* eslint-disable @typescript-eslint/unbound-method */
const stringTrim = String.prototype.trim;
const stringCharCodeAt = String.prototype.charCodeAt;
/* eslint-enable @typescript-eslint/unbound-method */

/** Membership test that touches no prototype method. */
export function containsValue(list: readonly string[], value: unknown): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === value) {
      return true;
    }
  }
  return false;
}

/** Append by defining an own element, bypassing inherited index setters. */
export function append<T>(list: T[], value: T): void {
  objectDefineProperty(list, list.length, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Read one **own** property of an untrusted object.
 *
 * Own-only on purpose: an inherited property — including one planted on
 * `Object.prototype` via a `__proto__` payload — must never supply a value the
 * caller did not actually send. Reads are guarded because an own getter or a
 * Proxy trap may throw.
 */
export function readOwnProperty(target: object, key: string): unknown {
  try {
    if (!objectHasOwn(target, key)) {
      return undefined;
    }
    return (target as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/**
 * Absence marker for {@link readOwnElement}.
 *
 * A bare object literal, so producing it calls no global function: this module
 * captures every intrinsic it relies on at load, and a sentinel is not a reason
 * to add a fresh dependency on a mutable global. It is used only through
 * reference identity, never inspected, and never frozen because nothing reads
 * it.
 *
 * The claim is exactly this and no more: **the reference is module-private.**
 * It is not exported and no entry point returns it, so it is not among the
 * values a caller ordinarily has to hand. That is why `undefined` was not used
 * instead — `undefined` is also a legitimate, and rejected, element *value*,
 * and an authorization list must refuse a missing element on its own rather
 * than depend on the element reader to refuse whatever turned up.
 */
const NO_OWN_ELEMENT = {};

/**
 * Read one **own** indexed element of an untrusted array.
 *
 * The same own-only discipline as {@link readOwnProperty}, through the same
 * captured `Object.hasOwn`, except that absence is reported as
 * {@link NO_OWN_ELEMENT} instead of collapsing into `undefined`.
 *
 * An ordinary `elements[index]` walks the prototype chain, so at a sparse hole
 * it resolves whatever a custom array prototype — or `Array.prototype` itself —
 * carries at that numeric key. Provenance is what decides authority here, not
 * the value's shape: an inherited entry can be a perfectly well-formed
 * repository path or a genuine command class, and a value nobody put in the
 * operator's array is still not authorization.
 *
 * **What this proves, exactly:** for any array whose own-property introspection
 * is truthful — every ordinary array, however its prototype chain is arranged —
 * a sparse hole and an inherited numeric property are both refused, because
 * `Object.hasOwn` answers `false` and the index is never read at all.
 *
 * **What it does not prove**, and must not be claimed to: that a value which
 * survives came from a real own element. A Proxy *defines* the observable
 * result of both operations, so one whose `getOwnPropertyDescriptor` trap
 * claims an index is own while the read forwards through the target's
 * prototype will pass an inherited value through. There is one own check and
 * one read, and nothing re-validates afterwards — but they are two separate
 * observations, not one atomic one, and a Proxy may answer them
 * inconsistently. C1 takes an object's own-property report at face value and
 * establishes provenance no further than that report. This grants no authority
 * a caller did not already have: anyone able to supply such a Proxy can supply
 * the same value as a dense own element instead, which is not an attack but a
 * configuration.
 *
 * Both operations are guarded, because a getter or a Proxy trap may throw.
 * Either way the answer is absence, never an exception.
 */
function readOwnElement(elements: object, index: number): unknown {
  try {
    if (!objectHasOwn(elements, index)) {
      return NO_OWN_ELEMENT;
    }
    return (elements as Record<number, unknown>)[index];
  } catch {
    return NO_OWN_ELEMENT;
  }
}

/** V1 bounds. Every unbounded dimension is capped before iteration. */
export const JOB_BOUNDS = objectFreeze({
  /**
   * Characters permitted in any identifier-shaped field. Oversize **rejects**.
   *
   * Matches PR 005's and PR 006's identifier bound by convention, because a
   * `jobId` may be correlated with an `invocationId` across boundaries. A test
   * pins the equality; the modules share no code.
   */
  MAX_IDENTIFIER_LENGTH: 256,
  /** Characters permitted in a repository-relative path. Oversize rejects. */
  MAX_PATH_LENGTH: 1_024,
  /** Entries permitted in `authorizedPaths`. Oversize rejects the whole job. */
  MAX_AUTHORIZED_PATHS: 512,
  /** Segments permitted in one path. Oversize rejects the path. */
  MAX_PATH_SEGMENTS: 64,
  /** Entries permitted in `authorizedCommandClasses`. */
  MAX_AUTHORIZED_COMMAND_CLASSES: 16,
} as const);

/**
 * Verification command **classes**.
 *
 * C1 never authorizes a shell command string. It authorizes a class, and a
 * later execution layer resolves a class to a concrete command through
 * repository policy. There is no field on this boundary that can carry a
 * command line, an argument vector, an environment, or a shell.
 *
 * The five members mirror the verification actions PR 002 already classifies
 * read-only (`test.run`, `lint.run`, `typecheck.run`, `build.run`,
 * `audit.run`). C1 does not import that taxonomy — a class here is an
 * authorization label, not an action kind — but the vocabularies are kept
 * aligned so the two layers cannot disagree about what verification means.
 */
export const VERIFICATION_COMMAND_CLASS = objectFreeze({
  TEST: 'test',
  LINT: 'lint',
  TYPECHECK: 'typecheck',
  BUILD: 'build',
  AUDIT: 'audit',
} as const);

export type VerificationCommandClass =
  (typeof VERIFICATION_COMMAND_CLASS)[keyof typeof VERIFICATION_COMMAND_CLASS];

/** Every member of the {@link VerificationCommandClass} union. */
export const VERIFICATION_COMMAND_CLASSES: readonly VerificationCommandClass[] = objectFreeze([
  VERIFICATION_COMMAND_CLASS.TEST,
  VERIFICATION_COMMAND_CLASS.LINT,
  VERIFICATION_COMMAND_CLASS.TYPECHECK,
  VERIFICATION_COMMAND_CLASS.BUILD,
  VERIFICATION_COMMAND_CLASS.AUDIT,
]);

/** Type guard: is this untrusted value a modeled verification command class? */
export function isVerificationCommandClass(value: unknown): value is VerificationCommandClass {
  return typeof value === 'string' && containsValue(VERIFICATION_COMMAND_CLASSES, value);
}

/**
 * Read an exact identifier, rejecting rather than aliasing an oversized value.
 *
 * **Identifiers reject; nothing here truncates.** C1 has no prose field at all,
 * so it has no field that is ever cut. A truncated identifier is worse than no
 * identifier: git resolves commit prefixes, so a cut SHA can falsely match a
 * real object, and a cut branch name can name a different ref entirely.
 *
 * The value is returned exactly as supplied, never trimmed. Normalising before
 * storing would let `" main"` and `"main"` become the same ref on a boundary
 * where exactness is the whole point.
 */
export function readExactIdentifier(value: unknown): string | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > JOB_BOUNDS.MAX_IDENTIFIER_LENGTH
  ) {
    return null;
  }
  const trimmed: unknown = reflectApply(stringTrim, value, []);
  return typeof trimmed === 'string' && trimmed.length > 0 ? value : null;
}

/** Character code at `index`, or `-1` if the read is unusable. */
function charCodeAt(value: string, index: number): number {
  const code: unknown = reflectApply(stringCharCodeAt, value, [index]);
  return typeof code === 'number' && numberIsInteger(code) ? code : -1;
}

const CODE_SLASH = 0x2f;
const CODE_BACKSLASH = 0x5c;
const CODE_COLON = 0x3a;
const CODE_DOT = 0x2e;
const CODE_TILDE = 0x7e;
const CODE_DELETE = 0x7f;
const CODE_SPACE = 0x20;
const CODE_HYPHEN = 0x2d;
const CODE_UNDERSCORE = 0x5f;
const CODE_DIGIT_0 = 0x30;
const CODE_DIGIT_9 = 0x39;
const CODE_UPPER_A = 0x41;
const CODE_UPPER_Z = 0x5a;
const CODE_LOWER_A = 0x61;
const CODE_LOWER_Z = 0x7a;

/** Is `value[start, end)` the segment `.git`, in any ASCII case? */
function isDotGitSegment(value: string, start: number, end: number): boolean {
  if (end - start !== 4) {
    return false;
  }
  if (charCodeAt(value, start) !== CODE_DOT) {
    return false;
  }
  // 0x20 folds ASCII upper case to lower case; only these three positions matter.
  const g = charCodeAt(value, start + 1) | 0x20;
  const i = charCodeAt(value, start + 2) | 0x20;
  const t = charCodeAt(value, start + 3) | 0x20;
  return g === 0x67 && i === 0x69 && t === 0x74;
}

/**
 * Read a repository-relative path, failing closed on anything questionable.
 *
 * **What this proves, exactly:** the value is a string that matches a
 * conservative repository-relative shape. Authorization is then exact string
 * equality against an operator-configured path.
 *
 * **What this does not prove**, and must not be claimed to: that two equal
 * strings name the same file. A pure model cannot know about case-insensitive
 * or case-preserving filesystems, Unicode normalisation forms applied by the
 * filesystem, symbolic links, hard links, bind mounts, or junctions. A future
 * execution layer must re-verify containment against the real filesystem it is
 * about to touch; this reader narrows the input, it does not sandbox it.
 *
 * Rejected, without exception:
 *
 * - non-strings, empty strings, and values over {@link JOB_BOUNDS.MAX_PATH_LENGTH}
 * - any `.` or `..` segment, so traversal never has to be resolved
 * - a leading `/`, an empty segment (`//`), or a trailing `/`
 * - a leading `~`
 * - `\` anywhere, because this model does not know the platform's separator
 *   semantics and will not guess
 * - `:` anywhere, which removes Windows drive-absolute forms (`C:/x`) and NTFS
 *   alternate data streams (`f.txt:s`) in one rule
 * - control characters, including NUL, which truncate paths in some syscalls
 * - a `.git` segment at any depth, in any ASCII case, so the repository's own
 *   metadata, hooks, and config — and a submodule's — are unreachable even if
 *   an operator misconfigures the scope
 * - a segment with a leading space, or a trailing space or dot, because
 *   Windows strips those and two strings that compare unequal here would name
 *   one file there
 *
 * No normalisation of any kind is performed. The value is returned exactly as
 * supplied or not at all.
 */
export function readRepositoryRelativePath(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const length = value.length;
  if (length === 0 || length > JOB_BOUNDS.MAX_PATH_LENGTH) {
    return null;
  }
  if (charCodeAt(value, 0) === CODE_TILDE) {
    return null;
  }

  let segments = 0;
  let segmentStart = 0;
  for (let index = 0; index <= length; index += 1) {
    const atEnd = index === length;
    const code = atEnd ? CODE_SLASH : charCodeAt(value, index);

    if (!atEnd) {
      // An unreadable code reads as -1, which this same bound rejects.
      if (code < CODE_SPACE || code === CODE_DELETE) {
        return null;
      }
      if (code === CODE_BACKSLASH || code === CODE_COLON) {
        return null;
      }
    }

    if (code !== CODE_SLASH) {
      continue;
    }

    const segmentLength = index - segmentStart;
    if (segmentLength === 0) {
      return null;
    }
    if (segmentLength === 1 && charCodeAt(value, segmentStart) === CODE_DOT) {
      return null;
    }
    if (
      segmentLength === 2 &&
      charCodeAt(value, segmentStart) === CODE_DOT &&
      charCodeAt(value, segmentStart + 1) === CODE_DOT
    ) {
      return null;
    }
    // `.git` at any depth: the repository's own metadata, and a submodule's.
    if (isDotGitSegment(value, segmentStart, index)) {
      return null;
    }
    // Windows strips trailing spaces and dots from a path component, so
    // `a.txt ` and `a.txt` can name the same file there but compare unequal
    // here. Rejecting both edges removes the ambiguity instead of guessing
    // which platform this will eventually run on.
    const first = charCodeAt(value, segmentStart);
    const last = charCodeAt(value, index - 1);
    if (first === CODE_SPACE || last === CODE_SPACE || last === CODE_DOT) {
      return null;
    }
    segments += 1;
    if (segments > JOB_BOUNDS.MAX_PATH_SEGMENTS) {
      return null;
    }
    segmentStart = index + 1;
  }

  return value;
}

/**
 * The one accepted spelling of a branch ref.
 *
 * Fully qualified, lower case, and matched literally. Git resolves the shorthand
 * `main`, the partially qualified `heads/main`, and the fully qualified
 * `refs/heads/main` to one and the same ref, so a boundary that compares ref
 * *strings* has three spellings for one authority target unless it fixes the
 * spelling first. C1 fixes it here.
 */
const BRANCH_REF_PREFIX = 'refs/heads/';

/** Is this the code of a character C1 accepts inside a branch name? */
function isBranchNameCharacter(code: number): boolean {
  return (
    (code >= CODE_LOWER_A && code <= CODE_LOWER_Z) ||
    (code >= CODE_UPPER_A && code <= CODE_UPPER_Z) ||
    (code >= CODE_DIGIT_0 && code <= CODE_DIGIT_9) ||
    code === CODE_HYPHEN ||
    code === CODE_UNDERSCORE ||
    code === CODE_DOT
  );
}

/** Does `value` begin with the literal, case-sensitive {@link BRANCH_REF_PREFIX}? */
function hasBranchRefPrefix(value: string): boolean {
  const prefixLength = BRANCH_REF_PREFIX.length;
  if (value.length <= prefixLength) {
    return false;
  }
  for (let index = 0; index < prefixLength; index += 1) {
    // An unreadable code reads as -1 and cannot equal a prefix character.
    if (charCodeAt(value, index) !== charCodeAt(BRANCH_REF_PREFIX, index)) {
      return false;
    }
  }
  return true;
}

/** Is `value[start, end)` a segment ending in `.lock`, in any ASCII case? */
function endsWithDotLockSuffix(value: string, start: number, end: number): boolean {
  if (end - start < 5) {
    return false;
  }
  if (charCodeAt(value, end - 5) !== CODE_DOT) {
    return false;
  }
  // 0x20 folds ASCII upper case to lower case; only these four positions matter.
  const l = charCodeAt(value, end - 4) | 0x20;
  const o = charCodeAt(value, end - 3) | 0x20;
  const c = charCodeAt(value, end - 2) | 0x20;
  const k = charCodeAt(value, end - 1) | 0x20;
  return l === 0x6c && o === 0x6f && c === 0x63 && k === 0x6b;
}

/**
 * Read a branch ref in the one canonical spelling C1 accepts.
 *
 * **Why one spelling, rather than a resolver.** Git's own shorthand rules make
 * `main`, `heads/main`, and `refs/heads/main` three names for one branch, and
 * the ambiguity is not decidable from the string alone: whether `main` resolves
 * to a branch, a tag, or a remote-tracking ref depends on what exists in a
 * repository at the moment the name is used. C1 is pure TypeScript by
 * construction — it runs no git, spawns no subprocess, opens no file, and
 * observes no repository — so it cannot ask which ref a shorthand denotes, and a
 * boundary that guesses would be guessing about authority.
 *
 * So C1 does not resolve; it **narrows**. Exactly one spelling is accepted, and
 * every other spelling of the same branch is refused as malformed rather than
 * silently treated as a different ref. The property that buys is precise, and it
 * is a property of ref *names* rather than of repository state:
 *
 * > Two accepted refs are the same canonical ref name if and only if they are
 * > equal strings — up to the ASCII-case caveat below.
 *
 * That is what makes `repairBranch !== protectedParentRef` mean "two different
 * canonical ref names" instead of "two different strings", which is what closes
 * caller-controlled textual aliasing. Before this, a job configured with
 * `protectedParentRef: 'refs/heads/main'` and `repairBranch: 'main'` was accepted
 * as a quarantined repair, and a `repair.push` naming `main` passed every check
 * and produced an `ExecutionPermit` whose ref denotes the protected branch.
 *
 * Accepted, and nothing else:
 *
 * - a value that survives {@link readExactIdentifier}, so the identifier bound
 *   applies and nothing is trimmed or truncated
 * - the literal, case-sensitive prefix `refs/heads/`, followed by a non-empty
 *   name; `Refs/Heads/x`, `heads/x`, `x`, `refs/tags/x`, `refs/remotes/…`, and a
 *   bare `refs/heads/` are all refused
 * - name segments separated by single `/`, each non-empty, so `//`, a leading
 *   `/`, and a trailing `/` are refused
 * - segment characters drawn only from `A-Z`, `a-z`, `0-9`, `-`, `_`, and `.`
 * - no segment beginning or ending with `.`, no `..` anywhere, and no segment
 *   ending in `.lock` in any ASCII case — the ref-name forms git itself refuses
 *
 * The conservative character set is deliberate and is part of the guarantee.
 * Restricting names to ASCII removes Unicode normalisation entirely: without it
 * an NFC and an NFD spelling of one branch name are unequal strings that a
 * filesystem-backed loose ref can resolve to a single ref, which is the same
 * aliasing failure in a different alphabet. It also removes `~`, `^`, `:`, `?`,
 * `*`, `[`, `\`, `@{`, and whitespace — every character git rejects in a ref
 * name, plus the revision-syntax operators that make `x^{}` and `x@{1}` name
 * something other than `x`. A branch name outside this set is refused, never
 * rewritten.
 *
 * **What this does not prove**, and must not be claimed to: that two unequal
 * accepted refs are two distinct branch targets in a repository. What is proved
 * is a structural canonical ref-name representation and this module's own
 * documented string-comparison rules; repository-resolved ref identity is not
 * established here. Two residues stand:
 *
 * - **Symbolic refs.** A repository may hold a canonical-looking ref — say
 *   `refs/heads/repair` — that is itself a symbolic ref to `refs/heads/main`.
 *   Whether such a ref exists, and what it dereferences to, is repository state
 *   at the moment the name is used. C1 does not detect that a ref is symbolic,
 *   does not resolve a symbolic ref's target, and cannot tell whether two
 *   distinct canonical names ultimately dereference to one repository target.
 * - **Filesystem identity.** Git stores loose refs as files, so on a
 *   case-insensitive filesystem `refs/heads/Main` and `refs/heads/main` can be
 *   one ref while comparing unequal here. That residue is handled where it
 *   matters — {@link mayDenoteSameBranchRef} compares the job's two configured
 *   refs case-insensitively, so such a pair is refused as configuration — rather
 *   than pretended away here. C1 observes no filesystem and cannot do better
 *   than refuse the ambiguous case.
 *
 * The symbolic-ref residue is not narrowable from a string at all, and neither is
 * the effective target a mutation would reach. A later trusted repository/Git
 * execution boundary must, before acting on any authority an `ExecutionPermit`
 * records, resolve the requested ref's effective ref-name referent against the
 * actual repository — the terminal ref reached through a symbolic-ref chain, not
 * commit-object identity, since a fresh repair branch may legitimately share the
 * protected parent's commit OID — and bind each effective identity the operation
 * acts on to the authorized repair ref. A terminal ref-name spelling is not by
 * itself repository ref identity: where a repository applies its own ref-identity
 * semantics — for instance a case-insensitive ref store treating `refs/heads/Main`
 * and `refs/heads/main` as one ref — terminal names that are not equal strings may
 * still be the same repository ref, so the boundary must judge sameness or
 * distinctness under that repository's actual ref-identity semantics rather than by
 * terminal-name string (in)equality alone, and fail closed where the required
 * distinctness cannot be safely proven. A commit advances one mutation target: the
 * worktree's effective `HEAD` referent, the ref it will actually advance. A push
 * binds two effective identities in distinct roles — its destination ref, the
 * receiving/mutation target the push advances, and its source ref, the input the
 * push consumes to select what is sent — each of which must be the authorized
 * repair ref, so an absent (deletion) or redirected source is refused. It must
 * **fail closed** — refusing the
 * operation — if any such effective identity is or dereferences to the
 * protected parent, if it changes between comparison and update, or if it cannot
 * be safely established; a resolve-then-act pre-check is not itself atomic, so the
 * invariant is enforced at the boundary that actually consumes each identity — the
 * mutation/receiving boundary for a commit or push, and the
 * change-request/provider creation boundary for a change request. That refusal is
 * bound to the operand's role rather than being a blanket ban on the protected
 * parent's identity: a `repair.change_request` `targetRef` is *required* to reach
 * the protected parent ref, and fails closed when it reaches anything else. Because
 * that operation mutates no ref, the identity it consumes is bound at its provider
 * create/update request: the effective source must remain the authorized repair ref
 * and the effective target the protected parent ref through to that request. The
 * provider may resolve those ref names at its own boundary, but must not let
 * re-resolution or ambient repository state substitute a materially different
 * effective identity for either end, and the boundary must fail closed if the
 * authorized relationship cannot be maintained or shown equivalent there.
 * Nothing here acquires git invocation, filesystem access, a subprocess, or
 * network to decide it. See `docs/architecture/C1-repair-job-authority.md`,
 * "What canonical ref names do and do not prove".
 *
 * The value is returned exactly as supplied, or not at all. No normalisation,
 * no prefixing, no case folding: a boundary that repaired the spelling would be
 * choosing an authority target on the caller's behalf.
 */
export function readCanonicalBranchRef(value: unknown): string | null {
  const identifier = readExactIdentifier(value);
  if (identifier === null) {
    return null;
  }
  if (!hasBranchRefPrefix(identifier)) {
    return null;
  }

  const length = identifier.length;
  let segmentStart = BRANCH_REF_PREFIX.length;
  for (let index = segmentStart; index <= length; index += 1) {
    const atEnd = index === length;
    const code = atEnd ? CODE_SLASH : charCodeAt(identifier, index);

    if (!atEnd && code !== CODE_SLASH) {
      // An unreadable code reads as -1, which is not a name character.
      if (!isBranchNameCharacter(code)) {
        return null;
      }
      // `..` is a revision-range operator and git refuses it in a ref name.
      if (code === CODE_DOT && charCodeAt(identifier, index - 1) === CODE_DOT) {
        return null;
      }
      continue;
    }

    const segmentLength = index - segmentStart;
    if (segmentLength === 0) {
      return null;
    }
    if (charCodeAt(identifier, segmentStart) === CODE_DOT) {
      return null;
    }
    if (charCodeAt(identifier, index - 1) === CODE_DOT) {
      return null;
    }
    if (endsWithDotLockSuffix(identifier, segmentStart, index)) {
      return null;
    }
    segmentStart = index + 1;
  }

  return identifier;
}

/**
 * Could these two accepted canonical ref names collapse into one ref?
 *
 * Both arguments are already-validated canonical refs, so this is exact string
 * equality widened by one conservative allowance: ASCII case. Git stores loose
 * refs as files, and on a case-insensitive filesystem `refs/heads/Main` and
 * `refs/heads/main` can be the same ref while comparing unequal. C1 observes no
 * filesystem and cannot tell which kind it will run on, so it treats such a pair
 * as possibly-identical and the job that configures one is refused.
 *
 * Conservative in the safe direction: it answers `true` — refuse — whenever it
 * cannot establish that the two *names* are distinct, including for a character
 * it could not read at all. Only ASCII case is folded, because the canonical
 * reader admits no other alphabet.
 *
 * A `false` result means only that the two names are distinct under this rule.
 * It is **not** a finding that they denote distinct targets in a repository: this
 * compares strings and resolves nothing, so a canonical name that is a symbolic
 * ref to the other still answers `false` here, and — since two different branch
 * refs may legitimately share one commit object — commit-object equality is not
 * the question either. Repository-resolved identity — whether the effective
 * referents reached by resolving symbolic-ref chains are the same or distinct
 * under the repository's own ref-identity semantics, which a terminal ref-name
 * spelling alone does not settle — is the later trusted repository/Git execution
 * boundary's to establish; see {@link readCanonicalBranchRef}.
 */
function mayDenoteSameBranchRef(left: string, right: string): boolean {
  if (left === right) {
    return true;
  }
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    const leftCode = charCodeAt(left, index);
    const rightCode = charCodeAt(right, index);
    if (leftCode === -1 || rightCode === -1) {
      // Unreadable: cannot establish distinctness, so refuse the pair.
      return true;
    }
    const foldedLeft =
      leftCode >= CODE_UPPER_A && leftCode <= CODE_UPPER_Z ? leftCode | 0x20 : leftCode;
    const foldedRight =
      rightCode >= CODE_UPPER_A && rightCode <= CODE_UPPER_Z ? rightCode | 0x20 : rightCode;
    if (foldedLeft !== foldedRight) {
      return false;
    }
  }
  return true;
}

/**
 * Read a bounded list of untrusted values, all-or-nothing.
 *
 * One unreadable entry rejects the whole list, and an oversized list is
 * rejected rather than truncated. Silently shortening an authorization list
 * would produce a job that looks configured but is not the one an operator
 * wrote, and silently keeping a prefix of a list an operator got wrong is not
 * an improvement on refusing it.
 *
 * Every entry is obtained through {@link readOwnElement}, so a list entry can
 * only ever be one the supplied object reports as its **own**. For an ordinary
 * array that is exactly the elements the job configuration actually supplied:
 * an index with no own element is a sparse hole, and a hole rejects the whole
 * list — it is never skipped, defaulted, or filled from the prototype chain —
 * so an inherited numeric property planted on a custom array prototype or on
 * `Array.prototype` is refused however well-formed its value looks. A Proxy
 * that misreports ownership is the documented limit of that guarantee, and it
 * widens nothing; see {@link readOwnElement}.
 */
function readList<T>(
  value: unknown,
  maxLength: number,
  read: (element: unknown) => T | null,
): readonly T[] | null {
  let elements: readonly unknown[] | null;
  try {
    elements = arrayIsArray(value) ? (value as readonly unknown[]) : null;
  } catch {
    // `Array.isArray` itself throws on a revoked Proxy.
    return null;
  }
  if (elements === null) {
    return null;
  }

  let rawLength: unknown;
  try {
    rawLength = elements.length;
  } catch {
    return null;
  }
  if (
    typeof rawLength !== 'number' ||
    !numberIsInteger(rawLength) ||
    rawLength < 0 ||
    rawLength > maxLength
  ) {
    return null;
  }

  const parsed: T[] = [];
  for (let index = 0; index < rawLength; index += 1) {
    const element = readOwnElement(elements, index);
    if (element === NO_OWN_ELEMENT) {
      // A sparse hole, or an own-check or read that threw. Either way this
      // index carries no own element, so the whole list is refused.
      return null;
    }
    const value_ = read(element);
    if (value_ === null) {
      return null;
    }
    append(parsed, value_);
  }
  return objectFreeze(parsed);
}

/**
 * Trusted job configuration: the complete authority envelope of one repair job.
 *
 * Deliberately absent, and never to be added: credentials, tokens, secrets,
 * prompt or instruction payloads, command lines, shell strings, callbacks,
 * file handles, API clients, rationale, metadata bags, or any field an agent
 * could populate. There is no field typed to accept one, so no agent-generated
 * value has anywhere to land.
 *
 * Every field is required. Trusted configuration is all-or-nothing: there is no
 * partially configured job and no field that degrades silently.
 */
export interface RepairJobAuthorization {
  /** Caller-minted job identity. Exact; never generated here, never truncated. */
  readonly jobId: string;
  /** Which policy version authorized this envelope. Audit and permit identity. */
  readonly policyVersion: string;
  /** The one repository this job may ever touch. */
  readonly repositoryId: string;
  /** The protected parent feature pull request this repair is stacked under. */
  readonly parentPullRequestId: string;
  /**
   * The protected parent integration ref, in the canonical `refs/heads/<name>`
   * spelling {@link readCanonicalBranchRef} defines.
   *
   * **No job operation may ever write to it.** It appears in exactly one
   * authorizable position: as the *target* of the stacked validation change
   * request, which does not mutate it.
   */
  readonly protectedParentRef: string;
  /** The parent pull request's HEAD at the moment the job was configured. */
  readonly parentHeadSha: string;
  /** Where the finding came from. A provider-neutral label; grants nothing. */
  readonly findingSource: string;
  /** The finding this repair addresses. */
  readonly findingId: string;
  /**
   * The commit the finding was verified against.
   *
   * Must equal {@link parentHeadSha} for the job to authorize anything: a
   * repair derived from a finding about a commit that is no longer HEAD is a
   * repair of something that may no longer exist.
   */
  readonly findingHeadSha: string;
  /**
   * The isolated repair branch, in the canonical `refs/heads/<name>` spelling
   * {@link readCanonicalBranchRef} defines.
   *
   * Must be a different canonical ref name from {@link protectedParentRef}. A
   * job whose repair branch is the protected parent ref is not a quarantined
   * repair; it is a direct write to protected history wearing a repair job's
   * name, and it is rejected as malformed configuration rather than evaluated.
   *
   * "Different branch ref", not "different string": both refs are read through
   * the canonical reader, so an alternate spelling of the protected parent —
   * `main`, `heads/main` — cannot pass as an isolated repair branch, and a pair
   * that differs only by ASCII case is refused too because a case-insensitive
   * filesystem can store the two as one loose ref.
   *
   * That closes caller-controlled textual aliasing only. It does not establish
   * that the two names resolve to distinct targets in a repository — a canonical
   * repair ref that is symbolic to the parent is invisible to a pure string
   * boundary — which the later trusted repository/Git execution boundary must
   * resolve or reject before it acts on any authority a permit records. See
   * {@link readCanonicalBranchRef}.
   */
  readonly repairBranch: string;
  /** The isolated repair worktree. Filesystem-shaped operations are bound to it. */
  readonly repairWorktreeId: string;
  /**
   * Exact repository-relative paths this job may read or edit.
   *
   * A list of exact paths, not a prefix, glob, or directory. Directory
   * authority would require normalisation and containment guarantees this pure
   * model cannot prove, and a `src/a` versus `src/ab` prefix boundary is a
   * classic escape. An empty list is legitimate: it describes a
   * verification-only job.
   */
  readonly authorizedPaths: readonly string[];
  /** Verification classes this job may run. An empty list is legitimate. */
  readonly authorizedCommandClasses: readonly VerificationCommandClass[];
  /** The agent performing the repair. Audit only; never authority. */
  readonly repairAgentId: string;
  /**
   * The validator that must independently validate this repair.
   *
   * Must differ from {@link repairAgentId}. A repair agent that is also its own
   * validator defeats the quarantine the whole pipeline exists to enforce, so
   * the job is rejected as malformed configuration.
   */
  readonly independentValidatorId: string;
}

/**
 * Every job field, in declaration order.
 *
 * Invalid-field reporting walks this order, so the result is deterministic.
 */
export const REPAIR_JOB_FIELD_ORDER = objectFreeze([
  'jobId',
  'policyVersion',
  'repositoryId',
  'parentPullRequestId',
  'protectedParentRef',
  'parentHeadSha',
  'findingSource',
  'findingId',
  'findingHeadSha',
  'repairBranch',
  'repairWorktreeId',
  'authorizedPaths',
  'authorizedCommandClasses',
  'repairAgentId',
  'independentValidatorId',
] as const);

export type RepairJobField = (typeof REPAIR_JOB_FIELD_ORDER)[number];

/**
 * A validated, frozen copy of a job's authority envelope.
 *
 * Authorization reads only a snapshot, never the caller's object. A getter or
 * Proxy trap on the configuration cannot therefore validate one repository,
 * branch, or path list and have a different one reach the decision or the
 * permit.
 */
export interface RepairJobSnapshot {
  readonly jobId: string;
  readonly policyVersion: string;
  readonly repositoryId: string;
  readonly parentPullRequestId: string;
  readonly protectedParentRef: string;
  readonly parentHeadSha: string;
  readonly findingSource: string;
  readonly findingId: string;
  readonly findingHeadSha: string;
  readonly repairBranch: string;
  readonly repairWorktreeId: string;
  readonly authorizedPaths: readonly string[];
  readonly authorizedCommandClasses: readonly VerificationCommandClass[];
  readonly repairAgentId: string;
  readonly independentValidatorId: string;
}

/** The outcome of reading a job envelope exactly once. */
export interface RepairJobReadResult {
  /** The frozen snapshot, or `null` when any field is invalid. */
  readonly snapshot: RepairJobSnapshot | null;
  /** Invalid field names in {@link REPAIR_JOB_FIELD_ORDER} order. */
  readonly invalidFields: readonly RepairJobField[];
}

const ALL_JOB_FIELDS_INVALID: RepairJobReadResult = objectFreeze({
  snapshot: null,
  invalidFields: REPAIR_JOB_FIELD_ORDER,
});

/**
 * Read and validate a job envelope, in a single pass, exactly once per field.
 *
 * Pure, total, and deterministic; never throws. This is the only validator:
 * {@link findInvalidRepairJobFields} and the authorization evaluator both go
 * through it, so there is no second implementation to drift.
 *
 * Every security-relevant value is read once into a local and never re-read, so
 * a getter or Proxy that returns a different value on each access cannot
 * validate one operand and hand a different one to the decision.
 */
export function readRepairJobAuthorization(job: RepairJobAuthorization): RepairJobReadResult {
  const record: unknown = job;
  if (typeof record !== 'object' || record === null) {
    return ALL_JOB_FIELDS_INVALID;
  }

  const jobId = readExactIdentifier(readOwnProperty(record, 'jobId'));
  const policyVersion = readExactIdentifier(readOwnProperty(record, 'policyVersion'));
  const repositoryId = readExactIdentifier(readOwnProperty(record, 'repositoryId'));
  const parentPullRequestId = readExactIdentifier(readOwnProperty(record, 'parentPullRequestId'));
  const protectedParentRef = readCanonicalBranchRef(
    readOwnProperty(record, 'protectedParentRef'),
  );
  const parentHeadSha = readExactIdentifier(readOwnProperty(record, 'parentHeadSha'));
  const findingSource = readExactIdentifier(readOwnProperty(record, 'findingSource'));
  const findingId = readExactIdentifier(readOwnProperty(record, 'findingId'));
  const findingHeadSha = readExactIdentifier(readOwnProperty(record, 'findingHeadSha'));
  const repairBranch = readCanonicalBranchRef(readOwnProperty(record, 'repairBranch'));
  const repairWorktreeId = readExactIdentifier(readOwnProperty(record, 'repairWorktreeId'));
  const authorizedPaths = readList(
    readOwnProperty(record, 'authorizedPaths'),
    JOB_BOUNDS.MAX_AUTHORIZED_PATHS,
    readRepositoryRelativePath,
  );
  const authorizedCommandClasses = readList(
    readOwnProperty(record, 'authorizedCommandClasses'),
    JOB_BOUNDS.MAX_AUTHORIZED_COMMAND_CLASSES,
    (element: unknown) => (isVerificationCommandClass(element) ? element : null),
  );
  const repairAgentId = readExactIdentifier(readOwnProperty(record, 'repairAgentId'));
  const independentValidatorId = readExactIdentifier(
    readOwnProperty(record, 'independentValidatorId'),
  );

  const invalidFields: RepairJobField[] = [];
  if (jobId === null) {
    append(invalidFields, 'jobId');
  }
  if (policyVersion === null) {
    append(invalidFields, 'policyVersion');
  }
  if (repositoryId === null) {
    append(invalidFields, 'repositoryId');
  }
  if (parentPullRequestId === null) {
    append(invalidFields, 'parentPullRequestId');
  }
  if (protectedParentRef === null) {
    append(invalidFields, 'protectedParentRef');
  }
  if (parentHeadSha === null) {
    append(invalidFields, 'parentHeadSha');
  }
  if (findingSource === null) {
    append(invalidFields, 'findingSource');
  }
  if (findingId === null) {
    append(invalidFields, 'findingId');
  }
  if (findingHeadSha === null) {
    append(invalidFields, 'findingHeadSha');
  }
  // The repair branch must be a *different branch ref* from the protected parent
  // ref, or the isolation the whole quarantine depends on does not exist. Both
  // refs are canonical here, so unequal strings are different canonical ref names
  // — except for the ASCII-case pair a case-insensitive filesystem can collapse
  // into one loose ref, which `mayDenoteSameBranchRef` refuses as well. This is a
  // name-level check: repository-resolved identity, including a canonical ref
  // that is symbolic to the parent, is the later trusted execution boundary's.
  if (
    repairBranch === null ||
    (protectedParentRef !== null && mayDenoteSameBranchRef(repairBranch, protectedParentRef))
  ) {
    append(invalidFields, 'repairBranch');
  }
  if (repairWorktreeId === null) {
    append(invalidFields, 'repairWorktreeId');
  }
  if (authorizedPaths === null) {
    append(invalidFields, 'authorizedPaths');
  }
  if (authorizedCommandClasses === null) {
    append(invalidFields, 'authorizedCommandClasses');
  }
  if (repairAgentId === null) {
    append(invalidFields, 'repairAgentId');
  }
  // A repair agent may not be its own independent validator.
  if (independentValidatorId === null || independentValidatorId === repairAgentId) {
    append(invalidFields, 'independentValidatorId');
  }

  if (invalidFields.length > 0) {
    return objectFreeze({ snapshot: null, invalidFields: objectFreeze(invalidFields) });
  }

  // Every value above is non-null here; the narrowing is re-stated per field so
  // no assertion operator is used on a security boundary.
  if (
    jobId === null ||
    policyVersion === null ||
    repositoryId === null ||
    parentPullRequestId === null ||
    protectedParentRef === null ||
    parentHeadSha === null ||
    findingSource === null ||
    findingId === null ||
    findingHeadSha === null ||
    repairBranch === null ||
    repairWorktreeId === null ||
    authorizedPaths === null ||
    authorizedCommandClasses === null ||
    repairAgentId === null ||
    independentValidatorId === null
  ) {
    return ALL_JOB_FIELDS_INVALID;
  }

  return objectFreeze({
    snapshot: objectFreeze({
      jobId,
      policyVersion,
      repositoryId,
      parentPullRequestId,
      protectedParentRef,
      parentHeadSha,
      findingSource,
      findingId,
      findingHeadSha,
      repairBranch,
      repairWorktreeId,
      authorizedPaths,
      authorizedCommandClasses,
      repairAgentId,
      independentValidatorId,
    }),
    invalidFields: objectFreeze([] as RepairJobField[]),
  });
}

/**
 * Return the job fields that are missing or invalid, in declaration order.
 *
 * A thin view over {@link readRepairJobAuthorization}, so a caller that
 * pre-validates a job gets exactly the answer the evaluator will get.
 */
export function findInvalidRepairJobFields(
  job: RepairJobAuthorization,
): readonly RepairJobField[] {
  return readRepairJobAuthorization(job).invalidFields;
}

/**
 * An untrusted claim about who is validating a repair.
 *
 * Declared shape is advisory: at runtime every property is read defensively and
 * any type may arrive.
 */
export interface ValidatorClaim {
  readonly validatorId?: string;
  /** Read for nothing. Present here only to document that it is ignored. */
  readonly providerId?: string;
  /** Read for nothing. A claimed role is not a role. */
  readonly role?: string;
}

/**
 * Does this claim satisfy the job's independent-validator constraint?
 *
 * The **only** thing consulted is `validatorId`, compared by exact string
 * equality against the job's trusted `independentValidatorId`. A claimed role,
 * a claimed provider, and a privileged-sounding label are read by nothing.
 *
 * The repair agent is additionally excluded outright, so the constraint holds
 * even if a future change to job validation were to admit a job whose validator
 * and repair agent coincide.
 *
 * C1 implements no validation workflow. This predicate exists so a later layer
 * cannot accidentally satisfy the constraint with agent-supplied prose.
 */
export function satisfiesIndependentValidator(
  job: RepairJobAuthorization,
  claim: ValidatorClaim,
): boolean {
  const snapshot = readRepairJobAuthorization(job).snapshot;
  if (snapshot === null) {
    return false;
  }
  const record: unknown = claim;
  if (typeof record !== 'object' || record === null) {
    return false;
  }
  const validatorId = readExactIdentifier(readOwnProperty(record, 'validatorId'));
  if (validatorId === null) {
    return false;
  }
  return validatorId === snapshot.independentValidatorId && validatorId !== snapshot.repairAgentId;
}
