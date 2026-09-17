/*
 * agentbridge-win-pipe-attest.exe
 *
 * Decision 062 DDR-D062-D + AMENDMENT 1 — LIVE PIPE-OBJECT IDENTITY RELAYER,
 * ALIAS-INDEPENDENT STRUCTURAL EVIDENCE.
 *
 * The single-purpose native artifact that answers one question the runtime
 * cannot answer from JavaScript: **who owns the kernel pipe object this client
 * is connected to right now, what exactly does its DACL contain, and what did
 * that same connection say first?** It connects to a candidate pipe, reads the
 * SECURITY DESCRIPTOR of the object behind that CONNECTED handle (never from a
 * descriptor file, argv, PID file, process listing, or any caller-supplied
 * value), relays exactly one bounded server hello read from the SAME pipe
 * handle, and prints the owner, the descriptor's STRUCTURE and the hello as
 * bounded evidence.
 *
 * WHY STRUCTURE AND NOT SDDL (AMENDMENT 1). The previous revision emitted the
 * descriptor as an SDDL string and the trust layer compared that string. SDDL
 * is a RENDERING, not an identity: Windows canonicalises principals into
 * two-letter aliases (LA for RID 500, LG, BA, SY, WD, AN, DA, DU, ...) and
 * canonicalises access masks into symbolic forms (FR, FA, GA, ...). A pipe
 * owned by a RID-500 operator renders as O:LAD:P(A;;0x12019F;;;LA), which is
 * the very same descriptor and was nevertheless rejected. The comparison was
 * STRICTLY STRONGER than the invariant: it additionally demanded a particular
 * rendering. This artifact therefore emits the kernel's STRUCTURAL facts —
 * numeric SIDs and fixed-width numeric fields — in which an alias is not
 * merely unequal but UNREPRESENTABLE.
 *
 * WHY THE PIPE OBJECT AND NOT THE PROCESS OBJECT. The revision before that
 * resolved the SERVER PID, pinned it against reuse, and read that process's
 * TokenUser SID. Its terminal claim was "the serving process runs as the
 * operator SID". That layer is UNDECIDABLE for the supported ordinary
 * unelevated interactive operator: against the accepted hosting posture,
 * opening the runtime's process object refuses EVERY access right, including
 * READ_CONTROL, so the layer returns no answer at all rather than a wrong one.
 * Note that this file therefore names none of those APIs even in prose: their
 * absence from the built import table is an asserted invariant. The pipe
 * object reaches the identical claim through a kernel object the supported
 * persona CAN read, and is strictly stronger in two places: PID reuse becomes
 * structurally impossible (no PID is ever consulted), and the claim attaches
 * to the pipe NAME, whose descriptor is assigned once at first-instance
 * creation and cannot be altered by a later instance.
 *
 * It makes NO identity decision. It does not know the operator SID, does not
 * compare SIDs, does not know that 0x12019F is special, does not know that one
 * ACE is required, does not parse the hello, does not know what a verify key
 * is, and has no notion of success beyond "every structural step succeeded".
 * All authorization lives in the TypeScript trust layer that consumes this
 * evidence. Every failure is fail-closed: a nonzero exit and NO stdout bytes.
 *
 * Read-only always: it never writes a file, never mutates an ACL, never takes
 * ownership, never touches the registry, the network, the environment, stdin,
 * or any shell/child process. It opens the pipe with GENERIC_READ only and
 * never writes a byte to it, so it cannot issue a command or perturb a session.
 * It opens NO process handle and adjusts NO privilege.
 *
 *   agentbridge-win-pipe-attest.exe \\.\pipe\<name>
 *
 * Evidence grammar V3 — LF-terminated ASCII lines, in this exact order, and
 * nothing else:
 *
 *     AGENTBRIDGE-ATTEST-V3
 *     PIPEOWNER <sid>
 *     DACL <present> <protected> <count>
 *     ACE <index> <type> <flags> <mask> <trustee>      x min(count, 4)
 *     HELLO <hex>
 *
 *   - <sid> and <trustee> are canonical NUMERIC SIDs (ConvertSidToStringSidW).
 *     No account-name lookup and no alias ever happens, so the output is
 *     identical on any locale and for any principal.
 *   - <present> and <protected> are the single characters 0 or 1, taken from
 *     the descriptor's SE_DACL_PRESENT and SE_DACL_PROTECTED control bits.
 *   - <count> is the TRUE kernel ACE count, decimal, even when it exceeds the
 *     bounded number of ACE lines emitted.
 *   - <index> is decimal, ascending from 0, no gaps.
 *   - <type> and <flags> are fixed-width 2-character lowercase hex.
 *   - <mask> is fixed-width 8-character lowercase hex.
 *   - <trustee> is NONE only for object ACE types, whose layout places GUIDs
 *     before the SID so no trustee exists at the fixed offset. Such an ACE can
 *     never satisfy the accepted ACCESS_ALLOWED type, so NONE can never be
 *     accepted; it is emitted so the line keeps a fixed arity.
 *   - <hex> is the exact bytes of the server hello frame BODY (the framed
 *     payload after the 4-byte big-endian length prefix), lowercase hex, at
 *     most ATTEST_MAX_BODY bytes. The bytes are relayed verbatim.
 *
 * The grammar is self-describing: <count> precedes the repeated ACE lines, so
 * a total parser knows exactly how many to expect before reading them.
 *
 * SAME-HANDLE RULE (mandatory). The descriptor is read from the handle
 * CreateFileW already returned, and the hello is read from that same handle.
 * The pipe is NEVER reopened by name: a second open could be routed to a
 * different object if the name were re-created in between, which is precisely
 * the time-of-check/time-of-use window this design exists to close. The
 * descriptor is read BEFORE the hello, so no relayed byte can precede the
 * identity evidence it is attributed to.
 *
 * ORDERING NOTE. Reading the descriptor first is also why no re-proof loop is
 * needed where an earlier revision required three: an NPFS pipe's security
 * descriptor is fixed for the lifetime of the pipe NAME, assigned when the
 * first instance is created, and a later instance's SECURITY_ATTRIBUTES are
 * ignored by the kernel. Only the object's OWNER holds the implicit WRITE_DAC
 * that could change it, and an owner-SID principal is out of scope under the
 * frozen threat model.
 *
 * ELEVATION. None is required, requested, or accepted. There is no fallback
 * path, no weaker path, and no process-object path: a failed security query
 * fails closed (DDR-D062-D, rejected alternative D-R2).
 *
 * DEADLINE. The read of a live-but-silent server is bounded by the CALLER: the
 * runtime runs this artifact through its bounded process runner (finite
 * timeout, killed on overrun, nonzero => fail closed). A server that has exited
 * breaks the pipe and returns immediately rather than blocking, so the only
 * blocking case is the one the caller's deadline already covers.
 *
 * Contract (see src/control/control-store.ts):
 *   stdout on success : the evidence lines, nothing else
 *   stderr            : a short bounded diagnostic token only (no SID, no bytes)
 *   exit codes        : 0 success
 *                       1 invalid arguments
 *                       2 pipe connect failed
 *                       3 object security / ACL query failed, including an
 *                         absent or NULL DACL (nothing to enumerate)
 *                       4 SID validation or string conversion failed
 *                       5 hello read failed (framing, bounds, or short read)
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 /* Windows 10; needed for SetDefaultDllDirectories */
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define EXIT_OK 0
#define EXIT_INVALID_ARGS 1
#define EXIT_CONNECT_FAILED 2
#define EXIT_SECURITY_QUERY 3
#define EXIT_CONVERT_FAILED 4
#define EXIT_HELLO_FAILED 5

/* Windows extended maximum path length, in wide characters. */
#define ATTEST_MAX_PATH 32767

/* A canonical SID string is far shorter than this; the cap keeps output bounded. */
#define ATTEST_SID_BUF 512

/* The accepted descriptor has exactly one ACE. The bound keeps the evidence
 * finite; a larger true count is still reported honestly and is rejected by
 * the trust layer on the count alone. */
#define ATTEST_MAX_ACES 4

/* ACE_HEADER is 4 bytes; a non-object ACE places the ACCESS_MASK at offset 4
 * and the SID at offset 8. */
#define ATTEST_ACE_SID_OFFSET 8

/* The fixed head of a SID: Revision (1) + SubAuthorityCount (1) +
 * IdentifierAuthority (6). IsValidSid reads exactly this much before it can
 * judge anything, so an ACE that cannot hold this many bytes at the trustee
 * offset must never have IsValidSid pointed into it. */
#define ATTEST_MIN_SID_BYTES (sizeof(SID) - sizeof(DWORD))
_Static_assert(ATTEST_MIN_SID_BYTES == 8,
               "a SID's fixed head is Revision + SubAuthorityCount + IdentifierAuthority");

/* Mirrors MAX_BODY_BYTES in src/control/control-channel.ts. A declared length
 * outside [1, ATTEST_MAX_BODY] is a framing violation, not a large message. */
#define ATTEST_MAX_BODY 4096

/* The 4-byte big-endian length prefix of one wire frame. */
#define ATTEST_PREFIX_BYTES 4

static void emit_err(const char *token) {
  fputs(token, stderr);
  fputc('\n', stderr);
}

/* Write raw bytes to stdout with no newline translation. */
static void write_stdout(const char *bytes, size_t len) {
  (void)_setmode(_fileno(stdout), _O_BINARY);
  fwrite(bytes, 1, len, stdout);
  (void)fflush(stdout);
}

/*
 * Accept only a local named-pipe path: exactly the local pipe prefix followed
 * by at least one more character. A UNC form (\\server\pipe\...) is rejected:
 * this artifact attests a LOCAL kernel object and a remote pipe has none here.
 */
static int is_local_pipe_path(const wchar_t *p, size_t len) {
  static const wchar_t prefix[] = L"\\\\.\\pipe\\";
  const size_t prefix_len = 9; /* characters in prefix, excluding the NUL */
  if (len <= prefix_len) {
    return 0;
  }
  return wcsncmp(p, prefix, prefix_len) == 0;
}

/*
 * Read exactly `want` bytes from a blocking handle into `dst`. A short read, a
 * broken pipe, or EOF before `want` bytes is a failure (0). Never loops without
 * progress: ReadFile returning 0 bytes ends the loop.
 */
static int read_exact(HANDLE h, unsigned char *dst, DWORD want) {
  DWORD done = 0;
  while (done < want) {
    DWORD got = 0;
    if (!ReadFile(h, dst + done, want - done, &got, NULL)) {
      return 0;
    }
    if (got == 0) {
      return 0;
    }
    done += got;
  }
  return 1;
}

/* Append a NUL-terminated ASCII literal; returns 0 on overflow. */
static int append_str(char *buf, size_t *len, size_t cap, const char *s) {
  size_t n = strlen(s);
  if (*len + n > cap) {
    return 0;
  }
  memcpy(buf + *len, s, n);
  *len += n;
  return 1;
}

/*
 * Narrow a wide string to UTF-8 and append it, rejecting anything that is not
 * printable single-line ASCII. Evidence lines are LF-delimited and
 * space-separated, so a control character, a space, or any byte outside
 * 0x21..0x7E could forge a line break or a field boundary and must fail closed
 * rather than be escaped. Canonical numeric SID strings are entirely inside
 * that range.
 */
static int append_narrow_token(char *buf, size_t *len, size_t cap, LPCWSTR wide,
                               size_t limit) {
  char utf8[ATTEST_SID_BUF];
  int need;
  size_t token_len;
  size_t i;

  if (wide == NULL || limit > ATTEST_SID_BUF) {
    return 0;
  }
  need = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
  if (need <= 1 || (size_t)need > limit) {
    return 0;
  }
  if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, need, NULL, NULL) <= 0) {
    return 0;
  }
  token_len = (size_t)(need - 1); /* exclude the NUL terminator */
  for (i = 0; i < token_len; i += 1) {
    unsigned char c = (unsigned char)utf8[i];
    if (c < 0x21 || c > 0x7E) {
      return 0;
    }
  }
  if (*len + token_len > cap) {
    return 0;
  }
  memcpy(buf + *len, utf8, token_len);
  *len += token_len;
  return 1;
}

/*
 * Validate a SID and append its canonical NUMERIC string. This is the ONLY way
 * a principal ever reaches the evidence, which is what makes an alias
 * unrepresentable rather than merely unequal.
 */
static int append_sid_token(char *buf, size_t *len, size_t cap, PSID sid) {
  LPWSTR text = NULL;
  int ok;

  if (sid == NULL || !IsValidSid(sid)) {
    return 0;
  }
  if (!ConvertSidToStringSidW(sid, &text)) {
    return 0;
  }
  ok = append_narrow_token(buf, len, cap, text, ATTEST_SID_BUF);
  LocalFree(text);
  return ok;
}

/* Append an unsigned decimal with no leading zeros; returns 0 on overflow. */
static int append_dec(char *buf, size_t *len, size_t cap, DWORD value) {
  char digits[16];
  int written = snprintf(digits, sizeof(digits), "%lu", (unsigned long)value);
  if (written <= 0 || (size_t)written >= sizeof(digits)) {
    return 0;
  }
  return append_str(buf, len, cap, digits);
}

/* Append a fixed-width lowercase hex field; `width` is 2 or 8 here. */
static int append_fixed_hex(char *buf, size_t *len, size_t cap, DWORD value,
                            int width) {
  char digits[16];
  int written = snprintf(digits, sizeof(digits), "%0*lx", width,
                         (unsigned long)value);
  if (written != width) {
    return 0;
  }
  return append_str(buf, len, cap, digits);
}

/* Append `n` bytes as lowercase hex; returns 0 on overflow. */
static int append_hex(char *buf, size_t *len, size_t cap,
                      const unsigned char *bytes, size_t n) {
  static const char digits[] = "0123456789abcdef";
  if (*len + (n * 2) > cap) {
    return 0;
  }
  for (size_t i = 0; i < n; i += 1) {
    buf[*len] = digits[(bytes[i] >> 4) & 0x0F];
    buf[*len + 1] = digits[bytes[i] & 0x0F];
    *len += 2;
  }
  return 1;
}

/*
 * Object ACE types carry ACE-specific flags and up to two GUIDs between the
 * access mask and the trustee, so no SID exists at the fixed offset. Every
 * other defined type places the SID at ATTEST_ACE_SID_OFFSET. An object ACE
 * can never satisfy the accepted ACCESS_ALLOWED type, so reporting its trustee
 * as NONE loses nothing a policy could have used.
 */
static int ace_has_fixed_trustee(BYTE type) {
  switch (type) {
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_OBJECT_ACE_TYPE:
    case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
    case SYSTEM_ALARM_OBJECT_ACE_TYPE:
    case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
    case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
    case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
      return 0;
    default:
      return 1;
  }
}

/*
 * The OWNER and DACL of the object behind the ALREADY-CONNECTED handle.
 *
 * `owner` and `dacl` point INTO `*sd_out`, which the caller must LocalFree.
 * READ_CONTROL is the only right this needs, and it is already inside the
 * FILE_GENERIC_READ the handle was opened with, so no access is widened here.
 *
 * A NULL or absent DACL is refused: there is no ACL to enumerate, which is an
 * observation failure rather than a policy decision. WHICH owner, WHICH ACE
 * and WHICH mask are accepted is NOT decided here — that is the trust layer's.
 */
static int query_pipe_security(HANDLE pipe, PSID *owner_out, PACL *dacl_out,
                               PSECURITY_DESCRIPTOR *sd_out) {
  PSID owner = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;

  *owner_out = NULL;
  *dacl_out = NULL;
  *sd_out = NULL;

  if (GetSecurityInfo(pipe, SE_KERNEL_OBJECT,
                      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS) {
    return 0;
  }
  if (sd == NULL || owner == NULL || !IsValidSid(owner) || dacl == NULL ||
      !IsValidAcl(dacl)) {
    if (sd != NULL) {
      LocalFree(sd);
    }
    return 0;
  }
  *owner_out = owner;
  *dacl_out = dacl;
  *sd_out = sd;
  return 1;
}

int wmain(int argc, wchar_t **argv) {
  /* Load system DLLs only from System32; never from the working directory. */
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

  if (argv == NULL || argc != 2 || argv[1] == NULL) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }
  const wchar_t *pipe_path = argv[1];
  size_t path_len = wcsnlen(pipe_path, ATTEST_MAX_PATH + 1);
  if (path_len == 0 || path_len > ATTEST_MAX_PATH ||
      !is_local_pipe_path(pipe_path, path_len)) {
    emit_err("ERR_PATH");
    return EXIT_INVALID_ARGS;
  }

  /* GENERIC_READ only: this artifact can never write a byte to the pipe, so it
   * cannot issue a command, complete a handshake, or perturb a live session.
   * GENERIC_READ maps to FILE_GENERIC_READ, which already contains the
   * READ_CONTROL the descriptor query needs — no widening is required. */
  HANDLE pipe =
      CreateFileW(pipe_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (pipe == INVALID_HANDLE_VALUE) {
    emit_err("ERR_CONNECT");
    return EXIT_CONNECT_FAILED;
  }

  /* ---- Pipe-object identity, read from THIS connected handle ------------- */

  PSID owner = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  if (!query_pipe_security(pipe, &owner, &dacl, &sd)) {
    CloseHandle(pipe);
    emit_err("ERR_SECURITY_QUERY");
    return EXIT_SECURITY_QUERY;
  }

  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION acl_size;
  ZeroMemory(&acl_size, sizeof(acl_size));
  if (!GetSecurityDescriptorControl(sd, &control, &revision) ||
      !GetAclInformation(dacl, &acl_size, (DWORD)sizeof(acl_size),
                         AclSizeInformation)) {
    LocalFree(sd);
    CloseHandle(pipe);
    emit_err("ERR_SECURITY_QUERY");
    return EXIT_SECURITY_QUERY;
  }
  const DWORD ace_count = acl_size.AceCount;
  const DWORD emitted_aces =
      ace_count < ATTEST_MAX_ACES ? ace_count : (DWORD)ATTEST_MAX_ACES;

  /* ---- Evidence, built whole in a bounded buffer ------------------------- */

  /* magic + labels + owner SID + DACL line + bounded ACE lines (each a few
   * fixed fields plus one SID) + 2 hex chars per body byte + newlines. */
  char out[128 + ATTEST_SID_BUF +
           (ATTEST_MAX_ACES * (64 + ATTEST_SID_BUF)) + (ATTEST_MAX_BODY * 2) +
           32];
  const size_t cap = sizeof(out);
  size_t len = 0;

  int ok = append_str(out, &len, cap, "AGENTBRIDGE-ATTEST-V3\nPIPEOWNER ");
  ok = ok && append_sid_token(out, &len, cap, owner);
  if (!ok) {
    LocalFree(sd);
    CloseHandle(pipe);
    emit_err("ERR_CONVERT");
    return EXIT_CONVERT_FAILED;
  }

  ok = append_str(out, &len, cap, "\nDACL ");
  ok = ok && append_str(out, &len, cap,
                        (control & SE_DACL_PRESENT) != 0 ? "1 " : "0 ");
  ok = ok && append_str(out, &len, cap,
                        (control & SE_DACL_PROTECTED) != 0 ? "1 " : "0 ");
  ok = ok && append_dec(out, &len, cap, ace_count);
  if (!ok) {
    LocalFree(sd);
    CloseHandle(pipe);
    emit_err("ERR_OVERFLOW");
    return EXIT_CONVERT_FAILED;
  }

  for (DWORD index = 0; index < emitted_aces; index += 1) {
    LPVOID raw = NULL;
    if (!GetAce(dacl, index, &raw) || raw == NULL) {
      LocalFree(sd);
      CloseHandle(pipe);
      emit_err("ERR_ACE");
      return EXIT_SECURITY_QUERY;
    }
    const ACE_HEADER *header = (const ACE_HEADER *)raw;
    /* A non-object ACE is ACE_HEADER + ACCESS_MASK + SID. Anything shorter
     * than that prefix cannot be read at the fixed offsets at all. */
    if (header->AceSize < ATTEST_ACE_SID_OFFSET) {
      LocalFree(sd);
      CloseHandle(pipe);
      emit_err("ERR_ACE");
      return EXIT_SECURITY_QUERY;
    }
    DWORD mask = 0;
    memcpy(&mask, (const unsigned char *)raw + sizeof(ACE_HEADER), sizeof(mask));

    ok = append_str(out, &len, cap, "\nACE ");
    ok = ok && append_dec(out, &len, cap, index);
    ok = ok && append_str(out, &len, cap, " ");
    ok = ok && append_fixed_hex(out, &len, cap, (DWORD)header->AceType, 2);
    ok = ok && append_str(out, &len, cap, " ");
    ok = ok && append_fixed_hex(out, &len, cap, (DWORD)header->AceFlags, 2);
    ok = ok && append_str(out, &len, cap, " ");
    ok = ok && append_fixed_hex(out, &len, cap, mask, 8);
    ok = ok && append_str(out, &len, cap, " ");
    if (!ok) {
      LocalFree(sd);
      CloseHandle(pipe);
      emit_err("ERR_OVERFLOW");
      return EXIT_CONVERT_FAILED;
    }

    /* A trustee may be read at the fixed offset ONLY when the ACE type places
     * one there AND the ACE is long enough to contain a SID's fixed head. The
     * size test must come BEFORE IsValidSid: the kernel accepts ACLs whose
     * ACEs carry no trustee at all (a valid ACL may hold an unknown type with
     * AceSize == ATTEST_ACE_SID_OFFSET), and pointing IsValidSid at such an
     * ACE would read its Revision and SubAuthorityCount past the ACE's end.
     * Both cases are reported as NONE: "no trustee at the fixed offset" is a
     * structural fact, not a policy decision, and NONE can never be accepted. */
    const size_t trustee_room = (size_t)header->AceSize - ATTEST_ACE_SID_OFFSET;
    if (!ace_has_fixed_trustee(header->AceType) ||
        trustee_room < ATTEST_MIN_SID_BYTES) {
      ok = append_str(out, &len, cap, "NONE");
    } else {
      PSID trustee = (PSID)((unsigned char *)raw + ATTEST_ACE_SID_OFFSET);
      /* The fixed head is now proven in-bounds, so IsValidSid may judge the
       * revision and sub-authority count; only then is GetLengthSid meaningful,
       * and the FULL SID must also lie wholly inside the ACE. */
      if (!IsValidSid(trustee) ||
          (size_t)GetLengthSid(trustee) > trustee_room) {
        LocalFree(sd);
        CloseHandle(pipe);
        emit_err("ERR_ACE_SID");
        return EXIT_CONVERT_FAILED;
      }
      ok = append_sid_token(out, &len, cap, trustee);
    }
    if (!ok) {
      LocalFree(sd);
      CloseHandle(pipe);
      emit_err("ERR_CONVERT");
      return EXIT_CONVERT_FAILED;
    }
  }

  LocalFree(sd);

  /* ---- Exactly one bounded hello frame, from the SAME pipe handle -------- */

  unsigned char prefix[ATTEST_PREFIX_BYTES];
  if (!read_exact(pipe, prefix, ATTEST_PREFIX_BYTES)) {
    CloseHandle(pipe);
    emit_err("ERR_HELLO_PREFIX");
    return EXIT_HELLO_FAILED;
  }
  DWORD body_len = ((DWORD)prefix[0] << 24) | ((DWORD)prefix[1] << 16) |
                   ((DWORD)prefix[2] << 8) | (DWORD)prefix[3];
  if (body_len == 0 || body_len > ATTEST_MAX_BODY) {
    CloseHandle(pipe);
    emit_err("ERR_HELLO_LENGTH");
    return EXIT_HELLO_FAILED;
  }
  unsigned char body[ATTEST_MAX_BODY];
  if (!read_exact(pipe, body, body_len)) {
    CloseHandle(pipe);
    emit_err("ERR_HELLO_BODY");
    return EXIT_HELLO_FAILED;
  }

  ok = append_str(out, &len, cap, "\nHELLO ");
  ok = ok && append_hex(out, &len, cap, body, (size_t)body_len);
  ok = ok && append_str(out, &len, cap, "\n");
  if (!ok) {
    CloseHandle(pipe);
    emit_err("ERR_OVERFLOW");
    return EXIT_HELLO_FAILED;
  }

  CloseHandle(pipe);
  write_stdout(out, len);
  return EXIT_OK;
}
