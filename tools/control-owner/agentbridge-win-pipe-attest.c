/*
 * agentbridge-win-pipe-attest.exe
 *
 * Decision 062 DDR-D062-B — LIVE PIPE SERVER IDENTITY RELAYER.
 *
 * The single-purpose native artifact that answers one question the runtime
 * cannot answer from JavaScript: **who actually owns the process that is
 * serving this named pipe right now, and what did that same process say
 * first?** It connects to a candidate pipe, resolves the SERVER process from
 * the kernel (never from a descriptor, argv, PID file, or any caller-supplied
 * value), pins that process against PID reuse by its creation time, reads the
 * server's TokenUser SID, relays exactly one bounded server hello read from the
 * SAME pipe handle, and prints both as bounded evidence.
 *
 * It makes NO policy decision. It does not know the operator SID, does not
 * compare SIDs, does not parse the hello, does not know what a verify key is,
 * and has no notion of success beyond "every structural step succeeded". All
 * authorization lives in the TypeScript trust layer that consumes this
 * evidence. Every failure is fail-closed: a nonzero exit and NO stdout bytes.
 *
 * Read-only always: it never writes a file, never mutates an ACL, never touches
 * the registry, the network, the environment, stdin, or any shell/child
 * process. It opens the pipe with GENERIC_READ only and never writes a byte to
 * it, so it cannot issue a command or perturb a session.
 *
 *   agentbridge-win-pipe-attest.exe \\.\pipe\<name>
 *
 * Evidence grammar V1 — exactly three LF-terminated ASCII lines, in this order,
 * and nothing else:
 *
 *     AGENTBRIDGE-ATTEST-V1
 *     SERVERSID <sid>
 *     HELLO <hex>
 *
 *   - <sid> is the canonical string SID (ConvertSidToStringSidW) of the SERVER
 *     process's TokenUser. No account name lookup ever happens, so the output
 *     is identical on any locale.
 *   - <hex> is the exact bytes of the server hello frame BODY (the framed
 *     payload after the 4-byte big-endian length prefix), lowercase hex, at
 *     most ATTEST_MAX_BODY bytes. The bytes are relayed verbatim; nothing is
 *     interpreted.
 *
 * PID REUSE GUARD (mandatory). A PID is not an identity: the kernel may reuse
 * it the instant its process dies. The process opened for `pid` is therefore
 * pinned by handle and by its exact creation FILETIME, and that pin is proven
 * intact AFTER the token query and AGAIN after the hello read:
 *
 *   - the pipe handle must still report the SAME server PID;
 *   - the pinned process must still be running (WaitForSingleObject == TIMEOUT,
 *     which is unambiguous where exit code 259 is not);
 *   - its creation FILETIME must be byte-identical to the one first recorded.
 *
 * So the SID and the hello are attributed to ONE pinned process instance, or to
 * nothing at all. A server that exits mid-attestation fails the guard.
 *
 * ELEVATION. Any OpenProcess / token-query failure fails closed with no
 * fallback and no weaker path (Commander v1 scope decision): a non-elevated
 * client attesting an elevated runtime is NOT a supported configuration and
 * must never be rescued by degrading the trust boundary.
 *
 * DEADLINE. The read of a live-but-silent server is bounded by the CALLER: the
 * runtime runs this artifact through its bounded process runner (finite
 * timeout, killed on overrun, nonzero => fail closed). A server that has exited
 * breaks the pipe and returns immediately rather than blocking, so the only
 * blocking case is the one the caller's deadline already covers.
 *
 * Contract (see src/control/control-store.ts):
 *   stdout on success : the three evidence lines, nothing else
 *   stderr            : a short bounded diagnostic token only (no SID, no bytes)
 *   exit codes        : 0 success
 *                       1 invalid arguments
 *                       2 pipe connect failed
 *                       3 server process resolution / PID-reuse guard failed
 *                       4 token query / SID conversion failed
 *                       5 hello read failed (framing, bounds, or short read)
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 /* Windows 10; needed for SetDefaultDllDirectories */
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <sddl.h>

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define EXIT_OK 0
#define EXIT_INVALID_ARGS 1
#define EXIT_CONNECT_FAILED 2
#define EXIT_SERVER_IDENTITY 3
#define EXIT_TOKEN_FAILED 4
#define EXIT_HELLO_FAILED 5

/* Windows extended maximum path length, in wide characters. */
#define ATTEST_MAX_PATH 32767

/* A canonical SID string is far shorter than this; the cap keeps output bounded. */
#define ATTEST_SID_BUF 512

/* Mirrors MAX_BODY_BYTES in src/control/control-channel.ts. A declared length
 * outside [1, ATTEST_MAX_BODY] is a framing violation, not a large message. */
#define ATTEST_MAX_BODY 4096

/* The 4-byte big-endian length prefix of one wire frame. */
#define ATTEST_PREFIX_BYTES 4

/* The TokenUser query is a fixed small structure plus one SID. */
#define ATTEST_TOKEN_BUF 4096

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
 * this artifact attests a LOCAL server process and a remote pipe has no local
 * process to attest.
 */
static int is_local_pipe_path(const wchar_t *p, size_t len) {
  static const wchar_t prefix[] = L"\\\\.\\pipe\\";
  const size_t prefix_len = 9; /* characters in prefix, excluding the NUL */
  if (len <= prefix_len) {
    return 0;
  }
  return wcsncmp(p, prefix, prefix_len) == 0;
}

/* Two FILETIMEs are the same instant iff both halves match exactly. */
static int filetime_equal(const FILETIME *a, const FILETIME *b) {
  return a->dwLowDateTime == b->dwLowDateTime &&
         a->dwHighDateTime == b->dwHighDateTime;
}

/*
 * Re-prove the pin: the pipe still names the same server PID, the pinned
 * process object is still running, and its creation instant is unchanged.
 * Returns 1 when the pin holds, 0 otherwise.
 */
static int pin_still_holds(HANDLE pipe, HANDLE proc, DWORD pid,
                           const FILETIME *created) {
  DWORD current_pid = 0;
  if (!GetNamedPipeServerProcessId(pipe, &current_pid) || current_pid != pid) {
    return 0;
  }
  /* WAIT_TIMEOUT means "not signalled", i.e. still running. Unlike exit code
   * 259 (STILL_ACTIVE) this cannot be confused with a genuine exit status. */
  if (WaitForSingleObject(proc, 0) != WAIT_TIMEOUT) {
    return 0;
  }
  FILETIME now_created, now_exit, now_kernel, now_user;
  if (!GetProcessTimes(proc, &now_created, &now_exit, &now_kernel, &now_user)) {
    return 0;
  }
  return filetime_equal(&now_created, created);
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
 * Convert a validated SID to its canonical string and append the UTF-8 bytes.
 * Returns 1 on success, 0 on any failure. *len advances only on success.
 */
static int append_sid(char *buf, size_t *len, size_t cap, PSID sid) {
  if (sid == NULL || !IsValidSid(sid)) {
    return 0;
  }
  LPWSTR wide = NULL;
  if (!ConvertSidToStringSidW(sid, &wide)) {
    return 0;
  }
  char utf8[ATTEST_SID_BUF];
  int need = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
  if (need <= 0 || need > ATTEST_SID_BUF) {
    LocalFree(wide);
    return 0;
  }
  if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, need, NULL, NULL) <= 0) {
    LocalFree(wide);
    return 0;
  }
  LocalFree(wide);
  size_t sid_len = (size_t)(need - 1); /* exclude the NUL terminator */
  if (*len + sid_len > cap) {
    return 0;
  }
  memcpy(buf + *len, utf8, sid_len);
  *len += sid_len;
  return 1;
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
 * The server process's TokenUser SID, appended canonically to the output
 * buffer. The token handle and its buffer never outlive this call.
 */
static int append_server_user_sid(HANDLE proc, char *out, size_t *len,
                                  size_t cap) {
  HANDLE token = NULL;
  if (!OpenProcessToken(proc, TOKEN_QUERY, &token)) {
    return 0;
  }
  DWORD needed = 0;
  (void)GetTokenInformation(token, TokenUser, NULL, 0, &needed);
  if (needed == 0 || needed > ATTEST_TOKEN_BUF) {
    CloseHandle(token);
    return 0;
  }
  unsigned char buffer[ATTEST_TOKEN_BUF];
  if (!GetTokenInformation(token, TokenUser, buffer, needed, &needed)) {
    CloseHandle(token);
    return 0;
  }
  CloseHandle(token);
  TOKEN_USER *user = (TOKEN_USER *)buffer;
  return append_sid(out, len, cap, user->User.Sid);
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
   * cannot issue a command, complete a handshake, or perturb a live session. */
  HANDLE pipe =
      CreateFileW(pipe_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (pipe == INVALID_HANDLE_VALUE) {
    emit_err("ERR_CONNECT");
    return EXIT_CONNECT_FAILED;
  }

  /* ---- Server process identity, pinned against PID reuse ----------------- */

  DWORD pid = 0;
  if (!GetNamedPipeServerProcessId(pipe, &pid) || pid == 0) {
    CloseHandle(pipe);
    emit_err("ERR_SERVER_PID");
    return EXIT_SERVER_IDENTITY;
  }
  /* The minimum rights the guard needs and nothing more: QUERY_LIMITED for the
   * creation time and the token, SYNCHRONIZE so WaitForSingleObject can decide
   * liveness. No READ memory right, no TERMINATE right, no duplication right. */
  HANDLE proc =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
  if (proc == NULL) {
    /* Fail closed with NO fallback: an unqueryable server (for example an
     * elevated runtime attested by a non-elevated client) is out of scope,
     * never a reason to weaken the boundary. */
    CloseHandle(pipe);
    emit_err("ERR_OPEN_PROCESS");
    return EXIT_SERVER_IDENTITY;
  }
  FILETIME created, exited, kernel_time, user_time;
  if (!GetProcessTimes(proc, &created, &exited, &kernel_time, &user_time)) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_PROC_TIMES");
    return EXIT_SERVER_IDENTITY;
  }
  /* The window between resolving the PID and pinning the object is exactly
   * where reuse could land; prove the pipe still names the pinned process. */
  if (!pin_still_holds(pipe, proc, pid, &created)) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_PID_REUSE");
    return EXIT_SERVER_IDENTITY;
  }

  /* ---- Evidence, built whole in a bounded buffer ------------------------- */

  /* magic + labels + SID + 2 hex chars per body byte + newlines, with room. */
  char out[64 + ATTEST_SID_BUF + (ATTEST_MAX_BODY * 2) + 32];
  const size_t cap = sizeof(out);
  size_t len = 0;
  int ok = append_str(out, &len, cap, "AGENTBRIDGE-ATTEST-V1\nSERVERSID ");
  ok = ok && append_server_user_sid(proc, out, &len, cap);
  if (!ok) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_TOKEN");
    return EXIT_TOKEN_FAILED;
  }
  /* The SID was read from the pinned object; prove the pin still holds before
   * that SID is allowed to stand as evidence. */
  if (!pin_still_holds(pipe, proc, pid, &created)) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_PID_REUSE");
    return EXIT_SERVER_IDENTITY;
  }

  /* ---- Exactly one bounded hello frame, from the SAME pipe handle -------- */

  unsigned char prefix[ATTEST_PREFIX_BYTES];
  if (!read_exact(pipe, prefix, ATTEST_PREFIX_BYTES)) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_HELLO_PREFIX");
    return EXIT_HELLO_FAILED;
  }
  DWORD body_len = ((DWORD)prefix[0] << 24) | ((DWORD)prefix[1] << 16) |
                   ((DWORD)prefix[2] << 8) | (DWORD)prefix[3];
  if (body_len == 0 || body_len > ATTEST_MAX_BODY) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_HELLO_LENGTH");
    return EXIT_HELLO_FAILED;
  }
  unsigned char body[ATTEST_MAX_BODY];
  if (!read_exact(pipe, body, body_len)) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_HELLO_BODY");
    return EXIT_HELLO_FAILED;
  }

  ok = append_str(out, &len, cap, "\nHELLO ");
  ok = ok && append_hex(out, &len, cap, body, (size_t)body_len);
  ok = ok && append_str(out, &len, cap, "\n");
  if (!ok) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_OVERFLOW");
    return EXIT_HELLO_FAILED;
  }

  /* Final pin proof: the hello came from the same pinned process instance the
   * SID did. A runtime that exited mid-attestation is rejected here. */
  if (!pin_still_holds(pipe, proc, pid, &created)) {
    CloseHandle(proc);
    CloseHandle(pipe);
    emit_err("ERR_PID_REUSE");
    return EXIT_SERVER_IDENTITY;
  }

  CloseHandle(proc);
  CloseHandle(pipe);
  write_stdout(out, len);
  return EXIT_OK;
}
