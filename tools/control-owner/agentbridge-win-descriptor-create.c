/*
 * agentbridge-win-descriptor-create.exe
 *
 * Decision 062 Amendment C (descriptor lifecycle v2) — the ONE narrow
 * identity-named runtime-descriptor creation primitive.
 *
 * WHY IT EXISTS
 *
 * Windows chooses a newly created file's OWNER from the creating token's DEFAULT
 * owner (TokenOwner), not from its user, and its DACL from the parent's
 * inheritable ACEs. On an elevated Administrator token the default owner is
 * BUILTIN\Administrators (S-1-5-32-544), so a descriptor created by a plain
 * file write is owned by Administrators while the runtime operator SID is the
 * account SID — and the exact-owner descriptor gate correctly rejects it. Its
 * DACL is likewise unprotected and inherited, not a set this process chose.
 *
 * This program removes that ambiguity by creating the descriptor with an
 * EXPLICIT security descriptor at CREATE_NEW time: owner = this process's exact
 * TokenUser SID, and a PROTECTED DACL whose principals are exactly that operator
 * plus SYSTEM. Nothing is inherited and nothing is mutated after the fact.
 *
 * IDENTITY-NAMED FILES (lifecycle v2). There is no shared fixed pathname. Each
 * runtime mints a 128-bit random identity (the suffix of its unpredictable pipe
 * name) and its descriptor is the file
 *
 *     <anchor>\runtime-descriptor-<runtime-id>.json
 *
 * where <runtime-id> is EXACTLY 32 lowercase hexadecimal characters. The runtime
 * id is the ONLY caller-controlled input to the filename, and it is validated
 * character-by-character before anything else happens: any other length, any
 * uppercase, any separator, dot, colon, space, control character, or non-ASCII
 * code point is rejected. The prefix and suffix are compile-time constants, so
 * the created pathname can never leave the anchor directory and can never name
 * anything but an identity-named descriptor.
 *
 * AUTHORITY (the complete list)
 *   - accepts exactly two arguments: an absolute, already-verified anchor path
 *     and one strictly validated runtime id
 *   - derives the runtime operator SID ITSELF from its own process token
 *     (TokenUser); there is no owner input of any kind
 *   - refuses to run as SYSTEM (S-1-5-18 may be a DACL principal, never the
 *     runtime operator — an owner can rewrite the DACL)
 *   - derives the output pathname internally from the anchor and the validated
 *     runtime id as above; there is no filename input and no path input below
 *     the anchor
 *   - reads the descriptor bytes ONLY from stdin, bounded to 4096 bytes
 *   - creates that one file with CREATE_NEW and an explicit security descriptor,
 *     with kernel delete-on-close armed in the same operation
 *   - writes those bytes, flushes, cancels delete-on-close on that same
 *     handle, closes
 *
 * LIFECYCLE (per invocation; the states are those of the file object)
 *
 *   S0 NOT_CREATED       argument, token, stdin, and ACL work; exits 1..5.
 *                        Nothing was created; an existing pathname is untouched.
 *   S1 CREATED_ARMED     entered atomically by CREATE_NEW success with
 *                        FILE_FLAG_DELETE_ON_CLOSE. Write + flush happen here.
 *                        Any exit or forced termination here: the kernel
 *                        removes the file at handle teardown (exit 6 on a
 *                        write/flush/cancel failure).
 *   S2 CREATED_RETAINED  entered when the delete-on-close disposition is
 *                        cancelled AFTER a complete, flushed write. The file
 *                        holds exactly the descriptor bytes. A close failure
 *                        here is exit 6 with a complete file possibly left.
 *   S3 CLOSED_COMPLETE   exit 0.
 *
 *   Invariant: after this process has terminated, a file created by THIS
 *   invocation that still exists holds the complete, flushed descriptor. No
 *   empty or partial file of this invocation survives termination. (Windows
 *   removes the name when the LAST handle to the file object closes; a foreign
 *   handle opened meanwhile — a filter driver or backup tool — defers removal
 *   until that handle closes, it does not cancel it.)
 *
 * NO AUTHORITY TO
 *   - create or provision any directory
 *   - open, replace, re-own, or re-ACL an existing file (CREATE_NEW only)
 *   - accept an owner SID, a filename, or any path below the anchor
 *   - delete anything by PATHNAME (the only deletion is the kernel's
 *     delete-on-close bound to the handle this invocation itself created, so
 *     no pathname race exists)
 *   - run a shell, cmd, PowerShell, or any child process
 *   - read the registry, the network, or environment-selected configuration
 *   - emit descriptor or token bytes anywhere (no stdout at all; stderr carries
 *     one bounded ASCII diagnostic token, never a path and never a secret)
 *
 * argv:
 *   agentbridge-win-descriptor-create.exe <absolute-anchor-path> <runtime-id>
 *
 * stdin:
 *   the exact serialized descriptor bytes, 1..4096 (binary, read to EOF)
 *
 * stdout:
 *   nothing, ever
 *
 * stderr:
 *   exactly one bounded diagnostic token + LF
 *
 * exit codes:
 *   0 success
 *   1 invalid arguments / unusable anchor / malformed runtime id
 *   2 operator identity unusable (token unreadable, or the operator is SYSTEM)
 *   3 security-descriptor construction failed
 *   4 stdin absent, empty, unreadable, or larger than 4096 bytes
 *   5 CREATE_NEW failed (an existing pathname always lands here)
 *   6 CREATE_NEW succeeded, then write/flush/cancel-delete-on-close/close
 *     failed. On a write, flush, or cancellation failure the file is still
 *     delete-armed and the kernel removes it when the handle closes; only a
 *     close failure after a successful cancellation can leave a (complete)
 *     file behind, which the caller that minted this identity removes.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 /* Windows 10; SetDefaultDllDirectories, FileDispositionInfoEx */
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
#define EXIT_OPERATOR_INVALID 2
#define EXIT_ACL_FAILED 3
#define EXIT_STDIN_FAILED 4
#define EXIT_CREATE_FAILED 5
#define EXIT_WRITE_FAILED 6

/* Windows extended maximum path length (\\?\ form), in wide characters. */
#define CREATOR_MAX_PATH 32767

/* The descriptor cap the consumer also enforces (MAX_DESCRIPTOR_BYTES). */
#define DESCRIPTOR_MAX_BYTES 4096

/* A TOKEN_USER for any real principal is far smaller; the cap keeps it bounded. */
#define TOKEN_INFO_MAX 4096

/* The runtime id is exactly this many lowercase hex characters (128 bits). */
#define RUNTIME_ID_LEN 32

/* The fixed filename prefix and suffix around the validated runtime id. */
static const wchar_t DESCRIPTOR_PREFIX[] = L"runtime-descriptor-";
static const wchar_t DESCRIPTOR_SUFFIX[] = L".json";

/* A short, fixed ASCII token — never a path, never descriptor or token bytes. */
static void emit_err(const char *token) {
  fputs(token, stderr);
  fputc('\n', stderr);
}

/*
 * Accept only a fully-qualified absolute path: drive-absolute (X:\...) or a
 * UNC / extended prefix (\\...). Identical shape to the read-only owner helper,
 * so both agree on what "an anchor path" is. Rejects empty, relative, and
 * drive-relative (X:foo) forms.
 */
static int is_supported_absolute(const wchar_t *path, size_t len) {
  if (path == NULL || len == 0) {
    return 0;
  }
  if (len >= 3 &&
      ((path[0] >= L'A' && path[0] <= L'Z') ||
       (path[0] >= L'a' && path[0] <= L'z')) &&
      path[1] == L':' && path[2] == L'\\') {
    return 1; /* drive-absolute */
  }
  if (len >= 2 && path[0] == L'\\' && path[1] == L'\\') {
    return 1; /* UNC or \\?\ extended */
  }
  return 0;
}

/*
 * Reject any anchor carrying a `.` or `..` component. The caller passes a
 * resolved path, so this can only be a mistake or an attempt to make the
 * derived filename land outside the verified anchor; the creator has no
 * authority to write anywhere but directly inside the anchor it was given.
 */
static int has_dot_component(const wchar_t *path, size_t len) {
  size_t start = 0;
  for (size_t i = 0; i <= len; i += 1) {
    int at_end = (i == len);
    if (!at_end && path[i] != L'\\' && path[i] != L'/') {
      continue;
    }
    size_t span = i - start;
    if (span == 1 && path[start] == L'.') {
      return 1;
    }
    if (span == 2 && path[start] == L'.' && path[start + 1] == L'.') {
      return 1;
    }
    start = i + 1;
  }
  return 0;
}

/*
 * The runtime id is valid iff it is EXACTLY RUNTIME_ID_LEN characters, each in
 * [0-9a-f]. This is a whitelist over the wide code units themselves, so no
 * separator, dot, colon, NUL-embedding trick, uppercase, or non-ASCII character
 * can pass. The length check uses wcsnlen with a bound one past the limit so an
 * over-long (or unterminated) argument is rejected instead of scanned.
 */
static int is_valid_runtime_id(const wchar_t *id) {
  if (id == NULL) {
    return 0;
  }
  size_t len = wcsnlen(id, RUNTIME_ID_LEN + 1);
  if (len != RUNTIME_ID_LEN) {
    return 0;
  }
  for (size_t i = 0; i < RUNTIME_ID_LEN; i += 1) {
    wchar_t c = id[i];
    int digit = (c >= L'0' && c <= L'9');
    int lower_hex = (c >= L'a' && c <= L'f');
    if (!digit && !lower_hex) {
      return 0;
    }
  }
  return 1;
}

/*
 * Build exactly `<anchor>\runtime-descriptor-<id>.json`. The prefix and suffix
 * are compile-time constants and the id has already been whitelisted, so no
 * caller-controlled separator or traversal can enter the result. Returns 0 on
 * overflow.
 */
static int build_descriptor_path(const wchar_t *anchor, size_t anchor_len,
                                 const wchar_t *runtime_id, wchar_t *out,
                                 size_t out_count) {
  size_t prefix_len = wcslen(DESCRIPTOR_PREFIX);
  size_t suffix_len = wcslen(DESCRIPTOR_SUFFIX);
  size_t pos;
  int need_separator;

  if (anchor == NULL || runtime_id == NULL || out == NULL || out_count == 0 ||
      anchor_len == 0) {
    return 0;
  }
  need_separator = anchor[anchor_len - 1] != L'\\';

  /* anchor_len <= CREATOR_MAX_PATH and the other terms are small constants, so
   * this sum cannot overflow size_t. */
  if (anchor_len + (need_separator ? 1u : 0u) + prefix_len + RUNTIME_ID_LEN +
          suffix_len + 1u >
      out_count) {
    return 0;
  }

  memcpy(out, anchor, anchor_len * sizeof(wchar_t));
  pos = anchor_len;
  if (need_separator) {
    out[pos] = L'\\';
    pos += 1;
  }
  memcpy(out + pos, DESCRIPTOR_PREFIX, prefix_len * sizeof(wchar_t));
  pos += prefix_len;
  memcpy(out + pos, runtime_id, RUNTIME_ID_LEN * sizeof(wchar_t));
  pos += RUNTIME_ID_LEN;
  memcpy(out + pos, DESCRIPTOR_SUFFIX, (suffix_len + 1u) * sizeof(wchar_t));
  return 1;
}

/*
 * The runtime operator is THIS process's token user — never an argument. The
 * TOKEN_USER buffer backs the returned PSID, so it is returned too and freed by
 * the caller. Both the filtered and the elevated token of an administrator
 * report the same TokenUser, which is exactly the SID `whoami /user` reports;
 * only the token's DEFAULT OWNER differs, and that default is what this program
 * exists to stop relying on.
 */
static int current_token_user(PSID *sid_out, TOKEN_USER **buffer_out) {
  HANDLE token = NULL;
  TOKEN_USER *info = NULL;
  DWORD needed = 0;

  if (sid_out == NULL || buffer_out == NULL) {
    return 0;
  }
  *sid_out = NULL;
  *buffer_out = NULL;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return 0;
  }
  if (GetTokenInformation(token, TokenUser, NULL, 0, &needed) ||
      GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
      needed == 0 || needed > TOKEN_INFO_MAX) {
    CloseHandle(token);
    return 0;
  }
  info = (TOKEN_USER *)LocalAlloc(LPTR, needed);
  if (info == NULL) {
    CloseHandle(token);
    return 0;
  }
  if (!GetTokenInformation(token, TokenUser, info, needed, &needed) ||
      info->User.Sid == NULL || !IsValidSid(info->User.Sid)) {
    LocalFree(info);
    CloseHandle(token);
    return 0;
  }
  CloseHandle(token);

  *buffer_out = info;
  *sid_out = info->User.Sid;
  return 1;
}

/*
 * Read the complete descriptor from stdin BEFORE anything is created, so a
 * malformed or over-long transport can never leave a partial file behind.
 *
 * Bounded at DESCRIPTOR_MAX_BYTES; the one-extra-byte probe makes >4096 bytes
 * fail closed instead of silently truncating. Empty input is rejected.
 */
static int read_descriptor_stdin(unsigned char *buffer, DWORD *length_out) {
  DWORD total = 0;
  int fd;

  if (buffer == NULL || length_out == NULL) {
    return 0;
  }
  fd = _fileno(stdin);
  if (fd < 0 || _setmode(fd, _O_BINARY) == -1) {
    return 0;
  }

  while (total < DESCRIPTOR_MAX_BYTES) {
    int count = _read(fd, buffer + total, (unsigned int)(DESCRIPTOR_MAX_BYTES - total));
    if (count < 0) {
      return 0; /* read error */
    }
    if (count == 0) {
      break; /* EOF */
    }
    total += (DWORD)count;
  }

  if (total == DESCRIPTOR_MAX_BYTES) {
    unsigned char overflow_probe = 0;
    int extra = _read(fd, &overflow_probe, 1);
    /* Anything but a clean EOF here means the input exceeded the cap (or the
     * stream failed); either way the descriptor is not exactly what was sent. */
    if (extra != 0) {
      return 0;
    }
  }
  if (total == 0) {
    return 0;
  }

  *length_out = total;
  return 1;
}

/*
 * A DACL with exactly two direct ALLOW ACEs — the operator and SYSTEM, each
 * FILE_ALL_ACCESS, NO_INHERITANCE (this is a leaf file; it propagates nothing).
 * Combined with SE_DACL_PROTECTED below, the created file's principal set is
 * exactly these two and no parent ACE can enter it.
 */
static DWORD build_restricted_dacl(PSID operator_sid, PSID system_sid, PACL *acl_out) {
  EXPLICIT_ACCESSW entries[2];

  if (operator_sid == NULL || system_sid == NULL || acl_out == NULL ||
      !IsValidSid(operator_sid) || !IsValidSid(system_sid)) {
    return ERROR_INVALID_PARAMETER;
  }
  ZeroMemory(entries, sizeof(entries));

  entries[0].grfAccessPermissions = FILE_ALL_ACCESS;
  entries[0].grfAccessMode = SET_ACCESS;
  entries[0].grfInheritance = NO_INHERITANCE;
  entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
  entries[0].Trustee.ptstrName = (LPWSTR)operator_sid;

  entries[1].grfAccessPermissions = FILE_ALL_ACCESS;
  entries[1].grfAccessMode = SET_ACCESS;
  entries[1].grfInheritance = NO_INHERITANCE;
  entries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  entries[1].Trustee.ptstrName = (LPWSTR)system_sid;

  *acl_out = NULL;
  return SetEntriesInAclW(2, entries, NULL, acl_out);
}

int wmain(int argc, wchar_t **argv) {
  const wchar_t *anchor;
  const wchar_t *runtime_id;
  size_t anchor_len;

  TOKEN_USER *token_user = NULL;
  PSID operator_sid = NULL;
  PSID system_sid = NULL;
  PACL dacl = NULL;

  SECURITY_DESCRIPTOR sd;
  SECURITY_ATTRIBUTES attributes;
  SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

  static wchar_t descriptor_path[CREATOR_MAX_PATH + 1];
  static unsigned char descriptor_bytes[DESCRIPTOR_MAX_BYTES];
  DWORD descriptor_length = 0;
  DWORD total_written = 0;

  HANDLE file = INVALID_HANDLE_VALUE;
  int exit_code = EXIT_INVALID_ARGS;

  /* Load system DLLs only from System32; never from the working directory. */
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

  /* Exactly two arguments. Any other argc — including a third argument that
   * might look like an owner SID or a filename — is rejected outright. */
  if (argv == NULL || argc != 3 || argv[1] == NULL || argv[2] == NULL) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }
  anchor = argv[1];
  runtime_id = argv[2];
  anchor_len = wcsnlen(anchor, CREATOR_MAX_PATH + 1);
  if (anchor_len == 0 || anchor_len > CREATOR_MAX_PATH ||
      !is_supported_absolute(anchor, anchor_len) ||
      has_dot_component(anchor, anchor_len)) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }
  if (!is_valid_runtime_id(runtime_id)) {
    emit_err("ERR_RUNTIME_ID");
    return EXIT_INVALID_ARGS;
  }
  if (!build_descriptor_path(anchor, anchor_len, runtime_id, descriptor_path,
                             sizeof(descriptor_path) / sizeof(descriptor_path[0]))) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }

  /* The runtime operator is derived here, from this process's own token. */
  if (!current_token_user(&operator_sid, &token_user)) {
    emit_err("ERR_TOKEN");
    exit_code = EXIT_OPERATOR_INVALID;
    goto cleanup;
  }
  if (!AllocateAndInitializeSid(&nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                0, 0, 0, 0, 0, 0, 0, &system_sid) ||
      system_sid == NULL || !IsValidSid(system_sid)) {
    emit_err("ERR_ACL");
    exit_code = EXIT_ACL_FAILED;
    goto cleanup;
  }
  /* SYSTEM is an allowed DACL principal but never an allowed runtime operator:
   * an owner can rewrite the DACL, so a SYSTEM-owned descriptor would not be a
   * per-operator secret at all. Same policy as the anchor gate. */
  if (EqualSid(operator_sid, system_sid)) {
    emit_err("ERR_OPERATOR_IS_SYSTEM");
    exit_code = EXIT_OPERATOR_INVALID;
    goto cleanup;
  }

  /* All secret-bearing bytes are read before any filesystem mutation. */
  if (!read_descriptor_stdin(descriptor_bytes, &descriptor_length)) {
    emit_err("ERR_STDIN");
    exit_code = EXIT_STDIN_FAILED;
    goto cleanup;
  }

  if (build_restricted_dacl(operator_sid, system_sid, &dacl) != ERROR_SUCCESS ||
      dacl == NULL) {
    emit_err("ERR_ACL");
    exit_code = EXIT_ACL_FAILED;
    goto cleanup;
  }

  /* An explicit absolute security descriptor: the owner is the exact operator
   * SID (never the token's default owner), the DACL is the two-principal ACL
   * above, and SE_DACL_PROTECTED stops the anchor's inheritable ACEs — or any
   * later-widened parent ACE — from being merged into the created file. */
  if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorOwner(&sd, operator_sid, FALSE) ||
      !SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE) ||
      !SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    emit_err("ERR_ACL");
    exit_code = EXIT_ACL_FAILED;
    goto cleanup;
  }

  ZeroMemory(&attributes, sizeof(attributes));
  attributes.nLength = sizeof(attributes);
  attributes.lpSecurityDescriptor = &sd;
  attributes.bInheritHandle = FALSE;

  /* CREATE_NEW is the exclusivity boundary: an existing pathname is never
   * opened, truncated, re-owned, or re-ACL'd — it is an error.
   *
   * S0 NOT_CREATED -> S1 CREATED_ARMED, atomically. FILE_FLAG_DELETE_ON_CLOSE
   * arms deletion on the file object this call creates, in the same kernel
   * operation that creates it, so there is no instant at which the file exists
   * without being armed. From here until the disposition is cancelled below,
   * ANY end of this process — normal exit, a failed write, or forced
   * termination (TerminateProcess, the parent's deadline kill) — makes the
   * kernel remove the file at handle teardown. No user-mode cleanup code needs
   * to run for that to happen. DELETE access is required for the flag and for
   * the cancellation; deletion is bound to THIS handle's file object, never to
   * the pathname, so a file that has since taken the same name is unaffected. */
  file = CreateFileW(descriptor_path, GENERIC_WRITE | DELETE, 0, &attributes,
                     CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
                     NULL);
  if (file == INVALID_HANDLE_VALUE) {
    emit_err("ERR_CREATE");
    exit_code = EXIT_CREATE_FAILED;
    goto cleanup;
  }

  while (total_written < descriptor_length) {
    DWORD written = 0;
    if (!WriteFile(file, descriptor_bytes + total_written,
                   descriptor_length - total_written, &written, NULL) ||
        written == 0) {
      emit_err("ERR_WRITE");
      exit_code = EXIT_WRITE_FAILED;
      goto cleanup;
    }
    total_written += written;
  }

  if (!FlushFileBuffers(file)) {
    emit_err("ERR_WRITE");
    exit_code = EXIT_WRITE_FAILED;
    goto cleanup;
  }

  /* S1 CREATED_ARMED -> S2 CREATED_RETAINED. Only now — after every descriptor
   * byte has been written AND flushed — is the delete-on-close disposition
   * cancelled, on the SAME handle. The classic FileDispositionInfo class cannot
   * clear a flag-armed delete-on-close (it reports success and the file is
   * still removed), so the FileDispositionInfoEx class with
   * FILE_DISPOSITION_FLAG_ON_CLOSE is required; it needs Windows 10 1709+ on
   * NTFS/ReFS. If the cancellation fails for any reason the file stays armed,
   * this invocation reports the post-create failure class, and the kernel
   * removes the file when the handle is closed below. */
  {
    FILE_DISPOSITION_INFO_EX retain;
    ZeroMemory(&retain, sizeof(retain));
    retain.Flags = FILE_DISPOSITION_FLAG_DO_NOT_DELETE | FILE_DISPOSITION_FLAG_ON_CLOSE;
    if (!SetFileInformationByHandle(file, FileDispositionInfoEx, &retain,
                                    sizeof(retain))) {
      emit_err("ERR_WRITE");
      exit_code = EXIT_WRITE_FAILED;
      goto cleanup;
    }
  }

  /* S2 CREATED_RETAINED -> S3 CLOSED_COMPLETE. */
  if (!CloseHandle(file)) {
    /* The handle is gone or unusable either way; do not close it twice, and do
     * not delete by pathname. The disposition was already cancelled, so the
     * complete, flushed file may persist: report exit 6 and let the caller —
     * which minted this exact identity — remove its own descriptor path. */
    file = INVALID_HANDLE_VALUE;
    emit_err("ERR_WRITE");
    exit_code = EXIT_WRITE_FAILED;
    goto cleanup;
  }
  file = INVALID_HANDLE_VALUE;
  exit_code = EXIT_OK;

cleanup:
  if (file != INVALID_HANDLE_VALUE) {
    /* A file was created but not completed (S1 CREATED_ARMED). Every path that
     * reaches here with a live handle left the delete-on-close disposition
     * armed — cancellation is the last step before the success close, and a
     * failed cancellation leaves it armed — so closing the handle is the
     * removal: the kernel unlinks the name at teardown of THIS file object,
     * exactly as it would have on forced termination. Nothing is deleted by
     * pathname, so a different file that has since taken the name is safe. */
    (void)CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
  }

  if (dacl != NULL) {
    LocalFree(dacl); /* SetEntriesInAclW allocates with LocalAlloc. */
  }
  if (system_sid != NULL) {
    FreeSid(system_sid); /* Paired with AllocateAndInitializeSid. */
  }
  if (token_user != NULL) {
    LocalFree(token_user); /* Backs operator_sid; freed last. */
  }

  /* The descriptor carries the runtime token. Erase it from this process's
   * memory before exit; nothing was ever written to stdout. */
  SecureZeroMemory(descriptor_bytes, sizeof(descriptor_bytes));
  return exit_code;
}
