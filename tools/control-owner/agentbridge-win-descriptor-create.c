/*
 * agentbridge-win-descriptor-create.exe
 *
 * Decision 062 Amendment C — the ONE narrow runtime-descriptor creation
 * primitive.
 *
 * WHY IT EXISTS
 *
 * Windows chooses a newly created file's OWNER from the creating token's
 * DEFAULT owner (TokenOwner), not from its user. On an elevated Administrator
 * token that default is BUILTIN\Administrators (S-1-5-32-544), so a descriptor
 * created by `writeFileSync` is owned by Administrators while the runtime
 * operator SID is the account SID — and the exact-owner descriptor gate
 * correctly rejects it (OWNER_MISMATCH), leaving the control channel
 * unavailable. The file's DACL is likewise whatever the parent's inheritable
 * ACEs produce (unprotected, inherited), not a set this process chose.
 *
 * This program removes that ambiguity by creating the descriptor with an
 * EXPLICIT security descriptor at CREATE_NEW time: owner = this process's exact
 * TokenUser SID, and a PROTECTED DACL whose principals are exactly that operator
 * plus SYSTEM. Nothing is inherited and nothing is mutated after the fact.
 *
 * AUTHORITY (the complete list)
 *   - accepts exactly one argument: an absolute, already-verified anchor path
 *   - derives the runtime operator SID ITSELF from its own process token
 *     (TokenUser); there is no owner input of any kind
 *   - refuses to run as SYSTEM (S-1-5-18 may be a DACL principal, never the
 *     runtime operator — an owner can rewrite the DACL)
 *   - derives the output pathname internally as exactly
 *         <anchor>\runtime-descriptor.json
 *     There is no filename input and no path input below the anchor.
 *   - reads the descriptor bytes ONLY from stdin, bounded to 4096 bytes
 *   - creates that one file with CREATE_NEW and an explicit security descriptor
 *   - writes those bytes, flushes, closes
 *
 * NO AUTHORITY TO
 *   - create or provision any directory
 *   - open, replace, re-own, or re-ACL an existing file (CREATE_NEW only)
 *   - accept an owner SID, a filename, or any path below the anchor
 *   - delete anything by PATHNAME (failure cleanup is handle-scoped disposition
 *     on the handle this invocation itself created, so no pathname race exists)
 *   - run a shell, cmd, PowerShell, or any child process
 *   - read the registry, the network, or environment-selected configuration
 *   - emit descriptor or token bytes anywhere (no stdout at all; stderr carries
 *     one bounded ASCII diagnostic token, never a path and never a secret)
 *
 * argv:
 *   agentbridge-win-descriptor-create.exe <absolute-anchor-path>
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
 *   1 invalid arguments / unusable anchor
 *   2 operator identity unusable (token unreadable, or the operator is SYSTEM)
 *   3 security-descriptor construction failed
 *   4 stdin absent, empty, unreadable, or larger than 4096 bytes
 *   5 CREATE_NEW failed (an existing pathname always lands here)
 *   6 write/flush/close failed (the created file is removed via its own handle)
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 /* Windows 10; SetDefaultDllDirectories, FileDispositionInfo */
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

/* The ONE pathname this program can ever create, relative to the anchor. */
static const wchar_t DESCRIPTOR_FILENAME[] = L"runtime-descriptor.json";

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
 * resolved path, so this can only be a mistake or an attempt to make the fixed
 * filename land outside the verified anchor; the creator has no authority to
 * write anywhere but directly inside the anchor it was given.
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
 * Build exactly `<anchor>\runtime-descriptor.json`. The filename is a compile-time
 * constant: no caller-controlled component exists. Returns 0 on overflow.
 */
static int build_descriptor_path(const wchar_t *anchor, size_t anchor_len,
                                 wchar_t *out, size_t out_count) {
  size_t filename_len = wcslen(DESCRIPTOR_FILENAME);
  size_t pos;
  int need_separator;

  if (anchor == NULL || out == NULL || out_count == 0 || anchor_len == 0) {
    return 0;
  }
  need_separator = anchor[anchor_len - 1] != L'\\';

  /* anchor_len <= CREATOR_MAX_PATH and filename_len is a small constant, so this
   * sum cannot overflow size_t. */
  if (anchor_len + (need_separator ? 1u : 0u) + filename_len + 1u > out_count) {
    return 0;
  }

  memcpy(out, anchor, anchor_len * sizeof(wchar_t));
  pos = anchor_len;
  if (need_separator) {
    out[pos] = L'\\';
    pos += 1;
  }
  memcpy(out + pos, DESCRIPTOR_FILENAME, (filename_len + 1u) * sizeof(wchar_t));
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

  /* Exactly one argument. Any other argc — including a second argument that
   * might look like an owner SID or a filename — is rejected outright. */
  if (argv == NULL || argc != 2 || argv[1] == NULL) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }
  anchor = argv[1];
  anchor_len = wcsnlen(anchor, CREATOR_MAX_PATH + 1);
  if (anchor_len == 0 || anchor_len > CREATOR_MAX_PATH ||
      !is_supported_absolute(anchor, anchor_len) ||
      has_dot_component(anchor, anchor_len)) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }
  if (!build_descriptor_path(anchor, anchor_len, descriptor_path,
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

  /* CREATE_NEW is the stale-descriptor boundary: an existing pathname is never
   * opened, truncated, re-owned, or re-ACL'd — it is an error. DELETE is
   * requested so a failed write can be undone through THIS handle (see below),
   * never by deleting a pathname that may since have been replaced. */
  file = CreateFileW(descriptor_path, GENERIC_WRITE | DELETE, 0, &attributes,
                     CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
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
  if (!CloseHandle(file)) {
    /* The handle is gone or unusable either way; do not close it twice, and do
     * not delete by pathname. Report failure and let the caller fail closed. */
    file = INVALID_HANDLE_VALUE;
    emit_err("ERR_WRITE");
    exit_code = EXIT_WRITE_FAILED;
    goto cleanup;
  }
  file = INVALID_HANDLE_VALUE;
  exit_code = EXIT_OK;

cleanup:
  if (file != INVALID_HANDLE_VALUE) {
    /* A file was created but not completed. Remove it through its OWN handle:
     * FileDispositionInfo is bound to the file object this invocation created,
     * so unlike DeleteFileW it cannot possibly remove a different file that has
     * since taken the pathname. Best effort — a failure here is not fatal; the
     * caller fails closed and the next startup's stale-removal gate applies. */
    FILE_DISPOSITION_INFO disposition;
    ZeroMemory(&disposition, sizeof(disposition));
    disposition.DeleteFile = TRUE;
    (void)SetFileInformationByHandle(file, FileDispositionInfo, &disposition,
                                     sizeof(disposition));
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
