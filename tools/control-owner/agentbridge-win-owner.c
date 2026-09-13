/*
 * agentbridge-win-owner.exe
 *
 * Decision 062 control-anchor security-descriptor probe. Read-only always: it
 * never mutates an ACL or owner, never writes files, never touches the network,
 * registry, environment-selected behaviour, stdin, or any shell/child process.
 *
 * Two bounded modes:
 *
 *   (1) OWNER-ONLY  (PR #84 F1, Amendment A) — backward compatible:
 *         agentbridge-win-owner.exe <absolute-path>
 *       prints the object's OWNER SID (canonical S-1-... string) and exits 0.
 *
 *   (2) ACL SNAPSHOT  (PR #85 F3, Amendment B) — canonical-SID snapshot:
 *         agentbridge-win-owner.exe --acl <absolute-path>
 *       prints, from ONE GetNamedSecurityInfoW(OWNER | DACL) read, a bounded,
 *       deterministic, locale-independent snapshot of the OWNER SID, the DACL
 *       presence and PROTECTED state, and every DACL ACE (type, exact ACE
 *       flags, access mask, canonical SID). No account name lookup ever
 *       happens, so the output is identical on any locale.
 *
 * ACL-snapshot grammar V2 (LF-terminated ASCII lines, in this exact order):
 *
 *     AGENTBRIDGE-ACL-V2
 *     OWNER <sid>
 *     DACL <PRESENT|NULL|ABSENT> <PROTECTED|UNPROTECTED>
 *     ACES <count>
 *     ACE <ALLOW|DENY> 0xXX 0xXXXXXXXX <sid>   (x <count>, PRESENT only)
 *
 *   - <sid> is a canonical SID string from ConvertSidToStringSidW.
 *   - the DACL state and the SE_DACL_PROTECTED control bit come from the SAME
 *     security descriptor as the owner and the ACEs (one read, one truth). A
 *     NULL or ABSENT DACL emits `ACES 0` and no ACE lines (the consumer fails
 *     closed on both); an empty-but-present DACL emits `ACES 0`.
 *   - `0xXX` is the exact two-hex-digit ACE_HEADER AceFlags value. Only the
 *     inheritance/propagation bits (mask 0x1F: OBJECT_INHERIT, CONTAINER_INHERIT,
 *     NO_PROPAGATE_INHERIT, INHERIT_ONLY, INHERITED) are representable; any other
 *     bit fails closed rather than being collapsed into lossy prose.
 *   - only ACCESS_ALLOWED and ACCESS_DENIED simple ACEs are representable; any
 *     other ACE type, an invalid SID, an unconvertible SID, more than
 *     ACL_MAX_ACES ACEs, or an over-long snapshot fails closed (nothing partial
 *     is emitted on failure).
 *
 * Contract (see src/control/control-store.ts):
 *   stdout on success : the mode's exact bytes, nothing else
 *   stderr            : a short bounded diagnostic token only (no path, no secret)
 *   exit codes        : 0 success
 *                       1 invalid arguments
 *                       2 GetNamedSecurityInfoW failed
 *                       3 owner absent / invalid
 *                       4 SID conversion failed
 *                       5 DACL unreadable / unhandled ACE / output overflow
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
#define EXIT_QUERY_FAILED 2
#define EXIT_OWNER_INVALID 3
#define EXIT_SID_CONVERT 4
#define EXIT_ACL_FAILED 5

/* Windows extended maximum path length (\\?\ form), in wide characters. */
#define OWNER_MAX_PATH 32767

/* A canonical SID string is far shorter than this; the cap keeps output bounded. */
#define OWNER_SID_BUF 512

/* Bounded ACL-snapshot output: a hard cap on ACE count and total bytes so a
 * hostile or pathological descriptor can never produce unbounded output. */
#define ACL_MAX_ACES 256
#define ACL_OUT_MAX 65536

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
 * Accept only a fully-qualified absolute path: drive-absolute (X:\...) or a
 * UNC / extended prefix (\\...). Reject empty, relative, and drive-relative
 * (X:foo) paths. Wide-only; no ANSI conversion.
 */
static int is_supported_absolute(const wchar_t *p, size_t len) {
  if (len == 0) {
    return 0;
  }
  if (len >= 3 &&
      ((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) &&
      p[1] == L':' && p[2] == L'\\') {
    return 1; /* drive-absolute */
  }
  if (len >= 2 && p[0] == L'\\' && p[1] == L'\\') {
    return 1; /* UNC or \\?\ extended */
  }
  return 0;
}

/*
 * Convert a validated SID to its canonical string and append the UTF-8 bytes to
 * buf. Returns 1 on success, 0 on any failure (invalid SID, conversion failure,
 * or buffer overflow). *len is only advanced on success.
 */
static int append_sid(char *buf, size_t *len, PSID sid) {
  if (sid == NULL || !IsValidSid(sid)) {
    return 0;
  }
  LPWSTR wide = NULL;
  if (!ConvertSidToStringSidW(sid, &wide)) {
    return 0;
  }
  char utf8[OWNER_SID_BUF];
  int need = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
  if (need <= 0 || need > OWNER_SID_BUF) {
    LocalFree(wide);
    return 0;
  }
  if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, need, NULL, NULL) <= 0) {
    LocalFree(wide);
    return 0;
  }
  LocalFree(wide);
  size_t sid_len = (size_t)(need - 1); /* exclude the NUL terminator */
  if (*len + sid_len > ACL_OUT_MAX) {
    return 0;
  }
  memcpy(buf + *len, utf8, sid_len);
  *len += sid_len;
  return 1;
}

/* Append a NUL-terminated ASCII literal; returns 0 on overflow. */
static int append_str(char *buf, size_t *len, const char *s) {
  size_t n = strlen(s);
  if (*len + n > ACL_OUT_MAX) {
    return 0;
  }
  memcpy(buf + *len, s, n);
  *len += n;
  return 1;
}

/* ---- Mode 1: owner-only (F1, Amendment A) — byte-for-byte preserved ------- */

static int print_owner_sid(const wchar_t *path) {
  PSID owner = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  DWORD rc = GetNamedSecurityInfoW(path, SE_FILE_OBJECT,
                                   OWNER_SECURITY_INFORMATION, &owner, NULL,
                                   NULL, NULL, &sd);
  if (rc != ERROR_SUCCESS) {
    emit_err("ERR_QUERY");
    return EXIT_QUERY_FAILED;
  }

  if (owner == NULL || !IsValidSid(owner)) {
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_OWNER");
    return EXIT_OWNER_INVALID;
  }

  LPWSTR sid_str = NULL;
  if (!ConvertSidToStringSidW(owner, &sid_str)) {
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_SID");
    return EXIT_SID_CONVERT;
  }

  /* Emit exactly "<sid>\n" as UTF-8 bytes with no newline translation. */
  char utf8[OWNER_SID_BUF];
  int need = WideCharToMultiByte(CP_UTF8, 0, sid_str, -1, NULL, 0, NULL, NULL);
  if (need <= 0 || need > OWNER_SID_BUF) {
    LocalFree(sid_str);
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_SID");
    return EXIT_SID_CONVERT;
  }
  if (WideCharToMultiByte(CP_UTF8, 0, sid_str, -1, utf8, need, NULL, NULL) <= 0) {
    LocalFree(sid_str);
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_SID");
    return EXIT_SID_CONVERT;
  }

  (void)_setmode(_fileno(stdout), _O_BINARY);
  /* need includes the NUL terminator; write the SID bytes then a single LF. */
  fwrite(utf8, 1, (size_t)(need - 1), stdout);
  fputc('\n', stdout);
  (void)fflush(stdout);

  LocalFree(sid_str);
  if (sd != NULL) {
    LocalFree(sd);
  }
  return EXIT_OK;
}

/* ---- Mode 2: ACL snapshot (F3, Amendment B) ------------------------------ */

static int print_acl_snapshot(const wchar_t *path) {
  PSID owner = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  DWORD rc = GetNamedSecurityInfoW(
      path, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
      &dacl, NULL, &sd);
  if (rc != ERROR_SUCCESS) {
    emit_err("ERR_QUERY");
    return EXIT_QUERY_FAILED;
  }

  if (owner == NULL || !IsValidSid(owner)) {
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_OWNER");
    return EXIT_OWNER_INVALID;
  }

  /* The DACL state and the PROTECTED control bit are read from the SAME
   * security descriptor the owner and ACEs came from, so the snapshot is one
   * coherent read. GetSecurityDescriptorDacl distinguishes ABSENT (no DACL in
   * the descriptor at all) from NULL (present flag set, NULL pointer: grants
   * everyone); both are represented explicitly so the consumer fails closed. */
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD control_revision = 0;
  BOOL sd_dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  PACL sd_dacl = NULL;
  if (!GetSecurityDescriptorControl(sd, &control, &control_revision) ||
      !GetSecurityDescriptorDacl(sd, &sd_dacl_present, &sd_dacl,
                                 &dacl_defaulted)) {
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_ACL");
    return EXIT_ACL_FAILED;
  }
  (void)control_revision;
  (void)dacl_defaulted;

  /* A present DACL must be the very ACL GetNamedSecurityInfoW returned and be
   * structurally valid. */
  int dacl_present = sd_dacl_present && sd_dacl != NULL;
  if (dacl_present && (dacl != sd_dacl || !IsValidAcl(sd_dacl))) {
    if (sd != NULL) {
      LocalFree(sd);
    }
    emit_err("ERR_ACL");
    return EXIT_ACL_FAILED;
  }

  DWORD ace_count = 0;
  if (dacl_present) {
    ACL_SIZE_INFORMATION size_info;
    if (!GetAclInformation(dacl, &size_info, sizeof(size_info),
                           AclSizeInformation)) {
      if (sd != NULL) {
        LocalFree(sd);
      }
      emit_err("ERR_ACL");
      return EXIT_ACL_FAILED;
    }
    ace_count = size_info.AceCount;
    if (ace_count > ACL_MAX_ACES) {
      if (sd != NULL) {
        LocalFree(sd);
      }
      emit_err("ERR_OVERFLOW");
      return EXIT_ACL_FAILED;
    }
  }

  /* Build the whole snapshot in a bounded buffer; only emit if it all fits and
   * every ACE is representable (all-or-nothing, never a partial snapshot). */
  char out[ACL_OUT_MAX];
  size_t len = 0;
  char header[128];
  (void)_snprintf_s(header, sizeof(header), _TRUNCATE,
                    "AGENTBRIDGE-ACL-V2\nOWNER ");
  int ok = append_str(out, &len, header);
  ok = ok && append_sid(out, &len, owner);
  ok = ok && append_str(out, &len, "\nDACL ");
  ok = ok && append_str(out, &len,
                        dacl_present ? "PRESENT" : (sd_dacl_present ? "NULL" : "ABSENT"));
  ok = ok && append_str(out, &len,
                        (control & SE_DACL_PROTECTED) != 0 ? " PROTECTED"
                                                            : " UNPROTECTED");

  char aces_line[64];
  (void)_snprintf_s(aces_line, sizeof(aces_line), _TRUNCATE, "\nACES %lu\n",
                    (unsigned long)ace_count);
  ok = ok && append_str(out, &len, aces_line);

  for (DWORD i = 0; ok && dacl_present && i < ace_count; i += 1) {
    LPVOID ace_ptr = NULL;
    if (!GetAce(dacl, i, &ace_ptr) || ace_ptr == NULL) {
      ok = 0;
      break;
    }
    ACE_HEADER *hdr = (ACE_HEADER *)ace_ptr;

    const char *type_str;
    if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
      type_str = "ALLOW";
    } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
      type_str = "DENY";
    } else {
      /* Any audit/alarm/object/callback ACE is unhandled — fail closed. */
      ok = 0;
      break;
    }

    /* ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share Mask + SidStart layout. */
    ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)ace_ptr;
    PSID ace_sid = (PSID)&ace->SidStart;
    /* ALLOW/DENY ACEs carry only inheritance/propagation flags (mask 0x1F).
     * Any other bit (audit success/failure, critical, or a future/unknown
     * flag) is not safely representable — fail closed, never lossy prose. */
    if ((hdr->AceFlags & (BYTE)~0x1F) != 0) {
      ok = 0;
      break;
    }

    char ace_prefix[64];
    (void)_snprintf_s(ace_prefix, sizeof(ace_prefix), _TRUNCATE,
                      "ACE %s 0x%02X 0x%08X ", type_str,
                      (unsigned int)hdr->AceFlags, (unsigned int)ace->Mask);
    ok = ok && append_str(out, &len, ace_prefix);
    ok = ok && append_sid(out, &len, ace_sid);
    ok = ok && append_str(out, &len, "\n");
  }

  if (sd != NULL) {
    LocalFree(sd);
  }

  if (!ok) {
    emit_err("ERR_ACL");
    return EXIT_ACL_FAILED;
  }

  write_stdout(out, len);
  return EXIT_OK;
}

int wmain(int argc, wchar_t **argv) {
  /* Load system DLLs only from System32; never from the working directory. */
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

  if (argv == NULL) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }

  /* Exactly one of two shapes: `<path>` (owner-only) or `--acl <path>`. Any
   * other argc, or a first token that is neither, is rejected — this also
   * rejects extra trailing arguments in both modes. */
  int acl_mode;
  const wchar_t *path;
  if (argc == 2 && argv[1] != NULL) {
    acl_mode = 0;
    path = argv[1];
  } else if (argc == 3 && argv[1] != NULL && argv[2] != NULL &&
             wcscmp(argv[1], L"--acl") == 0) {
    acl_mode = 1;
    path = argv[2];
  } else {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }

  size_t len = wcsnlen(path, OWNER_MAX_PATH + 1);
  if (len == 0 || len > OWNER_MAX_PATH || !is_supported_absolute(path, len)) {
    emit_err("ERR_PATH");
    return EXIT_INVALID_ARGS;
  }

  return acl_mode ? print_acl_snapshot(path) : print_owner_sid(path);
}
