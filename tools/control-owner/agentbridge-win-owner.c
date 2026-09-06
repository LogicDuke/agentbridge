/*
 * agentbridge-win-owner.exe
 *
 * Decision 062 / PR #84 F1 (Amendment A) — control-anchor OWNER SID probe.
 *
 * Single, minimal, read-only operation: given exactly one absolute Windows path,
 * print the object's OWNER SID (canonical S-1-... string) to stdout and exit 0.
 * It never mutates an ACL or owner, never writes files, never touches the network,
 * registry, environment-selected behaviour, stdin, or any shell/child process.
 *
 * Contract (see tools/control-owner and src/control/control-store.ts):
 *   stdout on success : "S-1-...\n"  (nothing else)
 *   stderr            : a short bounded diagnostic token only (no path, no secret)
 *   exit codes        : 0 success
 *                       1 invalid arguments
 *                       2 GetNamedSecurityInfoW failed
 *                       3 owner absent / invalid
 *                       4 SID conversion failed
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
#include <wchar.h>

#define EXIT_OK 0
#define EXIT_INVALID_ARGS 1
#define EXIT_QUERY_FAILED 2
#define EXIT_OWNER_INVALID 3
#define EXIT_SID_CONVERT 4

/* Windows extended maximum path length (\\?\ form), in wide characters. */
#define OWNER_MAX_PATH 32767

/* A canonical SID string is far shorter than this; the cap keeps output bounded. */
#define OWNER_SID_BUF 512

static void emit_err(const char *token) {
  fputs(token, stderr);
  fputc('\n', stderr);
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

int wmain(int argc, wchar_t **argv) {
  /* Load system DLLs only from System32; never from the working directory. */
  SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

  if (argc != 2 || argv == NULL || argv[1] == NULL) {
    emit_err("ERR_ARGS");
    return EXIT_INVALID_ARGS;
  }

  const wchar_t *path = argv[1];
  size_t len = wcsnlen(path, OWNER_MAX_PATH + 1);
  if (len == 0 || len > OWNER_MAX_PATH || !is_supported_absolute(path, len)) {
    emit_err("ERR_PATH");
    return EXIT_INVALID_ARGS;
  }

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
