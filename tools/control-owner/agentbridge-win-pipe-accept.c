/*
 * agentbridge-win-pipe-accept.node
 *
 * DDR-D062-C / D062 Runtime Authentication Revision 2 — EXPLICIT OPERATOR-SID
 * CONTROL PIPE ACCEPT PROVIDER.
 *
 * WHY IT EXISTS
 *
 * Node's own named-pipe server (libuv) creates every pipe instance with a NULL
 * lpSecurityAttributes, so the kernel assigns the DEFAULT named-pipe security
 * descriptor, which grants broad principals (Everyone / ANONYMOUS LOGON /
 * Users, depending on the system) read/write access to the pipe. The control
 * channel's authorization never rested on that descriptor — token possession
 * (HMAC) and live pipe-object attestation are the authenticators — but a
 * pipe reachable by every local principal is a wider transport access boundary
 * than the control channel needs, and JavaScript cannot narrow it: neither
 * Node nor libuv exposes SECURITY_ATTRIBUTES for a listening pipe.
 *
 * This in-process Node-API addon is the ONE narrow native capability that
 * closes that boundary. It creates every server instance of the control pipe
 * with an EXPLICIT security descriptor:
 *
 *   OWNER  = this process's exact TokenUser SID (never the token's default
 *            owner, never a name-resolved substitute, never an input)
 *   DACL   = PRESENT, PROTECTED (SE_DACL_PROTECTED), exactly ONE ALLOW ACE
 *   ACE    = that same TokenUser SID, NO_INHERITANCE,
 *            mask FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE
 *                 = 0x12019F
 *
 * No SYSTEM, no Everyone, no ANONYMOUS LOGON, no Users, no Authenticated Users,
 * no BUILTIN\Administrators, no foreign SID, no WRITE_DAC, no WRITE_OWNER, no
 * DELETE. A NULL or absent DACL is never produced. The FILE_APPEND_DATA /
 * FILE_CREATE_PIPE_INSTANCE alias (0x0004, inside FILE_GENERIC_WRITE) for the
 * exact trusted SID is the adopted residual of Model A and is deliberately NOT
 * removed here.
 *
 * NODE REMAINS THE SERVER PROCESS. The instances are created INSIDE the Node
 * runtime process by this addon: there is no helper, broker, or service. The
 * attestation path does not observe that fact through any process identity — it
 * reads the OWNER and DACL of the kernel PIPE OBJECT behind its own connected
 * handle, and never resolves a server PID or a server process's TokenUser SID.
 * What this addon guarantees for it is the descriptor above, written onto every
 * instance of the pipe NAME.
 *
 * WHAT IT DOES (the complete list)
 *   1. reads its own process token's TokenUser SID;
 *   2. builds the explicit security descriptor above, once per server;
 *   3. creates every named-pipe server instance with SECURITY_ATTRIBUTES
 *      carrying exactly that descriptor (FILE_FLAG_OVERLAPPED; the FIRST
 *      instance also FILE_FLAG_FIRST_PIPE_INSTANCE, so a same-name collision
 *      fails closed at listen time exactly as before);
 *   4. waits for a client asynchronously (overlapped ConnectNamedPipe + a
 *      thread-pool wait on the completion event; the JavaScript thread is never
 *      blocked and the libuv threadpool is never occupied);
 *   5. converts the connected HANDLE into a libuv file descriptor through the
 *      host's exported `uv_open_osfhandle` and hands that fd to JavaScript,
 *      which adopts it as an ordinary `net.Socket`. From that moment the socket
 *      is owned by JavaScript and libuv; this addon never touches it again.
 *
 * WHAT IT NEVER DOES
 *   - read or write a single protocol byte (no ReadFile/WriteFile on any pipe)
 *   - read descriptor or token files, or any file at all (no CreateFileW)
 *   - HMAC, Ed25519, or any cryptography
 *   - parse, dispatch, or construct a command or a WorkflowEvent
 *   - call into the orchestrator or any JavaScript other than the accept
 *     callback it was given
 *   - mutate a filesystem ACL or object ownership (nothing is re-ACL'd; the
 *     descriptor is chosen at CreateNamedPipeW time and never edited)
 *   - spawn a process, run a shell, perform a PATH lookup, or load a library
 *     (`uv_open_osfhandle` is resolved from the host process image that is
 *     already executing this addon, never from a DLL on disk)
 *   - touch Git, GitHub, the network, or the registry
 *   - act as a broker, service, helper process, or a general native runner
 *
 * The sole caller-controlled input is the pipe PATH, which must be a local
 * `\\.\pipe\<name>` (a UNC form is rejected). Instances are byte-mode,
 * PIPE_WAIT, and reject remote clients.
 *
 * JavaScript surface (Node-API, version floor 10):
 *
 *   createServer(pipePath: string, onAccept: (error: string | null, fd: number) => void)
 *     -> { accept(): void; close(): void }
 *
 *   createServer creates + arms the FIRST instance synchronously (throwing on
 *   any failure, including a name collision), so a resolved call means the
 *   name is held by THIS process. Each completed accept invokes `onAccept`
 *   exactly once on the JavaScript thread: `(null, fd)` with a libuv fd that
 *   JavaScript now owns, or `("ERR_... (win32)", -1)` after the failed
 *   instance has been closed here. The next instance is created only when
 *   JavaScript calls `accept()` again (one pending instance at a time), so
 *   JavaScript decides the accept cadence. `close()` cancels the pending
 *   instance, stops the wait, and releases every native resource; sockets
 *   already handed out are unaffected (they belong to JavaScript).
 *
 * Every failure is reported with a short fixed ASCII token plus the Win32
 * error number — never a path, never a SID, never bytes. Nothing is written to
 * stdout or stderr, ever.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 /* Windows 10 */
#endif
#define WIN32_LEAN_AND_MEAN

/* D062 Revision 2 native build policy: Node-API floor 10. Only the headers'
 * version-10-or-lower surface is compiled against; the source is the frozen
 * binding of that floor (a build flag cannot silently lower it). */
#ifndef NAPI_VERSION
#define NAPI_VERSION 10
#endif
#if NAPI_VERSION < 10
#error "agentbridge-win-pipe-accept requires Node-API version 10 or later"
#endif

#include <windows.h>
#include <aclapi.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <node_api.h>

/* Windows extended maximum path length, in wide characters. */
#define ACCEPT_MAX_PATH 32767

/* A TOKEN_USER for any real principal is far smaller; the cap keeps it bounded. */
#define TOKEN_INFO_MAX 4096

/* libuv's own named-pipe buffer size, so the transport behaves as before. */
#define PIPE_BUFFER_BYTES 65536

/* The ONE access mask the ONE ACE grants: FILE_GENERIC_READ | FILE_GENERIC_WRITE
 * | SYNCHRONIZE. Pinned at compile time to the exact adopted value, and proven
 * free of the forbidden rights, so no header drift can widen it silently. */
#define PIPE_ACCESS_MASK (FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE)
_Static_assert(PIPE_ACCESS_MASK == 0x12019FUL,
               "DDR-D062-C: the single pipe ACE must grant exactly 0x12019F");
_Static_assert((PIPE_ACCESS_MASK & (WRITE_DAC | WRITE_OWNER | DELETE)) == 0,
               "DDR-D062-C: WRITE_DAC, WRITE_OWNER and DELETE are forbidden");

/* int uv_open_osfhandle(uv_os_fd_t) — exported by the Node host executable. */
typedef int (*open_osfhandle_fn)(HANDLE);

typedef struct pipe_server {
  /* Marshals the thread-pool wait completion onto the JavaScript thread. */
  napi_threadsafe_function tsfn;
  open_osfhandle_fn open_osfhandle;

  wchar_t *path;

  /* The explicit security descriptor, built once, applied to EVERY instance. */
  TOKEN_USER *token_user;
  PSID operator_sid;
  PACL dacl;
  SECURITY_DESCRIPTOR sd;
  SECURITY_ATTRIBUTES sa;

  /* The one pending (created, not yet connected) instance and its wait. */
  HANDLE event;
  HANDLE instance;
  HANDLE wait;
  OVERLAPPED ov;
  int connected_sync;

  int closed;
  /* Two owners: the threadsafe function's finalizer and the JavaScript wrapper
   * (or the creator, before the wrapper exists). The last one frees. */
  int owners;
} pipe_server;

/*
 * Accept only a local named-pipe path: exactly the local pipe prefix followed
 * by at least one more character (the same shape the pipe attestor accepts).
 * A UNC form (\\server\pipe\...) is rejected: this addon serves a LOCAL pipe.
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
 * The runtime operator is THIS process's token user — never an argument, never
 * a name lookup. The TOKEN_USER buffer backs the returned PSID, so it is
 * returned too and freed by the caller. Identical to the descriptor creator.
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
 * The explicit pipe security: owner = exact TokenUser SID; DACL present,
 * protected, exactly ONE ALLOW ACE for that same SID with PIPE_ACCESS_MASK and
 * NO_INHERITANCE. Built once per server; every instance is created with it.
 */
static int build_pipe_security(pipe_server *s) {
  EXPLICIT_ACCESSW entry;

  if (!current_token_user(&s->operator_sid, &s->token_user)) {
    return 0;
  }

  ZeroMemory(&entry, sizeof(entry));
  entry.grfAccessPermissions = PIPE_ACCESS_MASK;
  entry.grfAccessMode = SET_ACCESS;
  entry.grfInheritance = NO_INHERITANCE;
  entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
  entry.Trustee.ptstrName = (LPWSTR)s->operator_sid;

  s->dacl = NULL;
  if (SetEntriesInAclW(1, &entry, NULL, &s->dacl) != ERROR_SUCCESS || s->dacl == NULL) {
    return 0;
  }

  if (!InitializeSecurityDescriptor(&s->sd, SECURITY_DESCRIPTOR_REVISION) ||
      !SetSecurityDescriptorOwner(&s->sd, s->operator_sid, FALSE) ||
      !SetSecurityDescriptorDacl(&s->sd, TRUE, s->dacl, FALSE) ||
      !SetSecurityDescriptorControl(&s->sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    return 0;
  }

  ZeroMemory(&s->sa, sizeof(s->sa));
  s->sa.nLength = sizeof(s->sa);
  s->sa.lpSecurityDescriptor = &s->sd;
  s->sa.bInheritHandle = FALSE;
  return 1;
}

/* Thread-pool wait callback: the completion event fired. Marshal to JS only. */
static void CALLBACK on_wait(PVOID context, BOOLEAN timed_out) {
  pipe_server *s = (pipe_server *)context;
  (void)timed_out;
  if (s != NULL && s->tsfn != NULL) {
    (void)napi_call_threadsafe_function(s->tsfn, NULL, napi_tsfn_nonblocking);
  }
}

/*
 * Create ONE server instance with the explicit SECURITY_ATTRIBUTES and arm an
 * asynchronous ConnectNamedPipe on it. Exactly one pending instance exists at
 * a time. Returns 1 on success; on failure returns 0 with a fixed token and
 * the Win32 error, having closed anything it created.
 */
static int arm_accept(pipe_server *s, int first, const char **code, DWORD *win32) {
  DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
  HANDLE h;

  if (s->instance != INVALID_HANDLE_VALUE) {
    return 1; /* already armed */
  }
  if (first) {
    /* Kernel-owned exclusivity: an existing pipe of this name fails here. */
    open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
  }

  /* EVERY instance carries the explicit descriptor — there is no other
   * CreateNamedPipeW call in this addon. */
  h = CreateNamedPipeW(s->path, open_mode,
                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                           PIPE_REJECT_REMOTE_CLIENTS,
                       PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_BYTES, PIPE_BUFFER_BYTES,
                       0, &s->sa);
  if (h == INVALID_HANDLE_VALUE) {
    *code = "ERR_PIPE_CREATE";
    *win32 = GetLastError();
    return 0;
  }

  ZeroMemory(&s->ov, sizeof(s->ov));
  s->ov.hEvent = s->event;
  s->connected_sync = 0;
  if (!ResetEvent(s->event)) {
    *code = "ERR_WAIT";
    *win32 = GetLastError();
    CloseHandle(h);
    return 0;
  }

  if (ConnectNamedPipe(h, &s->ov)) {
    s->connected_sync = 1;
    SetEvent(s->event);
  } else {
    DWORD e = GetLastError();
    if (e == ERROR_PIPE_CONNECTED) {
      /* A client connected between creation and this call. */
      s->connected_sync = 1;
      SetEvent(s->event);
    } else if (e != ERROR_IO_PENDING) {
      *code = "ERR_PIPE_CONNECT";
      *win32 = e;
      CloseHandle(h);
      return 0;
    }
  }
  s->instance = h;

  if (!RegisterWaitForSingleObject(&s->wait, s->event, on_wait, s, INFINITE,
                                   WT_EXECUTEONLYONCE)) {
    DWORD e = GetLastError();
    s->wait = NULL;
    if (!s->connected_sync) {
      DWORD n = 0;
      CancelIoEx(h, &s->ov);
      (void)GetOverlappedResult(h, &s->ov, &n, TRUE);
    }
    CloseHandle(h);
    s->instance = INVALID_HANDLE_VALUE;
    *code = "ERR_WAIT";
    *win32 = e;
    return 0;
  }
  return 1;
}

/* Stop accepting and release the pending instance; idempotent; JS thread only. */
static void do_close(pipe_server *s) {
  if (s->closed) {
    return;
  }
  s->closed = 1;
  if (s->wait != NULL) {
    /* Blocks only until an in-flight on_wait (a non-blocking enqueue) returns. */
    (void)UnregisterWaitEx(s->wait, INVALID_HANDLE_VALUE);
    s->wait = NULL;
  }
  if (s->instance != INVALID_HANDLE_VALUE) {
    if (!s->connected_sync) {
      DWORD n = 0;
      CancelIoEx(s->instance, &s->ov);
      (void)GetOverlappedResult(s->instance, &s->ov, &n, TRUE);
    }
    CloseHandle(s->instance);
    s->instance = INVALID_HANDLE_VALUE;
  }
  if (s->tsfn != NULL) {
    napi_threadsafe_function tsfn = s->tsfn;
    s->tsfn = NULL;
    (void)napi_release_threadsafe_function(tsfn, napi_tsfn_abort);
  }
}

static void free_server(pipe_server *s) {
  if (s->event != NULL) {
    CloseHandle(s->event);
  }
  if (s->dacl != NULL) {
    LocalFree(s->dacl); /* SetEntriesInAclW allocates with LocalAlloc. */
  }
  if (s->token_user != NULL) {
    LocalFree(s->token_user); /* Backs operator_sid. */
  }
  free(s->path);
  free(s);
}

static void release_owner(pipe_server *s) {
  if (--s->owners == 0) {
    free_server(s);
  }
}

/* The threadsafe function is fully torn down (JS thread). */
static void on_tsfn_finalize(napi_env env, void *data, void *hint) {
  pipe_server *s = (pipe_server *)data;
  (void)env;
  (void)hint;
  if (s == NULL) {
    return;
  }
  s->tsfn = NULL; /* already gone; do_close must not release it again */
  do_close(s);
  release_owner(s);
}

/* The JavaScript wrapper was collected without an explicit close(). */
static void on_wrap_finalize(napi_env env, void *data, void *hint) {
  pipe_server *s = (pipe_server *)data;
  (void)env;
  (void)hint;
  if (s == NULL) {
    return;
  }
  do_close(s);
  release_owner(s);
}

/*
 * JS thread: one accept completed (or failed). Hand the connected HANDLE to
 * JavaScript as a libuv fd — or report the failure — exactly once. The next
 * instance is created only when JavaScript calls accept() again.
 */
static void on_completion(napi_env env, napi_value js_cb, void *context, void *data) {
  pipe_server *s = (pipe_server *)context;
  HANDLE h;
  DWORD transferred = 0;
  DWORD win32 = 0;
  const char *code = NULL;
  int fd = -1;
  napi_value argv[2];
  napi_value undefined;
  napi_value result;
  char message[64];

  (void)data;
  if (env == NULL || s == NULL || s->closed) {
    return;
  }
  if (s->wait != NULL) {
    (void)UnregisterWaitEx(s->wait, INVALID_HANDLE_VALUE);
    s->wait = NULL;
  }
  h = s->instance;
  s->instance = INVALID_HANDLE_VALUE;
  if (h == INVALID_HANDLE_VALUE) {
    return;
  }

  if (!s->connected_sync && !GetOverlappedResult(h, &s->ov, &transferred, FALSE)) {
    win32 = GetLastError();
    code = "ERR_PIPE_CONNECT";
    CloseHandle(h);
  } else {
    /* Ownership of `h` transfers to the libuv fd; JavaScript closes it. */
    fd = s->open_osfhandle(h);
    if (fd < 0) {
      code = "ERR_OSFHANDLE";
      win32 = 0;
      CloseHandle(h);
      fd = -1;
    }
  }

  if (code == NULL) {
    if (napi_get_null(env, &argv[0]) != napi_ok) {
      return;
    }
  } else {
    (void)snprintf(message, sizeof(message), "%s (%lu)", code, (unsigned long)win32);
    if (napi_create_string_utf8(env, message, NAPI_AUTO_LENGTH, &argv[0]) != napi_ok) {
      return;
    }
  }
  if (napi_create_int32(env, fd, &argv[1]) != napi_ok ||
      napi_get_undefined(env, &undefined) != napi_ok) {
    return;
  }
  (void)napi_call_function(env, undefined, js_cb, 2, argv, &result);
}

static void throw_with(napi_env env, const char *code, DWORD win32) {
  char message[64];
  (void)snprintf(message, sizeof(message), "%s (%lu)", code, (unsigned long)win32);
  (void)napi_throw_error(env, "ERR_AGENTBRIDGE_PIPE_ACCEPT", message);
}

static pipe_server *unwrap_server(napi_env env, napi_callback_info info) {
  napi_value js_this;
  void *raw = NULL;
  size_t argc = 0;
  if (napi_get_cb_info(env, info, &argc, NULL, &js_this, NULL) != napi_ok ||
      napi_unwrap(env, js_this, &raw) != napi_ok) {
    return NULL;
  }
  return (pipe_server *)raw;
}

/* accept(): create + arm the NEXT instance (no-op if one is already pending). */
static napi_value js_accept(napi_env env, napi_callback_info info) {
  pipe_server *s = unwrap_server(env, info);
  const char *code = NULL;
  DWORD win32 = 0;
  if (s == NULL || s->closed) {
    throw_with(env, "ERR_CLOSED", 0);
    return NULL;
  }
  if (!arm_accept(s, 0, &code, &win32)) {
    throw_with(env, code, win32);
    return NULL;
  }
  return NULL;
}

/* close(): stop accepting, release the pending instance and every resource. */
static napi_value js_close(napi_env env, napi_callback_info info) {
  napi_value js_this;
  void *raw = NULL;
  size_t argc = 0;
  pipe_server *s;
  if (napi_get_cb_info(env, info, &argc, NULL, &js_this, NULL) != napi_ok ||
      napi_remove_wrap(env, js_this, &raw) != napi_ok || raw == NULL) {
    return NULL; /* already closed */
  }
  s = (pipe_server *)raw;
  do_close(s);
  release_owner(s); /* the wrapper's ownership ends here */
  return NULL;
}

/* createServer(pipePath, onAccept): hold the name and arm the first accept. */
static napi_value js_create_server(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  napi_valuetype type;
  size_t len = 0;
  size_t got = 0;
  pipe_server *s;
  napi_value resource_name;
  napi_value object;
  HMODULE host;
  const char *code = NULL;
  DWORD win32 = 0;
  napi_property_descriptor methods[2];

  if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 2 ||
      napi_typeof(env, argv[0], &type) != napi_ok || type != napi_string ||
      napi_typeof(env, argv[1], &type) != napi_ok || type != napi_function) {
    (void)napi_throw_type_error(env, "ERR_AGENTBRIDGE_PIPE_ACCEPT",
                                "createServer(pipePath: string, onAccept: function)");
    return NULL;
  }
  if (napi_get_value_string_utf16(env, argv[0], NULL, 0, &len) != napi_ok || len == 0 ||
      len > ACCEPT_MAX_PATH) {
    throw_with(env, "ERR_PIPE_PATH", 0);
    return NULL;
  }

  s = (pipe_server *)calloc(1, sizeof(*s));
  if (s == NULL) {
    throw_with(env, "ERR_MEMORY", 0);
    return NULL;
  }
  s->instance = INVALID_HANDLE_VALUE;
  s->owners = 2;

  s->path = (wchar_t *)calloc(len + 1, sizeof(wchar_t));
  if (s->path == NULL ||
      napi_get_value_string_utf16(env, argv[0], (char16_t *)s->path, len + 1, &got) !=
          napi_ok ||
      got != len || !is_local_pipe_path(s->path, len)) {
    free_server(s);
    throw_with(env, "ERR_PIPE_PATH", 0);
    return NULL;
  }

  /* The host process image that is executing this addon exports libuv's
   * uv_open_osfhandle (Node builds its CRT statically, so only the host's own
   * CRT can mint a file descriptor libuv will accept). No library is loaded. */
  host = GetModuleHandleW(NULL);
  s->open_osfhandle =
      host == NULL ? NULL : (open_osfhandle_fn)(void *)GetProcAddress(host, "uv_open_osfhandle");
  if (s->open_osfhandle == NULL) {
    free_server(s);
    throw_with(env, "ERR_HOST", GetLastError());
    return NULL;
  }

  s->event = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (s->event == NULL) {
    win32 = GetLastError();
    free_server(s);
    throw_with(env, "ERR_WAIT", win32);
    return NULL;
  }

  if (!build_pipe_security(s)) {
    win32 = GetLastError();
    free_server(s);
    throw_with(env, "ERR_ACL", win32);
    return NULL;
  }

  if (napi_create_string_utf8(env, "agentbridge-pipe-accept", NAPI_AUTO_LENGTH,
                              &resource_name) != napi_ok ||
      napi_create_threadsafe_function(env, argv[1], NULL, resource_name, 0, 1, s,
                                      on_tsfn_finalize, s, on_completion,
                                      &s->tsfn) != napi_ok) {
    free_server(s);
    throw_with(env, "ERR_NAPI", 0);
    return NULL;
  }

  /* From here the threadsafe function owns one reference; failures release
   * the creator's reference and let the finalizer free the rest. */
  if (!arm_accept(s, 1, &code, &win32)) {
    do_close(s);
    release_owner(s);
    throw_with(env, code, win32);
    return NULL;
  }

  ZeroMemory(methods, sizeof(methods));
  methods[0].utf8name = "accept";
  methods[0].method = js_accept;
  methods[0].attributes = napi_default;
  methods[1].utf8name = "close";
  methods[1].method = js_close;
  methods[1].attributes = napi_default;

  if (napi_create_object(env, &object) != napi_ok ||
      napi_define_properties(env, object, 2, methods) != napi_ok ||
      napi_wrap(env, object, s, on_wrap_finalize, NULL, NULL) != napi_ok) {
    do_close(s);
    release_owner(s);
    throw_with(env, "ERR_NAPI", 0);
    return NULL;
  }
  return object;
}

/* Node-API module registration (explicit exports; no macro magic). */
NAPI_MODULE_EXPORT int32_t node_api_module_get_api_version_v1(void) {
  return NAPI_VERSION;
}

NAPI_MODULE_EXPORT napi_value napi_register_module_v1(napi_env env, napi_value exports) {
  napi_property_descriptor entry;
  ZeroMemory(&entry, sizeof(entry));
  entry.utf8name = "createServer";
  entry.method = js_create_server;
  entry.attributes = napi_default;
  if (napi_define_properties(env, exports, 1, &entry) != napi_ok) {
    return NULL;
  }
  return exports;
}
