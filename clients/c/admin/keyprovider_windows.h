/* Included by admin.c after key material parsing helpers. */
#include <windows.h>
/* Quote one argv entry according to the Windows C runtime parsing rules. */
static wchar_t *kp_quote(wchar_t *dst, const wchar_t *arg) {
  *dst++ = L'"';
  while (*arg) {
    size_t slashes = 0;
    while (*arg == L'\\') { ++slashes; ++arg; }
    size_t copies = (*arg == L'"' || !*arg) ? slashes * 2 : slashes;
    while (copies--) *dst++ = L'\\';
    if (!*arg) break;
    if (*arg == L'"') *dst++ = L'\\';
    *dst++ = *arg++;
  }
  *dst++ = L'"';
  return dst;
}
static wchar_t *kp_wide(const char *s) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
  if (!n) return NULL;
  wchar_t *out = malloc((size_t)n * sizeof(*out));
  if (out && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out, n)) { free(out); return NULL; }
  return out;
}
/* Drain both streams on each iteration so a full stderr pipe cannot wedge stdout. */
static int kp_drain(HANDLE pipe, uint8_t *out, size_t *n, size_t limit) {
  for (unsigned round = 0; round < 16; ++round) {
    DWORD available = 0, got = 0;
    if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL))
      return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;
    if (!available) return 0;
    uint8_t scratch[4096];
    DWORD want = available < sizeof(scratch) ? available : sizeof(scratch);
    if (!ReadFile(pipe, scratch, want, &got, NULL)) return -1;
    size_t copy = got < limit - *n ? got : limit - *n;
    memcpy(out + *n, scratch, copy); *n += copy;
    SecureZeroMemory(scratch, sizeof(scratch));
    if (*n == limit) return 1;
  }
  return 0;
}
static int kp_exec(const char *helper, const char *uri, long timeout_s,
                   uint8_t out[32], char *err, size_t cap) {
  int rc = -1;
  HANDLE so = NULL, sw = NULL, se = NULL, ew = NULL;
  PROCESS_INFORMATION process = {0};
  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  wchar_t *exe = kp_wide(helper), *arg = kp_wide(uri), *cmd = NULL;
  uint8_t *raw = malloc(KP_MAX_PAYLOAD + 1), serr[1024] = {0};
  size_t n = 0, sn = 0;
  if (!exe || !arg || !raw) goto cleanup;
  cmd = calloc(2 * (wcslen(exe) + wcslen(arg)) + 8, sizeof(*cmd));
  if (!cmd) goto cleanup;
  wchar_t *end = kp_quote(cmd, exe); *end++ = L' '; end = kp_quote(end, arg); *end = 0;
  if (!CreatePipe(&so, &sw, &sa, 0) || !CreatePipe(&se, &ew, &sa, 0) ||
      !SetHandleInformation(so, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(se, HANDLE_FLAG_INHERIT, 0)) goto cleanup;
  STARTUPINFOW startup = {0}; startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = sw; startup.hStdError = ew;
  HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &sa, OPEN_EXISTING, 0, NULL);
  if (input == INVALID_HANDLE_VALUE) goto cleanup;
  startup.hStdInput = input;
  BOOL created = CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                                NULL, NULL, &startup, &process);
  CloseHandle(input);
  if (!created) goto cleanup;
  CloseHandle(sw); sw = NULL; CloseHandle(ew); ew = NULL;
  ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(timeout_s > 0 ? timeout_s : 30) * 1000;
  int done = 0;
  for (;;) {
    int a = kp_drain(so, raw, &n, KP_MAX_PAYLOAD + 1);
    /* Keep draining stderr even after the retained diagnostic buffer fills. */
    uint8_t discarded[4096]; size_t dn = 0;
    int b = sn < sizeof(serr)-1 ? kp_drain(se, serr, &sn, sizeof(serr)-1) : kp_drain(se, discarded, &dn, sizeof(discarded));
    if (n > KP_MAX_PAYLOAD) { snprintf(err, cap, "keyprovider: helper output exceeds %u bytes", KP_MAX_PAYLOAD); break; }
    if (a < 0 || b < 0) { snprintf(err, cap, "keyprovider: pipe read failed"); break; }
    if (done && a == 0 && b == 0) {
      DWORD status = 1; GetExitCodeProcess(process.hProcess, &status);
      if (status != 0) snprintf(err, cap, "keyprovider: helper exited %lu: %.256s", (unsigned long)status, (char*)serr);
      else if (parse_key_material(raw, n, out)) snprintf(err, cap, "keyprovider: helper: want 32 bytes or 64 hex chars");
      else rc = 0;
      break;
    }
    if (GetTickCount64() >= deadline) { snprintf(err, cap, "keyprovider: helper timed out"); break; }
    done = WaitForSingleObject(process.hProcess, 10) == WAIT_OBJECT_0;
  }
cleanup:
  if (process.hProcess) {
    if (WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0) {
      TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, INFINITE);
    }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
  } else snprintf(err, cap, "keyprovider: could not launch helper");
  if (so) CloseHandle(so); if (sw) CloseHandle(sw);
  if (se) CloseHandle(se); if (ew) CloseHandle(ew);
  if (raw) { wipe(raw, KP_MAX_PAYLOAD + 1); free(raw); }
  wipe(serr, sizeof(serr));
  if (cmd) { SecureZeroMemory(cmd, wcslen(cmd) * sizeof(*cmd)); free(cmd); }
  free(exe);
  if (arg) { SecureZeroMemory(arg, wcslen(arg) * sizeof(*arg)); free(arg); }
  return rc;
}
