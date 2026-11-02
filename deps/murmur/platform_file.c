#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <direct.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
/* Windows paths at the C API boundary are UTF-8. */
static wchar_t *wide(const char *path) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
  if (!n) { errno = EINVAL; return NULL; }
  wchar_t *result = malloc((size_t)n * sizeof(*result));
  if (!result) { errno = ENOMEM; return NULL; }
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, result, n)) {
    free(result); errno = EINVAL; return NULL;
  }
  return result;
}
static int winerr(void) {
  switch (GetLastError()) {
    case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: errno = ENOENT; break;
    case ERROR_ALREADY_EXISTS: case ERROR_FILE_EXISTS: errno = EEXIST; break;
    case ERROR_ACCESS_DENIED: case ERROR_SHARING_VIOLATION: errno = EACCES; break;
    default: errno = EIO;
  }
  return -1;
}
int murmur_file_stat(const char *path, struct stat *st) {
  wchar_t *p = wide(path); if (!p) return -1;
  struct _stat64 value;
  int rc = _wstat64(p, &value); free(p);
  if (rc) return rc;
  memset(st, 0, sizeof(*st));
  st->st_dev = value.st_dev; st->st_ino = value.st_ino;
  st->st_mode = value.st_mode; st->st_nlink = value.st_nlink;
  st->st_uid = value.st_uid; st->st_gid = value.st_gid;
  st->st_rdev = value.st_rdev; st->st_size = value.st_size;
  st->st_atime = value.st_atime; st->st_mtime = value.st_mtime; st->st_ctime = value.st_ctime;
  if ((long long)st->st_size != value.st_size) { errno = EOVERFLOW; return -1; }
  return 0;
}
int murmur_file_lstat(const char *path, struct stat *st) {
  wchar_t *p = wide(path); if (!p) return -1;
  DWORD flags = GetFileAttributesW(p); free(p);
  if (flags == INVALID_FILE_ATTRIBUTES) return winerr();
  /* Refuse traversal through junctions and symlinks in maintenance tools. */
  if (flags & FILE_ATTRIBUTE_REPARSE_POINT) { errno = ELOOP; return -1; }
  return murmur_file_stat(path, st);
}
int murmur_file_open(const char *path, int flags, ...) {
  int mode = 0;
  if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
  wchar_t *p = wide(path); if (!p) return -1;
  int fd = _wopen(p, flags | O_BINARY | O_NOINHERIT, mode);
  free(p); return fd;
}
int murmur_file_mkdir(const char *path, int mode) {
  (void)mode; wchar_t *p = wide(path); if (!p) return -1;
  int rc = _wmkdir(p); free(p); return rc;
}
int murmur_file_unlink(const char *path) {
  wchar_t *p = wide(path); if (!p) return -1;
  int rc = _wunlink(p); free(p); return rc;
}
int murmur_file_rename(const char *from, const char *to) {
  wchar_t *a = wide(from), *b = wide(to);
  if (!a || !b) { free(a); free(b); return -1; }
  int rc = MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ? 0 : winerr();
  free(a); free(b); return rc;
}
int murmur_file_link(const char *from, const char *to) {
  wchar_t *a = wide(from), *b = wide(to);
  if (!a || !b) { free(a); free(b); return -1; }
  int rc = CreateHardLinkW(b, a, NULL) ? 0 : winerr();
  free(a); free(b); return rc;
}
ssize_t murmur_file_pread(int fd, void *data, size_t size, long long offset) {
  if (offset < 0 || size > INT_MAX) { errno = EINVAL; return -1; }
  /* Reopen with an independent file position; do not race other descriptor users. */
  HANDLE h = ReOpenFile((HANDLE)_get_osfhandle(fd), GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OVERLAPPED);
  if (h == INVALID_HANDLE_VALUE) return winerr();
  OVERLAPPED ov = {0};
  ov.Offset = (DWORD)(uint64_t)offset; ov.OffsetHigh = (DWORD)((uint64_t)offset >> 32);
  ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!ov.hEvent) { CloseHandle(h); return winerr(); }
  DWORD got = 0;
  BOOL ok = ReadFile(h, data, (DWORD)size, &got, &ov);
  DWORD error = ok ? ERROR_SUCCESS : GetLastError();
  if (!ok && error == ERROR_IO_PENDING) { ok = GetOverlappedResult(h, &ov, &got, TRUE); error = ok ? ERROR_SUCCESS : GetLastError(); }
  CloseHandle(ov.hEvent); CloseHandle(h);
  if (error == ERROR_HANDLE_EOF) return 0;
  if (!ok) { SetLastError(error); return winerr(); }
  return (ssize_t)got;
}
#endif
