/* Murmur VFS method stubs. Each stub forwards to a Go export with the
 * file handle id; all logic (stores, mem files, locks, pragmas) lives
 * in Go. Mirrors the sqlite-murmur Rust VFS method table. */
#include <stdlib.h>
#include <string.h>
#include "../../../../deps/sqlite/sqlite3.h"

typedef struct {
  sqlite3_file base;
  unsigned long long handle;
} murmur_file_t;

extern int goVfsOpen(const char *name, unsigned long long handle, int flags, int *outFlags);
extern int goVfsClose(unsigned long long handle);
extern int goVfsRead(unsigned long long handle, void *data, int n, long long off);
extern int goVfsWrite(unsigned long long handle, const void *data, int n, long long off);
extern int goVfsTruncate(unsigned long long handle, long long n);
extern int goVfsSync(unsigned long long handle, int flags);
extern int goVfsFileSize(unsigned long long handle, long long *out);
extern int goVfsLock(unsigned long long handle, int level);
extern int goVfsUnlock(unsigned long long handle, int level);
extern int goVfsFileControl(unsigned long long handle, int op, void *arg);
extern int goVfsCheckReserved(unsigned long long handle, int *out);
extern int goVfsDelete(const char *name);
extern int goVfsAccess(const char *name, int flags, int *out);

static int ioClose(sqlite3_file *p) {
  return goVfsClose(((murmur_file_t *) p)->handle);
}

static int ioRead(sqlite3_file *p, void *data, int n, sqlite3_int64 off) {
  return goVfsRead(((murmur_file_t *) p)->handle, data, n, (long long) off);
}

static int ioWrite(sqlite3_file *p, const void *data, int n, sqlite3_int64 off) {
  return goVfsWrite(((murmur_file_t *) p)->handle, data, n, (long long) off);
}

static int ioTruncate(sqlite3_file *p, sqlite3_int64 n) {
  return goVfsTruncate(((murmur_file_t *) p)->handle, (long long) n);
}

static int ioSync(sqlite3_file *p, int flags) {
  return goVfsSync(((murmur_file_t *) p)->handle, flags);
}

static int ioFileSize(sqlite3_file *p, sqlite3_int64 *out) {
  long long size = 0;
  int rc = goVfsFileSize(((murmur_file_t *) p)->handle, &size);
  *out = (sqlite3_int64) size;
  return rc;
}

static int ioLock(sqlite3_file *p, int level) {
  return goVfsLock(((murmur_file_t *) p)->handle, level);
}

static int ioUnlock(sqlite3_file *p, int level) {
  return goVfsUnlock(((murmur_file_t *) p)->handle, level);
}

static int ioFileControl(sqlite3_file *p, int op, void *arg) {
  return goVfsFileControl(((murmur_file_t *) p)->handle, op, arg);
}

static int ioCheckReserved(sqlite3_file *p, int *out) {
  return goVfsCheckReserved(((murmur_file_t *) p)->handle, out);
}

static int ioSectorSize(sqlite3_file *p) {
  (void) p;
  return 4096;
}

static int ioDevice(sqlite3_file *p) {
  (void) p;
  return 0;
}

static const sqlite3_io_methods murmurMethods = {
  1,
  ioClose, ioRead, ioWrite, ioTruncate, ioSync, ioFileSize,
  ioLock, ioUnlock, ioCheckReserved, ioFileControl,
  ioSectorSize, ioDevice,
  0, 0, 0, 0, 0, 0
};

static unsigned long long nextHandle = 1;

static int vfsOpen(sqlite3_vfs *vfs, const char *name, sqlite3_file *out,
    int flags, int *outFlags) {
  (void) vfs;
  murmur_file_t *f = (murmur_file_t *) out;
  f->base.pMethods = 0;
  f->handle = __atomic_fetch_add(&nextHandle, 1, __ATOMIC_RELAXED);
  int rc = goVfsOpen(name, f->handle, flags, outFlags);
  if (rc != SQLITE_OK) {
    return rc;
  }
  f->base.pMethods = &murmurMethods;
  return SQLITE_OK;
}

static int vfsDelete(sqlite3_vfs *vfs, const char *name, int sync) {
  (void) vfs;
  (void) sync;
  return goVfsDelete(name);
}

static int vfsAccess(sqlite3_vfs *vfs, const char *name, int flags, int *out) {
  (void) vfs;
  return goVfsAccess(name, flags, out);
}

static sqlite3_vfs *vfsParent = 0;

static int vfsFullPathname(sqlite3_vfs *vfs, const char *name, int n, char *out) {
  (void) vfs;
  if (!vfsParent || !vfsParent->xFullPathname) {
    return SQLITE_MISUSE;
  }
  return vfsParent->xFullPathname(vfsParent, name, n, out);
}

static int vfsRandomness(sqlite3_vfs *vfs, int n, char *out) {
  if (vfsParent && vfsParent->xRandomness) {
    return vfsParent->xRandomness(vfsParent, n, out);
  }
  memset(out, 0, (size_t) n);
  return n;
}

static int vfsSleep(sqlite3_vfs *vfs, int us) {
  if (vfsParent && vfsParent->xSleep) {
    return vfsParent->xSleep(vfsParent, us);
  }
  return us;
}

static int vfsCurrentTime(sqlite3_vfs *vfs, double *out) {
  if (vfsParent && vfsParent->xCurrentTime) {
    return vfsParent->xCurrentTime(vfsParent, out);
  }
  *out = 0;
  return SQLITE_OK;
}

static sqlite3_vfs murmurVfs = {
  1,
  sizeof(murmur_file_t),
  1024,
  0,
  "murmur",
  0,
  vfsOpen, vfsDelete, vfsAccess, vfsFullPathname,
  0, 0, 0, 0,
  vfsRandomness, vfsSleep, vfsCurrentTime,
  0, 0, 0, 0
};

/* SQLITE_FCNTL_PRAGMA results must be sqlite3_mprintf-allocated: SQLite
 * releases arguments[0] with sqlite3_free. */
char *murmurPragmaStrdup(const char *s) {
  return sqlite3_mprintf("%s", s);
}

int murmurVfsRegister(const char *name) {
  vfsParent = sqlite3_vfs_find(0);
  murmurVfs.zName = name;
  return sqlite3_vfs_register(&murmurVfs, 0);
}
