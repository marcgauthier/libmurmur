// Native murmur VFS. Byte ops on main databases run entirely in C++
// (page cache + RocksDB pump, zero Go crossings on hits), as do the
// cross-connection locks (the NvDb lock table) and all control ops
// (open/close registry, PRAGMA, delete/access), which live in the
// C++ control plane (open.cc). Auxiliary files (rollback journals,
// temp files) are C++ memory files; WAL is rejected like the staged
// engine. The sqlite3_vfs layout mirrors
// bindings/sqlite/vfs_bridge.c exactly.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "../sqlite/sqlite3.h"

#include "open.h"

typedef struct NvDb NvDb;

extern "C" {
int64_t nv_db_read(NvDb *d, uint8_t *out, size_t n, int64_t off,
                   uint64_t *blocks);
int nv_db_write(NvDb *d, const uint8_t *in, size_t n, int64_t off,
                uint64_t *blocks);
int nv_db_truncate(NvDb *d, int64_t size);
int64_t nv_db_size(NvDb *d);
int nv_db_lock(NvDb *d, uint64_t file, int level);
int nv_db_unlock(NvDb *d, uint64_t file, int level);
int nv_db_check_reserved(NvDb *d, int *out);
void nv_db_forget_file(NvDb *d, uint64_t file);
}

// Control plane (open.cc): registry, PRAGMA, commit/access. All
// return SQLite result codes, except where noted.
namespace {

// Per-op timing counters, enabled with -DMURMUR_VFS_STATS=1 (diagnosis
// builds only; clock_gettime per op costs ~40ns).
struct VfsCounters {
  std::atomic<uint64_t> calls{0};
  std::atomic<uint64_t> ns{0};
};
struct VfsStats {
  VfsCounters open, close;
  VfsCounters readDb, readAux, writeDb, writeAux;
  VfsCounters truncate, sync, fileSize;
  VfsCounters lock, unlock, checkRes, fileControl;
  VfsCounters vfsDelete, vfsAccess;
};
VfsStats g_stats;

#ifdef MURMUR_VFS_STATS
inline uint64_t nowNs() {
  timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}
#endif
struct Timer {
#ifdef MURMUR_VFS_STATS
  VfsCounters &c;
  uint64_t t0;
  explicit Timer(VfsCounters &c) : c(c), t0(nowNs()) {}
  ~Timer() {
    c.calls.fetch_add(1, std::memory_order_relaxed);
    c.ns.fetch_add(nowNs() - t0, std::memory_order_relaxed);
  }
#else
  explicit Timer(VfsCounters &) {}
#endif
};
#ifdef MURMUR_VFS_STATS
#define VFS_TIMED(counter) Timer _t(g_stats.counter)
#else
#define VFS_TIMED(counter) ((void)0)
#endif

struct MemFile {
  std::mutex mu;
  std::vector<uint8_t> bytes;
  size_t size = 0;
};

struct NvFile {
  sqlite3_file base;
  NvDb *db;          // main databases (borrowed from C++ registry)
  uint64_t file;     // control-plane file handle for main databases
  std::string name;  // aux files: mem-map key
  std::shared_ptr<MemFile> aux;  // aux files: cached handle (no map find per I/O)
  bool main_db;
  bool delete_on_close;
};

std::mutex mem_mu;
std::unordered_map<std::string, std::shared_ptr<MemFile>> mem_files;
std::atomic<uint64_t> temp_id{0};

// fileDb resolves the file's codec, refreshing once from the
// registry when the file opened keyless (PRAGMA key provisions
// later). Hot path after the first refresh: one cached-pointer
// branch, no locks.
NvDb *fileDb(NvFile *f) {
  if (!f->db) {
    f->db = (NvDb *)nvEntryDb(f->file);
  }
  return f->db;
}

// Liveness questions (journal owner checks, -wal probes) go to the
// control-plane registry (nvStoreIsLive/nvAccessDb), the single
// source of truth; the old mirrored live-set is gone.
bool ends_with(const char *s, const char *suffix) {
  size_t sl = strlen(s), xl = strlen(suffix);
  return sl >= xl && memcmp(s + sl - xl, suffix, xl) == 0;
}

// Path canonicalization lives in the control plane
// (murmurCanonName, open.cc).

int ioClose(sqlite3_file *p) {
  VFS_TIMED(close);
  NvFile *f = (NvFile *)p;
  if (!f->main_db) {
    if (f->delete_on_close) {
      std::lock_guard<std::mutex> l(mem_mu);
      mem_files.erase(f->name);
    }
    f->~NvFile();
    return SQLITE_OK;
  }
  // Drop the lock entry before the control-plane close, which may
  // destroy the NvDb on last close.
  if (f->db) {
    nv_db_forget_file(f->db, f->file);
  }
  int rc = nvCloseDb(f->file);
  f->~NvFile();
  return rc;
}

int ioRead(sqlite3_file *p, void *data, int n, sqlite3_int64 off) {
  NvFile *f = (NvFile *)p;
  Timer _t(!f->main_db ? g_stats.readAux : g_stats.readDb);
  if (n < 0 || off < 0) {
    return SQLITE_IOERR_READ;
  }
  uint8_t *dst = (uint8_t *)data;
  if (f->main_db) {
    NvDb *db = fileDb(f);
    if (!db) {
      // Keyless: zeros + SHORT_READ, exactly like an empty file. The
      // only unlocked read SQLite performs is the open-time header
      // probe (direct, uncached), so this can never poison the pager
      // cache; every locked read needs the codec and fails at xLock.
      memset(dst, 0, (size_t)n);
      return SQLITE_IOERR_SHORT_READ;
    }
    uint64_t blocks = 0;
    int64_t got = nv_db_read(db, dst, (size_t)n, (int64_t)off, &blocks);
    if (got < 0) {
      return SQLITE_IOERR_READ;
    }
    if (got < n) {
      memset(dst + got, 0, (size_t)(n - got));
      return SQLITE_IOERR_SHORT_READ;
    }
    return SQLITE_OK;
  }
  // Cached handle: no map find, per-file lock only. The NvFile owns
  // its aux reference for life, so the raw pointer cannot dangle
  // (delete-while-open detaches the map entry, not this handle).
  MemFile *m = f->aux.get();
  if (!m) {
    std::lock_guard<std::mutex> l(mem_mu);
    auto it = mem_files.find(f->name);
    if (it == mem_files.end() || !it->second) {
      memset(dst, 0, (size_t)n);
      return SQLITE_IOERR_SHORT_READ;
    }
    f->aux = it->second;
    m = it->second.get();
  }
  std::lock_guard<std::mutex> l(m->mu);
  size_t have = m->size;
  size_t pos = (size_t)off;
  size_t avail = (pos < have) ? have - pos : 0;
  if (avail > (size_t)n) {
    avail = (size_t)n;
  }
  if (avail > 0) {
    memcpy(dst, m->bytes.data() + pos, avail);
  }
  if (avail < (size_t)n) {
    memset(dst + avail, 0, (size_t)n - avail);
    return SQLITE_IOERR_SHORT_READ;
  }
  return SQLITE_OK;
}

int ioWrite(sqlite3_file *p, const void *data, int n, sqlite3_int64 off) {
  NvFile *f = (NvFile *)p;
  Timer _t(!f->main_db ? g_stats.writeAux : g_stats.writeDb);
  if (n < 0 || off < 0) {
    return SQLITE_IOERR_WRITE;
  }
  if (f->main_db) {
    NvDb *db = fileDb(f);
    if (!db) {
      return SQLITE_IOERR_WRITE;
    }
    uint64_t blocks = 0;
    if (nv_db_write(db, (const uint8_t *)data, (size_t)n, (int64_t)off,
                    &blocks) != 0) {
      return SQLITE_IOERR_WRITE;
    }
    return SQLITE_OK;
  }
  MemFile *m = f->aux.get();
  if (!m) {
    std::lock_guard<std::mutex> l(mem_mu);
    std::shared_ptr<MemFile> &slot = mem_files[f->name];
    if (!slot) {
      slot = std::make_shared<MemFile>();
    }
    f->aux = slot;
    m = slot.get();
  }
  std::lock_guard<std::mutex> l(m->mu);
  size_t end = (size_t)off + (size_t)n;
  if (end > m->bytes.size()) {
    m->bytes.resize(end, 0);
  }
  memcpy(m->bytes.data() + (size_t)off, data, (size_t)n);
  if (end > m->size) {
    m->size = end;
  }
  return SQLITE_OK;
}

int ioTruncate(sqlite3_file *p, sqlite3_int64 n) {
  VFS_TIMED(truncate);
  NvFile *f = (NvFile *)p;
  if (n < 0) {
    return SQLITE_IOERR_TRUNCATE;
  }
  if (f->main_db) {
    NvDb *db = fileDb(f);
    if (!db) {
      return SQLITE_IOERR_TRUNCATE;
    }
    return nv_db_truncate(db, (int64_t)n) == 0 ? SQLITE_OK
                                              : SQLITE_IOERR_TRUNCATE;
  }
  MemFile *m = f->aux.get();
  if (!m) {
    std::lock_guard<std::mutex> l(mem_mu);
    std::shared_ptr<MemFile> &slot = mem_files[f->name];
    if (!slot) {
      slot = std::make_shared<MemFile>();
    }
    f->aux = slot;
    m = slot.get();
  }
  std::lock_guard<std::mutex> l(m->mu);
  m->bytes.resize((size_t)n, 0);
  m->size = (size_t)n;
  return SQLITE_OK;
}

int ioSync(sqlite3_file *p, int flags) {
  VFS_TIMED(sync);
  (void)p;
  (void)flags;
  // Deliberately deferred like the Rust io_sync: commits
  // acknowledge without waiting for disk; the engine's background
  // worker persists every flush_interval_ms.
  return SQLITE_OK;
}

int ioFileSize(sqlite3_file *p, sqlite3_int64 *out) {
  VFS_TIMED(fileSize);
  NvFile *f = (NvFile *)p;
  if (f->main_db) {
    NvDb *db = fileDb(f);
    if (!db) {
      // Keyless files look empty; size is re-read per transaction
      // once keyed, so nothing goes stale.
      *out = 0;
      return SQLITE_OK;
    }
    int64_t size = nv_db_size(db);
    if (size < 0) {
      return SQLITE_IOERR;
    }
    *out = (sqlite3_int64)size;
    return SQLITE_OK;
  }
  MemFile *m = f->aux.get();
  if (!m) {
    std::lock_guard<std::mutex> l(mem_mu);
    auto it = mem_files.find(f->name);
    if (it == mem_files.end() || !it->second) {
      *out = 0;
      return SQLITE_OK;
    }
    f->aux = it->second;
    m = it->second.get();
  }
  std::lock_guard<std::mutex> l(m->mu);
  *out = (sqlite3_int64)m->size;
  return SQLITE_OK;
}

int ioLock(sqlite3_file *p, int level) {
  VFS_TIMED(lock);
  NvFile *f = (NvFile *)p;
  if (!f->main_db) {
    return SQLITE_OK;
  }
  NvDb *db = fileDb(f);
  if (!db) {
    // Keyless: fail fast (BUSY would spin busy-handler retries).
    return SQLITE_IOERR;
  }
  return nv_db_lock(db, f->file, level);
}

int ioUnlock(sqlite3_file *p, int level) {
  VFS_TIMED(unlock);
  NvFile *f = (NvFile *)p;
  if (!f->main_db) {
    return SQLITE_OK;
  }
  NvDb *db = fileDb(f);
  if (!db) {
    return SQLITE_IOERR;
  }
  return nv_db_unlock(db, f->file, level);
}

int ioCheckReserved(sqlite3_file *p, int *out) {
  VFS_TIMED(checkRes);
  NvFile *f = (NvFile *)p;
  *out = 0;
  if (!f->main_db) {
    return SQLITE_OK;
  }
  NvDb *db = fileDb(f);
  if (!db) {
    // Keyless files hold no locks, so none is reserved.
    return SQLITE_OK;
  }
  return nv_db_check_reserved(db, out);
}

int ioFileControl(sqlite3_file *p, int op, void *arg) {
  VFS_TIMED(fileControl);
  NvFile *f = (NvFile *)p;
  if (op == SQLITE_FCNTL_MMAP_SIZE && arg != nullptr) {
    // Memory-mapped I/O is unsupported; force it off.
    *(sqlite3_int64 *)arg = 0;
    return SQLITE_OK;
  }
  if (op == SQLITE_FCNTL_COMMIT_PHASETWO) {
    // journal_mode=DELETE is enforced, so the journal-delete hook
    // snapshots this same commit; nothing to do here.
    return SQLITE_OK;
  }
  if (!f->main_db) {
    return SQLITE_NOTFOUND;
  }
  if (op == SQLITE_FCNTL_PRAGMA) {
    if (arg == nullptr) {
      return SQLITE_NOTFOUND;
    }
    // PRAGMA args are char*[4] per the SQLite contract.
    char **argv = (char **)arg;
    const char *name = argv[1];
    if (name == nullptr) {
      return SQLITE_NOTFOUND;
    }
    const char *value = argv[2];
    char small[4096];
    size_t out_len = 0;
    int rc = nvPragmaDb(f->file, name, value, value != nullptr, small,
                        sizeof(small), &out_len);
    if (rc == -2) {  // short buffer: grow and retry once
      size_t need = out_len ? out_len : 65536;
      if (need > (1 << 20)) {
        return SQLITE_NOMEM;
      }
      std::vector<char> big(need);
      rc = nvPragmaDb(f->file, name, value, value != nullptr, big.data(),
                      big.size(), &out_len);
      if (rc == SQLITE_OK && out_len > 0) {
        big.push_back('\0');
        argv[0] = sqlite3_mprintf("%s", big.data());
      }
      return rc;
    }
    if (rc == SQLITE_OK && out_len > 0 && out_len < sizeof(small)) {
      small[out_len] = '\0';
      argv[0] = sqlite3_mprintf("%s", small);
    }
    return rc;
  }
  (void)op;
  if (arg == nullptr) {
    return SQLITE_NOTFOUND;
  }
  return SQLITE_NOTFOUND;
}

int ioSectorSize(sqlite3_file *p) {
  (void)p;
  return 4096;
}

int ioDevice(sqlite3_file *p) {
  (void)p;
  return 0;
}

const sqlite3_io_methods nvMethods = {
    1,
    ioClose,
    ioRead,
    ioWrite,
    ioTruncate,
    ioSync,
    ioFileSize,
    ioLock,
    ioUnlock,
    ioCheckReserved,
    ioFileControl,
    ioSectorSize,
    ioDevice,
    0,
    0,
    0,
    0,
    0,
    0,
};

int vfsOpen(sqlite3_vfs *vfs, const char *name, sqlite3_file *out, int flags,
            int *outFlags) {
  VFS_TIMED(open);
  (void)vfs;
  NvFile *f = new (out) NvFile();
  f->base.pMethods = nullptr;
  f->db = nullptr;
  f->file = 0;
  f->main_db = (flags & SQLITE_OPEN_MAIN_DB) != 0;
  f->delete_on_close = (flags & SQLITE_OPEN_DELETEONCLOSE) != 0;
  if (!f->main_db) {
    if (name != nullptr && ends_with(name, "-wal")) {
      // WAL requires a different recovery design.
      f->~NvFile();
      return SQLITE_CANTOPEN;
    }
    if (name == nullptr) {
      uint64_t id = ++temp_id;
      char tmp[64];
      snprintf(tmp, sizeof(tmp), ":sqlite-murmur-temp:%llu",
               (unsigned long long)id);
      f->name = tmp;
    } else {
      f->name = murmurCanonName(name);
    }
    {
      std::lock_guard<std::mutex> l(mem_mu);
      std::shared_ptr<MemFile> &slot = mem_files[f->name];
      if (!slot) {
        slot = std::make_shared<MemFile>();
      }
      f->aux = slot;
    }
    f->base.pMethods = &nvMethods;
    if (outFlags) {
      *outFlags = flags;
    }
    return SQLITE_OK;
  }
  if (name == nullptr) {
    f->~NvFile();
    return SQLITE_CANTOPEN;
  }
  uint64_t db = 0, file = 0;
  int rc = nvOpenDb(name, (flags & SQLITE_OPEN_READONLY) != 0,
                      (flags & SQLITE_OPEN_CREATE) != 0, &db, &file);
  if (rc != SQLITE_OK) {
    f->~NvFile();
    return rc;
  }
  f->db = (NvDb *)db;
  f->file = file;
  f->base.pMethods = &nvMethods;
  if (outFlags) {
    *outFlags = flags;
  }
  return SQLITE_OK;
}

int vfsDelete(sqlite3_vfs *vfs, const char *name, int sync) {
  VFS_TIMED(vfsDelete);
  (void)vfs;
  (void)sync;
  if (name == nullptr) {
    return SQLITE_IOERR_DELETE;
  }
  std::string canon = murmurCanonName(name);
  {
    std::lock_guard<std::mutex> l(mem_mu);
    mem_files.erase(canon);
  }
  // Only a journal with a live owner needs the commit hook, which
  // takes the canon path as-is; every other delete answers OK
  // (stores are never deleted via xDelete).
  if (ends_with(canon.c_str(), "-journal") &&
      nvStoreIsLive(std::string(canon, 0, canon.size() - 8).c_str())) {
    return nvCommitDb(canon.c_str());
  }
  return SQLITE_OK;
}

int vfsAccess(sqlite3_vfs *vfs, const char *name, int flags, int *out) {
  VFS_TIMED(vfsAccess);
  (void)vfs;
  (void)flags;
  if (name == nullptr) {
    return nvAccessDb(name, out);
  }
  std::string canon = murmurCanonName(name);
  {
    std::lock_guard<std::mutex> l(mem_mu);
    auto it = mem_files.find(canon);
    if (it != mem_files.end() && it->second) {
      *out = 1;
      return SQLITE_OK;
    }
  }
  // The control plane answers the -journal/-wal owner rule and
  // stats everything else.
  return nvAccessDb(canon.c_str(), out);
}

sqlite3_vfs *vfsParent = nullptr;

int vfsFullPathname(sqlite3_vfs *vfs, const char *name, int n, char *out) {
  (void)vfs;
  if (!vfsParent || !vfsParent->xFullPathname) {
    return SQLITE_MISUSE;
  }
  return vfsParent->xFullPathname(vfsParent, name, n, out);
}

int vfsRandomness(sqlite3_vfs *vfs, int n, char *out) {
  if (vfsParent && vfsParent->xRandomness) {
    return vfsParent->xRandomness(vfsParent, n, out);
  }
  memset(out, 0, (size_t)n);
  return n;
}

int vfsSleep(sqlite3_vfs *vfs, int us) {
  if (vfsParent && vfsParent->xSleep) {
    return vfsParent->xSleep(vfsParent, us);
  }
  return us;
}

int vfsCurrentTime(sqlite3_vfs *vfs, double *out) {
  if (vfsParent && vfsParent->xCurrentTime) {
    return vfsParent->xCurrentTime(vfsParent, out);
  }
  *out = 0;
  return SQLITE_OK;
}

sqlite3_vfs nvVfs = {
    1,
    sizeof(NvFile),
    1024,
    0,
    "murmur",
    0,
    vfsOpen,
    vfsDelete,
    vfsAccess,
    vfsFullPathname,
    0,
    0,
    0,
    0,
    vfsRandomness,
    vfsSleep,
    vfsCurrentTime,
    0,
    0,
    0,
    0,
};

}  // namespace

extern "C" {

int nvVfsRegister(const char *name) {
  vfsParent = sqlite3_vfs_find(nullptr);
  if (sqlite3_vfs_find(name) == &nvVfs) {
    return SQLITE_OK;
  }
  nvVfs.zName = name;
  return sqlite3_vfs_register(&nvVfs, 0);
}

struct NvVfsStat {
  uint64_t calls;
  uint64_t ns;
};

// Order: open, close, readDb, readAux, writeDb, writeAux, truncate,
// sync, fileSize, lock, unlock, checkRes, fileControl, vfsDelete,
// vfsAccess (15 entries). Zeros unless built with MURMUR_VFS_STATS.
void nvVfsStats(NvVfsStat *out) {
  const VfsCounters *all[] = {
      &g_stats.open,        &g_stats.close,       &g_stats.readDb,
      &g_stats.readAux,     &g_stats.writeDb,     &g_stats.writeAux,
      &g_stats.truncate,    &g_stats.sync,        &g_stats.fileSize,
      &g_stats.lock,        &g_stats.unlock,      &g_stats.checkRes,
      &g_stats.fileControl, &g_stats.vfsDelete,   &g_stats.vfsAccess,
  };
  for (int i = 0; i < 15; i++) {
    out[i].calls = all[i]->calls.load(std::memory_order_relaxed);
    out[i].ns = all[i]->ns.load(std::memory_order_relaxed);
  }
}

void nvVfsStatsReset() {
  VfsCounters *all[] = {
      &g_stats.open,        &g_stats.close,       &g_stats.readDb,
      &g_stats.readAux,     &g_stats.writeDb,     &g_stats.writeAux,
      &g_stats.truncate,    &g_stats.sync,        &g_stats.fileSize,
      &g_stats.lock,        &g_stats.unlock,      &g_stats.checkRes,
      &g_stats.fileControl, &g_stats.vfsDelete,   &g_stats.vfsAccess,
  };
  for (int i = 0; i < 15; i++) {
    all[i]->calls.store(0, std::memory_order_relaxed);
    all[i]->ns.store(0, std::memory_order_relaxed);
  }
}

// Test-only: canonicalize one path for TestCanonDifferential (Go
// compares against sqlite.CanonicalPath). The caller frees with
// nvCanonTestFree.
const char *nvCanonTest(const char *name) {
  std::string c = murmurCanonName(name);
  char *out = (char *)malloc(c.size() + 1);
  if (out) {
    memcpy(out, c.c_str(), c.size() + 1);
  }
  return out;
}

void nvCanonTestFree(const char *p) { free((void *)p); }

}  // extern "C"
