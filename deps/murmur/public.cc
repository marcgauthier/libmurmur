// public.cc — stable libmurmur C API, declared in libmurmur.h.
//
// Subsystem entry points (nvOpenDb, nvStore*, nvOffline*, the QUIC
// transport) stay available, but ordinary clients program against
// murmur_* only: explicit typed functions instead of SQL strings.
// SQL PRAGMAs remain as compatibility aliases over the same paths.
#include "../../libmurmur.h"

#include <string.h>

#include "sqlite3.h"
#include "../crsqlite/include/sqlite_murmur_crsqlite.h"

extern "C" int nvVfsRegister(const char *name);
extern "C" void nvCtlSetDefaults(int cache_pages, unsigned flush_ms);

/* The native archive is also linked into Go, where cgo supplies strong
 * callback implementations. Standalone C clients need harmless defaults
 * for the Go-only PRAGMA extension hooks. */
extern "C" __attribute__((weak)) int nvMurmurExtFileGo(
    uint64_t, const char *, const char *, int, char *, size_t, size_t *);
extern "C" __attribute__((weak)) int nvMurmurExtStoreGo(
    uint64_t, const char *, const char *, int, char *, size_t, size_t *);
extern "C" __attribute__((weak)) void nvCloseFileGo(uint64_t);

extern "C" __attribute__((weak)) int nvMurmurExtFileGo(
    uint64_t, const char *, const char *, int, char *, size_t, size_t *out_len) {
  if (out_len) *out_len = 0;
  return SQLITE_NOTFOUND;
}
extern "C" __attribute__((weak)) int nvMurmurExtStoreGo(
    uint64_t, const char *, const char *, int, char *, size_t, size_t *out_len) {
  if (out_len) *out_len = 0;
  return SQLITE_NOTFOUND;
}
extern "C" __attribute__((weak)) void nvCloseFileGo(uint64_t) {}

extern "C" {

int murmur_db_key(struct sqlite3 *db, const uint8_t key[32]) {
  if (!db || !key) {
    return SQLITE_MISUSE;
  }
  // The VFS key path takes hex (the PRAGMA key contract), so encode
  // here and wipe after: callers never handle the hex form. The file
  // control runs under the connection mutex, exactly like parsing
  // `PRAGMA key='...'` on this connection.
  static const char digits[] = "0123456789abcdef";
  char hex[65];
  for (int i = 0; i < 32; i++) {
    hex[2 * i] = digits[key[i] >> 4];
    hex[2 * i + 1] = digits[key[i] & 15];
  }
  hex[64] = '\0';
  char *argv[4];
  argv[0] = nullptr;
  argv[1] = const_cast<char *>("key");
  argv[2] = hex;
  argv[3] = nullptr;
  int rc = sqlite3_file_control(db, "main", SQLITE_FCNTL_PRAGMA, argv);
  memset(hex, 0, sizeof(hex));
  if (argv[0]) {
    sqlite3_free(argv[0]);
  }
  return rc;
}

int murmur_vfs_register(int cache_pages, unsigned flush_interval_ms) {
  int rc = sqlite3_initialize();
  if (rc != SQLITE_OK) return rc;
  rc = nvVfsRegister("sqlite-murmur");
  if (rc == SQLITE_OK) nvCtlSetDefaults(cache_pages, flush_interval_ms);
  return rc;
}

int murmur_crsqlite_init(struct sqlite3 *db) {
  if (!db) return SQLITE_MISUSE;
  char *error = nullptr;
  int rc = sqlite3_crsqlite_init(db, &error, nullptr);
  sqlite3_free(error);
  return rc;
}

}  // extern "C"
