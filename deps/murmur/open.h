// open.h — C++ control plane for murmur stores: the store registry,
// lifecycle, per-store state, background flusher, and the PRAGMA
// table. Ported from pkgs/storage (engine/dir/pragma) and the
// bindings/nvfs Go registry so the VFS hot path and all control ops
// run without crossing into Go.
//
// Key model (P1e): stores open KEYLESS (no master, no codec) and
// provision on `PRAGMA key='<64 hex>'`, which stages the master in
// C++ store state and builds the codec from the keyring envelope
// (or unsealed: page key = master). Reads/writes on a keyless store
// fail until keyed; VFS files refresh their borrowed db lazily via
// nvEntryDb, and shell holders re-fetch once after keying. Key
// material never leaves C++; there are no key callbacks and no Go
// stash. A second PRAGMA key with a different master is MISUSE.
//
// Interim seams (cold paths only, killed by replication-native):
//   - nvMurmurExtFileGo / nvMurmurExtStoreGo: murmur_* PRAGMAs
//     outside the engine KDF table dispatch to the Go replication
//     extension slot. Dies when replication moves into the library.
//   - nvCloseFileGo: notifies Go so it drops the file's extension
//     slot. Dies with the extension slot.
//
// Callbacks must never re-enter this API on the same store:
// extension dispatch runs with the store lock released.
#ifndef SQLITE_MURMUR_NVFS_OPEN_H_
#define SQLITE_MURMUR_NVFS_OPEN_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#include <string>

// murmurCanonName replicates Go sqlite.CanonicalPath exactly (URI
// strip, percent-decode, absolute+Clean). Shared by the registry and
// the VFS file dispatch.
std::string murmurCanonName(const char *name);

extern "C" {
#endif

typedef struct NvStore NvStore;
typedef struct NvDb NvDb;

// Result codes mirror the SQLite primaries used by pkgs/storage
// (plus AUTH, mirroring Go CodeAuth for key failures).
enum {
  NV_CTL_OK = 0,
  NV_CTL_ERROR = 1,
  NV_CTL_BUSY = 5,
  NV_CTL_NOMEM = 7,
  NV_CTL_READONLY = 8,
  NV_CTL_IOERR = 10,
  NV_CTL_CORRUPT = 11,
  NV_CTL_NOTFOUND = 12,
  NV_CTL_MISUSE = 21,
  NV_CTL_AUTH = 23
};

// Keyring params mirror sqlite_murmur_keyring_args.
enum {
  NV_CTL_PARAM_KDF = 1,
  NV_CTL_PARAM_SCRYPT_N = 2,
  NV_CTL_PARAM_SCRYPT_R = 3,
  NV_CTL_PARAM_SCRYPT_P = 4
};

// nvCtlSetDefaults captures VFS-level open defaults at
// registration. Zeros select the built-ins (16384 page cache,
// 250 ms flush).
void nvCtlSetDefaults(int cache_pages, unsigned flush_ms);

// nvOpenDb opens (or attaches to) the store for canon path name and
// mints a file id. It mirrors the Go nvOpenDbGo creation loop,
// including the losing-race recheck. read_only is recorded per
// file; create>0 mkdirs the directory. Returns a SQLite code.
int nvOpenDb(const char *name, int read_only, int create, uint64_t *db,
             uint64_t *file);

// nvCloseDb drops one file id, destroying its store on last close.
// Unknown ids report SQLITE_IOERR.
int nvCloseDb(uint64_t file);

// nvEntryDb returns the live codec for a file or shell id, or NULL
// when the store is keyless (PRAGMA key not yet run). VFS files and
// shell holders call it to refresh a stale NULL after keying.
void *nvEntryDb(uint64_t id);

// nvOpenStoreRef opens a shell reference on a store without minting
// a file: offline tools and live control ops use it. create>0
// mkdirs; cache_pages<=0 selects the default. handle is an opaque
// id for the calls below; db/store are borrowed raw pointers the
// Go shell wraps (valid until nvCloseStoreRef).
int nvOpenStoreRef(const char *canon, int create, int cache_pages,
                   uint64_t *handle, void **db, void **store);

// nvCloseStoreRef drops one shell reference.
int nvCloseStoreRef(uint64_t handle);

// nvStoreIsLive reports whether canon names a live store (no open).
// nvStoreLiveCount reports how many stores are live.
int nvStoreIsLive(const char *canon);
int nvStoreLiveCount();

// nvPragmaDb serves one PRAGMA on a file. name/value follow the
// SQLITE_FCNTL_PRAGMA contract; result bytes go to out. Short
// buffers report -2 with *out_len = bytes needed (caller grows and
// retries once). Unknown names report SQLITE_NOTFOUND.
int nvPragmaDb(uint64_t file, const char *name, const char *value,
               int has_value, char *out, size_t cap, size_t *out_len);

// nvPragmaStore serves one PRAGMA on a shell reference with an
// explicit read_only context (operator use passes 0).
int nvPragmaStore(uint64_t handle, const char *name, const char *value,
                  int has_value, int read_only, char *out, size_t cap,
                  size_t *out_len);

// nvStoreKey provisions the 32-byte master on a shell reference:
// the explicit alternative to PRAGMA key (same behavior: CORRUPT
// for a wrong master on a sealed store, MISUSE for a second,
// different master). Shell holders re-fetch the codec via nvEntryDb
// after keying.
int nvStoreKey(uint64_t handle, const uint8_t master[32]);

// nvStoreBackup checkpoints a live store plus its byte-exact
// manifest into dest, which must not exist. Any failure removes
// dest. Mirrors Engine.BackupTo: callers sync first; existing dest
// or a bad cipher token answers ERROR, IO failures IOERR.
int nvStoreBackup(uint64_t handle, const char *dest, const char *cipher,
                  const uint8_t group[16], const uint8_t node[16]);

// nvStoreInventory serializes a live shell's ring state as JSON,
// byte-identical to Engine.InventoryJSON (`{"sealed":false}` or
// the sealed object). The envelope opens under the staged master,
// so external seals/rotates are observed without a ring reload.
// Returns -2 with *out_len = needed bytes when cap is short.
int nvStoreInventory(uint64_t handle, char *out, size_t cap,
                     size_t *out_len);

// nvStoreSetParam tunes one staged seal parameter (or seals, for
// NV_CTL_PARAM_KDF) on a shell reference. Mirrors Engine.SetParam.
// master travels with the call so shells seal with their own key;
// SQL seals (no master here) resolve it from the staged PRAGMA key.
int nvStoreSetParam(uint64_t handle, int param, uint64_t value,
                    const uint8_t master[32]);

// nvStoreRotate mints a fresh data key on a live sealed store
// (direct-KDF rings only) and installs it. Mirrors Engine.Rotate;
// the envelope is re-sealed under the staged PRAGMA key.
int nvStoreRotate(uint64_t handle, int read_only, uint32_t *new_id);

// nvStorePrune drops retired keys no live page references and
// reports pruneJSON (`{"pruned":[...],...}`). Mirrors Engine.Prune.
// Returns -2 with *out_len = needed bytes when cap is short.
int nvStorePrune(uint64_t handle, int read_only, char *out, size_t cap,
                 size_t *out_len);

// nvStoreKdf reads the seal state: sealed>0 reports the envelope
// header, else the staged seal parameters.
int nvStoreKdf(uint64_t handle, int *sealed, uint8_t *kdf,
               uint32_t *time_ms, uint32_t *mem_kib, uint8_t *threads);

// nvStoreSyncStats reads the commit-boundary size and the flusher
// batch count.
int nvStoreSyncStats(uint64_t handle, uint64_t *committed_size,
                     uint64_t *flush_batches);
/* Durability barrier for a live shell reference. Caller retains handle. */
int nvStoreFlush(uint64_t handle);
// Synchronize an already open main-database path (not a journal path).
int nvFlushDb(const char *path);

// nvCommitDb snapshots the commit boundary for a journal path:
// names not ending in -journal, or with no live owner, answer OK.
int nvCommitDb(const char *canon);

// nvAccessDb answers an existence probe: a -journal/-wal probe with
// a live owner (and no live main db of its own) answers absent;
// anything else stats the filesystem.
int nvAccessDb(const char *name, int *out);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // SQLITE_MURMUR_NVFS_OPEN_H_
