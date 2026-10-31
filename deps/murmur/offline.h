// offline.h - native offline storage tools (no registry, no VFS).
//
// Ports dir.go RekeyDir/VerifyDir: raw RocksDB opens (LOCK-serialized
// against live stores), trial decrypt, staged-envelope rekey protocol.
// Result codes mirror the Go taxonomy (dir.go/engine.go).
#ifndef MURMUR_OFFLINE_H
#define MURMUR_OFFLINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  NV_OFF_OK = 0,
  NV_OFF_ERROR = 1,
  NV_OFF_BUSY = 5,
  NV_OFF_IOERR = 10,
  NV_OFF_CORRUPT = 11,
  NV_OFF_CANTOPEN = 14,
  NV_OFF_MISUSE = 21,
  NV_OFF_AUTH = 23,
};

// nvOfflineRekey rewrites every page of a sealed store under a fresh
// data key sealed by new_master. fault_after aborts after N pages
// (test crash hook; 0 disables). Protocol: staged envelope in
// meta:keyring.REKEY, old-first trial decrypt, legacy pages stay
// unkeyed, zstd-3 recompress, 100-page synced chunks, atomic flip.
// The store must be closed (live same-process stores report BUSY).
int nvOfflineRekey(const char *dir, const uint8_t old_master[32],
                   const uint8_t new_master[32], int fault_after);

// nvOfflineVerify trial-opens every page of a sealed store.
// Read-only; the store must be closed (BUSY when live).
int nvOfflineVerify(const char *dir, const uint8_t master[32]);

// nvOfflineInventory serializes a closed store's ring state as JSON,
// byte-identical to Go InventoryJSON (`{"sealed":false}` or the
// sealed object). Returns NV_OFF_OK with *out_len set, or -2 with
// *out_len = needed bytes when cap is short.
int nvOfflineInventory(const char *dir, const uint8_t master[32], char *out,
                       size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif  // MURMUR_OFFLINE_H
