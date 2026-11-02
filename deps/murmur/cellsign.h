/* murmur cellsign - origin signatures for replication cells.
 *
 * Every replicated cell carries a 64-byte Ed25519 signature made by
 * its origin site's key at export time. Signatures travel verbatim
 * through forwarders, so any recipient can verify any cell against
 * the pinned site key in trusted_origins, regardless of which peer
 * delivered it. A compromised forwarder can withhold cells but
 * cannot forge another origin's cells.
 *
 * Keys: the local seed lives only in connection memory (attached at
 * engine Start from origin_key_file, wiped at detach). Trust comes
 * from the operator-owned trusted_origins setting mapping site hex
 * to pubkey hex. Unknown sites and bad signatures fail closed.
 */
#ifndef MURMUR_CELLSIGN_H
#define MURMUR_CELLSIGN_H

#include <stddef.h>
#include <stdint.h>

#include "sqlite3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Attach/detach the 32-byte origin seed to a connection. Attach
 * copies the seed; detach wipes it. */
int murmur_cellsign_attach(sqlite3 *db, const uint8_t seed[32]);
void murmur_cellsign_detach(sqlite3 *db);

/* Derive the Ed25519 public key for a seed. */
int murmur_cellsign_pubkey(const uint8_t seed[32], uint8_t pub[32]);

/* Sign canonical bytes with the attached seed. */
int murmur_cellsign_sign(sqlite3 *db, const uint8_t *msg, size_t len,
                         uint8_t sig[64]);

/* Verify canonical bytes. SQLITE_OK or SQLITE_AUTH. */
int murmur_cellsign_verify(const uint8_t pub[32], const uint8_t *msg,
                           size_t len, const uint8_t sig[64]);

/* Operator trust: the parsed trusted_origins map. Load once per
 * batch, then find in memory. n == 0 means unconfigured (legacy
 * unsigned mode); n > 0 enforces v2 signatures everywhere. */
typedef struct {
  uint8_t site[16];
  uint8_t pub[32];
} murmur_cellsign_entry_t;

typedef struct {
  murmur_cellsign_entry_t *ents;
  size_t n;
} murmur_cellsign_trust_t;

/* SQLITE_OK always (n == 0 when unconfigured); other sqlite rc on
 * error with *sqlrc set. */
int murmur_cellsign_trust_load(sqlite3 *db, murmur_cellsign_trust_t *t,
                               int *sqlrc);
void murmur_cellsign_trust_free(murmur_cellsign_trust_t *t);
/* Pinned pubkey for a site, or NULL when untrusted. */
const uint8_t *murmur_cellsign_trust_find(const murmur_cellsign_trust_t *t,
                                          const uint8_t site[16]);

/* Stored-signature side table for received cells (re-exported
 * verbatim by forwarders). */
int murmur_cellsign_ensure_schema(sqlite3 *db, int *sqlrc);
int murmur_cellsign_store(sqlite3 *db, const uint8_t *table, size_t table_len,
                          const uint8_t *pk, size_t pk_len, const uint8_t *cid,
                          size_t cid_len, const uint8_t site[16],
                          int64_t col_version, const uint8_t sig[64],
                          int *sqlrc);
/* 1 found (sig filled), 0 missing, -1 on error. */
int murmur_cellsign_lookup(sqlite3 *db, const uint8_t *table, size_t table_len,
                           const uint8_t *pk, size_t pk_len,
                           const uint8_t *cid, size_t cid_len,
                           const uint8_t site[16], int64_t col_version,
                           uint8_t sig[64], int *sqlrc);
/* Drop signatures with no matching change row. */
int murmur_cellsign_gc(sqlite3 *db, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_CELLSIGN_H */
