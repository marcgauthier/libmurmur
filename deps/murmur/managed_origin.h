#ifndef MURMUR_MANAGED_ORIGIN_H
#define MURMUR_MANAGED_ORIGIN_H
#include "managed.h"
#include "origin.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
  uint8_t database[16],origin[16],site[16],public_key[32];
} murmur_origin_identity_t;
typedef struct {
  murmur_origin_envelope_t envelope;
  uint8_t *payload; /* malloc-owned; clear with record_free */
  size_t bytes;
} murmur_origin_record_t;
/* Initial activation requires no prior CRR history or causal policy state.
 * Reopen must supply the same seed under the pinned identity. Never stores
 * the seed in SQL. Changing a bound key/identity is rejected. */
int murmur_managed_origin_configure(murmur_managed_t *,const uint8_t database[16],
                                    const uint8_t origin[16],const uint8_t seed[32]);
int murmur_managed_origin_identity(murmur_managed_t *,murmur_origin_identity_t *);
/* Pins origin/public-key/site binding; enabled=0 revokes without forgetting
 * the binding. A changed key or site under an existing origin is rejected. */
int murmur_managed_origin_trust(murmur_managed_t *,const murmur_origin_identity_t *,int enabled);
/* Supports ordinary and policy-bearing tables. Enabling requires an empty
 * table with cr-sqlite-compatible NOT NULL primary keys. Configure non-LWW
 * policies before data history; existing data requires a baseline upgrade.
 * The schema authority publishes replication changes atomically. Re-enabling
 * a table with signed history requires a checkpoint and is rejected. */
int murmur_managed_set_replication(murmur_managed_t *,const char *table,int enabled);
/* Returns an owned immutable record, or SQLITE_NOTFOUND. Export and successful
 * verified apply include a durability barrier. Duplicate apply sets applied=0;
 * gaps and uncovered causal dependencies return SQLITE_BUSY;
 * equivocation/auth failures return SQLITE_AUTH. Effects,
 * receipts and progress commit atomically. A durability failure after commit
 * is reported as IOERR; retry flush/apply to resolve that outcome. */
int murmur_managed_origin_next(murmur_managed_t *,const uint8_t origin[16],
                              uint64_t after,murmur_origin_record_t *);
void murmur_origin_record_free(murmur_origin_record_t *);
int murmur_managed_origin_apply(murmur_managed_t *,const murmur_origin_record_t *,int *applied);
/* Rows: origin BLOB, committed sequence INTEGER. */
int murmur_managed_origin_progress(murmur_managed_t *,murmur_row_fn,void *);
int murmur_managed_flush(murmur_managed_t *);
#ifdef __cplusplus
}
#endif
#endif
