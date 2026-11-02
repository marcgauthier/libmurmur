#ifndef MURMUR_BRIDGE_PEER_H
#define MURMUR_BRIDGE_PEER_H
#include "bridge_capture.h"
#include "bridge_ferry.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Opt-in signed ownership journal for native High peers. Capture must already
 * be attached with this database/node/High role. The key stays in native
 * connection memory; reopening must use the pinned identity/key. Configure
 * the same registered tables on every peer; journal transport uses CRR.
 * Ordinary user-table CRR transport must remain disabled for bridged tables:
 * signed semantic ownership joins, not raw row LWW, own their projection. */
int murmur_bridge_peer_configure(sqlite3 *, const uint8_t database[16],
                                 const uint8_t node[16],
                                 const uint8_t seed[32]);
/* Low nodes sign original row transactions with their own pinned key. The
 * designated exporter alone allocates ferry sequences; other nodes replicate
 * original signed records to it. Registered user-table raw transport must be
 * disabled, as on High. All Low nodes must use this profile together. */
int murmur_bridge_peer_low_configure(sqlite3 *, const uint8_t database[16],
                                     const uint8_t node[16],
                                     const uint8_t seed[32],
                                     const uint8_t exporter[16]);
/* Pins an original Low transaction key for import on High. This is separate
 * from the domain exporter's envelope key. Rebinding an origin is rejected. */
int murmur_bridge_source_origin(sqlite3 *, const uint8_t source[16],
                                const uint8_t origin[16],
                                const uint8_t public_key[32], int enabled);
/* Pins another High origin's Ed25519 key. Rebinding is rejected. Revocation
 * retains the binding and receipts; no key bytes are accepted from the wire. */
int murmur_bridge_peer_trust(sqlite3 *, const uint8_t node[16],
                             const uint8_t public_key[32], int enabled);
/* Configure a source verifier for bundles forwarded by High peers. Directory
 * and quarantine fields are ignored. Keys remain in native connection memory.
 * Receivers also install this policy automatically when created after peer
 * configuration. Reapply on reopen before draining source journal records. */
int murmur_bridge_peer_source(sqlite3 *,
                              const murmur_bridge_receiver_config_t *);
/* Authorize file parts for a configured peer; the handle must use this db.
 * File finalization is performed by the native driver using its live store. */
int murmur_bridge_peer_files(sqlite3 *, murmur_files_t *);
/* Drain at most 256 ready ownership records under the caller's transaction.
 * Native sync calls this after ingesting CRR bytes. Effects and receipts stay
 * in that transaction. Missing prior origins/gaps/schema remain pending.
 * No transport is started by these calls. */
int murmur_bridge_peer_apply(sqlite3 *);
/* Standalone bounded retry pass used by the native driver's tick. */
int murmur_bridge_peer_poll(sqlite3 *);
/* Atomically replace active trust while retaining immutable historical key
 * bindings. Peer replacement preserves the configured local signing identity. */
typedef struct {
 uint8_t origin[16];
 uint8_t public_key[32];
} murmur_bridge_trusted_key_t;
int murmur_bridge_peer_replace_trust(sqlite3 *,const murmur_bridge_trusted_key_t *,size_t);
int murmur_bridge_source_replace_trust(sqlite3 *,const uint8_t source[16],const murmur_bridge_trusted_key_t *,size_t);

#ifdef __cplusplus
}
#endif
#endif
