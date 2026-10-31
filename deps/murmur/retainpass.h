/* murmur retainpass - native retention floors: per-origin floor
 * collection over peer acks plus snapshot pins, and our own
 * stream's GC floor. Ports CollectFloors and MyStreamFloor from
 * pkgs/replication/retention.go; the Engine RetentionPass loop
 * that schedules them lands with the native engine. Online peers
 * arrive as an explicit id set (Go's map[NodeID]bool).
 */
#ifndef MURMUR_RETAINPASS_H
#define MURMUR_RETAINPASS_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"
#include "retain.h"
#include "sync.h"

typedef struct sqlite3 sqlite3;

#ifdef __cplusplus
extern "C" {
#endif

/* Advances per-origin retention floors; returns origins moved.
 * node feeds the live-head merge behind backend.Progress. */
murmur_sync_status_t murmur_collect_floors(sqlite3 *db,
                                           const murmur_node_t *node,
                                           const murmur_retain_params_t *params,
                                           const murmur_node_t *online,
                                           size_t n_online, uint64_t now_millis,
                                           uint64_t boot_millis,
                                           uint64_t *moved, int *sqlrc);

/* Our own stream's GC floor over live, non-retired peer acks. */
murmur_sync_status_t murmur_my_stream_floor(sqlite3 *db,
                                            const murmur_retain_params_t *params,
                                            const murmur_node_t *online,
                                            size_t n_online,
                                            const murmur_node_t *own,
                                            uint64_t own_applied,
                                            uint64_t now_millis,
                                            uint64_t boot_millis,
                                            uint64_t *floor, int *sqlrc);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_RETAINPASS_H */
