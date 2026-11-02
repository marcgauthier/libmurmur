#ifndef MURMUR_BRIDGE_PEER_SOURCE_INTERNAL_H
#define MURMUR_BRIDGE_PEER_SOURCE_INTERNAL_H
#include "bridge_ferry.h"
int bridge_peer_source(sqlite3 *, const murmur_bridge_receiver_config_t *);
int bridge_peer_received(sqlite3 *, const murmur_bridge_header_t *);
extern "C" int bridge_peer_finish_files(sqlite3 *, murmur_files_t *,
                                        int (*stop)(void *), void *);
#endif
