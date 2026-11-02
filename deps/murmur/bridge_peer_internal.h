#ifndef MURMUR_BRIDGE_PEER_INTERNAL_H
#define MURMUR_BRIDGE_PEER_INTERNAL_H
#include "bridge_ownership.h"
#include "bridge_store.h"
#include "origin.h"
ManagedVersion bridge_capture_clock(sqlite3 *);
void bridge_peer_owner_changed(sqlite3 *, const BridgeOwner &);
bool bridge_capture_low(sqlite3 *, const uint8_t database[16],
                        const uint8_t node[16]);
bool bridge_peer_low_changed(sqlite3 *, const void *, size_t,
                             const ManagedVersion &, std::string *proof);
bool bridge_peer_exporter(sqlite3 *);
void bridge_capture_forward_mark(sqlite3 *, const std::string &table,
                                 const std::string &key);
void bridge_rows_merge_low(sqlite3 *, const murmur_origin_envelope_t &,
                           const std::string &payload, bool local);
int bridge_peer_import_low_proof(sqlite3 *, const murmur_bridge_header_t *,
                                 const void *, size_t);
void bridge_peer_detach(sqlite3 *);
void bridge_peer_begin(sqlite3 *);
void bridge_peer_commit(sqlite3 *);
bool bridge_capture_high(sqlite3 *, const uint8_t database[16],
                         const uint8_t node[16]);
void bridge_rows_project(sqlite3 *, const std::string &table,
                         const std::string &key);
void bridge_rows_merge_owner(sqlite3 *, const BridgeOwner &,
                             const uint8_t origin[16]);
#endif
