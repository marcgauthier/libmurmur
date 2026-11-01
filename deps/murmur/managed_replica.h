#ifndef MURMUR_MANAGED_REPLICA_H
#define MURMUR_MANAGED_REPLICA_H
#include "managed_internal.h"
#include "managed_row.h"
#include "managed_origin.h"
/* Caller holds writer admission and an SQL transaction. */
bool managed_policy_has_table(murmur_managed *,const char *);
bool managed_replica_dirty(murmur_managed *);
void managed_replica_clear_dirty(murmur_managed *);
std::string managed_replica_capture(murmur_managed *,const murmur_origin_envelope_t &,const std::string &cells);
struct ManagedReplicaBatch { std::string cells; std::vector<ManagedRow> rows; };
ManagedReplicaBatch managed_replica_decode(const murmur_origin_record_t &);
void managed_replica_apply(murmur_managed *,const murmur_origin_envelope_t &,const ManagedReplicaBatch &);
#endif
