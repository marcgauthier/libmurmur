#ifndef MURMUR_MANAGED_ROW_H
#define MURMUR_MANAGED_ROW_H
#include "managed_value.h"
#include <array>
#include <map>
/* Internal replicated row state. This is not an independently authenticated
 * input: signed origin verification and causal dependency authorization must
 * precede materialization. No storage or network side effects occur here. */
struct ManagedVersion {
  uint64_t millis=0;
  uint32_t logical=0;
  std::array<uint8_t,16> origin{};
  int compare(const ManagedVersion &) const;
  bool empty() const;
};
struct ManagedRowColumn {
  int policy=MURMUR_POLICY_LWW;
  ManagedVersion version; /* LWW only */
  ManagedValue value; /* LWW, min or max */
  std::string baseline,causal; /* Counter, set, JSON or list */
};
struct ManagedRow {
  std::string table,key,epoch;
  ManagedVersion generation,tombstone;
  std::map<std::string,ManagedRowColumn> columns;
  bool alive() const { return generation.compare(tombstone)>0; }
};
/* Pure join: errors leave both inputs unchanged. Deletes compare against
 * insert generations, not later column edits. A new insert starts fresh
 * policy baselines. Tombstones are retained across newer generations. */
ManagedRow managed_row_join(const ManagedRow &,const ManagedRow &);
/* Check provenance using retained state for this generation. Missing foreign
 * history throws SQLITE_BUSY. Callers must separately authenticate the
 * envelope, schema and version bounds. First inserts may attest their own
 * generation/baselines; later writers cannot introduce foreign operations. */
void managed_row_authorize(sqlite3 *,const ManagedRow *known,const ManagedRow &,
    const uint8_t database[16],const uint8_t signer[16]);
ManagedValue managed_row_project(const ManagedRowColumn &);
std::string managed_row_encode(const ManagedRow &);
ManagedRow managed_row_decode(const std::string &);
#endif
