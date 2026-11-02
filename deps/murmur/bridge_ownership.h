#ifndef MURMUR_BRIDGE_OWNERSHIP_H
#define MURMUR_BRIDGE_OWNERSHIP_H
#include "managed_row.h"
#include <optional>
/* Pure HighLow ownership state. Authentication, persistence, schema binding
 * and write admission belong to the importer. IDs are stable 16-byte IDs;
 * key and value encodings reuse the native canonical typed-value codec. */
struct BridgeOwner {
  std::string table, key, column; /* empty column denotes row ownership */
  ManagedVersion epoch, release;
  bool owned = false;
  std::optional<ManagedRowColumn> cell;
};
/* Join is deterministic; conflicting content under an identical epoch and
 * cell version is corruption. Both inputs remain unchanged on failure. */
BridgeOwner bridge_owner_join(const BridgeOwner &, const BridgeOwner &);
BridgeOwner bridge_owner_claim(const BridgeOwner *, const std::string &table,
                               const std::string &key,
                               const std::string &column,
                               const ManagedVersion &,
                               const std::optional<ManagedRowColumn> &);
BridgeOwner bridge_owner_release(const BridgeOwner &, const ManagedVersion &);
std::string bridge_owner_encode(const BridgeOwner &);
BridgeOwner bridge_owner_decode(const std::string &);
#endif
