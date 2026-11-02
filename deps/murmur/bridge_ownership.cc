#include "bridge_ownership.h"
#include "managed_codec.h"
#include <climits>

namespace {
void version(ManagedEncoder &e, const ManagedVersion &v,
             bool optional = false) {
  if (!(optional && v.empty()) &&
      (v.millis > INT64_MAX || (!v.millis && !v.logical) ||
       v.origin == std::array<uint8_t, 16>{}))
    throw ManagedError{SQLITE_CORRUPT};
  e.number(v.millis);
  e.number(v.logical);
  e.raw(v.origin.data(), 16);
}
ManagedVersion version(ManagedDecoder &d) {
  ManagedVersion v;
  v.millis = d.number();
  auto logical = d.number();
  if (logical > UINT32_MAX)
    throw ManagedError{SQLITE_CORRUPT};
  v.logical = (uint32_t)logical;
  auto node = d.raw(16);
  std::copy(node.begin(), node.end(), v.origin.begin());
  return v;
}
void identity(const BridgeOwner &o) {
  if (o.table.size() != 16 || (!o.column.empty() && o.column.size() != 16))
    throw ManagedError{SQLITE_CORRUPT};
  auto key = managed_decode_values(o.key);
  if (key.empty() || managed_encode_values(key) != o.key)
    throw ManagedError{SQLITE_CORRUPT};
  for (auto &v : key)
    if (v.type == MURMUR_NULL)
      throw ManagedError{SQLITE_CORRUPT};
  if (o.column.empty() == o.cell.has_value())
    throw ManagedError{SQLITE_CORRUPT};
  if (o.cell && o.cell->policy != MURMUR_POLICY_LWW)
    throw ManagedError{SQLITE_MISMATCH};
}
void same(const BridgeOwner &a, const BridgeOwner &b) {
  if (a.table != b.table || a.key != b.key || a.column != b.column)
    throw ManagedError{SQLITE_MISMATCH};
}
} // namespace
std::string bridge_owner_encode(const BridgeOwner &o) {
  identity(o);
  ManagedEncoder e;
  e.raw("MBO1", 4);
  e.raw(o.table.data(), 16);
  e.blob(o.key);
  e.blob(o.column);
  if (o.release.compare(o.epoch) > 0 ||
      (!o.owned && o.release.compare(o.epoch) != 0) ||
      (o.owned && !o.release.empty() && o.release.compare(o.epoch) >= 0))
    throw ManagedError{SQLITE_CORRUPT};
  if (o.cell && o.cell->version.compare(o.epoch) < 0 && o.owned)
    throw ManagedError{SQLITE_CORRUPT};
  version(e, o.epoch);
  version(e, o.release, true);
  e.number(o.owned ? 1 : 0);
  e.number(o.cell ? 1 : 0);
  if (o.cell) {
    version(e, o.cell->version);
    e.blob(managed_encode_value(o.cell->value));
  }
  return e.bytes;
}
BridgeOwner bridge_owner_decode(const std::string &bytes) {
  ManagedDecoder d(bytes.data(), bytes.size());
  if (d.raw(4) != "MBO1")
    throw ManagedError{SQLITE_CORRUPT};
  BridgeOwner o;
  o.table = d.raw(16);
  o.key = d.blob();
  o.column = d.blob();
  o.epoch = version(d);
  o.release = version(d);
  auto owned = d.number(), cell = d.number();
  if (owned > 1 || cell > 1)
    throw ManagedError{SQLITE_CORRUPT};
  o.owned = owned;
  if (cell) {
    ManagedRowColumn c;
    c.version = version(d);
    c.value = managed_decode_value(d.blob());
    o.cell = std::move(c);
  }
  d.end();
  if (bridge_owner_encode(o) != bytes)
    throw ManagedError{SQLITE_CORRUPT};
  return o;
}
BridgeOwner bridge_owner_join(const BridgeOwner &a, const BridgeOwner &b) {
  auto encoded_a = bridge_owner_encode(a), encoded_b = bridge_owner_encode(b);
  same(a, b);
  int order = a.epoch.compare(b.epoch);
  if (!order && a.cell && b.cell)
    order = a.cell->version.compare(b.cell->version);
  if (!order && encoded_a != encoded_b)
    throw ManagedError{SQLITE_CORRUPT};
  return order < 0 ? b : a;
}
BridgeOwner bridge_owner_claim(const BridgeOwner *previous,
                               const std::string &table, const std::string &key,
                               const std::string &column,
                               const ManagedVersion &v,
                               const std::optional<ManagedRowColumn> &cell) {
  BridgeOwner o;
  o.table = table;
  o.key = key;
  o.column = column;
  o.epoch = v;
  o.owned = true;
  o.cell = cell;
  if (previous) {
    bridge_owner_encode(*previous);
    same(*previous, o);
    if (v.compare(previous->epoch) <= 0 ||
        (previous->cell && v.compare(previous->cell->version) <= 0))
      throw ManagedError{SQLITE_CONSTRAINT};
    if (previous->owned && !column.empty())
      o.epoch = previous->epoch;
    o.release = previous->release;
  }
  if (o.cell)
    o.cell->version = v;
  bridge_owner_encode(o);
  return o;
}
BridgeOwner bridge_owner_release(const BridgeOwner &previous,
                                 const ManagedVersion &v) {
  bridge_owner_encode(previous);
  if (!previous.owned)
    return previous;
  if (v.compare(previous.epoch) <= 0 ||
      (previous.cell && v.compare(previous.cell->version) <= 0))
    throw ManagedError{SQLITE_CONSTRAINT};
  auto o = previous;
  o.epoch = v;
  o.release = v;
  o.owned = false;
  bridge_owner_encode(o);
  return o;
}
