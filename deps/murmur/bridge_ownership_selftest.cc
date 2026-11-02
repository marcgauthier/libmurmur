#include "bridge_ownership.h"
#include <cstdio>
#include <cstdlib>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge ownership failure line %d: %s\n", __LINE__, #x); \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static ManagedVersion stamp(uint64_t n) {
  ManagedVersion v;
  v.millis = n;
  v.origin[0] = 1;
  return v;
}
int main() {
  ManagedValue pk;
  pk.type = MURMUR_INTEGER;
  pk.integer = 7;
  std::string table(16, 't'), column(16, 'c'),
      key = managed_encode_values({pk});
  ManagedRowColumn c;
  c.value.type = MURMUR_TEXT;
  c.value.data = "High value";
  auto first = bridge_owner_claim(nullptr, table, key, column, stamp(1), c);
  c.value.data = "new High value";
  auto edit = bridge_owner_claim(&first, table, key, column, stamp(2), c);
  CHECK(edit.epoch.compare(first.epoch) == 0 && edit.cell->version.millis == 2);
  CHECK(bridge_owner_encode(bridge_owner_join(first, edit)) ==
        bridge_owner_encode(edit));
  auto released = bridge_owner_release(edit, stamp(3));
  CHECK(!released.owned && released.release.millis == 3);
  CHECK(bridge_owner_encode(bridge_owner_release(released, stamp(4))) ==
        bridge_owner_encode(released));
  CHECK(bridge_owner_encode(bridge_owner_join(released, edit)) ==
        bridge_owner_encode(released));
  CHECK(bridge_owner_encode(bridge_owner_join(edit, released)) ==
        bridge_owner_encode(released));
  auto reclaim = bridge_owner_claim(&released, table, key, column, stamp(4), c);
  CHECK(reclaim.epoch.millis == 4 && reclaim.release.millis == 3);
  auto a = bridge_owner_join(bridge_owner_join(edit, released), reclaim);
  auto b = bridge_owner_join(edit, bridge_owner_join(released, reclaim));
  CHECK(bridge_owner_encode(a) == bridge_owner_encode(b));
  CHECK(bridge_owner_encode(bridge_owner_join(a, a)) == bridge_owner_encode(a));
  auto encoded = bridge_owner_encode(a);
  CHECK(bridge_owner_encode(bridge_owner_decode(encoded)) == encoded);
  auto forged = edit;
  forged.cell->value.data = "conflicting same version";
  bool rejected = false;
  try {
    bridge_owner_join(edit, forged);
  } catch (ManagedError e) {
    rejected = e.code == SQLITE_CORRUPT;
  }
  CHECK(rejected);
  auto row =
      bridge_owner_claim(nullptr, table, key, "", stamp(5), std::nullopt);
  CHECK(row.owned && !row.cell);
  CHECK(!bridge_owner_release(row, stamp(6)).owned);
  rejected = false;
  try {
    bridge_owner_release(edit, stamp(1));
  } catch (ManagedError e) {
    rejected = e.code == SQLITE_CONSTRAINT;
  }
  CHECK(rejected);
  for (size_t n = 0; n < encoded.size(); ++n) {
    rejected = false;
    try {
      bridge_owner_decode(encoded.substr(0, n));
    } catch (ManagedError) {
      rejected = true;
    }
    CHECK(rejected);
  }
  puts("BRIDGE-OWNERSHIP-OK");
}
