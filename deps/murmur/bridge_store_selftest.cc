#include "bridge_store.h"
#include "origin.h"
#include "sqlite3.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge store failure line %d: %s\n", __LINE__, #x);     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static int sql(sqlite3 *db, const char *text) {
  return sqlite3_exec(db, text, nullptr, nullptr, nullptr);
}
static int scalar(sqlite3 *db, const char *text) {
  sqlite3_stmt *q = nullptr;
  CHECK(sqlite3_prepare_v2(db, text, -1, &q, nullptr) == SQLITE_OK);
  CHECK(sqlite3_step(q) == SQLITE_ROW);
  int n = sqlite3_column_int(q, 0);
  sqlite3_finalize(q);
  return n;
}
static int apply(sqlite3 *db, const murmur_bridge_header_t *, const void *p,
                 size_t n, void *fail) {
  CHECK(n == 3 && !memcmp(p, "row", 3));
  int rc = sql(db, "INSERT INTO effects VALUES(1)");
  return rc == SQLITE_OK && fail ? SQLITE_ABORT : rc;
}
int main() {
  sqlite3 *low = nullptr, *high = nullptr;
  CHECK(sqlite3_open(":memory:", &low) == SQLITE_OK);
  CHECK(sqlite3_open(":memory:", &high) == SQLITE_OK);
  CHECK(murmur_bridge_store_init(low) == SQLITE_OK);
  CHECK(murmur_bridge_store_init(high) == SQLITE_OK);
  CHECK(murmur_bridge_store_init(high) == SQLITE_OK);
  CHECK(sql(low, "CREATE TABLE effects(n)") == SQLITE_OK);
  CHECK(sql(high, "CREATE TABLE effects(n)") == SQLITE_OK);
  uint8_t seed[32] = {1}, secret[32] = {2}, recipient[32], signer[32],
          schema[32] = {}, wrong[32] = {1};
  CHECK(murmur_bridge_recipient_public(secret, recipient) == SQLITE_OK);
  CHECK(murmur_origin_public_key(seed, signer) == SQLITE_OK);
  murmur_bridge_header_t h{};
  h.database[0] = 1;
  h.node[0] = 2;
  h.transaction[0] = 3;
  strcpy(h.stream, "overwatch");
  size_t mb = MURMUR_BRIDGE_MAX_BUNDLE, mp = MURMUR_BRIDGE_MAX_PAYLOAD;
  uint64_t cap = 1ull << 30;
  CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, "row", 3, mb, mp,
                                  cap) == SQLITE_MISUSE);
  CHECK(sql(low, "BEGIN; INSERT INTO effects VALUES(1)") == SQLITE_OK);
  CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, "row", 3, mb, mp,
                                  cap) == SQLITE_OK &&
        h.sequence == 1);
  CHECK(sql(low, "ROLLBACK") == SQLITE_OK);
  CHECK(scalar(low, "SELECT count(*) FROM effects") == 0);
  CHECK(scalar(low, "SELECT count(*) FROM murmur_bridge_lane") == 0);
  for (int i = 1; i <= 2; ++i) {
    CHECK(sql(low, "BEGIN") == SQLITE_OK);
    CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, "row", 3, mb, mp,
                                    cap) == SQLITE_OK &&
          h.sequence == (uint64_t)i);
    CHECK(sql(low, "COMMIT") == SQLITE_OK);
  }
  murmur_bridge_bytes_t first{}, second{};
  uint64_t seq = 0;
  CHECK(murmur_bridge_store_next(low, h.database, h.stream, &seq, &first) ==
            SQLITE_OK &&
        seq == 1);
  CHECK(murmur_bridge_store_ack(low, h.database, h.stream, seq) == SQLITE_OK);
  CHECK(murmur_bridge_store_next(low, h.database, h.stream, &seq, &second) ==
            SQLITE_OK &&
        seq == 2);
  CHECK(murmur_bridge_store_stage(high, second.data, second.len, h.database,
                                  h.stream, signer, secret, mb, mp,
                                  cap) == SQLITE_OK);
  CHECK(murmur_bridge_store_apply(high, h.database, h.stream, signer, secret,
                                  schema, mb, mp, apply,
                                  nullptr) == SQLITE_NOTFOUND);
  CHECK(murmur_bridge_store_stage(high, first.data, first.len, h.database,
                                  h.stream, signer, secret, mb, mp,
                                  1) == SQLITE_TOOBIG);
  CHECK(murmur_bridge_store_stage(high, first.data, first.len, h.database,
                                  h.stream, signer, secret, mb, mp,
                                  cap) == SQLITE_OK);
  CHECK(murmur_bridge_store_stage(high, first.data, first.len, h.database,
                                  h.stream, signer, secret, mb, mp,
                                  cap) == SQLITE_OK);
  CHECK(murmur_bridge_store_apply(high, h.database, h.stream, signer, secret,
                                  wrong, mb, mp, apply,
                                  nullptr) == SQLITE_SCHEMA);
  CHECK(murmur_bridge_store_apply(high, h.database, h.stream, signer, secret,
                                  schema, mb, mp, apply,
                                  (void *)1) == SQLITE_ABORT);
  CHECK(scalar(high, "SELECT count(*) FROM effects") == 0);
  CHECK(scalar(high, "SELECT count(*) FROM murmur_bridge_receipt") == 0);
  CHECK(murmur_bridge_store_apply(high, h.database, h.stream, signer, secret,
                                  schema, mb, mp, apply, nullptr) == SQLITE_OK);
  CHECK(murmur_bridge_store_stage(high, first.data, first.len, h.database,
                                  h.stream, signer, secret, mb, mp,
                                  cap) == SQLITE_OK);
  CHECK(murmur_bridge_store_apply(high, h.database, h.stream, signer, secret,
                                  schema, mb, mp, apply, nullptr) == SQLITE_OK);
  CHECK(murmur_bridge_store_apply(high, h.database, h.stream, signer, secret,
                                  schema, mb, mp, apply,
                                  nullptr) == SQLITE_NOTFOUND);
  CHECK(scalar(high, "SELECT count(*) FROM effects") == 2);
  h.sequence = 1;
  murmur_bridge_bytes_t conflict{};
  CHECK(murmur_bridge_seal(&h, seed, recipient, "different", 9, mb, mp,
                           &conflict) == SQLITE_OK);
  CHECK(murmur_bridge_store_stage(high, conflict.data, conflict.len, h.database,
                                  h.stream, signer, secret, mb, mp,
                                  cap) == SQLITE_AUTH);
  CHECK(scalar(high, "SELECT count(*) FROM effects") == 2);
  CHECK(scalar(high, "SELECT max(length(digest)) FROM murmur_bridge_receipt") ==
        32);
  CHECK(sql(low, "BEGIN") == SQLITE_OK);
  CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, "row", 3, mb, mp,
                                  1) == SQLITE_TOOBIG);
  CHECK(scalar(low, "SELECT allocated FROM murmur_bridge_lane") == 2);
  CHECK(sql(low, "COMMIT") == SQLITE_OK);
  // A lane budget cannot be consumed by unrelated source streams.
  uint64_t lane_cap = second.len + 16;
  CHECK(sql(low, "BEGIN") == SQLITE_OK);
  CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, "row", 3, mb, mp,
                                  lane_cap) == SQLITE_FULL);
  strcpy(h.stream, "other");
  CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, "row", 3, mb, mp,
                                  lane_cap) == SQLITE_OK);
  CHECK(sql(low, "COMMIT") == SQLITE_OK);
  CHECK(
      scalar(low,
             "SELECT count(*) FROM murmur_bridge_artifact WHERE kind='out'") ==
      2);
  murmur_bridge_bytes_free(&first);
  murmur_bridge_bytes_free(&second);
  murmur_bridge_bytes_free(&conflict);
  CHECK(sqlite3_close(low) == SQLITE_OK);
  CHECK(sqlite3_close(high) == SQLITE_OK);
  puts("BRIDGE-STORE-OK");
}
