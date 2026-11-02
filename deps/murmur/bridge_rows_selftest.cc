#include "bridge_rows.h"
#include "managed_row.h"
#include "origin.h"
#include "sqlite3.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge rows failure line %d: %s\n", __LINE__, #x);      \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static void sql(sqlite3 *db, const char *q) {
  CHECK(sqlite3_exec(db, q, nullptr, nullptr, nullptr) == SQLITE_OK);
}
static std::string text(sqlite3 *db, const char *q) {
  sqlite3_stmt *s = nullptr;
  CHECK(sqlite3_prepare_v2(db, q, -1, &s, nullptr) == SQLITE_OK);
  CHECK(sqlite3_step(s) == SQLITE_ROW);
  auto p = sqlite3_column_text(s, 0);
  std::string out = p ? (const char *)p : "NULL";
  sqlite3_finalize(s);
  return out;
}
static murmur_value_t key(const char *s) {
  murmur_value_t v{};
  v.type = MURMUR_TEXT;
  v.data = s;
  v.bytes = strlen(s);
  return v;
}
static murmur_bridge_version_t stamp(uint64_t n, uint8_t node = 2) {
  murmur_bridge_version_t v{};
  v.millis = n;
  v.origin[0] = node;
  return v;
}
struct Bytes {
  murmur_bridge_bytes_t b{};
  ~Bytes() { murmur_bridge_bytes_free(&b); }
};
struct Fixture {
  sqlite3 *low = nullptr, *high = nullptr;
  uint8_t tid[16], seed[32]{1}, secret[32]{}, recipient[32], pub[32];
  uint64_t clock = 0;
  murmur_bridge_header_t h{};
  Fixture() {
    CHECK(sqlite3_open(":memory:", &low) == SQLITE_OK);
    CHECK(sqlite3_open(":memory:", &high) == SQLITE_OK);
    secret[16] = 2;
    CHECK(murmur_origin_public_key(seed, pub) == SQLITE_OK);
    CHECK(murmur_bridge_recipient_public(secret, recipient) == SQLITE_OK);
    h.database[0] = 1;
    h.node[0] = 2;
    h.transaction[0] = 1;
    strcpy(h.stream, "overwatch");
    for (auto db : {low, high}) {
      CHECK(murmur_bridge_store_init(db) == SQLITE_OK);
      sql(db, "CREATE TABLE contacts(id TEXT PRIMARY KEY NOT NULL,name TEXT "
              "NOT NULL DEFAULT '',value INTEGER,score REAL,data BLOB)");
      uint8_t id[16];
      CHECK(murmur_bridge_rows_register(db, "contacts", id) == SQLITE_OK);
      memcpy(tid, id, 16);
    }
  }
  ~Fixture() {
    CHECK(sqlite3_close(low) == SQLITE_OK);
    CHECK(sqlite3_close(high) == SQLITE_OK);
  }
  int send(const char *changes, bool deleted = false) {
    sql(low, "BEGIN");
    sql(low, changes);
    auto k = key("one");
    auto v = stamp(++clock);
    Bytes row, payload;
    CHECK(murmur_bridge_rows_capture(low, tid, &k, 1, deleted, &v, &row.b) ==
          SQLITE_OK);
    CHECK(murmur_bridge_rows_pack(&row.b, 1, &payload.b) == SQLITE_OK);
    stage(payload.b);
    return apply();
  }
  void stage(const murmur_bridge_bytes_t &payload) {
    CHECK(murmur_bridge_rows_schema(low, h.schema) == SQLITE_OK);
    h.transaction[0] = (uint8_t)clock;
    CHECK(murmur_bridge_store_queue(low, &h, seed, recipient, payload.data,
                                    payload.len, MURMUR_BRIDGE_MAX_BUNDLE,
                                    MURMUR_BRIDGE_MAX_PAYLOAD,
                                    1u << 30) == SQLITE_OK);
    sql(low, "COMMIT");
    Bytes bundle;
    uint64_t seq = 0;
    CHECK(murmur_bridge_store_next(low, h.database, h.stream, &seq,
                                   &bundle.b) == SQLITE_OK);
    CHECK(murmur_bridge_store_stage(
              high, bundle.b.data, bundle.b.len, h.database, h.stream, pub,
              secret, MURMUR_BRIDGE_MAX_BUNDLE, MURMUR_BRIDGE_MAX_PAYLOAD,
              1u << 30) == SQLITE_OK);
    CHECK(murmur_bridge_store_ack(low, h.database, h.stream, seq) == SQLITE_OK);
  }
  int apply() {
    return murmur_bridge_rows_apply(high, h.database, h.stream, pub, secret,
                                    MURMUR_BRIDGE_MAX_BUNDLE,
                                    MURMUR_BRIDGE_MAX_PAYLOAD);
  }
  void claim(const char *changes, const char *column, uint64_t n) {
    sql(high, "BEGIN");
    sql(high, changes);
    auto k = key("one");
    auto v = stamp(n, 3);
    CHECK(murmur_bridge_rows_claim(high, tid, &k, 1, column, &v) == SQLITE_OK);
    sql(high, "COMMIT");
  }
  void release(const char *column, uint64_t n) {
    sql(high, "BEGIN");
    auto k = key("one");
    auto v = stamp(n, 3);
    CHECK(murmur_bridge_rows_release(high, tid, &k, 1, column, &v) ==
          SQLITE_OK);
    sql(high, "COMMIT");
  }
};
int main() {
  {
    Fixture f;
    CHECK(f.send("INSERT INTO contacts "
                 "VALUES('one','Low',9223372036854775807,1.5,x'00FF')") ==
          SQLITE_OK);
    CHECK(text(f.high, "SELECT name FROM contacts") == "Low");
    CHECK(text(f.high, "SELECT "
                       "typeof(value)||':'||value||':'||typeof(score)||':'||"
                       "hex(data) FROM contacts") ==
          "integer:9223372036854775807:real:00FF");
    f.claim("UPDATE contacts SET name='High'", "name", 100);
    CHECK(f.send(
              "UPDATE contacts SET name='new Low',value=NULL WHERE id='one'") ==
          SQLITE_OK);
    CHECK(text(f.high, "SELECT name||':'||typeof(value) FROM contacts") ==
          "High:null");
    f.release("name", 101);
    CHECK(text(f.high, "SELECT name FROM contacts") == "new Low");
    f.claim("DELETE FROM contacts", nullptr, 200);
    CHECK(f.send("UPDATE contacts SET name='latest Low'") == SQLITE_OK);
    CHECK(text(f.high, "SELECT count(*) FROM contacts") == "0");
    f.release(nullptr, 201);
    CHECK(text(f.high, "SELECT name FROM contacts") == "latest Low");
    f.claim("UPDATE contacts SET name='keep High'", "name", 300);
    CHECK(f.send("DELETE FROM contacts", true) == SQLITE_OK);
    CHECK(text(f.high, "SELECT name FROM contacts") == "keep High");
    f.release("name", 301);
    CHECK(text(f.high, "SELECT count(*) FROM contacts") == "0");
    CHECK(f.send("INSERT INTO contacts(id,name) VALUES('one','reinsert')") ==
          SQLITE_OK);
    CHECK(text(f.high, "SELECT name FROM contacts") == "reinsert");
    auto k = key("one");
    auto v = stamp(400, 3);
    sql(f.high, "BEGIN; UPDATE contacts SET name='rolled back'");
    CHECK(murmur_bridge_rows_claim(f.high, f.tid, &k, 1, "name", &v) ==
          SQLITE_OK);
    sql(f.high, "ROLLBACK");
    CHECK(f.send("UPDATE contacts SET name='after rollback'") == SQLITE_OK);
    CHECK(text(f.high, "SELECT name FROM contacts") == "after rollback");
  }
  {
    Fixture f;
    sql(f.low, "ALTER TABLE contacts ADD COLUMN extra TEXT");
    CHECK(murmur_bridge_rows_register(f.low, "contacts", f.tid) == SQLITE_OK);
    CHECK(f.send("INSERT INTO contacts(id,name,extra) VALUES('one','held','new "
                 "field')") == SQLITE_SCHEMA);
    CHECK(text(f.high, "SELECT count(*) FROM contacts") == "0");
    CHECK(text(f.high, "SELECT count(*) FROM murmur_bridge_receipt") == "0");
    sql(f.high, "ALTER TABLE contacts ADD COLUMN extra TEXT");
    CHECK(murmur_bridge_rows_register(f.high, "contacts", f.tid) == SQLITE_OK);
    CHECK(f.apply() == SQLITE_OK);
    CHECK(text(f.high, "SELECT extra FROM contacts") == "new field");
  }
  {
    Fixture f;
    sql(f.high, "CREATE TRIGGER reject_bad BEFORE INSERT ON contacts WHEN "
                "NEW.name='reject' BEGIN SELECT RAISE(ABORT,'rejected'); END");
    sql(f.low, "BEGIN; INSERT INTO contacts(id,name) "
               "VALUES('one','valid'),('two','reject')");
    Bytes first, second, payload;
    auto a = key("one"), b = key("two");
    auto v = stamp(++f.clock);
    CHECK(murmur_bridge_rows_capture(f.low, f.tid, &a, 1, 0, &v, &first.b) ==
          SQLITE_OK);
    CHECK(murmur_bridge_rows_capture(f.low, f.tid, &b, 1, 0, &v, &second.b) ==
          SQLITE_OK);
    murmur_bridge_bytes_t rows[] = {first.b, second.b};
    CHECK(murmur_bridge_rows_pack(rows, 2, &payload.b) == SQLITE_OK);
    f.stage(payload.b);
    CHECK(f.apply() == SQLITE_CONSTRAINT);
    CHECK(text(f.high, "SELECT count(*) FROM contacts") == "0");
    CHECK(text(f.high, "SELECT count(*) FROM murmur_bridge_shadows") == "0");
    CHECK(text(f.high, "SELECT count(*) FROM murmur_bridge_origin_domains") ==
          "0");
    CHECK(text(f.high, "SELECT count(*) FROM murmur_bridge_receipt") == "0");
    sql(f.high, "DROP TRIGGER reject_bad");
    CHECK(f.apply() == SQLITE_OK);
    CHECK(text(f.high, "SELECT count(*) FROM contacts") == "2");
  }
  {
    Fixture f;
    uint8_t out[16];
    CHECK(murmur_bridge_rows_register(f.high, "murmur_bridge_lane", out) ==
          SQLITE_AUTH);
    sql(f.high, "CREATE VIRTUAL TABLE search USING fts5(body)");
    CHECK(murmur_bridge_rows_register(f.high, "search", out) == SQLITE_SCHEMA);
    sql(f.high, "CREATE TABLE no_key(value)");
    CHECK(murmur_bridge_rows_register(f.high, "no_key", out) == SQLITE_SCHEMA);
    for (auto db : {f.low, f.high}) {
      sql(db, "CREATE TABLE composite(a INTEGER NOT NULL,b BLOB NOT NULL,value "
              "TEXT,PRIMARY KEY(a,b))");
      CHECK(murmur_bridge_rows_register(db, "composite", out) == SQLITE_OK);
    }
    sql(f.low, "BEGIN; INSERT INTO composite VALUES(7,x'00FF','typed key')");
    murmur_value_t keys[2]{};
    keys[0].type = MURMUR_INTEGER;
    keys[0].integer = 7;
    uint8_t blob[] = {0, 255};
    keys[1].type = MURMUR_BLOB;
    keys[1].data = blob;
    keys[1].bytes = 2;
    Bytes row, payload;
    auto v = stamp(++f.clock);
    CHECK(murmur_bridge_rows_capture(f.low, out, keys, 2, 0, &v, &row.b) ==
          SQLITE_OK);
    CHECK(murmur_bridge_rows_pack(&row.b, 1, &payload.b) == SQLITE_OK);
    f.stage(payload.b);
    CHECK(f.apply() == SQLITE_OK);
    CHECK(text(f.high, "SELECT value FROM composite WHERE a=7 AND b=x'00FF'") ==
          "typed key");
  }
  puts("BRIDGE-ROWS-OK");
}
