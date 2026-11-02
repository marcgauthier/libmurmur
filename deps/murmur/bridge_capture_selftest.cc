#include "bridge_capture.h"
#include "origin.h"
#include "sqlite3.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge capture failure line %d: %s\n", __LINE__, #x);   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static void sql(sqlite3 *db, const char *s) {
  CHECK(sqlite3_exec(db, s, nullptr, nullptr, nullptr) == SQLITE_OK);
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
static int write_sql(sqlite3 *db, void *q) {
  return sqlite3_exec(db, (const char *)q, nullptr, nullptr, nullptr);
}
static int write_abort(sqlite3 *db, void *q) {
  int rc = write_sql(db, q);
  return rc == SQLITE_OK ? SQLITE_ABORT : rc;
}
static int deny_notes(void *, int action, const char *table, const char *,
                      const char *, const char *) {
  return action == SQLITE_READ && table && !strcmp(table, "notes") ? SQLITE_DENY
                                                                   : SQLITE_OK;
}
static void write(sqlite3 *db, const char *s) {
  CHECK(murmur_bridge_write(db, write_sql, (void *)s) == SQLITE_OK);
}
struct Fixture {
  sqlite3 *low = nullptr, *high = nullptr;
  uint8_t table[16], pub[32], secret[32]{};
  murmur_bridge_capture_options_t l{}, h{};
  Fixture() {
    CHECK(sqlite3_open(":memory:", &low) == SQLITE_OK);
    CHECK(sqlite3_open(":memory:", &high) == SQLITE_OK);
    secret[16] = 2;
    l.role = MURMUR_BRIDGE_LOW;
    l.database[0] = 1;
    l.node[0] = 2;
    l.signer[0] = 1;
    l.staging_bytes = 1u << 30;
    strcpy(l.stream, "overwatch");
    CHECK(murmur_bridge_recipient_public(secret, l.recipient) == SQLITE_OK);
    CHECK(murmur_origin_public_key(l.signer, pub) == SQLITE_OK);
    h.role = MURMUR_BRIDGE_HIGH;
    h.database[0] = 9;
    h.node[0] = 3;
    h.staging_bytes = 1u << 30;
    strcpy(h.stream, "overwatch");
    for (auto db : {low, high}) {
      sql(db, "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email "
              "TEXT); CREATE TABLE local_state(value)");
      CHECK(murmur_bridge_rows_register(db, "notes", table) == SQLITE_OK);
    }
    CHECK(murmur_bridge_capture_attach(low, &l) == SQLITE_OK);
    CHECK(murmur_bridge_capture_attach(high, &h) == SQLITE_OK);
  }
  ~Fixture() {
    CHECK(sqlite3_close(low) == SQLITE_OK);
    CHECK(sqlite3_close(high) == SQLITE_OK);
  }
  void transfer() {
    murmur_bridge_bytes_t b{};
    uint64_t seq = 0;
    while (murmur_bridge_store_next(low, l.database, l.stream, &seq, &b) ==
           SQLITE_OK) {
      CHECK(murmur_bridge_store_stage(high, b.data, b.len, l.database, l.stream,
                                      pub, secret, MURMUR_BRIDGE_MAX_BUNDLE,
                                      MURMUR_BRIDGE_MAX_PAYLOAD,
                                      1u << 30) == SQLITE_OK);
      murmur_bridge_bytes_free(&b);
      CHECK(murmur_bridge_rows_apply(high, l.database, l.stream, pub, secret,
                                     MURMUR_BRIDGE_MAX_BUNDLE,
                                     MURMUR_BRIDGE_MAX_PAYLOAD) == SQLITE_OK);
      CHECK(murmur_bridge_store_ack(low, l.database, l.stream, seq) ==
            SQLITE_OK);
    }
  }
  struct Release {
    uint8_t table[16];
    const char *column;
  };
  static int release_callback(sqlite3 *db, void *data) {
    auto r = (Release *)data;
    sqlite3_stmt *q = nullptr;
    CHECK(sqlite3_prepare_v2(
              db, "SELECT millis,logical FROM murmur_bridge_clock WHERE id=1",
              -1, &q, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(q) == SQLITE_ROW);
    murmur_bridge_version_t v{};
    v.millis = (uint64_t)sqlite3_column_int64(q, 0);
    v.logical = (uint32_t)sqlite3_column_int64(q, 1) + 1;
    v.origin[0] = 3;
    sqlite3_finalize(q);
    murmur_value_t key{};
    key.type = MURMUR_TEXT;
    key.data = "one";
    key.bytes = 3;
    return murmur_bridge_rows_release(db, r->table, &key, 1, r->column, &v);
  }
  void release(const char *column) {
    Release r{};
    memcpy(r.table, table, 16);
    r.column = column;
    CHECK(murmur_bridge_write(high, release_callback, &r) == SQLITE_OK);
  }
};
int main() {
  Fixture f;
  CHECK(murmur_bridge_rows_apply(f.low, f.l.database, f.l.stream, f.pub,
                                 f.secret, MURMUR_BRIDGE_MAX_BUNDLE,
                                 MURMUR_BRIDGE_MAX_PAYLOAD) == SQLITE_AUTH);
  CHECK(murmur_bridge_rows_apply(f.high, f.h.database, f.l.stream, f.pub,
                                 f.secret, MURMUR_BRIDGE_MAX_BUNDLE,
                                 MURMUR_BRIDGE_MAX_PAYLOAD) == SQLITE_AUTH);
  write(f.low, "INSERT INTO local_state VALUES('local only')");
  CHECK(text(f.low, "SELECT count(*) FROM murmur_bridge_artifact") == "0");
  CHECK(murmur_bridge_write(
            f.low, write_abort,
            (void *)"INSERT INTO notes VALUES('abort','rollback','r')") ==
        SQLITE_ABORT);
  CHECK(text(f.low, "SELECT count(*) FROM notes") == "0");
  CHECK(text(f.low, "SELECT count(*) FROM murmur_bridge_artifact") == "0");
  write(f.low, "INSERT INTO notes VALUES('one','Low','first'),('two','Low "
               "two','second'); INSERT INTO notes VALUES('temporary','t','t'); "
               "DELETE FROM notes WHERE id='temporary'");
  CHECK(text(f.low, "SELECT count(*) FROM murmur_bridge_artifact") == "1");
  f.transfer();
  CHECK(text(f.high, "SELECT count(*) FROM notes") == "2");
  CHECK(text(f.high, "SELECT count(*) FROM murmur_bridge_owners") == "0");
  write(f.high, "UPDATE notes SET name='High' WHERE id='one'");
  CHECK(text(f.high, "SELECT count(*) FROM murmur_bridge_owners") == "1");
  write(
      f.low,
      "UPDATE notes SET name='Low again',email='updated email' WHERE id='one'");
  f.transfer();
  CHECK(text(f.high, "SELECT name||':'||email FROM notes WHERE id='one'") ==
        "High:updated email");
  f.release("name");
  CHECK(text(f.high, "SELECT name FROM notes WHERE id='one'") == "Low again");
  write(f.low, "UPDATE notes SET name='after release' WHERE id='one'");
  f.transfer();
  CHECK(text(f.high, "SELECT name FROM notes WHERE id='one'") ==
        "after release");
  write(f.high, "DELETE FROM notes WHERE id='one'");
  write(f.low, "UPDATE notes SET name='row suppressed' WHERE id='one'");
  f.transfer();
  CHECK(text(f.high, "SELECT count(*) FROM notes WHERE id='one'") == "0");
  f.release(nullptr);
  CHECK(text(f.high, "SELECT name FROM notes WHERE id='one'") ==
        "row suppressed");
  write(f.high, "DELETE FROM notes WHERE id='one'");
  write(f.high, "INSERT INTO notes VALUES('one','High reinsert','High email')");
  write(f.low, "UPDATE notes SET name='ignored Low',email='ignored email' "
               "WHERE id='one'");
  f.transfer();
  CHECK(text(f.high, "SELECT name||':'||email FROM notes WHERE id='one'") ==
        "High reinsert:High email");
  write(f.low, "UPDATE notes SET name=name WHERE id='one'");
  CHECK(text(f.low, "SELECT count(*) FROM murmur_bridge_artifact") == "0");
  CHECK(murmur_bridge_capture_detach(f.high) == SQLITE_OK);
  CHECK(murmur_bridge_capture_attach(f.high, &f.h) == SQLITE_OK);
  write(f.low, "UPDATE notes SET name='after reattach' WHERE id='one'");
  f.transfer();
  CHECK(text(f.high, "SELECT name FROM notes WHERE id='one'") ==
        "High reinsert");
  CHECK(murmur_bridge_capture_detach(f.low) == SQLITE_OK);
  auto limited = f.l;
  limited.staging_bytes = 1;
  CHECK(murmur_bridge_capture_attach(f.low, &limited) == SQLITE_OK);
  CHECK(murmur_bridge_write(
            f.low, write_sql,
            (void *)"INSERT INTO notes VALUES('too-big','rejected','queue "
                    "limit')") == SQLITE_TOOBIG);
  CHECK(text(f.low, "SELECT count(*) FROM notes WHERE id='too-big'") == "0");
  CHECK(text(f.low, "SELECT count(*) FROM murmur_bridge_dirty") == "0");
  {
    Fixture baseline;
    sql(baseline.low, "INSERT INTO notes VALUES('one','existing "
                      "one','a'),('two','existing two','b')");
    size_t count = 0;
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) == SQLITE_OK &&
          count == 1);
    baseline.transfer();
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) == SQLITE_OK &&
          count == 1);
    baseline.transfer();
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) ==
              SQLITE_NOTFOUND &&
          count == 0);
    CHECK(text(baseline.high, "SELECT count(*) FROM notes") == "2");
    CHECK(murmur_bridge_capture_detach(baseline.low) == SQLITE_OK);
    CHECK(murmur_bridge_capture_attach(baseline.low, &baseline.l) == SQLITE_OK);
    CHECK(sqlite3_set_authorizer(baseline.low, deny_notes, nullptr) ==
          SQLITE_OK);
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) ==
              SQLITE_NOTFOUND &&
          count == 0);
    CHECK(sqlite3_set_authorizer(baseline.low, nullptr, nullptr) == SQLITE_OK);
    for (auto db : {baseline.low, baseline.high}) {
      sql(db, "ALTER TABLE notes ADD COLUMN extra TEXT");
      CHECK(murmur_bridge_rows_register(db, "notes", baseline.table) ==
            SQLITE_OK);
    }
    sql(baseline.low, "UPDATE notes SET extra='new baseline value'");
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) == SQLITE_OK &&
          count == 1);
    baseline.transfer();
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) == SQLITE_OK &&
          count == 1);
    baseline.transfer();
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) ==
              SQLITE_NOTFOUND &&
          count == 0);
    CHECK(text(baseline.high,
               "SELECT count(*) FROM notes WHERE extra='new baseline value'") ==
          "2");
    CHECK(murmur_bridge_capture_detach(baseline.low) == SQLITE_OK);
    strcpy(baseline.l.stream, "second");
    CHECK(murmur_bridge_capture_attach(baseline.low, &baseline.l) == SQLITE_OK);
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) == SQLITE_OK &&
          count == 1);
    baseline.transfer();
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) == SQLITE_OK &&
          count == 1);
    baseline.transfer();
    CHECK(murmur_bridge_capture_prepare(baseline.low, 1, &count) ==
              SQLITE_NOTFOUND &&
          count == 0);
  }
  puts("BRIDGE-CAPTURE-OK");
}
