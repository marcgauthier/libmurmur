#include "../crsqlite/include/sqlite_murmur_crsqlite.h"
#include "../keyring/sha256.h"
#include "bridge_ownership.h"
#include "bridge_peer.h"
#include "managed_codec.h"
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
      fprintf(stderr, "bridge Low peer failure line %d: %s\n", __LINE__, #x);  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
void sql(sqlite3 *db, const char *q) {
  CHECK(sqlite3_exec(db, q, nullptr, nullptr, nullptr) == SQLITE_OK);
}
int execute(sqlite3 *db, void *arg) {
  return sqlite3_exec(db, (const char *)arg, nullptr, nullptr, nullptr);
}
void write(sqlite3 *db, const char *q) {
  CHECK(murmur_bridge_write(db, execute, (void *)q) == SQLITE_OK);
}
std::string scalar(sqlite3 *db, const char *q) {
  sqlite3_stmt *s = nullptr;
  CHECK(sqlite3_prepare_v2(db, q, -1, &s, nullptr) == SQLITE_OK);
  CHECK(sqlite3_step(s) == SQLITE_ROW);
  auto p = sqlite3_column_text(s, 0);
  std::string out = p ? (const char *)p : "NULL";
  sqlite3_finalize(s);
  return out;
}
struct Record {
  std::string id, body;
};
std::string digest(const std::string &bytes) {
  uint8_t d[32];
  murmur_sha256((const uint8_t *)bytes.data(), bytes.size(), d);
  return std::string((const char *)d, 32);
}
std::vector<Record> records(sqlite3 *db) {
  sqlite3_stmt *q = nullptr;
  CHECK(sqlite3_prepare_v2(
            db, "SELECT id,body FROM murmur_bridge_peer_log ORDER BY rowid", -1,
            &q, nullptr) == SQLITE_OK);
  std::vector<Record> out;
  while (sqlite3_step(q) == SQLITE_ROW) {
    Record r;
    r.id.assign((const char *)sqlite3_column_blob(q, 0),
                sqlite3_column_bytes(q, 0));
    r.body.assign((const char *)sqlite3_column_blob(q, 1),
                  sqlite3_column_bytes(q, 1));
    out.push_back(r);
  }
  sqlite3_finalize(q);
  return out;
}
int apply_records(sqlite3 *db, const std::vector<Record> &records) {
  sql(db, "BEGIN IMMEDIATE");
  for (auto &r : records) {
    sqlite3_stmt *q = nullptr;
    CHECK(sqlite3_prepare_v2(db,
                             "INSERT INTO murmur_bridge_peer_log VALUES(?1,?2) "
                             "ON CONFLICT(id) DO NOTHING",
                             -1, &q, nullptr) == SQLITE_OK);
    CHECK(sqlite3_bind_blob(q, 1, r.id.data(), (int)r.id.size(),
                            SQLITE_TRANSIENT) == SQLITE_OK);
    CHECK(sqlite3_bind_blob(q, 2, r.body.data(), (int)r.body.size(),
                            SQLITE_TRANSIENT) == SQLITE_OK);
    CHECK(sqlite3_step(q) == SQLITE_DONE);
    sqlite3_finalize(q);
  }
  int rc = murmur_bridge_peer_apply(db);
  sql(db, rc == SQLITE_OK ? "COMMIT" : "ROLLBACK");
  return rc;
}
int main() {
  sqlite3 *db[3]{};
  uint8_t source[16] = {6}, nodes[2][16] = {{8}, {9}},
          seeds[2][32] = {{21}, {22}}, keys[2][32]{};
  uint8_t secret[32] = {13}, recipient[32], seal_seed[32] = {4}, seal_key[32];
  CHECK(murmur_bridge_recipient_public(secret, recipient) == SQLITE_OK);
  CHECK(murmur_origin_public_key(seal_seed, seal_key) == SQLITE_OK);
  for (int i = 0; i < 3; i++) {
    CHECK(sqlite3_open(":memory:", &db[i]) == SQLITE_OK);
    CHECK(sqlite3_crsqlite_init(db[i], nullptr, nullptr) == SQLITE_OK);
    sql(db[i], "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT "
               "NULL,email TEXT NOT NULL)");
    uint8_t table[16];
    CHECK(murmur_bridge_rows_register(db[i], "notes", table) == SQLITE_OK);
    murmur_bridge_capture_options_t c{};
    c.role = i < 2 ? MURMUR_BRIDGE_LOW : MURMUR_BRIDGE_HIGH;
    c.database[0] = i < 2 ? 6 : 99;
    c.node[0] = (uint8_t)(8 + i);
    c.staging_bytes = 1u << 30;
    strcpy(c.stream, "original");
    memcpy(c.signer, seal_seed, 32);
    memcpy(c.recipient, recipient, 32);
    CHECK(murmur_bridge_capture_attach(db[i], &c) == SQLITE_OK);
    if (i < 2) {
      CHECK(murmur_origin_public_key(seeds[i], keys[i]) == SQLITE_OK);
      CHECK(murmur_bridge_peer_low_configure(db[i], source, nodes[i], seeds[i],
                                             nodes[0]) == SQLITE_OK);
    }
  }
  for (int i = 0; i < 2; i++) {
    CHECK(murmur_bridge_peer_trust(db[i], nodes[1 - i], keys[1 - i], 1) ==
          SQLITE_OK);
    CHECK(murmur_bridge_source_origin(db[2], source, nodes[i], keys[i], 1) ==
          SQLITE_OK);
  }
  auto drain = [&] {
    for (;;) {
      uint64_t sequence = 0;
      murmur_bridge_bytes_t bundle{};
      int rc = murmur_bridge_store_next(db[0], source, "original", &sequence,
                                        &bundle);
      if (rc == SQLITE_NOTFOUND)
        return;
      CHECK(rc == SQLITE_OK);
      CHECK(murmur_bridge_store_stage(
                db[2], bundle.data, bundle.len, source, "original", seal_key,
                secret, MURMUR_BRIDGE_MAX_BUNDLE, MURMUR_BRIDGE_MAX_PAYLOAD,
                1u << 30) == SQLITE_OK);
      CHECK(murmur_bridge_rows_apply(db[2], source, "original", seal_key,
                                     secret, MURMUR_BRIDGE_MAX_BUNDLE,
                                     MURMUR_BRIDGE_MAX_PAYLOAD) == SQLITE_OK);
      CHECK(murmur_bridge_store_ack(db[0], source, "original", sequence) ==
            SQLITE_OK);
      murmur_bridge_bytes_free(&bundle);
    }
  };
  write(db[1], "INSERT INTO notes VALUES('one','peer','email')");
  CHECK(
      scalar(db[1],
             "SELECT count(*) FROM murmur_bridge_artifact WHERE kind='out'") ==
      "0");
  CHECK(apply_records(db[0], records(db[1])) == SQLITE_OK);
  drain();
  CHECK(scalar(db[2], "SELECT name||':'||email FROM notes") == "peer:email");
  write(db[0], "UPDATE notes SET email='exporter' WHERE id='one'");
  CHECK(apply_records(db[1], records(db[0])) == SQLITE_OK);
  drain();
  CHECK(scalar(db[2], "SELECT name||':'||email FROM notes") == "peer:exporter");
  write(db[1], "UPDATE notes SET name='peer edit' WHERE id='one'");
  auto pending = records(db[1]);
  Record original = pending.back();
  // Re-sign a malicious snapshot with the real writer's key, retaining a
  // foreign field version but replacing its value. Original signatures alone
  // do not authorize editing another node's retained operations.
  ManagedDecoder record(original.body.data(), original.body.size());
  CHECK(record.raw(4) == "MBJ1");
  auto wire = record.raw(MURMUR_ORIGIN_ENVELOPE_BYTES);
  auto payload = record.blob();
  record.end();
  murmur_origin_envelope_t envelope{};
  CHECK(murmur_origin_envelope_decode(wire.data(), wire.size(), &envelope) ==
        SQLITE_OK);
  ManagedDecoder low(payload.data(), payload.size());
  CHECK(low.raw(4) == "MBL1");
  auto packet = low.blob();
  low.end();
  ManagedDecoder rows(packet.data(), packet.size());
  CHECK(rows.raw(4) == "MBT1" && rows.count(1024) == 1);
  auto row = managed_row_decode(rows.blob());
  rows.end();
  bool changed = false;
  for (auto &cell : row.columns)
    if (cell.second.value.type == MURMUR_TEXT &&
        cell.second.value.data == "exporter") {
      CHECK(!memcmp(cell.second.version.origin.data(), nodes[0], 16));
      cell.second.value.data = "forged";
      changed = true;
    }
  CHECK(changed);
  ManagedEncoder altered;
  altered.raw("MBT1", 4);
  altered.number(1);
  altered.blob(managed_row_encode(row));
  ManagedEncoder low_packet;
  low_packet.raw("MBL1", 4);
  low_packet.blob(altered.bytes);
  CHECK(murmur_origin_sign(&envelope, seeds[1], low_packet.bytes.data(),
                           low_packet.bytes.size()) == SQLITE_OK);
  uint8_t encoded[MURMUR_ORIGIN_ENVELOPE_BYTES];
  CHECK(murmur_origin_envelope_encode(&envelope, encoded, sizeof(encoded)) ==
        SQLITE_OK);
  ManagedEncoder forged;
  forged.raw("MBJ1", 4);
  forged.raw(encoded, sizeof(encoded));
  forged.blob(low_packet.bytes);
  Record bad{digest(forged.bytes), forged.bytes};
  CHECK(apply_records(db[0], {bad}) == SQLITE_CORRUPT);
  CHECK(scalar(db[0], "SELECT name||':'||email FROM notes") == "peer:exporter");
  CHECK(apply_records(db[0], pending) == SQLITE_OK);
  drain();
  CHECK(scalar(db[2], "SELECT name||':'||email FROM notes") ==
        "peer edit:exporter");
  write(db[1], "DELETE FROM notes WHERE id='one'");
  CHECK(apply_records(db[0], records(db[1])) == SQLITE_OK);
  drain();
  CHECK(scalar(db[2], "SELECT count(*) FROM notes") == "0");
  write(db[0], "INSERT INTO notes VALUES('one','reinsert','new')");
  CHECK(apply_records(db[1], records(db[0])) == SQLITE_OK);
  drain();
  CHECK(scalar(db[2], "SELECT name||':'||email FROM notes") == "reinsert:new");
  CHECK(
      scalar(
          db[2],
          "SELECT count(DISTINCT origin) FROM murmur_bridge_source_receipts") ==
      "2");
  for (auto p : db) {
    sql(p, "SELECT crsql_finalize()");
    CHECK(sqlite3_close(p) == SQLITE_OK);
  }
  puts("BRIDGE-LOW-PEER-OK");
}
