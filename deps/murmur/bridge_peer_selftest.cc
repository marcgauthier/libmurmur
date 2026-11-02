#include "../crsqlite/include/sqlite_murmur_crsqlite.h"
#include "bridge_peer.h"
#include "bridge_publish.h"
#include "origin.h"
#include "sqlite3.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge peer failure line %d: %s\n", __LINE__, #x);      \
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
std::string value(sqlite3 *db, const char *q) {
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
int try_records(sqlite3 *db, const std::vector<Record> &records) {
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
void apply_records(sqlite3 *db, const std::vector<Record> &records) {
  CHECK(try_records(db, records) == SQLITE_OK);
}

int main() {
  sqlite3 *db[2]{};
  uint8_t database[16] = {9}, seeds[2][32] = {{11}, {12}}, pubs[2][32]{};
  murmur_bridge_capture_options_t config[2]{};
  for (int i = 0; i < 2; i++) {
    CHECK(sqlite3_open(":memory:", &db[i]) == SQLITE_OK);
    CHECK(sqlite3_crsqlite_init(db[i], nullptr, nullptr) == SQLITE_OK);
    sql(db[i], "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT "
               "NULL,email TEXT NOT NULL)");
    uint8_t table[16];
    CHECK(murmur_bridge_rows_register(db[i], "notes", table) == SQLITE_OK);
    config[i].role = MURMUR_BRIDGE_HIGH;
    memcpy(config[i].database, database, 16);
    config[i].node[0] = (uint8_t)(i + 1);
    config[i].staging_bytes = 1u << 30;
    strcpy(config[i].stream, "peer");
    CHECK(murmur_bridge_capture_attach(db[i], &config[i]) == SQLITE_OK);
    CHECK(murmur_bridge_peer_configure(db[i], database, config[i].node,
                                       seeds[i]) == SQLITE_OK);
    CHECK(murmur_origin_public_key(seeds[i], pubs[i]) == SQLITE_OK);
  }
  for (int i = 0; i < 2; i++)
    CHECK(murmur_bridge_peer_trust(db[i], config[1 - i].node, pubs[1 - i], 1) ==
          SQLITE_OK);
  // A High-only insertion has no Low shadow. Both required fields must land
  // before projection, otherwise the first field would violate NOT NULL.
  write(db[0], "INSERT INTO notes VALUES('one','High','email')");
  auto first = records(db[0]);
  CHECK(first.size() == 1);
  apply_records(db[1], first);
  CHECK(value(db[1], "SELECT name||':'||email FROM notes") == "High:email");
  write(db[1],
        "UPDATE notes SET name='peer',email='peer email' WHERE id='one'");
  apply_records(db[0], records(db[1]));
  CHECK(value(db[0], "SELECT name||':'||email FROM notes") ==
        "peer:peer email");
  // Failed SQL rolls back both ordinary data and the signing journal.
  auto before = records(db[0]).size();
  CHECK(murmur_bridge_write(
            db[0], execute,
            (void *)"UPDATE notes SET name='bad'; INSERT INTO notes "
                    "VALUES('one','duplicate','duplicate')") != SQLITE_OK);
  CHECK(records(db[0]).size() == before);
  write(db[0], "DELETE FROM notes WHERE id='one'");
  apply_records(db[1], records(db[0]));
  CHECK(value(db[1], "SELECT count(*) FROM notes") == "0");
  // Reordered immutable records retry without resurrecting a deleted row.
  apply_records(db[1], first);
  CHECK(value(db[1], "SELECT count(*) FROM notes") == "0");
  // High reinsert releases the row claim and publishes all new field values
  // atomically. Its peer must never see a partially reconstructed row.
  write(db[1], "INSERT INTO notes VALUES('one','reinsert','new email')");
  apply_records(db[0], records(db[1]));
  CHECK(value(db[0], "SELECT name||':'||email FROM notes") ==
        "reinsert:new email");
  uint8_t wrong[32];
  memcpy(wrong, pubs[0], 32);
  wrong[0] ^= 1;
  CHECK(murmur_bridge_peer_trust(db[1], config[0].node, wrong, 1) ==
        SQLITE_AUTH);
  // Detaching wipes the key. Captured writes remain blocked until the same
  // pinned signing identity is restored; existing journal history is retained.
  CHECK(murmur_bridge_capture_detach(db[1]) == SQLITE_OK);
  CHECK(murmur_bridge_capture_attach(db[1], &config[1]) == SQLITE_OK);
  CHECK(murmur_bridge_write(db[1], execute,
                            (void *)"UPDATE notes SET name='unsigned'") ==
        SQLITE_AUTH);
  CHECK(murmur_bridge_peer_configure(db[1], database, config[1].node,
                                     seeds[1]) == SQLITE_OK);
  CHECK(value(db[1], "SELECT name FROM notes") == "reinsert");

  // Only one High node receives the ferry. Its peer must reverify the
  // original Low signature, then commit the Low shadow and both receipts.
  auto dir = std::filesystem::temp_directory_path() /
             ("murmur-peer-source-" +
              std::to_string(
                  std::chrono::steady_clock::now().time_since_epoch().count()));
  CHECK(std::filesystem::create_directory(dir));
  struct Cleanup {
    std::filesystem::path path;
    ~Cleanup() { std::filesystem::remove_all(path); }
  } cleanup{dir};
  sqlite3 *low = nullptr;
  CHECK(sqlite3_open(":memory:", &low) == SQLITE_OK);
  sql(low, "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT NOT "
           "NULL,email TEXT NOT NULL)");
  uint8_t table[16];
  CHECK(murmur_bridge_rows_register(low, "notes", table) == SQLITE_OK);
  murmur_bridge_capture_options_t source{};
  source.role = MURMUR_BRIDGE_LOW;
  source.database[0] = 5;
  source.node[0] = 7;
  source.signer[0] = 9;
  source.staging_bytes = 1u << 30;
  strcpy(source.stream, "source");
  uint8_t secret[32] = {13}, source_pub[32];
  CHECK(murmur_bridge_recipient_public(secret, source.recipient) == SQLITE_OK);
  CHECK(murmur_origin_public_key(source.signer, source_pub) == SQLITE_OK);
  CHECK(murmur_bridge_capture_attach(low, &source) == SQLITE_OK);
  write(low, "INSERT INTO notes VALUES('low','Low','email')");
  auto directory = dir.u8string();
  CHECK(murmur_bridge_publish(low, source.database, source.stream,
                              directory.c_str()) == SQLITE_OK);
  murmur_bridge_receiver_config_t trust{};
  memcpy(trust.source, source.database, 16);
  memcpy(trust.exporter, source.node, 16);
  memcpy(trust.receiver, secret, 32);
  memcpy(trust.signers[0], source_pub, 32);
  trust.signer_count = 1;
  trust.stream = source.stream;
  trust.directory = directory.c_str();
  trust.staging_bytes = 1u << 30;
  murmur_bridge_receiver_t *receiver = nullptr;
  CHECK(murmur_bridge_receiver_new(db[0], &trust, &receiver) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  CHECK(value(db[0], "SELECT name FROM notes WHERE id='low'") == "Low");
  // A trusted High origin cannot replace the operator-pinned Low signature.
  trust.signers[0][0] ^= 1;
  CHECK(murmur_bridge_peer_source(db[1], &trust) == SQLITE_OK);
  CHECK(try_records(db[1], records(db[0])) == SQLITE_AUTH);
  CHECK(value(db[1], "SELECT count(*) FROM notes WHERE id='low'") == "0");
  trust.signers[0][0] ^= 1;
  CHECK(murmur_bridge_peer_source(db[1], &trust) == SQLITE_OK);
  apply_records(db[1], records(db[0]));
  CHECK(value(db[1], "SELECT name FROM notes WHERE id='low'") == "Low");
  CHECK(value(db[1], "SELECT count(*) FROM murmur_bridge_receipt") == "1");
  murmur_bridge_receiver_free(receiver);
  CHECK(sqlite3_close(low) == SQLITE_OK);
  for (int i = 0; i < 2; i++) {
    sql(db[i], "SELECT crsql_finalize()");
    CHECK(sqlite3_close(db[i]) == SQLITE_OK);
  }
  puts("BRIDGE-PEER-OK");
}
