#include "bridge_capture.h"
#include "bridge_ferry.h"
#include "bridge_sender.h"
#include "kv.h"
#include "origin.h"
#include "sqlite3.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "bridge ferry failure line %d: %s\n", __LINE__, #x);     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
struct Guard {
  Guard() { murmur_db_writer_lock(); }
  ~Guard() { murmur_db_writer_unlock(); }
};
void sql(sqlite3 *db, const char *s) {
  Guard guard;
  CHECK(sqlite3_exec(db, s, nullptr, nullptr, nullptr) == SQLITE_OK);
}
int write_sql(sqlite3 *db, void *arg) {
  return sqlite3_exec(db, (const char *)arg, nullptr, nullptr, nullptr);
}
void write(sqlite3 *db, const char *s) {
  CHECK(murmur_bridge_write(db, write_sql, (void *)s) == SQLITE_OK);
}
std::string scalar(sqlite3 *db, const char *s) {
  Guard guard;
  sqlite3_stmt *q = nullptr;
  CHECK(sqlite3_prepare_v2(db, s, -1, &q, nullptr) == SQLITE_OK);
  CHECK(sqlite3_step(q) == SQLITE_ROW);
  const auto *p = sqlite3_column_text(q, 0);
  std::string value = p ? (const char *)p : "NULL";
  sqlite3_finalize(q);
  return value;
}
int main() {
  auto unique =
      "murmur-native-ferry-" +
      std::to_string(
          std::chrono::steady_clock::now().time_since_epoch().count());
  auto dir = std::filesystem::temp_directory_path() / unique;
  CHECK(std::filesystem::create_directory(dir));
  struct Cleanup {
    std::filesystem::path dir;
    ~Cleanup() { std::filesystem::remove_all(dir); }
  } cleanup{dir};
  sqlite3 *low = nullptr, *high = nullptr;
  CHECK(sqlite3_open(":memory:", &low) == SQLITE_OK);
  CHECK(sqlite3_open(":memory:", &high) == SQLITE_OK);
  uint8_t id[16], secret[32] = {2}, signer[32];
  for (auto db : {low, high}) {
    sql(db, "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT,email "
            "TEXT)");
    CHECK(murmur_bridge_rows_register(db, "notes", id) == SQLITE_OK);
  }
  sql(low, "INSERT INTO notes VALUES('one','baseline','email')");
  murmur_bridge_capture_options_t l{}, h{};
  l.role = MURMUR_BRIDGE_LOW;
  l.database[0] = 1;
  l.node[0] = 2;
  l.signer[0] = 1;
  l.staging_bytes = 1u << 30;
  strcpy(l.stream, "native");
  CHECK(murmur_bridge_recipient_public(secret, l.recipient) == SQLITE_OK);
  CHECK(murmur_origin_public_key(l.signer, signer) == SQLITE_OK);
  h.role = MURMUR_BRIDGE_HIGH;
  h.database[0] = 9;
  h.node[0] = 3;
  h.staging_bytes = 1u << 30;
  strcpy(h.stream, "native");
  CHECK(murmur_bridge_capture_attach(low, &l) == SQLITE_OK);
  CHECK(murmur_bridge_capture_attach(high, &h) == SQLITE_OK);
  murmur_bridge_sender_t *sender = nullptr;
  std::string directory = dir.u8string();
  CHECK(murmur_bridge_sender_new(low, l.database, l.stream, directory.c_str(),
                                 1, &sender) == SQLITE_OK);
  murmur_bridge_receiver_config_t config{};
  memcpy(config.source, l.database, 16);
  memcpy(config.exporter, l.node, 16);
  memcpy(config.receiver, secret, 32);
  memcpy(config.signers[0], signer, 32);
  config.signer_count = 1;
  config.stream = l.stream;
  config.directory = directory.c_str();
  config.staging_bytes = 1u << 30;
  murmur_bridge_receiver_t *receiver = nullptr;
  CHECK(murmur_bridge_receiver_new(high, &config, &receiver) == SQLITE_OK);
  CHECK(murmur_bridge_sender_poll(sender, 1) ==
        SQLITE_OK); // one baseline batch
  CHECK(murmur_bridge_sender_poll(sender, 1) == SQLITE_OK); // publish it
  CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  CHECK(scalar(high, "SELECT name FROM notes WHERE id='one'") == "baseline");
  write(high, "UPDATE notes SET name='High' WHERE id='one'");
  write(low, "UPDATE notes SET name='Low',email='updated' WHERE id='one'");
  CHECK(murmur_bridge_sender_poll(sender, 1) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  CHECK(scalar(high, "SELECT name||':'||email FROM notes WHERE id='one'") ==
        "High:updated");
  murmur_value_t key{};
  key.type = MURMUR_TEXT;
  key.data = "one";
  key.bytes = 3;
  CHECK(murmur_bridge_capture_release(high, "notes", &key, 1, "name") ==
        SQLITE_OK);
  CHECK(murmur_bridge_capture_release(high, "notes", &key, 1, "name") ==
        SQLITE_NOTFOUND);
  CHECK(scalar(high, "SELECT name||':'||email FROM notes WHERE id='one'") ==
        "Low:updated");
  CHECK(murmur_bridge_sender_start(sender, 10) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_start(receiver, 10) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_poll(receiver, 1) == SQLITE_MISUSE);
  write(low, "UPDATE notes SET name='live' WHERE id='one'");
  bool applied = false;
  for (size_t i = 0; i < 300; ++i) {
    murmur_bridge_ferry_status_t status{};
    murmur_bridge_receiver_status(receiver, &status);
    if (status.applied == 3) {
      applied = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  CHECK(applied);
  murmur_bridge_sender_stop(sender);
  murmur_bridge_sender_stop(sender);
  murmur_bridge_receiver_stop(receiver);
  murmur_bridge_receiver_stop(receiver);
  CHECK(scalar(high, "SELECT name FROM notes WHERE id='one'") == "live");
  murmur_bridge_sender_status_t source_status{};
  murmur_bridge_sender_status(sender, &source_status);
  CHECK(source_status.published == 3 && source_status.baseline_complete &&
        source_status.baseline_rows == 1);
  murmur_bridge_receiver_free(receiver);
  CHECK(murmur_bridge_receiver_new(high, &config, &receiver) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  murmur_bridge_ferry_status_t status{};
  murmur_bridge_receiver_status(receiver, &status);
  CHECK(status.duplicate == 3 && status.applied == 0 && status.rejected == 0);
  murmur_bridge_receiver_free(receiver);
  murmur_bridge_sender_free(sender);
  CHECK(sqlite3_close(low) == SQLITE_OK);
  CHECK(sqlite3_close(high) == SQLITE_OK);
  puts("BRIDGE-FERRY-OK");
}
