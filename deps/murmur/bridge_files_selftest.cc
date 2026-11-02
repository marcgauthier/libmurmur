#include "../crsqlite/include/sqlite_murmur_crsqlite.h"
#include "../keyring/sha256.h"
#include "bridge_capture.h"
#include "bridge_ferry.h"
#include "bridge_files_internal.h"
#include "bridge_sender.h"
#include "managed_codec.h"
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
      fprintf(stderr, "bridge files failure line %d: %s\n", __LINE__, #x);     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
int main() {
  auto dir = std::filesystem::temp_directory_path() /
             ("murmur-bridge-files-" +
              std::to_string(
                  std::chrono::steady_clock::now().time_since_epoch().count()));
  CHECK(std::filesystem::create_directory(dir));
  struct Cleanup {
    std::filesystem::path p;
    ~Cleanup() { std::filesystem::remove_all(p); }
  } cleanup{dir};
  auto ferry = dir / "ferry";
  CHECK(std::filesystem::create_directory(ferry));
  sqlite3 *db[2]{};
  murmur_files_t *files[2]{};
  for (int i = 0; i < 2; i++) {
    CHECK(sqlite3_open(":memory:", &db[i]) == SQLITE_OK);
    char *detail = nullptr;
    int rc = 0;
    CHECK(sqlite3_crsqlite_init(db[i], &detail, nullptr) == SQLITE_OK);
    sqlite3_free(detail);
    detail = nullptr;
    uint8_t key[32] = {(uint8_t)(i + 1)};
    murmur_node_t node{};
    node.b[0] = (uint8_t)(i + 2);
    murmur_files_config_t config;
    murmur_files_config_default(&config, "", key);
    // The config borrows its directory for this call.
    auto directory = (dir / (i ? "high" : "low")).u8string();
    config.directory = directory.c_str();
    CHECK(murmur_files_open(&config, db[i], &node, &files[i], &detail, &rc) ==
          MURMUR_FILES_OK);
    free(detail);
    CHECK(sqlite3_exec(
              db[i],
              "CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,name TEXT)",
              nullptr, nullptr, nullptr) == SQLITE_OK);
    uint8_t id[16];
    CHECK(murmur_bridge_rows_register(db[i], "notes", id) == SQLITE_OK);
  }
  uint8_t secret[32] = {3}, pub[32];
  murmur_bridge_capture_options_t low{}, high{};
  low.role = MURMUR_BRIDGE_LOW;
  low.database[0] = 1;
  low.node[0] = 2;
  low.signer[0] = 7;
  strcpy(low.stream, "files");
  low.staging_bytes = 1u << 30;
  CHECK(murmur_bridge_recipient_public(secret, low.recipient) == SQLITE_OK);
  CHECK(murmur_origin_public_key(low.signer, pub) == SQLITE_OK);
  high.role = MURMUR_BRIDGE_HIGH;
  high.database[0] = 9;
  high.node[0] = 3;
  strcpy(high.stream, "files");
  high.staging_bytes = 1u << 30;
  CHECK(murmur_bridge_capture_attach(db[0], &low) == SQLITE_OK);
  CHECK(murmur_bridge_capture_attach(db[1], &high) == SQLITE_OK);
  std::vector<uint8_t> content(384u << 10);
  for (size_t i = 0; i < content.size(); i++)
    content[i] = (uint8_t)(i * 37 + i / 251);
  auto upload = [&](const char *name, const std::vector<uint8_t> &bytes) {
    char *detail = nullptr;
    int rc = 0;
    murmur_file_upload_t *u = nullptr;
    CHECK(murmur_files_begin_upload(files[0], name, &u, &detail, &rc) ==
          MURMUR_FILES_OK);
    CHECK(murmur_files_upload_append(u, bytes.data(), bytes.size(), &detail) ==
          MURMUR_FILES_OK);
    CHECK(murmur_files_finish_upload(files[0], u, nullptr, &detail, &rc) ==
          MURMUR_FILES_OK);
    free(detail);
  };
  upload("proof.bin", content);
  CHECK(bridge_files_init(db[0]) == SQLITE_OK);
  auto exporter =
      bridge_files_exporter_new(db[0], files[0], low.database, low.stream);
  uint64_t queued = 0;
  auto running = [] { return false; };
  CHECK(bridge_files_export_step(exporter, 1, running, &queued) == SQLITE_OK &&
        queued == 1);
  bridge_files_exporter_free(exporter);
  // Recreate after one part. Prefix scanning does not enqueue the saved part.
  exporter =
      bridge_files_exporter_new(db[0], files[0], low.database, low.stream);
  for (int i = 0; i < 10; i++)
    CHECK(bridge_files_export_step(exporter, 1, running, &queued) == SQLITE_OK);
  bridge_files_exporter_free(exporter);
  murmur_bridge_sender_t *sender = nullptr;
  auto directory = ferry.u8string();
  CHECK(murmur_bridge_sender_new(db[0], low.database, low.stream,
                                 directory.c_str(), 0, &sender) == SQLITE_OK);
  CHECK(murmur_bridge_sender_files(sender, files[0]) == SQLITE_OK);
  CHECK(murmur_bridge_sender_poll(sender, 256) == SQLITE_OK);
  murmur_bridge_sender_status_t status{};
  murmur_bridge_sender_status(sender, &status);
  CHECK(status.published == 7 && status.file_parts == 0);
  murmur_bridge_receiver_config_t cfg{};
  memcpy(cfg.source, low.database, 16);
  memcpy(cfg.exporter, low.node, 16);
  memcpy(cfg.receiver, secret, 32);
  memcpy(cfg.signers[0], pub, 32);
  cfg.signer_count = 1;
  cfg.stream = low.stream;
  cfg.directory = directory.c_str();
  cfg.staging_bytes = 1u << 30;
  murmur_bridge_receiver_t *receiver = nullptr;
  CHECK(murmur_bridge_receiver_new(db[1], &cfg, &receiver) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_files(receiver, files[1]) == SQLITE_OK);
  for (int i = 0; i < 12; i++)
    CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  murmur_bridge_ferry_status_t received{};
  murmur_bridge_receiver_status(receiver, &received);
  CHECK(received.applied == 7 && received.files_completed == 1);
  auto check = [&](const char *name, const std::vector<uint8_t> &want) {
    char *detail = nullptr;
    int rc = 0;
    murmur_file_download_t *d = nullptr;
    CHECK(murmur_files_download(files[1], name, &d, &detail, &rc) ==
          MURMUR_FILES_OK);
    std::vector<uint8_t> got;
    uint8_t buf[65536];
    int done = 0;
    while (!done) {
      size_t n = 0;
      uint64_t offset = 0;
      CHECK(murmur_files_download_next(d, sizeof(buf), &offset, buf, &n, &done,
                                       &detail) == MURMUR_FILES_OK);
      CHECK(offset == got.size());
      got.insert(got.end(), buf, buf + n);
    }
    CHECK(got == want);
    murmur_files_download_close(d);
    free(detail);
  };
  check("proof.bin", content);
  murmur_bridge_receiver_free(receiver);
  CHECK(murmur_bridge_receiver_new(db[1], &cfg, &receiver) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_files(receiver, files[1]) == SQLITE_OK);
  CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  murmur_bridge_receiver_status(receiver, &received);
  CHECK(received.duplicate == 7 && received.applied == 0 &&
        received.files_completed == 0);
  upload("empty", {});
  for (int i = 0; i < 8; i++)
    CHECK(murmur_bridge_sender_poll(sender, 256) == SQLITE_OK);
  for (int i = 0; i < 8; i++)
    CHECK(murmur_bridge_receiver_poll(receiver, 256) == SQLITE_OK);
  check("empty", {});
  // Atomic callback failure leaves no visible file metadata or callback effect.
  char *detail = nullptr;
  int rc = 0;
  murmur_file_upload_t *u = nullptr;
  CHECK(murmur_files_begin_upload(files[1], "failed", &u, &detail, &rc) ==
        MURMUR_FILES_OK);
  auto abort = [](sqlite3 *database, const murmur_files_meta_t *, void *) {
    sqlite3_exec(database, "INSERT INTO notes VALUES('failed','failed')",
                 nullptr, nullptr, nullptr);
    return SQLITE_ABORT;
  };
  CHECK(murmur_files_finish_upload_atomic(files[1], u, abort, nullptr, nullptr,
                                          &detail,
                                          &rc) == MURMUR_FILES_SQLITE &&
        rc == SQLITE_ABORT);
  free(detail);
  detail = nullptr;
  murmur_files_meta_t meta{};
  int found = 0;
  CHECK(murmur_files_metadata(files[1], "failed", &meta, &found, &detail,
                              &rc) == MURMUR_FILES_OK &&
        !found);
  free(detail);
  sqlite3_stmt *q = nullptr;
  CHECK(sqlite3_prepare_v2(db[1], "SELECT count(*) FROM notes", -1, &q,
                           nullptr) == SQLITE_OK);
  CHECK(sqlite3_step(q) == SQLITE_ROW && sqlite3_column_int(q, 0) == 0);
  sqlite3_finalize(q);

  // Direct authenticated-part staging: transaction rollback, offset rejection,
  // duplicate idempotence, staging bounds, and content authentication.
  murmur_bridge_header_t header{};
  memcpy(header.database, low.database, 16);
  strcpy(header.stream, "files");
  auto part = [](const std::string &name, const std::string &digest,
                 uint64_t total, uint64_t offset, bool final,
                 const std::string &data) {
    ManagedEncoder e;
    e.raw("MBF1", 4);
    e.blob(name);
    e.raw(digest.data(), 32);
    e.number(total);
    e.number(offset);
    e.number(final);
    e.blob(data);
    return e.bytes;
  };
  auto scalar = [&](const char *query) {
    sqlite3_stmt *q = nullptr;
    CHECK(sqlite3_prepare_v2(db[1], query, -1, &q, nullptr) == SQLITE_OK);
    CHECK(sqlite3_step(q) == SQLITE_ROW);
    int n = sqlite3_column_int(q, 0);
    sqlite3_finalize(q);
    return n;
  };
  auto stage = [&](const std::string &payload, uint64_t capacity, bool commit) {
    CHECK(sqlite3_exec(db[1], "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) ==
          SQLITE_OK);
    int result = bridge_files_stage(db[1], &header, payload.data(),
                                    payload.size(), capacity);
    CHECK(sqlite3_exec(db[1],
                       result == SQLITE_OK && commit ? "COMMIT" : "ROLLBACK",
                       nullptr, nullptr, nullptr) == SQLITE_OK);
    return result;
  };
  uint8_t digest[32];
  murmur_sha256((const uint8_t *)"abcdef", 6, digest);
  std::string hash((const char *)digest, 32);
  auto prefix = part("partial", hash, 6, 0, false, "abc");
  CHECK(stage(prefix, 1u << 30, false) == SQLITE_OK);
  CHECK(scalar("SELECT count(*) FROM murmur_bridge_file_chunk") == 0);
  CHECK(stage(prefix, 1u << 30, true) == SQLITE_OK);
  CHECK(stage(prefix, 1u << 30, true) == SQLITE_OK);
  CHECK(stage(part("partial", hash, 6, 0, false, "xyz"), 1u << 30, true) ==
        SQLITE_AUTH);
  CHECK(stage(part("partial", hash, 6, 4, false, "ef"), 1u << 30, true) ==
        SQLITE_BUSY);
  CHECK(stage(part("partial", hash, 6, 3, false, "def"), 5, true) ==
        SQLITE_TOOBIG);
  CHECK(stage(part("partial", hash, 6, 6, true, ""), 1u << 30, true) ==
        SQLITE_BUSY);
  CHECK(stage(part("partial", hash, 6, 3, false, "def"), 1u << 30, true) ==
        SQLITE_OK);
  CHECK(stage(part("partial", hash, 6, 6, true, ""), 1u << 30, true) ==
        SQLITE_OK);
  uint64_t completed = 0;
  CHECK(bridge_files_finish_one(
            db[1], files[1], header.database, header.stream,
            [] { return true; }, &completed) == SQLITE_OK &&
        completed == 0);
  CHECK(scalar("SELECT count(*) FROM murmur_bridge_file_chunk") == 2);
  CHECK(bridge_files_finish_one(db[1], files[1], header.database, header.stream,
                                running, &completed) == SQLITE_OK &&
        completed == 1);
  check("partial", {'a', 'b', 'c', 'd', 'e', 'f'});
  CHECK(scalar("SELECT count(*) FROM murmur_bridge_file_chunk") == 0);
  // Staged bytes with a forged full-content digest never publish metadata.
  std::string wrong(32, 'x');
  CHECK(stage(part("bad-digest", wrong, 3, 0, false, "abc"), 1u << 30, true) ==
        SQLITE_OK);
  CHECK(stage(part("bad-digest", wrong, 3, 3, true, ""), 1u << 30, true) ==
        SQLITE_OK);
  CHECK(bridge_files_finish_one(db[1], files[1], header.database, header.stream,
                                running, &completed) == SQLITE_AUTH &&
        completed == 0);
  detail = nullptr;
  found = 0;
  CHECK(murmur_files_metadata(files[1], "bad-digest", &meta, &found, &detail,
                              &rc) == MURMUR_FILES_OK &&
        !found);
  free(detail);
  CHECK(scalar("SELECT count(*) FROM murmur_bridge_file_chunk") == 1);
  murmur_bridge_receiver_free(receiver);
  murmur_bridge_sender_free(sender);
  for (int i = 0; i < 2; i++) {
    murmur_files_close(files[i]);
    sqlite3_exec(db[i], "SELECT crsql_finalize()", nullptr, nullptr, nullptr);
    CHECK(sqlite3_close(db[i]) == SQLITE_OK);
  }
  puts("BRIDGE-FILES-OK");
}
