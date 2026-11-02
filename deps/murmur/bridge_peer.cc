#include "bridge_peer.h"
#include "../codec/aesgcm.h"
#include "../keyring/sha256.h"
#include "bridge_capture_internal.h"
#include "bridge_files_internal.h"
#include "bridge_peer_internal.h"
#include "bridge_peer_source_internal.h"
#include "config.h"
#include "kv.h"
#include "managed_codec.h"
#include "open.h"
#include "origin.h"
#include "schema.h"
#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <tuple>
#include <vector>

namespace {
constexpr const char *slot = "murmur.native.bridge.peer.v1";
struct Source {
  std::array<uint8_t, 16> database{}, exporter{};
  std::array<uint8_t, 32> receiver{};
  std::vector<std::array<uint8_t, 32>> signers;
  std::string stream;
  uint64_t capacity = 0;
  ~Source() {
    volatile uint8_t *p = receiver.data();
    for (size_t i = 0; i < receiver.size(); ++i)
      p[i] = 0;
  }
};
struct Runtime {
  std::array<uint8_t, 16> database{}, node{};
  std::array<uint8_t, 32> seed{};
  uint64_t scan_after = 0;
  std::map<std::pair<std::string, std::string>, Source> sources;
  size_t file_cursor = 0;
  bool files_enabled = false;
  bool low = false;
  std::array<uint8_t, 16> exporter{};
  ~Runtime() {
    volatile uint8_t *p = seed.data();
    for (size_t i = 0; i < seed.size(); ++i)
      p[i] = 0;
  }
};
Runtime *runtime(sqlite3 *db) {
  return static_cast<Runtime *>(sqlite3_get_clientdata(db, slot));
}
struct Guard {
  Guard() { murmur_db_writer_lock(); }
  ~Guard() { murmur_db_writer_unlock(); }
};
struct Query {
  sqlite3_stmt *p = nullptr;
  Query(sqlite3 *db, const char *sql) {
    managed_check(sqlite3_prepare_v2(db, sql, -1, &p, nullptr));
  }
  ~Query() { sqlite3_finalize(p); }
  void blob(int n, const void *v, size_t len) {
    managed_check(sqlite3_bind_blob64(p, n, v, len, SQLITE_TRANSIENT));
  }
  void blob(int n, const std::string &v) { blob(n, v.data(), v.size()); }
  void number(int n, uint64_t v) {
    if (v > INT64_MAX)
      throw ManagedError{SQLITE_FULL};
    managed_check(sqlite3_bind_int64(p, n, (sqlite3_int64)v));
  }
  uint64_t number(int n) {
    auto v = sqlite3_column_int64(p, n);
    if (v < 0)
      throw ManagedError{SQLITE_CORRUPT};
    return (uint64_t)v;
  }
  std::string blob(int n) {
    if (sqlite3_column_type(p, n) != SQLITE_BLOB)
      throw ManagedError{SQLITE_CORRUPT};
    auto v = (const char *)sqlite3_column_blob(p, n);
    return std::string(v ? v : "", (size_t)sqlite3_column_bytes(p, n));
  }
  bool row() {
    int rc = sqlite3_step(p);
    if (rc == SQLITE_ROW)
      return true;
    if (rc != SQLITE_DONE)
      throw ManagedError{rc};
    return false;
  }
  void done() {
    if (row())
      throw ManagedError{SQLITE_CORRUPT};
  }
};
void sql(sqlite3 *db, const char *s) {
  managed_check(sqlite3_exec(db, s, nullptr, nullptr, nullptr));
}
template <typename Fn> int boundary(Fn fn) {
  try {
    fn();
    return SQLITE_OK;
  } catch (ManagedError e) {
    return e.code;
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_ERROR;
  }
}
std::string hash(const std::string &s) {
  uint8_t digest[32];
  murmur_sha256((const uint8_t *)s.data(), s.size(), digest);
  return std::string((const char *)digest, 32);
}
bool nonzero(const uint8_t *p, size_t n) {
  uint8_t b = 0;
  for (size_t i = 0; i < n; ++i)
    b |= p[i];
  return b;
}
struct Savepoint {
  sqlite3 *db;
  bool complete = false;
  Savepoint(sqlite3 *p) : db(p) { sql(db, "SAVEPOINT murmur_bridge_peer"); }
  ~Savepoint() {
    if (!complete)
      sqlite3_exec(db,
                   "ROLLBACK TO murmur_bridge_peer; RELEASE murmur_bridge_peer",
                   nullptr, nullptr, nullptr);
  }
  void commit() {
    sql(db, "RELEASE murmur_bridge_peer");
    complete = true;
  }
};
uint64_t head(sqlite3 *db, const uint8_t origin[16]) {
  Query q(db, "SELECT sequence FROM murmur_bridge_peer_heads WHERE origin=?1");
  q.blob(1, origin, 16);
  return q.row() ? q.number(0) : 0;
}
void receipt(sqlite3 *db, const murmur_origin_envelope_t &envelope,
             const std::string &digest) {
  Query save(db, "INSERT INTO murmur_bridge_peer_receipts VALUES(?1,?2,?3)");
  save.blob(1, envelope.origin, 16);
  save.number(2, envelope.sequence);
  save.blob(3, digest);
  save.done();
  Query update(db, "INSERT INTO murmur_bridge_peer_heads VALUES(?1,?2) ON "
                   "CONFLICT(origin) DO UPDATE SET sequence=excluded.sequence");
  update.blob(1, envelope.origin, 16);
  update.number(2, envelope.sequence);
  update.done();
}
std::string pack(const murmur_origin_envelope_t &envelope,
                 const std::string &payload) {
  uint8_t header[MURMUR_ORIGIN_ENVELOPE_BYTES];
  managed_check(
      murmur_origin_envelope_encode(&envelope, header, sizeof(header)));
  ManagedEncoder e;
  e.raw("MBJ1", 4);
  e.raw(header, sizeof(header));
  e.blob(payload);
  return e.bytes;
}
void unpack(const std::string &record, murmur_origin_envelope_t &envelope,
            std::string &payload) {
  ManagedDecoder d(record.data(), record.size());
  if (d.raw(4) != "MBJ1")
    throw ManagedError{SQLITE_CORRUPT};
  auto raw = d.raw(MURMUR_ORIGIN_ENVELOPE_BYTES);
  managed_check(
      murmur_origin_envelope_decode(raw.data(), raw.size(), &envelope));
  payload = d.blob();
  d.end();
  if (pack(envelope, payload) != record)
    throw ManagedError{SQLITE_CORRUPT};
}
std::string publish(sqlite3 *db, Runtime &r, const std::string &payload,
                    const ManagedVersion &stamp) {
  murmur_origin_envelope_t e{};
  memcpy(e.database, r.database.data(), 16);
  memcpy(e.origin, r.node.data(), 16);
  e.sequence = head(db, r.node.data()) + 1;
  if (e.sequence > INT64_MAX)
    throw ManagedError{SQLITE_FULL};
  e.millis = stamp.millis;
  e.logical = stamp.logical;
  managed_check(murmur_bridge_rows_schema(db, e.schema));
  if (murmur_rand_bytes(e.transaction, 16))
    throw ManagedError{SQLITE_ERROR};
  managed_check(
      murmur_origin_sign(&e, r.seed.data(), payload.data(), payload.size()));
  auto record = pack(e, payload);
  auto digest = hash(record);
  Query save(db, "INSERT INTO murmur_bridge_peer_log VALUES(?1,?2)");
  save.blob(1, digest);
  save.blob(2, record);
  save.done();
  receipt(db, e, digest);
  return record;
}
void receive(sqlite3 *db, Runtime &r, const std::string &payload) {
  ManagedDecoder d(payload.data(), payload.size());
  if (d.raw(4) != "MBS1")
    throw ManagedError{SQLITE_CORRUPT};
  auto bundle = d.blob();
  d.end();
  if (bundle.size() < 345 || bundle.size() > MURMUR_BRIDGE_MAX_BUNDLE ||
      memcmp(bundle.data(), "MHB1", 4))
    throw ManagedError{SQLITE_CORRUPT};
  auto stream_len = (uint8_t)bundle[60];
  if (!stream_len || stream_len > 64)
    throw ManagedError{SQLITE_CORRUPT};
  auto found =
      r.sources.find({bundle.substr(4, 16), bundle.substr(61, stream_len)});
  if (found == r.sources.end())
    throw ManagedError{SQLITE_BUSY};
  auto &source = found->second;
  auto digest = hash(bundle);
  Query accepted(db, "SELECT 1 FROM murmur_bridge_receipt WHERE source=?1 AND "
                     "stream=?2 AND digest=?3 LIMIT 1");
  accepted.blob(1, source.database.data(), 16);
  managed_check(sqlite3_bind_text(accepted.p, 2, source.stream.c_str(), -1,
                                  SQLITE_TRANSIENT));
  accepted.blob(3, digest);
  if (accepted.row())
    return;
  murmur_bridge_header_t h{};
  murmur_bridge_bytes_t plain{};
  struct Clean {
    murmur_bridge_bytes_t *p;
    ~Clean() { murmur_bridge_bytes_free(p); }
  } cleanup{&plain};
  int rc = SQLITE_AUTH;
  for (auto &key : source.signers) {
    rc = murmur_bridge_unseal(
        bundle.data(), bundle.size(), source.database.data(),
        source.stream.c_str(), key.data(), source.receiver.data(),
        MURMUR_BRIDGE_MAX_BUNDLE, MURMUR_BRIDGE_MAX_PAYLOAD, &h, &plain);
    if (rc == SQLITE_OK)
      break;
    if (rc != SQLITE_AUTH)
      throw ManagedError{rc};
  }
  managed_check(rc);
  if (memcmp(h.node, source.exporter.data(), 16) || h.sequence > INT64_MAX)
    throw ManagedError{SQLITE_AUTH};
  Query seen(db, "SELECT digest FROM murmur_bridge_receipt WHERE source=?1 AND "
                 "stream=?2 AND sequence=?3");
  seen.blob(1, h.database, 16);
  managed_check(sqlite3_bind_text(seen.p, 2, h.stream, -1, SQLITE_TRANSIENT));
  seen.number(3, h.sequence);
  if (seen.row()) {
    if (seen.blob(0) != digest)
      throw ManagedError{SQLITE_AUTH};
    return;
  }
  uint64_t applied = 0;
  Query progress(
      db,
      "SELECT applied FROM murmur_bridge_lane WHERE source=?1 AND stream=?2");
  progress.blob(1, h.database, 16);
  managed_check(
      sqlite3_bind_text(progress.p, 2, h.stream, -1, SQLITE_TRANSIENT));
  if (progress.row())
    applied = progress.number(0);
  if (h.sequence != applied + 1)
    throw ManagedError{SQLITE_BUSY};
  uint8_t schema[32];
  managed_check(murmur_bridge_rows_schema(db, schema));
  if (memcmp(schema, h.schema, 32))
    throw ManagedError{SQLITE_SCHEMA};
  if (plain.len >= 4 && !memcmp(plain.data, "MBF1", 4)) {
    if (!r.files_enabled)
      throw ManagedError{SQLITE_SCHEMA};
    managed_check(bridge_files_init(db));
    managed_check(
        bridge_files_stage(db, &h, plain.data, plain.len, source.capacity));
  } else
    managed_check(bridge_rows_import(db, &h, plain.data, plain.len));
  Query save(db, "INSERT INTO murmur_bridge_receipt VALUES(?1,?2,?3,?4)");
  save.blob(1, h.database, 16);
  managed_check(sqlite3_bind_text(save.p, 2, h.stream, -1, SQLITE_TRANSIENT));
  save.number(3, h.sequence);
  save.blob(4, digest);
  save.done();
  Query update(
      db,
      "INSERT INTO murmur_bridge_lane(source,stream,applied) VALUES(?1,?2,?3) "
      "ON CONFLICT(source,stream) DO UPDATE SET applied=excluded.applied");
  update.blob(1, h.database, 16);
  managed_check(sqlite3_bind_text(update.p, 2, h.stream, -1, SQLITE_TRANSIENT));
  update.number(3, h.sequence);
  update.done();
  Query remove(db, "DELETE FROM murmur_bridge_artifact WHERE source=?1 AND "
                   "stream=?2 AND sequence=?3 AND kind='in'");
  remove.blob(1, h.database, 16);
  managed_check(sqlite3_bind_text(remove.p, 2, h.stream, -1, SQLITE_TRANSIENT));
  remove.number(3, h.sequence);
  remove.done();
}
std::vector<BridgeOwner> owners(const std::string &payload,
                                const murmur_origin_envelope_t &envelope) {
  ManagedDecoder d(payload.data(), payload.size());
  if (d.raw(4) != "MBH1")
    throw ManagedError{SQLITE_CORRUPT};
  std::vector<BridgeOwner> out;
  std::set<std::tuple<std::string, std::string, std::string>> seen;
  for (size_t n = d.count(32766); n; --n) {
    auto owner = bridge_owner_decode(d.blob());
    if (!seen.emplace(owner.table, owner.key, owner.column).second)
      throw ManagedError{SQLITE_CORRUPT};
    // The signing node must own the operation being forwarded. Claim epochs
    // from an earlier node are admitted only by semantic merge against history.
    auto operation =
        owner.owned && owner.cell ? owner.cell->version : owner.epoch;
    if (memcmp(operation.origin.data(), envelope.origin, 16) ||
        operation.millis > envelope.millis ||
        (operation.millis == envelope.millis &&
         operation.logical > envelope.logical))
      throw ManagedError{SQLITE_AUTH};
    out.push_back(std::move(owner));
  }
  d.end();
  if (out.empty())
    throw ManagedError{SQLITE_CORRUPT};
  return out;
}
} // namespace
static int configure_peer(sqlite3 *db, const uint8_t database[16],
                          const uint8_t node[16], const uint8_t seed[32],
                          const uint8_t *exporter) {
  if (!db || !database || !node || !seed || !nonzero(database, 16) ||
      !nonzero(node, 16) || !nonzero(seed, 32))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    if (!sqlite3_get_autocommit(db) ||
        (exporter ? !bridge_capture_low(db, database, node)
                  : !bridge_capture_high(db, database, node)))
      throw ManagedError{SQLITE_MISUSE};
    if (auto prior = runtime(db)) {
      if (memcmp(prior->database.data(), database, 16) ||
          memcmp(prior->node.data(), node, 16) ||
          memcmp(prior->seed.data(), seed, 32) ||
          prior->low != (exporter != nullptr) ||
          (exporter && memcmp(prior->exporter.data(), exporter, 16)))
        throw ManagedError{SQLITE_AUTH};
      return;
    }
    {
      Query raw(db, "SELECT t.name FROM murmur_bridge_tables t JOIN "
                    "sqlite_schema s ON s.name=t.name||'__crsql_clock'");
      if (raw.row()) {
        Query config(db, "SELECT 1 FROM sqlite_schema WHERE type='table' AND "
                         "name='murmur_config'");
        if (!config.row())
          throw ManagedError{SQLITE_CONSTRAINT};
        murmur_table_flags_t flags{};
        struct FlagsCleanup {
          murmur_table_flags_t *flags;
          ~FlagsCleanup() { murmur_cfg_table_flags_free(flags); }
        } cleanup{&flags};
        int rc = SQLITE_OK;
        if (murmur_cfg_table_flags(db, &flags, &rc) != MURMUR_SYNC_OK)
          throw ManagedError{rc == SQLITE_OK ? SQLITE_ERROR : rc};
        do {
          const auto *name = sqlite3_column_text(raw.p, 0);
          int length = sqlite3_column_bytes(raw.p, 0);
          if (!name || !murmur_cfg_table_disabled(&flags, name, (size_t)length))
            throw ManagedError{SQLITE_CONSTRAINT};
        } while (raw.row());
      }
    }
    auto r = std::make_unique<Runtime>();
    r->low = exporter != nullptr;
    if (exporter) {
      // A zero exporter selects signed peer replication without a ferry.
      memcpy(r->exporter.data(), exporter, 16);
    }
    std::copy(database, database + 16, r->database.begin());
    std::copy(node, node + 16, r->node.begin());
    std::copy(seed, seed + 32, r->seed.begin());
    uint8_t pub[32];
    managed_check(murmur_origin_public_key(seed, pub));
    Savepoint tx(db);
    sql(db, "CREATE TABLE IF NOT EXISTS murmur_bridge_peer_config(id INTEGER "
            "PRIMARY KEY CHECK(id=1),database_id BLOB NOT NULL,node BLOB NOT "
            "NULL,public_key BLOB NOT NULL,role INTEGER NOT NULL,exporter BLOB "
            "NOT NULL);"
            "CREATE TABLE IF NOT EXISTS murmur_bridge_peer_keys(origin BLOB "
            "PRIMARY KEY NOT NULL,public_key BLOB NOT NULL,enabled INTEGER NOT "
            "NULL);"
            "CREATE TABLE IF NOT EXISTS murmur_bridge_peer_heads(origin BLOB "
            "PRIMARY KEY NOT NULL,sequence INTEGER NOT NULL);"
            "CREATE TABLE IF NOT EXISTS murmur_bridge_peer_receipts(origin "
            "BLOB NOT NULL,sequence INTEGER NOT NULL,digest BLOB NOT "
            "NULL,PRIMARY KEY(origin,sequence));"
            "CREATE INDEX IF NOT EXISTS murmur_bridge_peer_receipt_digest ON "
            "murmur_bridge_peer_receipts(digest);"
            "CREATE TABLE IF NOT EXISTS murmur_bridge_peer_dirty(id BLOB "
            "PRIMARY KEY NOT NULL,body BLOB NOT NULL);"
            "CREATE TABLE IF NOT EXISTS murmur_bridge_peer_log(id BLOB PRIMARY "
            "KEY NOT NULL,body BLOB NOT NULL DEFAULT x'');");
    Query prior(db, "SELECT database_id,node,public_key,role,exporter FROM "
                    "murmur_bridge_peer_config WHERE id=1");
    if (prior.row()) {
      if (prior.blob(0) != std::string((const char *)database, 16) ||
          prior.blob(1) != std::string((const char *)node, 16) ||
          prior.blob(2) != std::string((const char *)pub, 32) ||
          prior.number(3) != (r->low ? 1u : 2u) ||
          prior.blob(4) != std::string((const char *)r->exporter.data(), 16))
        throw ManagedError{SQLITE_AUTH};
    } else {
      if (r->low) {
        Query captured(db, "SELECT 1 FROM murmur_bridge_capture LIMIT 1");
        if (captured.row())
          throw ManagedError{SQLITE_CONSTRAINT};
        Query queued(
            db,
            "SELECT 1 FROM murmur_bridge_artifact WHERE kind='out' LIMIT 1");
        if (queued.row())
          throw ManagedError{SQLITE_CONSTRAINT};
      }
      Query owned(db, "SELECT 1 FROM murmur_bridge_owners LIMIT 1");
      if (owned.row())
        throw ManagedError{SQLITE_CONSTRAINT};
      Query save(
          db, "INSERT INTO murmur_bridge_peer_config VALUES(1,?1,?2,?3,?4,?5)");
      save.blob(1, database, 16);
      save.blob(2, node, 16);
      save.blob(3, pub, 32);
      save.number(4, r->low ? 1 : 2);
      save.blob(5, r->exporter.data(), 16);
      save.done();
    }
    Query pin(db, "INSERT INTO murmur_bridge_peer_keys VALUES(?1,?2,1) ON "
                  "CONFLICT(origin) DO NOTHING");
    pin.blob(1, node, 16);
    pin.blob(2, pub, 32);
    pin.done();
    Query check(db, "SELECT public_key,enabled FROM murmur_bridge_peer_keys "
                    "WHERE origin=?1");
    check.blob(1, node, 16);
    if (!check.row() || check.blob(0) != std::string((const char *)pub, 32) ||
        !check.number(1))
      throw ManagedError{SQLITE_AUTH};
    static const uint8_t table[] = "murmur_bridge_peer_log";
    int rc = SQLITE_OK;
    auto status = murmur_schema_make_crr(db, table, sizeof(table) - 1, &rc);
    if (status != MURMUR_SYNC_OK)
      throw ManagedError{rc == SQLITE_OK ? SQLITE_ERROR : rc};
    sql(db, "DELETE FROM murmur_bridge_peer_dirty");
    tx.commit();
    managed_check(sqlite3_set_clientdata(
        db, slot, r.get(), [](void *p) { delete static_cast<Runtime *>(p); }));
    r.release();
  });
}
extern "C" int murmur_bridge_peer_configure(sqlite3 *db,
                                            const uint8_t database[16],
                                            const uint8_t node[16],
                                            const uint8_t seed[32]) {
  return configure_peer(db, database, node, seed, nullptr);
}
extern "C" int murmur_bridge_peer_low_configure(sqlite3 *db,
                                                const uint8_t database[16],
                                                const uint8_t node[16],
                                                const uint8_t seed[32],
                                                const uint8_t exporter[16]) {
  if (!exporter)
    return SQLITE_MISUSE;
  return configure_peer(db, database, node, seed, exporter);
}
extern "C" int murmur_bridge_peer_trust(sqlite3 *db, const uint8_t node[16],
                                        const uint8_t key[32], int enabled) {
  if (!db || !node || !key || !nonzero(node, 16) || !nonzero(key, 32) ||
      (enabled != 0 && enabled != 1))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r || !sqlite3_get_autocommit(db))
      throw ManagedError{SQLITE_MISUSE};
    if (!memcmp(r->node.data(), node, 16) && !enabled)
      throw ManagedError{SQLITE_AUTH};
    Savepoint tx(db);
    Query old(db,
              "SELECT public_key FROM murmur_bridge_peer_keys WHERE origin=?1");
    old.blob(1, node, 16);
    if (old.row() && old.blob(0) != std::string((const char *)key, 32))
      throw ManagedError{SQLITE_AUTH};
    Query save(db, "INSERT INTO murmur_bridge_peer_keys VALUES(?1,?2,?3) ON "
                   "CONFLICT(origin) DO UPDATE SET enabled=excluded.enabled");
    save.blob(1, node, 16);
    save.blob(2, key, 32);
    save.number(3, enabled);
    save.done();
    tx.commit();
  });
}
bool bridge_peer_exporter(sqlite3 *db) {
  auto r = runtime(db);
  return !r || (r->low && r->node == r->exporter);
}
bool bridge_peer_low_changed(sqlite3 *db, const void *rows, size_t len,
                             const ManagedVersion &stamp, std::string *proof) {
  auto r = runtime(db);
  if (!r)
    return false;
  if (!r->low || !proof)
    throw ManagedError{SQLITE_MISUSE};
  ManagedEncoder payload;
  payload.raw("MBL1", 4);
  payload.blob(std::string((const char *)rows, len));
  auto record = publish(db, *r, payload.bytes, stamp);
  if (r->node == r->exporter) {
    ManagedEncoder packet;
    packet.raw("MHP1", 4);
    packet.blob(record);
    *proof = packet.bytes;
  } else
    proof->clear();
  return true;
}
void bridge_peer_detach(sqlite3 *db) {
  managed_check(sqlite3_set_clientdata(db, slot, nullptr, nullptr));
}
void bridge_peer_begin(sqlite3 *db) {
  if (!runtime(db)) {
    Query table(db, "SELECT 1 FROM sqlite_schema WHERE type='table' AND "
                    "name='murmur_bridge_peer_config'");
    if (table.row()) {
      Query configured(db, "SELECT 1 FROM murmur_bridge_peer_config LIMIT 1");
      if (configured.row())
        throw ManagedError{SQLITE_AUTH};
    }
    return;
  }
  if (runtime(db))
    sql(db, "DELETE FROM murmur_bridge_peer_dirty");
}
void bridge_peer_owner_changed(sqlite3 *db, const BridgeOwner &owner) {
  if (!runtime(db))
    return;
  if (runtime(db)->low)
    throw ManagedError{SQLITE_AUTH};
  ManagedEncoder key;
  key.blob(owner.table);
  key.blob(owner.key);
  key.blob(owner.column);
  Query save(db, "INSERT INTO murmur_bridge_peer_dirty VALUES(?1,?2) ON "
                 "CONFLICT(id) DO UPDATE SET body=excluded.body");
  save.blob(1, hash(key.bytes));
  save.blob(2, bridge_owner_encode(owner));
  save.done();
}
void bridge_peer_commit(sqlite3 *db) {
  auto r = runtime(db);
  if (!r)
    return;
  ManagedEncoder payload;
  payload.raw("MBH1", 4);
  std::vector<std::string> dirty;
  {
    Query q(db, "SELECT body FROM murmur_bridge_peer_dirty ORDER BY id");
    while (q.row()) {
      if (dirty.size() >= 32766)
        throw ManagedError{SQLITE_TOOBIG};
      dirty.push_back(q.blob(0));
    }
  }
  if (dirty.empty())
    return;
  payload.number(dirty.size());
  murmur_origin_envelope_t envelope{};
  memcpy(envelope.database, r->database.data(), 16);
  memcpy(envelope.origin, r->node.data(), 16);
  envelope.sequence = head(db, r->node.data()) + 1;
  if (envelope.sequence > INT64_MAX)
    throw ManagedError{SQLITE_FULL};
  managed_check(murmur_bridge_rows_schema(db, envelope.schema));
  if (murmur_rand_bytes(envelope.transaction, 16))
    throw ManagedError{SQLITE_ERROR};
  for (auto &bytes : dirty) {
    auto owner = bridge_owner_decode(bytes);
    auto stamp = owner.owned && owner.cell ? owner.cell->version : owner.epoch;
    if (memcmp(stamp.origin.data(), r->node.data(), 16))
      throw ManagedError{SQLITE_AUTH};
    if (stamp.millis > envelope.millis ||
        (stamp.millis == envelope.millis && stamp.logical > envelope.logical)) {
      envelope.millis = stamp.millis;
      envelope.logical = stamp.logical;
    }
    payload.blob(bytes);
  }
  managed_check(murmur_origin_sign(&envelope, r->seed.data(),
                                   payload.bytes.data(), payload.bytes.size()));
  auto record = pack(envelope, payload.bytes);
  auto digest = hash(record);
  Query insert(db, "INSERT INTO murmur_bridge_peer_log VALUES(?1,?2)");
  insert.blob(1, digest);
  insert.blob(2, record);
  insert.done();
  receipt(db, envelope, digest);
  sql(db, "DELETE FROM murmur_bridge_peer_dirty");
}
extern "C" int murmur_bridge_peer_apply(sqlite3 *db) {
  if (!db)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r)
      return;
    if (sqlite3_get_autocommit(db))
      throw ManagedError{SQLITE_MISUSE};
    std::vector<std::pair<std::string, std::string>> pending;
    Query q(db, "SELECT l.id,l.body,l.rowid FROM murmur_bridge_peer_log l "
                "WHERE l.rowid>?1 AND "
                "length(l.body)>0 AND NOT EXISTS(SELECT 1 FROM "
                "murmur_bridge_peer_receipts r WHERE r.digest=l.id) ORDER BY "
                "l.rowid LIMIT 256");
    q.number(1, r->scan_after);
    size_t examined = 0, bytes = 0;
    bool exhausted = true;
    while (q.row()) {
      auto len = sqlite3_column_bytes(q.p, 1);
      if (len < 0 || (size_t)len > MURMUR_BRIDGE_MAX_PAYLOAD)
        throw ManagedError{SQLITE_TOOBIG};
      if (!pending.empty() && (size_t)len > MURMUR_BRIDGE_MAX_PAYLOAD - bytes) {
        exhausted = false;
        break;
      }
      bytes += (size_t)len;
      pending.emplace_back(q.blob(0), q.blob(1));
      r->scan_after = q.number(2);
      ++examined;
    }
    if (exhausted && examined < 256)
      r->scan_after = 0;
    for (auto &item : pending) {
      if (hash(item.second) != item.first)
        throw ManagedError{SQLITE_AUTH};
      murmur_origin_envelope_t envelope{};
      std::string payload;
      unpack(item.second, envelope, payload);
      Query key(db, "SELECT public_key,enabled FROM murmur_bridge_peer_keys "
                    "WHERE origin=?1");
      key.blob(1, envelope.origin, 16);
      if (!key.row() || !key.number(1))
        throw ManagedError{SQLITE_AUTH};
      auto pub = key.blob(0);
      if (pub.size() != 32)
        throw ManagedError{SQLITE_CORRUPT};
      managed_check(
          murmur_origin_verify(&envelope, r->database.data(), envelope.origin,
                               (const uint8_t *)pub.data(), payload.data(),
                               payload.size(), MURMUR_BRIDGE_MAX_PAYLOAD));
      if (envelope.sequence > INT64_MAX || envelope.millis > INT64_MAX ||
          !nonzero(envelope.transaction, 16))
        throw ManagedError{SQLITE_AUTH};
      auto current = head(db, envelope.origin);
      if (envelope.sequence <= current) {
        Query old(db, "SELECT digest FROM murmur_bridge_peer_receipts WHERE "
                      "origin=?1 AND sequence=?2");
        old.blob(1, envelope.origin, 16);
        old.number(2, envelope.sequence);
        if (!old.row() || old.blob(0) != item.first)
          throw ManagedError{SQLITE_AUTH};
        continue;
      }
      if (envelope.sequence != current + 1)
        continue;
      uint8_t schema[32];
      managed_check(murmur_bridge_rows_schema(db, schema));
      if (memcmp(schema, envelope.schema, 32))
        continue;
      int result = boundary([&] {
        Savepoint tx(db);
        if (r->low) {
          ManagedDecoder low(payload.data(), payload.size());
          if (low.raw(4) != "MBL1")
            throw ManagedError{SQLITE_AUTH};
          auto rows = low.blob();
          low.end();
          bridge_rows_merge_low(db, envelope, rows, true);
          if (r->node == r->exporter) {
            ManagedEncoder proof;
            proof.raw("MHP1", 4);
            proof.blob(item.second);
            managed_check(bridge_capture_enqueue(db, proof.bytes.data(),
                                                 proof.bytes.size()));
            ManagedDecoder packet(rows.data(), rows.size());
            if (packet.raw(4) != "MBT1")
              throw ManagedError{SQLITE_CORRUPT};
            for (size_t n = packet.count(1024); n; --n) {
              auto row = managed_row_decode(packet.blob());
              bridge_capture_forward_mark(db, row.table, row.key);
            }
            packet.end();
          }
        } else if (payload.size() >= 4 && !memcmp(payload.data(), "MBS1", 4))
          receive(db, *r, payload);
        else {
          auto incoming = owners(payload, envelope);
          std::set<std::pair<std::string, std::string>> affected;
          for (auto &owner : incoming) {
            bridge_rows_merge_owner(db, owner, envelope.origin);
            affected.emplace(owner.table, owner.key);
          }
          for (auto &row : affected)
            bridge_rows_project(db, row.first, row.second);
        }
        receipt(db, envelope, item.first);
        tx.commit();
      });
      if (result == SQLITE_BUSY || result == SQLITE_SCHEMA)
        continue;
      managed_check(result);
    }
  });
}

extern "C" int murmur_bridge_peer_poll(sqlite3 *db) {
  if (!db)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    if (!runtime(db))
      return;
    if (!sqlite3_get_autocommit(db))
      throw ManagedError{SQLITE_MISUSE};
    auto before = sqlite3_total_changes64(db);
    sql(db, "BEGIN IMMEDIATE");
    int rc = murmur_bridge_peer_apply(db);
    if (rc == SQLITE_OK)
      rc = sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
    if (!sqlite3_get_autocommit(db))
      sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
    managed_check(rc);
    if (sqlite3_total_changes64(db) != before) {
      const char *path = sqlite3_db_filename(db, "main");
      if (path && *path && nvFlushDb(path))
        throw ManagedError{SQLITE_IOERR_FSYNC};
    }
  });
}

int bridge_peer_source(sqlite3 *db,
                       const murmur_bridge_receiver_config_t *config) {
  if (!db || !config)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r)
      return;
    if (!config->stream || !config->signer_count || config->signer_count > 8 ||
        !nonzero(config->source, 16) || !nonzero(config->exporter, 16) ||
        !nonzero(config->receiver, 32) ||
        !memcmp(config->source, r->database.data(), 16) ||
        !config->staging_bytes || config->staging_bytes > (1ull << 30))
      throw ManagedError{SQLITE_MISUSE};
    Source source;
    memcpy(source.database.data(), config->source, 16);
    memcpy(source.exporter.data(), config->exporter, 16);
    memcpy(source.receiver.data(), config->receiver, 32);
    size_t length = 0;
    for (; length < 65 && config->stream[length]; ++length) {
      char c = config->stream[length];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-'))
        throw ManagedError{SQLITE_MISUSE};
    }
    if (!length || length > 64)
      throw ManagedError{SQLITE_MISUSE};
    source.stream = config->stream;
    source.capacity = config->staging_bytes;
    for (size_t i = 0; i < config->signer_count; ++i) {
      if (!nonzero(config->signers[i], 32))
        throw ManagedError{SQLITE_MISUSE};
      std::array<uint8_t, 32> key;
      memcpy(key.data(), config->signers[i], 32);
      source.signers.push_back(key);
    }
    auto key = std::make_pair(
        std::string((const char *)source.database.data(), 16), source.stream);
    auto old = r->sources.find(key);
    if (old != r->sources.end() && old->second.exporter != source.exporter)
      throw ManagedError{SQLITE_AUTH};
    if (old == r->sources.end() && r->sources.size() >= 64)
      throw ManagedError{SQLITE_FULL};
    r->sources[key] = source;
  });
}
int bridge_peer_received(sqlite3 *db, const murmur_bridge_header_t *header) {
  if (!db || !header || sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r)
      return;
    Query q(db, "SELECT bundle FROM murmur_bridge_artifact WHERE source=?1 AND "
                "stream=?2 AND sequence=?3 AND kind='in'");
    q.blob(1, header->database, 16);
    managed_check(
        sqlite3_bind_text(q.p, 2, header->stream, -1, SQLITE_TRANSIENT));
    q.number(3, header->sequence);
    if (!q.row())
      throw ManagedError{SQLITE_NOTFOUND};
    ManagedEncoder packet;
    packet.raw("MBS1", 4);
    packet.blob(q.blob(0));
    publish(db, *r, packet.bytes, bridge_capture_clock(db));
  });
}
int bridge_peer_finish_files(sqlite3 *db, murmur_files_t *files,
                             int (*stop)(void *), void *ctx) {
  if (!db || !files)
    return SQLITE_OK;
  // Copy only the source identity under admission. File-store gates always
  // precede writer admission; never keep the guard while encrypting objects.
  std::array<uint8_t, 16> source{};
  std::string stream;
  {
    Guard guard;
    auto r = runtime(db);
    if (!r || r->sources.empty())
      return SQLITE_OK;
    auto i = r->sources.begin();
    std::advance(i, r->file_cursor++ % r->sources.size());
    source = i->second.database;
    stream = i->second.stream;
  }
  uint64_t completed = 0;
  return bridge_files_finish_one(
      db, files, source.data(), stream.c_str(),
      [=] { return stop && stop(ctx); }, &completed);
}

extern "C" int
murmur_bridge_peer_source(sqlite3 *db,
                          const murmur_bridge_receiver_config_t *config) {
  if (!db)
    return SQLITE_MISUSE;
  Guard guard;
  if (!runtime(db))
    return SQLITE_MISUSE;
  return bridge_peer_source(db, config);
}
extern "C" int murmur_bridge_peer_files(sqlite3 *db, murmur_files_t *files) {
  if (!db || !files || murmur_files_database(files) != db)
    return SQLITE_MISUSE;
  Guard guard;
  auto r = runtime(db);
  if (!r)
    return SQLITE_MISUSE;
  r->files_enabled = true;
  return SQLITE_OK;
}

extern "C" int murmur_bridge_source_origin(sqlite3 *db,
                                           const uint8_t source[16],
                                           const uint8_t origin[16],
                                           const uint8_t key[32], int enabled) {
  if (!db || !source || !origin || !key || !nonzero(source, 16) ||
      !nonzero(origin, 16) || !nonzero(key, 32) ||
      (enabled != 0 && enabled != 1))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    if (!sqlite3_get_autocommit(db))
      throw ManagedError{SQLITE_MISUSE};
    Savepoint tx(db);
    Query prior(db, "SELECT public_key FROM murmur_bridge_source_keys WHERE "
                    "source=?1 AND origin=?2");
    prior.blob(1, source, 16);
    prior.blob(2, origin, 16);
    if (prior.row() && prior.blob(0) != std::string((const char *)key, 32))
      throw ManagedError{SQLITE_AUTH};
    Query save(
        db, "INSERT INTO murmur_bridge_source_keys VALUES(?1,?2,?3,?4) ON "
            "CONFLICT(source,origin) DO UPDATE SET enabled=excluded.enabled");
    save.blob(1, source, 16);
    save.blob(2, origin, 16);
    save.blob(3, key, 32);
    save.number(4, enabled);
    save.done();
    tx.commit();
  });
}
int bridge_peer_import_low_proof(sqlite3 *db,
                                 const murmur_bridge_header_t *header,
                                 const void *data, size_t len) {
  if (!db || !header || sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    ManagedDecoder d(data, len);
    if (d.raw(4) != "MHP1")
      throw ManagedError{SQLITE_CORRUPT};
    auto record = d.blob();
    d.end();
    murmur_origin_envelope_t e{};
    std::string payload;
    unpack(record, e, payload);
    if (memcmp(e.database, header->database, 16) ||
        memcmp(e.schema, header->schema, 32) || e.sequence > INT64_MAX ||
        e.millis > INT64_MAX || !nonzero(e.transaction, 16))
      throw ManagedError{SQLITE_AUTH};
    auto digest = hash(record);
    Query seen(db, "SELECT digest FROM murmur_bridge_source_receipts WHERE "
                   "source=?1 AND origin=?2 AND sequence=?3");
    seen.blob(1, e.database, 16);
    seen.blob(2, e.origin, 16);
    seen.number(3, e.sequence);
    if (seen.row()) {
      if (seen.blob(0) != digest)
        throw ManagedError{SQLITE_AUTH};
      return;
    }
    Query key(db, "SELECT public_key,enabled FROM murmur_bridge_source_keys "
                  "WHERE source=?1 AND origin=?2");
    key.blob(1, e.database, 16);
    key.blob(2, e.origin, 16);
    if (!key.row())
      throw ManagedError{SQLITE_BUSY};
    if (!key.number(1))
      throw ManagedError{SQLITE_AUTH};
    auto pub = key.blob(0);
    if (pub.size() != 32)
      throw ManagedError{SQLITE_CORRUPT};
    managed_check(murmur_origin_verify(
        &e, e.database, e.origin, (const uint8_t *)pub.data(), payload.data(),
        payload.size(), MURMUR_BRIDGE_MAX_PAYLOAD));
    uint64_t progress = 0;
    Query old(db, "SELECT sequence FROM murmur_bridge_source_heads WHERE "
                  "source=?1 AND origin=?2");
    old.blob(1, e.database, 16);
    old.blob(2, e.origin, 16);
    if (old.row())
      progress = old.number(0);
    if (e.sequence != progress + 1)
      throw ManagedError{SQLITE_BUSY};
    ManagedDecoder packet(payload.data(), payload.size());
    if (packet.raw(4) != "MBL1")
      throw ManagedError{SQLITE_AUTH};
    auto rows = packet.blob();
    packet.end();
    bridge_rows_merge_low(db, e, rows, false);
    Query receipt(
        db, "INSERT INTO murmur_bridge_source_receipts VALUES(?1,?2,?3,?4)");
    receipt.blob(1, e.database, 16);
    receipt.blob(2, e.origin, 16);
    receipt.number(3, e.sequence);
    receipt.blob(4, digest);
    receipt.done();
    Query head(
        db, "INSERT INTO murmur_bridge_source_heads VALUES(?1,?2,?3) ON "
            "CONFLICT(source,origin) DO UPDATE SET sequence=excluded.sequence");
    head.blob(1, e.database, 16);
    head.blob(2, e.origin, 16);
    head.number(3, e.sequence);
    head.done();
  });
}

extern "C" int murmur_bridge_peer_replace_trust(sqlite3 *db,
 const murmur_bridge_trusted_key_t *keys,size_t count) {
 if(!db || (count && !keys) || count>1024) return SQLITE_MISUSE;
 return boundary([&]{
  Guard guard;
  auto r=runtime(db);
  if(!r || !sqlite3_get_autocommit(db)) throw ManagedError{SQLITE_MISUSE};
  Savepoint tx(db);
  Query disable(db,"UPDATE murmur_bridge_peer_keys SET enabled=0 WHERE origin<>?1");
  disable.blob(1,r->node.data(),16);disable.done();
  for(size_t i=0;i<count;i++){
   if(!nonzero(keys[i].origin,16)||!nonzero(keys[i].public_key,32))throw ManagedError{SQLITE_MISUSE};
   Query prior(db,"SELECT public_key FROM murmur_bridge_peer_keys WHERE origin=?1");
   prior.blob(1,keys[i].origin,16);
   if(prior.row()&&prior.blob(0)!=std::string((const char*)keys[i].public_key,32))throw ManagedError{SQLITE_AUTH};
   Query save(db,"INSERT INTO murmur_bridge_peer_keys VALUES(?1,?2,1) ON CONFLICT(origin) DO UPDATE SET enabled=1");
   save.blob(1,keys[i].origin,16);save.blob(2,keys[i].public_key,32);save.done();
  }
  tx.commit();
 });
}
extern "C" int murmur_bridge_source_replace_trust(sqlite3 *db,const uint8_t source[16],
 const murmur_bridge_trusted_key_t *keys,size_t count) {
 if(!db || !source || !nonzero(source,16) || (count && !keys) || count>1024)return SQLITE_MISUSE;
 return boundary([&]{
  Guard guard;
  if(!sqlite3_get_autocommit(db))throw ManagedError{SQLITE_MISUSE};
  Savepoint tx(db);
  Query disable(db,"UPDATE murmur_bridge_source_keys SET enabled=0 WHERE source=?1");
  disable.blob(1,source,16);disable.done();
  for(size_t i=0;i<count;i++){
   if(!nonzero(keys[i].origin,16)||!nonzero(keys[i].public_key,32))throw ManagedError{SQLITE_MISUSE};
   Query prior(db,"SELECT public_key FROM murmur_bridge_source_keys WHERE source=?1 AND origin=?2");
   prior.blob(1,source,16);prior.blob(2,keys[i].origin,16);
   if(prior.row()&&prior.blob(0)!=std::string((const char*)keys[i].public_key,32))throw ManagedError{SQLITE_AUTH};
   Query save(db,"INSERT INTO murmur_bridge_source_keys VALUES(?1,?2,?3,1) ON CONFLICT(source,origin) DO UPDATE SET enabled=1");
   save.blob(1,source,16);save.blob(2,keys[i].origin,16);save.blob(3,keys[i].public_key,32);save.done();
  }
  tx.commit();
 });
}
