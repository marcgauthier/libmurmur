#include "bridge_capture.h"
#include "../codec/aesgcm.h"
#include "../keyring/sha256.h"
#include "bridge_capture_internal.h"
#include "bridge_ownership.h"
#include "bridge_peer_internal.h"
#include "kv.h"
#include "managed_codec.h"
#include "open.h"
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstring>
#include <memory>

namespace {
constexpr const char *slot = "murmur.native.bridge.capture.v1";
struct Guard {
  Guard() { murmur_db_writer_lock(); }
  ~Guard() { murmur_db_writer_unlock(); }
};
struct Statement {
  sqlite3_stmt *p = nullptr;
  Statement(sqlite3 *db, const std::string &sql) {
    managed_check(sqlite3_prepare_v2(db, sql.c_str(), -1, &p, nullptr));
  }
  ~Statement() { sqlite3_finalize(p); }
  void blob(int n, const std::string &s) {
    managed_check(
        sqlite3_bind_blob64(p, n, s.data(), s.size(), SQLITE_TRANSIENT));
  }
  void text(int n, const std::string &s) {
    managed_check(sqlite3_bind_text64(p, n, s.data(), s.size(),
                                      SQLITE_TRANSIENT, SQLITE_UTF8));
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
      throw ManagedError{SQLITE_ERROR};
  }
};
std::string bytes(sqlite3_stmt *p, int n) {
  auto v = ManagedValue::column(p, n);
  if (v.type != MURMUR_BLOB)
    throw ManagedError{SQLITE_CORRUPT};
  return v.data;
}
std::string text(sqlite3_stmt *p, int n) {
  auto v = ManagedValue::column(p, n);
  if (v.type != MURMUR_TEXT)
    throw ManagedError{SQLITE_CORRUPT};
  return v.data;
}
void exec(sqlite3 *db, const std::string &s) {
  managed_check(sqlite3_exec(db, s.c_str(), nullptr, nullptr, nullptr));
}
std::string quote(const std::string &s) {
  char *p = sqlite3_mprintf("\"%w\"", s.c_str());
  if (!p)
    throw ManagedError{SQLITE_NOMEM};
  std::unique_ptr<char, decltype(&sqlite3_free)> free(p, sqlite3_free);
  return p;
}
std::string hex(const std::string &s) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (unsigned char b : s) {
    out += digits[b >> 4];
    out += digits[b & 15];
  }
  return out;
}
template <class F> int boundary(F f) {
  try {
    f();
    return SQLITE_OK;
  } catch (ManagedError e) {
    return e.code;
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_ERROR;
  }
}
struct Field {
  std::string name;
  int pk = 0;
};
struct Table {
  std::string id, name, declaration;
  std::vector<Field> fields;
  std::vector<size_t> keys;
};
struct Runtime {
  murmur_bridge_capture_options_t options{};
  std::vector<Table> tables;
  std::vector<std::string> triggers;
  uint8_t schema[32]{};
  bool active = false;
  bool schema_valid = false;
  sqlite3_int64 main_version = 0, temp_version = 0;
  unsigned paused = 0;
  ~Runtime() {
    volatile uint8_t *p = options.signer;
    for (size_t i = 0; i < 32; ++i)
      p[i] = 0;
  }
};
Runtime *runtime(sqlite3 *db) {
  return (Runtime *)sqlite3_get_clientdata(db, slot);
}
std::string baseline_scope(const Runtime &r, const std::string &digest,
                           bool table) {
  ManagedEncoder e;
  static const char domain[] = "murmur/native-bridge-baseline/v1";
  e.raw(domain, sizeof(domain) - 1);
  e.number(table ? 1 : 0);
  e.raw(r.options.database, 16);
  e.blob(r.options.stream);
  e.blob(digest);
  uint8_t out[32];
  murmur_sha256((const uint8_t *)e.bytes.data(), e.bytes.size(), out);
  return std::string((const char *)out, 32);
}

void pack(sqlite3_context *ctx, int n, sqlite3_value **args) {
  int rc = boundary([&] {
    std::vector<ManagedValue> values;
    ManagedEncoder budget;
    for (int i = 0; i < n; ++i) {
      auto v = ManagedValue::argument(args[i]);
      budget.blob(managed_encode_value(v));
      values.push_back(std::move(v));
    }
    auto body = managed_encode_values(values);
    if (body.size() > MURMUR_BRIDGE_MAX_PAYLOAD)
      throw ManagedError{SQLITE_TOOBIG};
    sqlite3_result_blob64(ctx, body.data(), body.size(), SQLITE_TRANSIENT);
  });
  if (rc != SQLITE_OK)
    sqlite3_result_error_code(ctx, rc);
}
void active(sqlite3_context *ctx, int, sqlite3_value **) {
  auto r = runtime(sqlite3_context_db_handle(ctx));
  sqlite3_result_int(ctx, r && r->active && !r->paused);
}
std::string tuple(const Table &t, const std::string &prefix, bool keys) {
  std::string out = "murmur_bridge_values(";
  bool first = true;
  if (keys)
    for (auto i : t.keys) {
      if (!first)
        out += ",";
      first = false;
      out += prefix + "." + quote(t.fields[i].name);
    }
  else
    for (auto &f : t.fields) {
      if (!first)
        out += ",";
      first = false;
      out += prefix + "." + quote(f.name);
    }
  return out + ")";
}
void drop_triggers(sqlite3 *db, Runtime &r) {
  for (auto &name : r.triggers)
    exec(db, "DROP TRIGGER IF EXISTS temp." + quote(name));
  r.triggers.clear();
}
void refresh(sqlite3 *db, Runtime &r) {
  auto schema_version = [&](const char *sql) {
    Statement st(db, sql);
    if (!st.row())
      throw ManagedError{SQLITE_CORRUPT};
    return sqlite3_column_int64(st.p, 0);
  };
  auto main_version = schema_version("PRAGMA main.schema_version"),
       temp_version = schema_version("PRAGMA temp.schema_version");
  if (r.schema_valid && r.main_version == main_version &&
      r.temp_version == temp_version)
    return;
  uint8_t schema[32];
  managed_check(murmur_bridge_rows_schema(db, schema));
  std::vector<Table> tables;
  Statement st(
      db, "SELECT id,name,definition FROM murmur_bridge_tables ORDER BY id");
  while (st.row()) {
    Table t;
    t.id = bytes(st.p, 0);
    t.name = text(st.p, 1);
    auto definition = bytes(st.p, 2);
    uint8_t declaration[32];
    murmur_sha256((const uint8_t *)definition.data(), definition.size(),
                  declaration);
    t.declaration = std::string((const char *)declaration, 32);
    if (t.id.size() != 16)
      throw ManagedError{SQLITE_CORRUPT};
    Statement columns(
        db, "SELECT name,pk FROM pragma_table_xinfo(?1) ORDER BY cid");
    columns.text(1, t.name);
    while (columns.row())
      t.fields.push_back(
          {text(columns.p, 0), sqlite3_column_int(columns.p, 1)});
    if (t.fields.size() >
        (size_t)sqlite3_limit(db, SQLITE_LIMIT_FUNCTION_ARG, -1))
      throw ManagedError{SQLITE_TOOBIG};
    for (size_t i = 0; i < t.fields.size(); ++i)
      if (t.fields[i].pk)
        t.keys.push_back(i);
    std::sort(t.keys.begin(), t.keys.end(), [&](size_t a, size_t b) {
      return t.fields[a].pk < t.fields[b].pk;
    });
    tables.push_back(std::move(t));
  }
  drop_triggers(db, r);
  r.tables = std::move(tables);
  for (auto &t : r.tables) {
    auto insert = [&](const char *prefix, bool before) {
      return "INSERT INTO murmur_bridge_dirty(table_id,row_key,before_row) "
             "VALUES(x'" +
             hex(t.id) + "'," + tuple(t, prefix, true) + "," +
             (before ? tuple(t, prefix, false) : "NULL") +
             ") ON CONFLICT(table_id,row_key) DO NOTHING;";
    };
    for (auto op : {"INSERT", "UPDATE", "DELETE"}) {
      auto name = "murmur_bridge_capture_" + hex(t.id) + "_" + op;
      std::string body;
      if (strcmp(op, "INSERT"))
        body += insert("OLD", true);
      if (strcmp(op, "DELETE"))
        body += insert("NEW", false);
      exec(db, "DROP TRIGGER IF EXISTS temp." + quote(name));
      exec(db, "CREATE TEMP TRIGGER " + quote(name) + " AFTER " + op +
                   " ON main." + quote(t.name) +
                   " WHEN murmur_bridge_capture_active() BEGIN " + body +
                   " END");
      r.triggers.push_back(name);
    }
  }
  memcpy(r.schema, schema, 32);
  r.main_version = schema_version("PRAGMA main.schema_version");
  r.temp_version = schema_version("PRAGMA temp.schema_version");
  r.schema_valid = true;
}
struct Dirty {
  const Table *table;
  std::string key;
  std::optional<std::vector<ManagedValue>> before, current;
};
std::vector<Dirty> dirty(sqlite3 *db, Runtime &r) {
  Statement st(db, "SELECT table_id,row_key,before_row FROM "
                   "main.murmur_bridge_dirty ORDER BY table_id,row_key");
  std::vector<Dirty> changes;
  ManagedEncoder budget;
  while (st.row()) {
    if (changes.size() >= 1024)
      throw ManagedError{SQLITE_TOOBIG};
    auto id = bytes(st.p, 0);
    auto it = std::find_if(r.tables.begin(), r.tables.end(),
                           [&](const Table &t) { return t.id == id; });
    if (it == r.tables.end())
      throw ManagedError{SQLITE_SCHEMA};
    Dirty d;
    d.table = &*it;
    d.key = bytes(st.p, 1);
    auto old = ManagedValue::column(st.p, 2);
    budget.blob(d.key);
    if (old.type == MURMUR_BLOB)
      budget.blob(old.data);
    if (old.type == MURMUR_BLOB)
      d.before = managed_decode_values(old.data);
    else if (old.type != MURMUR_NULL)
      throw ManagedError{SQLITE_CORRUPT};
    auto key = managed_decode_values(d.key);
    if (key.size() != it->keys.size())
      throw ManagedError{SQLITE_SCHEMA};
    std::string query = "SELECT ";
    for (size_t i = 0; i < it->fields.size(); ++i) {
      if (i)
        query += ",";
      query += quote(it->fields[i].name);
    }
    query += " FROM " + quote(it->name) + " WHERE ";
    for (size_t i = 0; i < it->keys.size(); ++i) {
      if (i)
        query += " AND ";
      query +=
          quote(it->fields[it->keys[i]].name) + " IS ?" + std::to_string(i + 1);
    }
    Statement row(db, query);
    for (size_t i = 0; i < key.size(); ++i)
      managed_check(key[i].bind(row.p, (int)i + 1));
    if (row.row()) {
      d.current.emplace();
      for (size_t i = 0; i < it->fields.size(); ++i) {
        auto value = ManagedValue::column(row.p, (int)i);
        budget.blob(managed_encode_value(value));
        d.current->push_back(std::move(value));
      }
      if (row.row())
        throw ManagedError{SQLITE_CORRUPT};
    }
    if (d.before && d.before->size() != it->fields.size())
      throw ManagedError{SQLITE_CORRUPT};
    if (!d.before && !d.current)
      continue;
    if (d.before && d.current &&
        managed_encode_values(*d.before) == managed_encode_values(*d.current))
      continue;
    changes.push_back(std::move(d));
  }
  return changes;
}
ManagedVersion next_version(sqlite3 *db, Runtime &r,
                            const std::vector<Dirty> &changes) {
  ManagedVersion latest;
  Statement clock(db,
                  "SELECT millis,logical FROM murmur_bridge_clock WHERE id=1");
  if (clock.row()) {
    auto millis = sqlite3_column_int64(clock.p, 0),
         logical = sqlite3_column_int64(clock.p, 1);
    if (millis < 0 || logical < 0 || logical > UINT32_MAX)
      throw ManagedError{SQLITE_CORRUPT};
    latest.millis = (uint64_t)millis;
    latest.logical = (uint32_t)logical;
  }
  auto observe = [&](const ManagedVersion &v) {
    if (v.compare(latest) > 0)
      latest = v;
  };
  for (auto &d : changes) {
    Statement st(db, "SELECT body FROM murmur_bridge_capture WHERE table_id=?1 "
                     "AND row_key=?2");
    st.blob(1, d.table->id);
    st.blob(2, d.key);
    if (st.row()) {
      auto row = managed_row_decode(bytes(st.p, 0));
      observe(row.generation);
      observe(row.tombstone);
      for (auto &c : row.columns)
        observe(c.second.version);
    }
    Statement owners(db, "SELECT body FROM murmur_bridge_owners WHERE "
                         "table_id=?1 AND row_key=?2");
    owners.blob(1, d.table->id);
    owners.blob(2, d.key);
    while (owners.row()) {
      auto o = bridge_owner_decode(bytes(owners.p, 0));
      observe(o.epoch);
      observe(o.release);
      if (o.cell)
        observe(o.cell->version);
    }
  }
  auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  ManagedVersion v;
  if (now > 0 && (uint64_t)now > latest.millis)
    v.millis = (uint64_t)now;
  else {
    v = latest;
    if (v.logical == UINT32_MAX) {
      if (v.millis == INT64_MAX)
        throw ManagedError{SQLITE_FULL};
      ++v.millis;
      v.logical = 0;
    } else
      ++v.logical;
  }
  std::copy(r.options.node, r.options.node + 16, v.origin.begin());
  if (v.millis > INT64_MAX)
    throw ManagedError{SQLITE_FULL};
  Statement save(db, "INSERT INTO murmur_bridge_clock(id,millis,logical) "
                     "VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET "
                     "millis=excluded.millis,logical=excluded.logical");
  managed_check(sqlite3_bind_int64(save.p, 1, (sqlite3_int64)v.millis));
  managed_check(sqlite3_bind_int64(save.p, 2, v.logical));
  save.done();
  return v;
}
std::vector<murmur_value_t> key(const Dirty &d,
                                std::vector<ManagedValue> &owned) {
  owned = managed_decode_values(d.key);
  std::vector<murmur_value_t> out;
  for (auto &v : owned) {
    murmur_value_t c{};
    c.type = v.type;
    c.integer = v.integer;
    c.real = v.real;
    c.data = v.data.data();
    c.bytes = v.data.size();
    out.push_back(c);
  }
  return out;
}
struct Record {
  murmur_bridge_bytes_t b{};
  ~Record() { murmur_bridge_bytes_free(&b); }
};
void enqueue(sqlite3 *db, Runtime &r, const void *payload, size_t len) {
  murmur_bridge_header_t h{};
  memcpy(h.database, r.options.database, 16);
  memcpy(h.node, r.options.node, 16);
  memcpy(h.stream, r.options.stream, 65);
  memcpy(h.schema, r.schema, 32);
  if (murmur_rand_bytes(h.transaction, 16))
    throw ManagedError{SQLITE_ERROR};
  managed_check(murmur_bridge_store_queue(
      db, &h, r.options.signer, r.options.recipient, payload, len,
      MURMUR_BRIDGE_MAX_BUNDLE, MURMUR_BRIDGE_MAX_PAYLOAD,
      r.options.staging_bytes));
}
void finish(sqlite3 *db, Runtime &r) {
  auto changes = dirty(db, r);
  if (changes.empty())
    return;
  auto v = next_version(db, r, changes);
  murmur_bridge_version_t stamp{};
  stamp.millis = v.millis;
  stamp.logical = v.logical;
  std::copy(v.origin.begin(), v.origin.end(), stamp.origin);
  std::vector<std::unique_ptr<Record>> records;
  for (auto &d : changes) {
    std::vector<ManagedValue> owned;
    auto keys = key(d, owned);
    if (r.options.role == MURMUR_BRIDGE_LOW) {
      auto rec = std::make_unique<Record>();
      managed_check(murmur_bridge_rows_capture(
          db, (const uint8_t *)d.table->id.data(), keys.data(), keys.size(),
          !d.current, &stamp, &rec->b));
      records.push_back(std::move(rec));
    } else if (!d.current)
      managed_check(
          murmur_bridge_rows_claim(db, (const uint8_t *)d.table->id.data(),
                                   keys.data(), keys.size(), nullptr, &stamp));
    else {
      // A new High insertion revokes its previous row-delete claim without
      // projecting Low values over the just-inserted High values.
      Statement old(db, "SELECT body FROM murmur_bridge_owners WHERE "
                        "table_id=?1 AND row_key=?2 AND column_id=x''");
      old.blob(1, d.table->id);
      old.blob(2, d.key);
      if (old.row()) {
        auto prior = bridge_owner_decode(bytes(old.p, 0));
        if (prior.owned) {
          auto released = bridge_owner_release(prior, v);
          Statement save(db, "UPDATE murmur_bridge_owners SET body=?3 WHERE "
                             "table_id=?1 AND row_key=?2 AND column_id=x''");
          save.blob(1, d.table->id);
          save.blob(2, d.key);
          save.blob(3, bridge_owner_encode(released));
          save.done();
          bridge_peer_owner_changed(db, released);
        }
      }
      for (size_t i = 0; i < d.table->fields.size(); ++i)
        if (!d.table->fields[i].pk &&
            (!d.before || managed_encode_value((*d.before)[i]) !=
                              managed_encode_value((*d.current)[i])))
          managed_check(murmur_bridge_rows_claim(
              db, (const uint8_t *)d.table->id.data(), keys.data(), keys.size(),
              d.table->fields[i].name.c_str(), &stamp));
    }
  }
  if (!records.empty()) {
    std::vector<murmur_bridge_bytes_t> borrowed;
    for (auto &p : records)
      borrowed.push_back(p->b);
    Record payload;
    managed_check(
        murmur_bridge_rows_pack(borrowed.data(), borrowed.size(), &payload.b));
    std::string proof;
    if (bridge_peer_low_changed(db, payload.b.data, payload.b.len, v, &proof)) {
      if (!proof.empty())
        enqueue(db, r, proof.data(), proof.size());
    } else
      enqueue(db, r, payload.b.data, payload.b.len);
    for (auto &d : changes) {
      Statement mark(
          db, "INSERT INTO murmur_bridge_baseline_rows(scope,table_id,row_key) "
              "VALUES(?1,?2,?3) ON CONFLICT DO NOTHING");
      mark.blob(1, baseline_scope(r, d.table->declaration, true));
      mark.blob(2, d.table->id);
      mark.blob(3, d.key);
      mark.done();
    }
  }
}
} // namespace
int bridge_capture_enqueue(sqlite3 *db, const void *payload, size_t len) {
  if (!db || sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r || r->options.role != MURMUR_BRIDGE_LOW)
      throw ManagedError{SQLITE_MISUSE};
    refresh(db, *r);
    enqueue(db, *r, payload, len);
  });
}
ManagedVersion bridge_capture_clock(sqlite3 *db) {
  auto r = runtime(db);
  if (!r || sqlite3_get_autocommit(db))
    throw ManagedError{SQLITE_MISUSE};
  return next_version(db, *r, {});
}
bool bridge_capture_low(sqlite3 *db, const uint8_t database[16],
                        const uint8_t node[16]) {
  auto r = runtime(db);
  return r && r->options.role == MURMUR_BRIDGE_LOW &&
         !memcmp(r->options.database, database, 16) &&
         !memcmp(r->options.node, node, 16);
}
void bridge_capture_forward_mark(sqlite3 *db, const std::string &table,
                                 const std::string &key) {
  auto r = runtime(db);
  if (!r || r->options.role != MURMUR_BRIDGE_LOW)
    throw ManagedError{SQLITE_MISUSE};
  refresh(db, *r);
  auto t = std::find_if(r->tables.begin(), r->tables.end(),
                        [&](const Table &t) { return t.id == table; });
  if (t == r->tables.end())
    throw ManagedError{SQLITE_SCHEMA};
  Statement mark(
      db, "INSERT INTO murmur_bridge_baseline_rows(scope,table_id,row_key) "
          "VALUES(?1,?2,?3) ON CONFLICT DO NOTHING");
  mark.blob(1, baseline_scope(*r, t->declaration, true));
  mark.blob(2, table);
  mark.blob(3, key);
  mark.done();
}
bool bridge_capture_high(sqlite3 *db, const uint8_t database[16],
                         const uint8_t node[16]) {
  auto r = runtime(db);
  return r && r->options.role == MURMUR_BRIDGE_HIGH &&
         !memcmp(r->options.database, database, 16) &&
         !memcmp(r->options.node, node, 16);
}
void bridge_capture_pause(sqlite3 *db, bool pause) {
  auto r = runtime(db);
  if (!r)
    return;
  if (pause)
    ++r->paused;
  else if (r->paused)
    --r->paused;
}
void bridge_capture_invalidate(sqlite3 *db) {
  auto r = runtime(db);
  if (r)
    r->schema_valid = false;
}
bool bridge_capture_accepts(sqlite3 *db, const uint8_t source[16]) {
  auto r = runtime(db);
  return !r || (r->options.role == MURMUR_BRIDGE_HIGH &&
                memcmp(source, r->options.database, 16));
}
bool bridge_capture_exports(sqlite3 *db, const uint8_t source[16],
                            const char *stream) {
  auto r = runtime(db);
  return r && r->options.role == MURMUR_BRIDGE_LOW &&
         !memcmp(source, r->options.database, 16) &&
         !strcmp(stream, r->options.stream);
}
extern "C" int
murmur_bridge_capture_attach(sqlite3 *db,
                             const murmur_bridge_capture_options_t *options) {
  if (!db || !options || !sqlite3_get_autocommit(db) || runtime(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = std::make_unique<Runtime>();
    r->options = *options;
    if ((options->role != MURMUR_BRIDGE_LOW &&
         options->role != MURMUR_BRIDGE_HIGH) ||
        !options->staging_bytes || options->staging_bytes > (1u << 30))
      throw ManagedError{SQLITE_MISUSE};
    uint8_t dbid = 0, node = 0;
    for (int i = 0; i < 16; ++i) {
      dbid |= options->database[i];
      node |= options->node[i];
    }
    if (!dbid || !node)
      throw ManagedError{SQLITE_MISUSE};
    size_t n = 0;
    for (; n < 65 && options->stream[n]; ++n) {
      char c = options->stream[n];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-'))
        throw ManagedError{SQLITE_MISUSE};
    }
    if (!n || n > 64)
      throw ManagedError{SQLITE_MISUSE};
    if (options->role == MURMUR_BRIDGE_HIGH) {
      std::string origin((const char *)options->node, 16), local(16, '\0');
      Statement existing(
          db,
          "SELECT source FROM murmur_bridge_origin_domains WHERE origin=?1");
      existing.blob(1, origin);
      if (existing.row()) {
        if (bytes(existing.p, 0) != local)
          throw ManagedError{SQLITE_AUTH};
      } else {
        Statement reserve(
            db, "INSERT INTO murmur_bridge_origin_domains(origin,source) "
                "VALUES(?1,?2)");
        reserve.blob(1, origin);
        reserve.blob(2, local);
        reserve.done();
      }
    }
    managed_check(murmur_bridge_store_init(db));
    exec(db,
         "CREATE TABLE IF NOT EXISTS murmur_bridge_clock(id INTEGER PRIMARY "
         "KEY CHECK(id=1),millis INTEGER NOT NULL,logical INTEGER NOT NULL)");
    exec(db, "CREATE TABLE IF NOT EXISTS murmur_bridge_dirty(table_id "
             "BLOB NOT NULL,row_key BLOB NOT NULL,before_row BLOB,PRIMARY "
             "KEY(table_id,row_key))");
    exec(db, "CREATE TABLE IF NOT EXISTS murmur_bridge_baseline(schema BLOB "
             "PRIMARY KEY NOT NULL)");
    exec(db, "CREATE TABLE IF NOT EXISTS murmur_bridge_baseline_rows(scope "
             "BLOB NOT NULL,table_id BLOB NOT NULL,row_key BLOB NOT "
             "NULL,PRIMARY KEY(scope,table_id,row_key))");
    managed_check(sqlite3_create_function_v2(
        db, "murmur_bridge_values", -1,
        SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS, nullptr, pack,
        nullptr, nullptr, nullptr));
    managed_check(sqlite3_create_function_v2(
        db, "murmur_bridge_capture_active", 0, SQLITE_UTF8 | SQLITE_INNOCUOUS,
        nullptr, active, nullptr, nullptr, nullptr));
    refresh(db, *r);
    auto owned = r.release();
    managed_check(sqlite3_set_clientdata(db, slot, owned,
                                         [](void *p) { delete (Runtime *)p; }));
  });
}
extern "C" int murmur_bridge_capture_detach(sqlite3 *db) {
  if (!db || !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r)
      return;
    if (r->active)
      throw ManagedError{SQLITE_MISUSE};
    bridge_peer_detach(db);
    drop_triggers(db, *r);
    exec(db, "DELETE FROM main.murmur_bridge_dirty");
    managed_check(sqlite3_set_clientdata(db, slot, nullptr, nullptr));
  });
}
extern "C" int murmur_bridge_capture_attached(sqlite3 *db) {
  if (!db)
    return 0;
  Guard guard;
  return runtime(db) != nullptr;
}
extern "C" int murmur_bridge_capture_begin(sqlite3 *db) {
  if (!db || !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r || r->active)
      throw ManagedError{SQLITE_MISUSE};
    refresh(db, *r);
    exec(db, "BEGIN IMMEDIATE");
    try {
      exec(db, "DELETE FROM main.murmur_bridge_dirty");
      bridge_peer_begin(db);
      r->active = true;
    } catch (...) {
      sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
      throw;
    }
  });
}
extern "C" int murmur_bridge_capture_rollback(sqlite3 *db) {
  if (!db)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r)
      throw ManagedError{SQLITE_MISUSE};
    r->active = false;
    if (!sqlite3_get_autocommit(db))
      exec(db, "ROLLBACK");
  });
}
extern "C" int murmur_bridge_capture_commit(sqlite3 *db) {
  if (!db)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r || !r->active)
      throw ManagedError{SQLITE_MISUSE};
    r->active = false;
    try {
      if (sqlite3_get_autocommit(db))
        throw ManagedError{SQLITE_ABORT};
      if (!r->schema_valid)
        throw ManagedError{SQLITE_SCHEMA};
      finish(db, *r);
      bridge_peer_commit(db);
      exec(db, "DELETE FROM main.murmur_bridge_dirty");
      exec(db, "COMMIT");
    } catch (...) {
      if (!sqlite3_get_autocommit(db))
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
      throw;
    }
    const char *path = sqlite3_db_filename(db, "main");
    if (path && *path && nvFlushDb(path))
      throw ManagedError{SQLITE_IOERR_FSYNC};
  });
}
extern "C" int murmur_bridge_write(sqlite3 *db, murmur_bridge_write_fn fn,
                                   void *arg) {
  if (!db || !fn)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    managed_check(murmur_bridge_capture_begin(db));
    try {
      managed_check(fn(db, arg));
    } catch (...) {
      murmur_bridge_capture_rollback(db);
      throw;
    }
    managed_check(murmur_bridge_capture_commit(db));
  });
}

namespace {
struct ReleaseCall {
  const char *table;
  const murmur_value_t *key;
  size_t count;
  const char *column;
};
int release_claim(sqlite3 *db, void *arg) {
  return boundary([&] {
    auto &call = *static_cast<ReleaseCall *>(arg);
    auto r = runtime(db);
    if (!r || r->options.role != MURMUR_BRIDGE_HIGH)
      throw ManagedError{SQLITE_MISUSE};
    auto table =
        std::find_if(r->tables.begin(), r->tables.end(),
                     [&](const Table &t) { return t.name == call.table; });
    if (table == r->tables.end())
      throw ManagedError{SQLITE_SCHEMA};
    std::vector<ManagedValue> keys;
    size_t bytes = 0;
    for (size_t i = 0; i < call.count; ++i) {
      if (call.key[i].bytes > MURMUR_BRIDGE_MAX_PAYLOAD - bytes)
        throw ManagedError{SQLITE_TOOBIG};
      bytes += call.key[i].bytes;
      keys.push_back(ManagedValue::from(call.key[i]));
    }
    Dirty d;
    d.table = &*table;
    d.key = managed_encode_values(keys);
    auto v = next_version(db, *r, {d});
    murmur_bridge_version_t stamp{};
    stamp.millis = v.millis;
    stamp.logical = v.logical;
    std::copy(v.origin.begin(), v.origin.end(), stamp.origin);
    managed_check(
        murmur_bridge_rows_release(db, (const uint8_t *)table->id.data(),
                                   call.key, call.count, call.column, &stamp));
  });
}
} // namespace
extern "C" int murmur_bridge_capture_release(sqlite3 *db, const char *table,
                                             const murmur_value_t *key,
                                             size_t count, const char *column) {
  if (!db || !table || !*table || !key || !count || count > 32766 ||
      (column && !*column))
    return SQLITE_MISUSE;
  ReleaseCall call{table, key, count, column};
  return murmur_bridge_write(db, release_claim, &call);
}

extern "C" int murmur_bridge_capture_release_encoded(sqlite3 *db,
                                                     const char *table,
                                                     const void *data,
                                                     size_t len,
                                                     const char *column) {
  if (!db || !data || !len || len > MURMUR_BRIDGE_MAX_PAYLOAD)
    return SQLITE_MISUSE;
  int result = SQLITE_OK;
  int rc = boundary([&] {
    auto bytes = std::string((const char *)data, len);
    auto keys = managed_decode_values(bytes);
    if (keys.empty() || keys.size() > 32766 ||
        managed_encode_values(keys) != bytes)
      throw ManagedError{SQLITE_CORRUPT};
    std::vector<murmur_value_t> raw;
    for (auto &value : keys) {
      murmur_value_t v{};
      v.type = value.type;
      v.integer = value.integer;
      v.real = value.real;
      v.data = value.data.data();
      v.bytes = value.data.size();
      raw.push_back(v);
    }
    result = murmur_bridge_capture_release(db, table, raw.data(), raw.size(),
                                           column);
  });
  return rc == SQLITE_OK ? result : rc;
}

namespace {
struct BaselineBatch {
  Runtime *runtime;
  size_t limit, count = 0;
};
int prepare_batch(sqlite3 *db, void *arg) {
  return boundary([&] {
    auto &b = *(BaselineBatch *)arg;
    for (auto &t : b.runtime->tables) {
      if (b.count >= b.limit)
        break;
      auto row_key = tuple(t, "b", true);
      Statement st(
          db, "INSERT INTO murmur_bridge_dirty(table_id,row_key,before_row) "
              "SELECT ?1," +
                  row_key + ",NULL FROM " + quote(t.name) +
                  " AS b WHERE NOT EXISTS (SELECT 1 FROM "
                  "murmur_bridge_baseline_rows "
                  "c WHERE c.table_id=?1 AND c.row_key=" +
                  row_key + " AND c.scope=?2) LIMIT ?3");
      st.blob(1, t.id);
      st.blob(2, baseline_scope(*b.runtime, t.declaration, true));
      managed_check(
          sqlite3_bind_int64(st.p, 3, (sqlite3_int64)(b.limit - b.count)));
      st.done();
      b.count += (size_t)sqlite3_changes(db);
    }
    if (!b.count) {
      Statement done(db, "INSERT INTO murmur_bridge_baseline(schema) "
                         "VALUES(?1) ON CONFLICT DO NOTHING");
      done.blob(1,
                baseline_scope(*b.runtime,
                               std::string((const char *)b.runtime->schema, 32),
                               false));
      done.done();
    }
  });
}
} // namespace
extern "C" int murmur_bridge_capture_prepare(sqlite3 *db, size_t limit,
                                             size_t *captured) {
  if (!captured)
    return SQLITE_MISUSE;
  *captured = 0;
  if (!db || !limit || limit > 1024 || !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  bool complete = false;
  int rc = boundary([&] {
    Guard guard;
    auto r = runtime(db);
    if (!r || r->active || r->options.role != MURMUR_BRIDGE_LOW)
      throw ManagedError{SQLITE_MISUSE};
    refresh(db, *r);
    Statement done(db, "SELECT 1 FROM murmur_bridge_baseline WHERE schema=?1");
    done.blob(
        1, baseline_scope(*r, std::string((const char *)r->schema, 32), false));
    if (done.row()) {
      const char *path = sqlite3_db_filename(db, "main");
      if (path && *path && nvFlushDb(path))
        throw ManagedError{SQLITE_IOERR_FSYNC};
      complete = true;
      return;
    }
    BaselineBatch batch{r, limit};
    managed_check(murmur_bridge_write(db, prepare_batch, &batch));
    *captured = batch.count;
    complete = !batch.count;
  });
  return rc == SQLITE_OK && complete ? SQLITE_NOTFOUND : rc;
}
