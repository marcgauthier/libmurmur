#include "bridge_rows.h"
#include "../codec/aesgcm.h"
#include "../keyring/sha256.h"
#include "bridge_capture_internal.h"
#include "bridge_ownership.h"
#include "bridge_peer_internal.h"
#include "bridge_peer_source_internal.h"
#include "kv.h"
#include "managed_codec.h"
#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>
#include <set>

namespace {
struct Guard {
  Guard() { murmur_db_writer_lock(); }
  ~Guard() { murmur_db_writer_unlock(); }
};
struct OwnedBytes {
  murmur_bridge_bytes_t b{};
  ~OwnedBytes() { murmur_bridge_bytes_free(&b); }
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
std::string column(sqlite3_stmt *p, int at, murmur_value_type_t type) {
  auto v = ManagedValue::column(p, at);
  if (v.type != type)
    throw ManagedError{SQLITE_CORRUPT};
  return v.data;
}
void exec(sqlite3 *db, const std::string &sql) {
  managed_check(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr));
}
struct Savepoint {
  sqlite3 *db;
  bool active = true;
  explicit Savepoint(sqlite3 *d) : db(d) {
    exec(db, "SAVEPOINT murmur_bridge_rows");
  }
  ~Savepoint() {
    if (active)
      sqlite3_exec(db,
                   "ROLLBACK TO murmur_bridge_rows; RELEASE murmur_bridge_rows",
                   nullptr, nullptr, nullptr);
  }
  void commit() {
    exec(db, "RELEASE murmur_bridge_rows");
    active = false;
  }
};
template <class F> int boundary(F fn) {
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
std::string id(const void *p) {
  if (!p)
    throw ManagedError{SQLITE_MISUSE};
  return std::string((const char *)p, 16);
}
std::string named_id(const std::string &space, const std::string &name) {
  ManagedEncoder e;
  e.raw("murmur/native-bridge-id/v1", 26);
  e.blob(space);
  e.blob(name);
  uint8_t out[32];
  murmur_sha256((const uint8_t *)e.bytes.data(), e.bytes.size(), out);
  return std::string((const char *)out, 16);
}
std::string quote(const std::string &name) {
  char *p = sqlite3_mprintf("\"%w\"", name.c_str());
  if (!p)
    throw ManagedError{SQLITE_NOMEM};
  std::unique_ptr<char, decltype(&sqlite3_free)> free(p, sqlite3_free);
  return p;
}
void valid_name(const std::string &name) {
  if (name.empty() || name.size() > 1024 ||
      name.find('\0') != std::string::npos ||
      !murmur_utf8_valid((const uint8_t *)name.data(), name.size()))
    throw ManagedError{SQLITE_SCHEMA};
}
struct Field {
  std::string id, name, type, default_sql;
  int pk = 0, not_null = 0;
};
struct Table {
  std::string id, name, definition;
  std::vector<Field> fields;
  std::vector<size_t> keys;
};
Table inspect(sqlite3 *db, const std::string &name) {
  valid_name(name);
  std::string lower = name;
  for (auto &c : lower)
    if (c >= 'A' && c <= 'Z')
      c += (char)('a' - 'A');
  if (lower.rfind("sqlite_", 0) == 0 || lower.rfind("murmur_", 0) == 0 ||
      lower.rfind("crsql_", 0) == 0 ||
      lower.find("__crsql_") != std::string::npos)
    throw ManagedError{SQLITE_AUTH};
  Table t;
  t.name = name;
  t.id = named_id("table", name);
  Statement kind(
      db, "SELECT type FROM pragma_table_list WHERE schema='main' AND name=?1");
  kind.text(1, name);
  if (!kind.row() || column(kind.p, 0, MURMUR_TEXT) != "table")
    throw ManagedError{SQLITE_SCHEMA};
  Statement table(db, "SELECT type,sql FROM sqlite_schema WHERE name=?1");
  table.text(1, name);
  if (!table.row() || column(table.p, 0, MURMUR_TEXT) != "table")
    throw ManagedError{SQLITE_SCHEMA};
  auto sql = column(table.p, 1, MURMUR_TEXT);
  std::string upper = sql;
  for (auto &c : upper)
    if (c >= 'a' && c <= 'z')
      c -= (char)('a' - 'A');
  if (upper.find("CREATE VIRTUAL TABLE") != std::string::npos)
    throw ManagedError{SQLITE_SCHEMA};
  Statement st(db, "SELECT name,type,\"notnull\",dflt_value,pk,hidden FROM "
                   "pragma_table_xinfo(?1) ORDER BY cid");
  st.text(1, name);
  ManagedEncoder schema;
  schema.blob(t.id);
  schema.blob(name);
  while (st.row()) {
    if (sqlite3_column_int(st.p, 5))
      throw ManagedError{SQLITE_SCHEMA};
    Field f;
    f.name = column(st.p, 0, MURMUR_TEXT);
    valid_name(f.name);
    f.type = column(st.p, 1, MURMUR_TEXT);
    f.not_null = sqlite3_column_int(st.p, 2);
    f.pk = sqlite3_column_int(st.p, 4);
    auto def = ManagedValue::column(st.p, 3);
    if (def.type == MURMUR_TEXT)
      f.default_sql = def.data;
    f.id = named_id(t.id, f.name);
    schema.blob(f.id);
    schema.blob(f.name);
    schema.blob(f.type);
    schema.number(f.not_null);
    schema.number(f.pk);
    schema.blob(managed_encode_value(def));
    t.fields.push_back(std::move(f));
    if (t.fields.size() > 32766)
      throw ManagedError{SQLITE_TOOBIG};
  }
  for (size_t i = 0; i < t.fields.size(); ++i)
    if (t.fields[i].pk)
      t.keys.push_back(i);
  std::sort(t.keys.begin(), t.keys.end(), [&](size_t a, size_t b) {
    return t.fields[a].pk < t.fields[b].pk;
  });
  if (t.keys.empty())
    throw ManagedError{SQLITE_SCHEMA};
  t.definition = schema.bytes;
  return t;
}
void init(sqlite3 *db) {
  exec(db, "CREATE TABLE IF NOT EXISTS murmur_bridge_tables(id BLOB PRIMARY "
           "KEY NOT NULL,name TEXT UNIQUE NOT NULL,definition BLOB NOT NULL);"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_capture(table_id BLOB NOT "
           "NULL,row_key BLOB NOT NULL,body BLOB NOT NULL,PRIMARY "
           "KEY(table_id,row_key));"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_shadows(source BLOB NOT "
           "NULL,table_id BLOB NOT NULL,row_key BLOB NOT NULL,body BLOB NOT "
           "NULL,PRIMARY KEY(source,table_id,row_key));"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_owners(table_id BLOB NOT "
           "NULL,row_key BLOB NOT NULL,column_id BLOB NOT NULL,body BLOB NOT "
           "NULL,PRIMARY KEY(table_id,row_key,column_id));"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_origin_domains(origin "
           "BLOB PRIMARY KEY NOT NULL,source BLOB NOT NULL);"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_source_keys(source BLOB "
           "NOT NULL,origin BLOB NOT NULL,public_key BLOB NOT NULL,enabled "
           "INTEGER NOT NULL,PRIMARY KEY(source,origin));"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_source_heads(source BLOB "
           "NOT NULL,origin BLOB NOT NULL,sequence INTEGER NOT NULL,PRIMARY "
           "KEY(source,origin));"
           "CREATE TABLE IF NOT EXISTS murmur_bridge_source_receipts(source "
           "BLOB NOT NULL,origin BLOB NOT NULL,sequence INTEGER NOT "
           "NULL,digest BLOB NOT NULL,PRIMARY KEY(source,origin,sequence));");
}
Table registered(sqlite3 *db, const std::string &tid) {
  Statement st(db,
               "SELECT name,definition FROM murmur_bridge_tables WHERE id=?1");
  st.blob(1, tid);
  if (!st.row())
    throw ManagedError{SQLITE_SCHEMA};
  auto t = inspect(db, column(st.p, 0, MURMUR_TEXT));
  if (t.id != tid || t.definition != column(st.p, 1, MURMUR_BLOB))
    throw ManagedError{SQLITE_SCHEMA};
  return t;
}
std::vector<ManagedValue> key_values(const Table &t,
                                     const murmur_value_t *values, size_t n) {
  if (n != t.keys.size() || (!values && n))
    throw ManagedError{SQLITE_MISMATCH};
  std::vector<ManagedValue> key;
  ManagedEncoder budget;
  for (size_t i = 0; i < n; ++i) {
    auto v = ManagedValue::from(values[i]);
    if (v.type == MURMUR_NULL)
      throw ManagedError{SQLITE_CONSTRAINT};
    budget.blob(managed_encode_value(v));
    key.push_back(std::move(v));
  }
  return key;
}
void bind_key(Statement &s, int first, const std::vector<ManagedValue> &key) {
  for (size_t i = 0; i < key.size(); ++i)
    managed_check(key[i].bind(s.p, first + (int)i));
}
std::string predicate(const Table &t) {
  std::string s;
  for (size_t i = 0; i < t.keys.size(); ++i) {
    if (i)
      s += " AND ";
    s += quote(t.fields[t.keys[i]].name) + " IS ?" + std::to_string(i + 1);
  }
  return s;
}
std::optional<std::map<std::string, ManagedValue>>
read(sqlite3 *db, const Table &t, const std::vector<ManagedValue> &key) {
  std::string sql = "SELECT ";
  for (size_t i = 0; i < t.fields.size(); ++i) {
    if (i)
      sql += ",";
    sql += quote(t.fields[i].name);
  }
  sql += " FROM " + quote(t.name) + " WHERE " + predicate(t);
  Statement st(db, sql);
  bind_key(st, 1, key);
  if (!st.row())
    return std::nullopt;
  std::map<std::string, ManagedValue> out;
  ManagedEncoder budget;
  for (size_t i = 0; i < t.fields.size(); ++i) {
    auto value = ManagedValue::column(st.p, (int)i);
    budget.blob(managed_encode_value(value));
    out[t.fields[i].id] = std::move(value);
  }
  std::vector<ManagedValue> actual;
  for (auto i : t.keys)
    actual.push_back(out.at(t.fields[i].id));
  if (managed_encode_values(actual) != managed_encode_values(key))
    throw ManagedError{SQLITE_MISMATCH};
  if (st.row())
    throw ManagedError{SQLITE_CORRUPT};
  return out;
}
ManagedVersion version(const murmur_bridge_version_t *v) {
  if (!v)
    throw ManagedError{SQLITE_MISUSE};
  ManagedVersion out;
  out.millis = v->millis;
  out.logical = v->logical;
  std::copy(v->origin, v->origin + 16, out.origin.begin());
  if ((!out.millis && !out.logical) || out.millis > INT64_MAX ||
      out.origin == std::array<uint8_t, 16>{})
    throw ManagedError{SQLITE_MISUSE};
  return out;
}
void output(const std::string &bytes, murmur_bridge_bytes_t *out) {
  auto p = (uint8_t *)malloc(bytes.empty() ? 1 : bytes.size());
  if (!p)
    throw ManagedError{SQLITE_NOMEM};
  memcpy(p, bytes.data(), bytes.size());
  out->data = p;
  out->len = bytes.size();
}
std::optional<BridgeOwner> owner(sqlite3 *db, const std::string &tid,
                                 const std::string &key,
                                 const std::string &cid) {
  Statement st(db, "SELECT body FROM murmur_bridge_owners WHERE table_id=?1 "
                   "AND row_key=?2 AND column_id=?3");
  st.blob(1, tid);
  st.blob(2, key);
  st.blob(3, cid);
  if (!st.row())
    return std::nullopt;
  auto o = bridge_owner_decode(column(st.p, 0, MURMUR_BLOB));
  if (o.table != tid || o.key != key || o.column != cid)
    throw ManagedError{SQLITE_CORRUPT};
  return o;
}
void save_owner(sqlite3 *db, const BridgeOwner &o) {
  Statement st(
      db, "INSERT INTO murmur_bridge_owners(table_id,row_key,column_id,body) "
          "VALUES(?1,?2,?3,?4) ON CONFLICT(table_id,row_key,column_id) DO "
          "UPDATE SET body=excluded.body");
  st.blob(1, o.table);
  st.blob(2, o.key);
  st.blob(3, o.column);
  st.blob(4, bridge_owner_encode(o));
  st.done();
  bridge_peer_owner_changed(db, o);
}
void project(sqlite3 *db, const Table &t, const std::string &key) {
  BridgeCapturePause pause(db);
  auto keys = managed_decode_values(key);
  if (keys.size() != t.keys.size())
    throw ManagedError{SQLITE_SCHEMA};
  auto row_owner = owner(db, t.id, key, "");
  Statement shadows(db, "SELECT body FROM murmur_bridge_shadows WHERE "
                        "table_id=?1 AND row_key=?2 ORDER BY source");
  shadows.blob(1, t.id);
  shadows.blob(2, key);
  std::optional<ManagedRow> low;
  while (shadows.row()) {
    auto r = managed_row_decode(column(shadows.p, 0, MURMUR_BLOB));
    if (r.table != t.id || r.key != key)
      throw ManagedError{SQLITE_CORRUPT};
    low = low ? managed_row_join(*low, r) : r;
  }
  std::map<std::string, BridgeOwner> owned;
  for (auto &f : t.fields)
    if (!f.pk) {
      auto o = owner(db, t.id, key, f.id);
      if (o && o->owned)
        owned.emplace(f.id, *o);
    }
  if ((row_owner && row_owner->owned) ||
      (low && !low->alive() && owned.empty())) {
    Statement del(db,
                  "DELETE FROM " + quote(t.name) + " WHERE " + predicate(t));
    bind_key(del, 1, keys);
    del.done();
    return;
  }
  if (!low && owned.empty())
    return; /* A released local-only row does not invent Low data. */
  auto prior = read(db, t, keys);
  if (low && !low->alive() && owned.size() && prior) {
    /* A Low delete cannot erase High-owned fields. Preserve the existing row
     * until the final field claim is released, then project its tombstone. */
    return;
  }
  std::map<std::string, ManagedValue> values;
  for (size_t i = 0; i < t.keys.size(); ++i)
    values[t.fields[t.keys[i]].id] = keys[i];
  for (auto &f : t.fields)
    if (!f.pk) {
      auto high = owned.find(f.id);
      if (high != owned.end())
        values[f.id] = high->second.cell->value;
      else if (low && low->columns.count(f.id))
        values[f.id] = managed_row_project(low->columns.at(f.id));
      else if (prior)
        values[f.id] = prior->at(f.id);
    }
  std::string names, binds, updates;
  int count = 0;
  for (auto &f : t.fields)
    if (values.count(f.id)) {
      if (count) {
        names += ",";
        binds += ",";
      }
      names += quote(f.name);
      binds += "?" + std::to_string(++count);
      if (!f.pk) {
        if (!updates.empty())
          updates += ",";
        updates += quote(f.name) + "=excluded." + quote(f.name);
      }
    }
  std::string conflict;
  for (auto i : t.keys) {
    if (!conflict.empty())
      conflict += ",";
    conflict += quote(t.fields[i].name);
  }
  Statement upsert(
      db, "INSERT INTO " + quote(t.name) + "(" + names + ") VALUES(" + binds +
              ") ON CONFLICT(" + conflict + ") " +
              (updates.empty() ? "DO NOTHING" : "DO UPDATE SET " + updates));
  count = 0;
  for (auto &f : t.fields) {
    auto v = values.find(f.id);
    if (v != values.end())
      managed_check(v->second.bind(upsert.p, ++count));
  }
  upsert.done();
}
std::vector<ManagedRow> unpack(const void *data, size_t n) {
  ManagedDecoder d(data, n);
  if (d.raw(4) != "MBT1")
    throw ManagedError{SQLITE_CORRUPT};
  std::vector<ManagedRow> rows;
  std::set<std::pair<std::string, std::string>> seen;
  for (size_t count = d.count(1024); count; --count) {
    auto row = managed_row_decode(d.blob());
    if (!seen.emplace(row.table, row.key).second)
      throw ManagedError{SQLITE_CORRUPT};
    rows.push_back(std::move(row));
  }
  d.end();
  return rows;
}
void bind_origin(sqlite3 *db, const std::string &source,
                 const ManagedVersion &v) {
  if (v.empty())
    return;
  auto origin = id(v.origin.data());
  Statement old(
      db, "SELECT source FROM murmur_bridge_origin_domains WHERE origin=?1");
  old.blob(1, origin);
  if (old.row()) {
    if (column(old.p, 0, MURMUR_BLOB) != source)
      throw ManagedError{SQLITE_AUTH};
    return;
  }
  Statement add(
      db,
      "INSERT INTO murmur_bridge_origin_domains(origin,source) VALUES(?1,?2)");
  add.blob(1, origin);
  add.blob(2, source);
  add.done();
}
int import_rows(sqlite3 *db, const murmur_bridge_header_t *h, const void *p,
                size_t n, void *) {
  return boundary([&] {
    uint8_t digest[32];
    managed_check(murmur_bridge_rows_schema(db, digest));
    if (memcmp(digest, h->schema, 32))
      throw ManagedError{SQLITE_SCHEMA};
    auto rows = unpack(p, n);
    auto source = id(h->database);
    for (auto &r : rows) {
      auto t = registered(db, r.table);
      auto keys = managed_decode_values(r.key);
      if (keys.size() != t.keys.size())
        throw ManagedError{SQLITE_SCHEMA};
      if (r.alive() && r.columns.size() != t.fields.size() - t.keys.size())
        throw ManagedError{SQLITE_SCHEMA};
      for (auto &cell : r.columns) {
        auto field =
            std::find_if(t.fields.begin(), t.fields.end(), [&](const Field &f) {
              return f.id == cell.first && !f.pk;
            });
        if (field == t.fields.end())
          throw ManagedError{SQLITE_SCHEMA};
        if (cell.second.policy != MURMUR_POLICY_LWW)
          throw ManagedError{SQLITE_MISMATCH};
        bind_origin(db, source, cell.second.version);
      }
      bind_origin(db, source, r.generation);
      bind_origin(db, source, r.tombstone);
      Statement old(db, "SELECT body FROM murmur_bridge_shadows WHERE "
                        "source=?1 AND table_id=?2 AND row_key=?3");
      old.blob(1, source);
      old.blob(2, r.table);
      old.blob(3, r.key);
      if (old.row())
        r = managed_row_join(managed_row_decode(column(old.p, 0, MURMUR_BLOB)),
                             r);
      Statement save(
          db, "INSERT INTO murmur_bridge_shadows(source,table_id,row_key,body) "
              "VALUES(?1,?2,?3,?4) ON CONFLICT(source,table_id,row_key) DO "
              "UPDATE SET body=excluded.body");
      save.blob(1, source);
      save.blob(2, r.table);
      save.blob(3, r.key);
      save.blob(4, managed_row_encode(r));
      save.done();
      project(db, t, r.key);
    }
  });
}
} // namespace
extern "C" int murmur_bridge_rows_register(sqlite3 *db, const char *name,
                                           uint8_t tid[16]) {
  if (!db || !name || !tid)
    return SQLITE_MISUSE;
  memset(tid, 0, 16);
  return boundary([&] {
    Guard guard;
    Savepoint tx(db);
    init(db);
    auto t = inspect(db, name);
    Statement save(db, "INSERT INTO murmur_bridge_tables(id,name,definition) "
                       "VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET "
                       "name=excluded.name,definition=excluded.definition");
    save.blob(1, t.id);
    save.text(2, t.name);
    save.blob(3, t.definition);
    save.done();
    tx.commit();
    bridge_capture_invalidate(db);
    memcpy(tid, t.id.data(), 16);
  });
}
extern "C" int murmur_bridge_rows_schema(sqlite3 *db, uint8_t digest[32]) {
  if (!db || !digest)
    return SQLITE_MISUSE;
  memset(digest, 0, 32);
  return boundary([&] {
    Guard guard;
    ManagedEncoder e;
    e.raw("MBSC1", 5);
    Statement st(db, "SELECT id FROM murmur_bridge_tables ORDER BY id");
    while (st.row()) {
      auto t = registered(db, column(st.p, 0, MURMUR_BLOB));
      e.blob(t.definition);
    }
    murmur_sha256((const uint8_t *)e.bytes.data(), e.bytes.size(), digest);
  });
}
extern "C" int murmur_bridge_rows_capture(sqlite3 *db, const uint8_t tid[16],
                                          const murmur_value_t *key,
                                          size_t count, int deleted,
                                          const murmur_bridge_version_t *stamp,
                                          murmur_bridge_bytes_t *out) {
  if (!db || !out)
    return SQLITE_MISUSE;
  *out = {};
  if (sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    Savepoint tx(db);
    auto t = registered(db, id(tid));
    auto keys = key_values(t, key, count);
    auto encoded = managed_encode_values(keys);
    auto v = version(stamp);
    auto current = read(db, t, keys);
    if ((deleted && current) || (!deleted && !current))
      throw ManagedError{SQLITE_CONSTRAINT};
    std::optional<ManagedRow> prior;
    Statement old(db, "SELECT body FROM murmur_bridge_capture WHERE "
                      "table_id=?1 AND row_key=?2");
    old.blob(1, t.id);
    old.blob(2, encoded);
    if (old.row())
      prior = managed_row_decode(column(old.p, 0, MURMUR_BLOB));
    if (prior) {
      if (prior->table != t.id || prior->key != encoded)
        throw ManagedError{SQLITE_CORRUPT};
      if (v.compare(prior->generation) <= 0 ||
          (!prior->tombstone.empty() && v.compare(prior->tombstone) <= 0))
        throw ManagedError{SQLITE_CONSTRAINT};
      for (auto &c : prior->columns)
        if (v.compare(c.second.version) <= 0)
          throw ManagedError{SQLITE_CONSTRAINT};
    }
    ManagedRow row;
    if (prior)
      row = *prior;
    row.table = t.id;
    row.key = encoded;
    if (!prior || (!deleted && !prior->alive())) {
      row.columns.clear();
      uint8_t epoch[16];
      if (murmur_rand_bytes(epoch, sizeof(epoch)))
        throw ManagedError{SQLITE_ERROR};
      row.epoch = id(epoch);
      row.generation = v;
    }
    if (deleted)
      row.tombstone = v;
    else
      for (auto &f : t.fields)
        if (!f.pk) {
          auto &cell = row.columns[f.id];
          auto value = current->at(f.id);
          if (cell.version.empty() ||
              managed_encode_value(cell.value) != managed_encode_value(value)) {
            cell.value = value;
            cell.version = v;
          }
        }
    auto body = managed_row_encode(row);
    Statement save(db,
                   "INSERT INTO murmur_bridge_capture(table_id,row_key,body) "
                   "VALUES(?1,?2,?3) ON CONFLICT(table_id,row_key) DO UPDATE "
                   "SET body=excluded.body");
    save.blob(1, t.id);
    save.blob(2, encoded);
    save.blob(3, body);
    save.done();
    OwnedBytes bytes;
    output(body, &bytes.b);
    tx.commit();
    *out = bytes.b;
    bytes.b = {};
  });
}
extern "C" int murmur_bridge_rows_pack(const murmur_bridge_bytes_t *records,
                                       size_t n, murmur_bridge_bytes_t *out) {
  if (!out)
    return SQLITE_MISUSE;
  *out = {};
  if ((!records && n) || n > 1024)
    return SQLITE_MISUSE;
  return boundary([&] {
    ManagedEncoder e;
    e.raw("MBT1", 4);
    e.number(n);
    std::set<std::pair<std::string, std::string>> seen;
    for (size_t i = 0; i < n; ++i) {
      if (!records[i].data || records[i].len > MURMUR_BRIDGE_MAX_PAYLOAD)
        throw ManagedError{SQLITE_CORRUPT};
      std::string body((const char *)records[i].data, records[i].len);
      auto r = managed_row_decode(body);
      if (!seen.emplace(r.table, r.key).second)
        throw ManagedError{SQLITE_CONSTRAINT};
      e.blob(body);
    }
    output(e.bytes, out);
  });
}
void bridge_rows_merge_owner(sqlite3 *db, const BridgeOwner &incoming,
                             const uint8_t origin[16]) {
  auto t = registered(db, incoming.table);
  auto keys = managed_decode_values(incoming.key);
  if (keys.size() != t.keys.size())
    throw ManagedError{SQLITE_SCHEMA};
  std::vector<murmur_value_t> raw;
  for (auto &v : keys) {
    murmur_value_t c{};
    c.type = v.type;
    c.integer = v.integer;
    c.real = v.real;
    c.data = v.data.data();
    c.bytes = v.data.size();
    raw.push_back(c);
  }
  if (managed_encode_values(key_values(t, raw.data(), raw.size())) !=
      incoming.key)
    throw ManagedError{SQLITE_SCHEMA};
  if (!incoming.column.empty()) {
    auto field =
        std::find_if(t.fields.begin(), t.fields.end(), [&](const Field &f) {
          return !f.pk && f.id == incoming.column;
        });
    if (field == t.fields.end())
      throw ManagedError{SQLITE_SCHEMA};
  }
  auto previous = owner(db, incoming.table, incoming.key, incoming.column);
  if (previous && bridge_owner_encode(bridge_owner_join(*previous, incoming)) ==
                      bridge_owner_encode(*previous))
    return;
  auto same_version = [](const ManagedVersion &a, const ManagedVersion &b) {
    return !a.compare(b);
  };
  // A writer may preserve an earlier foreign claim epoch or cell only when
  // that content is already authenticated locally. Otherwise defer until the
  // originating peer's preceding ownership record arrives.
  if (memcmp(incoming.epoch.origin.data(), origin, 16) &&
      (!previous || !same_version(previous->epoch, incoming.epoch)))
    throw ManagedError{SQLITE_BUSY};
  if (incoming.cell &&
      memcmp(incoming.cell->version.origin.data(), origin, 16)) {
    if (!previous || !previous->cell ||
        !same_version(previous->cell->version, incoming.cell->version) ||
        managed_encode_value(previous->cell->value) !=
            managed_encode_value(incoming.cell->value))
      throw ManagedError{SQLITE_BUSY};
  }
  if (!incoming.release.empty() &&
      memcmp(incoming.release.origin.data(), origin, 16) &&
      (!previous || previous->release.compare(incoming.release) < 0))
    throw ManagedError{SQLITE_BUSY};
  bind_origin(db, std::string(16, '\0'), incoming.epoch);
  bind_origin(db, std::string(16, '\0'), incoming.release);
  if (incoming.cell)
    bind_origin(db, std::string(16, '\0'), incoming.cell->version);
  auto joined = previous ? bridge_owner_join(*previous, incoming) : incoming;
  // Deliberately bypass local-change journalling: imported records never echo.
  Statement save(
      db,
      "INSERT INTO murmur_bridge_owners VALUES(?1,?2,?3,?4) ON "
      "CONFLICT(table_id,row_key,column_id) DO UPDATE SET body=excluded.body");
  save.blob(1, joined.table);
  save.blob(2, joined.key);
  save.blob(3, joined.column);
  save.blob(4, bridge_owner_encode(joined));
  save.done();
}
void bridge_rows_project(sqlite3 *db, const std::string &table,
                         const std::string &key) {
  project(db, registered(db, table), key);
}
void bridge_rows_merge_low(sqlite3 *db, const murmur_origin_envelope_t &e,
                           const std::string &payload, bool local) {
  auto incoming = unpack(payload.data(), payload.size());
  auto source = id(e.database);
  ManagedEncoder merged;
  merged.raw("MBT1", 4);
  merged.number(incoming.size());
  auto limit = [&](const ManagedVersion &v) {
    if (v.millis > e.millis || (v.millis == e.millis && v.logical > e.logical))
      throw ManagedError{SQLITE_AUTH};
  };
  auto own = [&](const ManagedVersion &v) {
    return !memcmp(v.origin.data(), e.origin, 16);
  };
  for (auto &row : incoming) {
    auto t = registered(db, row.table);
    auto keys = managed_decode_values(row.key);
    if (keys.size() != t.keys.size())
      throw ManagedError{SQLITE_SCHEMA};
    std::optional<ManagedRow> prior;
    Statement old(db, local ? "SELECT body FROM murmur_bridge_capture WHERE "
                              "table_id=?1 AND row_key=?2"
                            : "SELECT body FROM murmur_bridge_shadows WHERE "
                              "table_id=?1 AND row_key=?2 AND source=?3");
    old.blob(1, row.table);
    old.blob(2, row.key);
    if (!local)
      old.blob(3, source);
    if (old.row())
      prior = managed_row_decode(column(old.p, 0, MURMUR_BLOB));
    limit(row.generation);
    limit(row.tombstone);
    if (!row.tombstone.empty() && !own(row.tombstone) &&
        (!prior || row.tombstone.compare(prior->tombstone) > 0))
      throw ManagedError{SQLITE_BUSY};
    int generation = prior ? row.generation.compare(prior->generation) : 1;
    if (generation > 0 && !own(row.generation))
      throw ManagedError{SQLITE_BUSY};
    if (generation == 0 && row.epoch != prior->epoch)
      throw ManagedError{SQLITE_CORRUPT};
    for (auto &cell : row.columns) {
      if (cell.second.policy != MURMUR_POLICY_LWW)
        throw ManagedError{SQLITE_MISMATCH};
      limit(cell.second.version);
      if (generation < 0 || own(cell.second.version))
        continue;
      auto known = prior ? prior->columns.find(cell.first) : row.columns.end();
      if (!prior || generation > 0 || known == prior->columns.end() ||
          cell.second.version.compare(known->second.version) > 0)
        throw ManagedError{SQLITE_BUSY};
      if (!cell.second.version.compare(known->second.version) &&
          managed_encode_value(cell.second.value) !=
              managed_encode_value(known->second.value))
        throw ManagedError{SQLITE_CORRUPT};
    }
    if (local) {
      if (prior)
        row = managed_row_join(*prior, row);
      Statement save(
          db, "INSERT INTO murmur_bridge_capture VALUES(?1,?2,?3) ON "
              "CONFLICT(table_id,row_key) DO UPDATE SET body=excluded.body");
      save.blob(1, row.table);
      save.blob(2, row.key);
      save.blob(3, managed_row_encode(row));
      save.done();
    }
    merged.blob(managed_row_encode(row));
  }
  murmur_bridge_header_t header{};
  memcpy(header.database, e.database, 16);
  memcpy(header.schema, e.schema, 32);
  managed_check(import_rows(db, &header, merged.bytes.data(),
                            merged.bytes.size(), nullptr));
}
int bridge_rows_import(sqlite3 *db, const murmur_bridge_header_t *h,
                       const void *data, size_t len) {
  if (len >= 4 && !memcmp(data, "MHP1", 4))
    return bridge_peer_import_low_proof(db, h, data, len);
  return boundary([&] {
    Statement required(
        db, "SELECT 1 FROM murmur_bridge_source_keys WHERE source=?1 LIMIT 1");
    required.blob(1, id(h->database));
    if (required.row())
      throw ManagedError{SQLITE_AUTH};
    managed_check(import_rows(db, h, data, len, nullptr));
  });
}
namespace {
int import_typed(sqlite3 *db, const murmur_bridge_header_t *header,
                 const void *data, size_t len, void *) {
  int rc = bridge_rows_import(db, header, data, len);
  return rc == SQLITE_OK ? bridge_peer_received(db, header) : rc;
}
} // namespace
extern "C" int murmur_bridge_rows_apply(sqlite3 *db, const uint8_t source[16],
                                        const char *stream,
                                        const uint8_t signer[32],
                                        const uint8_t receiver[32], size_t mb,
                                        size_t mp) {
  if (!db || !source)
    return SQLITE_MISUSE;
  {
    Guard guard;
    if (!bridge_capture_accepts(db, source))
      return SQLITE_AUTH;
  }
  uint8_t schema[32];
  int rc = murmur_bridge_rows_schema(db, schema);
  if (rc != SQLITE_OK)
    return rc;
  return murmur_bridge_store_apply(db, source, stream, signer, receiver, schema,
                                   mb, mp, import_typed, nullptr);
}
namespace {
void change_owner(sqlite3 *db, const uint8_t tid[16], const murmur_value_t *key,
                  size_t n, const char *name,
                  const murmur_bridge_version_t *stamp, bool release) {
  Guard guard;
  Savepoint tx(db);
  auto t = registered(db, id(tid));
  auto keys = key_values(t, key, n);
  auto encoded = managed_encode_values(keys);
  auto v = version(stamp);
  // Reserve local High node identities separately from every Low domain.
  // The zero domain cannot appear in an authenticated source envelope.
  bind_origin(db, std::string(16, '\0'), v);
  std::string cid;
  if (name) {
    auto f = std::find_if(t.fields.begin(), t.fields.end(),
                          [&](const Field &f) { return f.name == name; });
    if (f == t.fields.end() || f->pk)
      throw ManagedError{SQLITE_SCHEMA};
    cid = f->id;
  }
  auto previous = owner(db, t.id, encoded, cid);
  if (release) {
    if (!previous || !previous->owned)
      throw ManagedError{SQLITE_NOTFOUND};
    save_owner(db, bridge_owner_release(*previous, v));
    project(db, t, encoded);
  } else {
    auto values = read(db, t, keys);
    std::optional<ManagedRowColumn> cell;
    if (name) {
      if (!values)
        throw ManagedError{SQLITE_NOTFOUND};
      ManagedRowColumn c;
      c.value = values->at(cid);
      cell = c;
    } else if (values)
      throw ManagedError{SQLITE_CONSTRAINT};
    save_owner(db, bridge_owner_claim(previous ? &*previous : nullptr, t.id,
                                      encoded, cid, v, cell));
  }
  tx.commit();
}
} // namespace
extern "C" int murmur_bridge_rows_claim(sqlite3 *db, const uint8_t tid[16],
                                        const murmur_value_t *key, size_t n,
                                        const char *col,
                                        const murmur_bridge_version_t *stamp) {
  if (!db || sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] { change_owner(db, tid, key, n, col, stamp, false); });
}
extern "C" int
murmur_bridge_rows_release(sqlite3 *db, const uint8_t tid[16],
                           const murmur_value_t *key, size_t n, const char *col,
                           const murmur_bridge_version_t *stamp) {
  if (!db || sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  return boundary([&] { change_owner(db, tid, key, n, col, stamp, true); });
}
