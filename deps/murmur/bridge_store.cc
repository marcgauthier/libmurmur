#include "bridge_store.h"
#include "../keyring/sha256.h"
#include "kv.h"
#include "open.h"
#include "sqlite3.h"
#include <climits>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

namespace {
struct Lock {
  Lock() { murmur_db_writer_lock(); }
  ~Lock() { murmur_db_writer_unlock(); }
};
struct Statement {
  sqlite3_stmt *p = nullptr;
  ~Statement() { sqlite3_finalize(p); }
  int prepare(sqlite3 *db, const char *sql) {
    return sqlite3_prepare_v2(db, sql, -1, &p, nullptr);
  }
  int lane(const uint8_t *source, const char *stream) {
    int rc = sqlite3_bind_blob(p, 1, source, 16, SQLITE_TRANSIENT);
    return rc == SQLITE_OK
               ? sqlite3_bind_text(p, 2, stream, -1, SQLITE_TRANSIENT)
               : rc;
  }
};
struct Transaction {
  sqlite3 *db;
  bool active = false;
  const char *rollback;
  explicit Transaction(sqlite3 *d) : db(d), rollback("ROLLBACK") {}
  ~Transaction() {
    if (active)
      sqlite3_exec(db, rollback, nullptr, nullptr, nullptr);
  }
  int begin(bool nested = false) {
    rollback =
        nested ? "ROLLBACK TO bridge_queue; RELEASE bridge_queue" : "ROLLBACK";
    int rc =
        sqlite3_exec(db, nested ? "SAVEPOINT bridge_queue" : "BEGIN IMMEDIATE",
                     nullptr, nullptr, nullptr);
    active = rc == SQLITE_OK;
    return rc;
  }
  int commit(bool nested = false) {
    int rc = sqlite3_exec(db, nested ? "RELEASE bridge_queue" : "COMMIT",
                          nullptr, nullptr, nullptr);
    if (rc == SQLITE_OK)
      active = false;
    return rc;
  }
};
bool valid(sqlite3 *db, const uint8_t *source, const char *stream) {
  if (!db || !source || !stream)
    return false;
  size_t n = 0;
  uint8_t v = 0;
  for (int i = 0; i < 16; ++i)
    v |= source[i];
  if (!v)
    return false;
  for (; n < 65 && stream[n]; ++n) {
    char c = stream[n];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-'))
      return false;
  }
  return n > 0 && n <= 64;
}
int done(Statement &q) {
  int rc = sqlite3_step(q.p);
  return rc == SQLITE_DONE ? SQLITE_OK : rc;
}
int budget(sqlite3 *db, const char *kind, size_t bytes, uint64_t limit,
           const uint8_t source[16], const char *stream) {
  constexpr uint64_t hard = 1ull << 30;
  if (!limit || limit > hard || bytes > limit)
    return SQLITE_TOOBIG;
  Statement q;
  int rc = q.prepare(
      db, "SELECT coalesce(sum(length(bundle)),0),coalesce(sum(CASE WHEN "
          "source=?2 AND stream=?3 THEN length(bundle) ELSE 0 END),0) FROM "
          "murmur_bridge_artifact WHERE kind=?1");
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_text(q.p, 1, kind, -1, SQLITE_STATIC);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_blob(q.p, 2, source, 16, SQLITE_STATIC);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_text(q.p, 3, stream, -1, SQLITE_STATIC);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  if (rc != SQLITE_ROW)
    return rc;
  auto total = sqlite3_column_int64(q.p, 0),
       lane = sqlite3_column_int64(q.p, 1);
  return total < 0 || lane < 0 || (uint64_t)total > hard - bytes ||
                 (uint64_t)lane > limit - bytes
             ? SQLITE_FULL
             : SQLITE_OK;
}
int insert(sqlite3 *db, const char *kind, const uint8_t *source,
           const char *stream, uint64_t seq, const void *b, size_t n) {
  Statement q;
  int rc = q.prepare(
      db,
      "INSERT INTO murmur_bridge_artifact(source,stream,sequence,kind,bundle) "
      "VALUES(?,?,?,?,?)");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_int64(q.p, 3, (sqlite3_int64)seq);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_text(q.p, 4, kind, -1, SQLITE_STATIC);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_blob64(q.p, 5, b, n, SQLITE_TRANSIENT);
  return rc == SQLITE_OK ? done(q) : rc;
}
int barrier(sqlite3 *db) {
  const char *path = sqlite3_db_filename(db, "main");
  if (!path || !*path)
    return SQLITE_OK; /* in-memory unit fixtures */
  return nvFlushDb(path) == 0 ? SQLITE_OK : SQLITE_IOERR_FSYNC;
}
} // namespace
extern "C" int murmur_bridge_store_init(sqlite3 *db) {
  if (!db || !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  Lock lock;
  Transaction tx(db);
  int rc = tx.begin();
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_exec(
      db,
      "CREATE TABLE IF NOT EXISTS murmur_bridge_lane(source BLOB NOT "
      "NULL,stream TEXT NOT NULL,allocated INTEGER NOT NULL DEFAULT 0,applied "
      "INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(source,stream));"
      "CREATE TABLE IF NOT EXISTS murmur_bridge_artifact(source BLOB NOT "
      "NULL,stream TEXT NOT NULL,sequence INTEGER NOT NULL,kind TEXT NOT "
      "NULL,bundle BLOB NOT NULL,PRIMARY KEY(source,stream,sequence,kind));"
      "CREATE TABLE IF NOT EXISTS murmur_bridge_receipt(source BLOB NOT "
      "NULL,stream TEXT NOT NULL,sequence INTEGER NOT NULL,digest BLOB NOT "
      "NULL,PRIMARY KEY(source,stream,sequence));"
      "CREATE INDEX IF NOT EXISTS murmur_bridge_receipt_digest ON "
      "murmur_bridge_receipt(source,stream,digest);",
      nullptr, nullptr, nullptr);
  return rc == SQLITE_OK ? tx.commit() : rc;
}
extern "C" int murmur_bridge_store_queue(sqlite3 *db, murmur_bridge_header_t *h,
                                         const uint8_t signer[32],
                                         const uint8_t recipient[32],
                                         const void *payload, size_t len,
                                         size_t mb, size_t mp,
                                         uint64_t capacity) {
  if (!h || !valid(db, h->database, h->stream) || sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  Lock lock;
  Transaction tx(db);
  int rc = tx.begin(true);
  if (rc != SQLITE_OK)
    return rc;
  Statement q;
  rc = q.prepare(
      db,
      "INSERT INTO murmur_bridge_lane(source,stream,allocated) VALUES(?,?,1) "
      "ON CONFLICT(source,stream) DO UPDATE SET allocated=allocated+1 WHERE "
      "allocated<9223372036854775807 RETURNING allocated");
  if (rc == SQLITE_OK)
    rc = q.lane(h->database, h->stream);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  if (rc != SQLITE_ROW)
    return rc == SQLITE_DONE ? SQLITE_FULL : rc;
  murmur_bridge_header_t copy = *h;
  copy.sequence = (uint64_t)sqlite3_column_int64(q.p, 0);
  rc = sqlite3_step(q.p);
  if (rc != SQLITE_DONE)
    return rc;
  murmur_bridge_bytes_t b{};
  rc = murmur_bridge_seal(&copy, signer, recipient, payload, len, mb, mp, &b);
  if (rc == SQLITE_OK)
    rc = budget(db, "out", b.len, capacity, h->database, h->stream);
  if (rc == SQLITE_OK)
    rc = insert(db, "out", copy.database, copy.stream, copy.sequence, b.data,
                b.len);
  murmur_bridge_bytes_free(&b);
  if (rc == SQLITE_OK)
    rc = tx.commit(true);
  if (rc == SQLITE_OK)
    *h = copy;
  return rc;
}
extern "C" int murmur_bridge_store_next(sqlite3 *db, const uint8_t source[16],
                                        const char *stream, uint64_t *seq,
                                        murmur_bridge_bytes_t *b) {
  if (!b || !seq)
    return SQLITE_MISUSE;
  *b = {};
  *seq = 0;
  if (!valid(db, source, stream))
    return SQLITE_MISUSE;
  Lock lock;
  Statement q;
  int rc = q.prepare(
      db, "SELECT sequence,bundle FROM murmur_bridge_artifact WHERE source=? "
          "AND stream=? AND kind='out' ORDER BY sequence LIMIT 1");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  if (rc != SQLITE_ROW)
    return rc == SQLITE_DONE ? SQLITE_NOTFOUND : rc;
  size_t n = (size_t)sqlite3_column_bytes(q.p, 1);
  if (sqlite3_column_type(q.p, 1) != SQLITE_BLOB ||
      n > MURMUR_BRIDGE_MAX_BUNDLE)
    return SQLITE_CORRUPT;
  if (n && !sqlite3_column_blob(q.p, 1))
    return SQLITE_NOMEM;
  auto p = (uint8_t *)malloc(n ? n : 1);
  if (!p)
    return SQLITE_NOMEM;
  memcpy(p, sqlite3_column_blob(q.p, 1), n);
  b->data = p;
  b->len = n;
  *seq = (uint64_t)sqlite3_column_int64(q.p, 0);
  return SQLITE_OK;
}
extern "C" int murmur_bridge_store_ack(sqlite3 *db, const uint8_t source[16],
                                       const char *stream, uint64_t seq) {
  if (!valid(db, source, stream) || seq == 0 || seq > INT64_MAX ||
      !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  Lock lock;
  Statement q;
  int rc = q.prepare(db, "DELETE FROM murmur_bridge_artifact WHERE source=? "
                         "AND stream=? AND sequence=? AND kind='out'");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_int64(q.p, 3, (sqlite3_int64)seq);
  if (rc == SQLITE_OK)
    rc = done(q);
  return rc == SQLITE_OK ? barrier(db) : rc;
}
extern "C" int murmur_bridge_store_stage(sqlite3 *db, const void *b, size_t n,
                                         const uint8_t source[16],
                                         const char *stream,
                                         const uint8_t signer[32],
                                         const uint8_t receiver[32], size_t mb,
                                         size_t mp, uint64_t capacity) {
  if (!valid(db, source, stream) || !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  murmur_bridge_header_t h{};
  murmur_bridge_bytes_t payload{};
  int rc = murmur_bridge_unseal(b, n, source, stream, signer, receiver, mb, mp,
                                &h, &payload);
  murmur_bridge_bytes_free(&payload);
  if (rc != SQLITE_OK)
    return rc;
  if (h.sequence > INT64_MAX)
    return SQLITE_FULL;
  Lock lock;
  Transaction tx(db);
  rc = tx.begin();
  if (rc != SQLITE_OK)
    return rc;
  Statement q;
  rc = q.prepare(
      db,
      "SELECT bundle,0 FROM murmur_bridge_artifact WHERE source=? AND stream=? "
      "AND sequence=? AND kind='in' UNION ALL SELECT digest,1 FROM "
      "murmur_bridge_receipt WHERE source=?1 AND stream=?2 AND sequence=?3");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_int64(q.p, 3, (sqlite3_int64)h.sequence);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  if (rc == SQLITE_ROW) {
    uint8_t digest[32];
    murmur_sha256((const uint8_t *)b, n, digest);
    bool receipt = sqlite3_column_int(q.p, 1) != 0;
    size_t expected = receipt ? 32 : n;
    const void *bytes = receipt ? (const void *)digest : b;
    if ((size_t)sqlite3_column_bytes(q.p, 0) != expected ||
        memcmp(sqlite3_column_blob(q.p, 0), bytes, expected))
      return SQLITE_AUTH;
    rc = sqlite3_step(q.p);
    if (rc != SQLITE_DONE)
      return rc;
  } else if (rc == SQLITE_DONE) {
    rc = budget(db, "in", n, capacity, source, stream);
    if (rc != SQLITE_OK)
      return rc;
    rc = insert(db, "in", source, stream, h.sequence, b, n);
    if (rc != SQLITE_OK)
      return rc;
  } else
    return rc;
  rc = tx.commit();
  return rc == SQLITE_OK ? barrier(db) : rc;
}
extern "C" int
murmur_bridge_store_apply(sqlite3 *db, const uint8_t source[16],
                          const char *stream, const uint8_t signer[32],
                          const uint8_t receiver[32], const uint8_t schema[32],
                          size_t mb, size_t mp, murmur_bridge_apply_fn apply,
                          void *arg) {
  if (!valid(db, source, stream) || !apply || !schema ||
      !sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  Lock lock;
  Transaction tx(db);
  int rc = tx.begin();
  if (rc != SQLITE_OK)
    return rc;
  Statement q;
  rc = q.prepare(
      db, "SELECT sequence,bundle FROM murmur_bridge_artifact WHERE source=? "
          "AND stream=? AND kind='in' AND sequence=coalesce((SELECT applied "
          "FROM murmur_bridge_lane WHERE source=?1 AND stream=?2),0)+1");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  if (rc != SQLITE_ROW)
    return rc == SQLITE_DONE ? SQLITE_NOTFOUND : rc;
  murmur_bridge_header_t h{};
  murmur_bridge_bytes_t payload{};
  rc = murmur_bridge_unseal(sqlite3_column_blob(q.p, 1),
                            (size_t)sqlite3_column_bytes(q.p, 1), source,
                            stream, signer, receiver, mb, mp, &h, &payload);
  if (rc != SQLITE_OK)
    return rc;
  if (memcmp(schema, h.schema, 32)) {
    murmur_bridge_bytes_free(&payload);
    return SQLITE_SCHEMA;
  }
  uint8_t bundle_digest[32];
  murmur_sha256((const uint8_t *)sqlite3_column_blob(q.p, 1),
                (size_t)sqlite3_column_bytes(q.p, 1), bundle_digest);
  rc = apply(db, &h, payload.data, payload.len, arg);
  murmur_bridge_bytes_free(&payload);
  if (rc != SQLITE_OK)
    return rc;
  if (sqlite3_get_autocommit(db))
    return SQLITE_MISUSE;
  sqlite3_finalize(q.p);
  q.p = nullptr;
  rc = q.prepare(
      db, "INSERT INTO murmur_bridge_receipt(source,stream,sequence,digest) "
          "VALUES(?,?,?,?)");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_int64(q.p, 3, (sqlite3_int64)h.sequence);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_blob(q.p, 4, bundle_digest, 32, SQLITE_TRANSIENT);
  if (rc == SQLITE_OK)
    rc = done(q);
  if (rc != SQLITE_OK)
    return rc;
  sqlite3_finalize(q.p);
  q.p = nullptr;
  rc = q.prepare(
      db, "INSERT INTO murmur_bridge_lane(source,stream,applied) VALUES(?,?,?) "
          "ON CONFLICT(source,stream) DO UPDATE SET applied=excluded.applied");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_int64(q.p, 3, (sqlite3_int64)h.sequence);
  if (rc == SQLITE_OK)
    rc = done(q);
  if (rc != SQLITE_OK)
    return rc;
  sqlite3_finalize(q.p);
  q.p = nullptr;
  rc = q.prepare(db, "DELETE FROM murmur_bridge_artifact WHERE source=? AND "
                     "stream=? AND sequence=? AND kind='in'");
  if (rc == SQLITE_OK)
    rc = q.lane(source, stream);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_int64(q.p, 3, (sqlite3_int64)h.sequence);
  if (rc == SQLITE_OK)
    rc = done(q);
  if (rc == SQLITE_OK)
    rc = tx.commit();
  return rc == SQLITE_OK ? barrier(db) : rc;
}
