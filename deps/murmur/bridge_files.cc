#include "../keyring/sha256.h"
#include "bridge_capture.h"
#include "bridge_capture_internal.h"
#include "bridge_files_internal.h"
#include "kv.h"
#include "managed_codec.h"
#include "open.h"
#include <array>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {
constexpr size_t chunk_limit = 64u << 10;
constexpr uint64_t staging_limit = 1ull << 30;
struct Guard {
  Guard() { murmur_db_writer_lock(); }
  ~Guard() { murmur_db_writer_unlock(); }
};
struct Query {
  sqlite3_stmt *q = nullptr;
  Query(sqlite3 *db, const char *sql) {
    managed_check(sqlite3_prepare_v2(db, sql, -1, &q, nullptr));
  }
  ~Query() { sqlite3_finalize(q); }
  void blob(int n, const std::string &s) {
    managed_check(
        sqlite3_bind_blob64(q, n, s.data(), s.size(), SQLITE_TRANSIENT));
  }
  void text(int n, const std::string &s) {
    managed_check(sqlite3_bind_text64(q, n, s.data(), s.size(),
                                      SQLITE_TRANSIENT, SQLITE_UTF8));
  }
  void number(int n, uint64_t v) {
    if (v > INT64_MAX)
      throw ManagedError{SQLITE_TOOBIG};
    managed_check(sqlite3_bind_int64(q, n, (sqlite3_int64)v));
  }
  bool row() {
    int rc = sqlite3_step(q);
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
  std::string bytes(int n) {
    if (sqlite3_column_type(q, n) != SQLITE_BLOB)
      throw ManagedError{SQLITE_CORRUPT};
    auto p = (const char *)sqlite3_column_blob(q, n);
    return std::string(p ? p : "", (size_t)sqlite3_column_bytes(q, n));
  }
  std::string text(int n) {
    if (sqlite3_column_type(q, n) != SQLITE_TEXT)
      throw ManagedError{SQLITE_CORRUPT};
    auto p = (const char *)sqlite3_column_text(q, n);
    return std::string(p, (size_t)sqlite3_column_bytes(q, n));
  }
  uint64_t number(int n) {
    auto v = sqlite3_column_int64(q, n);
    if (v < 0)
      throw ManagedError{SQLITE_CORRUPT};
    return (uint64_t)v;
  }
};
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
void sql(sqlite3 *db, const char *q) {
  managed_check(sqlite3_exec(db, q, nullptr, nullptr, nullptr));
}
void flush(sqlite3 *db) {
  const char *p = sqlite3_db_filename(db, "main");
  if (p && *p && nvFlushDb(p))
    throw ManagedError{SQLITE_IOERR_FSYNC};
}
void file_result(murmur_files_status_t status, char *detail, int rc) {
  free(detail);
  if (status == MURMUR_FILES_OK)
    return;
  switch (status) {
  case MURMUR_FILES_AUTH:
    throw ManagedError{SQLITE_AUTH};
  case MURMUR_FILES_UNAVAILABLE:
    throw ManagedError{SQLITE_NOTFOUND};
  case MURMUR_FILES_OVERLOADED:
    throw ManagedError{SQLITE_FULL};
  case MURMUR_FILES_SQLITE:
    throw ManagedError{rc == SQLITE_OK ? SQLITE_ERROR : rc};
  case MURMUR_FILES_INVALID:
  case MURMUR_FILES_PROTOCOL:
    throw ManagedError{SQLITE_CORRUPT};
  default:
    throw ManagedError{SQLITE_IOERR};
  }
}
struct Part {
  std::string name, digest, data;
  uint64_t total = 0, offset = 0;
  bool final = false;
};
void valid(const Part &p) {
  if (p.name.empty() || p.name.size() > 4096 ||
      p.name.find('\0') != std::string::npos ||
      !murmur_utf8_valid((const uint8_t *)p.name.data(), p.name.size()) ||
      p.digest.size() != 32 || p.total > staging_limit || p.offset > p.total ||
      p.data.size() > chunk_limit || p.data.size() > p.total - p.offset ||
      (p.final && (p.offset != p.total || !p.data.empty())) ||
      (!p.final && p.data.empty()))
    throw ManagedError{SQLITE_CORRUPT};
}
std::string encode(const Part &p) {
  valid(p);
  ManagedEncoder e;
  e.raw("MBF1", 4);
  e.blob(p.name);
  e.raw(p.digest.data(), 32);
  e.number(p.total);
  e.number(p.offset);
  e.number(p.final);
  e.blob(p.data);
  return e.bytes;
}
Part decode(const void *data, size_t len) {
  if (len > chunk_limit + 4200)
    throw ManagedError{SQLITE_TOOBIG};
  ManagedDecoder d(data, len);
  if (d.raw(4) != "MBF1")
    throw ManagedError{SQLITE_CORRUPT};
  Part p;
  p.name = d.text();
  p.digest = d.raw(32);
  p.total = d.number();
  p.offset = d.number();
  auto final = d.number();
  if (final > 1)
    throw ManagedError{SQLITE_CORRUPT};
  p.final = final;
  p.data = d.blob();
  d.end();
  valid(p);
  if (encode(p) != std::string((const char *)data, len))
    throw ManagedError{SQLITE_CORRUPT};
  return p;
}
std::string transfer(const uint8_t source[16], const char *stream,
                     const Part &p) {
  ManagedEncoder e;
  static const char domain[] = "murmur/native-bridge-file/v1";
  e.raw(domain, sizeof(domain) - 1);
  e.raw(source, 16);
  e.blob(stream);
  e.blob(p.name);
  e.blob(p.digest);
  e.number(p.total);
  uint8_t digest[32];
  murmur_sha256((const uint8_t *)e.bytes.data(), e.bytes.size(), digest);
  return std::string((const char *)digest, 32);
}
struct List {
  murmur_files_meta_t *data = nullptr;
  size_t count = 0;
  ~List() { murmur_files_meta_list_free(data, count); }
};
struct Upload {
  murmur_file_upload_t *p = nullptr;
  ~Upload() {
    if (p)
      murmur_files_upload_abort(p);
  }
};
} // namespace

struct BridgeFileExporter {
  sqlite3 *db;
  murmur_files_t *files;
  std::string source, stream, after;
  murmur_file_download_t *download = nullptr;
  Part part;
  uint64_t generation = 0, position = 0, saved = 0;
  bool at_end = false;
  ~BridgeFileExporter() {
    if (download)
      murmur_files_download_close(download);
  }
};
int bridge_files_init(sqlite3 *db) {
  if (!db)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    sql(db,
        "CREATE TABLE IF NOT EXISTS murmur_bridge_file_export(source BLOB NOT "
        "NULL,stream TEXT NOT NULL,name TEXT NOT NULL,digest BLOB NOT "
        "NULL,generation INTEGER NOT NULL,offset INTEGER NOT NULL,done INTEGER "
        "NOT NULL,PRIMARY KEY(source,stream,name));"
        "CREATE TABLE IF NOT EXISTS murmur_bridge_file_transfer(id BLOB "
        "PRIMARY KEY NOT NULL,source BLOB NOT NULL,stream TEXT NOT NULL,name "
        "TEXT NOT NULL,digest BLOB NOT NULL,total INTEGER NOT NULL,received "
        "INTEGER NOT NULL,ready INTEGER NOT NULL,done INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS murmur_bridge_file_pending ON "
        "murmur_bridge_file_transfer(source,stream,done,ready);"
        "CREATE TABLE IF NOT EXISTS murmur_bridge_file_chunk(transfer BLOB NOT "
        "NULL,offset INTEGER NOT NULL,data BLOB NOT NULL,PRIMARY "
        "KEY(transfer,offset));");
  });
}
BridgeFileExporter *bridge_files_exporter_new(sqlite3 *db,
                                              murmur_files_t *files,
                                              const uint8_t source[16],
                                              const char *stream) {
  auto p = std::make_unique<BridgeFileExporter>();
  p->db = db;
  p->files = files;
  p->source.assign((const char *)source, 16);
  p->stream = stream;
  return p.release();
}
void bridge_files_exporter_free(BridgeFileExporter *p) { delete p; }
namespace {
void reset(BridgeFileExporter &e) {
  if (e.download)
    murmur_files_download_close(e.download);
  e.download = nullptr;
  e.part = {};
  e.position = e.saved = 0;
  e.at_end = false;
}
bool select_file(BridgeFileExporter &e) {
  List list;
  char *detail = nullptr;
  int rc = SQLITE_OK;
  auto list_status = murmur_files_list_bounded(e.files, 4u << 20, &list.data,
                                               &list.count, &detail, &rc);
  file_result(list_status, detail, rc);
  // Scan at most one metadata page each poll. Cursor wraps after the last name,
  // so changed files and newly available peer objects are eventually revisited.
  size_t examined = 0;
  for (size_t i = 0; i < list.count; ++i) {
    auto &m = list.data[i];
    if (e.after >= m.name)
      continue;
    if (++examined > 256)
      return false;
    e.after = m.name;
    bool done = false;
    uint64_t saved = 0;
    {
      Guard guard;
      Query q(
          e.db,
          "SELECT digest,generation,offset,done FROM murmur_bridge_file_export "
          "WHERE source=?1 AND stream=?2 AND name=?3");
      q.blob(1, e.source);
      q.text(2, e.stream);
      q.text(3, m.name);
      if (q.row() && q.bytes(0) == std::string((const char *)m.digest, 32) &&
          q.number(1) == m.generation) {
        done = q.number(3);
        saved = q.number(2);
      }
    }
    if (done)
      continue;
    if (m.bytes > staging_limit)
      throw ManagedError{SQLITE_TOOBIG};
    detail = nullptr;
    rc = SQLITE_OK;
    auto status =
        murmur_files_download(e.files, m.name, &e.download, &detail, &rc);
    if (status == MURMUR_FILES_UNAVAILABLE) {
      free(detail);
      continue;
    }
    file_result(status, detail, rc);
    auto pinned = murmur_files_download_metadata(e.download);
    e.part.name = pinned->name;
    e.part.digest.assign((const char *)pinned->digest, 32);
    e.part.total = pinned->bytes;
    e.generation = pinned->generation;
    if (e.part.total > staging_limit) {
      reset(e);
      throw ManagedError{SQLITE_TOOBIG};
    }
    // Metadata may have changed between selection and pinning.
    if (e.part.digest != std::string((const char *)m.digest, 32) ||
        e.generation != m.generation)
      saved = 0;
    if (saved > e.part.total) {
      reset(e);
      throw ManagedError{SQLITE_CORRUPT};
    }
    e.saved = saved;
    return true;
  }
  e.after.clear();
  return false;
}
struct Emit {
  BridgeFileExporter *exporter;
  std::string payload;
  uint64_t offset;
  bool final;
};
int emit(sqlite3 *db, void *arg) {
  return boundary([&] {
    auto &call = *static_cast<Emit *>(arg);
    auto &e = *call.exporter;
    Query previous(
        db,
        "SELECT digest,generation,offset,done FROM murmur_bridge_file_export "
        "WHERE source=?1 AND stream=?2 AND name=?3");
    previous.blob(1, e.source);
    previous.text(2, e.stream);
    previous.text(3, e.part.name);
    uint64_t offset = 0;
    bool done = false;
    if (previous.row() && previous.bytes(0) == e.part.digest &&
        previous.number(1) == e.generation) {
      offset = previous.number(2);
      done = previous.number(3);
    }
    if (offset != e.saved || done)
      throw ManagedError{SQLITE_BUSY};
    managed_check(
        bridge_capture_enqueue(db, call.payload.data(), call.payload.size()));
    Query save(
        db,
        "INSERT INTO murmur_bridge_file_export VALUES(?1,?2,?3,?4,?5,?6,?7) ON "
        "CONFLICT(source,stream,name) DO UPDATE SET "
        "digest=excluded.digest,generation=excluded.generation,offset=excluded."
        "offset,done=excluded.done");
    save.blob(1, e.source);
    save.text(2, e.stream);
    save.text(3, e.part.name);
    save.blob(4, e.part.digest);
    save.number(5, e.generation);
    save.number(6, call.offset);
    save.number(7, call.final);
    save.done();
  });
}
} // namespace
int bridge_files_export_step(BridgeFileExporter *e, size_t budget,
                             const std::function<bool()> &stop,
                             uint64_t *queued) {
  if (queued)
    *queued = 0;
  if (!e || !queued || !budget || budget > 256)
    return SQLITE_MISUSE;
  int result = boundary([&] {
    if (!e->download && !select_file(*e))
      return;
    for (size_t i = 0; i < budget && !stop(); ++i) {
      if (e->at_end) {
        e->part.offset = e->part.total;
        e->part.data.clear();
        e->part.final = true;
        Emit call{e, encode(e->part), e->part.total, true};
        managed_check(murmur_bridge_write(e->db, emit, &call));
        ++*queued;
        reset(*e);
        return;
      }
      std::array<uint8_t, chunk_limit> data{};
      uint64_t offset = 0;
      size_t n = 0;
      int done = 0;
      char *detail = nullptr;
      size_t want =
          e->position < e->saved
              ? (size_t)std::min<uint64_t>(chunk_limit, e->saved - e->position)
              : chunk_limit;
      auto status = murmur_files_download_next(e->download, want, &offset,
                                               data.data(), &n, &done, &detail);
      file_result(status, detail, SQLITE_OK);
      if (offset != e->position || n > e->part.total - e->position)
        throw ManagedError{SQLITE_AUTH};
      e->position += n;
      e->at_end = done;
      if (e->position <= e->saved) {
        if (!n && !done)
          throw ManagedError{SQLITE_IOERR};
        continue;
      }
      e->part.offset = offset;
      e->part.data.assign((const char *)data.data(), n);
      e->part.final = false;
      Emit call{e, encode(e->part), e->position, false};
      managed_check(murmur_bridge_write(e->db, emit, &call));
      e->saved = e->position;
      ++*queued;
    }
  });
  if (result != SQLITE_OK)
    reset(*e);
  return result;
}

int bridge_files_stage(sqlite3 *db, const murmur_bridge_header_t *h,
                       const void *data, size_t len, uint64_t capacity) {
  if (!db || !h || sqlite3_get_autocommit(db) || !capacity ||
      capacity > staging_limit)
    return SQLITE_MISUSE;
  return boundary([&] {
    Guard guard;
    auto part = decode(data, len);
    if (part.total > capacity)
      throw ManagedError{SQLITE_TOOBIG};
    auto id = transfer(h->database, h->stream, part);
    Query find(db, "SELECT name,digest,total,received,ready,done FROM "
                   "murmur_bridge_file_transfer WHERE id=?1");
    find.blob(1, id);
    uint64_t received = 0;
    bool ready = false, done = false;
    if (find.row()) {
      if (find.text(0) != part.name || find.bytes(1) != part.digest ||
          find.number(2) != part.total)
        throw ManagedError{SQLITE_AUTH};
      received = find.number(3);
      ready = find.number(4);
      done = find.number(5);
    } else {
      Query add(db, "INSERT INTO murmur_bridge_file_transfer "
                    "VALUES(?1,?2,?3,?4,?5,?6,0,0,0)");
      add.blob(1, id);
      add.blob(2, std::string((const char *)h->database, 16));
      add.text(3, h->stream);
      add.text(4, part.name);
      add.blob(5, part.digest);
      add.number(6, part.total);
      add.done();
    }
    if (done)
      return;
    if (part.final) {
      if (received != part.total)
        throw ManagedError{SQLITE_BUSY};
      Query update(
          db, "UPDATE murmur_bridge_file_transfer SET ready=1 WHERE id=?1");
      update.blob(1, id);
      update.done();
      return;
    }
    if (part.offset < received) {
      Query old(db, "SELECT data FROM murmur_bridge_file_chunk WHERE "
                    "transfer=?1 AND offset=?2");
      old.blob(1, id);
      old.number(2, part.offset);
      if (!old.row() || old.bytes(0) != part.data)
        throw ManagedError{SQLITE_AUTH};
      return;
    }
    if (ready || part.offset != received)
      throw ManagedError{SQLITE_BUSY};
    Query usage(db, "SELECT coalesce(sum(length(c.data)),0),coalesce(sum(CASE "
                    "WHEN t.source=?1 AND t.stream=?2 THEN length(c.data) ELSE "
                    "0 END),0) FROM murmur_bridge_file_chunk c JOIN "
                    "murmur_bridge_file_transfer t ON t.id=c.transfer");
    usage.blob(1, std::string((const char *)h->database, 16));
    usage.text(2, h->stream);
    if (!usage.row())
      throw ManagedError{SQLITE_CORRUPT};
    if (usage.number(0) > staging_limit - part.data.size() ||
        usage.number(1) > capacity - part.data.size())
      throw ManagedError{SQLITE_FULL};
    Query add(db, "INSERT INTO murmur_bridge_file_chunk VALUES(?1,?2,?3)");
    add.blob(1, id);
    add.number(2, part.offset);
    add.blob(3, part.data);
    add.done();
    Query update(
        db, "UPDATE murmur_bridge_file_transfer SET received=?2 WHERE id=?1");
    update.blob(1, id);
    update.number(2, received + part.data.size());
    update.done();
  });
}
namespace {
struct Complete {
  std::string id, digest;
  uint64_t total;
};
int complete(sqlite3 *db, const murmur_files_meta_t *meta, void *arg) {
  return boundary([&] {
    auto &c = *static_cast<Complete *>(arg);
    if (c.digest != std::string((const char *)meta->digest, 32) ||
        c.total != meta->bytes)
      throw ManagedError{SQLITE_AUTH};
    Query check(
        db, "SELECT done,ready FROM murmur_bridge_file_transfer WHERE id=?1");
    check.blob(1, c.id);
    if (!check.row() || check.number(0))
      throw ManagedError{SQLITE_NOTFOUND};
    if (!check.number(1))
      throw ManagedError{SQLITE_BUSY};
    Query mark(db, "UPDATE murmur_bridge_file_transfer SET done=1 WHERE id=?1");
    mark.blob(1, c.id);
    mark.done();
    Query remove(db, "DELETE FROM murmur_bridge_file_chunk WHERE transfer=?1");
    remove.blob(1, c.id);
    remove.done();
  });
}
} // namespace
int bridge_files_finish_one(sqlite3 *db, murmur_files_t *files,
                            const uint8_t source[16], const char *stream,
                            const std::function<bool()> &stop,
                            uint64_t *completed) {
  if (completed)
    *completed = 0;
  if (!db || !files || !completed)
    return SQLITE_MISUSE;
  // Prevent two receivers from finalizing the same name concurrently. No SQL
  // admission is retained while taking file-store gates or encrypting chunks.
  static std::mutex finishing;
  std::unique_lock<std::mutex> serial(finishing, std::try_to_lock);
  if (!serial.owns_lock())
    return SQLITE_OK;
  return boundary([&] {
    Complete c;
    std::string name;
    {
      Guard guard;
      flush(db);
      Query q(db, "SELECT id,name,digest,total FROM "
                  "murmur_bridge_file_transfer WHERE source=?1 AND stream=?2 "
                  "AND ready=1 AND done=0 ORDER BY rowid LIMIT 1");
      q.blob(1, std::string((const char *)source, 16));
      q.text(2, stream);
      if (!q.row())
        return;
      c.id = q.bytes(0);
      name = q.text(1);
      c.digest = q.bytes(2);
      c.total = q.number(3);
    }
    Upload upload;
    char *detail = nullptr;
    int rc = SQLITE_OK;
    auto begin_status =
        murmur_files_begin_upload(files, name.c_str(), &upload.p, &detail, &rc);
    file_result(begin_status, detail, rc);
    uint64_t offset = 0;
    while (offset < c.total) {
      if (stop())
        return;
      std::string bytes;
      {
        Guard guard;
        Query q(db, "SELECT data FROM murmur_bridge_file_chunk WHERE "
                    "transfer=?1 AND offset=?2");
        q.blob(1, c.id);
        q.number(2, offset);
        if (!q.row())
          throw ManagedError{SQLITE_CORRUPT};
        bytes = q.bytes(0);
        if (bytes.empty() || bytes.size() > chunk_limit ||
            bytes.size() > c.total - offset)
          throw ManagedError{SQLITE_CORRUPT};
      }
      detail = nullptr;
      auto status = murmur_files_upload_append(
          upload.p, (const uint8_t *)bytes.data(), bytes.size(), &detail);
      file_result(status, detail, SQLITE_OK);
      offset += bytes.size();
    }
    if (stop())
      return;
    detail = nullptr;
    rc = SQLITE_OK;
    auto raw = upload.p;
    upload.p = nullptr;
    auto status = murmur_files_finish_upload_atomic(files, raw, complete, &c,
                                                    nullptr, &detail, &rc);
    if (status == MURMUR_FILES_SQLITE && rc == SQLITE_NOTFOUND) {
      free(detail);
      return;
    }
    file_result(status, detail, rc);
    ++*completed;
  });
}
