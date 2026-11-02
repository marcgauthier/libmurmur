#include "bridge_sender.h"
#include "bridge_capture.h"
#include "bridge_capture_internal.h"
#include "bridge_files_internal.h"
#include "bridge_peer_internal.h"
#include "bridge_worker_internal.h"
#include "kv.h"
#include "sqlite3.h"
#include <array>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <string>

struct murmur_bridge_sender {
  sqlite3 *db;
  std::array<uint8_t, 16> source;
  std::string stream, directory;
  bool prepare;
  BridgeFileExporter *files = nullptr;
  std::mutex status_lock;
  murmur_bridge_sender_status_t status{};
  BridgeWorker worker;
};
namespace {
struct Lock {
  Lock() { murmur_db_writer_lock(); }
  ~Lock() { murmur_db_writer_unlock(); }
};
int poll(murmur_bridge_sender &s, size_t count) {
  murmur_bridge_sender_status_t delta{};
  int rc = SQLITE_OK;
  bool empty = false;
  for (size_t i = 0; i < count; ++i) {
    if (s.worker.stopping())
      break;
    Lock lock;
    if (!bridge_capture_exports(s.db, s.source.data(), s.stream.c_str())) {
      rc = SQLITE_MISUSE;
      break;
    }
    rc = murmur_bridge_publish(s.db, s.source.data(), s.stream.c_str(),
                               s.directory.c_str());
    if (rc == SQLITE_NOTFOUND) {
      rc = SQLITE_OK;
      empty = true;
      break;
    }
    if (rc != SQLITE_OK)
      break;
    ++delta.published;
  }
  if (rc == SQLITE_OK && empty && s.prepare) {
    bool done;
    {
      std::lock_guard<std::mutex> guard(s.status_lock);
      done = s.status.baseline_complete;
    }
    if (!done) {
      Lock lock;
      size_t captured = 0;
      rc = murmur_bridge_capture_prepare(s.db, 256, &captured);
      if (rc == SQLITE_NOTFOUND) {
        rc = SQLITE_OK;
        delta.baseline_complete = 1;
      }
      if (rc == SQLITE_OK)
        delta.baseline_rows = captured;
    }
  }
  if (rc == SQLITE_OK && empty && s.files && !s.worker.stopping())
    rc = bridge_files_export_step(
        s.files, 256, [&s] { return s.worker.stopping(); }, &delta.file_parts);
  std::lock_guard<std::mutex> guard(s.status_lock);
  s.status.published += delta.published;
  s.status.file_parts += delta.file_parts;
  s.status.baseline_rows += delta.baseline_rows;
  s.status.baseline_complete |= delta.baseline_complete;
  s.status.last_result = rc;
  return rc;
}
} // namespace
extern "C" int murmur_bridge_sender_new(sqlite3 *db, const uint8_t source[16],
                                        const char *stream,
                                        const char *directory, int prepare,
                                        murmur_bridge_sender_t **out) {
  if (out)
    *out = nullptr;
  if (!db || !source || !stream || !directory || !*directory || !out ||
      (prepare != 0 && prepare != 1))
    return SQLITE_MISUSE;
  try {
    // Match against attached capture before copying caller-controlled strings.
    Lock lock;
    if (!sqlite3_get_autocommit(db) ||
        (!bridge_capture_exports(db, source, stream) ||
         !bridge_peer_exporter(db)))
      return SQLITE_MISUSE;
    auto st =
        std::filesystem::symlink_status(std::filesystem::u8path(directory));
    if (!std::filesystem::is_directory(st) || std::filesystem::is_symlink(st))
      return SQLITE_CANTOPEN;
    std::unique_ptr<murmur_bridge_sender> s(new murmur_bridge_sender);
    s->db = db;
    std::copy(source, source + 16, s->source.begin());
    s->stream = stream;
    s->directory = directory;
    s->prepare = prepare;
    s->status.baseline_complete = !prepare;
    *out = s.release();
    return SQLITE_OK;
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_CANTOPEN;
  }
}
extern "C" int murmur_bridge_sender_files(murmur_bridge_sender_t *s,
                                          murmur_files_t *files) {
  if (!s || !files || murmur_files_database(files) != s->db)
    return SQLITE_MISUSE;
  return s->worker.manual([&] {
    int rc = bridge_files_init(s->db);
    if (rc != SQLITE_OK)
      return rc;
    try {
      auto next = bridge_files_exporter_new(s->db, files, s->source.data(),
                                            s->stream.c_str());
      bridge_files_exporter_free(s->files);
      s->files = next;
      return SQLITE_OK;
    } catch (const std::bad_alloc &) {
      return SQLITE_NOMEM;
    } catch (...) {
      return SQLITE_ERROR;
    }
  });
}
extern "C" int murmur_bridge_sender_poll(murmur_bridge_sender_t *s,
                                         size_t count) {
  if (!s || !count || count > 256)
    return SQLITE_MISUSE;
  return s->worker.manual([s, count] { return poll(*s, count); });
}
extern "C" int murmur_bridge_sender_start(murmur_bridge_sender_t *s,
                                          unsigned interval) {
  if (!s)
    return SQLITE_MISUSE;
  return s->worker.start(interval, [s] { poll(*s, 256); });
}
extern "C" void murmur_bridge_sender_stop(murmur_bridge_sender_t *s) {
  if (s)
    s->worker.stop();
}
extern "C" void
murmur_bridge_sender_status(murmur_bridge_sender_t *s,
                            murmur_bridge_sender_status_t *out) {
  if (!out)
    return;
  *out = {};
  if (!s)
    return;
  std::lock_guard<std::mutex> guard(s->status_lock);
  *out = s->status;
}
extern "C" void murmur_bridge_sender_free(murmur_bridge_sender_t *s) {
  murmur_bridge_sender_stop(s);
  if (s)
    bridge_files_exporter_free(s->files);
  delete s;
}
