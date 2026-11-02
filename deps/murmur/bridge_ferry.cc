#include "bridge_ferry.h"
#include "../keyring/sha256.h"
#include "bridge_artifact_internal.h"
#include "bridge_capture_internal.h"
#include "bridge_files_internal.h"
#include "bridge_peer_source_internal.h"
#include "bridge_worker_internal.h"
#include "kv.h"
#include "managed_value.h"
#include "open.h"
#include "sqlite3.h"
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

struct murmur_bridge_receiver {
  sqlite3 *db;
  murmur_files_t *files = nullptr;
  std::array<uint8_t, 16> source, exporter;
  std::array<uint8_t, 32> secret;
  std::vector<std::array<uint8_t, 32>> signers;
  std::string stream;
  std::filesystem::path directory, quarantine;
  uint64_t capacity;
  std::filesystem::directory_iterator cursor, end;
  std::mutex polling, status_lock;
  BridgeWorker worker;
  murmur_bridge_ferry_status_t status{};
  ~murmur_bridge_receiver() {
    volatile uint8_t *p = secret.data();
    for (size_t i = 0; i < secret.size(); ++i)
      p[i] = 0;
  }
};
namespace {
struct Lock {
  Lock() { murmur_db_writer_lock(); }
  ~Lock() { murmur_db_writer_unlock(); }
};
struct Statement {
  sqlite3_stmt *p = nullptr;
  ~Statement() { sqlite3_finalize(p); }
};
bool nonzero(const uint8_t *p, size_t n) {
  uint8_t v = 0;
  for (size_t i = 0; i < n; ++i)
    v |= p[i];
  return v != 0;
}
bool filename(const std::string &s, uint8_t digest[32]) {
  if (s.size() != 71 || s.compare(64, 7, ".bundle"))
    return false;
  for (size_t i = 0; i < 32; ++i) {
    unsigned v = 0;
    for (size_t j = 0; j < 2; ++j) {
      char c = s[2 * i + j];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        return false;
      v = 16 * v + (c <= '9' ? c - '0' : c - 'a' + 10);
    }
    digest[i] = (uint8_t)v;
  }
  return true;
}
int read_artifact(const std::filesystem::path &dir, const std::string &name,
                  std::vector<uint8_t> &out) {
#ifdef _WIN32
  struct File {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~File() {
      if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
    }
  } f;
  f.h =
      CreateFileW((dir / name).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (f.h == INVALID_HANDLE_VALUE)
    return SQLITE_CANTOPEN;
  BY_HANDLE_FILE_INFORMATION info{};
  LARGE_INTEGER size{};
  if (!GetFileInformationByHandle(f.h, &info) || !GetFileSizeEx(f.h, &size))
    return SQLITE_IOERR_FSTAT;
  if (info.dwFileAttributes &
      (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
    return SQLITE_AUTH;
  if (size.QuadPart < 345 || size.QuadPart > MURMUR_BRIDGE_MAX_BUNDLE)
    return SQLITE_TOOBIG;
  out.resize((size_t)size.QuadPart);
  size_t off = 0;
  while (off < out.size()) {
    DWORD got = 0;
    if (!ReadFile(f.h, out.data() + off, (DWORD)(out.size() - off), &got,
                  nullptr) ||
        !got)
      return SQLITE_IOERR_READ;
    off += got;
  }
#else
  struct File {
    int fd = -1;
    ~File() {
      if (fd >= 0)
        close(fd);
    }
  } d, f;
  d.fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (d.fd < 0)
    return SQLITE_CANTOPEN;
  f.fd = openat(d.fd, name.c_str(),
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (f.fd < 0)
    return errno == ELOOP ? SQLITE_AUTH : SQLITE_CANTOPEN;
  struct stat st{};
  if (fstat(f.fd, &st))
    return SQLITE_IOERR_FSTAT;
  if (!S_ISREG(st.st_mode))
    return SQLITE_AUTH;
  if (st.st_size < 345 || st.st_size > MURMUR_BRIDGE_MAX_BUNDLE)
    return SQLITE_TOOBIG;
  out.resize((size_t)st.st_size);
  size_t off = 0;
  while (off < out.size()) {
    ssize_t got = read(f.fd, out.data() + off, out.size() - off);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0)
      return SQLITE_IOERR_READ;
    off += (size_t)got;
  }
  uint8_t extra;
  ssize_t got;
  do {
    got = read(f.fd, &extra, 1);
  } while (got < 0 && errno == EINTR);
  if (got != 0)
    return SQLITE_IOERR_READ;
#endif
  return SQLITE_OK;
}
// Query helpers execute only under writer admission.
int known(murmur_bridge_receiver &r, const uint8_t digest[32], bool &found) {
  Statement q;
  int rc = sqlite3_prepare_v2(r.db,
                              "SELECT 1 FROM murmur_bridge_receipt WHERE "
                              "source=? AND stream=? AND digest=? LIMIT 1",
                              -1, &q.p, nullptr);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_blob(q.p, 1, r.source.data(), 16, SQLITE_STATIC);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_text(q.p, 2, r.stream.c_str(), -1, SQLITE_STATIC);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_blob(q.p, 3, digest, 32, SQLITE_STATIC);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  found = rc == SQLITE_ROW;
  return rc == SQLITE_ROW || rc == SQLITE_DONE ? SQLITE_OK : rc;
}
int progress(murmur_bridge_receiver &r, uint64_t &next) {
  Statement q;
  int rc = sqlite3_prepare_v2(
      r.db,
      "SELECT applied FROM murmur_bridge_lane WHERE source=? AND stream=?", -1,
      &q.p, nullptr);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_blob(q.p, 1, r.source.data(), 16, SQLITE_STATIC);
  if (rc == SQLITE_OK)
    rc = sqlite3_bind_text(q.p, 2, r.stream.c_str(), -1, SQLITE_STATIC);
  if (rc != SQLITE_OK)
    return rc;
  rc = sqlite3_step(q.p);
  next = 1;
  if (rc == SQLITE_ROW) {
    sqlite3_int64 n = sqlite3_column_int64(q.p, 0);
    if (n < 0 || n == std::numeric_limits<sqlite3_int64>::max())
      return SQLITE_FULL;
    next = (uint64_t)n + 1;
    return SQLITE_OK;
  }
  return rc == SQLITE_DONE ? SQLITE_OK : rc;
}
int reject(murmur_bridge_receiver &r, const std::vector<uint8_t> &data,
           const uint8_t digest[32], murmur_bridge_ferry_status_t &status) {
  ++status.rejected;
  if (r.quarantine.empty())
    return SQLITE_OK;
  // Serialize quota checks across all native receivers. Quarantine directories
  // are operator-owned, never shared with untrusted external writers.
  static std::mutex quota;
  std::lock_guard<std::mutex> guard(quota);
  try {
    size_t count = 0;
    uint64_t bytes = 0;
    bool exists = false;
    for (const auto &entry :
         std::filesystem::directory_iterator(r.quarantine)) {
      if (++count > 1024)
        return SQLITE_FULL;
      auto st = entry.symlink_status();
      if (!std::filesystem::is_regular_file(st))
        return SQLITE_AUTH;
      auto size = entry.file_size();
      if (size > (64u << 20) || bytes > (64u << 20) - size)
        return SQLITE_FULL;
      bytes += size;
      uint8_t seen[32];
      if (filename(entry.path().filename().u8string(), seen) &&
          !memcmp(seen, digest, 32))
        exists = true;
    }
    if (!exists && (count >= 1024 || bytes > (64u << 20) - data.size()))
      return SQLITE_FULL;
    return bridge_artifact_publish(r.quarantine.u8string().c_str(), data.data(),
                                   data.size());
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_IOERR;
  }
}
int import_payload(sqlite3 *db, const murmur_bridge_header_t *header,
                   const void *payload, size_t len, void *arg) {
  auto &r = *static_cast<murmur_bridge_receiver *>(arg);
  if (!bridge_capture_accepts(db, header->database))
    return SQLITE_AUTH;
  int rc = SQLITE_OK;
  if (len >= 4 && !memcmp(payload, "MBF1", 4)) {
    if (!r.files)
      return SQLITE_SCHEMA;
    rc = bridge_files_stage(db, header, payload, len, r.capacity);
  } else
    rc = bridge_rows_import(db, header, payload, len);
  return rc == SQLITE_OK ? bridge_peer_received(db, header) : rc;
}
int artifact(murmur_bridge_receiver &r, const std::string &name,
             const uint8_t digest[32], murmur_bridge_ferry_status_t &s) {
  {
    Lock lock;
    bool found = false;
    int rc = known(r, digest, found);
    if (rc != SQLITE_OK)
      return rc;
    if (found) {
      ++s.duplicate;
      return SQLITE_OK;
    }
  }
  std::vector<uint8_t> data;
  int rc = read_artifact(r.directory, name, data);
  if (rc == SQLITE_AUTH || rc == SQLITE_TOOBIG) {
    ++s.rejected;
    return SQLITE_OK;
  }
  if (rc != SQLITE_OK)
    return rc;
  uint8_t actual[32];
  murmur_sha256(data.data(), data.size(), actual);
  if (memcmp(actual, digest, 32)) {
    return reject(r, data, actual, s);
  }
  // Untrusted routing hints only skip unrelated streams. Authentication below
  // is mandatory before using the header, sequence or typed payload.
  if (data.size() < 345 || memcmp(data.data(), "MHB1", 4)) {
    return reject(r, data, actual, s);
  }
  if (memcmp(data.data() + 4, r.source.data(), 16) ||
      data[60] != r.stream.size() ||
      memcmp(data.data() + 61, r.stream.data(), r.stream.size()))
    return SQLITE_OK;
  murmur_bridge_header_t h{};
  size_t trusted = 0;
  for (; trusted < r.signers.size(); ++trusted) {
    murmur_bridge_bytes_t payload{};
    rc = murmur_bridge_unseal(data.data(), data.size(), r.source.data(),
                              r.stream.c_str(), r.signers[trusted].data(),
                              r.secret.data(), MURMUR_BRIDGE_MAX_BUNDLE,
                              MURMUR_BRIDGE_MAX_PAYLOAD, &h, &payload);
    murmur_bridge_bytes_free(&payload);
    if (rc == SQLITE_OK)
      break;
    if (rc != SQLITE_AUTH) {
      if (rc == SQLITE_NOMEM)
        return rc;
      break;
    }
  }
  if (rc != SQLITE_OK || memcmp(h.node, r.exporter.data(), 16)) {
    return reject(r, data, actual, s);
  }
  Lock lock;
  uint64_t next = 0;
  rc = progress(r, next);
  if (rc != SQLITE_OK)
    return rc;
  if (h.sequence > next) {
    ++s.deferred;
    return SQLITE_OK;
  }
  rc = murmur_bridge_store_stage(
      r.db, data.data(), data.size(), r.source.data(), r.stream.c_str(),
      r.signers[trusted].data(), r.secret.data(), MURMUR_BRIDGE_MAX_BUNDLE,
      MURMUR_BRIDGE_MAX_PAYLOAD, r.capacity);
  if (rc == SQLITE_AUTH)
    return reject(r, data, actual, s);
  if (rc != SQLITE_OK)
    return rc;
  if (h.sequence < next) {
    ++s.duplicate;
    return SQLITE_OK;
  }
  uint8_t schema[32];
  rc = murmur_bridge_rows_schema(r.db, schema);
  if (rc == SQLITE_OK)
    rc = murmur_bridge_store_apply(
        r.db, r.source.data(), r.stream.c_str(), r.signers[trusted].data(),
        r.secret.data(), schema, MURMUR_BRIDGE_MAX_BUNDLE,
        MURMUR_BRIDGE_MAX_PAYLOAD, import_payload, &r);
  if (rc == SQLITE_SCHEMA) {
    ++s.deferred;
    return SQLITE_OK;
  }
  if (rc != SQLITE_OK)
    return rc;
  ++s.applied;
  return SQLITE_OK;
}
int poll(murmur_bridge_receiver &r, size_t count) {
  std::lock_guard<std::mutex> serial(r.polling);
  murmur_bridge_ferry_status_t delta{};
  int rc = SQLITE_OK;
  try {
    if (r.files) {
      rc = bridge_files_finish_one(
          r.db, r.files, r.source.data(), r.stream.c_str(),
          [&r] { return r.worker.stopping(); }, &delta.files_completed);
      if (rc != SQLITE_OK)
        throw ManagedError{rc};
    }
    if (r.cursor == r.end)
      r.cursor = std::filesystem::directory_iterator(r.directory);
    for (size_t n = 0; n < count && r.cursor != r.end; ++n) {
      if (r.worker.stopping())
        break;
      auto name = r.cursor->path().filename().u8string();
      ++r.cursor;
      ++delta.scanned;
      uint8_t digest[32];
      if (!filename(name, digest))
        continue;
      rc = artifact(r, name, digest, delta);
      if (rc != SQLITE_OK)
        break;
    }
  } catch (ManagedError error) {
    rc = error.code;
  } catch (const std::bad_alloc &) {
    rc = SQLITE_NOMEM;
  } catch (...) {
    r.cursor = r.end;
    rc = SQLITE_IOERR;
  }
  std::lock_guard<std::mutex> status(r.status_lock);
  r.status.scanned += delta.scanned;
  r.status.files_completed += delta.files_completed;
  r.status.applied += delta.applied;
  r.status.duplicate += delta.duplicate;
  r.status.deferred += delta.deferred;
  r.status.rejected += delta.rejected;
  r.status.last_result = rc;
  return rc;
}
} // namespace
extern "C" int
murmur_bridge_receiver_new(sqlite3 *db,
                           const murmur_bridge_receiver_config_t *c,
                           murmur_bridge_receiver_t **out) {
  if (out)
    *out = nullptr;
  if (!db || !c || !out || !c->stream || !c->directory || !*c->directory ||
      !c->signer_count || c->signer_count > 8 || !nonzero(c->source, 16) ||
      !nonzero(c->exporter, 16) || !nonzero(c->receiver, 32) ||
      c->staging_bytes < MURMUR_BRIDGE_MAX_BUNDLE ||
      c->staging_bytes > (1ull << 30))
    return SQLITE_MISUSE;
  size_t n = 0;
  for (; n < 65 && c->stream[n]; ++n) {
    char v = c->stream[n];
    if (!((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') ||
          (v >= '0' && v <= '9') || v == '_' || v == '-'))
      return SQLITE_MISUSE;
  }
  if (!n || n > 64)
    return SQLITE_MISUSE;
  for (size_t i = 0; i < c->signer_count; ++i)
    if (!nonzero(c->signers[i], 32))
      return SQLITE_MISUSE;
  try {
    auto r = new murmur_bridge_receiver;
    struct Cleanup {
      murmur_bridge_receiver *r;
      ~Cleanup() { delete r; }
    } cleanup{r};
    r->db = db;
    r->stream = c->stream;
    r->directory = std::filesystem::u8path(c->directory);
    r->capacity = c->staging_bytes;
    if (c->quarantine_directory && *c->quarantine_directory) {
      r->quarantine = std::filesystem::u8path(c->quarantine_directory);
      auto st = std::filesystem::symlink_status(r->quarantine);
      if (!std::filesystem::is_directory(st) ||
          std::filesystem::is_symlink(st) ||
          std::filesystem::equivalent(r->quarantine, r->directory))
        return SQLITE_CANTOPEN;
    }
    std::copy(c->source, c->source + 16, r->source.begin());
    std::copy(c->exporter, c->exporter + 16, r->exporter.begin());
    std::copy(c->receiver, c->receiver + 32, r->secret.begin());
    for (size_t i = 0; i < c->signer_count; ++i) {
      std::array<uint8_t, 32> key;
      std::copy(c->signers[i], c->signers[i] + 32, key.begin());
      r->signers.push_back(key);
    }
    auto st = std::filesystem::symlink_status(r->directory);
    if (!std::filesystem::is_directory(st) || std::filesystem::is_symlink(st))
      return SQLITE_CANTOPEN;
    {
      Lock lock;
      int rc = murmur_bridge_store_init(db);
      if (rc != SQLITE_OK)
        return rc;
    }
    {
      int rc = bridge_peer_source(db, c);
      if (rc != SQLITE_OK)
        return rc;
    }
    *out = r;
    cleanup.r = nullptr;
    return SQLITE_OK;
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_CANTOPEN;
  }
}
extern "C" int murmur_bridge_receiver_files(murmur_bridge_receiver_t *r,
                                            murmur_files_t *files) {
  if (!r || !files || murmur_files_database(files) != r->db)
    return SQLITE_MISUSE;
  return r->worker.manual([&] {
    int rc = bridge_files_init(r->db);
    if (rc == SQLITE_OK)
      r->files = files;
    return rc;
  });
}
extern "C" int murmur_bridge_receiver_poll(murmur_bridge_receiver_t *r,
                                           size_t count) {
  if (!r || !count || count > 256)
    return SQLITE_MISUSE;
  return r->worker.manual([r, count] { return poll(*r, count); });
}
extern "C" int murmur_bridge_receiver_start(murmur_bridge_receiver_t *r,
                                            unsigned interval) {
  if (!r)
    return SQLITE_MISUSE;
  return r->worker.start(interval, [r] { poll(*r, 256); });
}
extern "C" void murmur_bridge_receiver_stop(murmur_bridge_receiver_t *r) {
  if (r)
    r->worker.stop();
}
extern "C" void
murmur_bridge_receiver_status(murmur_bridge_receiver_t *r,
                              murmur_bridge_ferry_status_t *out) {
  if (!out)
    return;
  *out = {};
  if (!r)
    return;
  std::lock_guard<std::mutex> guard(r->status_lock);
  *out = r->status;
}
extern "C" void murmur_bridge_receiver_free(murmur_bridge_receiver_t *r) {
  murmur_bridge_receiver_stop(r);
  delete r;
}
