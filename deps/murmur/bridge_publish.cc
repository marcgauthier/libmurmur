#include "bridge_publish.h"
#include "../codec/aesgcm.h"
#include "../keyring/sha256.h"
#include "bridge_artifact_internal.h"
#include "sqlite3.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <new>
#include <string>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
std::string hex(const uint8_t *b, size_t n) {
  static const char digits[] = "0123456789abcdef";
  std::string s;
  s.reserve(2 * n);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(digits[b[i] >> 4]);
    s.push_back(digits[b[i] & 15]);
  }
  return s;
}
struct Bytes {
  murmur_bridge_bytes_t b{};
  ~Bytes() { murmur_bridge_bytes_free(&b); }
};
#ifdef _WIN32
struct File {
  HANDLE h = INVALID_HANDLE_VALUE;
  ~File() {
    if (h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
  }
};
int publish(const std::filesystem::path &dir, const uint8_t *b, size_t n,
            const std::string &name, const std::string &temp) {
  auto staging = dir / temp, target = dir / name;
  File file;
  file.h = CreateFileW(staging.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file.h == INVALID_HANDLE_VALUE)
    return SQLITE_CANTOPEN;
  struct Cleanup {
    std::filesystem::path p;
    ~Cleanup() { DeleteFileW(p.c_str()); }
  } cleanup{staging};
  size_t off = 0;
  while (off < n) {
    DWORD wrote = 0;
    if (!WriteFile(file.h, b + off, (DWORD)(n - off), &wrote, nullptr) ||
        !wrote)
      return SQLITE_IOERR_WRITE;
    off += wrote;
  }
  if (!FlushFileBuffers(file.h))
    return SQLITE_IOERR_FSYNC;
  if (!CloseHandle(file.h)) {
    file.h = INVALID_HANDLE_VALUE;
    return SQLITE_IOERR_CLOSE;
  }
  file.h = INVALID_HANDLE_VALUE;
  if (MoveFileExW(staging.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH))
    return SQLITE_OK;
  if (GetLastError() != ERROR_ALREADY_EXISTS &&
      GetLastError() != ERROR_FILE_EXISTS)
    return SQLITE_IOERR;
  File existing;
  existing.h =
      CreateFileW(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                  OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (existing.h == INVALID_HANDLE_VALUE)
    return SQLITE_IOERR;
  BY_HANDLE_FILE_INFORMATION info{};
  LARGE_INTEGER size{};
  if (!GetFileInformationByHandle(existing.h, &info) ||
      (info.dwFileAttributes &
       (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
      !GetFileSizeEx(existing.h, &size) || size.QuadPart != (LONGLONG)n)
    return SQLITE_AUTH;
  uint8_t buf[65536];
  off = 0;
  while (off < n) {
    DWORD got = 0;
    size_t want = std::min(sizeof(buf), n - off);
    if (!ReadFile(existing.h, buf, (DWORD)want, &got, nullptr) || got != want ||
        memcmp(buf, b + off, got))
      return SQLITE_AUTH;
    off += got;
  }
  if (!CloseHandle(existing.h)) {
    existing.h = INVALID_HANDLE_VALUE;
    return SQLITE_IOERR_CLOSE;
  }
  existing.h = INVALID_HANDLE_VALUE;
  return MoveFileExW(staging.c_str(), target.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
             ? SQLITE_OK
             : SQLITE_IOERR;
}
#else
struct File {
  int fd = -1;
  ~File() {
    if (fd >= 0)
      close(fd);
  }
};
int publish(const std::filesystem::path &dir, const uint8_t *b, size_t n,
            const std::string &name, const std::string &temp) {
  File directory;
  directory.fd =
      open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory.fd < 0)
    return SQLITE_CANTOPEN;
  File file;
  file.fd = openat(directory.fd, temp.c_str(),
                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (file.fd < 0)
    return SQLITE_CANTOPEN;
  struct Cleanup {
    int fd;
    const std::string &name;
    ~Cleanup() { unlinkat(fd, name.c_str(), 0); }
  } cleanup{directory.fd, temp};
  size_t off = 0;
  while (off < n) {
    ssize_t wrote = write(file.fd, b + off, n - off);
    if (wrote < 0 && errno == EINTR)
      continue;
    if (wrote <= 0)
      return SQLITE_IOERR_WRITE;
    off += (size_t)wrote;
  }
  if (fsync(file.fd))
    return SQLITE_IOERR_FSYNC;
  /* linkat does not replace an existing artifact. Readers see the complete
   * synced file immediately; unlinking the temporary name is cleanup only. */
  if (linkat(directory.fd, temp.c_str(), directory.fd, name.c_str(), 0)) {
    if (errno != EEXIST)
      return SQLITE_IOERR;
    File existing;
    existing.fd =
        openat(directory.fd, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (existing.fd < 0)
      return SQLITE_AUTH;
    struct stat st{};
    if (fstat(existing.fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size != (off_t)n)
      return SQLITE_AUTH;
    uint8_t buf[65536];
    off = 0;
    while (off < n) {
      size_t want = std::min(sizeof(buf), n - off);
      ssize_t got = read(existing.fd, buf, want);
      if (got < 0 && errno == EINTR)
        continue;
      if (got <= 0 || memcmp(buf, b + off, (size_t)got))
        return SQLITE_AUTH;
      off += (size_t)got;
    }
    if (fsync(existing.fd))
      return SQLITE_IOERR_FSYNC;
  }
  return fsync(directory.fd) == 0 ? SQLITE_OK : SQLITE_IOERR_FSYNC;
}
#endif
} // namespace
int bridge_artifact_publish(const char *directory, const void *data,
                            size_t len) {
  if (!directory || !*directory || !data || !len ||
      len > MURMUR_BRIDGE_MAX_BUNDLE)
    return SQLITE_MISUSE;
  try {
    uint8_t digest[32], random[16];
    murmur_sha256(static_cast<const uint8_t *>(data), len, digest);
    if (murmur_rand_bytes(random, sizeof(random)))
      return SQLITE_ERROR;
    return publish(
        std::filesystem::u8path(directory), static_cast<const uint8_t *>(data),
        len, hex(digest, 32) + ".bundle", "." + hex(random, 16) + ".pending");
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_IOERR;
  }
}
extern "C" int murmur_bridge_publish(sqlite3 *db, const uint8_t source[16],
                                     const char *stream,
                                     const char *directory) {
  if (!directory || !*directory)
    return SQLITE_MISUSE;
  try {
    Bytes bytes;
    uint64_t sequence = 0;
    int rc = murmur_bridge_store_next(db, source, stream, &sequence, &bytes.b);
    if (rc != SQLITE_OK)
      return rc;
    rc = bridge_artifact_publish(directory, bytes.b.data, bytes.b.len);
    return rc == SQLITE_OK
               ? murmur_bridge_store_ack(db, source, stream, sequence)
               : rc;
  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  } catch (...) {
    return SQLITE_IOERR;
  }
}
