#ifndef MURMUR_OS_RANDOM_H
#define MURMUR_OS_RANDOM_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
static inline int murmur_os_random(uint8_t *out, size_t n) {
  while (n) {
    ULONG chunk = n > 1048576 ? 1048576 : (ULONG)n;
    if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return 0;
    out += chunk; n -= chunk;
  }
  return 1;
}
#else
#include <errno.h>
#include <stdio.h>
#ifdef __linux__
#include <sys/random.h>
#endif
static inline int murmur_os_random(uint8_t *out, size_t n) {
#ifdef __linux__
  while (n) {
    ssize_t got = getrandom(out, n, 0);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) break;
    out += got; n -= (size_t)got;
  }
#endif
  if (!n) return 1;
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) return 0;
  size_t got = fread(out, 1, n, f);
  fclose(f);
  return got == n;
}
#endif
#endif
