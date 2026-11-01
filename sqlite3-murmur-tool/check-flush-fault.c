/* Test-only link seam: prove that a failed close barrier cannot report success. */
#include <stdint.h>
#include <stdlib.h>
#include "sqlite3.h"

int __real_nvStoreFlush(uint64_t handle);
int __wrap_nvStoreFlush(uint64_t handle) {
  int rc = __real_nvStoreFlush(handle);
  return getenv("MURMUR_CLI_TEST_FLUSH_FAILURE") ? SQLITE_IOERR : rc;
}
