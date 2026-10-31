/* CRC32-Castagnoli, reflected (poly 0x82F63B78), init/xorout all-ones.
 * Matches Go hash/crc32 with the Castagnoli table.
 */
#include "crc32c.h"

static uint32_t table[256];
static int table_ready = 0;

static void build_table(void) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int k = 0; k < 8; k++) {
      c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
    }
    table[i] = c;
  }
  table_ready = 1;
}

uint32_t murmur_crc32c(const uint8_t *in, size_t len) {
  /* Single-threaded init race is benign: every thread writes the
   * same deterministic table. (Keyring calls are cold-path.) */
  if (!table_ready) {
    build_table();
  }
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    c = table[(c ^ in[i]) & 0xFF] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFFu;
}
