/* CRC32-Castagnoli (reflected, poly 0x82F63B78) for the keys.enc v3
 * header checksum. Project-owned table implementation.
 * Byte-identical to Go hash/crc32 with the Castagnoli table:
 * Checksum("123456789") == 0xE3069283.
 */
#ifndef MURMUR_CRC32C_H
#define MURMUR_CRC32C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t murmur_crc32c(const uint8_t *in, size_t len);

#ifdef __cplusplus
}
#endif

#endif
