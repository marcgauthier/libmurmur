/* Canonical signed origin envelopes. Verification does not advance progress;
 * receivers must commit effects and duplicate receipts atomically. */
#ifndef MURMUR_ORIGIN_H
#define MURMUR_ORIGIN_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
  uint8_t database[16], origin[16], transaction[16];
  uint64_t sequence, millis;
  uint32_t logical;
  uint8_t schema[32], payload_digest[32], signature[64];
} murmur_origin_envelope_t;
#define MURMUR_ORIGIN_ENVELOPE_BYTES 200
/* Fixed MOR2 header and canonical little-endian fields. No struct padding.
 * Encode requires 200 bytes; decode rejects other lengths and sequence 0. */
int murmur_origin_envelope_encode(const murmur_origin_envelope_t *,void *,size_t);
int murmur_origin_envelope_decode(const void *,size_t,murmur_origin_envelope_t *);
int murmur_origin_public_key(const uint8_t seed[32], uint8_t public_key[32]);
int murmur_origin_sign(murmur_origin_envelope_t *, const uint8_t seed[32],
                       const void *payload, size_t payload_len);
int murmur_origin_verify(const murmur_origin_envelope_t *,
                         const uint8_t database[16], const uint8_t origin[16],
                         const uint8_t public_key[32], const void *payload,
                         size_t payload_len, size_t max_payload);
#ifdef __cplusplus
}
#endif
#endif
