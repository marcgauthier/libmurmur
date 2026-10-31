/* murmur postcard - the schema-less Rust `postcard` v1 wire format:
 * 8-bit integers raw, wider integers LEB128 (zig-zag signed),
 * floats little-endian fixed, bytes/strings length-prefixed,
 * options as 0/1 tags, enums as varint index plus fields.
 * Byte-exact with murmur/internal/postcard (itself validated
 * against the Rust crate); file frames and metadata persist and
 * cross the wire in this format.
 */
#ifndef MURMUR_POSTCARD_H
#define MURMUR_POSTCARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  MURMUR_PC_OK = 0,
  MURMUR_PC_TRUNCATED = 1,
  MURMUR_PC_OVERFLOW = 2,
  MURMUR_PC_VALUE = 3,
  MURMUR_PC_TRAILING = 4,
} murmur_pc_status_t;

/* ---- encoder (zero value ready; finish frees) ---- */
typedef struct {
  uint8_t *b;
  size_t len, cap;
} murmur_pc_enc_t;

void murmur_pc_enc_init(murmur_pc_enc_t *e);
void murmur_pc_enc_finish(murmur_pc_enc_t *e);
void murmur_pc_u8(murmur_pc_enc_t *e, uint8_t v);
void murmur_pc_i8(murmur_pc_enc_t *e, int8_t v);
void murmur_pc_u16(murmur_pc_enc_t *e, uint16_t v);
void murmur_pc_u32(murmur_pc_enc_t *e, uint32_t v);
void murmur_pc_u64(murmur_pc_enc_t *e, uint64_t v);
void murmur_pc_i16(murmur_pc_enc_t *e, int16_t v);
void murmur_pc_i32(murmur_pc_enc_t *e, int32_t v);
void murmur_pc_i64(murmur_pc_enc_t *e, int64_t v);
void murmur_pc_bool(murmur_pc_enc_t *e, int v);
void murmur_pc_f32(murmur_pc_enc_t *e, float v);
void murmur_pc_f64(murmur_pc_enc_t *e, double v);
void murmur_pc_raw(murmur_pc_enc_t *e, const uint8_t *b, size_t n);
void murmur_pc_len(murmur_pc_enc_t *e, size_t n);
void murmur_pc_bytes(murmur_pc_enc_t *e, const uint8_t *b, size_t n);
void murmur_pc_str(murmur_pc_enc_t *e, const uint8_t *s, size_t n);
void murmur_pc_disc(murmur_pc_enc_t *e, uint32_t v);
void murmur_pc_none(murmur_pc_enc_t *e);
void murmur_pc_some(murmur_pc_enc_t *e);

/* ---- decoder (sticky first error, zero values after; raw
 * bytes/strings borrow the input) ---- */
typedef struct {
  const uint8_t *b;
  size_t len, off;
  murmur_pc_status_t err;
} murmur_pc_dec_t;

void murmur_pc_dec_init(murmur_pc_dec_t *d, const uint8_t *b, size_t n);
murmur_pc_status_t murmur_pc_end(murmur_pc_dec_t *d);
void murmur_pc_fail(murmur_pc_dec_t *d, murmur_pc_status_t st);
uint8_t murmur_pc_g_u8(murmur_pc_dec_t *d);
int8_t murmur_pc_g_i8(murmur_pc_dec_t *d);
uint16_t murmur_pc_g_u16(murmur_pc_dec_t *d);
uint32_t murmur_pc_g_u32(murmur_pc_dec_t *d);
uint64_t murmur_pc_g_u64(murmur_pc_dec_t *d);
uint32_t murmur_pc_g_disc(murmur_pc_dec_t *d);
int16_t murmur_pc_g_i16(murmur_pc_dec_t *d);
int32_t murmur_pc_g_i32(murmur_pc_dec_t *d);
int64_t murmur_pc_g_i64(murmur_pc_dec_t *d);
int murmur_pc_g_bool(murmur_pc_dec_t *d);
float murmur_pc_g_f32(murmur_pc_dec_t *d);
double murmur_pc_g_f64(murmur_pc_dec_t *d);
/* Borrow n bytes (NULL on error); out points into the input. */
const uint8_t *murmur_pc_g_raw(murmur_pc_dec_t *d, size_t n);
size_t murmur_pc_g_len(murmur_pc_dec_t *d);
const uint8_t *murmur_pc_g_bytes(murmur_pc_dec_t *d, size_t *n);
const uint8_t *murmur_pc_g_str(murmur_pc_dec_t *d, size_t *n);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_POSTCARD_H */
