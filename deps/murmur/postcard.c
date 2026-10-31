/* murmur postcard - see postcard.h. */
#include "postcard.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "msgcodec.h" /* murmur_utf8_valid */

void murmur_pc_enc_init(murmur_pc_enc_t *e) {
  memset(e, 0, sizeof(*e));
}

void murmur_pc_enc_finish(murmur_pc_enc_t *e) {
  free(e->b);
  memset(e, 0, sizeof(*e));
}

static void need(murmur_pc_enc_t *e, size_t more) {
  if (e->len + more <= e->cap) {
    return;
  }
  size_t ncap = e->cap ? e->cap * 2 : 64;
  while (ncap < e->len + more) {
    ncap *= 2;
  }
  uint8_t *nb = (uint8_t *)realloc(e->b, ncap);
  if (!nb) {
    return;
  }
  e->b = nb;
  e->cap = ncap;
}

static void put(murmur_pc_enc_t *e, uint8_t v) {
  need(e, 1);
  if (e->len < e->cap) {
    e->b[e->len++] = v;
  }
}

static void uvarint(murmur_pc_enc_t *e, uint64_t v) {
  while (v >= 0x80) {
    put(e, (uint8_t)v | 0x80);
    v >>= 7;
  }
  put(e, (uint8_t)v);
}

void murmur_pc_u8(murmur_pc_enc_t *e, uint8_t v) { put(e, v); }
void murmur_pc_i8(murmur_pc_enc_t *e, int8_t v) { put(e, (uint8_t)v); }
void murmur_pc_u16(murmur_pc_enc_t *e, uint16_t v) { uvarint(e, v); }
void murmur_pc_u32(murmur_pc_enc_t *e, uint32_t v) { uvarint(e, v); }
void murmur_pc_u64(murmur_pc_enc_t *e, uint64_t v) { uvarint(e, v); }

void murmur_pc_i16(murmur_pc_enc_t *e, int16_t v) {
  int32_t x = v;
  uvarint(e, (uint64_t)((uint32_t)(x << 1) ^ (uint32_t)(x >> 31)));
}

void murmur_pc_i32(murmur_pc_enc_t *e, int32_t v) {
  uvarint(e, (uint64_t)((uint32_t)(v << 1) ^ (uint32_t)(v >> 31)));
}

void murmur_pc_i64(murmur_pc_enc_t *e, int64_t v) {
  uvarint(e, (uint64_t)(v << 1) ^ (uint64_t)(v >> 63));
}

void murmur_pc_bool(murmur_pc_enc_t *e, int v) { put(e, v ? 1 : 0); }

void murmur_pc_f32(murmur_pc_enc_t *e, float v) {
  uint32_t b = 0;
  memcpy(&b, &v, 4);
  put(e, (uint8_t)b);
  put(e, (uint8_t)(b >> 8));
  put(e, (uint8_t)(b >> 16));
  put(e, (uint8_t)(b >> 24));
}

void murmur_pc_f64(murmur_pc_enc_t *e, double v) {
  uint64_t b = 0;
  memcpy(&b, &v, 8);
  for (int i = 0; i < 8; i++) {
    put(e, (uint8_t)(b >> (8 * i)));
  }
}

void murmur_pc_raw(murmur_pc_enc_t *e, const uint8_t *b, size_t n) {
  if (n == 0) {
    return;
  }
  need(e, n);
  if (e->len + n <= e->cap) {
    memcpy(e->b + e->len, b, n);
    e->len += n;
  }
}

void murmur_pc_len(murmur_pc_enc_t *e, size_t n) {
  uvarint(e, (uint64_t)n);
}

void murmur_pc_bytes(murmur_pc_enc_t *e, const uint8_t *b, size_t n) {
  uvarint(e, (uint64_t)n);
  murmur_pc_raw(e, b, n);
}

void murmur_pc_str(murmur_pc_enc_t *e, const uint8_t *s, size_t n) {
  murmur_pc_bytes(e, s, n);
}

void murmur_pc_disc(murmur_pc_enc_t *e, uint32_t v) { uvarint(e, v); }
void murmur_pc_none(murmur_pc_enc_t *e) { put(e, 0); }
void murmur_pc_some(murmur_pc_enc_t *e) { put(e, 1); }

void murmur_pc_dec_init(murmur_pc_dec_t *d, const uint8_t *b, size_t n) {
  d->b = b;
  d->len = n;
  d->off = 0;
  d->err = MURMUR_PC_OK;
}

murmur_pc_status_t murmur_pc_end(murmur_pc_dec_t *d) {
  if (d->err != MURMUR_PC_OK) {
    return d->err;
  }
  if (d->off != d->len) {
    return MURMUR_PC_TRAILING;
  }
  return MURMUR_PC_OK;
}

void murmur_pc_fail(murmur_pc_dec_t *d, murmur_pc_status_t st) {
  if (d->err == MURMUR_PC_OK) {
    d->err = st;
  }
}

static uint8_t byte(murmur_pc_dec_t *d) {
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  if (d->off >= d->len) {
    murmur_pc_fail(d, MURMUR_PC_TRUNCATED);
    return 0;
  }
  return d->b[d->off++];
}

static uint64_t uvarint_dec(murmur_pc_dec_t *d) {
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  uint64_t v = 0;
  for (int i = 0; i < 10; i++) {
    if (d->off >= d->len) {
      murmur_pc_fail(d, MURMUR_PC_TRUNCATED);
      return 0;
    }
    uint8_t b = d->b[d->off++];
    if (i == 9 && b > 1) {
      murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
      return 0;
    }
    v |= (uint64_t)(b & 0x7F) << (7 * i);
    if ((b & 0x80) == 0) {
      return v;
    }
  }
  murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
  return 0;
}

uint8_t murmur_pc_g_u8(murmur_pc_dec_t *d) { return byte(d); }
int8_t murmur_pc_g_i8(murmur_pc_dec_t *d) { return (int8_t)byte(d); }

uint16_t murmur_pc_g_u16(murmur_pc_dec_t *d) {
  uint64_t v = uvarint_dec(d);
  if (d->err == MURMUR_PC_OK && v > 0xFFFFu) {
    murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
  }
  return (uint16_t)v;
}

uint32_t murmur_pc_g_u32(murmur_pc_dec_t *d) {
  uint64_t v = uvarint_dec(d);
  if (d->err == MURMUR_PC_OK && v > 0xFFFFFFFFu) {
    murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
  }
  return (uint32_t)v;
}

uint64_t murmur_pc_g_u64(murmur_pc_dec_t *d) { return uvarint_dec(d); }
uint32_t murmur_pc_g_disc(murmur_pc_dec_t *d) { return murmur_pc_g_u32(d); }

static int64_t zigzag64(uint64_t n) {
  return (int64_t)(n >> 1) ^ -(int64_t)(n & 1);
}

int16_t murmur_pc_g_i16(murmur_pc_dec_t *d) {
  uint64_t n = uvarint_dec(d);
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  int64_t v = zigzag64(n);
  if (v > 32767 || v < -32768) {
    murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
  }
  return (int16_t)v;
}

int32_t murmur_pc_g_i32(murmur_pc_dec_t *d) {
  uint64_t n = uvarint_dec(d);
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  int64_t v = zigzag64(n);
  if (v > 2147483647LL || v < -2147483648LL) {
    murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
  }
  return (int32_t)v;
}

int64_t murmur_pc_g_i64(murmur_pc_dec_t *d) {
  uint64_t n = uvarint_dec(d);
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  return zigzag64(n);
}

int murmur_pc_g_bool(murmur_pc_dec_t *d) {
  uint8_t b = byte(d);
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  if (b > 1) {
    murmur_pc_fail(d, MURMUR_PC_VALUE);
    return 0;
  }
  return b == 1;
}

static const uint8_t *fixed(murmur_pc_dec_t *d, size_t n) {
  if (d->err != MURMUR_PC_OK) {
    return NULL;
  }
  if (d->len - d->off < n) {
    murmur_pc_fail(d, MURMUR_PC_TRUNCATED);
    return NULL;
  }
  const uint8_t *b = d->b + d->off;
  d->off += n;
  return b;
}

float murmur_pc_g_f32(murmur_pc_dec_t *d) {
  const uint8_t *b = fixed(d, 4);
  if (!b) {
    return 0;
  }
  uint32_t v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
               ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
  float f = 0;
  memcpy(&f, &v, 4);
  return f;
}

double murmur_pc_g_f64(murmur_pc_dec_t *d) {
  const uint8_t *b = fixed(d, 8);
  if (!b) {
    return 0;
  }
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v |= (uint64_t)b[i] << (8 * i);
  }
  double f = 0;
  memcpy(&f, &v, 8);
  return f;
}

const uint8_t *murmur_pc_g_raw(murmur_pc_dec_t *d, size_t n) {
  return fixed(d, n);
}

size_t murmur_pc_g_len(murmur_pc_dec_t *d) {
  uint64_t v = uvarint_dec(d);
  if (d->err != MURMUR_PC_OK) {
    return 0;
  }
  /* Go rejects above MaxInt (int64); match even though inputs this
   * long are unrepresentable either way. */
  if (v > (uint64_t)INT64_MAX) {
    murmur_pc_fail(d, MURMUR_PC_OVERFLOW);
    return 0;
  }
  return (size_t)v;
}

const uint8_t *murmur_pc_g_bytes(murmur_pc_dec_t *d, size_t *n) {
  size_t m = murmur_pc_g_len(d);
  if (d->err != MURMUR_PC_OK) {
    if (n) {
      *n = 0;
    }
    return NULL;
  }
  const uint8_t *b = fixed(d, m);
  if (n) {
    *n = b ? m : 0;
  }
  return b;
}

const uint8_t *murmur_pc_g_str(murmur_pc_dec_t *d, size_t *n) {
  size_t m = 0;
  const uint8_t *b = murmur_pc_g_bytes(d, &m);
  if (d->err != MURMUR_PC_OK) {
    if (n) {
      *n = 0;
    }
    return NULL;
  }
  if (!murmur_utf8_valid(b, m)) {
    murmur_pc_fail(d, MURMUR_PC_VALUE);
    if (n) {
      *n = 0;
    }
    return NULL;
  }
  if (n) {
    *n = m;
  }
  return b;
}
