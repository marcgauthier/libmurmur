/* murmur msgcodec - see msgcodec.h. Ports the protocol.go codec
 * byte for byte; testdata/{key*,cursor*,msg_*,crsb_cells,u64_*}.bin
 * and the head-key .txt files are the goldens. */
#include "msgcodec.h"

#include <string.h>

#define SHORT ((size_t)-1)

static size_t put_uvarint(uint8_t *out, size_t cap, size_t pos, uint64_t v) {
  do {
    if (pos >= cap) {
      return SHORT;
    }
    uint8_t b = (uint8_t)(v & 0x7f);
    v >>= 7;
    if (v) {
      b |= 0x80;
    }
    out[pos++] = b;
  } while (v);
  return pos;
}

static int get_uvarint(const uint8_t *buf, size_t len, size_t *pos,
                       uint64_t *v) {
  uint64_t x = 0;
  unsigned shift = 0;
  for (int i = 0; i < 10; i++) {
    if (*pos >= len) {
      return -1;
    }
    uint8_t b = buf[(*pos)++];
    if (b < 0x80) {
      if (i == 9 && b > 1) {
        return -1;
      }
      x |= (uint64_t)b << shift;
      *v = x;
      return 0;
    }
    x |= (uint64_t)(b & 0x7f) << shift;
    shift += 7;
  }
  return -1;
}

/* Zigzag, mirroring Go zigEncode/zigDecode exactly (including
 * INT64_MIN, which maps to UINT64_MAX). */
static uint64_t zig_encode(int64_t v) {
  return ((uint64_t)v << 1) ^ (v < 0 ? ~0ULL : 0ULL);
}

static int64_t zig_decode(uint64_t v) {
  int64_t r = (int64_t)(v >> 1);
  if (v & 1) {
    r = ~r;
  }
  return r;
}

static size_t put_fixed(uint8_t *out, size_t cap, size_t pos, const void *p,
                        size_t n) {
  if (n > cap - pos) {
    return SHORT;
  }
  memcpy(out + pos, p, n);
  return pos + n;
}

static int get_fixed(const uint8_t *buf, size_t len, size_t *pos, void *p,
                     size_t n) {
  if (n > len - *pos) {
    return -1;
  }
  memcpy(p, buf + *pos, n);
  *pos += n;
  return 0;
}

/* Strict UTF-8 validation, mirroring Go utf8.Valid: rejects
 * overlongs, surrogates, and code points past U+10FFFF. */
int murmur_utf8_valid(const uint8_t *s, size_t n) {
  size_t i = 0;
  while (i < n) {
    uint8_t c = s[i];
    size_t need = 0;
    uint8_t lo = 0x80, hi = 0xbf;
    if (c < 0x80) {
      i++;
      continue;
    } else if (c < 0xc2) {
      return 0;
    } else if (c < 0xe0) {
      need = 1;
    } else if (c < 0xf0) {
      need = 2;
      if (c == 0xe0) {
        lo = 0xa0;
      } else if (c == 0xed) {
        hi = 0x9f;
      }
    } else if (c < 0xf5) {
      need = 3;
      if (c == 0xf0) {
        lo = 0x90;
      } else if (c == 0xf4) {
        hi = 0x8f;
      }
    } else {
      return 0;
    }
    if (n - i - 1 < need) {
      return 0;
    }
    if (s[i + 1] < lo || s[i + 1] > hi) {
      return 0;
    }
    for (size_t k = 2; k <= need; k++) {
      if (s[i + k] < 0x80 || s[i + k] > 0xbf) {
        return 0;
      }
    }
    i += 1 + need;
  }
  return 1;
}

static size_t put_bytes(uint8_t *out, size_t cap, size_t pos,
                        const uint8_t *p, size_t n) {
  pos = put_uvarint(out, cap, pos, (uint64_t)n);
  if (pos == SHORT) {
    return SHORT;
  }
  if (n == 0) {
    return pos;
  }
  return put_fixed(out, cap, pos, p, n);
}

/* Borrows the byte string from buf (no copy). */
static int get_bytes(const uint8_t *buf, size_t len, size_t *pos,
                     const uint8_t **p, size_t *n) {
  uint64_t count = 0;
  if (get_uvarint(buf, len, pos, &count) != 0) {
    return -1;
  }
  if (count > len - *pos) {
    return -1;
  }
  *p = count ? buf + *pos : NULL;
  *n = (size_t)count;
  *pos += (size_t)count;
  return 0;
}

static int get_string(const uint8_t *buf, size_t len, size_t *pos,
                      const uint8_t **p, size_t *n) {
  if (get_bytes(buf, len, pos, p, n) != 0) {
    return -1;
  }
  if (*n > 0 && !murmur_utf8_valid(*p, *n)) {
    return -1;
  }
  return 0;
}

static size_t put_node(uint8_t *out, size_t cap, size_t pos,
                       const murmur_node_t *n) {
  return put_fixed(out, cap, pos, n->b, sizeof(n->b));
}

static int get_node(const uint8_t *buf, size_t len, size_t *pos,
                    murmur_node_t *n) {
  return get_fixed(buf, len, pos, n->b, sizeof(n->b));
}

static size_t put_digest(uint8_t *out, size_t cap, size_t pos,
                         const uint8_t d[32]) {
  return put_fixed(out, cap, pos, d, 32);
}

static int get_digest(const uint8_t *buf, size_t len, size_t *pos,
                      uint8_t d[32]) {
  return get_fixed(buf, len, pos, d, 32);
}

static size_t put_addr(uint8_t *out, size_t cap, size_t pos,
                       const murmur_addr_t *a) {
  pos = put_uvarint(out, cap, pos, a->is6 ? 1 : 0);
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_fixed(out, cap, pos, a->ip, a->is6 ? 16 : 4);
  if (pos == SHORT) {
    return SHORT;
  }
  return put_uvarint(out, cap, pos, a->port);
}

static int get_addr(const uint8_t *buf, size_t len, size_t *pos,
                    murmur_addr_t *a) {
  uint64_t fam = 0;
  if (get_uvarint(buf, len, pos, &fam) != 0) {
    return -1;
  }
  memset(a->ip, 0, sizeof(a->ip));
  if (fam == 0) {
    if (get_fixed(buf, len, pos, a->ip, 4) != 0) {
      return -1;
    }
    a->is6 = 0;
  } else if (fam == 1) {
    if (get_fixed(buf, len, pos, a->ip, 16) != 0) {
      return -1;
    }
    a->is6 = 1;
  } else {
    return -1;
  }
  uint64_t port = 0;
  if (get_uvarint(buf, len, pos, &port) != 0 || port > 65535) {
    return -1;
  }
  a->port = (uint16_t)port;
  return 0;
}

/* ---- Key ---- */

static size_t put_key(uint8_t *out, size_t cap, size_t pos,
                      const murmur_key_t *k) {
  pos = put_uvarint(out, cap, pos, zig_encode(k->version));
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_uvarint(out, cap, pos, zig_encode(k->seq));
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_bytes(out, cap, pos, k->table, k->table_len);
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_bytes(out, cap, pos, k->pk, k->pk_len);
  if (pos == SHORT) {
    return SHORT;
  }
  return put_bytes(out, cap, pos, k->cid, k->cid_len);
}

static int get_key(const uint8_t *buf, size_t len, size_t *pos,
                   murmur_key_t *k) {
  uint64_t v = 0;
  if (get_uvarint(buf, len, pos, &v) != 0) {
    return -1;
  }
  k->version = zig_decode(v);
  if (get_uvarint(buf, len, pos, &v) != 0) {
    return -1;
  }
  k->seq = zig_decode(v);
  if (get_string(buf, len, pos, &k->table, &k->table_len) != 0) {
    return -1;
  }
  if (get_bytes(buf, len, pos, &k->pk, &k->pk_len) != 0) {
    return -1;
  }
  return get_string(buf, len, pos, &k->cid, &k->cid_len);
}

size_t murmur_key_encode(const murmur_key_t *k, uint8_t *out, size_t cap) {
  if (!k || !out) {
    return 0;
  }
  size_t pos = put_key(out, cap, 0, k);
  return pos == SHORT ? 0 : pos;
}

murmur_mship_status_t murmur_key_decode(const uint8_t *buf, size_t len,
                                        murmur_key_t *out) {
  if (!buf || !out) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  if (get_key(buf, len, &pos, out) != 0) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  return pos == len ? MURMUR_OK : MURMUR_MSHIP_PROTOCOL;
}

/* ---- Cursor ---- */

static size_t put_cursor(uint8_t *out, size_t cap, size_t pos,
                         const murmur_cursor_t *c) {
  pos = put_uvarint(out, cap, pos, zig_encode(c->from));
  if (pos == SHORT) {
    return SHORT;
  }
  if (pos + 1 > cap) {
    return SHORT;
  }
  if (!c->has_through) {
    out[pos++] = 0;
  } else {
    out[pos++] = 1;
    pos = put_uvarint(out, cap, pos, zig_encode(c->through));
    if (pos == SHORT) {
      return SHORT;
    }
  }
  if (pos + 1 > cap) {
    return SHORT;
  }
  if (!c->has_after) {
    out[pos++] = 0;
    return pos;
  }
  out[pos++] = 1;
  return put_key(out, cap, pos, &c->after);
}

static int get_cursor(const uint8_t *buf, size_t len, size_t *pos,
                      murmur_cursor_t *c) {
  uint64_t v = 0;
  if (get_uvarint(buf, len, pos, &v) != 0) {
    return -1;
  }
  c->from = zig_decode(v);
  c->has_through = 0;
  c->has_after = 0;
  if (*pos >= len) {
    return -1;
  }
  uint8_t b = buf[(*pos)++];
  if (b == 1) {
    if (get_uvarint(buf, len, pos, &v) != 0) {
      return -1;
    }
    c->through = zig_decode(v);
    c->has_through = 1;
  } else if (b != 0) {
    return -1;
  }
  if (*pos >= len) {
    return -1;
  }
  b = buf[(*pos)++];
  if (b == 1) {
    if (get_key(buf, len, pos, &c->after) != 0) {
      return -1;
    }
    c->has_after = 1;
  } else if (b != 0) {
    return -1;
  }
  return 0;
}

size_t murmur_cursor_encode(const murmur_cursor_t *c, uint8_t *out,
                            size_t cap) {
  if (!c || !out) {
    return 0;
  }
  size_t pos = put_cursor(out, cap, 0, c);
  return pos == SHORT ? 0 : pos;
}

murmur_mship_status_t murmur_cursor_decode(const uint8_t *buf, size_t len,
                                           murmur_cursor_t *out) {
  if (!buf || !out) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  if (get_cursor(buf, len, &pos, out) != 0) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  return pos == len ? MURMUR_OK : MURMUR_MSHIP_PROTOCOL;
}

/* ---- Message ---- */

size_t murmur_msg_encode(const murmur_msg_t *m, uint8_t *out, size_t cap) {
  if (!m || !out) {
    return 0;
  }
  size_t pos = 0;
  switch (m->tag) {
    case MURMUR_MSG_HELLO:
    case MURMUR_MSG_PULL:
    case MURMUR_MSG_RESET:
    case MURMUR_MSG_IDLE:
    case MURMUR_MSG_BATCH:
    case MURMUR_MSG_CHUNK:
    case MURMUR_MSG_SNAPSHOT_REQUEST:
    case MURMUR_MSG_SNAPSHOT_MANIFEST:
    case MURMUR_MSG_SCHEMA_REQUEST:
    case MURMUR_MSG_SCHEMA_MANIFEST:
    case MURMUR_MSG_SCHEMA_ACK:
    case MURMUR_MSG_END:
    case MURMUR_MSG_ACK:
    case MURMUR_MSG_ERROR:
      break;
    default:
      return 0;
  }
  pos = put_uvarint(out, cap, pos, (uint64_t)m->tag);
  if (pos == SHORT) {
    return 0;
  }
  switch (m->tag) {
    case MURMUR_MSG_HELLO:
      pos = put_node(out, cap, pos, &m->group);
      if (pos == SHORT) return 0;
      pos = put_node(out, cap, pos, &m->node);
      if (pos == SHORT) return 0;
      pos = put_node(out, cap, pos, &m->site);
      if (pos == SHORT) return 0;
      pos = put_digest(out, cap, pos, m->schema);
      if (pos == SHORT) return 0;
      pos = put_uvarint(out, cap, pos, m->incarnation);
      if (pos == SHORT) return 0;
      pos = put_addr(out, cap, pos, &m->addr);
      break;
    case MURMUR_MSG_PULL:
      pos = put_node(out, cap, pos, &m->group);
      if (pos == SHORT) return 0;
      pos = put_node(out, cap, pos, &m->node);
      if (pos == SHORT) return 0;
      pos = put_node(out, cap, pos, &m->site);
      if (pos == SHORT) return 0;
      pos = put_digest(out, cap, pos, m->schema);
      if (pos == SHORT) return 0;
      if (pos + 1 > cap) return 0;
      if (!m->has_expected) {
        out[pos++] = 0;
      } else {
        out[pos++] = 1;
        pos = put_node(out, cap, pos, &m->expected);
        if (pos == SHORT) return 0;
      }
      pos = put_cursor(out, cap, pos, &m->cursor);
      break;
    case MURMUR_MSG_RESET:
      pos = put_node(out, cap, pos, &m->site);
      break;
    case MURMUR_MSG_IDLE:
      break;
    case MURMUR_MSG_BATCH:
      pos = put_node(out, cap, pos, &m->site);
      if (pos == SHORT) return 0;
      pos = put_cursor(out, cap, pos, &m->cursor);
      if (pos == SHORT) return 0;
      pos = put_uvarint(out, cap, pos, m->bytes);
      if (pos == SHORT) return 0;
      pos = put_digest(out, cap, pos, m->digest);
      break;
    case MURMUR_MSG_CHUNK:
      pos = put_uvarint(out, cap, pos, m->index);
      if (pos == SHORT) return 0;
      pos = put_bytes(out, cap, pos, m->data, m->data_len);
      break;
    case MURMUR_MSG_SNAPSHOT_REQUEST:
      pos = put_node(out, cap, pos, &m->group);
      if (pos == SHORT) return 0;
      pos = put_node(out, cap, pos, &m->node);
      if (pos == SHORT) return 0;
      pos = put_node(out, cap, pos, &m->site);
      if (pos == SHORT) return 0;
      pos = put_digest(out, cap, pos, m->schema);
      break;
    case MURMUR_MSG_SNAPSHOT_MANIFEST:
    case MURMUR_MSG_SCHEMA_MANIFEST:
      pos = put_bytes(out, cap, pos, m->data, m->data_len);
      break;
    case MURMUR_MSG_SCHEMA_REQUEST:
      break;
    case MURMUR_MSG_SCHEMA_ACK:
      pos = put_digest(out, cap, pos, m->digest);
      if (pos == SHORT) return 0;
      pos = put_uvarint(out, cap, pos, m->sequence);
      break;
    case MURMUR_MSG_END:
      break;
    case MURMUR_MSG_ACK:
      pos = put_digest(out, cap, pos, m->digest);
      break;
    case MURMUR_MSG_ERROR:
      pos = put_bytes(out, cap, pos, m->data, m->data_len);
      break;
  }
  return pos == SHORT ? 0 : pos;
}

murmur_mship_status_t murmur_msg_decode(const uint8_t *buf, size_t len,
                                        murmur_msg_t *out) {
  if (!buf || !out) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  uint64_t tag = 0;
  if (get_uvarint(buf, len, &pos, &tag) != 0 || tag > 13) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  memset(out, 0, sizeof(*out));
  out->tag = (murmur_msg_tag_t)tag;
  switch (out->tag) {
    case MURMUR_MSG_HELLO:
      if (get_node(buf, len, &pos, &out->group) != 0 ||
          get_node(buf, len, &pos, &out->node) != 0 ||
          get_node(buf, len, &pos, &out->site) != 0 ||
          get_digest(buf, len, &pos, out->schema) != 0 ||
          get_uvarint(buf, len, &pos, &out->incarnation) != 0 ||
          get_addr(buf, len, &pos, &out->addr) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_PULL: {
      if (get_node(buf, len, &pos, &out->group) != 0 ||
          get_node(buf, len, &pos, &out->node) != 0 ||
          get_node(buf, len, &pos, &out->site) != 0 ||
          get_digest(buf, len, &pos, out->schema) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      if (pos >= len) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      uint8_t b = buf[pos++];
      if (b == 1) {
        if (get_node(buf, len, &pos, &out->expected) != 0) {
          return MURMUR_MSHIP_PROTOCOL;
        }
        out->has_expected = 1;
      } else if (b != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      if (get_cursor(buf, len, &pos, &out->cursor) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    }
    case MURMUR_MSG_RESET:
      if (get_node(buf, len, &pos, &out->site) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_IDLE:
      break;
    case MURMUR_MSG_BATCH:
      if (get_node(buf, len, &pos, &out->site) != 0 ||
          get_cursor(buf, len, &pos, &out->cursor) != 0 ||
          get_uvarint(buf, len, &pos, &out->bytes) != 0 ||
          get_digest(buf, len, &pos, out->digest) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_CHUNK: {
      uint64_t idx = 0;
      if (get_uvarint(buf, len, &pos, &idx) != 0 || idx > 0xffffffffu) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      out->index = (uint32_t)idx;
      if (get_bytes(buf, len, &pos, &out->data, &out->data_len) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    }
    case MURMUR_MSG_SNAPSHOT_REQUEST:
      if (get_node(buf, len, &pos, &out->group) != 0 ||
          get_node(buf, len, &pos, &out->node) != 0 ||
          get_node(buf, len, &pos, &out->site) != 0 ||
          get_digest(buf, len, &pos, out->schema) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_SNAPSHOT_MANIFEST:
    case MURMUR_MSG_SCHEMA_MANIFEST:
      if (get_bytes(buf, len, &pos, &out->data, &out->data_len) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_SCHEMA_REQUEST:
      break;
    case MURMUR_MSG_SCHEMA_ACK:
      if (get_digest(buf, len, &pos, out->digest) != 0 ||
          get_uvarint(buf, len, &pos, &out->sequence) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_END:
      break;
    case MURMUR_MSG_ACK:
      if (get_digest(buf, len, &pos, out->digest) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
    case MURMUR_MSG_ERROR:
      if (get_string(buf, len, &pos, &out->data, &out->data_len) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
      break;
  }
  return pos == len ? MURMUR_OK : MURMUR_MSHIP_PROTOCOL;
}

/* ---- Frames ---- */

size_t murmur_frame_encode(const murmur_msg_t *m, uint8_t *out, size_t cap) {
  if (!m || !out || cap < 4) {
    return 0;
  }
  size_t n = murmur_msg_encode(m, out + 4, cap - 4);
  if (n == 0 || n > MURMUR_FRAME_BYTES) {
    return 0;
  }
  out[0] = (uint8_t)(n >> 24);
  out[1] = (uint8_t)(n >> 16);
  out[2] = (uint8_t)(n >> 8);
  out[3] = (uint8_t)n;
  return 4 + n;
}

murmur_mship_status_t murmur_frame_decode(const uint8_t *buf, size_t len,
                                          murmur_msg_t *out) {
  if (!buf || !out) {
    return MURMUR_MSHIP_INVALID;
  }
  if (len < 4) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  uint32_t n = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
               ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
  if (n == 0 || n > MURMUR_FRAME_BYTES || len != (size_t)4 + n) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  return murmur_msg_decode(buf + 4, n, out);
}

/* ---- CRSB cells ---- */

static size_t put_u32le(uint8_t *out, size_t cap, size_t pos, uint32_t v) {
  if (4 > cap - pos) {
    return SHORT;
  }
  out[pos] = (uint8_t)v;
  out[pos + 1] = (uint8_t)(v >> 8);
  out[pos + 2] = (uint8_t)(v >> 16);
  out[pos + 3] = (uint8_t)(v >> 24);
  return pos + 4;
}

static size_t put_u64le(uint8_t *out, size_t cap, size_t pos, uint64_t v) {
  if (8 > cap - pos) {
    return SHORT;
  }
  for (int i = 0; i < 8; i++) {
    out[pos + i] = (uint8_t)(v >> (8 * i));
  }
  return pos + 8;
}

static int get_u32le(const uint8_t *buf, size_t len, size_t *pos,
                     uint32_t *v) {
  if (4 > len - *pos) {
    return -1;
  }
  *v = (uint32_t)buf[*pos] | ((uint32_t)buf[*pos + 1] << 8) |
       ((uint32_t)buf[*pos + 2] << 16) | ((uint32_t)buf[*pos + 3] << 24);
  *pos += 4;
  return 0;
}

static int get_u64le(const uint8_t *buf, size_t len, size_t *pos,
                     uint64_t *v) {
  if (8 > len - *pos) {
    return -1;
  }
  uint64_t x = 0;
  for (int i = 0; i < 8; i++) {
    x |= (uint64_t)buf[*pos + i] << (8 * i);
  }
  *v = x;
  *pos += 8;
  return 0;
}

static size_t put_field(uint8_t *out, size_t cap, size_t pos,
                        const uint8_t *p, size_t n) {
  /* Field lengths are u32 on the wire; oversized inputs fail. */
  if (n > 0xffffffffu) {
    return SHORT;
  }
  pos = put_u32le(out, cap, pos, (uint32_t)n);
  if (pos == SHORT || n == 0) {
    return pos;
  }
  return put_fixed(out, cap, pos, p, n);
}

static int get_field(const uint8_t *buf, size_t len, size_t *pos,
                     const uint8_t **p, size_t *n) {
  uint32_t count = 0;
  if (get_u32le(buf, len, pos, &count) != 0) {
    return -1;
  }
  if (count > len - *pos) {
    return -1;
  }
  *p = count ? buf + *pos : NULL;
  *n = count;
  *pos += count;
  return 0;
}

static size_t put_cell(uint8_t *out, size_t cap, size_t pos,
                       const murmur_cell_t *c) {
  pos = put_field(out, cap, pos, c->table, c->table_len);
  if (pos == SHORT) return SHORT;
  pos = put_field(out, cap, pos, c->pk, c->pk_len);
  if (pos == SHORT) return SHORT;
  pos = put_field(out, cap, pos, c->cid, c->cid_len);
  if (pos == SHORT) return SHORT;
  if (pos + 1 > cap) return SHORT;
  uint64_t w = 0;
  switch (c->val_tag) {
    case 0:
      out[pos++] = 0;
      break;
    case 1:
      out[pos++] = 1;
      pos = put_u64le(out, cap, pos, (uint64_t)c->val_int);
      if (pos == SHORT) return SHORT;
      break;
    case 2:
      out[pos++] = 2;
      memcpy(&w, &c->val_real, sizeof(w));
      pos = put_u64le(out, cap, pos, w);
      if (pos == SHORT) return SHORT;
      break;
    case 3:
      out[pos++] = 3;
      pos = put_field(out, cap, pos, c->val_blob, c->val_blob_len);
      if (pos == SHORT) return SHORT;
      break;
    default:
      /* Go encodes every other tag as blob (tag 4). */
      out[pos++] = 4;
      pos = put_field(out, cap, pos, c->val_blob, c->val_blob_len);
      if (pos == SHORT) return SHORT;
      break;
  }
  pos = put_u64le(out, cap, pos, (uint64_t)c->col_version);
  if (pos == SHORT) return SHORT;
  pos = put_u64le(out, cap, pos, (uint64_t)c->db_version);
  if (pos == SHORT) return SHORT;
  pos = put_field(out, cap, pos, c->site, c->site_len);
  if (pos == SHORT) return SHORT;
  pos = put_u64le(out, cap, pos, (uint64_t)c->cl);
  if (pos == SHORT) return SHORT;
  return put_u64le(out, cap, pos, (uint64_t)c->seq);
}

static int get_cell(const uint8_t *buf, size_t len, size_t *pos,
                    murmur_cell_t *c) {
  if (get_field(buf, len, pos, &c->table, &c->table_len) != 0 ||
      (c->table_len > 0 && !murmur_utf8_valid(c->table, c->table_len))) {
    return -1;
  }
  if (get_field(buf, len, pos, &c->pk, &c->pk_len) != 0) {
    return -1;
  }
  if (get_field(buf, len, pos, &c->cid, &c->cid_len) != 0 ||
      (c->cid_len > 0 && !murmur_utf8_valid(c->cid, c->cid_len))) {
    return -1;
  }
  if (*pos >= len) {
    return -1;
  }
  uint8_t tag = buf[(*pos)++];
  c->val_tag = tag;
  c->val_int = 0;
  c->val_real = 0;
  c->val_blob = NULL;
  c->val_blob_len = 0;
  uint64_t w = 0;
  switch (tag) {
    case 0:
      break;
    case 1:
      if (get_u64le(buf, len, pos, &w) != 0) {
        return -1;
      }
      c->val_int = (int64_t)w;
      break;
    case 2:
      if (get_u64le(buf, len, pos, &w) != 0) {
        return -1;
      }
      memcpy(&c->val_real, &w, sizeof(w));
      break;
    case 3:
    case 4:
      if (get_field(buf, len, pos, &c->val_blob, &c->val_blob_len) != 0) {
        return -1;
      }
      break;
    default:
      return -1;
  }
  if (get_u64le(buf, len, pos, &w) != 0) {
    return -1;
  }
  c->col_version = (int64_t)w;
  if (get_u64le(buf, len, pos, &w) != 0) {
    return -1;
  }
  c->db_version = (int64_t)w;
  if (get_field(buf, len, pos, &c->site, &c->site_len) != 0) {
    return -1;
  }
  if (get_u64le(buf, len, pos, &w) != 0) {
    return -1;
  }
  c->cl = (int64_t)w;
  if (get_u64le(buf, len, pos, &w) != 0) {
    return -1;
  }
  c->seq = (int64_t)w;
  return 0;
}

size_t murmur_cell_encode(const murmur_cell_t *c, uint8_t *out,
                          size_t cap) {
  if (!c || !out) {
    return 0;
  }
  size_t pos = put_cell(out, cap, 0, c);
  return pos == SHORT ? 0 : pos;
}

size_t murmur_cells_encode(const murmur_cell_t *cells, size_t n,
                           uint8_t *out, size_t cap) {
  if ((!cells && n > 0) || !out || n > 0xffffffffu) {
    return 0;
  }
  size_t pos = 0;
  pos = put_fixed(out, cap, pos, "CRSB", 4);
  if (pos == SHORT) return 0;
  pos = put_u32le(out, cap, pos, 1);
  if (pos == SHORT) return 0;
  pos = put_u32le(out, cap, pos, (uint32_t)n);
  if (pos == SHORT) return 0;
  for (size_t i = 0; i < n; i++) {
    pos = put_cell(out, cap, pos, &cells[i]);
    if (pos == SHORT) return 0;
  }
  return pos;
}

murmur_mship_status_t murmur_cells_decode(const uint8_t *buf, size_t len,
                                          murmur_cell_t *out, size_t cap,
                                          size_t *n) {
  if (!buf || !n) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  uint8_t magic[4];
  if (get_fixed(buf, len, &pos, magic, 4) != 0 ||
      memcmp(magic, "CRSB", 4) != 0) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  uint32_t ver = 0;
  if (get_u32le(buf, len, &pos, &ver) != 0 || ver != 1) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  uint32_t count = 0;
  if (get_u32le(buf, len, &pos, &count) != 0) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  if ((uint64_t)count > (uint64_t)(len - pos) + 1) {
    /* Each cell needs at least one byte; absurd counts fail fast. */
    return MURMUR_MSHIP_PROTOCOL;
  }
  if (count > cap) {
    return MURMUR_MSHIP_OVERLOADED;
  }
  if (count > 0 && !out) {
    return MURMUR_MSHIP_INVALID;
  }
  for (uint32_t i = 0; i < count; i++) {
    if (get_cell(buf, len, &pos, &out[i]) != 0) {
      return MURMUR_MSHIP_PROTOCOL;
    }
  }
  if (pos != len) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  *n = count;
  return MURMUR_OK;
}

/* ---- u64 heads ---- */

size_t murmur_u64_encode(uint64_t v, uint8_t *out, size_t cap) {
  if (!out) {
    return 0;
  }
  size_t pos = put_uvarint(out, cap, 0, v);
  return pos == SHORT ? 0 : pos;
}

murmur_mship_status_t murmur_u64_decode(const uint8_t *buf, size_t len,
                                        uint64_t *v) {
  if (!buf || !v) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  if (get_uvarint(buf, len, &pos, v) != 0) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  return pos == len ? MURMUR_OK : MURMUR_MSHIP_PROTOCOL;
}

/* ---- head keys ---- */

static size_t head_key(const char *prefix, const murmur_node_t *origin,
                       char *out, size_t cap) {
  static const char digits[] = "0123456789abcdef";
  size_t plen = strlen(prefix);
  if (!origin || !out || plen + 32 > cap) {
    return 0;
  }
  memcpy(out, prefix, plen);
  for (int i = 0; i < 16; i++) {
    out[plen + 2 * i] = digits[origin->b[i] >> 4];
    out[plen + 2 * i + 1] = digits[origin->b[i] & 15];
  }
  return plen + 32;
}

size_t murmur_progress_key(const murmur_node_t *origin, char *out,
                           size_t cap) {
  return head_key("07/replication/applied/", origin, out, cap);
}

size_t murmur_observed_key(const murmur_node_t *origin, char *out,
                           size_t cap) {
  return head_key("07/replication/observed/", origin, out, cap);
}

/* ---- schema pairs ---- */

/* Postcard varint decode, mirroring Go postcardUvarintDecode: up to
 * 10 bytes, wraparound (not rejection) on wide 10th bytes, failure
 * past 10 continuation bytes or at end of input. */
static int get_puvarint(const uint8_t *buf, size_t len, size_t *pos,
                        uint64_t *v) {
  uint64_t x = 0;
  unsigned shift = 0;
  for (int i = 0; i < 10; i++) {
    if (*pos >= len) {
      return -1;
    }
    uint8_t c = buf[(*pos)++];
    x |= (uint64_t)(c & 0x7f) << shift;
    if (!(c & 0x80)) {
      *v = x;
      return 0;
    }
    shift += 7;
  }
  return -1;
}

size_t murmur_schema_pairs_encode(const murmur_schema_pair_t *pairs,
                                 size_t n, uint8_t *out, size_t cap) {
  if ((!pairs && n > 0) || !out) {
    return 0;
  }
  size_t pos = put_uvarint(out, cap, 0, (uint64_t)n);
  if (pos == SHORT) {
    return 0;
  }
  for (size_t i = 0; i < n; i++) {
    pos = put_bytes(out, cap, pos, pairs[i].table, pairs[i].table_len);
    if (pos == SHORT) {
      return 0;
    }
    pos = put_bytes(out, cap, pos, pairs[i].ddl, pairs[i].ddl_len);
    if (pos == SHORT) {
      return 0;
    }
  }
  return pos;
}

murmur_mship_status_t murmur_schema_pairs_decode(
    const uint8_t *buf, size_t len, murmur_schema_pair_t *out, size_t cap,
    size_t *n) {
  if (!buf || !n) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  uint64_t count = 0;
  if (get_puvarint(buf, len, &pos, &count) != 0) {
    return MURMUR_MSHIP_INVALID;
  }
  if (count > cap) {
    return MURMUR_MSHIP_OVERLOADED;
  }
  if (count > 0 && !out) {
    return MURMUR_MSHIP_INVALID;
  }
  for (uint64_t i = 0; i < count; i++) {
    uint64_t slen = 0;
    if (get_puvarint(buf, len, &pos, &slen) != 0 || slen > len - pos) {
      return MURMUR_MSHIP_INVALID;
    }
    out[i].table = slen ? buf + pos : NULL;
    out[i].table_len = (size_t)slen;
    pos += (size_t)slen;
    if (get_puvarint(buf, len, &pos, &slen) != 0 || slen > len - pos) {
      return MURMUR_MSHIP_INVALID;
    }
    out[i].ddl = slen ? buf + pos : NULL;
    out[i].ddl_len = (size_t)slen;
    pos += (size_t)slen;
  }
  if (pos != len) {
    return MURMUR_MSHIP_INVALID;
  }
  *n = (size_t)count;
  return MURMUR_OK;
}
