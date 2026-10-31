/* murmur txcodec - see txcodec.h. */
#include "txcodec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "msgcodec.h"
#include "sha256.h"
#include "sqlite3.h"

static void set_sqlrc(int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
}

size_t murmur_tx_uvarint_encode(uint64_t v, uint8_t *out, size_t cap) {
  return murmur_u64_encode(v, out, cap);
}

int murmur_tx_uvarint_decode(const uint8_t *b, size_t n, size_t *pos,
                             uint64_t *v) {
  /* binary.Uvarint: up to 10 bytes, overflow fails closed */
  uint64_t r = 0;
  unsigned shift = 0;
  size_t p = *pos;
  for (int i = 0; i < 10 && p < n; i++) {
    uint8_t c = b[p++];
    if (i == 9 && c > 1) {
      return -1;
    }
    r |= (uint64_t)(c & 0x7F) << shift;
    shift += 7;
    if (!(c & 0x80)) {
      /* Uvarint also rejects non-minimal encodings past the first
       * byte? No: Go accepts them; only overflow (n>0 check) and
       * truncation fail. Mirror exactly. */
      *pos = p;
      *v = r;
      return 0;
    }
  }
  return -1;
}

uint8_t *murmur_tx_encode_u64(uint64_t v, size_t *len) {
  uint8_t tmp[10];
  size_t n = murmur_u64_encode(v, tmp, sizeof(tmp));
  if (n == 0) {
    return NULL;
  }
  uint8_t *out = (uint8_t *)malloc(n);
  if (!out) {
    return NULL;
  }
  memcpy(out, tmp, n);
  if (len) {
    *len = n;
  }
  return out;
}

murmur_sync_status_t murmur_tx_decode_u64(const uint8_t *b, size_t n,
                                          uint64_t *v, int *sqlrc) {
  size_t pos = 0;
  uint64_t r = 0;
  if (!b || murmur_tx_uvarint_decode(b, n, &pos, &r) != 0 || pos != n) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (v) {
    *v = r;
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

uint8_t *murmur_tx_progress_encode(const murmur_tx_progress_t *p, size_t *len) {
  uint8_t *out = (uint8_t *)malloc(16 + 4 * 10);
  if (!out) {
    return NULL;
  }
  memcpy(out, p->origin.b, 16);
  size_t w = 16, n = 0;
  uint64_t vals[4] = {p->applied, p->observed, p->retained_from,
                      p->retained_through};
  for (int i = 0; i < 4; i++) {
    n = murmur_u64_encode(vals[i], out + w, 40 - w + 16);
    if (n == 0) {
      free(out);
      return NULL;
    }
    w += n;
  }
  if (len) {
    *len = w;
  }
  return out;
}

murmur_sync_status_t murmur_tx_progress_decode(const uint8_t *b, size_t n,
                                               murmur_tx_progress_t *p,
                                               int *sqlrc) {
  murmur_tx_progress_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  if (!b || n < 16) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  memcpy(tmp.origin.b, b, 16);
  size_t pos = 16;
  uint64_t *slots[4] = {&tmp.applied, &tmp.observed, &tmp.retained_from,
                        &tmp.retained_through};
  for (int i = 0; i < 4; i++) {
    if (murmur_tx_uvarint_decode(b, n, &pos, slots[i]) != 0) {
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
  }
  if (pos != n) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (p) {
    *p = tmp;
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

static void hex16(const murmur_node_t *id, char *out) {
  static const char *d = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    out[2 * i] = d[id->b[i] >> 4];
    out[2 * i + 1] = d[id->b[i] & 15];
  }
}

static uint8_t *join_key(const char *prefix, const murmur_node_t *id,
                         size_t *len) {
  size_t pl = strlen(prefix);
  uint8_t *out = (uint8_t *)malloc(pl + 32 + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, prefix, pl);
  hex16(id, (char *)out + pl);
  out[pl + 32] = '\0';
  if (len) {
    *len = pl + 32;
  }
  return out;
}

uint8_t *murmur_tx_progress_key(const murmur_node_t *origin, size_t *len) {
  return join_key("07/replication/applied/", origin, len);
}

uint8_t *murmur_tx_observed_key(const murmur_node_t *origin, size_t *len) {
  return join_key("07/replication/observed/", origin, len);
}

uint8_t *murmur_tx_retained_key(const murmur_node_t *origin, size_t *len) {
  return join_key("07/replication/retained/", origin, len);
}

uint8_t *murmur_tx_floor_key(const murmur_node_t *origin, size_t *len) {
  return join_key("07/replication/retention/floor/", origin, len);
}

uint8_t *murmur_tx_schema_manifest_key(size_t *len) {
  static const char *k = "07/replication/schema/manifest";
  uint8_t *out = (uint8_t *)malloc(strlen(k) + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, k, strlen(k) + 1);
  if (len) {
    *len = strlen(k);
  }
  return out;
}

uint8_t *murmur_tx_schema_accepted_key(const murmur_node_t *signer,
                                       size_t *len) {
  return join_key("07/replication/schema/accepted/", signer, len);
}

uint8_t *murmur_tx_chunk_prefix(const murmur_node_t *origin, uint64_t seq,
                                size_t *len) {
  char hex[32];
  hex16(origin, hex);
  char *out = (char *)malloc(22 + 32 + 1 + 20 + 1 + 1);
  if (!out) {
    return NULL;
  }
  int n = snprintf(out, 22 + 32 + 1 + 20 + 1 + 1,
                   "07/replication/chunks/%.*s/%020llu/", 32, hex,
                   (unsigned long long)seq);
  if (n < 0) {
    free(out);
    return NULL;
  }
  if (len) {
    *len = (size_t)n;
  }
  return (uint8_t *)out;
}

uint64_t murmur_tx_zig_encode(int64_t v) {
  /* unsigned math: Go wraps, C signed shift would be UB on INT64_MIN */
  return ((uint64_t)v << 1) ^ (uint64_t)-(v < 0);
}

int64_t murmur_tx_zig_decode(uint64_t v) {
  return (int64_t)((v >> 1) ^ (0u - (v & 1)));
}

void murmur_signed_schema_free(murmur_signed_schema_t *s) {
  if (!s) {
    return;
  }
  free(s->schema);
  free(s->signature);
  memset(s, 0, sizeof(*s));
}

/* appendBytes helper with realloc growth */
typedef struct {
  uint8_t *p;
  size_t n;
  size_t cap;
} buf_t;

static int buf_reserve(buf_t *b, size_t extra) {
  if (b->n + extra <= b->cap) {
    return 0;
  }
  size_t ncap = b->cap ? b->cap : 64;
  while (ncap < b->n + extra) {
    ncap *= 2;
  }
  uint8_t *np = (uint8_t *)realloc(b->p, ncap);
  if (!np) {
    return -1;
  }
  b->p = np;
  b->cap = ncap;
  return 0;
}

static int buf_put(buf_t *b, const uint8_t *p, size_t n) {
  if (buf_reserve(b, n) != 0) {
    return -1;
  }
  if (n > 0) {
    memcpy(b->p + b->n, p, n);
  }
  b->n += n;
  return 0;
}

static int buf_uvarint(buf_t *b, uint64_t v) {
  uint8_t tmp[10];
  size_t n = murmur_u64_encode(v, tmp, sizeof(tmp));
  if (n == 0) {
    return -1;
  }
  return buf_put(b, tmp, n);
}

static int buf_bytes(buf_t *b, const uint8_t *p, size_t n) {
  if (buf_uvarint(b, (uint64_t)n) != 0) {
    return -1;
  }
  if (n > 0 && !p) {
    return -1;
  }
  return buf_put(b, p, n);
}

uint8_t *murmur_signed_schema_encode(const murmur_signed_schema_t *s,
                                     size_t *len) {
  buf_t b;
  memset(&b, 0, sizeof(b));
  int rc = buf_put(&b, s->database.b, 16);
  if (rc == 0) {
    rc = buf_put(&b, s->signer.b, 16);
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, s->sequence);
  }
  if (rc == 0) {
    rc = buf_bytes(&b, s->schema, s->schema_len);
  }
  if (rc == 0) {
    rc = buf_bytes(&b, s->signature, s->signature_len);
  }
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

murmur_sync_status_t murmur_signed_schema_decode(const uint8_t *b, size_t n,
                                                 murmur_signed_schema_t *s,
                                                 int *sqlrc) {
  murmur_signed_schema_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  murmur_sync_status_t st = MURMUR_SYNC_PROTOCOL;
  if (!b || n < 32) {
    goto out;
  }
  memcpy(tmp.database.b, b, 16);
  memcpy(tmp.signer.b, b + 16, 16);
  size_t pos = 32;
  if (murmur_tx_uvarint_decode(b, n, &pos, &tmp.sequence) != 0) {
    goto out;
  }
  for (int i = 0; i < 2; i++) {
    uint64_t sl = 0;
    if (murmur_tx_uvarint_decode(b, n, &pos, &sl) != 0 || sl > n - pos) {
      goto out;
    }
    uint8_t **slot = i == 0 ? &tmp.schema : &tmp.signature;
    size_t *llen = i == 0 ? &tmp.schema_len : &tmp.signature_len;
    *slot = (uint8_t *)malloc(sl ? (size_t)sl : 1);
    if (!*slot) {
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      murmur_signed_schema_free(&tmp);
      return MURMUR_SYNC_SQLITE;
    }
    memcpy(*slot, b + pos, (size_t)sl);
    *llen = (size_t)sl;
    pos += (size_t)sl;
  }
  if (pos != n) {
    goto out;
  }
  if (s) {
    *s = tmp;
  } else {
    murmur_signed_schema_free(&tmp);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
out:
  murmur_signed_schema_free(&tmp);
  set_sqlrc(sqlrc, SQLITE_OK);
  return st;
}

uint8_t *murmur_signed_schema_bytes(const murmur_signed_schema_t *s,
                                    size_t *len) {
  static const uint8_t domain[] = "murmur/sqlite-schema/v1";
  buf_t b;
  memset(&b, 0, sizeof(b));
  uint8_t sum[32];
  static const uint8_t empty[1] = {0};
  murmur_sha256(s->schema_len ? s->schema : empty, s->schema_len, sum);
  int rc = buf_put(&b, domain, sizeof(domain) - 1);
  if (rc == 0) {
    rc = buf_put(&b, s->database.b, 16);
  }
  if (rc == 0) {
    rc = buf_put(&b, s->signer.b, 16);
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, s->sequence);
  }
  if (rc == 0) {
    rc = buf_bytes(&b, sum, 32);
  }
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

void murmur_crr_snapshot_free(murmur_crr_snapshot_t *s) {
  if (!s) {
    return;
  }
  if (s->segments) {
    for (size_t i = 0; i < s->n_segments; i++) {
      free(s->segments[i]);
    }
    free(s->segments);
    free(s->segment_lens);
  }
  memset(s, 0, sizeof(*s));
}

uint8_t *murmur_crr_snapshot_encode(const murmur_crr_snapshot_t *s,
                                    size_t *len) {
  buf_t b;
  memset(&b, 0, sizeof(b));
  int rc = buf_put(&b, s->schema, 32);
  if (rc == 0) {
    rc = buf_uvarint(&b, murmur_tx_zig_encode(s->version));
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, (uint64_t)s->n_segments);
  }
  for (size_t i = 0; i < s->n_segments && rc == 0; i++) {
    rc = buf_bytes(&b, s->segments[i], s->segment_lens[i]);
  }
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

murmur_sync_status_t murmur_crr_snapshot_decode(const uint8_t *b, size_t n,
                                                murmur_crr_snapshot_t *s,
                                                int *sqlrc) {
  murmur_crr_snapshot_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  if (!b || n < 32) {
    goto fail;
  }
  memcpy(tmp.schema, b, 32);
  size_t pos = 32;
  uint64_t v = 0, count = 0;
  if (murmur_tx_uvarint_decode(b, n, &pos, &v) != 0 ||
      murmur_tx_uvarint_decode(b, n, &pos, &count) != 0) {
    goto fail;
  }
  tmp.version = murmur_tx_zig_decode(v);
  if (count > (1u << 20)) {
    goto fail;
  }
  if (count > 0) {
    tmp.segments = (uint8_t **)calloc((size_t)count, sizeof(*tmp.segments));
    tmp.segment_lens = (size_t *)calloc((size_t)count, sizeof(*tmp.segment_lens));
    if (!tmp.segments || !tmp.segment_lens) {
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      murmur_crr_snapshot_free(&tmp);
      return MURMUR_SYNC_SQLITE;
    }
    for (uint64_t i = 0; i < count; i++) {
      uint64_t sl = 0;
      if (murmur_tx_uvarint_decode(b, n, &pos, &sl) != 0 || sl > n - pos) {
        tmp.n_segments = (size_t)i;
        goto fail;
      }
      tmp.segments[i] = (uint8_t *)malloc(sl ? (size_t)sl : 1);
      if (!tmp.segments[i]) {
        tmp.n_segments = (size_t)i;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        murmur_crr_snapshot_free(&tmp);
        return MURMUR_SYNC_SQLITE;
      }
      memcpy(tmp.segments[i], b + pos, (size_t)sl);
      tmp.segment_lens[i] = (size_t)sl;
      pos += (size_t)sl;
    }
    tmp.n_segments = (size_t)count;
  }
  if (pos != n) {
    goto fail;
  }
  if (s) {
    *s = tmp;
  } else {
    murmur_crr_snapshot_free(&tmp);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
fail:
  murmur_crr_snapshot_free(&tmp);
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_PROTOCOL;
}

/* ---- Transfer codecs ---- */

static int cmp_ack(const void *a, const void *b) {
  return memcmp(((const murmur_tx_ack_t *)a)->origin.b,
                ((const murmur_tx_ack_t *)b)->origin.b, 16);
}

uint8_t *murmur_tx_boundary_encode(const murmur_tx_ack_t *acks, size_t n,
                                   size_t *len) {
  buf_t b;
  memset(&b, 0, sizeof(b));
  murmur_tx_ack_t *sorted = NULL;
  if (n > 0) {
    sorted = (murmur_tx_ack_t *)malloc(n * sizeof(*sorted));
    if (!sorted) {
      return NULL;
    }
    memcpy(sorted, acks, n * sizeof(*sorted));
    qsort(sorted, n, sizeof(*sorted), cmp_ack);
  }
  int rc = buf_uvarint(&b, (uint64_t)n);
  for (size_t i = 0; i < n && rc == 0; i++) {
    rc = buf_put(&b, sorted[i].origin.b, 16);
    if (rc == 0) {
      rc = buf_uvarint(&b, sorted[i].seq);
    }
  }
  free(sorted);
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

void murmur_tx_acks_free(murmur_tx_ack_t *acks, size_t n) {
  (void)n;
  free(acks);
}

murmur_sync_status_t murmur_tx_boundary_decode(const uint8_t *b, size_t n,
                                               size_t *pos,
                                               murmur_tx_ack_t **acks,
                                               size_t *count, int *sqlrc) {
  *acks = NULL;
  *count = 0;
  uint64_t cnt = 0;
  if (!b || murmur_tx_uvarint_decode(b, n, pos, &cnt) != 0 || cnt > 4096) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_tx_ack_t *v = NULL;
  if (cnt > 0) {
    v = (murmur_tx_ack_t *)calloc((size_t)cnt, sizeof(*v));
    if (!v) {
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      return MURMUR_SYNC_SQLITE;
    }
    for (uint64_t i = 0; i < cnt; i++) {
      /* entries preserved in wire order; Go's map keeps last-wins,
       * so C lookups must scan from the end */
      if (n - *pos < 16) {
        free(v);
        set_sqlrc(sqlrc, SQLITE_OK);
        return MURMUR_SYNC_PROTOCOL;
      }
      memcpy(v[i].origin.b, b + *pos, 16);
      *pos += 16;
      if (murmur_tx_uvarint_decode(b, n, pos, &v[i].seq) != 0) {
        free(v);
        set_sqlrc(sqlrc, SQLITE_OK);
        return MURMUR_SYNC_PROTOCOL;
      }
    }
  }
  *acks = v;
  *count = (size_t)cnt;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

uint8_t *murmur_tx_progress_vec_encode(const murmur_tx_progress_t *ps, size_t n,
                                       size_t *len) {
  buf_t b;
  memset(&b, 0, sizeof(b));
  int rc = buf_uvarint(&b, (uint64_t)n);
  for (size_t i = 0; i < n && rc == 0; i++) {
    size_t el = 0;
    uint8_t *enc = murmur_tx_progress_encode(&ps[i], &el);
    if (!enc) {
      rc = -1;
      break;
    }
    rc = buf_put(&b, enc, el);
    free(enc);
  }
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

murmur_sync_status_t murmur_tx_progress_vec_decode(const uint8_t *b, size_t n,
                                                   size_t *pos,
                                                   murmur_tx_progress_t **ps,
                                                   size_t *count, int *sqlrc) {
  *ps = NULL;
  *count = 0;
  uint64_t cnt = 0;
  if (!b || murmur_tx_uvarint_decode(b, n, pos, &cnt) != 0 || cnt > 4096) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  murmur_tx_progress_t *v = NULL;
  if (cnt > 0) {
    v = (murmur_tx_progress_t *)calloc((size_t)cnt, sizeof(*v));
    if (!v) {
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      return MURMUR_SYNC_SQLITE;
    }
    for (uint64_t i = 0; i < cnt; i++) {
      if (n - *pos < 16) {
        free(v);
        set_sqlrc(sqlrc, SQLITE_OK);
        return MURMUR_SYNC_PROTOCOL;
      }
      memcpy(v[i].origin.b, b + *pos, 16);
      *pos += 16;
      uint64_t *slots[4] = {&v[i].applied, &v[i].observed,
                            &v[i].retained_from, &v[i].retained_through};
      for (int k = 0; k < 4; k++) {
        if (murmur_tx_uvarint_decode(b, n, pos, slots[k]) != 0) {
          free(v);
          set_sqlrc(sqlrc, SQLITE_OK);
          return MURMUR_SYNC_PROTOCOL;
        }
      }
    }
  }
  *ps = v;
  *count = (size_t)cnt;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

void murmur_tx_peer_free(murmur_tx_peer_t *p) {
  if (!p) {
    return;
  }
  free(p->acks);
  memset(p, 0, sizeof(*p));
}

uint8_t *murmur_tx_peer_encode(const murmur_tx_peer_t *p, size_t *len) {
  size_t bl = 0;
  uint8_t *bnd = murmur_tx_boundary_encode(p->acks, p->n_acks, &bl);
  if (!bnd && (p->n_acks > 0 || bl > 0)) {
    return NULL;
  }
  buf_t b;
  memset(&b, 0, sizeof(b));
  uint8_t flag = p->retired ? 1 : 0;
  int rc = buf_put(&b, p->node.b, 16);
  if (rc == 0) {
    rc = buf_uvarint(&b, p->last_seen_millis);
  }
  if (rc == 0) {
    rc = buf_put(&b, &flag, 1);
  }
  if (rc == 0) {
    rc = buf_put(&b, bnd, bl);
  }
  free(bnd);
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

murmur_sync_status_t murmur_tx_peer_decode(const uint8_t *b, size_t n,
                                           murmur_tx_peer_t *p, int *sqlrc) {
  murmur_tx_peer_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  if (!b || n < 16) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  memcpy(tmp.node.b, b, 16);
  size_t pos = 16;
  if (murmur_tx_uvarint_decode(b, n, &pos, &tmp.last_seen_millis) != 0 ||
      pos >= n) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (b[pos] == 1) {
    tmp.retired = 1;
  } else if (b[pos] != 0) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  pos++;
  size_t cnt = 0;
  murmur_sync_status_t st = murmur_tx_boundary_decode(b, n, &pos, &tmp.acks,
                                                      &cnt, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  tmp.n_acks = cnt;
  if (pos != n) {
    murmur_tx_peer_free(&tmp);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (p) {
    *p = tmp;
  } else {
    murmur_tx_peer_free(&tmp);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

uint8_t *murmur_tx_peer_key(const murmur_node_t *node, size_t *len) {
  return join_key("07/replication/retention/peers/", node, len);
}

uint8_t *murmur_tx_excluded_key(const murmur_node_t *node, size_t *len) {
  return join_key("07/replication/excluded/", node, len);
}

void murmur_tx_manifest_free(murmur_tx_manifest_t *m) {
  if (!m) {
    return;
  }
  free(m->progress);
  free(m->chunks);
  free(m->signature);
  memset(m, 0, sizeof(*m));
}

uint8_t *murmur_tx_manifest_encode(const murmur_tx_manifest_t *m, size_t *len) {
  size_t vl = 0;
  uint8_t *vec = murmur_tx_progress_vec_encode(m->progress, m->n_progress, &vl);
  if (!vec && m->n_progress > 0) {
    return NULL;
  }
  buf_t b;
  memset(&b, 0, sizeof(b));
  int rc = buf_put(&b, m->database.b, 16);
  if (rc == 0) {
    rc = buf_put(&b, m->donor.b, 16);
  }
  if (rc == 0) {
    rc = buf_put(&b, m->recipient.b, 16);
  }
  if (rc == 0) {
    rc = buf_put(&b, m->transfer.b, 16);
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, m->expires);
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, m->bytes);
  }
  if (rc == 0) {
    rc = buf_put(&b, m->digest, 32);
  }
  if (rc == 0) {
    rc = buf_put(&b, m->schema, 32);
  }
  if (rc == 0) {
    rc = buf_put(&b, vec, vl);
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, (uint64_t)m->n_chunks);
  }
  for (size_t i = 0; i < m->n_chunks && rc == 0; i++) {
    rc = buf_put(&b, m->chunks[i], 32);
  }
  if (rc == 0) {
    rc = buf_bytes(&b, m->signature, m->signature_len);
  }
  free(vec);
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

static murmur_sync_status_t manifest_decode_rest(const uint8_t *b, size_t n,
                                                 size_t *pos,
                                                 murmur_tx_manifest_t *m,
                                                 int *sqlrc) {
  memset(m, 0, sizeof(*m));
  if (!b || n - *pos < 64) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  memcpy(m->database.b, b + *pos, 16);
  memcpy(m->donor.b, b + *pos + 16, 16);
  memcpy(m->recipient.b, b + *pos + 32, 16);
  memcpy(m->transfer.b, b + *pos + 48, 16);
  *pos += 64;
  if (murmur_tx_uvarint_decode(b, n, pos, &m->expires) != 0 ||
      murmur_tx_uvarint_decode(b, n, pos, &m->bytes) != 0) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (n - *pos < 64) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  memcpy(m->digest, b + *pos, 32);
  memcpy(m->schema, b + *pos + 32, 32);
  *pos += 64;
  size_t npc = 0;
  murmur_sync_status_t st = murmur_tx_progress_vec_decode(b, n, pos,
                                                          &m->progress, &npc,
                                                          sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_tx_manifest_free(m);
    return st;
  }
  m->n_progress = npc;
  uint64_t nc = 0;
  if (murmur_tx_uvarint_decode(b, n, pos, &nc) != 0 || nc > (1u << 24)) {
    murmur_tx_manifest_free(m);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (nc > 0) {
    if ((uint64_t)(n - *pos) < nc * 32) {
      murmur_tx_manifest_free(m);
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    m->chunks = (uint8_t(*)[32])malloc((size_t)nc * 32);
    if (!m->chunks) {
      murmur_tx_manifest_free(m);
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      return MURMUR_SYNC_SQLITE;
    }
    memcpy(m->chunks, b + *pos, (size_t)nc * 32);
    *pos += (size_t)nc * 32;
    m->n_chunks = (size_t)nc;
  }
  uint64_t sl = 0;
  if (murmur_tx_uvarint_decode(b, n, pos, &sl) != 0 || sl > n - *pos) {
    murmur_tx_manifest_free(m);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  m->signature = (uint8_t *)malloc(sl ? (size_t)sl : 1);
  if (!m->signature) {
    murmur_tx_manifest_free(m);
    set_sqlrc(sqlrc, SQLITE_NOMEM);
    return MURMUR_SYNC_SQLITE;
  }
  memcpy(m->signature, b + *pos, (size_t)sl);
  m->signature_len = (size_t)sl;
  *pos += (size_t)sl;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

murmur_sync_status_t murmur_tx_manifest_decode(const uint8_t *b, size_t n,
                                               murmur_tx_manifest_t *m,
                                               int *sqlrc) {
  murmur_tx_manifest_t tmp;
  size_t pos = 0;
  murmur_sync_status_t st = manifest_decode_rest(b, n, &pos, &tmp, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (pos != n) {
    murmur_tx_manifest_free(&tmp);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (m) {
    *m = tmp;
  } else {
    murmur_tx_manifest_free(&tmp);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

void murmur_tx_incoming_free(murmur_tx_incoming_t *r) {
  if (!r) {
    return;
  }
  murmur_tx_manifest_free(&r->manifest);
  memset(r, 0, sizeof(*r));
}

uint8_t *murmur_tx_incoming_encode(const murmur_tx_incoming_t *r, size_t *len) {
  size_t ml = 0;
  uint8_t *m = murmur_tx_manifest_encode(&r->manifest, &ml);
  if (!m) {
    return NULL;
  }
  buf_t b;
  memset(&b, 0, sizeof(b));
  int rc = buf_put(&b, m, ml);
  free(m);
  if (rc == 0) {
    rc = buf_uvarint(&b, r->deadline);
  }
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

murmur_sync_status_t murmur_tx_incoming_decode(const uint8_t *b, size_t n,
                                               murmur_tx_incoming_t *r,
                                               int *sqlrc) {
  murmur_tx_incoming_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  size_t pos = 0;
  murmur_sync_status_t st = manifest_decode_rest(b, n, &pos, &tmp.manifest,
                                                 sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (murmur_tx_uvarint_decode(b, n, &pos, &tmp.deadline) != 0 || pos != n) {
    murmur_tx_incoming_free(&tmp);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (r) {
    *r = tmp;
  } else {
    murmur_tx_incoming_free(&tmp);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

void murmur_tx_pin_free(murmur_tx_pin_t *p) {
  if (!p) {
    return;
  }
  free(p->boundary);
  free(p->target);
  memset(p, 0, sizeof(*p));
}

uint8_t *murmur_tx_pin_encode(const murmur_tx_pin_t *p, size_t *len) {
  size_t bl = 0, tl = 0;
  uint8_t *bnd = murmur_tx_boundary_encode(p->boundary, p->n_boundary, &bl);
  uint8_t *tgt = NULL;
  if (p->has_target) {
    tgt = murmur_tx_boundary_encode(p->target, p->n_target, &tl);
    if (!tgt && (p->n_target > 0 || tl > 0)) {
      free(bnd);
      return NULL;
    }
  }
  if (!bnd && (p->n_boundary > 0 || bl > 0)) {
    free(tgt);
    return NULL;
  }
  buf_t b;
  memset(&b, 0, sizeof(b));
  uint8_t flag = p->has_target ? 1 : 0;
  int rc = buf_put(&b, p->recipient.b, 16);
  if (rc == 0) {
    rc = buf_put(&b, bnd, bl);
  }
  if (rc == 0) {
    rc = buf_put(&b, &flag, 1);
  }
  if (rc == 0 && p->has_target) {
    rc = buf_put(&b, tgt, tl);
  }
  if (rc == 0) {
    rc = buf_uvarint(&b, p->expires);
  }
  if (rc == 0) {
    rc = buf_put(&b, p->digest, 32);
  }
  free(bnd);
  free(tgt);
  if (rc != 0) {
    free(b.p);
    return NULL;
  }
  if (len) {
    *len = b.n;
  }
  return b.p;
}

murmur_sync_status_t murmur_tx_pin_decode(const uint8_t *b, size_t n,
                                          murmur_tx_pin_t *p, int *sqlrc) {
  murmur_tx_pin_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  if (!b || n < 16) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  memcpy(tmp.recipient.b, b, 16);
  size_t pos = 16, cnt = 0;
  murmur_sync_status_t st =
      murmur_tx_boundary_decode(b, n, &pos, &tmp.boundary, &cnt, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  tmp.n_boundary = cnt;
  if (pos >= n) {
    murmur_tx_pin_free(&tmp);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (b[pos] == 1) {
    tmp.has_target = 1;
    pos++;
    st = murmur_tx_boundary_decode(b, n, &pos, &tmp.target, &cnt, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      murmur_tx_pin_free(&tmp);
      return st;
    }
    tmp.n_target = cnt;
  } else if (b[pos] == 0) {
    pos++;
  } else {
    murmur_tx_pin_free(&tmp);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  if (murmur_tx_uvarint_decode(b, n, &pos, &tmp.expires) != 0 ||
      n - pos != 32) {
    murmur_tx_pin_free(&tmp);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  memcpy(tmp.digest, b + pos, 32);
  pos += 32;
  if (p) {
    *p = tmp;
  } else {
    murmur_tx_pin_free(&tmp);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

static uint8_t *join_hex(const char *prefix, const murmur_node_t *id,
                         const char *suffix, size_t *len) {
  size_t pl = strlen(prefix), sl = suffix ? strlen(suffix) : 0;
  uint8_t *out = (uint8_t *)malloc(pl + 32 + sl + 1);
  if (!out) {
    return NULL;
  }
  static const char *d = "0123456789abcdef";
  memcpy(out, prefix, pl);
  for (int i = 0; i < 16; i++) {
    out[pl + 2 * i] = (uint8_t)d[id->b[i] >> 4];
    out[pl + 2 * i + 1] = (uint8_t)d[id->b[i] & 15];
  }
  if (suffix) {
    memcpy(out + pl + 32, suffix, sl);
  }
  out[pl + 32 + sl] = '\0';
  if (len) {
    *len = pl + 32 + sl;
  }
  return out;
}

uint8_t *murmur_tx_header_key(const char *prefix, const murmur_node_t *transfer,
                              size_t *len) {
  return join_hex(prefix, transfer, "/header", len);
}

uint8_t *murmur_tx_chunk_key(const char *prefix, const murmur_node_t *transfer,
                             uint32_t index, size_t *len) {
  size_t pl = strlen(prefix);
  uint8_t *out = (uint8_t *)malloc(pl + 32 + 7 + 10 + 1);
  if (!out) {
    return NULL;
  }
  static const char *d = "0123456789abcdef";
  memcpy(out, prefix, pl);
  for (int i = 0; i < 16; i++) {
    out[pl + 2 * i] = (uint8_t)d[transfer->b[i] >> 4];
    out[pl + 2 * i + 1] = (uint8_t)d[transfer->b[i] & 15];
  }
  int n = snprintf((char *)out + pl + 32, 7 + 10 + 1, "/chunk/%08u",
                   (unsigned)index);
  if (n < 0) {
    free(out);
    return NULL;
  }
  if (len) {
    *len = pl + 32 + (size_t)n;
  }
  return out;
}

uint8_t *murmur_tx_pin_key(const murmur_node_t *transfer, size_t *len) {
  return join_hex("07/replication/snapshot-v1/pins/", transfer, NULL, len);
}

uint8_t *murmur_tx_receipt_key(const murmur_node_t *transfer, size_t *len) {
  return join_hex("07/replication/snapshot-v1/receipts/", transfer, NULL, len);
}

uint8_t *murmur_tx_install_key(const murmur_node_t *transfer, size_t *len) {
  return join_hex("07/replication/snapshot-v1/in/", transfer, "/install", len);
}
