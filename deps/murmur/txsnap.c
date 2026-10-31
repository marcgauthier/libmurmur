/* murmur txsnap - see txsnap.h. */
#include "txsnap.h"

#include <stdlib.h>
#include <string.h>

#include "kv.h"
#include "sha256.h"
#include "sqlite3.h"
#include "txretain.h"

static void set_sqlrc(int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
}

static murmur_sync_status_t sqlite_fail(int *sqlrc, int rc) {
  set_sqlrc(sqlrc, rc);
  return MURMUR_SYNC_SQLITE;
}

static murmur_sync_status_t ok_rc(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

static murmur_sync_status_t auth_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_AUTH;
}

static murmur_sync_status_t busy_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OVERLOADED;
}

static murmur_sync_status_t protocol_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_PROTOCOL;
}

murmur_sync_status_t murmur_tx_validate_chunk(const murmur_tx_manifest_t *m,
                                              const murmur_node_t *source,
                                              uint32_t index,
                                              const uint8_t *data,
                                              size_t data_len, int *sqlrc) {
  if (!murmur_node_eq(&m->donor, source)) {
    return auth_fail(sqlrc);
  }
  if ((uint64_t)index >= (uint64_t)m->n_chunks) {
    return auth_fail(sqlrc);
  }
  /* Go wraps int(m.Bytes) and compares signed lengths; expected can
   * go negative, which mismatches every real length. */
  int64_t rest = (int64_t)m->bytes - (int64_t)index * 65536;
  int64_t expected = rest > 65536 ? 65536 : rest;
  if (expected < 0 || (int64_t)data_len != expected) {
    return auth_fail(sqlrc);
  }
  uint8_t digest[32];
  murmur_sha256(data, data_len, digest);
  if (memcmp(digest, m->chunks[index], 32) != 0) {
    return auth_fail(sqlrc);
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_tx_stream_read(sqlite3 *db,
                                           const murmur_tx_manifest_t *m,
                                           uint64_t offset, int64_t length,
                                           uint8_t **out, size_t *out_len,
                                           int *sqlrc) {
  if (length < 0) {
    return protocol_fail(sqlrc);
  }
  uint64_t end = offset + (uint64_t)length;
  if (end < offset || end > m->bytes) {
    return protocol_fail(sqlrc);
  }
  uint8_t *buf = (uint8_t *)malloc(length ? (size_t)length : 1);
  if (!buf) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  /* Go wraps int(offset) the same way; negative positions only arise
   * past 8EiB manifests, where the chunk Get misses first. */
  int64_t at = (int64_t)offset;
  size_t have = 0;
  while (have < (size_t)length) {
    int64_t index = at / 65536;
    uint32_t ui = (uint32_t)index;
    size_t cklen = 0;
    uint8_t *ckey = murmur_tx_chunk_key(MURMUR_TX_IN, &m->transfer, ui, &cklen);
    if (!ckey) {
      free(buf);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    murmur_sync_status_t s =
        murmur_kv_get(db, ckey, cklen, &raw, &raw_len, &found, sqlrc);
    free(ckey);
    if (s != MURMUR_SYNC_OK) {
      free(buf);
      return s;
    }
    if (!found) {
      free(buf);
      return busy_fail(sqlrc);
    }
    s = murmur_tx_validate_chunk(m, &m->donor, ui, raw, raw_len, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      free(raw);
      free(buf);
      return s;
    }
    /* Go slices raw[off:off+n] unchecked and would panic on a short
     * chunk or wrapped offset; fail closed instead. */
    int64_t off = at % 65536;
    if (at < 0 || off < 0 || (uint64_t)off > raw_len) {
      free(raw);
      free(buf);
      return protocol_fail(sqlrc);
    }
    size_t n = (size_t)length - have;
    if (n > raw_len - (size_t)off) {
      n = raw_len - (size_t)off;
    }
    memcpy(buf + have, raw + off, n);
    have += n;
    at += (int64_t)n;
    free(raw);
  }
  *out = buf;
  *out_len = (size_t)length;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_tx_load_incoming(sqlite3 *db,
                                             murmur_tx_incoming_t *r,
                                             int *found, int *sqlrc) {
  if (found) {
    *found = 0;
  }
  static const uint8_t pfx[] = MURMUR_TX_IN;
  uint8_t **keys = NULL;
  size_t *lens = NULL, n = 0;
  murmur_sync_status_t s =
      murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  static const char tail[] = "/header";
  for (size_t i = 0; i < n; i++) {
    if (lens[i] < sizeof(tail) - 1 ||
        memcmp(keys[i] + lens[i] - (sizeof(tail) - 1), tail,
               sizeof(tail) - 1) != 0) {
      continue;
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int ok = 0;
    s = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &ok, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      murmur_kv_keys_free(keys, lens, n);
      return s;
    }
    if (!ok) {
      continue;
    }
    s = murmur_tx_incoming_decode(raw, raw_len, r, sqlrc);
    free(raw);
    murmur_kv_keys_free(keys, lens, n);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    if (found) {
      *found = 1;
    }
    return ok_rc(sqlrc);
  }
  murmur_kv_keys_free(keys, lens, n);
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_tx_receive(sqlite3 *db, const murmur_node_t *source,
                                       const murmur_node_t *transfer,
                                       uint32_t index, const uint8_t *data,
                                       size_t data_len, uint64_t now,
                                       int *sqlrc) {
  size_t rklen = 0;
  uint8_t *rkey = murmur_tx_receipt_key(transfer, &rklen);
  if (!rkey) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *rraw = NULL;
  size_t rlen = 0;
  int rok = 0;
  murmur_sync_status_t s =
      murmur_kv_get(db, rkey, rklen, &rraw, &rlen, &rok, sqlrc);
  free(rkey);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (rok) {
    /* Completed transfers validate only; receipts decode as Incoming. */
    murmur_tx_incoming_t receipt;
    s = murmur_tx_incoming_decode(rraw, rlen, &receipt, sqlrc);
    free(rraw);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    s = murmur_tx_validate_chunk(&receipt.manifest, source, index, data,
                                 data_len, sqlrc);
    murmur_tx_incoming_free(&receipt);
    return s;
  }
  size_t hk = 0;
  uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, transfer, &hk);
  if (!hkey) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *hraw = NULL;
  size_t hlen = 0;
  int hs = 0;
  s = murmur_kv_get(db, hkey, hk, &hraw, &hlen, &hs, sqlrc);
  free(hkey);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (!hs) {
    return busy_fail(sqlrc);
  }
  murmur_tx_incoming_t state;
  s = murmur_tx_incoming_decode(hraw, hlen, &state, sqlrc);
  free(hraw);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (state.deadline <= now) {
    murmur_tx_incoming_free(&state);
    return busy_fail(sqlrc);
  }
  s = murmur_tx_validate_chunk(&state.manifest, source, index, data, data_len,
                               sqlrc);
  murmur_tx_incoming_free(&state);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  size_t cklen = 0;
  uint8_t *ckey = murmur_tx_chunk_key(MURMUR_TX_IN, transfer, index, &cklen);
  if (!ckey) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *prev = NULL;
  size_t prev_len = 0;
  int have_prev = 0;
  s = murmur_kv_get(db, ckey, cklen, &prev, &prev_len, &have_prev, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    free(ckey);
    return s;
  }
  if (have_prev) {
    s = (prev_len == data_len && memcmp(prev, data, data_len) == 0)
            ? MURMUR_SYNC_OK
            : MURMUR_SYNC_AUTH;
    free(prev);
    free(ckey);
    set_sqlrc(sqlrc, SQLITE_OK);
    return s;
  }
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  r.key = ckey;
  r.key_len = cklen;
  r.value = (uint8_t *)data; /* kv_commit only reads values */
  r.value_len = data_len;
  s = murmur_kv_commit(db, &r, 1, sqlrc);
  free(ckey);
  return s;
}

murmur_sync_status_t murmur_tx_missing(sqlite3 *db,
                                       const murmur_tx_incoming_t *state,
                                       uint32_t **indexes, size_t *n,
                                       int *sqlrc) {
  *indexes = NULL;
  *n = 0;
  size_t inlen = strlen(MURMUR_TX_IN);
  size_t plen = inlen + 32 + sizeof("/chunk/") - 1 + 1;
  char *prefix = (char *)malloc(plen);
  if (!prefix) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  static const char *d = "0123456789abcdef";
  memcpy(prefix, MURMUR_TX_IN, inlen);
  for (int i = 0; i < 16; i++) {
    prefix[inlen + 2 * i] = d[state->manifest.transfer.b[i] >> 4];
    prefix[inlen + 2 * i + 1] = d[state->manifest.transfer.b[i] & 15];
  }
  memcpy(prefix + inlen + 32, "/chunk/", sizeof("/chunk/") - 1);
  prefix[plen - 1] = '\0';
  uint8_t **keys = NULL;
  size_t *lens = NULL;
  size_t nk = 0;
  murmur_sync_status_t s = murmur_kv_keys(db, (const uint8_t *)prefix, plen - 1,
                                          &keys, &lens, &nk, sqlrc);
  free(prefix);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  uint32_t *miss = (uint32_t *)malloc(128 * sizeof(*miss));
  if (!miss) {
    murmur_kv_keys_free(keys, lens, nk);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  size_t nm = 0;
  for (size_t i = 0; i < state->manifest.n_chunks && nm < 128; i++) {
    size_t cklen = 0;
    uint8_t *ckey =
        murmur_tx_chunk_key(MURMUR_TX_IN, &state->manifest.transfer,
                            (uint32_t)i, &cklen);
    if (!ckey) {
      s = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      break;
    }
    int saved = 0;
    for (size_t k = 0; k < nk && !saved; k++) {
      saved = lens[k] == cklen && memcmp(keys[k], ckey, cklen) == 0;
    }
    free(ckey);
    if (!saved) {
      miss[nm++] = (uint32_t)i;
    }
  }
  murmur_kv_keys_free(keys, lens, nk);
  if (s != MURMUR_SYNC_OK) {
    free(miss);
    return s;
  }
  if (nm == 0) {
    free(miss);
    return ok_rc(sqlrc);
  }
  *indexes = miss;
  *n = nm;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_tx_prune_limit(sqlite3 *db,
                                           const murmur_node_t *origin,
                                           uint64_t now, uint64_t *limit,
                                           int *sqlrc) {
  *limit = UINT64_MAX;
  static const uint8_t pfx[] = MURMUR_TX_PINS;
  uint8_t **keys = NULL;
  size_t *lens = NULL, n = 0;
  murmur_sync_status_t s =
      murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    s = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    if (!found) {
      continue;
    }
    murmur_tx_pin_t pin;
    s = murmur_tx_pin_decode(raw, raw_len, &pin, sqlrc);
    free(raw);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    if (pin.expires > now) {
      int have = 0;
      for (size_t k = pin.n_boundary; k > 0; k--) {
        if (murmur_node_eq(&pin.boundary[k - 1].origin, origin)) {
          if (pin.boundary[k - 1].seq < *limit) {
            *limit = pin.boundary[k - 1].seq;
          }
          have = 1;
          break;
        }
      }
      if (!have && *limit > 0) {
        *limit = 0;
      }
    }
    murmur_tx_pin_free(&pin);
  }
  murmur_kv_keys_free(keys, lens, n);
  return s;
}

/* ---- maintain ---- */

static int has_suffix(const uint8_t *k, size_t len, const char *suf) {
  size_t sl = strlen(suf);
  return len >= sl && memcmp(k + len - sl, suf, sl) == 0;
}

static murmur_sync_status_t push_tombstone(murmur_kv_record_t **recs,
                                           size_t *nrecs, size_t *cap,
                                           const uint8_t *key, size_t len,
                                           int *sqlrc) {
  if (*nrecs >= *cap) {
    size_t ncap = *cap ? *cap * 2 : 64;
    murmur_kv_record_t *nv =
        (murmur_kv_record_t *)realloc(*recs, ncap * sizeof(*nv));
    if (!nv) {
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      return MURMUR_SYNC_SQLITE;
    }
    *recs = nv;
    *cap = ncap;
  }
  uint8_t *cp = (uint8_t *)malloc(len ? len : 1);
  if (!cp) {
    set_sqlrc(sqlrc, SQLITE_NOMEM);
    return MURMUR_SYNC_SQLITE;
  }
  memcpy(cp, key, len);
  (*recs)[*nrecs].key = cp;
  (*recs)[*nrecs].key_len = len;
  (*recs)[*nrecs].value = NULL;
  (*recs)[*nrecs].value_len = 0;
  (*recs)[*nrecs].is_delete = 1;
  (*nrecs)++;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

/* Live transfer ids (bare 32-hex strings, one set per prefix). */
typedef struct {
  char **ids;
  size_t n, cap;
} hexset_t;

static void hexset_free(hexset_t *t) {
  for (size_t i = 0; i < t->n; i++) {
    free(t->ids[i]);
  }
  free(t->ids);
  memset(t, 0, sizeof(*t));
}

static int hexset_add(hexset_t *t, const murmur_node_t *id) {
  if (t->n >= t->cap) {
    size_t ncap = t->cap ? t->cap * 2 : 16;
    char **ns = (char **)realloc(t->ids, ncap * sizeof(*ns));
    if (!ns) {
      return -1;
    }
    t->ids = ns;
    t->cap = ncap;
  }
  char *cp = (char *)malloc(33);
  if (!cp) {
    return -1;
  }
  static const char *d = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    cp[2 * i] = d[id->b[i] >> 4];
    cp[2 * i + 1] = d[id->b[i] & 15];
  }
  cp[32] = '\0';
  t->ids[t->n++] = cp;
  return 0;
}

static int hexset_has(const hexset_t *t, const char *s, size_t len) {
  if (len != 32) {
    return 0;
  }
  for (size_t i = 0; i < t->n; i++) {
    if (memcmp(t->ids[i], s, 32) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Last-wins ack lookup over a boundary that may hold duplicates. */
static uint64_t boundary_ack(const murmur_tx_ack_t *acks, size_t n,
                             const murmur_node_t *origin) {
  for (size_t i = n; i > 0; i--) {
    if (murmur_node_eq(&acks[i - 1].origin, origin)) {
      return acks[i - 1].seq;
    }
  }
  return 0;
}

/* Every unique origin of a boundary reads its last (map-winning) seq. */
static int boundary_covered(const murmur_tx_ack_t *need, size_t n_need,
                            const murmur_tx_ack_t *have, size_t n_have) {
  for (size_t i = 0; i < n_need; i++) {
    int later = 0;
    for (size_t k = i + 1; k < n_need; k++) {
      if (murmur_node_eq(&need[k].origin, &need[i].origin)) {
        later = 1;
        break;
      }
    }
    if (later) {
      continue;
    }
    if (boundary_ack(have, n_have, &need[i].origin) < need[i].seq) {
      return 0;
    }
  }
  return 1;
}

/* One IN/OUT sweep: expired headers drop (live-marked instead once
 * the 256 cap fills, like Go's else branch), then every non-header
 * key under a non-live transfer id drops. Commits separately. */
static murmur_sync_status_t sweep_prefix(sqlite3 *db, const char *prefix,
                                         int incoming, uint64_t now,
                                         int *sqlrc) {
  size_t plen = strlen(prefix);
  uint8_t **keys = NULL;
  size_t *lens = NULL, n = 0;
  murmur_sync_status_t s = murmur_kv_keys(db, (const uint8_t *)prefix, plen,
                                          &keys, &lens, &n, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  hexset_t live;
  memset(&live, 0, sizeof(live));
  murmur_kv_record_t *recs = NULL;
  size_t nrecs = 0, cap = 0;
  for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
    if (!has_suffix(keys[i], lens[i], "/header")) {
      continue;
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    s = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    if (!found) {
      continue;
    }
    murmur_node_t transfer;
    int expired = 0;
    if (incoming) {
      murmur_tx_incoming_t r;
      s = murmur_tx_incoming_decode(raw, raw_len, &r, sqlrc);
      free(raw);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      transfer = r.manifest.transfer;
      expired = r.deadline <= now;
      murmur_tx_incoming_free(&r);
    } else {
      murmur_tx_manifest_t m;
      s = murmur_tx_manifest_decode(raw, raw_len, &m, sqlrc);
      free(raw);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      transfer = m.transfer;
      expired = m.expires <= now;
      size_t pklen = 0;
      uint8_t *pkey = murmur_tx_pin_key(&m.transfer, &pklen);
      murmur_tx_manifest_free(&m);
      if (!pkey) {
        s = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        break;
      }
      uint8_t *praw = NULL;
      size_t prlen = 0;
      int pok = 0;
      s = murmur_kv_get(db, pkey, pklen, &praw, &prlen, &pok, sqlrc);
      free(pkey);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      int targeted = 1;
      if (pok) {
        murmur_tx_pin_t pin;
        s = murmur_tx_pin_decode(praw, prlen, &pin, sqlrc);
        free(praw);
        if (s != MURMUR_SYNC_OK) {
          break;
        }
        targeted = pin.has_target;
        murmur_tx_pin_free(&pin);
      }
      expired = expired || targeted;
    }
    if (expired && nrecs < 256) {
      s = push_tombstone(&recs, &nrecs, &cap, keys[i], lens[i], sqlrc);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
    } else {
      if (hexset_add(&live, &transfer) != 0) {
        s = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        break;
      }
    }
  }
  for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
    if (nrecs >= 256) {
      break;
    }
    if (has_suffix(keys[i], lens[i], "/header")) {
      continue;
    }
    /* id = the key segment after the prefix, up to the next '/' */
    size_t start = plen < lens[i] ? plen : lens[i];
    size_t end = start;
    while (end < lens[i] && keys[i][end] != '/') {
      end++;
    }
    if (hexset_has(&live, (const char *)keys[i] + start, end - start)) {
      continue;
    }
    s = push_tombstone(&recs, &nrecs, &cap, keys[i], lens[i], sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
  }
  murmur_kv_keys_free(keys, lens, n);
  hexset_free(&live);
  if (s != MURMUR_SYNC_OK) {
    for (size_t i = 0; i < nrecs; i++) {
      free(recs[i].key);
    }
    free(recs);
    return s;
  }
  if (nrecs == 0) {
    free(recs);
    return ok_rc(sqlrc);
  }
  s = murmur_kv_commit(db, recs, nrecs, sqlrc);
  for (size_t i = 0; i < nrecs; i++) {
    free(recs[i].key);
  }
  free(recs);
  return s;
}

static murmur_sync_status_t commit_tombstones(sqlite3 *db,
                                              murmur_kv_record_t *recs,
                                              size_t nrecs, int *sqlrc) {
  if (nrecs == 0) {
    free(recs);
    return ok_rc(sqlrc);
  }
  murmur_sync_status_t s = murmur_kv_commit(db, recs, nrecs, sqlrc);
  for (size_t i = 0; i < nrecs; i++) {
    free(recs[i].key);
  }
  free(recs);
  return s;
}

murmur_sync_status_t murmur_tx_maintain(sqlite3 *db, uint64_t now, int *sqlrc) {
  murmur_sync_status_t s;
  /* pins: expired or caught-up drop, committed before the sweeps */
  {
    static const uint8_t pfx[] = MURMUR_TX_PINS;
    uint8_t **keys = NULL;
    size_t *lens = NULL, n = 0;
    s = murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    murmur_kv_record_t *recs = NULL;
    size_t nrecs = 0, cap = 0;
    for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
      uint8_t *raw = NULL;
      size_t raw_len = 0;
      int found = 0;
      s = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      if (!found) {
        continue;
      }
      murmur_tx_pin_t pin;
      s = murmur_tx_pin_decode(raw, raw_len, &pin, sqlrc);
      free(raw);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      int caught_up = 0;
      if (pin.has_target) {
        murmur_tx_peer_t peer;
        int pok = 0;
        s = murmur_tx_peer(db, &pin.recipient, &peer, &pok, sqlrc);
        if (s != MURMUR_SYNC_OK) {
          murmur_tx_pin_free(&pin);
          break;
        }
        if (pok) {
          caught_up = boundary_covered(pin.target, pin.n_target, peer.acks,
                                       peer.n_acks);
          murmur_tx_peer_free(&peer);
        }
      }
      int drop = pin.expires <= now || caught_up;
      murmur_tx_pin_free(&pin);
      if (drop) {
        s = push_tombstone(&recs, &nrecs, &cap, keys[i], lens[i], sqlrc);
        if (s != MURMUR_SYNC_OK) {
          break;
        }
      }
      if (nrecs == 256) {
        break;
      }
    }
    murmur_kv_keys_free(keys, lens, n);
    if (s != MURMUR_SYNC_OK) {
      for (size_t i = 0; i < nrecs; i++) {
        free(recs[i].key);
      }
      free(recs);
      return s;
    }
    s = commit_tombstones(db, recs, nrecs, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
  }
  s = sweep_prefix(db, MURMUR_TX_IN, 1, now, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  s = sweep_prefix(db, MURMUR_TX_OUT, 0, now, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  /* receipts decode as Incoming; expired deadlines drop */
  {
    static const uint8_t pfx[] = MURMUR_TX_RECEIPTS;
    uint8_t **keys = NULL;
    size_t *lens = NULL, n = 0;
    s = murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    murmur_kv_record_t *recs = NULL;
    size_t nrecs = 0, cap = 0;
    for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
      uint8_t *raw = NULL;
      size_t raw_len = 0;
      int found = 0;
      s = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      if (!found) {
        continue;
      }
      murmur_tx_incoming_t r;
      s = murmur_tx_incoming_decode(raw, raw_len, &r, sqlrc);
      free(raw);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      int drop = r.deadline <= now;
      murmur_tx_incoming_free(&r);
      if (drop) {
        s = push_tombstone(&recs, &nrecs, &cap, keys[i], lens[i], sqlrc);
        if (s != MURMUR_SYNC_OK) {
          break;
        }
      }
      if (nrecs == 256) {
        break;
      }
    }
    murmur_kv_keys_free(keys, lens, n);
    if (s != MURMUR_SYNC_OK) {
      for (size_t i = 0; i < nrecs; i++) {
        free(recs[i].key);
      }
      free(recs);
      return s;
    }
    s = commit_tombstones(db, recs, nrecs, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
  }
  /* Version 8 partial transfers have no durable sender identity. */
  {
    static const uint8_t pfx[] = "07/replication/snapshot/";
    uint8_t **keys = NULL;
    size_t *lens = NULL, n = 0;
    s = murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    if (n > 256) {
      for (size_t i = 256; i < n; i++) {
        free(keys[i]);
      }
      n = 256;
    }
    murmur_kv_record_t *recs = NULL;
    size_t nrecs = 0, cap = 0;
    for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
      s = push_tombstone(&recs, &nrecs, &cap, keys[i], lens[i], sqlrc);
    }
    murmur_kv_keys_free(keys, lens, n);
    if (s != MURMUR_SYNC_OK) {
      for (size_t i = 0; i < nrecs; i++) {
        free(recs[i].key);
      }
      free(recs);
      return s;
    }
    return commit_tombstones(db, recs, nrecs, sqlrc);
  }
}

/* ---- reap ---- */

static int node_in(const murmur_node_t *ids, size_t n,
                   const murmur_node_t *x) {
  for (size_t i = 0; i < n; i++) {
    if (murmur_node_eq(&ids[i], x)) {
      return 1;
    }
  }
  return 0;
}

murmur_sync_status_t murmur_tx_reap_forgotten_pins(sqlite3 *db, uint64_t now,
                                                  uint64_t max_offline_ms,
                                                  const murmur_node_t *online,
                                                  size_t n_online, int *sqlrc) {
  murmur_sync_status_t s;
  static const uint8_t pfx[] = MURMUR_TX_PINS;
  uint8_t **keys = NULL;
  size_t *lens = NULL, n = 0;
  s = murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  murmur_kv_record_t *recs = NULL;
  size_t nrecs = 0, cap = 0;
  for (size_t i = 0; i < n && s == MURMUR_SYNC_OK; i++) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    s = murmur_kv_get(db, keys[i], lens[i], &raw, &raw_len, &found, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    if (!found) {
      continue;
    }
    murmur_tx_pin_t pin;
    s = murmur_tx_pin_decode(raw, raw_len, &pin, sqlrc);
    free(raw);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    murmur_tx_peer_t peer;
    int pok = 0;
    s = murmur_tx_peer(db, &pin.recipient, &peer, &pok, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      murmur_tx_pin_free(&pin);
      break;
    }
    int is_online = node_in(online, n_online, &pin.recipient);
    int forgotten = 0;
    if (pok) {
      /* saturating skew: future timestamps read zero unseen */
      uint64_t unseen =
          now < peer.last_seen_millis ? 0 : now - peer.last_seen_millis;
      forgotten = peer.retired || (!is_online && unseen > max_offline_ms);
    }
    /* the outer recency check wraps like Go's uint64 subtraction */
    int fulfilled = !pin.has_target && pin.n_boundary > 0 && pok &&
                    !peer.retired &&
                    (is_online || now - peer.last_seen_millis <= max_offline_ms);
    if (fulfilled) {
      uint64_t unseen =
          now < peer.last_seen_millis ? 0 : now - peer.last_seen_millis;
      fulfilled = is_online || unseen <= max_offline_ms;
      if (fulfilled) {
        fulfilled = boundary_covered(pin.boundary, pin.n_boundary, peer.acks,
                                     peer.n_acks);
      }
    }
    if (pok) {
      murmur_tx_peer_free(&peer);
    }
    murmur_tx_pin_free(&pin);
    if ((forgotten || fulfilled) && nrecs < 256) {
      s = push_tombstone(&recs, &nrecs, &cap, keys[i], lens[i], sqlrc);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
    }
    if (nrecs >= 256) {
      break;
    }
  }
  murmur_kv_keys_free(keys, lens, n);
  if (s != MURMUR_SYNC_OK) {
    for (size_t i = 0; i < nrecs; i++) {
      free(recs[i].key);
    }
    free(recs);
    return s;
  }
  return commit_tombstones(db, recs, nrecs, sqlrc);
}

