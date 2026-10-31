/* murmur snapbuild - see snapbuild.h. */
#include "snapbuild.h"

#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "sqlite3.h"
#include "txretain.h"
#include "txsnap.h"

#define FRAME_BYTES (8 << 20)

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

static murmur_sync_status_t invalid_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_INVALID;
}

static murmur_sync_status_t protocol_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_PROTOCOL;
}

static murmur_sync_status_t busy_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OVERLOADED;
}

static murmur_sync_status_t auth_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_AUTH;
}

static uint64_t sat_add(uint64_t a, uint64_t b) {
  if (UINT64_MAX - a < b) {
    return UINT64_MAX;
  }
  return a + b;
}

uint64_t murmur_snap_deadline(const murmur_snap_params_t *p, uint64_t now) {
  return sat_add(now, p->transfer_lifetime_ms);
}

static int trusted_source(const murmur_snap_params_t *p,
                          const murmur_node_t *source) {
  for (size_t i = 0; i < p->n_trusted; i++) {
    if (murmur_node_eq(&p->trusted[i], source)) {
      return 1;
    }
  }
  return 0;
}

/* Go's ceilDiv(int(bytes), ChunkBytes): the addition wraps mod 2^64
 * and the division truncates toward zero. */
static int64_t ceil_div_wrap(uint64_t bytes) {
  int64_t n = (int64_t)bytes;
  int64_t s = (int64_t)((uint64_t)n + (uint64_t)(MURMUR_TX_CHUNK_BYTES - 1));
  return s / MURMUR_TX_CHUNK_BYTES;
}

murmur_sync_status_t murmur_snap_verify(
    const murmur_tx_manifest_t *m, const murmur_node_t *database,
    const murmur_node_t *recipient, const murmur_node_t *source,
    const murmur_snap_params_t *params, uint64_t now, int *sqlrc) {
  if (!murmur_node_eq(&m->database, database) ||
      !murmur_node_eq(&m->donor, source) ||
      !murmur_node_eq(&m->recipient, recipient) ||
      !trusted_source(params, source) || m->expires <= now) {
    return auth_fail(sqlrc);
  }
  int64_t want_chunks = ceil_div_wrap(m->bytes);
  if (m->bytes > (uint64_t)params->snapshot_bytes ||
      m->bytes > (uint64_t)params->snapshot_staging_bytes ||
      m->n_progress > 4096 || want_chunks < 0 ||
      (uint64_t)m->n_chunks != (uint64_t)want_chunks) {
    return busy_fail(sqlrc);
  }
  for (size_t i = 0; i < m->n_progress; i++) {
    const murmur_tx_progress_t *p = &m->progress[i];
    for (size_t k = 0; k < i; k++) {
      if (murmur_node_eq(&m->progress[k].origin, &p->origin)) {
        return protocol_fail(sqlrc);
      }
    }
    if (p->observed < p->applied ||
        (p->retained_from > p->retained_through && p->retained_through != 0)) {
      return protocol_fail(sqlrc);
    }
  }
  return ok_rc(sqlrc);
}

/* ---- streaming build ---- */

typedef struct {
  murmur_snap_emit_fn emit;
  void *ctx;
  const murmur_node_t *transfer;
  /* 16 streaming chunks plus the final pin+header in one group */
  murmur_kv_record_t staged[18];
  uint8_t *keys[18];
  uint8_t *vals[18];
  size_t n;
  murmur_sha256_t digest;
  uint8_t *buffer;
  size_t buffered;
  uint8_t (*hashes)[32];
  size_t n_hashes, cap_hashes;
  int64_t total;
} builder_t;

static void builder_free(builder_t *b) {
  for (size_t i = 0; i < b->n; i++) {
    free(b->keys[i]);
    free(b->vals[i]);
  }
  free(b->buffer);
  free(b->hashes);
  memset(b, 0, sizeof(*b));
}

static murmur_sync_status_t builder_flush(builder_t *b, int *sqlrc) {
  if (b->n == 0) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OK;
  }
  murmur_sync_status_t s = b->emit(b->ctx, b->staged, b->n, sqlrc);
  for (size_t i = 0; i < b->n; i++) {
    free(b->keys[i]);
    free(b->vals[i]);
    b->keys[i] = NULL;
    b->vals[i] = NULL;
  }
  b->n = 0;
  return s;
}

static murmur_sync_status_t builder_push_chunk(builder_t *b, int *sqlrc) {
  if (b->n_hashes >= b->cap_hashes) {
    size_t ncap = b->cap_hashes ? b->cap_hashes * 2 : 16;
    uint8_t(*nh)[32] =
        (uint8_t(*)[32])realloc(b->hashes, ncap * sizeof(*nh));
    if (!nh) {
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    b->hashes = nh;
    b->cap_hashes = ncap;
  }
  murmur_sha256(b->buffer, b->buffered, b->hashes[b->n_hashes]);
  size_t klen = 0;
  uint8_t *key = murmur_tx_chunk_key(MURMUR_TX_OUT, b->transfer,
                                     (uint32_t)b->n_hashes, &klen);
  uint8_t *cp = (uint8_t *)malloc(b->buffered ? b->buffered : 1);
  if (!key || !cp) {
    free(key);
    free(cp);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  memcpy(cp, b->buffer, b->buffered);
  b->n_hashes++;
  b->keys[b->n] = key;
  b->vals[b->n] = cp;
  b->staged[b->n].key = key;
  b->staged[b->n].key_len = klen;
  b->staged[b->n].value = cp;
  b->staged[b->n].value_len = b->buffered;
  b->staged[b->n].is_delete = 0;
  b->n++;
  b->buffered = 0;
  if (b->n == 16) {
    return builder_flush(b, sqlrc);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

static murmur_sync_status_t builder_push(builder_t *b,
                                         const murmur_snap_params_t *params,
                                         const uint8_t *data, size_t len,
                                         int *sqlrc) {
  if (len > UINT64_MAX - (uint64_t)b->total) {
    return busy_fail(sqlrc);
  }
  b->total = (int64_t)((uint64_t)b->total + (uint64_t)len);
  if (b->total > params->snapshot_bytes ||
      b->total > params->snapshot_staging_bytes) {
    return busy_fail(sqlrc);
  }
  murmur_sha256_update(&b->digest, data, len);
  size_t off = 0;
  while (off < len) {
    size_t take = MURMUR_TX_CHUNK_BYTES - b->buffered;
    if (take > len - off) {
      take = len - off;
    }
    memcpy(b->buffer + b->buffered, data + off, take);
    b->buffered += take;
    off += take;
    if (b->buffered == MURMUR_TX_CHUNK_BYTES) {
      murmur_sync_status_t s = builder_push_chunk(b, sqlrc);
      if (s != MURMUR_SYNC_OK) {
        return s;
      }
    }
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

murmur_sync_status_t murmur_snap_build_streaming(
    const murmur_node_t *database, const murmur_node_t *donor,
    const murmur_node_t *recipient, const uint8_t **pages,
    const size_t *page_lens, size_t n_pages,
    const murmur_tx_progress_t *progress, size_t n_progress,
    const uint8_t schema[32], const murmur_snap_params_t *params,
    uint64_t now, murmur_snap_emit_fn emit, void *emit_ctx,
    murmur_tx_manifest_t *out, int *sqlrc) {
  if (n_progress > 4096) {
    return busy_fail(sqlrc);
  }
  murmur_node_t transfer;
  for (int i = 0; i < 2; i++) {
    uint64_t w = 0;
    if (murmur_word_crypto(NULL, &w) != 0) {
      return sqlite_fail(sqlrc, SQLITE_IOERR);
    }
    memcpy(transfer.b + 8 * i, &w, 8);
  }
  /* last-wins applied boundary over the progress list */
  murmur_tx_ack_t *boundary = NULL;
  size_t n_boundary = 0;
  if (n_progress > 0) {
    boundary =
        (murmur_tx_ack_t *)calloc(n_progress, sizeof(*boundary));
    if (!boundary) {
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    for (size_t i = 0; i < n_progress; i++) {
      size_t slot = n_boundary;
      for (size_t k = 0; k < n_boundary; k++) {
        if (murmur_node_eq(&boundary[k].origin, &progress[i].origin)) {
          slot = k;
          break;
        }
      }
      if (slot == n_boundary) {
        boundary[n_boundary].origin = progress[i].origin;
        n_boundary++;
      }
      boundary[slot].seq = progress[i].applied;
    }
  }
  murmur_tx_manifest_t manifest;
  memset(&manifest, 0, sizeof(manifest));
  murmur_sync_status_t s;
  /* phase 1: preliminary pin + chunkless header */
  {
    murmur_tx_pin_t pre;
    memset(&pre, 0, sizeof(pre));
    pre.recipient = *recipient;
    pre.boundary = boundary;
    pre.n_boundary = n_boundary;
    pre.expires = sat_add(now, MURMUR_TX_BUILD_GRACE_MILLIS);
    size_t pkl = 0, pyl = 0, hkl = 0, hyl = 0;
    uint8_t *pkey = murmur_tx_pin_key(&transfer, &pkl);
    uint8_t *py = murmur_tx_pin_encode(&pre, &pyl);
    murmur_tx_manifest_t prelim;
    memset(&prelim, 0, sizeof(prelim));
    prelim.database = *database;
    prelim.donor = *donor;
    prelim.recipient = *recipient;
    prelim.transfer = transfer;
    prelim.expires = pre.expires;
    memcpy(prelim.schema, schema, 32);
    prelim.progress = (murmur_tx_progress_t *)progress;
    prelim.n_progress = n_progress;
    uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_OUT, &transfer, &hkl);
    uint8_t *hy = murmur_tx_manifest_encode(&prelim, &hyl);
    if (!pkey || !py || !hkey || !hy) {
      free(pkey);
      free(py);
      free(hkey);
      free(hy);
      free(boundary);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    murmur_kv_record_t recs[2];
    memset(recs, 0, sizeof(recs));
    recs[0].key = pkey;
    recs[0].key_len = pkl;
    recs[0].value = py;
    recs[0].value_len = pyl;
    recs[1].key = hkey;
    recs[1].key_len = hkl;
    recs[1].value = hy;
    recs[1].value_len = hyl;
    s = emit(emit_ctx, recs, 2, sqlrc);
    free(pkey);
    free(py);
    free(hkey);
    free(hy);
    if (s != MURMUR_SYNC_OK) {
      free(boundary);
      return s;
    }
  }
  builder_t b;
  memset(&b, 0, sizeof(b));
  b.emit = emit;
  b.ctx = emit_ctx;
  b.transfer = &transfer;
  b.buffer = (uint8_t *)malloc(MURMUR_TX_CHUNK_BYTES);
  if (!b.buffer) {
    free(boundary);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_sha256_init(&b.digest);
  static const uint8_t magic[] = MURMUR_TX_STREAM_MAGIC;
  s = builder_push(&b, params, magic, MURMUR_TX_STREAM_MAGIC_LEN, sqlrc);
  for (size_t i = 0; i < n_pages && s == MURMUR_SYNC_OK; i++) {
    if (page_lens[i] == 0 || params->max_transaction_bytes < 0 ||
        (uint64_t)params->max_transaction_bytes < page_lens[i]) {
      s = busy_fail(sqlrc);
      break;
    }
    uint8_t ln[4];
    uint32_t plen = (uint32_t)page_lens[i];
    ln[0] = (uint8_t)(plen >> 24);
    ln[1] = (uint8_t)(plen >> 16);
    ln[2] = (uint8_t)(plen >> 8);
    ln[3] = (uint8_t)plen;
    s = builder_push(&b, params, ln, 4, sqlrc);
    if (s == MURMUR_SYNC_OK) {
      s = builder_push(&b, params, pages[i], page_lens[i], sqlrc);
    }
  }
  if (s == MURMUR_SYNC_OK && b.buffered > 0) {
    s = builder_push_chunk(&b, sqlrc);
  }
  if (s != MURMUR_SYNC_OK) {
    builder_free(&b);
    free(boundary);
    return s;
  }
  manifest.database = *database;
  manifest.donor = *donor;
  manifest.recipient = *recipient;
  manifest.transfer = transfer;
  manifest.expires = murmur_snap_deadline(params, now);
  manifest.bytes = (uint64_t)b.total;
  memcpy(manifest.schema, schema, 32);
  murmur_sha256_final(&b.digest, manifest.digest);
  manifest.chunks = b.hashes;
  manifest.n_chunks = b.n_hashes;
  b.hashes = NULL;
  if (n_progress > 0) {
    manifest.progress =
        (murmur_tx_progress_t *)malloc(n_progress * sizeof(*progress));
    if (!manifest.progress) {
      builder_free(&b);
      free(boundary);
      murmur_tx_manifest_free(&manifest);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    memcpy(manifest.progress, progress, n_progress * sizeof(*progress));
    manifest.n_progress = n_progress;
  }
  /* final group: pin with digest plus the signed header */
  {
    murmur_tx_pin_t pin;
    memset(&pin, 0, sizeof(pin));
    pin.recipient = *recipient;
    pin.boundary = boundary;
    pin.n_boundary = n_boundary;
    pin.expires = manifest.expires;
    memcpy(pin.digest, manifest.digest, 32);
    size_t pkl = 0, pyl = 0, hkl = 0, hyl = 0;
    uint8_t *pkey = murmur_tx_pin_key(&transfer, &pkl);
    uint8_t *py = murmur_tx_pin_encode(&pin, &pyl);
    uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_OUT, &transfer, &hkl);
    uint8_t *hy = murmur_tx_manifest_encode(&manifest, &hyl);
    free(boundary);
    boundary = NULL;
    if (!pkey || !py || !hkey || !hy) {
      free(pkey);
      free(py);
      free(hkey);
      free(hy);
      builder_free(&b);
      murmur_tx_manifest_free(&manifest);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    /* at most 15 chunks pending (streaming flushes at 16) */
    b.keys[b.n] = pkey;
    b.vals[b.n] = py;
    b.staged[b.n].key = pkey;
    b.staged[b.n].key_len = pkl;
    b.staged[b.n].value = py;
    b.staged[b.n].value_len = pyl;
    b.staged[b.n].is_delete = 0;
    b.n++;
    b.keys[b.n] = hkey;
    b.vals[b.n] = hy;
    b.staged[b.n].key = hkey;
    b.staged[b.n].key_len = hkl;
    b.staged[b.n].value = hy;
    b.staged[b.n].value_len = hyl;
    b.staged[b.n].is_delete = 0;
    b.n++;
    s = builder_flush(&b, sqlrc);
    if (s == MURMUR_SYNC_OK) {
      s = emit(emit_ctx, b.staged, 0, sqlrc);
    }
  }
  if (s != MURMUR_SYNC_OK) {
    builder_free(&b);
    murmur_tx_manifest_free(&manifest);
    return s;
  }
  builder_free(&b);
  if (out) {
    *out = manifest;
  } else {
    murmur_tx_manifest_free(&manifest);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

/* ---- accept ---- */

static int manifest_bytes_equal(const murmur_tx_manifest_t *a,
                                const murmur_tx_manifest_t *b) {
  size_t al = 0, bl = 0;
  uint8_t *ae = murmur_tx_manifest_encode(a, &al);
  uint8_t *be = murmur_tx_manifest_encode(b, &bl);
  int eq = ae && be && al == bl && memcmp(ae, be, al) == 0;
  free(ae);
  free(be);
  return eq;
}

murmur_sync_status_t murmur_snap_accept(sqlite3 *db,
                                        const murmur_node_t *database,
                                        const murmur_node_t *recipient,
                                        const murmur_snap_params_t *params,
                                        const murmur_node_t *source,
                                        const murmur_tx_manifest_t *m,
                                        uint64_t now, int *sqlrc) {
  murmur_sync_status_t s =
      murmur_snap_verify(m, database, recipient, source, params, now, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (m->n_chunks == 0) {
    return busy_fail(sqlrc);
  }
  size_t rklen = 0;
  uint8_t *rkey = murmur_tx_receipt_key(&m->transfer, &rklen);
  if (!rkey) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *rraw = NULL;
  size_t rlen = 0;
  int rok = 0;
  s = murmur_kv_get(db, rkey, rklen, &rraw, &rlen, &rok, sqlrc);
  free(rkey);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (rok) {
    murmur_tx_incoming_t done;
    s = murmur_tx_incoming_decode(rraw, rlen, &done, sqlrc);
    free(rraw);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    int eq = manifest_bytes_equal(&done.manifest, m);
    murmur_tx_incoming_free(&done);
    if (!eq) {
      return auth_fail(sqlrc);
    }
    return ok_rc(sqlrc);
  }
  murmur_tx_incoming_t old;
  int have_old = 0;
  s = murmur_tx_load_incoming(db, &old, &have_old, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (have_old) {
    int eq = manifest_bytes_equal(&old.manifest, m);
    murmur_tx_incoming_free(&old);
    if (!eq) {
      return busy_fail(sqlrc);
    }
    return ok_rc(sqlrc);
  }
  static const uint8_t rpfx[] = MURMUR_TX_RECEIPTS;
  uint8_t **rkeys = NULL;
  size_t *rlens = NULL, nr = 0;
  s = murmur_kv_keys(db, rpfx, sizeof(rpfx) - 1, &rkeys, &rlens, &nr, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  murmur_kv_keys_free(rkeys, rlens, nr);
  if (params->staging_transfers < 0 ||
      nr >= (uint64_t)params->staging_transfers) {
    return busy_fail(sqlrc);
  }
  uint64_t used = m->bytes;
  static const uint8_t ipfx[] = MURMUR_TX_IN;
  uint8_t **ikeys = NULL;
  size_t *ilens = NULL, ni = 0;
  s = murmur_kv_keys(db, ipfx, sizeof(ipfx) - 1, &ikeys, &ilens, &ni, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  static const char htail[] = "/header";
  for (size_t i = 0; i < ni && s == MURMUR_SYNC_OK; i++) {
    if (ilens[i] >= sizeof(htail) - 1 &&
        memcmp(ikeys[i] + ilens[i] - (sizeof(htail) - 1), htail,
               sizeof(htail) - 1) == 0) {
      continue;
    }
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    s = murmur_kv_get(db, ikeys[i], ilens[i], &raw, &raw_len, &found, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    if (!found) {
      continue;
    }
    free(raw);
    uint64_t prev = used;
    used += (uint64_t)raw_len;
    if (used < prev || used > (uint64_t)params->snapshot_staging_bytes) {
      s = busy_fail(sqlrc);
      break;
    }
  }
  murmur_kv_keys_free(ikeys, ilens, ni);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  uint64_t deadline = m->expires;
  uint64_t cap = murmur_snap_deadline(params, now);
  if (cap < deadline) {
    deadline = cap;
  }
  murmur_tx_incoming_t staged;
  memset(&staged, 0, sizeof(staged));
  staged.manifest = *m;
  staged.deadline = deadline;
  size_t hl = 0, hkl = 0;
  uint8_t *henc = murmur_tx_incoming_encode(&staged, &hl);
  uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, &m->transfer, &hkl);
  if (!henc || !hkey) {
    free(henc);
    free(hkey);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  r.key = hkey;
  r.key_len = hkl;
  r.value = henc;
  r.value_len = hl;
  s = murmur_kv_commit(db, &r, 1, sqlrc);
  free(henc);
  free(hkey);
  return s;
}

/* ---- finish ---- */

murmur_sync_status_t murmur_snap_finish(sqlite3 *db,
                                        const murmur_node_t *database,
                                        const murmur_node_t *recipient,
                                        const murmur_snap_params_t *params,
                                        const murmur_node_t *source,
                                        const murmur_node_t *transfer,
                                        uint64_t now, int *done, int *sqlrc) {
  if (done) {
    *done = 0;
  }
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
    murmur_tx_incoming_t r;
    s = murmur_tx_incoming_decode(rraw, rlen, &r, sqlrc);
    free(rraw);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
    int donor_ok = murmur_node_eq(&r.manifest.donor, source);
    murmur_tx_incoming_free(&r);
    if (!donor_ok) {
      return auth_fail(sqlrc);
    }
    if (done) {
      *done = 1;
    }
    return ok_rc(sqlrc);
  }
  size_t hklen = 0;
  uint8_t *hkey = murmur_tx_header_key(MURMUR_TX_IN, transfer, &hklen);
  if (!hkey) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *hraw = NULL;
  size_t hlen = 0;
  int have_hdr = 0;
  s = murmur_kv_get(db, hkey, hklen, &hraw, &hlen, &have_hdr, sqlrc);
  free(hkey);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (!have_hdr) {
    return ok_rc(sqlrc);
  }
  murmur_tx_incoming_t inc;
  s = murmur_tx_incoming_decode(hraw, hlen, &inc, sqlrc);
  free(hraw);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  s = murmur_snap_verify(&inc.manifest, database, recipient, source, params,
                         now, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    murmur_tx_incoming_free(&inc);
    return s;
  }
  if (inc.deadline <= now) {
    murmur_tx_incoming_free(&inc);
    return ok_rc(sqlrc);
  }
  uint8_t *schema_raw = NULL;
  size_t schema_len = 0;
  s = murmur_backend_schema(db, &schema_raw, &schema_len, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    murmur_tx_incoming_free(&inc);
    return s;
  }
  uint8_t schema_sum[32];
  murmur_sha256(schema_raw ? schema_raw : (const uint8_t *)"", schema_len,
                schema_sum);
  free(schema_raw);
  if (memcmp(schema_sum, inc.manifest.schema, 32) != 0) {
    murmur_tx_incoming_free(&inc);
    return busy_fail(sqlrc);
  }
  uint32_t *missing = NULL;
  size_t n_missing = 0;
  s = murmur_tx_missing(db, &inc, &missing, &n_missing, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    murmur_tx_incoming_free(&inc);
    return s;
  }
  int complete = n_missing == 0;
  free(missing);
  if (!complete) {
    murmur_tx_incoming_free(&inc);
    return ok_rc(sqlrc);
  }
  size_t iklen = 0;
  uint8_t *ikey = murmur_tx_install_key(transfer, &iklen);
  if (!ikey) {
    murmur_tx_incoming_free(&inc);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *iraw = NULL;
  size_t ilen = 0;
  int have_install = 0;
  s = murmur_kv_get(db, ikey, iklen, &iraw, &ilen, &have_install, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    murmur_tx_incoming_free(&inc);
    free(ikey);
    return s;
  }
  uint64_t install = 0;
  if (have_install) {
    s = murmur_tx_decode_u64(iraw, ilen, &install, sqlrc);
    free(iraw);
    if (s != MURMUR_SYNC_OK) {
      murmur_tx_incoming_free(&inc);
      free(ikey);
      return s;
    }
  }
  int streamed = 0;
  if (inc.manifest.bytes >= MURMUR_TX_STREAM_MAGIC_LEN) {
    uint8_t *head = NULL;
    size_t head_len = 0;
    s = murmur_tx_stream_read(db, &inc.manifest, 0, MURMUR_TX_STREAM_MAGIC_LEN,
                              &head, &head_len, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      murmur_tx_incoming_free(&inc);
      free(ikey);
      return s;
    }
    static const uint8_t magic[] = MURMUR_TX_STREAM_MAGIC;
    streamed = head_len == MURMUR_TX_STREAM_MAGIC_LEN &&
               memcmp(head, magic, head_len) == 0;
    free(head);
  }
  uint8_t *data = NULL;
  size_t data_len = 0, data_cap = 0;
  if (!have_install) {
    murmur_sha256_t digest;
    murmur_sha256_init(&digest);
    uint64_t total = 0;
    for (size_t i = 0; i < inc.manifest.n_chunks && s == MURMUR_SYNC_OK; i++) {
      size_t cklen = 0;
      uint8_t *ckey =
          murmur_tx_chunk_key(MURMUR_TX_IN, transfer, (uint32_t)i, &cklen);
      if (!ckey) {
        s = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      uint8_t *craw = NULL;
      size_t craw_len = 0;
      int cok = 0;
      s = murmur_kv_get(db, ckey, cklen, &craw, &craw_len, &cok, sqlrc);
      free(ckey);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
      if (!cok) {
        murmur_tx_incoming_free(&inc);
        free(ikey);
        free(data);
        return ok_rc(sqlrc);
      }
      s = murmur_tx_validate_chunk(&inc.manifest, source, (uint32_t)i, craw,
                                   craw_len, sqlrc);
      if (s != MURMUR_SYNC_OK) {
        free(craw);
        break;
      }
      murmur_sha256_update(&digest, craw, craw_len);
      total += (uint64_t)craw_len;
      if (!streamed) {
        if (data_len + craw_len > data_cap) {
          size_t ncap = data_cap ? data_cap * 2 : 65536;
          while (ncap < data_len + craw_len) {
            ncap *= 2;
          }
          uint8_t *nd = (uint8_t *)realloc(data, ncap);
          if (!nd) {
            free(craw);
            s = sqlite_fail(sqlrc, SQLITE_NOMEM);
            break;
          }
          data = nd;
          data_cap = ncap;
        }
        memcpy(data + data_len, craw, craw_len);
        data_len += craw_len;
      }
      free(craw);
    }
    if (s == MURMUR_SYNC_OK) {
      uint8_t sum[32];
      murmur_sha256_final(&digest, sum);
      if (total != inc.manifest.bytes ||
          memcmp(sum, inc.manifest.digest, 32) != 0) {
        s = auth_fail(sqlrc);
      }
    }
    if (s != MURMUR_SYNC_OK) {
      murmur_tx_incoming_free(&inc);
      free(ikey);
      free(data);
      return s;
    }
  }
  if (streamed) {
    uint64_t cursor = have_install ? install : MURMUR_TX_STREAM_MAGIC_LEN;
    if (cursor < MURMUR_TX_STREAM_MAGIC_LEN ||
        cursor > inc.manifest.bytes) {
      murmur_tx_incoming_free(&inc);
      free(ikey);
      free(data);
      return protocol_fail(sqlrc);
    }
    if (cursor < inc.manifest.bytes) {
      const uint8_t *payloads[16];
      size_t payload_lens[16];
      size_t n_payloads = 0;
      uint8_t *owned[16];
      memset(owned, 0, sizeof(owned));
      int64_t used = 0;
      while (cursor < inc.manifest.bytes && n_payloads < 16 &&
             s == MURMUR_SYNC_OK) {
        uint8_t *ln = NULL;
        size_t ln_len = 0;
        s = murmur_tx_stream_read(db, &inc.manifest, cursor, 4, &ln, &ln_len,
                                  sqlrc);
        if (s != MURMUR_SYNC_OK) {
          break;
        }
        if (ln_len != 4) {
          free(ln);
          s = protocol_fail(sqlrc);
          break;
        }
        uint64_t length = ((uint64_t)ln[0] << 24) | ((uint64_t)ln[1] << 16) |
                          ((uint64_t)ln[2] << 8) | (uint64_t)ln[3];
        free(ln);
        if (length == 0 || params->max_transaction_bytes < 0 ||
            length > (uint64_t)params->max_transaction_bytes) {
          s = busy_fail(sqlrc);
          break;
        }
        /* Go wraps used+length the same way before comparing */
        int64_t sum = (int64_t)((uint64_t)used + length);
        if (n_payloads > 0 && sum > params->batch_bytes) {
          break;
        }
        used = sum;
        uint8_t *page = NULL;
        size_t page_len = 0;
        s = murmur_tx_stream_read(db, &inc.manifest, cursor + 4,
                                  (int64_t)length, &page, &page_len, sqlrc);
        if (s != MURMUR_SYNC_OK) {
          break;
        }
        payloads[n_payloads] = page;
        payload_lens[n_payloads] = page_len;
        owned[n_payloads] = page;
        n_payloads++;
        cursor += 4 + length;
      }
      if (s == MURMUR_SYNC_OK) {
        size_t cl = 0;
        uint8_t *cenc = murmur_tx_encode_u64(cursor, &cl);
        if (!cenc) {
          s = sqlite_fail(sqlrc, SQLITE_NOMEM);
        } else {
          murmur_kv_record_t r;
          memset(&r, 0, sizeof(r));
          r.key = ikey;
          r.key_len = iklen;
          r.value = cenc;
          r.value_len = cl;
          s = murmur_backend_apply(db, payloads, payload_lens, n_payloads, &r,
                                   1, sqlrc);
          free(cenc);
        }
      }
      for (size_t i = 0; i < n_payloads; i++) {
        free(owned[i]);
      }
      if (s != MURMUR_SYNC_OK) {
        murmur_tx_incoming_free(&inc);
        free(ikey);
        free(data);
        return s;
      }
      /* backend_apply success always means applied (Go returns true
       * with nil error); an unfinished cursor just needs recall */
      if (cursor < inc.manifest.bytes) {
        murmur_tx_incoming_free(&inc);
        free(ikey);
        free(data);
        return ok_rc(sqlrc);
      }
    }
  }
  murmur_tx_incoming_t receipt = inc;
  receipt.deadline = murmur_snap_deadline(params, now);
  size_t rkl = 0, rel = 0;
  uint8_t *rkey2 = murmur_tx_receipt_key(transfer, &rkl);
  uint8_t *renc = murmur_tx_incoming_encode(&receipt, &rel);
  size_t hdkl = 0;
  uint8_t *hdkey = murmur_tx_header_key(MURMUR_TX_IN, transfer, &hdkl);
  if (!rkey2 || !renc || !hdkey) {
    free(rkey2);
    free(renc);
    free(hdkey);
    murmur_tx_incoming_free(&inc);
    free(ikey);
    free(data);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  size_t nrecs = 3 + inc.manifest.n_progress;
  murmur_kv_record_t *recs =
      (murmur_kv_record_t *)calloc(nrecs ? nrecs : 1, sizeof(*recs));
  uint8_t **aux = (uint8_t **)calloc(nrecs * 2 ? nrecs * 2 : 1, sizeof(*aux));
  if (!recs || !aux) {
    free(recs);
    free(aux);
    free(rkey2);
    free(renc);
    free(hdkey);
    murmur_tx_incoming_free(&inc);
    free(ikey);
    free(data);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  aux[0] = rkey2;
  aux[1] = renc;
  aux[2] = hdkey;
  aux[3] = ikey; /* adopted: freed with the batch below */
  ikey = NULL;
  recs[0].key = rkey2;
  recs[0].key_len = rkl;
  recs[0].value = renc;
  recs[0].value_len = rel;
  recs[1].key = hdkey;
  recs[1].key_len = hdkl;
  recs[1].is_delete = 1;
  recs[2].key = aux[3];
  recs[2].key_len = iklen;
  recs[2].is_delete = 1;
  size_t naux = 4;
  for (size_t i = 0; i < inc.manifest.n_progress && s == MURMUR_SYNC_OK; i++) {
    size_t pkl = 0;
    uint8_t *pkey =
        murmur_tx_progress_key(&inc.manifest.progress[i].origin, &pkl);
    if (!pkey) {
      s = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    aux[naux++] = pkey;
    uint8_t *praw = NULL;
    size_t prlen = 0;
    int pok = 0;
    s = murmur_kv_get(db, pkey, pkl, &praw, &prlen, &pok, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    uint64_t old = 0;
    if (pok) {
      s = murmur_tx_decode_u64(praw, prlen, &old, sqlrc);
      free(praw);
      if (s != MURMUR_SYNC_OK) {
        break;
      }
    }
    if (inc.manifest.progress[i].applied > old) {
      old = inc.manifest.progress[i].applied;
    }
    size_t ovl = 0;
    uint8_t *ov = murmur_tx_encode_u64(old, &ovl);
    if (!ov) {
      s = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    aux[naux++] = ov;
    recs[3 + i].key = pkey;
    recs[3 + i].key_len = pkl;
    recs[3 + i].value = ov;
    recs[3 + i].value_len = ovl;
  }
  if (s == MURMUR_SYNC_OK) {
    if (!streamed) {
      const uint8_t *one = data ? data : (const uint8_t *)"";
      s = murmur_backend_apply(db, &one, &data_len, 1, recs, nrecs, sqlrc);
    } else {
      s = murmur_backend_apply(db, NULL, NULL, 0, recs, nrecs, sqlrc);
    }
  }
  for (size_t i = 0; i < naux; i++) {
    free(aux[i]);
  }
  free(aux);
  free(recs);
  murmur_tx_incoming_free(&inc);
  free(ikey);
  free(data);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (done) {
    *done = 1;
  }
  return ok_rc(sqlrc);
}

/* ---- build_for ---- */

static murmur_sync_status_t commit_emit(void *ctx,
                                        const murmur_kv_record_t *records,
                                        size_t n, int *sqlrc) {
  return murmur_kv_commit((sqlite3 *)ctx, records, n, sqlrc);
}

murmur_sync_status_t murmur_snap_build_for(
    sqlite3 *db, const murmur_node_t *database, const murmur_node_t *donor,
    const murmur_snap_params_t *params, int64_t batch_bytes,
    int64_t max_batch_bytes, const murmur_node_t *recipient, uint64_t now,
    murmur_tx_manifest_t *out, int *sqlrc) {
  uint8_t *schema_raw = NULL;
  size_t schema_len = 0;
  murmur_sync_status_t s =
      murmur_backend_schema(db, &schema_raw, &schema_len, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  uint8_t schema[32];
  murmur_sha256(schema_raw ? schema_raw : (const uint8_t *)"", schema_len,
                schema);
  free(schema_raw);
  murmur_tx_progress_t *heads = NULL;
  size_t n_heads = 0;
  s = murmur_tx_progress(db, &heads, &n_heads, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  const uint8_t **pages = NULL;
  size_t *page_lens = NULL;
  size_t n_pages = 0, cap_pages = 0;
  murmur_cursor_t cursor;
  memset(&cursor, 0, sizeof(cursor));
  murmur_stored_cursor_t owned;
  memset(&owned, 0, sizeof(owned));
  int have_owned = 0;
  for (;;) {
    murmur_export_t batch;
    memset(&batch, 0, sizeof(batch));
    s = murmur_sync_export(db, &cursor, batch_bytes, max_batch_bytes, &batch,
                           sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    if (n_pages >= cap_pages) {
      size_t ncap = cap_pages ? cap_pages * 2 : 4;
      const uint8_t **np =
          (const uint8_t **)realloc(pages, ncap * sizeof(*np));
      size_t *nl = (size_t *)realloc(page_lens, ncap * sizeof(*nl));
      if (!np || !nl) {
        free(np);
        free(nl);
        murmur_sync_export_free(&batch);
        s = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      pages = np;
      page_lens = nl;
      cap_pages = ncap;
    }
    /* the batch shell is dropped; the blob moves into pages */
    pages[n_pages] = batch.blob;
    page_lens[n_pages] = batch.blob_len;
    batch.blob = NULL;
    n_pages++;
    int more = batch.next.cursor.has_through;
    if (have_owned) {
      murmur_sync_cursor_free(&owned);
      have_owned = 0;
    }
    if (more) {
      owned = batch.next;
      batch.next.owned = NULL;
      memset(&batch.next.cursor, 0, sizeof(batch.next.cursor));
      cursor = owned.cursor;
      have_owned = 1;
    }
    murmur_sync_export_free(&batch);
    if (!more) {
      break;
    }
  }
  if (have_owned) {
    murmur_sync_cursor_free(&owned);
  }
  if (s != MURMUR_SYNC_OK) {
    for (size_t i = 0; i < n_pages; i++) {
      free((void *)pages[i]);
    }
    free(pages);
    free(page_lens);
    murmur_tx_progress_free(heads, n_heads);
    return s;
  }
  s = murmur_snap_build_streaming(database, donor, recipient, pages, page_lens,
                                  n_pages, heads, n_heads, schema, params, now,
                                  commit_emit, db, out, sqlrc);
  for (size_t i = 0; i < n_pages; i++) {
    free((void *)pages[i]);
  }
  free(pages);
  free(page_lens);
  murmur_tx_progress_free(heads, n_heads);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  size_t ml = 0;
  uint8_t *menc = murmur_tx_manifest_encode(out, &ml);
  if (!menc) {
    murmur_tx_manifest_free(out);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  free(menc);
  if (ml > FRAME_BYTES) {
    murmur_tx_manifest_free(out);
    return busy_fail(sqlrc);
  }
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}
