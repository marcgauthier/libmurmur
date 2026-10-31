/* murmur retainpass - see retainpass.h. */
#include "retainpass.h"

#include <stdlib.h>
#include <string.h>

#include "kv.h"
#include "sqlite3.h"
#include "txretain.h"
#include "txsnap.h"

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

static int node_in(const murmur_node_t *ids, size_t n,
                   const murmur_node_t *x) {
  for (size_t i = 0; i < n; i++) {
    if (murmur_node_eq(&ids[i], x)) {
      return 1;
    }
  }
  return 0;
}

static uint64_t ack_lookup(const murmur_tx_peer_t *peer,
                           const murmur_node_t *origin) {
  for (size_t i = peer->n_acks; i > 0; i--) {
    if (murmur_node_eq(&peer->acks[i - 1].origin, origin)) {
      return peer->acks[i - 1].seq;
    }
  }
  return 0;
}

/* A peer counts toward floors unless retired or stale-offline. */
static int peer_counts(const murmur_tx_peer_t *peer,
                       const murmur_retain_params_t *params,
                       const murmur_node_t *online, size_t n_online,
                       uint64_t now_millis) {
  uint64_t since = 0;
  if (now_millis >= peer->last_seen_millis) {
    since = now_millis - peer->last_seen_millis;
  }
  return !peer->retired &&
         (node_in(online, n_online, &peer->node) ||
          since <= params->max_offline_ms);
}

murmur_sync_status_t murmur_collect_floors(sqlite3 *db,
                                           const murmur_node_t *node,
                                           const murmur_retain_params_t *params,
                                           const murmur_node_t *online,
                                           size_t n_online, uint64_t now_millis,
                                           uint64_t boot_millis,
                                           uint64_t *moved, int *sqlrc) {
  if (moved) {
    *moved = 0;
  }
  murmur_tx_retention_status_t st;
  memset(&st, 0, sizeof(st));
  murmur_sync_status_t s = murmur_tx_status(db, &st, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  int unrecorded = 0;
  for (size_t i = 0; i < n_online && !unrecorded; i++) {
    int found = 0;
    for (size_t k = 0; k < st.n_peers && !found; k++) {
      found = murmur_node_eq(&st.peers[k].node, &online[i]);
    }
    unrecorded = !found;
  }
  int young = params->bootstrap_nonempty && now_millis >= boot_millis &&
              now_millis - boot_millis < MURMUR_STARTUP_GRACE_MILLIS;
  murmur_tx_progress_t *heads = NULL;
  size_t n_heads = 0;
  s = murmur_backend_progress(db, node, &heads, &n_heads, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    murmur_tx_retention_status_free(&st);
    return s;
  }
  murmur_kv_record_t *recs = NULL;
  size_t nrecs = 0, cap = 0;
  uint8_t **owned = NULL;
  size_t nowned = 0, cap_owned = 0;
  uint64_t nmoved = 0;
  uint64_t npruned = 0;
  for (size_t h = 0; h < n_heads && s == MURMUR_SYNC_OK; h++) {
    int have_recorded = 0;
    uint64_t recorded = 0;
    for (size_t k = 0; k < st.n_peers; k++) {
      if (!peer_counts(&st.peers[k], params, online, n_online, now_millis)) {
        continue;
      }
      uint64_t ack = ack_lookup(&st.peers[k], &heads[h].origin);
      if (!have_recorded || ack < recorded) {
        recorded = ack;
        have_recorded = 1;
      }
    }
    uint64_t peer_floor;
    if (unrecorded) {
      peer_floor = 0;
    } else if (have_recorded) {
      peer_floor = recorded;
    } else if (young) {
      peer_floor = 0;
    } else {
      peer_floor = UINT64_MAX;
    }
    uint64_t snapshot_floor = UINT64_MAX;
    s = murmur_tx_prune_limit(db, &heads[h].origin, now_millis, &snapshot_floor,
                              sqlrc);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    uint64_t tail_cap = 0;
    if (heads[h].applied > params->min_retained) {
      tail_cap = heads[h].applied - params->min_retained;
    }
    uint64_t floor = peer_floor;
    if (snapshot_floor < floor) {
      floor = snapshot_floor;
    }
    if (tail_cap < floor) {
      floor = tail_cap;
    }
    size_t fkl = 0;
    uint8_t *fkey = murmur_tx_floor_key(&heads[h].origin, &fkl);
    if (!fkey) {
      s = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    uint8_t *fraw = NULL;
    size_t flen = 0;
    int fok = 0;
    s = murmur_kv_get(db, fkey, fkl, &fraw, &flen, &fok, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      free(fkey);
      break;
    }
    uint64_t prev = 0;
    if (fok) {
      s = murmur_tx_decode_u64(fraw, flen, &prev, sqlrc);
      free(fraw);
      if (s != MURMUR_SYNC_OK) {
        free(fkey);
        break;
      }
    }
    if (floor <= prev) {
      free(fkey);
      continue;
    }
    npruned += floor - prev;
    size_t ovl = 0;
    uint8_t *ov = murmur_tx_encode_u64(floor, &ovl);
    murmur_tx_progress_t retained = heads[h];
    retained.retained_from = floor + 1;
    if (floor == UINT64_MAX) {
      retained.retained_from = UINT64_MAX;
    }
    retained.retained_through = heads[h].applied;
    size_t rkl = 0, rel = 0;
    uint8_t *rkey = murmur_tx_retained_key(&heads[h].origin, &rkl);
    uint8_t *re = murmur_tx_progress_encode(&retained, &rel);
    if (!ov || !rkey || !re) {
      free(fkey);
      free(ov);
      free(rkey);
      free(re);
      s = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
    if (nrecs + 2 > cap) {
      size_t ncap = cap ? cap * 2 : 8;
      while (ncap < nrecs + 2) {
        ncap *= 2;
      }
      murmur_kv_record_t *nr =
          (murmur_kv_record_t *)realloc(recs, ncap * sizeof(*nr));
      if (!nr) {
        free(fkey);
        free(ov);
        free(rkey);
        free(re);
        s = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      recs = nr;
      cap = ncap;
    }
    if (nowned + 4 > cap_owned) {
      size_t ncap = cap_owned ? cap_owned * 2 : 16;
      while (ncap < nowned + 4) {
        ncap *= 2;
      }
      uint8_t **no = (uint8_t **)realloc(owned, ncap * sizeof(*no));
      if (!no) {
        free(fkey);
        free(ov);
        free(rkey);
        free(re);
        s = sqlite_fail(sqlrc, SQLITE_NOMEM);
        break;
      }
      owned = no;
      cap_owned = ncap;
    }
    owned[nowned++] = fkey;
    owned[nowned++] = ov;
    owned[nowned++] = rkey;
    owned[nowned++] = re;
    recs[nrecs].key = fkey;
    recs[nrecs].key_len = fkl;
    recs[nrecs].value = ov;
    recs[nrecs].value_len = ovl;
    recs[nrecs].is_delete = 0;
    nrecs++;
    recs[nrecs].key = rkey;
    recs[nrecs].key_len = rkl;
    recs[nrecs].value = re;
    recs[nrecs].value_len = rel;
    recs[nrecs].is_delete = 0;
    nrecs++;
    nmoved++;
  }
  murmur_tx_retention_status_free(&st);
  murmur_tx_progress_free(heads, n_heads);
  if (s != MURMUR_SYNC_OK) {
    for (size_t i = 0; i < nowned; i++) {
      free(owned[i]);
    }
    free(owned);
    free(recs);
    return s;
  }
  if (nrecs > 0) {
    s = murmur_kv_commit(db, recs, nrecs, sqlrc);
  }
  for (size_t i = 0; i < nowned; i++) {
    free(owned[i]);
  }
  free(owned);
  free(recs);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  /* the collection stamp lands even when no floor moved; the pruned
   * total advances by this pass's released transactions */
  static const uint8_t last[] = "07/replication/retention/last";
  static const uint8_t collected[] = "07/replication/retention/collected";
  size_t el = 0;
  uint8_t *enc = murmur_tx_encode_u64(now_millis, &el);
  if (!enc) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint64_t total = npruned;
  uint8_t *craw = NULL;
  size_t craw_len = 0;
  int cfound = 0;
  s = murmur_kv_get(db, collected, sizeof(collected) - 1, &craw, &craw_len,
                    &cfound, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    free(enc);
    return s;
  }
  if (cfound) {
    uint64_t prev_total = 0;
    s = murmur_tx_decode_u64(craw, craw_len, &prev_total, sqlrc);
    free(craw);
    if (s != MURMUR_SYNC_OK) {
      free(enc);
      return s;
    }
    total += prev_total;
  }
  size_t cl = 0;
  uint8_t *cenc = murmur_tx_encode_u64(total, &cl);
  if (!cenc) {
    free(enc);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_kv_record_t stamp[2];
  memset(stamp, 0, sizeof(stamp));
  stamp[0].key = (uint8_t *)last;
  stamp[0].key_len = sizeof(last) - 1;
  stamp[0].value = enc;
  stamp[0].value_len = el;
  stamp[1].key = (uint8_t *)collected;
  stamp[1].key_len = sizeof(collected) - 1;
  stamp[1].value = cenc;
  stamp[1].value_len = cl;
  s = murmur_kv_commit(db, stamp, 2, sqlrc);
  free(enc);
  free(cenc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (moved) {
    *moved = nmoved;
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_my_stream_floor(sqlite3 *db,
                                            const murmur_retain_params_t *params,
                                            const murmur_node_t *online,
                                            size_t n_online,
                                            const murmur_node_t *own,
                                            uint64_t own_applied,
                                            uint64_t now_millis,
                                            uint64_t boot_millis,
                                            uint64_t *floor, int *sqlrc) {
  if (floor) {
    *floor = 0;
  }
  murmur_tx_retention_status_t st;
  memset(&st, 0, sizeof(st));
  murmur_sync_status_t s = murmur_tx_status(db, &st, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  for (size_t i = 0; i < n_online; i++) {
    int found = 0;
    for (size_t k = 0; k < st.n_peers && !found; k++) {
      found = murmur_node_eq(&st.peers[k].node, &online[i]);
    }
    if (!found) {
      murmur_tx_retention_status_free(&st);
      return ok_rc(sqlrc);
    }
  }
  int have_acked = 0;
  uint64_t acked = 0;
  for (size_t k = 0; k < st.n_peers; k++) {
    if (!peer_counts(&st.peers[k], params, online, n_online, now_millis)) {
      continue;
    }
    uint64_t v = ack_lookup(&st.peers[k], own);
    if (!have_acked || v < acked) {
      acked = v;
      have_acked = 1;
    }
  }
  murmur_tx_retention_status_free(&st);
  int young = params->bootstrap_nonempty && now_millis >= boot_millis &&
              now_millis - boot_millis < MURMUR_STARTUP_GRACE_MILLIS;
  uint64_t fl;
  if (have_acked) {
    fl = acked;
    if (own_applied < fl) {
      fl = own_applied;
    }
  } else if (young) {
    fl = 0;
  } else {
    fl = own_applied;
  }
  if (fl < params->min_retained) {
    return ok_rc(sqlrc);
  }
  if (floor) {
    *floor = fl - params->min_retained;
  }
  return ok_rc(sqlrc);
}
