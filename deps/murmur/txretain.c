/* murmur txretain - see txretain.h. */
#include "txretain.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kv.h"
#include "sqlite3.h"

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

uint64_t murmur_tx_now_millis(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

void murmur_tx_retention_status_free(murmur_tx_retention_status_t *st) {
  if (!st) {
    return;
  }
  if (st->peers) {
    for (size_t i = 0; i < st->n_peers; i++) {
      murmur_tx_peer_free(&st->peers[i]);
    }
    free(st->peers);
  }
  memset(st, 0, sizeof(*st));
}

murmur_sync_status_t murmur_tx_status(sqlite3 *db,
                                      murmur_tx_retention_status_t *st,
                                      int *sqlrc) {
  memset(st, 0, sizeof(*st));
  static const uint8_t pfx[] = "07/replication/retention/peers/";
  uint8_t **keys = NULL;
  size_t *lens = NULL, n = 0;
  murmur_sync_status_t s =
      murmur_kv_keys(db, pfx, sizeof(pfx) - 1, &keys, &lens, &n, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  size_t cap = 0;
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
    if (st->n_peers >= cap) {
      size_t ncap = cap ? cap * 2 : 8;
      murmur_tx_peer_t *nv =
          (murmur_tx_peer_t *)realloc(st->peers, ncap * sizeof(*nv));
      if (!nv) {
        free(raw);
        s = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        break;
      }
      st->peers = nv;
      cap = ncap;
    }
    s = murmur_tx_peer_decode(raw, raw_len, &st->peers[st->n_peers], sqlrc);
    free(raw);
    if (s != MURMUR_SYNC_OK) {
      break;
    }
    st->n_peers++;
  }
  murmur_kv_keys_free(keys, lens, n);
  if (s != MURMUR_SYNC_OK) {
    murmur_tx_retention_status_free(st);
    return s;
  }
  static const uint8_t collected[] = "07/replication/retention/collected";
  static const uint8_t last[] = "07/replication/retention/last";
  const uint8_t *ck[2] = {collected, last};
  const size_t cl[2] = {sizeof(collected) - 1, sizeof(last) - 1};
  uint64_t *slots[2] = {&st->collected_transactions,
                        &st->last_collection_millis};
  for (int i = 0; i < 2; i++) {
    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int found = 0;
    s = murmur_kv_get(db, ck[i], cl[i], &raw, &raw_len, &found, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      murmur_tx_retention_status_free(st);
      return s;
    }
    if (found) {
      s = murmur_tx_decode_u64(raw, raw_len, slots[i], sqlrc);
      free(raw);
      if (s != MURMUR_SYNC_OK) {
        murmur_tx_retention_status_free(st);
        return s;
      }
    }
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_tx_peer(sqlite3 *db, const murmur_node_t *node,
                                    murmur_tx_peer_t *peer, int *found,
                                    int *sqlrc) {
  if (found) {
    *found = 0;
  }
  size_t klen = 0;
  uint8_t *key = murmur_tx_peer_key(node, &klen);
  if (!key) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int ok = 0;
  murmur_sync_status_t s =
      murmur_kv_get(db, key, klen, &raw, &raw_len, &ok, sqlrc);
  free(key);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (!ok) {
    return ok_rc(sqlrc);
  }
  murmur_tx_peer_t tmp;
  s = murmur_tx_peer_decode(raw, raw_len, &tmp, sqlrc);
  free(raw);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (peer) {
    *peer = tmp;
  } else {
    murmur_tx_peer_free(&tmp);
  }
  if (found) {
    *found = 1;
  }
  return ok_rc(sqlrc);
}

/* Last-wins ack lookup (wire order preserved, Go map keeps last). */
static uint64_t ack_lookup(const murmur_tx_ack_t *acks, size_t n,
                           const murmur_node_t *origin) {
  for (size_t i = n; i > 0; i--) {
    if (murmur_node_eq(&acks[i - 1].origin, origin)) {
      return acks[i - 1].seq;
    }
  }
  return 0;
}

murmur_sync_status_t murmur_tx_touch(sqlite3 *db, const murmur_node_t *node,
                                     const murmur_tx_progress_t *progress,
                                     size_t n_progress, int *sqlrc) {
  murmur_tx_peer_t state;
  memset(&state, 0, sizeof(state));
  int found = 0;
  murmur_sync_status_t s = murmur_tx_peer(db, node, &state, &found, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (!found) {
    state.node = *node;
  }
  if (state.retired) {
    murmur_tx_peer_free(&state);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_AUTH;
  }
  uint64_t now = murmur_tx_now_millis();
  int changed = state.last_seen_millis == 0;
  for (size_t i = 0; i < n_progress; i++) {
    uint64_t v = ack_lookup(state.acks, state.n_acks, &progress[i].origin);
    if (progress[i].applied > v) {
      changed = 1;
      /* update last occurrence, else append (Go map assign) */
      size_t slot = state.n_acks;
      for (size_t k = state.n_acks; k > 0; k--) {
        if (murmur_node_eq(&state.acks[k - 1].origin, &progress[i].origin)) {
          slot = k - 1;
          break;
        }
      }
      if (slot == state.n_acks) {
        murmur_tx_ack_t *nv = (murmur_tx_ack_t *)realloc(
            state.acks, (state.n_acks + 1) * sizeof(*nv));
        if (!nv) {
          murmur_tx_peer_free(&state);
          return sqlite_fail(sqlrc, SQLITE_NOMEM);
        }
        state.acks = nv;
        state.acks[state.n_acks].origin = progress[i].origin;
        state.n_acks++;
      }
      state.acks[slot].seq = progress[i].applied;
    }
  }
  /* Go counts map entries (deduped); count distinct origins */
  size_t distinct = 0;
  for (size_t i = 0; i < state.n_acks; i++) {
    int seen = 0;
    for (size_t k = 0; k < i; k++) {
      if (murmur_node_eq(&state.acks[k].origin, &state.acks[i].origin)) {
        seen = 1;
        break;
      }
    }
    distinct += !seen;
  }
  if (distinct > 4096) {
    murmur_tx_peer_free(&state);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_OVERLOADED;
  }
  uint64_t since = 0;
  if (now >= state.last_seen_millis) {
    since = now - state.last_seen_millis;
  }
  if (!changed && since < 10000) {
    murmur_tx_peer_free(&state);
    return ok_rc(sqlrc);
  }
  if (now > state.last_seen_millis) {
    state.last_seen_millis = now;
  }
  size_t klen = 0, vlen = 0;
  uint8_t *key = murmur_tx_peer_key(node, &klen);
  uint8_t *val = murmur_tx_peer_encode(&state, &vlen);
  murmur_tx_peer_free(&state);
  if (!key || !val) {
    free(key);
    free(val);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  r.key = key;
  r.key_len = klen;
  r.value = val;
  r.value_len = vlen;
  s = murmur_kv_commit(db, &r, 1, sqlrc);
  free(key);
  free(val);
  return s;
}

murmur_sync_status_t murmur_tx_retire(sqlite3 *db, const murmur_node_t *node,
                                      int *sqlrc) {
  murmur_tx_peer_t state;
  memset(&state, 0, sizeof(state));
  int found = 0;
  murmur_sync_status_t s = murmur_tx_peer(db, node, &state, &found, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (!found) {
    state.node = *node;
    state.last_seen_millis = murmur_tx_now_millis();
  }
  state.retired = 1;
  size_t klen = 0, vlen = 0, elen = 0;
  uint8_t *key = murmur_tx_peer_key(node, &klen);
  uint8_t *val = murmur_tx_peer_encode(&state, &vlen);
  uint8_t *excl = murmur_tx_excluded_key(node, &elen);
  murmur_tx_peer_free(&state);
  if (!key || !val || !excl) {
    free(key);
    free(val);
    free(excl);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  murmur_kv_record_t rs[2];
  memset(rs, 0, sizeof(rs));
  rs[0].key = key;
  rs[0].key_len = klen;
  rs[0].value = val;
  rs[0].value_len = vlen;
  rs[1].key = excl;
  rs[1].key_len = elen;
  rs[1].value = (uint8_t *)node->b; /* kv_commit only reads values */
  rs[1].value_len = 16;
  s = murmur_kv_commit(db, rs, 2, sqlrc);
  free(key);
  free(val);
  free(excl);
  return s;
}
