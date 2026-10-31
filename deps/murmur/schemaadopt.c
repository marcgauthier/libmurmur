/* murmur schemaadopt - see schemaadopt.h. */
#include "schemaadopt.h"

#include <stdlib.h>
#include <string.h>

#include "kv.h"
#include "sha256.h"
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

static int schema_too_large(const murmur_schema_params_t *p, size_t len) {
  return p->max_schema_bytes < 0 ||
         len > (uint64_t)p->max_schema_bytes;
}

/* digest[32] + uvarint sequence, no trailing bytes */
static murmur_sync_status_t read_cursor(sqlite3 *db, uint8_t digest[32],
                                        uint64_t *sequence, int *found,
                                        int *sqlrc) {
  static const uint8_t key[] = "07/replication/schema/manifest";
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int ok = 0;
  murmur_sync_status_t s =
      murmur_kv_get(db, key, sizeof(key) - 1, &raw, &raw_len, &ok, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (!ok) {
    *found = 0;
    return ok_rc(sqlrc);
  }
  if (raw_len < 32) {
    free(raw);
    return protocol_fail(sqlrc);
  }
  memcpy(digest, raw, 32);
  size_t pos = 32;
  uint64_t v = 0;
  if (murmur_tx_uvarint_decode(raw, raw_len, &pos, &v) != 0 ||
      pos != raw_len) {
    free(raw);
    return protocol_fail(sqlrc);
  }
  free(raw);
  *sequence = v;
  *found = 1;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_schema_build_manifest(
    sqlite3 *db, const murmur_schema_params_t *params,
    const murmur_node_t *own, const murmur_node_t *database,
    const uint8_t *schema, size_t schema_len, murmur_signed_schema_t *out,
    int *sqlrc) {
  if (params->master_enabled &&
      (!params->has_master || !murmur_node_eq(&params->master, own))) {
    return invalid_fail(sqlrc);
  }
  if (schema_too_large(params, schema_len)) {
    return busy_fail(sqlrc);
  }
  uint8_t digest[32];
  murmur_sha256(schema ? schema : (const uint8_t *)"", schema_len, digest);
  uint8_t stored[32];
  uint64_t sequence = 1;
  int found = 0;
  murmur_sync_status_t s = read_cursor(db, stored, &sequence, &found, sqlrc);
  if (s != MURMUR_SYNC_OK) {
    return s;
  }
  if (found && memcmp(stored, digest, 32) == 0) {
    /* keep sequence */
  } else if (found) {
    if (sequence == UINT64_MAX) {
      return protocol_fail(sqlrc);
    }
    sequence++;
  } else {
    sequence = 1;
  }
  if (!found || memcmp(stored, digest, 32) != 0) {
    static const uint8_t key[] = "07/replication/schema/manifest";
    uint8_t enc[32 + 10];
    memcpy(enc, digest, 32);
    size_t vl = murmur_tx_uvarint_encode(sequence, enc + 32, 10);
    if (vl == 0) {
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    murmur_kv_record_t r;
    memset(&r, 0, sizeof(r));
    r.key = (uint8_t *)key;
    r.key_len = sizeof(key) - 1;
    r.value = enc;
    r.value_len = 32 + vl;
    s = murmur_kv_commit(db, &r, 1, sqlrc);
    if (s != MURMUR_SYNC_OK) {
      return s;
    }
  }
  murmur_signed_schema_t m;
  memset(&m, 0, sizeof(m));
  m.database = *database;
  m.signer = *own;
  m.sequence = sequence;
  m.schema = (uint8_t *)malloc(schema_len ? schema_len : 1);
  if (!m.schema) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  memcpy(m.schema, schema, schema_len);
  m.schema_len = schema_len;
  if (out) {
    *out = m;
  } else {
    murmur_signed_schema_free(&m);
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_schema_verify_transport(
    const murmur_signed_schema_t *s, const murmur_node_t *database,
    const murmur_node_t *source, const murmur_schema_params_t *params,
    int *sqlrc) {
  if (!murmur_node_eq(&s->database, database) ||
      !murmur_node_eq(&s->signer, source) || s->sequence == 0 ||
      schema_too_large(params, s->schema_len)) {
    return auth_fail(sqlrc);
  }
  return ok_rc(sqlrc);
}

static uint8_t *accepted_key(const murmur_node_t *signer, size_t *len) {
  static const char *pfx = "07/replication/schema/accepted/";
  static const char *d = "0123456789abcdef";
  size_t pl = strlen(pfx);
  uint8_t *out = (uint8_t *)malloc(pl + 32 + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, pfx, pl);
  for (int i = 0; i < 16; i++) {
    out[pl + 2 * i] = (uint8_t)d[signer->b[i] >> 4];
    out[pl + 2 * i + 1] = (uint8_t)d[signer->b[i] & 15];
  }
  out[pl + 32] = '\0';
  if (len) {
    *len = pl + 32;
  }
  return out;
}

murmur_sync_status_t murmur_schema_record_accepted(
    sqlite3 *db, const murmur_signed_schema_t *s, int *sqlrc) {
  size_t klen = 0;
  uint8_t *key = accepted_key(&s->signer, &klen);
  uint8_t *val = (uint8_t *)malloc(10 + 10 + s->schema_len);
  if (!key || !val) {
    free(key);
    free(val);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  size_t pos = murmur_tx_uvarint_encode(s->sequence, val, 10);
  size_t vl = murmur_tx_uvarint_encode((uint64_t)s->schema_len, val + pos,
                                       10);
  if (pos == 0 || vl == 0) {
    free(key);
    free(val);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  pos += vl;
  memcpy(val + pos, s->schema, s->schema_len);
  pos += s->schema_len;
  murmur_kv_record_t r;
  memset(&r, 0, sizeof(r));
  r.key = key;
  r.key_len = klen;
  r.value = val;
  r.value_len = pos;
  murmur_sync_status_t st = murmur_kv_commit(db, &r, 1, sqlrc);
  free(key);
  free(val);
  return st;
}

/* uvarint seq + uvarint-len bytes, no trailing bytes */
static murmur_sync_status_t read_accepted(const uint8_t *raw, size_t raw_len,
                                          uint64_t *sequence, int *sqlrc) {
  size_t pos = 0;
  uint64_t seq = 0, len = 0;
  if (!raw || murmur_tx_uvarint_decode(raw, raw_len, &pos, &seq) != 0 ||
      murmur_tx_uvarint_decode(raw, raw_len, &pos, &len) != 0 ||
      len > raw_len - pos || pos + len != raw_len) {
    return protocol_fail(sqlrc);
  }
  *sequence = seq;
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

murmur_sync_status_t murmur_schema_check_manifest(
    sqlite3 *db, const murmur_schema_params_t *params,
    const murmur_node_t *own, const uint8_t *local_schema,
    size_t local_len, const murmur_signed_schema_t *s,
    const murmur_node_t *database, const murmur_node_t *source,
    murmur_schema_decision_t *decision, int *sqlrc) {
  if (decision) {
    *decision = MURMUR_SCHEMA_RECORD;
  }
  murmur_sync_status_t st =
      murmur_schema_verify_transport(s, database, source, params, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  int adoptable;
  if (params->has_master) {
    int master_self =
        params->master_enabled && murmur_node_eq(&params->master, own);
    adoptable = murmur_node_eq(&s->signer, &params->master) && !master_self;
  } else {
    adoptable = 1;
  }
  size_t klen = 0;
  uint8_t *key = accepted_key(&s->signer, &klen);
  if (!key) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  uint8_t *raw = NULL;
  size_t raw_len = 0;
  int found = 0;
  st = murmur_kv_get(db, key, klen, &raw, &raw_len, &found, sqlrc);
  free(key);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint64_t accepted_seq = 0;
  if (found) {
    st = read_accepted(raw, raw_len, &accepted_seq, sqlrc);
    free(raw);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
  }
  if (s->sequence <= accepted_seq) {
    if (decision) {
      *decision = MURMUR_SCHEMA_STALE;
    }
    return ok_rc(sqlrc);
  }
  if (s->schema_len == local_len &&
      memcmp(s->schema, local_schema, local_len) == 0) {
    st = murmur_schema_record_accepted(db, s, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    if (decision) {
      *decision = MURMUR_SCHEMA_CURRENT;
    }
    return ok_rc(sqlrc);
  }
  if (!adoptable || !params->accept_remote) {
    st = murmur_schema_record_accepted(db, s, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    return ok_rc(sqlrc);
  }
  murmur_schema_diff_t diff;
  memset(&diff, 0, sizeof(diff));
  st = murmur_schema_diff(local_schema, local_len, s->schema, s->schema_len,
                          &diff, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  int additive = diff.additive;
  murmur_schema_diff_free(&diff);
  if (!additive) {
    st = murmur_schema_record_accepted(db, s, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    return ok_rc(sqlrc);
  }
  if (decision) {
    *decision = MURMUR_SCHEMA_ADOPT;
  }
  return ok_rc(sqlrc);
}
