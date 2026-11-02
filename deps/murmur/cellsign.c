#include "cellsign.h"

#include "../aws-lc/include/openssl/curve25519.h"
#include "../aws-lc/include/openssl/mem.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  uint8_t seed[32];
} cellsign_seed_t;

static const char kSlot[] = "murmur.native.cellsign.v1";

static void seed_free(void *p) {
  if (p) {
    OPENSSL_cleanse(p, sizeof(cellsign_seed_t));
    free(p);
  }
}

int murmur_cellsign_attach(sqlite3 *db, const uint8_t seed[32]) {
  if (!db || !seed) {
    return SQLITE_MISUSE;
  }
  cellsign_seed_t *s = (cellsign_seed_t *)malloc(sizeof(*s));
  if (!s) {
    return SQLITE_NOMEM;
  }
  memcpy(s->seed, seed, 32);
  /* set_clientdata frees any prior seed through seed_free. */
  if (sqlite3_set_clientdata(db, kSlot, s, seed_free) != SQLITE_OK) {
    seed_free(s);
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

void murmur_cellsign_detach(sqlite3 *db) {
  if (db) {
    sqlite3_set_clientdata(db, kSlot, NULL, NULL);
  }
}

int murmur_cellsign_pubkey(const uint8_t seed[32], uint8_t pub[32]) {
  uint8_t priv[ED25519_PRIVATE_KEY_LEN];
  if (!seed || !pub) {
    return SQLITE_MISUSE;
  }
  ED25519_keypair_from_seed(pub, priv, seed);
  OPENSSL_cleanse(priv, sizeof(priv));
  return SQLITE_OK;
}

int murmur_cellsign_sign(sqlite3 *db, const uint8_t *msg, size_t len,
                         uint8_t sig[64]) {
  uint8_t priv[ED25519_PRIVATE_KEY_LEN];
  uint8_t pub[ED25519_PUBLIC_KEY_LEN];
  cellsign_seed_t *s;
  if (!db || !sig || (!msg && len > 0)) {
    return SQLITE_MISUSE;
  }
  s = (cellsign_seed_t *)sqlite3_get_clientdata(db, kSlot);
  if (!s) {
    return SQLITE_MISUSE;
  }
  ED25519_keypair_from_seed(pub, priv, s->seed);
  if (!ED25519_sign(sig, msg, len, priv)) {
    OPENSSL_cleanse(priv, sizeof(priv));
    return SQLITE_ERROR;
  }
  OPENSSL_cleanse(priv, sizeof(priv));
  return SQLITE_OK;
}

int murmur_cellsign_verify(const uint8_t pub[32], const uint8_t *msg,
                           size_t len, const uint8_t sig[64]) {
  if (!pub || !sig || (!msg && len > 0)) {
    return SQLITE_MISUSE;
  }
  return ED25519_verify(msg, len, sig, pub) ? SQLITE_OK : SQLITE_AUTH;
}

static int hex_val(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int hex_decode(const char *s, uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++) {
    int hi = hex_val(s[2 * i]);
    int lo = hex_val(s[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

int murmur_cellsign_trust_load(sqlite3 *db, murmur_cellsign_trust_t *t,
                               int *sqlrc) {
  static const char kSQL[] =
      "SELECT value FROM murmur_config WHERE name='trusted_origins'";
  sqlite3_stmt *st = NULL;
  if (!db || !t) {
    if (sqlrc) {
      *sqlrc = SQLITE_MISUSE;
    }
    return SQLITE_MISUSE;
  }
  memset(t, 0, sizeof(*t));
  /* Stores without replication metadata (e.g. managed stores)
   * are unconfigured (legacy), not broken. */
  static const char kHas[] =
      "SELECT 1 FROM sqlite_schema WHERE type='table' AND "
      "name='murmur_config'";
  if (sqlite3_prepare_v2(db, kHas, -1, &st, NULL) != SQLITE_OK) {
    if (sqlrc) {
      *sqlrc = sqlite3_errcode(db);
    }
    return sqlite3_errcode(db);
  }
  int has = sqlite3_step(st) == SQLITE_ROW;
  sqlite3_finalize(st);
  st = NULL;
  if (!has) {
    if (sqlrc) {
      *sqlrc = SQLITE_OK;
    }
    return SQLITE_OK;
  }
  if (sqlite3_prepare_v2(db, kSQL, -1, &st, NULL) != SQLITE_OK) {
    if (sqlrc) {
      *sqlrc = sqlite3_errcode(db);
    }
    return sqlite3_errcode(db);
  }
  int rc = sqlite3_step(st);
  char *raw = NULL;
  if (rc == SQLITE_ROW) {
    const uint8_t *v = sqlite3_column_text(st, 0);
    int n = sqlite3_column_bytes(st, 0);
    if (v) {
      raw = (char *)malloc((size_t)n + 1);
      if (!raw) {
        sqlite3_finalize(st);
        if (sqlrc) {
          *sqlrc = SQLITE_NOMEM;
        }
        return SQLITE_NOMEM;
      }
      memcpy(raw, v, (size_t)n);
      raw[n] = '\0';
    }
  } else if (rc != SQLITE_DONE) {
    if (sqlrc) {
      *sqlrc = rc;
    }
    sqlite3_finalize(st);
    return rc;
  }
  sqlite3_finalize(st);
  if (!raw || !raw[0]) {
    free(raw);
    if (sqlrc) {
      *sqlrc = SQLITE_OK;
    }
    return SQLITE_OK;
  }
  /* {"<site-hex>":"<pubkey-hex>", ...}; parsed with json_each.
   * Malformed entries are skipped (fail closed at lookup: an
   * unparseable pin simply never matches). */
  static const char kEach[] =
      "SELECT key, value FROM json_each(?) WHERE type='text'";
  if (sqlite3_prepare_v2(db, kEach, -1, &st, NULL) != SQLITE_OK) {
    free(raw);
    if (sqlrc) {
      *sqlrc = sqlite3_errcode(db);
    }
    return sqlite3_errcode(db);
  }
  sqlite3_bind_text(st, 1, raw, -1, SQLITE_TRANSIENT);
  free(raw);
  size_t cap = 0;
  while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
    const char *k = (const char *)sqlite3_column_text(st, 0);
    const char *v = (const char *)sqlite3_column_text(st, 1);
    murmur_cellsign_entry_t e;
    if (!k || !v || strlen(k) != 32 || strlen(v) != 64 ||
        hex_decode(k, e.site, 16) != 0 || hex_decode(v, e.pub, 32) != 0) {
      continue;
    }
    if (t->n == cap) {
      size_t ncap = cap ? cap * 2 : 16;
      murmur_cellsign_entry_t *grown =
          (murmur_cellsign_entry_t *)realloc(t->ents,
                                             ncap * sizeof(*t->ents));
      if (!grown) {
        sqlite3_finalize(st);
        murmur_cellsign_trust_free(t);
        if (sqlrc) {
          *sqlrc = SQLITE_NOMEM;
        }
        return SQLITE_NOMEM;
      }
      t->ents = grown;
      cap = ncap;
    }
    t->ents[t->n++] = e;
  }
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    murmur_cellsign_trust_free(t);
    if (sqlrc) {
      *sqlrc = rc;
    }
    return rc;
  }
  if (sqlrc) {
    *sqlrc = SQLITE_OK;
  }
  return SQLITE_OK;
}

void murmur_cellsign_trust_free(murmur_cellsign_trust_t *t) {
  if (t) {
    free(t->ents);
    memset(t, 0, sizeof(*t));
  }
}

const uint8_t *murmur_cellsign_trust_find(const murmur_cellsign_trust_t *t,
                                          const uint8_t site[16]) {
  if (!t || !site) {
    return NULL;
  }
  for (size_t i = 0; i < t->n; i++) {
    if (memcmp(t->ents[i].site, site, 16) == 0) {
      return t->ents[i].pub;
    }
  }
  return NULL;
}

int murmur_cellsign_ensure_schema(sqlite3 *db, int *sqlrc) {
  static const char kDDL[] =
      "CREATE TABLE IF NOT EXISTS murmur_cell_sigs("
      "\"table\" BLOB NOT NULL,pk BLOB NOT NULL,cid BLOB NOT NULL,"
      "site BLOB NOT NULL,col_version INTEGER NOT NULL,sig BLOB NOT NULL,"
      "PRIMARY KEY(\"table\",pk,cid,site,col_version));";
  char *err = NULL;
  if (!db) {
    if (sqlrc) {
      *sqlrc = SQLITE_MISUSE;
    }
    return SQLITE_MISUSE;
  }
  int rc = sqlite3_exec(db, kDDL, NULL, NULL, &err);
  sqlite3_free(err);
  if (sqlrc) {
    *sqlrc = rc == SQLITE_OK ? SQLITE_OK : rc;
  }
  return rc;
}

int murmur_cellsign_store(sqlite3 *db, const uint8_t *table, size_t table_len,
                          const uint8_t *pk, size_t pk_len, const uint8_t *cid,
                          size_t cid_len, const uint8_t site[16],
                          int64_t col_version, const uint8_t sig[64],
                          int *sqlrc) {
  static const char kSQL[] =
      "INSERT OR REPLACE INTO murmur_cell_sigs"
      "(\"table\",pk,cid,site,col_version,sig) VALUES(?1,?2,?3,?4,?5,?6)";
  sqlite3_stmt *st = NULL;
  int rc;
  if (!db || !sig) {
    if (sqlrc) {
      *sqlrc = SQLITE_MISUSE;
    }
    return SQLITE_MISUSE;
  }
  rc = sqlite3_prepare_v2(db, kSQL, -1, &st, NULL);
  if (rc != SQLITE_OK) {
    if (sqlrc) {
      *sqlrc = rc;
    }
    return rc;
  }
  sqlite3_bind_blob(st, 1, table, (int)table_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, pk, (int)pk_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, cid, (int)cid_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 4, site, 16, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 5, col_version);
  sqlite3_bind_blob(st, 6, sig, 64, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (sqlrc) {
    *sqlrc = rc == SQLITE_DONE ? SQLITE_OK : rc;
  }
  return rc == SQLITE_DONE ? SQLITE_OK : rc;
}

int murmur_cellsign_lookup(sqlite3 *db, const uint8_t *table, size_t table_len,
                           const uint8_t *pk, size_t pk_len,
                           const uint8_t *cid, size_t cid_len,
                           const uint8_t site[16], int64_t col_version,
                           uint8_t sig[64], int *sqlrc) {
  static const char kSQL[] =
      "SELECT sig FROM murmur_cell_sigs WHERE \"table\"=?1 AND pk=?2 AND "
      "cid=?3 AND site=?4 AND col_version=?5";
  sqlite3_stmt *st = NULL;
  int rc;
  if (!db || !sig) {
    if (sqlrc) {
      *sqlrc = SQLITE_MISUSE;
    }
    return -1;
  }
  rc = sqlite3_prepare_v2(db, kSQL, -1, &st, NULL);
  if (rc != SQLITE_OK) {
    if (sqlrc) {
      *sqlrc = rc;
    }
    return -1;
  }
  sqlite3_bind_blob(st, 1, table, (int)table_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 2, pk, (int)pk_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 3, cid, (int)cid_len, SQLITE_TRANSIENT);
  sqlite3_bind_blob(st, 4, site, 16, SQLITE_TRANSIENT);
  sqlite3_bind_int64(st, 5, col_version);
  rc = sqlite3_step(st);
  int found = 0;
  if (rc == SQLITE_ROW) {
    const void *blob = sqlite3_column_blob(st, 0);
    if (blob && sqlite3_column_bytes(st, 0) == 64) {
      memcpy(sig, blob, 64);
      found = 1;
    }
  } else if (rc != SQLITE_DONE) {
    if (sqlrc) {
      *sqlrc = rc;
    }
    sqlite3_finalize(st);
    return -1;
  }
  sqlite3_finalize(st);
  if (sqlrc) {
    *sqlrc = SQLITE_OK;
  }
  return found;
}

int murmur_cellsign_gc(sqlite3 *db, int *sqlrc) {
  /* crsql_changes key columns may be TEXT or BLOB depending on
   * the cr-sqlite build; the sig table stores BLOBs, and SQLite
   * never equates TEXT with BLOB, so both sides CAST. */
  static const char kSQL[] =
      "DELETE FROM murmur_cell_sigs WHERE NOT EXISTS(SELECT 1 FROM "
      "crsql_changes c WHERE CAST(c.\"table\" AS BLOB)="
      "CAST(murmur_cell_sigs.\"table\" AS BLOB) AND CAST(c.pk AS BLOB)="
      "CAST(murmur_cell_sigs.pk AS BLOB) AND CAST(c.cid AS BLOB)="
      "CAST(murmur_cell_sigs.cid AS BLOB) AND CAST(c.site_id AS BLOB)="
      "CAST(murmur_cell_sigs.site AS BLOB) AND "
      "c.col_version=murmur_cell_sigs.col_version)";
  char *err = NULL;
  int rc;
  if (!db) {
    if (sqlrc) {
      *sqlrc = SQLITE_MISUSE;
    }
    return SQLITE_MISUSE;
  }
  rc = sqlite3_exec(db, kSQL, NULL, NULL, &err);
  sqlite3_free(err);
  if (sqlrc) {
    *sqlrc = rc == SQLITE_OK ? SQLITE_OK : rc;
  }
  return rc;
}
