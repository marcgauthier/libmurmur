/* Native search manager. See search.h and search.go. */
#include "search.h"

#include <ctype.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "vec0.h"

const char *murmur_search_status_str(murmur_search_status_t st) {
  switch (st) {
    case MURMUR_SEARCH_OK:
      return "ok";
    case MURMUR_SEARCH_INVALID:
      return "invalid";
    case MURMUR_SEARCH_SQLITE:
      return "sqlite";
    case MURMUR_SEARCH_NOMEM:
      return "nomem";
    case MURMUR_SEARCH_MISMATCH:
      return "mismatch";
  }
  return "unknown";
}

/* ---------- small owned sets ---------- */

typedef struct {
  char **v;
  size_t n, cap;
} strset_t;

static void strset_free(strset_t *s) {
  for (size_t i = 0; i < s->n; i++) {
    free(s->v[i]);
  }
  free(s->v);
  memset(s, 0, sizeof(*s));
}

static void strset_clear(strset_t *s) {
  for (size_t i = 0; i < s->n; i++) {
    free(s->v[i]);
  }
  s->n = 0;
}

static int strset_has(const strset_t *s, const char *lower) {
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->v[i], lower) == 0) {
      return 1;
    }
  }
  return 0;
}

/* Adds an already-lowercased owned copy; 0 ok, -1 nomem. */
static int strset_add(strset_t *s, const char *lower) {
  if (strset_has(s, lower)) {
    return 0;
  }
  if (s->n == s->cap) {
    size_t ncap = s->cap ? s->cap * 2 : 8;
    char **nv = (char **)realloc(s->v, ncap * sizeof(*nv));
    if (!nv) {
      return -1;
    }
    s->v = nv;
    s->cap = ncap;
  }
  char *cp = strdup(lower);
  if (!cp) {
    return -1;
  }
  s->v[s->n++] = cp;
  return 0;
}

static char *str_lower(const char *s) {
  size_t n = strlen(s);
  char *o = (char *)malloc(n + 1);
  if (!o) {
    return NULL;
  }
  for (size_t i = 0; i < n; i++) {
    o[i] = (char)tolower((unsigned char)s[i]);
  }
  o[n] = '\0';
  return o;
}

typedef struct {
  char *table; /* lowercased source */
  int64_t rowid;
} hit_t;

typedef struct {
  hit_t *v;
  size_t n, cap;
} hitlist_t;

static void hitlist_free(hitlist_t *h) {
  for (size_t i = 0; i < h->n; i++) {
    free(h->v[i].table);
  }
  free(h->v);
  memset(h, 0, sizeof(*h));
}

static void hitlist_clear(hitlist_t *h) {
  for (size_t i = 0; i < h->n; i++) {
    free(h->v[i].table);
  }
  h->n = 0;
}

typedef struct {
  int64_t *v;
  size_t n, cap;
} keyset_t;

static void keyset_free(keyset_t *s) {
  free(s->v);
  memset(s, 0, sizeof(*s));
}

static void keyset_clear(keyset_t *s) { s->n = 0; }

static int keyset_add(keyset_t *s, int64_t k) {
  if (s->n == s->cap) {
    size_t ncap = s->cap ? s->cap * 2 : 32;
    int64_t *nv = (int64_t *)realloc(s->v, ncap * sizeof(*nv));
    if (!nv) {
      return -1;
    }
    s->v = nv;
    s->cap = ncap;
  }
  s->v[s->n++] = k;
  return 0;
}

static int key_cmp(const void *a, const void *b) {
  int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
  return (x > y) - (x < y);
}

/* ---------- owned definition ---------- */

typedef struct {
  murmur_search_tag_t tag;
  char *name;
  char *source;
  char **columns;
  size_t n_columns;
  char *tokenizer; /* fts5, default unicode61 */
  char *vector_column;
  int dimensions;
  murmur_distance_t distance;
} def_t;

static void def_free(def_t *d) {
  free(d->name);
  free(d->source);
  for (size_t i = 0; i < d->n_columns; i++) {
    free(d->columns[i]);
  }
  free(d->columns);
  free(d->tokenizer);
  free(d->vector_column);
  memset(d, 0, sizeof(*d));
}

static int def_copy(def_t *dst, const murmur_search_def_t *src) {
  memset(dst, 0, sizeof(*dst));
  dst->tag = src->tag;
  dst->name = src->name ? strdup(src->name) : NULL;
  dst->source = src->source_table ? strdup(src->source_table) : NULL;
  if ((src->name && !dst->name) || (src->source_table && !dst->source)) {
    def_free(dst);
    return -1;
  }
  if (src->tag == MURMUR_SEARCH_FTS5) {
    if (src->n_columns) {
      dst->columns = (char **)calloc(src->n_columns, sizeof(char *));
      if (!dst->columns) {
        def_free(dst);
        return -1;
      }
      for (size_t i = 0; i < src->n_columns; i++) {
        dst->columns[i] = strdup(src->columns[i] ? src->columns[i] : "");
        if (!dst->columns[i]) {
          dst->n_columns = i;
          def_free(dst);
          return -1;
        }
      }
      dst->n_columns = src->n_columns;
    }
    dst->tokenizer = strdup(src->tokenizer && src->tokenizer[0]
                                ? src->tokenizer
                                : "unicode61");
    if (!dst->tokenizer) {
      def_free(dst);
      return -1;
    }
  } else {
    dst->vector_column =
        strdup(src->vector_column ? src->vector_column : "");
    if (!dst->vector_column) {
      def_free(dst);
      return -1;
    }
    dst->dimensions = src->dimensions;
    dst->distance = src->distance;
  }
  return 0;
}

static int def_equal(const def_t *a, const def_t *b) {
  if (a->tag != b->tag) {
    return 0;
  }
  if (strcmp(a->name, b->name) != 0 || strcmp(a->source, b->source) != 0) {
    return 0;
  }
  if (a->tag == MURMUR_SEARCH_VECTOR) {
    return strcmp(a->vector_column, b->vector_column) == 0 &&
           a->dimensions == b->dimensions && a->distance == b->distance;
  }
  if (strcmp(a->tokenizer, b->tokenizer) != 0 ||
      a->n_columns != b->n_columns) {
    return 0;
  }
  for (size_t i = 0; i < a->n_columns; i++) {
    if (strcmp(a->columns[i], b->columns[i]) != 0) {
      return 0;
    }
  }
  return 1;
}

typedef struct {
  def_t def;
  strset_t owned; /* lowercased temp names */
  int installed;
  int ready;
  int rebuild;
  int started;
  int has_last;
  int64_t last;
  int worowid; /* source is WITHOUT ROWID: hook-blind, tripwired */
  keyset_t keys;
  char *err; /* nullable owned */
} index_state_t;

static void index_free(index_state_t *s) {
  def_free(&s->def);
  strset_free(&s->owned);
  keyset_free(&s->keys);
  free(s->err);
  memset(s, 0, sizeof(*s));
}

static void index_invalidate(index_state_t *s) {
  s->rebuild = 1;
  s->started = 0;
  s->has_last = 0;
  keyset_clear(&s->keys);
  s->ready = 0;
}

struct murmur_search_manager {
  pthread_mutex_t mu;
  def_t *explicit_defs;
  size_t n_explicit;
  index_state_t *indexes;
  size_t n_indexes;
  hitlist_t hits;          /* update-hook (table, rowid) pairs */
  sqlite3 *attached;         /* borrowed hook connection, nullable */
  sqlite3_int64 changes_seen; /* total_changes() after last tick */
  strset_t queued_sources; /* lowercased tables with noted churn */
  size_t budget;
  size_t batch;
  size_t next;
  strset_t publications;
  pthread_mutex_t guard_mu;
  strset_t guard_names;
  char *guard_ready; /* parallel to guard_names.v: 0/1 */
};

static void set_detail(char **out, const char *msg) {
  if (out) {
    *out = msg ? strdup(msg) : NULL;
  }
}

static void set_sqlrc(int *out, int rc) {
  if (out) {
    *out = rc;
  }
}

static murmur_search_status_t invalid(char **detail, int *sqlrc,
                                      const char *msg) {
  set_detail(detail, msg);
  set_sqlrc(sqlrc, SQLITE_MISUSE);
  return MURMUR_SEARCH_INVALID;
}

static murmur_search_status_t sqlite_err(char **detail, int *sqlrc, int rc) {
  set_detail(detail, "search sqlite error");
  set_sqlrc(sqlrc, rc);
  return MURMUR_SEARCH_SQLITE;
}

static murmur_search_status_t nomem(char **detail, int *sqlrc) {
  set_detail(detail, "search out of memory");
  set_sqlrc(sqlrc, SQLITE_NOMEM);
  return MURMUR_SEARCH_NOMEM;
}

/* ---------- validation (ValidateSearchOptions) ---------- */

static int ascii_letter(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int ascii_alnum(unsigned char c) {
  return ascii_letter(c) || (c >= '0' && c <= '9');
}

static int ascii_equal_fold(const char *a, const char *b) {
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
      return 0;
    }
    a++;
    b++;
  }
  return *a == *b;
}

static int has_nul(const char *s) { return strchr(s, '\0') != s + strlen(s); }

static murmur_search_status_t validate_defs(const murmur_search_def_t *defs,
                                            size_t n, char **detail) {
  strset_t names;
  memset(&names, 0, sizeof(names));
  murmur_search_status_t st = MURMUR_SEARCH_OK;
  for (size_t i = 0; i < n && st == MURMUR_SEARCH_OK; i++) {
    const murmur_search_def_t *d = &defs[i];
    const char *name = d->name ? d->name : "";
    const char *source = d->source_table ? d->source_table : "";
    char *lower = str_lower(name);
    if (!lower) {
      st = MURMUR_SEARCH_NOMEM;
      set_detail(detail, "search out of memory");
      break;
    }
    int dup = strset_has(&names, lower);
    int bad_name = name[0] == '\0' || has_nul(name) || source[0] == '\0' ||
                   has_nul(source) || strncmp(lower, "sqlite_", 7) == 0 ||
                   strncmp(lower, "_crdt_", 6) == 0 || dup;
    if (!bad_name && strset_add(&names, lower) != 0) {
      st = MURMUR_SEARCH_NOMEM;
      set_detail(detail, "search out of memory");
    }
    free(lower);
    if (bad_name) {
      st = invalid(detail, NULL, "invalid or duplicate search index name");
      break;
    }
    if (st != MURMUR_SEARCH_OK) {
      break;
    }
    /* Columns: FTS5 list, vector singleton. */
    strset_t lowered;
    memset(&lowered, 0, sizeof(lowered));
    size_t ncol = d->tag == MURMUR_SEARCH_VECTOR ? 1 : d->n_columns;
    int valid = ncol > 0;
    for (size_t k = 0; k < ncol && valid; k++) {
      const char *c = d->tag == MURMUR_SEARCH_VECTOR ? d->vector_column
                                                    : d->columns[k];
      if (!c) {
        c = "";
      }
      char *lc = str_lower(c);
      if (!lc || c[0] == '\0' || has_nul(c) || ascii_equal_fold(c, "rowid") ||
          ascii_equal_fold(c, name) || strset_has(&lowered, lc)) {
        valid = 0;
      } else if (strset_add(&lowered, lc) != 0) {
        st = MURMUR_SEARCH_NOMEM;
        set_detail(detail, "search out of memory");
        valid = 0;
      }
      free(lc);
    }
    strset_free(&lowered);
    if (st != MURMUR_SEARCH_OK) {
      break;
    }
    if (!valid) {
      st = invalid(detail, NULL, "invalid search index columns");
      break;
    }
    if (d->tag == MURMUR_SEARCH_FTS5) {
      const char *tok = d->tokenizer && d->tokenizer[0] ? d->tokenizer
                                                       : "unicode61";
      if (strcmp(tok, "unicode61") != 0 && strcmp(tok, "ascii") != 0 &&
          strcmp(tok, "porter") != 0 && strcmp(tok, "trigram") != 0) {
        st = invalid(detail, NULL, "unsupported FTS5 tokenizer");
        break;
      }
    } else {
      const char *col = d->vector_column ? d->vector_column : "";
      if (col[0] == '\0' || !ascii_letter((unsigned char)col[0])) {
        st = invalid(
            detail, NULL, "sqlite-vec column names must be ASCII SQL identifiers");
        break;
      }
      for (size_t k = 0; col[k]; k++) {
        if (!ascii_alnum((unsigned char)col[k]) && col[k] != '_') {
          st = invalid(detail, NULL,
                       "sqlite-vec column names must be ASCII SQL identifiers");
          break;
        }
      }
      if (st != MURMUR_SEARCH_OK) {
        break;
      }
      if (d->dimensions < 1 || d->dimensions > 8192) {
        st = invalid(detail, NULL, "vector dimensions must be from 1 to 8192");
        break;
      }
      if (d->distance != MURMUR_DIST_L1 && d->distance != MURMUR_DIST_L2 &&
          d->distance != MURMUR_DIST_COSINE) {
        st = invalid(detail, NULL, "invalid vector distance");
        break;
      }
    }
  }
  strset_free(&names);
  return st;
}

murmur_search_status_t murmur_search_open(const murmur_search_def_t *defs,
                                          size_t n_defs, size_t queue_bytes,
                                          size_t batch_rows,
                                          murmur_search_manager_t **out,
                                          char **detail_out) {
  if (out) {
    *out = NULL;
  }
  if (detail_out) {
    *detail_out = NULL;
  }
  if (queue_bytes == 0 || queue_bytes > (128u << 20) || batch_rows == 0 ||
      batch_rows > 65536) {
    return invalid(detail_out, NULL, "invalid search maintenance limits");
  }
  if (n_defs && !defs) {
    return invalid(detail_out, NULL, "invalid search index name");
  }
  murmur_search_status_t st = validate_defs(defs, n_defs, detail_out);
  if (st != MURMUR_SEARCH_OK) {
    return st;
  }
  murmur_search_manager_t *m =
      (murmur_search_manager_t *)calloc(1, sizeof(*m));
  if (!m) {
    return nomem(detail_out, NULL);
  }
  pthread_mutex_init(&m->mu, NULL);
  pthread_mutex_init(&m->guard_mu, NULL);
  m->budget = queue_bytes;
  m->batch = batch_rows;
  if (n_defs) {
    m->explicit_defs = (def_t *)calloc(n_defs, sizeof(def_t));
    m->indexes = (index_state_t *)calloc(n_defs, sizeof(index_state_t));
    if (!m->explicit_defs || !m->indexes) {
      murmur_search_close(m);
      return nomem(detail_out, NULL);
    }
    for (size_t i = 0; i < n_defs; i++) {
      if (def_copy(&m->explicit_defs[i], &defs[i]) != 0 ||
          def_copy(&m->indexes[i].def, &defs[i]) != 0) {
        m->n_explicit = i;
        m->n_indexes = i;
        murmur_search_close(m);
        return nomem(detail_out, NULL);
      }
      char *lower = str_lower(defs[i].name);
      if (!lower || strset_add(&m->indexes[i].owned, lower) != 0) {
        free(lower);
        m->n_explicit = i + 1;
        m->n_indexes = i + 1;
        murmur_search_close(m);
        return nomem(detail_out, NULL);
      }
      free(lower);
    }
    m->n_explicit = n_defs;
    m->n_indexes = n_defs;
  }
  *out = m;
  return MURMUR_SEARCH_OK;
}

void murmur_search_close(murmur_search_manager_t *m) {
  if (!m) {
    return;
  }
  for (size_t i = 0; i < m->n_explicit; i++) {
    def_free(&m->explicit_defs[i]);
  }
  free(m->explicit_defs);
  for (size_t i = 0; i < m->n_indexes; i++) {
    index_free(&m->indexes[i]);
  }
  free(m->indexes);
  hitlist_free(&m->hits);
  strset_free(&m->queued_sources);
  strset_free(&m->publications);
  strset_free(&m->guard_names);
  free(m->guard_ready);
  pthread_mutex_destroy(&m->guard_mu);
  pthread_mutex_destroy(&m->mu);
  free(m);
}

static int index_copy(index_state_t *dst, const index_state_t *src) {
  memset(dst, 0, sizeof(*dst));
  /* Rebuild an owned def from src's owned strings. */
  murmur_search_def_t tmp;
  memset(&tmp, 0, sizeof(tmp));
  tmp.tag = src->def.tag;
  tmp.name = src->def.name;
  tmp.source_table = src->def.source;
  if (src->def.tag == MURMUR_SEARCH_FTS5) {
    const char **cols =
        (const char **)calloc(src->def.n_columns ? src->def.n_columns : 1,
                              sizeof(char *));
    if (!cols) {
      return -1;
    }
    for (size_t i = 0; i < src->def.n_columns; i++) {
      cols[i] = src->def.columns[i];
    }
    tmp.columns = cols;
    tmp.n_columns = src->def.n_columns;
    tmp.tokenizer = src->def.tokenizer;
    int rc = def_copy(&dst->def, &tmp);
    free(cols);
    if (rc != 0) {
      return -1;
    }
  } else {
    tmp.vector_column = src->def.vector_column;
    tmp.dimensions = src->def.dimensions;
    tmp.distance = src->def.distance;
    if (def_copy(&dst->def, &tmp) != 0) {
      return -1;
    }
  }
  for (size_t i = 0; i < src->owned.n; i++) {
    if (strset_add(&dst->owned, src->owned.v[i]) != 0) {
      index_free(dst);
      return -1;
    }
  }
  dst->installed = src->installed;
  dst->ready = src->ready;
  dst->rebuild = src->rebuild;
  dst->started = src->started;
  dst->has_last = src->has_last;
  dst->worowid = src->worowid;
  dst->last = src->last;
  for (size_t i = 0; i < src->keys.n; i++) {
    if (keyset_add(&dst->keys, src->keys.v[i]) != 0) {
      index_free(dst);
      return -1;
    }
  }
  if (src->err) {
    dst->err = strdup(src->err);
    if (!dst->err) {
      index_free(dst);
      return -1;
    }
  }
  return 0;
}

murmur_search_manager_t *murmur_search_clone(const murmur_search_manager_t *m) {
  if (!m) {
    return NULL;
  }
  pthread_mutex_lock((pthread_mutex_t *)&m->mu);
  murmur_search_manager_t *o =
      (murmur_search_manager_t *)calloc(1, sizeof(*o));
  if (!o) {
    pthread_mutex_unlock((pthread_mutex_t *)&m->mu);
    return NULL;
  }
  pthread_mutex_init(&o->mu, NULL);
  pthread_mutex_init(&o->guard_mu, NULL);
  o->budget = m->budget;
  o->batch = m->batch;
  o->next = m->next;
  o->changes_seen = m->changes_seen;
  int ok = 1;
  if (m->n_explicit) {
    o->explicit_defs = (def_t *)calloc(m->n_explicit, sizeof(def_t));
    if (!o->explicit_defs) {
      ok = 0;
    }
    for (size_t i = 0; ok && i < m->n_explicit; i++) {
      murmur_search_def_t tmp;
      memset(&tmp, 0, sizeof(tmp));
      tmp.tag = m->explicit_defs[i].tag;
      tmp.name = m->explicit_defs[i].name;
      tmp.source_table = m->explicit_defs[i].source;
      const char **cols = NULL;
      if (tmp.tag == MURMUR_SEARCH_FTS5) {
        cols = (const char **)calloc(
            m->explicit_defs[i].n_columns ? m->explicit_defs[i].n_columns : 1,
            sizeof(char *));
        if (!cols) {
          ok = 0;
          break;
        }
        for (size_t k = 0; k < m->explicit_defs[i].n_columns; k++) {
          cols[k] = m->explicit_defs[i].columns[k];
        }
        tmp.columns = cols;
        tmp.n_columns = m->explicit_defs[i].n_columns;
        tmp.tokenizer = m->explicit_defs[i].tokenizer;
      } else {
        tmp.vector_column = m->explicit_defs[i].vector_column;
        tmp.dimensions = m->explicit_defs[i].dimensions;
        tmp.distance = m->explicit_defs[i].distance;
      }
      if (def_copy(&o->explicit_defs[i], &tmp) != 0) {
        ok = 0;
      }
      free(cols);
    }
    o->n_explicit = m->n_explicit;
  }
  if (ok && m->n_indexes) {
    o->indexes = (index_state_t *)calloc(m->n_indexes, sizeof(index_state_t));
    if (!o->indexes) {
      ok = 0;
    }
    for (size_t i = 0; ok && i < m->n_indexes; i++) {
      if (index_copy(&o->indexes[i], &m->indexes[i]) != 0) {
        ok = 0;
      }
    }
    o->n_indexes = m->n_indexes;
  }
  if (ok && m->hits.n) {
    o->hits.v = (hit_t *)calloc(m->hits.n, sizeof(hit_t));
    if (!o->hits.v) {
      ok = 0;
    } else {
      for (size_t i = 0; ok && i < m->hits.n; i++) {
        o->hits.v[i].table = strdup(m->hits.v[i].table);
        o->hits.v[i].rowid = m->hits.v[i].rowid;
        ok = o->hits.v[i].table != NULL;
      }
      o->hits.n = m->hits.n;
      o->hits.cap = m->hits.n;
    }
  }
  for (size_t i = 0; ok && i < m->queued_sources.n; i++) {
    ok = strset_add(&o->queued_sources, m->queued_sources.v[i]) == 0;
  }
  for (size_t i = 0; ok && i < m->publications.n; i++) {
    ok = strset_add(&o->publications, m->publications.v[i]) == 0;
  }
  pthread_mutex_lock((pthread_mutex_t *)&m->guard_mu);
  for (size_t i = 0; ok && i < m->guard_names.n; i++) {
    ok = strset_add(&o->guard_names, m->guard_names.v[i]) == 0;
  }
  if (ok && m->guard_names.n) {
    o->guard_ready = (char *)malloc(m->guard_names.n);
    if (!o->guard_ready) {
      ok = 0;
    } else {
      memcpy(o->guard_ready, m->guard_ready, m->guard_names.n);
    }
  }
  pthread_mutex_unlock((pthread_mutex_t *)&m->guard_mu);
  pthread_mutex_unlock((pthread_mutex_t *)&m->mu);
  if (!ok) {
    murmur_search_close(o);
    return NULL;
  }
  return o;
}

/* ---------- quoting + createSQL ---------- */

/* Go quote(): double quotes, inner quotes doubled. */
static char *sql_quote(const char *s) {
  size_t n = strlen(s), extra = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '"') {
      extra++;
    }
  }
  char *o = (char *)malloc(n + extra + 3);
  if (!o) {
    return NULL;
  }
  char *p = o;
  *p++ = '"';
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '"') {
      *p++ = '"';
    }
    *p++ = s[i];
  }
  *p++ = '"';
  *p = '\0';
  return o;
}

static const char *distance_name(murmur_distance_t d) {
  switch (d) {
    case MURMUR_DIST_L2:
      return "l2";
    case MURMUR_DIST_COSINE:
      return "cosine";
    case MURMUR_DIST_L1:
      return "l1";
  }
  return "unknown";
}

/* CREATE VIRTUAL TABLE temp."name" USING fts5(...)/vec0(...). The
 * vector column travels unquoted, like search.go (validated to ASCII
 * identifier at open). */
static char *create_sql(const def_t *d) {
  char *out = NULL;
  if (d->tag == MURMUR_SEARCH_VECTOR) {
    out = sqlite3_mprintf("CREATE VIRTUAL TABLE temp.%w USING vec0(%s "
                          "float[%d] distance_metric=%s)",
                          d->name, d->vector_column, d->dimensions,
                          distance_name(d->distance));
    return out;
  }
  size_t need = 0;
  char **quoted = NULL;
  if (d->n_columns) {
    quoted = (char **)calloc(d->n_columns, sizeof(char *));
    if (!quoted) {
      return NULL;
    }
    for (size_t i = 0; i < d->n_columns; i++) {
      quoted[i] = sql_quote(d->columns[i]);
      if (!quoted[i]) {
        for (size_t k = 0; k < i; k++) {
          free(quoted[k]);
        }
        free(quoted);
        return NULL;
      }
      need += strlen(quoted[i]) + 1;
    }
  }
  char *cols = (char *)malloc(need + 1);
  if (!cols) {
    for (size_t i = 0; i < d->n_columns; i++) {
      free(quoted[i]);
    }
    free(quoted);
    return NULL;
  }
  cols[0] = '\0';
  for (size_t i = 0; i < d->n_columns; i++) {
    if (i) {
      strcat(cols, ",");
    }
    strcat(cols, quoted[i]);
    free(quoted[i]);
  }
  free(quoted);
  /* Tokenizer is single-quoted verbatim like search.go; the value was
   * validated against the built-in set at open. */
  out = sqlite3_mprintf(
      "CREATE VIRTUAL TABLE temp.%w USING fts5(%s, tokenize='%s')", d->name,
      cols, d->tokenizer);
  free(cols);
  return out;
}

/* ---------- live-schema introspection ---------- */

typedef struct {
  char *name;
  char *type;
  int pk; /* 1-based pk order, 0 = not pk */
} table_col_t;

static void table_cols_free(table_col_t *cols, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(cols[i].name);
    free(cols[i].type);
  }
  free(cols);
}

/* PRAGMA main.table_info("table"). without_rowid set when the create
 * SQL carries WITHOUT ROWID. found=0 when the table is absent. */
static murmur_search_status_t table_info(sqlite3 *db, const char *table,
                                         table_col_t **cols_out, size_t *n_out,
                                         int *without_rowid, int *found,
                                         char **detail, int *sqlrc) {
  *cols_out = NULL;
  *n_out = 0;
  *without_rowid = 0;
  *found = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT sql FROM main.sqlite_schema WHERE type='table' AND name=?",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_err(detail, sqlrc, rc);
  }
  sqlite3_bind_text(st, 1, table, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_ROW) {
    const unsigned char *sql = sqlite3_column_text(st, 0);
    *found = 1;
    if (sql) {
      /* Case-insensitive WITHOUT ROWID scan. */
      const char *s = (const char *)sql;
      size_t n = strlen(s);
      for (size_t i = 0; i + 13 <= n; i++) {
        if (strncasecmp(s + i, "without rowid", 13) == 0) {
          *without_rowid = 1;
          break;
        }
      }
    }
  } else if (rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_err(detail, sqlrc, rc);
  }
  sqlite3_finalize(st);
  if (!*found) {
    return MURMUR_SEARCH_OK;
  }
  char *pragma = sqlite3_mprintf("PRAGMA main.table_info(%w)", table);
  if (!pragma) {
    return nomem(detail, sqlrc);
  }
  rc = sqlite3_prepare_v2(db, pragma, -1, &st, NULL);
  sqlite3_free(pragma);
  if (rc != SQLITE_OK) {
    return sqlite_err(detail, sqlrc, rc);
  }
  table_col_t *cols = NULL;
  size_t n = 0, cap = 0;
  murmur_search_status_t s = MURMUR_SEARCH_OK;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      s = sqlite_err(detail, sqlrc, rc);
      break;
    }
    if (n == cap) {
      size_t ncap = cap ? cap * 2 : 8;
      table_col_t *nv =
          (table_col_t *)realloc(cols, ncap * sizeof(*nv));
      if (!nv) {
        s = nomem(detail, sqlrc);
        break;
      }
      cols = nv;
      cap = ncap;
    }
    const unsigned char *cn = sqlite3_column_text(st, 1);
    const unsigned char *ct = sqlite3_column_text(st, 2);
    cols[n].name = strdup(cn ? (const char *)cn : "");
    cols[n].type = strdup(ct ? (const char *)ct : "");
    cols[n].pk = sqlite3_column_int(st, 5);
    if (!cols[n].name || !cols[n].type) {
      free(cols[n].name);
      free(cols[n].type);
      s = nomem(detail, sqlrc);
      break;
    }
    n++;
  }
  sqlite3_finalize(st);
  if (s != MURMUR_SEARCH_OK) {
    table_cols_free(cols, n);
    return s;
  }
  *cols_out = cols;
  *n_out = n;
  return MURMUR_SEARCH_OK;
}

/* Lowercased names of temp tables/indexes (tempSearchTables). */
static murmur_search_status_t temp_tables(sqlite3 *db, strset_t *out,
                                          char **detail, int *sqlrc) {
  memset(out, 0, sizeof(*out));
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT name FROM sqlite_temp_schema WHERE type IN ('table','index')",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_err(detail, sqlrc, rc);
  }
  murmur_search_status_t s = MURMUR_SEARCH_OK;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      s = sqlite_err(detail, sqlrc, rc);
      break;
    }
    const unsigned char *nm = sqlite3_column_text(st, 0);
    if (nm) {
      char *lower = str_lower((const char *)nm);
      if (!lower || strset_add(out, lower) != 0) {
        free(lower);
        s = nomem(detail, sqlrc);
        break;
      }
      free(lower);
    }
  }
  sqlite3_finalize(st);
  if (s != MURMUR_SEARCH_OK) {
    strset_free(out);
  }
  return s;
}

static int exec_batch(sqlite3 *db, const char *sql, char **detail,
                      int *sqlrc) {
  char *err = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
  sqlite3_free(err);
  if (rc != SQLITE_OK) {
    set_detail(detail, "search sqlite error");
    set_sqlrc(sqlrc, rc);
    return -1;
  }
  return 0;
}

/* ---------- register / validate / sync / drop ---------- */

murmur_search_status_t murmur_search_register(sqlite3 *db,
                                              const murmur_search_manager_t *m,
                                              char **detail_out, int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  if (murmurRegisterVec0(db) != SQLITE_OK) {
    return sqlite_err(detail_out, sqlrc, sqlite3_errcode(db));
  }
  size_t n = 0;
  if (m) {
    pthread_mutex_lock((pthread_mutex_t *)&m->mu);
    n = m->n_indexes;
    pthread_mutex_unlock((pthread_mutex_t *)&m->mu);
  }
  if (n == 0) {
    return MURMUR_SEARCH_OK;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, "PRAGMA temp_store", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_err(detail_out, sqlrc, rc);
  }
  rc = sqlite3_step(st);
  int cur = rc == SQLITE_ROW ? sqlite3_column_int(st, 0) : -1;
  sqlite3_finalize(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    return sqlite_err(detail_out, sqlrc, rc);
  }
  if (cur != 2) {
    if (exec_batch(db, "PRAGMA temp_store=MEMORY", detail_out, sqlrc) != 0) {
      return MURMUR_SEARCH_SQLITE;
    }
  }
  return MURMUR_SEARCH_OK;
}

/* Caller holds m->mu. Mirrors ValidateSearchSchema against live SQL
 * introspection: source exists (unless allow_missing and not
 * installed), exactly one INTEGER PRIMARY KEY column, indexed
 * columns present with TEXT (fts5) / BLOB (vector) declared type. */
static murmur_search_status_t validate_schema_locked(
    murmur_search_manager_t *m, sqlite3 *db, int allow_missing,
    char **detail, int *sqlrc) {
  for (size_t i = 0; i < m->n_indexes; i++) {
    index_state_t *ix = &m->indexes[i];
    const def_t *d = &ix->def;
    /* Source schema colliding with an owned temp name. */
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(
        db, "SELECT name FROM main.sqlite_schema WHERE type='table'", -1, &st,
        NULL);
    if (rc != SQLITE_OK) {
      return sqlite_err(detail, sqlrc, rc);
    }
    murmur_search_status_t s = MURMUR_SEARCH_OK;
    for (;;) {
      rc = sqlite3_step(st);
      if (rc == SQLITE_DONE) {
        break;
      }
      if (rc != SQLITE_ROW) {
        s = sqlite_err(detail, sqlrc, rc);
        break;
      }
      const unsigned char *tn = sqlite3_column_text(st, 0);
      if (tn) {
        char *lower = str_lower((const char *)tn);
        if (!lower) {
          s = nomem(detail, sqlrc);
          break;
        }
        if (strset_has(&ix->owned, lower)) {
          char *msg = sqlite3_mprintf(
              "source schema collides with search index %s", d->name);
          set_detail(detail, msg ? msg : "source schema collides");
          sqlite3_free(msg);
          set_sqlrc(sqlrc, SQLITE_MISUSE);
          s = MURMUR_SEARCH_INVALID;
        }
        free(lower);
        if (s != MURMUR_SEARCH_OK) {
          break;
        }
      }
    }
    sqlite3_finalize(st);
    if (s != MURMUR_SEARCH_OK) {
      return s;
    }
    table_col_t *cols = NULL;
    size_t ncol = 0;
    int worowid = 0, found = 0;
    s = table_info(db, d->source, &cols, &ncol, &worowid, &found, detail,
                   sqlrc);
    if (s != MURMUR_SEARCH_OK) {
      return s;
    }
    if (!found) {
      if (allow_missing && !ix->installed) {
        continue;
      }
      char *msg =
          sqlite3_mprintf("missing source table %s", d->source);
      set_detail(detail, msg ? msg : "missing source table");
      sqlite3_free(msg);
      set_sqlrc(sqlrc, SQLITE_MISUSE);
      return MURMUR_SEARCH_INVALID;
    }
    /* Exactly one INTEGER PRIMARY KEY. */
    const table_col_t *pk = NULL;
    size_t npk = 0;
    for (size_t k = 0; k < ncol; k++) {
      if (cols[k].pk) {
        npk++;
        pk = &cols[k];
      }
    }
    if (npk != 1 || !ascii_equal_fold(pk->type, "INTEGER")) {
      char *msg = sqlite3_mprintf(
          "%s requires one INTEGER PRIMARY KEY for search indexing",
          d->source);
      set_detail(detail, msg ? msg : "search pk");
      sqlite3_free(msg);
      table_cols_free(cols, ncol);
      set_sqlrc(sqlrc, SQLITE_MISUSE);
      return MURMUR_SEARCH_INVALID;
    }
    size_t nneed = d->tag == MURMUR_SEARCH_VECTOR ? 1 : d->n_columns;
    for (size_t k = 0; k < nneed; k++) {
      const char *need = d->tag == MURMUR_SEARCH_VECTOR ? d->vector_column
                                                       : d->columns[k];
      const table_col_t *hit = NULL;
      for (size_t c = 0; c < ncol; c++) {
        if (strcmp(cols[c].name, need) == 0) {
          hit = &cols[c];
          break;
        }
      }
      if (!hit) {
        char *msg =
            sqlite3_mprintf("missing search column %s.%s", d->source, need);
        set_detail(detail, msg ? msg : "missing search column");
        sqlite3_free(msg);
        table_cols_free(cols, ncol);
        set_sqlrc(sqlrc, SQLITE_MISUSE);
        return MURMUR_SEARCH_INVALID;
      }
      const char *expected = d->tag == MURMUR_SEARCH_VECTOR ? "BLOB" : "TEXT";
      if (!ascii_equal_fold(hit->type, expected)) {
        char *msg = sqlite3_mprintf("%s.%s must be declared %s", d->source,
                                    hit->name, expected);
        set_detail(detail, msg ? msg : "search column type");
        sqlite3_free(msg);
        table_cols_free(cols, ncol);
        set_sqlrc(sqlrc, SQLITE_MISUSE);
        return MURMUR_SEARCH_INVALID;
      }
    }
    table_cols_free(cols, ncol);
  }
  return MURMUR_SEARCH_OK;
}

murmur_search_status_t murmur_search_drop(murmur_search_manager_t *m,
                                          sqlite3 *db, char **detail_out,
                                          int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  pthread_mutex_lock(&m->mu);
  murmur_search_status_t s = MURMUR_SEARCH_OK;
  for (size_t i = 0; i < m->n_indexes && s == MURMUR_SEARCH_OK; i++) {
    if (!m->indexes[i].installed) {
      continue;
    }
    char *sql =
        sqlite3_mprintf("DROP TABLE temp.%w", m->indexes[i].def.name);
    if (!sql) {
      s = nomem(detail_out, sqlrc);
      break;
    }
    if (exec_batch(db, sql, detail_out, sqlrc) != 0) {
      s = MURMUR_SEARCH_SQLITE;
    }
    sqlite3_free(sql);
    m->indexes[i].installed = 0;
  }
  pthread_mutex_unlock(&m->mu);
  return s;
}

/* Caller holds m->mu. */
static void publish_guard_locked(murmur_search_manager_t *m) {
  strset_t names;
  memset(&names, 0, sizeof(names));
  /* name -> ready: rebuild the parallel arrays. */
  size_t total = 0;
  for (size_t i = 0; i < m->n_indexes; i++) {
    total += m->indexes[i].owned.n;
  }
  char *ready = total ? (char *)malloc(total) : NULL;
  if (total && !ready) {
    return;
  }
  size_t w = 0;
  for (size_t i = 0; i < m->n_indexes; i++) {
    for (size_t k = 0; k < m->indexes[i].owned.n; k++) {
      const char *nm = m->indexes[i].owned.v[k];
      size_t j = 0;
      for (; j < names.n; j++) {
        if (strcmp(names.v[j], nm) == 0) {
          break;
        }
      }
      if (j < names.n) {
        ready[j] = ready[j] && m->indexes[i].ready;
        continue;
      }
      if (strset_add(&names, nm) != 0) {
        strset_free(&names);
        free(ready);
        return;
      }
      ready[w++] = m->indexes[i].ready ? 1 : 0;
    }
  }
  pthread_mutex_lock(&m->guard_mu);
  strset_free(&m->guard_names);
  free(m->guard_ready);
  m->guard_names = names;
  m->guard_ready = ready;
  pthread_mutex_unlock(&m->guard_mu);
}

murmur_search_status_t murmur_search_sync_schema(murmur_search_manager_t *m,
                                                 sqlite3 *db, int allow_missing,
                                                 char **detail_out,
                                                 int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  pthread_mutex_lock(&m->mu);
  /* Definitions are the explicit set (no StoredSchema-derived merge
   * in this port). Resync when they differ from installed states. */
  int same = m->n_explicit == m->n_indexes;
  for (size_t i = 0; same && i < m->n_explicit; i++) {
    same = def_equal(&m->explicit_defs[i], &m->indexes[i].def);
  }
  murmur_search_status_t s = MURMUR_SEARCH_OK;
  if (!same) {
    index_state_t *fresh = NULL;
    if (m->n_explicit) {
      fresh = (index_state_t *)calloc(m->n_explicit, sizeof(index_state_t));
      if (!fresh) {
        s = nomem(detail_out, sqlrc);
        goto out;
      }
      for (size_t i = 0; i < m->n_explicit; i++) {
        murmur_search_def_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.tag = m->explicit_defs[i].tag;
        tmp.name = m->explicit_defs[i].name;
        tmp.source_table = m->explicit_defs[i].source;
        const char **cols = NULL;
        if (tmp.tag == MURMUR_SEARCH_FTS5) {
          cols = (const char **)calloc(
              m->explicit_defs[i].n_columns ? m->explicit_defs[i].n_columns
                                            : 1,
              sizeof(char *));
          if (!cols) {
            for (size_t k = 0; k < i; k++) {
              index_free(&fresh[k]);
            }
            free(fresh);
            s = nomem(detail_out, sqlrc);
            goto out;
          }
          for (size_t k = 0; k < m->explicit_defs[i].n_columns; k++) {
            cols[k] = m->explicit_defs[i].columns[k];
          }
          tmp.columns = cols;
          tmp.n_columns = m->explicit_defs[i].n_columns;
          tmp.tokenizer = m->explicit_defs[i].tokenizer;
        } else {
          tmp.vector_column = m->explicit_defs[i].vector_column;
          tmp.dimensions = m->explicit_defs[i].dimensions;
          tmp.distance = m->explicit_defs[i].distance;
        }
        int rc = def_copy(&fresh[i].def, &tmp);
        free(cols);
        char *lower = rc == 0 ? str_lower(m->explicit_defs[i].name) : NULL;
        if (rc != 0 || !lower ||
            strset_add(&fresh[i].owned, lower) != 0) {
          free(lower);
          for (size_t k = 0; k <= i; k++) {
            index_free(&fresh[k]);
          }
          free(fresh);
          s = nomem(detail_out, sqlrc);
          goto out;
        }
        free(lower);
      }
    }
    /* Validate the candidate set against the live schema before
     * dropping anything. On failure the old states are restored. */
    index_state_t *saved = m->indexes;
    size_t saved_n = m->n_indexes;
    m->indexes = fresh;
    m->n_indexes = m->n_explicit;
    s = validate_schema_locked(m, db, allow_missing, detail_out, sqlrc);
    if (s == MURMUR_SEARCH_OK) {
      /* Register then drop the old tables (drop needs no lock; we
       * hold m->mu, so inline the drop here). */
      pthread_mutex_unlock(&m->mu);
      s = murmur_search_register(db, m, detail_out, sqlrc);
      pthread_mutex_lock(&m->mu);
      for (size_t i = 0; s == MURMUR_SEARCH_OK && i < saved_n; i++) {
        if (!saved[i].installed) {
          continue;
        }
        char *sql = sqlite3_mprintf("DROP TABLE temp.%w", saved[i].def.name);
        if (!sql) {
          s = nomem(detail_out, sqlrc);
          break;
        }
        if (exec_batch(db, sql, detail_out, sqlrc) != 0) {
          s = MURMUR_SEARCH_SQLITE;
        }
        sqlite3_free(sql);
      }
    }
    if (s != MURMUR_SEARCH_OK) {
      for (size_t i = 0; i < m->n_indexes; i++) {
        index_free(&m->indexes[i]);
      }
      free(m->indexes);
      m->indexes = saved;
      m->n_indexes = saved_n;
      goto out;
    }
    for (size_t i = 0; i < saved_n; i++) {
      index_free(&saved[i]);
    }
    free(saved);
    strset_clear(&m->queued_sources);
    m->next = 0;
  }
  s = validate_schema_locked(m, db, allow_missing, detail_out, sqlrc);
  if (s != MURMUR_SEARCH_OK) {
    goto out;
  }
  for (size_t i = 0; i < m->n_indexes && s == MURMUR_SEARCH_OK; i++) {
    index_state_t *ix = &m->indexes[i];
    table_col_t *cols = NULL;
    size_t ncol = 0;
    int worowid = 0, found = 0;
    s = table_info(db, ix->def.source, &cols, &ncol, &worowid, &found,
                   detail_out, sqlrc);
    table_cols_free(cols, ncol);
    if (s != MURMUR_SEARCH_OK) {
      break;
    }
    if (!found) {
      continue;
    }
    ix->worowid = worowid;
    if (!ix->installed) {
      strset_t before, after;
      s = temp_tables(db, &before, detail_out, sqlrc);
      char *sql = s == MURMUR_SEARCH_OK ? create_sql(&ix->def) : NULL;
      if (s == MURMUR_SEARCH_OK && !sql) {
        strset_free(&before);
        s = nomem(detail_out, sqlrc);
      }
      if (s == MURMUR_SEARCH_OK &&
          exec_batch(db, sql, detail_out, sqlrc) != 0) {
        s = MURMUR_SEARCH_SQLITE;
      }
      sqlite3_free(sql);
      if (s == MURMUR_SEARCH_OK) {
        s = temp_tables(db, &after, detail_out, sqlrc);
      } else {
        memset(&after, 0, sizeof(after));
      }
      if (s == MURMUR_SEARCH_OK) {
        strset_clear(&ix->owned);
        for (size_t k = 0; k < after.n; k++) {
          if (!strset_has(&before, after.v[k])) {
            if (strset_add(&ix->owned, after.v[k]) != 0) {
              s = nomem(detail_out, sqlrc);
              break;
            }
          }
        }
      }
      strset_free(&before);
      strset_free(&after);
      if (s != MURMUR_SEARCH_OK) {
        break;
      }
      ix->installed = 1;
    }
    index_invalidate(ix);
  }
  if (s == MURMUR_SEARCH_OK) {
    s = validate_schema_locked(m, db, allow_missing, detail_out, sqlrc);
  }
  if (s == MURMUR_SEARCH_OK) {
    publish_guard_locked(m);
  }
out:
  pthread_mutex_unlock(&m->mu);
  return s;
}

/* ---------- feed: update hook + noted tables ---------- */

/* Caller holds m->mu. */
static size_t memory_locked(const murmur_search_manager_t *m) {
  size_t total = 0;
  for (size_t i = 0; i < m->n_indexes; i++) {
    total += m->indexes[i].keys.n * 32;
  }
  return total;
}

/* Caller holds m->mu. Overflow invalidates installed indexes with
 * pending keys or noted sources (Go overflow; there is no changeset
 * queue in this port). */
static void overflow_locked(murmur_search_manager_t *m) {
  for (size_t i = 0; i < m->n_indexes; i++) {
    index_state_t *ix = &m->indexes[i];
    if (!ix->installed) {
      continue;
    }
    char *lower = str_lower(ix->def.source);
    int noted = lower && strset_has(&m->queued_sources, lower);
    free(lower);
    if (ix->keys.n > 0 || noted) {
      index_invalidate(ix);
    }
  }
  strset_clear(&m->queued_sources);
  publish_guard_locked(m);
}

static void update_hook(void *arg, int op, const char *db_name,
                        const char *table, sqlite3_int64 rowid) {
  (void)op;
  murmur_search_manager_t *m = (murmur_search_manager_t *)arg;
  if (!table || !table[0]) {
    return;
  }
  /* Owned temp tables live in temp; a main-schema source collides
   * with them only if validation was bypassed. Skip temp noise. */
  if (strcmp(db_name ? db_name : "", "temp") == 0) {
    return;
  }
  pthread_mutex_lock(&m->mu);
  char *tlower = str_lower(table);
  if (!tlower) {
    pthread_mutex_unlock(&m->mu);
    return;
  }
  int hit = 0;
  for (size_t i = 0; i < m->n_indexes; i++) {
    char *slower = str_lower(m->indexes[i].def.source);
    if (slower && strcmp(slower, tlower) == 0) {
      hit = 1;
    }
    free(slower);
    if (hit) {
      break;
    }
  }
  if (!hit) {
    free(tlower);
    pthread_mutex_unlock(&m->mu);
    return;
  }
  /* Stash (table, rowid); the tick resolves WITHOUT ROWID sources
   * (meaningless rowid) into invalidations. The hook must not touch
   * SQLite, so that check waits for tick time. */
  if (m->hits.n == m->hits.cap) {
    size_t ncap = m->hits.cap ? m->hits.cap * 2 : 64;
    hit_t *nv = (hit_t *)realloc(m->hits.v, ncap * sizeof(*nv));
    if (!nv) {
      free(tlower);
      pthread_mutex_unlock(&m->mu);
      return;
    }
    m->hits.v = nv;
    m->hits.cap = ncap;
  }
  m->hits.v[m->hits.n].table = tlower;
  m->hits.v[m->hits.n].rowid = rowid;
  m->hits.n++;
  if (memory_locked(m) + m->hits.n * 32 > m->budget) {
    overflow_locked(m);
    hitlist_clear(&m->hits);
  }
  pthread_mutex_unlock(&m->mu);
}

void murmur_search_attach(murmur_search_manager_t *m, sqlite3 *db) {
  if (m && db) {
    pthread_mutex_lock(&m->mu);
    m->attached = db;
    m->changes_seen = sqlite3_total_changes(db);
    pthread_mutex_unlock(&m->mu);
    sqlite3_update_hook(db, update_hook, m);
  }
}

void murmur_search_detach(murmur_search_manager_t *m, sqlite3 *db) {
  if (db) {
    sqlite3_update_hook(db, NULL, NULL);
  }
  if (m) {
    pthread_mutex_lock(&m->mu);
    if (!db || m->attached == db) {
      m->attached = NULL;
    }
    pthread_mutex_unlock(&m->mu);
  }
}

void murmur_search_note_table(murmur_search_manager_t *m, const char *table) {
  if (!m || !table || !table[0]) {
    return;
  }
  pthread_mutex_lock(&m->mu);
  char *lower = str_lower(table);
  if (lower) {
    if (strset_add(&m->queued_sources, lower) != 0) {
      /* Best effort. */
    }
    free(lower);
  }
  pthread_mutex_unlock(&m->mu);
}

int murmur_search_pending(murmur_search_manager_t *m) {
  if (!m) {
    return 0;
  }
  pthread_mutex_lock(&m->mu);
  int pending = m->queued_sources.n > 0 || m->hits.n > 0;
  for (size_t i = 0; !pending && i < m->n_indexes; i++) {
    pending = m->indexes[i].rebuild || m->indexes[i].keys.n > 0;
  }
  /* WITHOUT ROWID tripwire: hook-blind sources pend on any
   * connection-wide write activity since the last tick. */
  if (!pending && m->attached) {
    if (sqlite3_total_changes(m->attached) != m->changes_seen) {
      for (size_t i = 0; i < m->n_indexes; i++) {
        if (m->indexes[i].installed && m->indexes[i].worowid) {
          pending = 1;
          break;
        }
      }
    }
  }
  pthread_mutex_unlock(&m->mu);
  return pending;
}

int murmur_search_guard_ready(murmur_search_manager_t *m, const char *name,
                              int *ready_out) {
  if (ready_out) {
    *ready_out = 0;
  }
  if (!m || !name) {
    return 0;
  }
  char *lower = str_lower(name);
  if (!lower) {
    return 0;
  }
  pthread_mutex_lock(&m->guard_mu);
  int found = 0;
  for (size_t i = 0; i < m->guard_names.n; i++) {
    if (strcmp(m->guard_names.v[i], lower) == 0) {
      found = 1;
      if (ready_out) {
        *ready_out = m->guard_ready ? m->guard_ready[i] : 0;
      }
      break;
    }
  }
  pthread_mutex_unlock(&m->guard_mu);
  free(lower);
  return found;
}

murmur_search_status_t murmur_search_status(murmur_search_manager_t *m,
                                            murmur_search_index_status_t **out,
                                            size_t *n_out) {
  if (out) {
    *out = NULL;
  }
  if (n_out) {
    *n_out = 0;
  }
  if (!m) {
    return MURMUR_SEARCH_INVALID;
  }
  pthread_mutex_lock(&m->mu);
  murmur_search_index_status_t *v = NULL;
  if (m->n_indexes) {
    v = (murmur_search_index_status_t *)calloc(m->n_indexes, sizeof(*v));
    if (!v) {
      pthread_mutex_unlock(&m->mu);
      return MURMUR_SEARCH_NOMEM;
    }
    for (size_t i = 0; i < m->n_indexes; i++) {
      v[i].name = strdup(m->indexes[i].def.name);
      if (m->indexes[i].err) {
        v[i].error = strdup(m->indexes[i].err);
      }
      v[i].ready = m->indexes[i].ready;
      v[i].rebuilding = m->indexes[i].rebuild;
      v[i].pending_keys = m->indexes[i].keys.n;
      if (!v[i].name || (m->indexes[i].err && !v[i].error)) {
        for (size_t k = 0; k <= i; k++) {
          free(v[k].name);
          free(v[k].error);
        }
        free(v);
        pthread_mutex_unlock(&m->mu);
        return MURMUR_SEARCH_NOMEM;
      }
    }
  }
  *out = v;
  *n_out = m->n_indexes;
  pthread_mutex_unlock(&m->mu);
  return MURMUR_SEARCH_OK;
}

void murmur_search_status_free(murmur_search_index_status_t *st, size_t n) {
  if (!st) {
    return;
  }
  for (size_t i = 0; i < n; i++) {
    free(st[i].name);
    free(st[i].error);
  }
  free(st);
}

static int strptr_cmp(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

murmur_search_status_t murmur_search_take_publications(
    murmur_search_manager_t *m, char ***out, size_t *n_out) {
  if (out) {
    *out = NULL;
  }
  if (n_out) {
    *n_out = 0;
  }
  if (!m) {
    return MURMUR_SEARCH_INVALID;
  }
  pthread_mutex_lock(&m->mu);
  char **v = NULL;
  if (m->publications.n) {
    v = (char **)calloc(m->publications.n, sizeof(char *));
    if (!v) {
      pthread_mutex_unlock(&m->mu);
      return MURMUR_SEARCH_NOMEM;
    }
    for (size_t i = 0; i < m->publications.n; i++) {
      v[i] = strdup(m->publications.v[i]);
      if (!v[i]) {
        for (size_t k = 0; k < i; k++) {
          free(v[k]);
        }
        free(v);
        pthread_mutex_unlock(&m->mu);
        return MURMUR_SEARCH_NOMEM;
      }
    }
    qsort(v, m->publications.n, sizeof(char *), strptr_cmp);
  }
  *out = v;
  *n_out = m->publications.n;
  strset_clear(&m->publications);
  pthread_mutex_unlock(&m->mu);
  return MURMUR_SEARCH_OK;
}

void murmur_search_published_free(char **names, size_t n) {
  if (!names) {
    return;
  }
  for (size_t i = 0; i < n; i++) {
    free(names[i]);
  }
  free(names);
}

/* ---------- maintenance turn ---------- */

/* Caller holds m->mu. Resolves stashed hook hits into per-index keys
 * (decodePending). Noted tables invalidate outright. WITHOUT ROWID
 * sources never fire the hook, so any connection-wide write activity
 * since the last tick invalidates their indexes (tripwire); the
 * tick refreshes changes_seen after its own temp writes. */
static murmur_search_status_t drain_hits_locked(murmur_search_manager_t *m,
                                                sqlite3 *db, char **detail,
                                                int *sqlrc) {
  sqlite3_int64 cur = sqlite3_total_changes(db);
  if (cur != m->changes_seen) {
    for (size_t i = 0; i < m->n_indexes; i++) {
      if (m->indexes[i].installed && m->indexes[i].worowid) {
        index_invalidate(&m->indexes[i]);
      }
    }
  }
  for (size_t h = 0; h < m->hits.n; h++) {
    for (size_t i = 0; i < m->n_indexes; i++) {
      index_state_t *ix = &m->indexes[i];
      char *slower = str_lower(ix->def.source);
      int match = slower && strcmp(slower, m->hits.v[h].table) == 0;
      free(slower);
      if (!match || !ix->installed) {
        continue;
      }
      if (ix->worowid) {
        /* The hook cannot observe this table; a hit means the
         * schema changed shape since sync. Rebuild. */
        index_invalidate(ix);
        continue;
      }
      if (keyset_add(&ix->keys, m->hits.v[h].rowid) != 0) {
        hitlist_clear(&m->hits);
        return nomem(detail, sqlrc);
      }
    }
  }
  hitlist_clear(&m->hits);
  for (size_t i = 0; i < m->n_indexes; i++) {
    index_state_t *ix = &m->indexes[i];
    if (!ix->installed) {
      continue;
    }
    char *slower = str_lower(ix->def.source);
    int noted = slower && strset_has(&m->queued_sources, slower);
    free(slower);
    if (noted) {
      index_invalidate(ix);
    }
  }
  strset_clear(&m->queued_sources);
  if (memory_locked(m) > m->budget) {
    overflow_locked(m);
  }
  return MURMUR_SEARCH_OK;
}

static int finite_floats(const uint8_t *raw, size_t n) {
  if (n % 4 != 0) {
    return 0;
  }
  for (size_t i = 0; i < n; i += 4) {
    uint32_t bits = (uint32_t)raw[i] | ((uint32_t)raw[i + 1] << 8) |
                    ((uint32_t)raw[i + 2] << 16) | ((uint32_t)raw[i + 3] << 24);
    float f;
    memcpy(&f, &bits, 4);
    if (!isfinite((double)f)) {
      return 0;
    }
  }
  return 1;
}

/* INSERT INTO temp."name"(rowid, cols...) from an already-stepped
 * source row statement. skip_out set when a NULL vector skips. */
static murmur_search_status_t insert_search_row(
    sqlite3 *db, const def_t *d, int64_t key, sqlite3_stmt *src, int first_col,
    int *skip_out, char **detail, int *sqlrc) {
  *skip_out = 0;
  size_t ncol = d->tag == MURMUR_SEARCH_VECTOR ? 1 : d->n_columns;
  if (d->tag == MURMUR_SEARCH_VECTOR) {
    int t = sqlite3_column_type(src, first_col);
    if (t == SQLITE_NULL) {
      *skip_out = 1;
      return MURMUR_SEARCH_OK;
    }
    if (t != SQLITE_BLOB) {
      set_detail(detail, "embedding must be a float32 BLOB");
      set_sqlrc(sqlrc, SQLITE_MISUSE);
      return MURMUR_SEARCH_INVALID;
    }
    int n = sqlite3_column_bytes(src, first_col);
    const uint8_t *raw = sqlite3_column_blob(src, first_col);
    if (n != d->dimensions * 4 || !raw ||
        !finite_floats(raw, (size_t)n)) {
      char *msg = sqlite3_mprintf("invalid embedding for %s row %lld",
                                  d->name, (long long)key);
      set_detail(detail, msg ? msg : "invalid embedding");
      sqlite3_free(msg);
      set_sqlrc(sqlrc, SQLITE_MISUSE);
      return MURMUR_SEARCH_INVALID;
    }
  }
  /* Build INSERT with bound values. */
  size_t cap = 128 + strlen(d->name) * 2 + ncol * 64;
  char *sql = (char *)malloc(cap);
  if (!sql) {
    return nomem(detail, sqlrc);
  }
  char *qname = sql_quote(d->name);
  if (!qname) {
    free(sql);
    return nomem(detail, sqlrc);
  }
  int w = snprintf(sql, cap, "INSERT INTO temp.%s(rowid", qname);
  free(qname);
  for (size_t k = 0; k < ncol && w > 0 && (size_t)w < cap; k++) {
    const char *col =
        d->tag == MURMUR_SEARCH_VECTOR ? d->vector_column : d->columns[k];
    char *qc = sql_quote(col);
    if (!qc) {
      free(sql);
      return nomem(detail, sqlrc);
    }
    w += snprintf(sql + w, cap - (size_t)w, ",%s", qc);
    free(qc);
  }
  if (w <= 0 || (size_t)w >= cap) {
    free(sql);
    return nomem(detail, sqlrc);
  }
  w += snprintf(sql + w, cap - (size_t)w, ") VALUES(?");
  for (size_t k = 0; k < ncol && w > 0 && (size_t)w < cap; k++) {
    w += snprintf(sql + w, cap - (size_t)w, ",?");
  }
  if (w <= 0 || (size_t)w + 2 >= cap) {
    free(sql);
    return nomem(detail, sqlrc);
  }
  strcat(sql, ")");
  sqlite3_stmt *ins = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &ins, NULL);
  free(sql);
  if (rc != SQLITE_OK) {
    return sqlite_err(detail, sqlrc, rc);
  }
  sqlite3_bind_int64(ins, 1, key);
  for (size_t k = 0; k < ncol; k++) {
    int ci = first_col + (int)k;
    switch (sqlite3_column_type(src, ci)) {
      case SQLITE_INTEGER:
        sqlite3_bind_int64(ins, (int)k + 2, sqlite3_column_int64(src, ci));
        break;
      case SQLITE_FLOAT:
        sqlite3_bind_double(ins, (int)k + 2, sqlite3_column_double(src, ci));
        break;
      case SQLITE_TEXT:
        sqlite3_bind_text(ins, (int)k + 2,
                          (const char *)sqlite3_column_text(src, ci),
                          sqlite3_column_bytes(src, ci), SQLITE_TRANSIENT);
        break;
      case SQLITE_BLOB:
        sqlite3_bind_blob(ins, (int)k + 2, sqlite3_column_blob(src, ci),
                          sqlite3_column_bytes(src, ci), SQLITE_TRANSIENT);
        break;
      default:
        sqlite3_bind_null(ins, (int)k + 2);
        break;
    }
  }
  rc = sqlite3_step(ins);
  sqlite3_finalize(ins);
  if (rc != SQLITE_DONE) {
    return sqlite_err(detail, sqlrc, rc);
  }
  return MURMUR_SEARCH_OK;
}

/* One index's bounded work inside SAVEPOINT murmur_search_work.
 * completed_out gains worked keys (caller frees). */
static murmur_search_status_t index_work(sqlite3 *db, index_state_t *ix,
                                         size_t remaining, size_t *count_out,
                                         int64_t **completed_out,
                                         size_t *n_completed, char **detail,
                                         int *sqlrc) {
  *count_out = 0;
  *completed_out = NULL;
  *n_completed = 0;
  const def_t *d = &ix->def;
  table_col_t *cols = NULL;
  size_t ncol = 0;
  int worowid = 0, found = 0;
  murmur_search_status_t s =
      table_info(db, d->source, &cols, &ncol, &worowid, &found, detail, sqlrc);
  if (s != MURMUR_SEARCH_OK) {
    return s;
  }
  const char *pk = NULL;
  if (!found) {
    table_cols_free(cols, ncol);
    set_detail(detail, "search schema mismatch");
    set_sqlrc(sqlrc, SQLITE_MISUSE);
    return MURMUR_SEARCH_MISMATCH;
  }
  size_t npk = 0;
  for (size_t k = 0; k < ncol; k++) {
    if (cols[k].pk) {
      npk++;
      pk = cols[k].name;
    }
  }
  if (npk != 1) {
    table_cols_free(cols, ncol);
    set_detail(detail, "search schema mismatch");
    set_sqlrc(sqlrc, SQLITE_MISUSE);
    return MURMUR_SEARCH_MISMATCH;
  }
  char *pkname = strdup(pk);
  table_cols_free(cols, ncol);
  if (!pkname) {
    return nomem(detail, sqlrc);
  }
  size_t ncols = d->tag == MURMUR_SEARCH_VECTOR ? 1 : d->n_columns;
  /* Quoted column list shared by both paths. */
  char *collist = NULL;
  {
    size_t need = 1;
    char **qs = (char **)calloc(ncols ? ncols : 1, sizeof(char *));
    if (!qs) {
      free(pkname);
      return nomem(detail, sqlrc);
    }
    for (size_t k = 0; k < ncols; k++) {
      const char *col =
          d->tag == MURMUR_SEARCH_VECTOR ? d->vector_column : d->columns[k];
      qs[k] = sql_quote(col);
      if (!qs[k]) {
        for (size_t j = 0; j < k; j++) {
          free(qs[j]);
        }
        free(qs);
        free(pkname);
        return nomem(detail, sqlrc);
      }
      need += strlen(qs[k]) + 1;
    }
    collist = (char *)malloc(need);
    if (!collist) {
      for (size_t k = 0; k < ncols; k++) {
        free(qs[k]);
      }
      free(qs);
      free(pkname);
      return nomem(detail, sqlrc);
    }
    collist[0] = '\0';
    for (size_t k = 0; k < ncols; k++) {
      if (k) {
        strcat(collist, ",");
      }
      strcat(collist, qs[k]);
      free(qs[k]);
    }
    free(qs);
  }
  size_t total = 0;
  if (ix->rebuild) {
    if (!ix->started) {
      char *del = sqlite3_mprintf("DELETE FROM temp.%w", d->name);
      if (!del) {
        free(pkname);
        free(collist);
        return nomem(detail, sqlrc);
      }
      int ok = exec_batch(db, del, detail, sqlrc);
      sqlite3_free(del);
      if (ok != 0) {
        free(pkname);
        free(collist);
        return MURMUR_SEARCH_SQLITE;
      }
      ix->started = 1;
    }
    char *sql = NULL;
    if (ix->has_last) {
      sql = sqlite3_mprintf("SELECT %w,%s FROM main.%w WHERE %w > ? ORDER BY "
                            "%w LIMIT ?",
                            pkname, collist, d->source, pkname, pkname);
    } else {
      sql = sqlite3_mprintf("SELECT %w,%s FROM main.%w ORDER BY %w LIMIT ?",
                            pkname, collist, d->source, pkname);
    }
    free(pkname);
    free(collist);
    if (!sql) {
      return nomem(detail, sqlrc);
    }
    sqlite3_stmt *sel = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &sel, NULL);
    sqlite3_free(sql);
    if (rc != SQLITE_OK) {
      return sqlite_err(detail, sqlrc, rc);
    }
    if (ix->has_last) {
      sqlite3_bind_int64(sel, 1, ix->last);
      sqlite3_bind_int64(sel, 2, (int64_t)remaining);
    } else {
      sqlite3_bind_int64(sel, 1, (int64_t)remaining);
    }
    for (;;) {
      rc = sqlite3_step(sel);
      if (rc == SQLITE_DONE) {
        break;
      }
      if (rc != SQLITE_ROW) {
        sqlite3_finalize(sel);
        return sqlite_err(detail, sqlrc, rc);
      }
      int64_t key = sqlite3_column_int64(sel, 0);
      int skip = 0;
      s = insert_search_row(db, d, key, sel, 1, &skip, detail, sqlrc);
      if (s != MURMUR_SEARCH_OK) {
        sqlite3_finalize(sel);
        return s;
      }
      ix->last = key;
      ix->has_last = 1;
      total++;
    }
    sqlite3_finalize(sel);
    if (total < remaining) {
      ix->rebuild = 0;
    }
  } else {
    /* Sorted, deduped, capped keys. */
    size_t nk = ix->keys.n;
    int64_t *keys = NULL;
    if (nk) {
      keys = (int64_t *)malloc(nk * sizeof(*keys));
      if (!keys) {
        free(pkname);
        free(collist);
        return nomem(detail, sqlrc);
      }
      memcpy(keys, ix->keys.v, nk * sizeof(*keys));
      qsort(keys, nk, sizeof(*keys), key_cmp);
      size_t w = 0;
      for (size_t r = 0; r < nk; r++) {
        if (w == 0 || keys[r] != keys[w - 1]) {
          keys[w++] = keys[r];
        }
      }
      nk = w;
      if (nk > remaining) {
        nk = remaining;
      }
    }
    char *del = sqlite3_mprintf("DELETE FROM temp.%w WHERE rowid=?", d->name);
    char *sel =
        sqlite3_mprintf("SELECT %s FROM main.%w WHERE %w=?", collist,
                        d->source, pkname);
    free(pkname);
    free(collist);
    if (!del || !sel) {
      sqlite3_free(del);
      sqlite3_free(sel);
      free(keys);
      return nomem(detail, sqlrc);
    }
    s = MURMUR_SEARCH_OK;
    for (size_t k = 0; k < nk && s == MURMUR_SEARCH_OK; k++) {
      sqlite3_stmt *ds = NULL;
      int rc = sqlite3_prepare_v2(db, del, -1, &ds, NULL);
      if (rc != SQLITE_OK) {
        s = sqlite_err(detail, sqlrc, rc);
        break;
      }
      sqlite3_bind_int64(ds, 1, keys[k]);
      rc = sqlite3_step(ds);
      sqlite3_finalize(ds);
      if (rc != SQLITE_DONE) {
        s = sqlite_err(detail, sqlrc, rc);
        break;
      }
      sqlite3_stmt *ss = NULL;
      rc = sqlite3_prepare_v2(db, sel, -1, &ss, NULL);
      if (rc != SQLITE_OK) {
        s = sqlite_err(detail, sqlrc, rc);
        break;
      }
      sqlite3_bind_int64(ss, 1, keys[k]);
      rc = sqlite3_step(ss);
      if (rc == SQLITE_ROW) {
        int skip = 0;
        s = insert_search_row(db, d, keys[k], ss, 0, &skip, detail, sqlrc);
        rc = sqlite3_step(ss);
        if (s == MURMUR_SEARCH_OK && rc != SQLITE_DONE) {
          s = sqlite_err(detail, sqlrc, rc);
        }
      } else if (rc != SQLITE_DONE) {
        s = sqlite_err(detail, sqlrc, rc);
      }
      sqlite3_finalize(ss);
    }
    sqlite3_free(del);
    sqlite3_free(sel);
    if (s != MURMUR_SEARCH_OK) {
      free(keys);
      return s;
    }
    total = nk;
    *completed_out = keys;
    *n_completed = nk;
  }
  *count_out = total;
  return MURMUR_SEARCH_OK;
}

murmur_search_status_t murmur_search_tick(murmur_search_manager_t *m,
                                          sqlite3 *db, char ***published_out,
                                          size_t *n_published,
                                          char **detail_out, int *sqlrc) {
  if (published_out) {
    *published_out = NULL;
  }
  if (n_published) {
    *n_published = 0;
  }
  if (detail_out) {
    *detail_out = NULL;
  }
  pthread_mutex_lock(&m->mu);
  murmur_search_status_t s =
      drain_hits_locked(m, db, detail_out, sqlrc);
  char **published = NULL;
  size_t npub = 0, pubcap = 0;
  size_t remaining = m->batch;
  size_t length = m->n_indexes;
  size_t start = length ? m->next % length : 0;
  char *first_detail = NULL;
  int first_sqlrc = 0;
  murmur_search_status_t first_err = MURMUR_SEARCH_OK;
  for (size_t off = 0; off < length && s == MURMUR_SEARCH_OK; off++) {
    if (remaining == 0) {
      break;
    }
    size_t pos = length ? (start + off) % length : 0;
    index_state_t *ix = &m->indexes[pos];
    if (!ix->installed || (!ix->rebuild && ix->keys.n == 0)) {
      continue;
    }
    if (length) {
      m->next = (pos + 1) % length;
    }
    int saved_rebuild = ix->rebuild, saved_started = ix->started;
    int saved_has = ix->has_last;
    int64_t saved_last = ix->last;
    if (exec_batch(db, "SAVEPOINT murmur_search_work", detail_out, sqlrc) !=
        0) {
      s = MURMUR_SEARCH_SQLITE;
      break;
    }
    size_t count = 0;
    int64_t *completed = NULL;
    size_t n_completed = 0;
    char *detail = NULL;
    int sqlrc1 = 0;
    s = index_work(db, ix, remaining, &count, &completed, &n_completed,
                   &detail, &sqlrc1);
    if (s == MURMUR_SEARCH_OK) {
      if (exec_batch(db, "RELEASE murmur_search_work", &detail, &sqlrc1) !=
          0) {
        s = MURMUR_SEARCH_SQLITE;
      }
    }
    if (s == MURMUR_SEARCH_OK) {
      /* Remove completed keys. */
      for (size_t k = 0; k < n_completed; k++) {
        for (size_t j = 0; j < ix->keys.n; j++) {
          if (ix->keys.v[j] == completed[k]) {
            ix->keys.v[j] = ix->keys.v[ix->keys.n - 1];
            ix->keys.n--;
            break;
          }
        }
      }
      free(completed);
      if (count < 1) {
        count = 1;
      }
      remaining = remaining > count ? remaining - count : 0;
      free(ix->err);
      ix->err = NULL;
      if (!ix->rebuild && ix->keys.n == 0) {
        ix->ready = 1;
      }
      if (ix->ready) {
        if (npub == pubcap) {
          size_t ncap = pubcap ? pubcap * 2 : 4;
          char **nv = (char **)realloc(published, ncap * sizeof(*nv));
          if (!nv) {
            free(detail);
            s = nomem(detail_out, sqlrc);
            break;
          }
          published = nv;
          pubcap = ncap;
        }
        published[npub] = strdup(ix->def.name);
        if (!published[npub]) {
          free(detail);
          s = nomem(detail_out, sqlrc);
          break;
        }
        npub++;
      }
      free(detail);
      s = MURMUR_SEARCH_OK;
    } else {
      free(completed);
      exec_batch(db, "ROLLBACK TO murmur_search_work; RELEASE murmur_search_work",
                 NULL, NULL);
      ix->rebuild = saved_rebuild;
      ix->started = saved_started;
      ix->has_last = saved_has;
      ix->last = saved_last;
      ix->ready = 0;
      free(ix->err);
      ix->err = detail ? detail : NULL;
      if (!ix->err) {
        ix->err = strdup("search maintenance failed");
      }
      if (first_err == MURMUR_SEARCH_OK) {
        first_err = s;
        first_detail = detail ? strdup(detail) : NULL;
        first_sqlrc = sqlrc1;
      } else {
        free(detail);
      }
      s = MURMUR_SEARCH_OK;
    }
  }
  /* Exclude this turn's own temp writes from the next tripwire. */
  m->changes_seen = sqlite3_total_changes(db);
  publish_guard_locked(m);
  for (size_t i = 0; i < npub; i++) {
    if (strset_add(&m->publications, published[i]) != 0) {
      /* Best effort. */
    }
  }
  pthread_mutex_unlock(&m->mu);
  if (first_err != MURMUR_SEARCH_OK) {
    murmur_search_published_free(published, npub);
    set_detail(detail_out, first_detail);
    free(first_detail);
    set_sqlrc(sqlrc, first_sqlrc);
    return first_err;
  }
  if (published_out) {
    *published_out = published;
  } else {
    murmur_search_published_free(published, npub);
  }
  if (n_published) {
    *n_published = npub;
  }
  return s;
}

murmur_search_status_t murmur_search_refresh(murmur_search_manager_t *m,
                                             sqlite3 *db,
                                             char ***published_out,
                                             size_t *n_published,
                                             char **detail_out, int *sqlrc) {
  if (published_out) {
    *published_out = NULL;
  }
  if (n_published) {
    *n_published = 0;
  }
  strset_t acc;
  memset(&acc, 0, sizeof(acc));
  murmur_search_status_t s = MURMUR_SEARCH_OK;
  while (murmur_search_pending(m)) {
    char **names = NULL;
    size_t n = 0;
    s = murmur_search_tick(m, db, &names, &n, detail_out, sqlrc);
    if (s != MURMUR_SEARCH_OK) {
      murmur_search_published_free(names, n);
      break;
    }
    for (size_t i = 0; i < n; i++) {
      if (strset_add(&acc, names[i]) != 0) {
        s = nomem(detail_out, sqlrc);
        break;
      }
    }
    murmur_search_published_free(names, n);
    if (s != MURMUR_SEARCH_OK) {
      break;
    }
  }
  if (s != MURMUR_SEARCH_OK) {
    strset_free(&acc);
    return s;
  }
  if (acc.n > 1) {
    qsort(acc.v, acc.n, sizeof(char *), strptr_cmp);
  }
  if (published_out) {
    *published_out = acc.v;
  } else {
    murmur_search_published_free(acc.v, acc.n);
  }
  if (n_published) {
    *n_published = acc.n;
  }
  return MURMUR_SEARCH_OK;
}





