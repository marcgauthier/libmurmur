/* murmur schema - see schema.h. */
#include "schema.h"

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "msgcodec.h"
#include "sha256.h"
#include "sqlite3.h"
#include "../crsqlite/include/sqlite_murmur_crsqlite.h"

static void set_sqlrc(int *sqlrc, int rc) {
  if (sqlrc) {
    *sqlrc = rc;
  }
}

static murmur_sync_status_t sqlite_fail(int *sqlrc, int rc) {
  set_sqlrc(sqlrc, rc);
  return MURMUR_SYNC_SQLITE;
}

/* Go errInvalid: caller/peer data rejected, no SQLite failure. */
static murmur_sync_status_t invalid_fail(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_MISUSE);
  return MURMUR_SYNC_INVALID;
}

static murmur_sync_status_t ok_rc(int *sqlrc) {
  set_sqlrc(sqlrc, SQLITE_OK);
  return MURMUR_SYNC_OK;
}

/* ---- Go []rune parity ----
 *
 * The DDL lexers iterate runes and compare byte(c) against quote
 * bytes, so a rune whose low byte equals a quote toggles quoting,
 * and accumulated text re-encodes runes (invalid bytes become
 * U+FFFD, i.e. EF BF BD). This decoder plus re-encoding emitter
 * replicates that byte for byte. */

static uint32_t utf8_next(const uint8_t *s, size_t n, size_t *pos) {
  uint8_t c = s[*pos];
  if (c < 0x80) {
    (*pos)++;
    return c;
  }
  size_t need = 0;
  uint32_t r = 0;
  if ((c & 0xE0) == 0xC0) {
    need = 1;
    r = c & 0x1F;
  } else if ((c & 0xF0) == 0xE0) {
    need = 2;
    r = c & 0x0F;
  } else if ((c & 0xF8) == 0xF0) {
    need = 3;
    r = c & 0x07;
  } else {
    (*pos)++;
    return 0xFFFD;
  }
  if (*pos + need >= n) {
    (*pos)++;
    return 0xFFFD;
  }
  for (size_t i = 1; i <= need; i++) {
    uint8_t d = s[*pos + i];
    if ((d & 0xC0) != 0x80) {
      (*pos)++;
      return 0xFFFD;
    }
    r = (r << 6) | (d & 0x3F);
  }
  if ((need == 1 && r < 0x80) || (need == 2 && r < 0x800) ||
      (need == 3 && r < 0x10000) || r > 0x10FFFF ||
      (r >= 0xD800 && r <= 0xDFFF)) {
    (*pos)++;
    return 0xFFFD;
  }
  *pos += 1 + need;
  return r;
}

typedef struct {
  uint8_t *p;
  size_t n;
  size_t cap;
  int oom;
} grow_t;

static void grow_reserve(grow_t *g, size_t extra) {
  if (g->oom || g->n + extra <= g->cap) {
    return;
  }
  size_t ncap = g->cap ? g->cap : 64;
  while (ncap < g->n + extra) {
    ncap *= 2;
  }
  uint8_t *np = (uint8_t *)realloc(g->p, ncap);
  if (!np) {
    g->oom = 1;
    return;
  }
  g->p = np;
  g->cap = ncap;
}

static void grow_byte(grow_t *g, uint8_t b) {
  grow_reserve(g, 1);
  if (!g->oom) {
    g->p[g->n++] = b;
  }
}

/* Appends the UTF-8 encoding of r (like Go Builder.WriteRune). */
static void grow_rune(grow_t *g, uint32_t r) {
  if (r < 0x80) {
    grow_byte(g, (uint8_t)r);
  } else if (r < 0x800) {
    grow_byte(g, (uint8_t)(0xC0 | (r >> 6)));
    grow_byte(g, (uint8_t)(0x80 | (r & 0x3F)));
  } else if (r < 0x10000) {
    grow_byte(g, (uint8_t)(0xE0 | (r >> 12)));
    grow_byte(g, (uint8_t)(0x80 | ((r >> 6) & 0x3F)));
    grow_byte(g, (uint8_t)(0x80 | (r & 0x3F)));
  } else {
    grow_byte(g, (uint8_t)(0xF0 | (r >> 18)));
    grow_byte(g, (uint8_t)(0x80 | ((r >> 12) & 0x3F)));
    grow_byte(g, (uint8_t)(0x80 | ((r >> 6) & 0x3F)));
    grow_byte(g, (uint8_t)(0x80 | (r & 0x3F)));
  }
}

/* Go strings.TrimSpace/Fields separator set: the six ASCII
 * whitespace bytes plus U+0085 and U+00A0. */
static int is_go_space_at(const uint8_t *s, size_t n, size_t pos,
                          size_t *width) {
  uint8_t c = s[pos];
  if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
      c == '\f') {
    *width = 1;
    return 1;
  }
  if (c == 0xC2 && pos + 1 < n && (s[pos + 1] == 0x85 || s[pos + 1] == 0xA0)) {
    *width = 2;
    return 1;
  }
  return 0;
}

/* Trims Go space from both ends (views, no copy). */
static void trim_space(const uint8_t *s, size_t n, const uint8_t **out,
                       size_t *out_len) {
  size_t a = 0, b = n, w = 0;
  while (a < b && is_go_space_at(s, n, a, &w)) {
    a += w;
  }
  while (b > a) {
    /* trailing: ASCII byte or the two 2-byte sequences */
    uint8_t c = s[b - 1];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
        c == '\f') {
      b--;
    } else if ((c == 0x85 || c == 0xA0) && b >= 2 && s[b - 2] == 0xC2) {
      b -= 2;
    } else {
      break;
    }
  }
  *out = s + a;
  *out_len = b - a;
}

static int is_word_byte(uint8_t c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

static int valid_ident(const uint8_t *s, size_t n) {
  if (n == 0 || n > 128) {
    return 0;
  }
  for (size_t i = 0; i < n; i++) {
    uint8_t c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '$')) {
      return 0;
    }
  }
  return 1;
}

/* ASCII case-insensitive compare (callers compare ASCII names). */
static int equal_fold_ascii(const uint8_t *a, size_t an, const uint8_t *b,
                            size_t bn) {
  if (an != bn) {
    return 0;
  }
  for (size_t i = 0; i < an; i++) {
    uint8_t x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') {
      x += 'a' - 'A';
    }
    if (y >= 'A' && y <= 'Z') {
      y += 'a' - 'A';
    }
    if (x != y) {
      return 0;
    }
  }
  return 1;
}

/* splits fields on Go-space runs (views into s; malloc'd index). */
typedef struct {
  const uint8_t *p;
  size_t n;
} view_t;

static int split_fields(const uint8_t *s, size_t n, view_t **out,
                        size_t *count) {
  *out = NULL;
  *count = 0;
  size_t cap = 0;
  size_t i = 0, w = 0;
  while (i < n) {
    while (i < n && is_go_space_at(s, n, i, &w)) {
      i += w;
    }
    if (i >= n) {
      break;
    }
    size_t start = i;
    while (i < n && !is_go_space_at(s, n, i, &w)) {
      i++;
    }
    if (*count >= cap) {
      size_t ncap = cap ? cap * 2 : 8;
      view_t *nv = (view_t *)realloc(*out, ncap * sizeof(*nv));
      if (!nv) {
        free(*out);
        *out = NULL;
        return -1;
      }
      *out = nv;
      cap = ncap;
    }
    (*out)[*count].p = s + start;
    (*out)[*count].n = i - start;
    (*count)++;
  }
  return 0;
}

/* Owned string list. */
typedef struct {
  char *p;
  size_t n;
} str_t;

static void strs_free(str_t *v, size_t n) {
  if (v) {
    for (size_t i = 0; i < n; i++) {
      free(v[i].p);
    }
    free(v);
  }
}

static int strs_push(str_t **v, size_t *n, size_t *cap, const uint8_t *p,
                     size_t len) {
  if (*n >= *cap) {
    size_t ncap = *cap ? *cap * 2 : 8;
    str_t *nv = (str_t *)realloc(*v, ncap * sizeof(*nv));
    if (!nv) {
      return -1;
    }
    *v = nv;
    *cap = ncap;
  }
  char *cp = (char *)malloc(len + 1);
  if (!cp) {
    return -1;
  }
  memcpy(cp, p, len);
  cp[len] = '\0';
  (*v)[*n].p = cp;
  (*v)[*n].n = len;
  (*n)++;
  return 0;
}

/* Splits on top-level commas, respecting nested parens and quotes
 * (Go splitTopLevel, rune-exact). Returns 1/0; -1 on OOM. */
static int split_top_level(const uint8_t *s, size_t n, str_t **out,
                           size_t *count) {
  *out = NULL;
  *count = 0;
  size_t cap = 0;
  int depth = 0;
  uint8_t quote = 0;
  int quoted = 0;
  grow_t cur;
  memset(&cur, 0, sizeof(cur));
  size_t pos = 0;
  int ok = 1;
  while (pos < n) {
    uint32_t c = utf8_next(s, n, &pos);
    if (quoted) {
      grow_rune(&cur, c);
      if ((uint8_t)c == quote) {
        /* doubled quote: Go compares the next rune's low byte */
        size_t p2 = pos;
        uint32_t d = p2 < n ? utf8_next(s, n, &p2) : 0;
        if (p2 > pos && (uint8_t)d == quote) {
          pos = p2;
          grow_rune(&cur, d);
        } else {
          quoted = 0;
        }
      }
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      quoted = 1;
      quote = (uint8_t)c;
      grow_rune(&cur, c);
    } else if (c == '(') {
      depth++;
      grow_rune(&cur, c);
    } else if (c == ')') {
      depth--;
      if (depth < 0) {
        ok = 0;
        break;
      }
      grow_rune(&cur, c);
    } else if (c == ',' && depth == 0) {
      if (strs_push(out, count, &cap, cur.p ? cur.p : (uint8_t *)"",
                    cur.n) != 0) {
        ok = -1;
        break;
      }
      cur.n = 0;
    } else {
      grow_rune(&cur, c);
    }
    if (cur.oom) {
      ok = -1;
      break;
    }
  }
  if (ok == 1 && (quoted || depth != 0)) {
    ok = 0;
  }
  if (ok == 1) {
    if (strs_push(out, count, &cap, cur.p ? cur.p : (uint8_t *)"", cur.n) !=
        0) {
      ok = -1;
    }
  }
  free(cur.p);
  if (ok != 1) {
    strs_free(*out, *count);
    *out = NULL;
    *count = 0;
  }
  return ok;
}

/* Canonical comparison form: unquoted text upper-cased (ASCII),
 * quoted text verbatim with quotes, tokens joined by one space
 * (Go normalizeDDL, rune-exact). */
static char *normalize_ddl(const uint8_t *s, size_t n) {
  str_t *tokens = NULL;
  size_t ntok = 0, tokcap = 0;
  grow_t cur, quo;
  memset(&cur, 0, sizeof(cur));
  memset(&quo, 0, sizeof(quo));
  uint8_t quote = 0;
  int quoted = 0;
  size_t pos = 0;
  int fail = 0;
  while (pos < n) {
    uint32_t c = utf8_next(s, n, &pos);
    if (quoted) {
      grow_rune(&quo, c);
      if ((uint8_t)c == quote) {
        size_t p2 = pos;
        uint32_t d = p2 < n ? utf8_next(s, n, &p2) : 0;
        if (p2 > pos && (uint8_t)d == quote) {
          pos = p2;
          grow_rune(&quo, d);
        } else {
          quoted = 0;
          if (strs_push(&tokens, &ntok, &tokcap, quo.p, quo.n) != 0) {
            fail = 1;
            break;
          }
          quo.n = 0;
        }
      }
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      if (cur.n > 0) {
        for (size_t i = 0; i < cur.n; i++) {
          if (cur.p[i] >= 'a' && cur.p[i] <= 'z') {
            cur.p[i] -= 'a' - 'A';
          }
        }
        if (strs_push(&tokens, &ntok, &tokcap, cur.p, cur.n) != 0) {
          fail = 1;
          break;
        }
        cur.n = 0;
      }
      quoted = 1;
      quote = (uint8_t)c;
      quo.n = 0;
      grow_rune(&quo, c);
    } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
               c == '\f') {
      /* Go splits on the six ASCII blanks only (no U+0085/U+00A0). */
      if (cur.n > 0) {
        for (size_t i = 0; i < cur.n; i++) {
          if (cur.p[i] >= 'a' && cur.p[i] <= 'z') {
            cur.p[i] -= 'a' - 'A';
          }
        }
        if (strs_push(&tokens, &ntok, &tokcap, cur.p, cur.n) != 0) {
          fail = 1;
          break;
        }
        cur.n = 0;
      }
    } else {
      grow_rune(&cur, c);
    }
    if (cur.oom || quo.oom) {
      fail = 1;
      break;
    }
  }
  if (!fail && cur.n > 0) {
    for (size_t i = 0; i < cur.n; i++) {
      if (cur.p[i] >= 'a' && cur.p[i] <= 'z') {
        cur.p[i] -= 'a' - 'A';
      }
    }
    if (strs_push(&tokens, &ntok, &tokcap, cur.p, cur.n) != 0) {
      fail = 1;
    }
  }
  if (!fail && quo.n > 0) {
    if (strs_push(&tokens, &ntok, &tokcap, quo.p, quo.n) != 0) {
      fail = 1;
    }
  }
  free(cur.p);
  free(quo.p);
  if (fail) {
    strs_free(tokens, ntok);
    return NULL;
  }
  /* Join with single spaces. */
  size_t total = 0;
  for (size_t i = 0; i < ntok; i++) {
    total += tokens[i].n + (i ? 1 : 0);
  }
  char *out = (char *)malloc(total + 1);
  if (!out) {
    strs_free(tokens, ntok);
    return NULL;
  }
  size_t w = 0;
  for (size_t i = 0; i < ntok; i++) {
    if (i) {
      out[w++] = ' ';
    }
    memcpy(out + w, tokens[i].p, tokens[i].n);
    w += tokens[i].n;
  }
  out[w] = '\0';
  strs_free(tokens, ntok);
  return out;
}

/* Lexes DDL into words; parens, commas, dots, semicolons become
 * one-char tokens (Go lexWords, rune-exact minus the always-false
 * bail). Returns 1/0; -1 on OOM. */
static int lex_words(const uint8_t *s, size_t n, str_t **out, size_t *count) {
  *out = NULL;
  *count = 0;
  size_t cap = 0;
  grow_t cur;
  memset(&cur, 0, sizeof(cur));
  uint8_t quote = 0;
  int quoted = 0;
  size_t pos = 0;
  int ok = 1;
  while (pos < n) {
    uint32_t c = utf8_next(s, n, &pos);
    if (quoted) {
      grow_rune(&cur, c);
      if ((uint8_t)c == quote) {
        size_t p2 = pos;
        uint32_t d = p2 < n ? utf8_next(s, n, &p2) : 0;
        if (p2 > pos && (uint8_t)d == quote) {
          pos = p2;
          grow_rune(&cur, d);
        } else {
          quoted = 0;
        }
      }
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      /* Go flushes pending text before a quote opens. */
      if (cur.n > 0) {
        if (strs_push(out, count, &cap, cur.p, cur.n) != 0) {
          ok = -1;
          break;
        }
        cur.n = 0;
      }
      quoted = 1;
      quote = (uint8_t)c;
      grow_rune(&cur, c);
    } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
               c == '\f') {
      if (cur.n > 0) {
        if (strs_push(out, count, &cap, cur.p, cur.n) != 0) {
          ok = -1;
          break;
        }
        cur.n = 0;
      }
    } else if (c == '(' || c == ')' || c == ',' || c == '.' || c == ';') {
      if (cur.n > 0) {
        if (strs_push(out, count, &cap, cur.p, cur.n) != 0) {
          ok = -1;
          break;
        }
        cur.n = 0;
      }
      uint8_t b = (uint8_t)c;
      if (strs_push(out, count, &cap, &b, 1) != 0) {
        ok = -1;
        break;
      }
    } else {
      grow_rune(&cur, c);
    }
    if (cur.oom) {
      ok = -1;
      break;
    }
  }
  if (ok == 1 && cur.n > 0) {
    if (strs_push(out, count, &cap, cur.p, cur.n) != 0) {
      ok = -1;
    }
  }
  free(cur.p);
  if (ok == 1 && quoted) {
    ok = 0;
  }
  if (ok != 1) {
    strs_free(*out, *count);
    *out = NULL;
    *count = 0;
  }
  return ok;
}

/* No unquoted semicolon, or exactly one with only ASCII blanks
 * after it (Go singleStatement, raw rune scan and all). */
static int single_statement(const uint8_t *s, size_t n) {
  uint8_t quote = 0;
  int quoted = 0;
  int semis = 0;
  int trailing_ok = 1;
  size_t pos = 0;
  while (pos < n) {
    uint32_t c = utf8_next(s, n, &pos);
    if (quoted) {
      if ((uint8_t)c == quote) {
        size_t p2 = pos;
        uint32_t d = p2 < n ? utf8_next(s, n, &p2) : 0;
        if (p2 > pos && (uint8_t)d == quote) {
          pos = p2;
        } else {
          quoted = 0;
        }
      }
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      quoted = 1;
      quote = (uint8_t)c;
    } else if (c == ';') {
      semis++;
      trailing_ok = 1;
      /* raw byte scan: any non-blank byte (quotes included, like
       * Go's quote-blind rune scan) vetoes the trailing slot */
      for (size_t k = pos; k < n; k++) {
        uint8_t b = s[k];
        if (b != ' ' && b != '\t' && b != '\n' && b != '\r' && b != '\v' &&
            b != '\f') {
          trailing_ok = 0;
          break;
        }
      }
    }
  }
  return !quoted && (semis == 0 || (semis == 1 && trailing_ok));
}

/* An unquoted semicolon anywhere (Go hasUnquotedSemicolon). */
static int has_unquoted_semicolon(const uint8_t *s, size_t n) {
  uint8_t quote = 0;
  int quoted = 0;
  size_t pos = 0;
  while (pos < n) {
    uint32_t c = utf8_next(s, n, &pos);
    if (quoted) {
      if ((uint8_t)c == quote) {
        size_t p2 = pos;
        uint32_t d = p2 < n ? utf8_next(s, n, &p2) : 0;
        if (p2 > pos && (uint8_t)d == quote) {
          pos = p2;
        } else {
          quoted = 0;
        }
      }
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      quoted = 1;
      quote = (uint8_t)c;
    } else if (c == ';') {
      return 1;
    }
  }
  return 0;
}

/* Strips one trailing semicolon plus Go space, repeatedly
 * (Go stripTight, owned). */
static char *strip_tight(const uint8_t *s, size_t n, size_t *out_len) {
  const uint8_t *t = s;
  size_t tn = n;
  trim_space(t, tn, &t, &tn);
  for (;;) {
    if (tn == 0 || t[tn - 1] != ';') {
      break;
    }
    tn--;
    trim_space(t, tn, &t, &tn);
  }
  char *out = (char *)malloc(tn + 1);
  if (out) {
    memcpy(out, t, tn);
    out[tn] = '\0';
    if (out_len) {
      *out_len = tn;
    }
  }
  return out;
}

/* Unquotes one lexed word (Go unquoteIdent, owned): matching
 * "/` ends unwrap with doubled unescape, [..] unwraps, a leading
 * single quote fails, anything else passes through (validIdent
 * screens the survivors downstream). */
static char *unquote_ident(const uint8_t *w, size_t n, size_t *out_len) {
  if (n >= 2 && w[0] == w[n - 1] && (w[0] == '"' || w[0] == '`')) {
    grow_t g;
    memset(&g, 0, sizeof(g));
    for (size_t i = 1; i + 1 < n; i++) {
      if (w[i] == w[0] && i + 1 < n - 1 && w[i + 1] == w[0]) {
        grow_byte(&g, w[0]);
        i++;
      } else {
        grow_byte(&g, w[i]);
      }
    }
    if (g.oom) {
      free(g.p);
      return NULL;
    }
    grow_byte(&g, '\0');
    if (g.oom) {
      free(g.p);
      return NULL;
    }
    if (out_len) {
      *out_len = g.n - 1;
    }
    return (char *)g.p;
  }
  if (n >= 2 && w[0] == '[' && w[n - 1] == ']') {
    char *out = (char *)malloc(n - 1);
    if (!out) {
      return NULL;
    }
    memcpy(out, w + 1, n - 2);
    out[n - 2] = '\0';
    if (out_len) {
      *out_len = n - 2;
    }
    return out;
  }
  if (n >= 1 && w[0] == '\'') {
    return NULL;
  }
  char *out = (char *)malloc(n + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, w, n);
  out[n] = '\0';
  if (out_len) {
    *out_len = n;
  }
  return out;
}

/* Parsed column plus the normalized table constraints. */
typedef struct {
  char *name;     /* lower-cased (ASCII) */
  char *def;      /* normalizeDDL(element) */
  char *original; /* trimmed element, verbatim */
} col_t;

typedef struct {
  col_t *cols;
  size_t n_cols;
  str_t *cons; /* normalized, byte-sorted */
  size_t n_cons;
} ddl_shape_t;

static void ddl_shape_free(ddl_shape_t *sh) {
  if (sh->cols) {
    for (size_t i = 0; i < sh->n_cols; i++) {
      free(sh->cols[i].name);
      free(sh->cols[i].def);
      free(sh->cols[i].original);
    }
    free(sh->cols);
  }
  strs_free(sh->cons, sh->n_cons);
  memset(sh, 0, sizeof(*sh));
}

static int is_constraint_prefix(const uint8_t *up, size_t n) {
  static const char *kws[] = {"PRIMARY", "FOREIGN", "UNIQUE",
                              "CHECK",   "CONSTRAINT"};
  for (size_t i = 0; i < sizeof(kws) / sizeof(kws[0]); i++) {
    size_t k = strlen(kws[i]);
    if (n == k && memcmp(up, kws[i], k) == 0) {
      return 1;
    }
  }
  return 0;
}

static int cmp_strt(const void *a, const void *b) {
  const str_t *x = (const str_t *)a, *y = (const str_t *)b;
  size_t m = x->n < y->n ? x->n : y->n;
  int c = memcmp(x->p, y->p, m);
  if (c != 0) {
    return c;
  }
  if (x->n < y->n) {
    return -1;
  }
  return x->n > y->n;
}

/* Parses the CREATE TABLE body (Go ddlColumns). Returns 1/0; -1 OOM. */
static int ddl_columns(const uint8_t *ddl, size_t n, ddl_shape_t *out) {
  memset(out, 0, sizeof(*out));
  const uint8_t *open = memchr(ddl, '(', n);
  if (!open) {
    return 0;
  }
  const uint8_t *rest = open + 1;
  size_t rest_n = (size_t)((ddl + n) - rest);
  const uint8_t *close = NULL;
  for (size_t i = rest_n; i > 0; i--) {
    if (rest[i - 1] == ')') {
      close = rest + i - 1;
      break;
    }
  }
  if (!close || close <= rest) {
    return 0;
  }
  str_t *parts = NULL;
  size_t nparts = 0;
  int sr = split_top_level(rest, (size_t)(close - rest), &parts, &nparts);
  if (sr != 1) {
    return sr;
  }
  size_t colcap = 0, concap = 0;
  int rc = 1;
  for (size_t i = 0; i < nparts; i++) {
    const uint8_t *el = (const uint8_t *)parts[i].p;
    size_t eln = parts[i].n;
    trim_space(el, eln, &el, &eln);
    size_t wlen = 0;
    while (wlen < eln && is_word_byte(el[wlen])) {
      wlen++;
    }
    char *up = (char *)malloc(wlen + 1);
    if (!up) {
      rc = -1;
      break;
    }
    for (size_t k = 0; k < wlen; k++) {
      uint8_t c = el[k];
      up[k] = (char)((c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c);
    }
    up[wlen] = '\0';
    int is_con = is_constraint_prefix((const uint8_t *)up, wlen);
    free(up);
    if (is_con) {
      char *norm = normalize_ddl(el, eln);
      if (!norm) {
        rc = -1;
        break;
      }
      if (strs_push(&out->cons, &out->n_cons, &concap,
                    (const uint8_t *)norm, strlen(norm)) != 0) {
        free(norm);
        rc = -1;
        break;
      }
      free(norm);
      continue;
    }
    view_t *fields = NULL;
    size_t nfields = 0;
    if (split_fields(el, eln, &fields, &nfields) != 0) {
      rc = -1;
      break;
    }
    if (nfields == 0) {
      free(fields);
      rc = 0;
      break;
    }
    /* Trim all leading/trailing double quotes (Go Trim('"')). */
    const uint8_t *nm = fields[0].p;
    size_t nmn = fields[0].n;
    while (nmn > 0 && nm[0] == '"') {
      nm++;
      nmn--;
    }
    while (nmn > 0 && nm[nmn - 1] == '"') {
      nmn--;
    }
    free(fields);
    if (!valid_ident(nm, nmn)) {
      rc = 0;
      break;
    }
    if (out->n_cols >= colcap) {
      size_t ncap = colcap ? colcap * 2 : 8;
      col_t *nv = (col_t *)realloc(out->cols, ncap * sizeof(*nv));
      if (!nv) {
        rc = -1;
        break;
      }
      out->cols = nv;
      colcap = ncap;
    }
    char *norm = normalize_ddl(el, eln);
    char *lname = (char *)malloc(nmn + 1);
    char *orig = (char *)malloc(eln + 1);
    if (!norm || !lname || !orig) {
      free(norm);
      free(lname);
      free(orig);
      rc = -1;
      break;
    }
    for (size_t k = 0; k < nmn; k++) {
      uint8_t c = nm[k];
      lname[k] = (char)((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
    }
    lname[nmn] = '\0';
    memcpy(orig, el, eln);
    orig[eln] = '\0';
    out->cols[out->n_cols].name = lname;
    out->cols[out->n_cols].def = norm;
    out->cols[out->n_cols].original = orig;
    out->n_cols++;
  }
  strs_free(parts, nparts);
  if (rc == 1) {
    qsort(out->cons, out->n_cons, sizeof(*out->cons), cmp_strt);
  } else {
    ddl_shape_free(out);
  }
  return rc;
}

murmur_sync_status_t murmur_check_create_table(const uint8_t *table,
                                               size_t table_len,
                                               const uint8_t *ddl,
                                               size_t ddl_len, int *sqlrc) {
  if (!valid_ident(table, table_len) || !single_statement(ddl, ddl_len)) {
    return invalid_fail(sqlrc);
  }
  str_t *words = NULL;
  size_t nwords = 0;
  int lr = lex_words(ddl, ddl_len, &words, &nwords);
  if (lr < 0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (lr == 0) {
    return invalid_fail(sqlrc);
  }
  size_t i = 0;
  murmur_sync_status_t st = MURMUR_SYNC_OK;
  int fail = 0;
  /* eat(CREATE) eat(TABLE) */
  if (i >= nwords ||
      !equal_fold_ascii((const uint8_t *)words[i].p, words[i].n,
                        (const uint8_t *)"CREATE", 6)) {
    fail = 1;
  } else {
    i++;
  }
  if (!fail &&
      (i >= nwords ||
       !equal_fold_ascii((const uint8_t *)words[i].p, words[i].n,
                         (const uint8_t *)"TABLE", 5))) {
    fail = 1;
  } else if (!fail) {
    i++;
  }
  /* optional IF: Go's eat-chain rejects a bare IF EXISTS (the NOT
   * arm short-circuits true), so only IF NOT EXISTS passes */
  if (!fail && i < nwords &&
      equal_fold_ascii((const uint8_t *)words[i].p, words[i].n,
                       (const uint8_t *)"IF", 2)) {
    i++;
    if (i >= nwords ||
        !equal_fold_ascii((const uint8_t *)words[i].p, words[i].n,
                          (const uint8_t *)"NOT", 3)) {
      fail = 1;
    } else {
      i++;
      if (i >= nwords ||
          !equal_fold_ascii((const uint8_t *)words[i].p, words[i].n,
                            (const uint8_t *)"EXISTS", 6)) {
        fail = 1;
      } else {
        i++;
      }
    }
  }
  if (!fail && i >= nwords) {
    fail = 1;
  }
  if (!fail) {
    size_t nmlen = 0;
    char *name = unquote_ident((const uint8_t *)words[i].p, words[i].n,
                               &nmlen);
    if (!name) {
      fail = 1;
    } else {
      i++;
      if (i < nwords && words[i].n == 1 && words[i].p[0] == '.') {
        /* schema-qualified: only main allowed */
        if (!equal_fold_ascii((const uint8_t *)name, nmlen,
                              (const uint8_t *)"main", 4)) {
          fail = 1;
        } else {
          i++;
          free(name);
          name = NULL;
          if (i >= nwords) {
            fail = 1;
          } else {
            name = unquote_ident((const uint8_t *)words[i].p, words[i].n,
                                 &nmlen);
            if (!name) {
              fail = 1;
            } else {
              i++;
            }
          }
        }
      }
      if (!fail &&
          (!valid_ident((const uint8_t *)name, nmlen) ||
           !equal_fold_ascii((const uint8_t *)name, nmlen, table, table_len))) {
        fail = 1;
      }
      free(name);
    }
  }
  if (!fail && (i >= nwords || words[i].n != 1 || words[i].p[0] != '(')) {
    fail = 1;
  }
  strs_free(words, nwords);
  if (fail) {
    st = MURMUR_SYNC_INVALID;
  }
  set_sqlrc(sqlrc, fail ? SQLITE_MISUSE : SQLITE_OK);
  return st;
}

murmur_sync_status_t murmur_check_add_column(const uint8_t *coldef,
                                             size_t coldef_len, char **name,
                                             int *sqlrc) {
  if (name) {
    *name = NULL;
  }
  const uint8_t *trimmed = NULL;
  size_t tlen = 0;
  trim_space(coldef, coldef_len, &trimmed, &tlen);
  if (has_unquoted_semicolon(coldef, coldef_len) || tlen == 0) {
    return invalid_fail(sqlrc);
  }
  /* split runs on the raw def, like Go */
  str_t *parts = NULL;
  size_t nparts = 0;
  int sr = split_top_level(coldef, coldef_len, &parts, &nparts);
  if (sr < 0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (sr == 0 || nparts != 1) {
    strs_free(parts, nparts);
    return invalid_fail(sqlrc);
  }
  strs_free(parts, nparts);
  /* leading-word screen over the trimmed view: Go's six words only */
  size_t wlen = 0;
  while (wlen < tlen && is_word_byte(trimmed[wlen])) {
    wlen++;
  }
  char *up = (char *)malloc(wlen + 1);
  if (!up) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  for (size_t k = 0; k < wlen; k++) {
    uint8_t c = trimmed[k];
    up[k] = (char)((c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c);
  }
  up[wlen] = '\0';
  static const char *bad[] = {"",       "PRIMARY", "FOREIGN",
                              "UNIQUE", "CHECK",   "CONSTRAINT"};
  int screened = 0;
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    if (strcmp(up, bad[i]) == 0) {
      screened = 1;
      break;
    }
  }
  free(up);
  if (screened) {
    return invalid_fail(sqlrc);
  }
  view_t *fields = NULL;
  size_t nfields = 0;
  if (split_fields(coldef, coldef_len, &fields, &nfields) != 0) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (nfields == 0) {
    free(fields);
    return invalid_fail(sqlrc);
  }
  const uint8_t *nm = fields[0].p;
  size_t nmn = fields[0].n;
  while (nmn > 0 && nm[0] == '"') {
    nm++;
    nmn--;
  }
  while (nmn > 0 && nm[nmn - 1] == '"') {
    nmn--;
  }
  free(fields);
  if (!valid_ident(nm, nmn)) {
    return invalid_fail(sqlrc);
  }
  /* original case, like Go (callers bind it; SQLite folds) */
  char *kept = (char *)malloc(nmn + 1);
  if (!kept) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  memcpy(kept, nm, nmn);
  kept[nmn] = '\0';
  if (name) {
    *name = kept;
  } else {
    free(kept);
  }
  return ok_rc(sqlrc);
}

/* ---- Additive diff (Go SchemaDiff) ---- */

static int bytes_eq(const uint8_t *a, size_t an, const uint8_t *b,
                      size_t bn) {
  if (an != bn) {
    return 0;
  }
  if (an == 0) {
    return 1;
  }
  if (!a || !b) {
    return 0;
  }
  return memcmp(a, b, an) == 0;
}

/* Decodes canonical pair bytes via the golden-validated postcard
 * decoder (Go DecodeSchemaPairs). Views borrow blob. Returns
 * 1/0; -1 on OOM. */
static int decode_wire_pairs(const uint8_t *blob, size_t len,
                             murmur_schema_pair_t **out, size_t *count) {
  *out = NULL;
  *count = 0;
  size_t cap = 16;
  for (;;) {
    murmur_schema_pair_t *v =
        (murmur_schema_pair_t *)malloc(cap * sizeof(*v));
    if (!v) {
      return -1;
    }
    size_t n = 0;
    murmur_mship_status_t ms =
        murmur_schema_pairs_decode(blob, len, v, cap, &n);
    if (ms == MURMUR_OK) {
      *out = v;
      *count = n;
      return 1;
    }
    free(v);
    if (ms != MURMUR_MSHIP_OVERLOADED) {
      return 0;
    }
    if (cap >= (SIZE_MAX / 2) / sizeof(*v)) {
      return -1;
    }
    cap *= 2;
  }
}

/* Last match wins (Go map assignment while ranging in order). */
static const murmur_schema_pair_t *wire_lookup(const murmur_schema_pair_t *v,
                                               size_t n, const uint8_t *name,
                                               size_t name_len) {
  const murmur_schema_pair_t *hit = NULL;
  for (size_t i = 0; i < n; i++) {
    if (bytes_eq(v[i].table, v[i].table_len, name, name_len)) {
      hit = &v[i];
    }
  }
  return hit;
}

static int delta_push(murmur_schema_delta_ent_t **v, size_t *n, size_t *cap,
                      const uint8_t *table, size_t table_len, const uint8_t *def,
                      size_t def_len) {
  if (*n >= *cap) {
    size_t ncap = *cap ? *cap * 2 : 8;
    murmur_schema_delta_ent_t *nv =
        (murmur_schema_delta_ent_t *)realloc(*v, ncap * sizeof(*nv));
    if (!nv) {
      return -1;
    }
    *v = nv;
    *cap = ncap;
  }
  char *t = (char *)malloc(table_len + 1);
  char *d = (char *)malloc(def_len + 1);
  if (!t || !d) {
    free(t);
    free(d);
    return -1;
  }
  if (table_len) {
    memcpy(t, table, table_len);
  }
  t[table_len] = '\0';
  if (def_len) {
    memcpy(d, def, def_len);
  }
  d[def_len] = '\0';
  (*v)[*n].table = t;
  (*v)[*n].def = d;
  (*n)++;
  return 0;
}

void murmur_schema_diff_free(murmur_schema_diff_t *d) {
  if (!d) {
    return;
  }
  if (d->new_tables) {
    for (size_t i = 0; i < d->n_tables; i++) {
      free(d->new_tables[i].table);
      free(d->new_tables[i].def);
    }
    free(d->new_tables);
  }
  if (d->add_columns) {
    for (size_t i = 0; i < d->n_columns; i++) {
      free(d->add_columns[i].table);
      free(d->add_columns[i].def);
    }
    free(d->add_columns);
  }
  free(d->incompatible);
  memset(d, 0, sizeof(*d));
}

/* Builds prefix + a + mid + b; embedded NUL bytes truncate the
 * name (Go %s would not), but only the diagnostic text differs. */
static char *incompat_msg(const char *prefix, const uint8_t *a, size_t an,
                          const char *mid, const uint8_t *b, size_t bn) {
  size_t al = 0, bl = 0;
  if (a) {
    while (al < an && a[al]) {
      al++;
    }
  }
  if (b) {
    while (bl < bn && b[bl]) {
      bl++;
    }
  }
  size_t pl = strlen(prefix), ml = mid ? strlen(mid) : 0;
  char *out = (char *)malloc(pl + al + ml + bl + 1);
  if (!out) {
    return NULL;
  }
  size_t w = 0;
  memcpy(out + w, prefix, pl);
  w += pl;
  if (a) {
    memcpy(out + w, a, al);
    w += al;
  }
  if (mid) {
    memcpy(out + w, mid, ml);
    w += ml;
  }
  if (b) {
    memcpy(out + w, b, bl);
    w += bl;
  }
  out[w] = '\0';
  return out;
}

murmur_sync_status_t murmur_schema_diff(const uint8_t *local, size_t local_len,
                                        const uint8_t *remote,
                                        size_t remote_len,
                                        murmur_schema_diff_t *out, int *sqlrc) {
  memset(out, 0, sizeof(*out));
  murmur_schema_pair_t *lv = NULL, *rv = NULL;
  size_t ln = 0, rn = 0;
  int lr = decode_wire_pairs(local, local_len, &lv, &ln);
  int rr = decode_wire_pairs(remote, remote_len, &rv, &rn);
  if (lr < 0 || rr < 0) {
    free(lv);
    free(rv);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (lr == 0 || rr == 0) {
    free(lv);
    free(rv);
    return invalid_fail(sqlrc);
  }
  size_t tcap = 0, ccap = 0;
  murmur_sync_status_t st = MURMUR_SYNC_OK;
  /* Incompatibility is data, not an error (Go returns it with a nil
   * error); done stops the scan once the reason is set. */
  int done = 0;
  for (size_t i = 0; i < rn && st == MURMUR_SYNC_OK && !done; i++) {
    const murmur_schema_pair_t *le =
        wire_lookup(lv, ln, rv[i].table, rv[i].table_len);
    if (!le) {
      if (delta_push(&out->new_tables, &out->n_tables, &tcap, rv[i].table,
                     rv[i].table_len, rv[i].ddl, rv[i].ddl_len) != 0) {
        st = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
      }
      continue;
    }
    if (bytes_eq(le->ddl, le->ddl_len, rv[i].ddl, rv[i].ddl_len)) {
      continue;
    }
    static const uint8_t empty_ddl[1] = {0};
    ddl_shape_t before, after;
    int br = ddl_columns(le->ddl ? le->ddl : empty_ddl, le->ddl_len, &before);
    int ar =
        ddl_columns(rv[i].ddl ? rv[i].ddl : empty_ddl, rv[i].ddl_len, &after);
    if (br < 0 || ar < 0) {
      if (br == 1) {
        ddl_shape_free(&before);
      }
      if (ar == 1) {
        ddl_shape_free(&after);
      }
      st = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      break;
    }
    if (br == 0 || ar == 0) {
      const char *prefix =
          br == 0 ? "unparseable local DDL: " : "unparseable remote DDL: ";
      if (br == 1) {
        ddl_shape_free(&before);
      }
      if (ar == 1) {
        ddl_shape_free(&after);
      }
      out->incompatible = incompat_msg(prefix, rv[i].table, rv[i].table_len,
                                       NULL, NULL, 0);
      if (!out->incompatible) {
        st = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
      } else {
        done = 1;
      }
      break;
    }
    int bad = 0;
    if (before.n_cons != after.n_cons) {
      bad = 1;
    } else {
      for (size_t k = 0; k < before.n_cons; k++) {
        if (before.cons[k].n != after.cons[k].n ||
            memcmp(before.cons[k].p, after.cons[k].p, before.cons[k].n) != 0) {
          bad = 1;
          break;
        }
      }
    }
    if (bad) {
      out->incompatible =
          incompat_msg("table constraint change: ", rv[i].table,
                       rv[i].table_len, NULL, NULL, 0);
      ddl_shape_free(&before);
      ddl_shape_free(&after);
      if (!out->incompatible) {
        st = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
      } else {
        done = 1;
      }
      break;
    }
    for (size_t k = 0; k < before.n_cols && st == MURMUR_SYNC_OK && !done;
         k++) {
      const col_t *match = NULL;
      for (size_t j = 0; j < after.n_cols; j++) {
        if (strcmp(before.cols[k].name, after.cols[j].name) == 0) {
          match = &after.cols[j];
          break;
        }
      }
      if (!match) {
        out->incompatible = incompat_msg(
            "column dropped: ", rv[i].table, rv[i].table_len, ".",
            (const uint8_t *)before.cols[k].name, strlen(before.cols[k].name));
        if (!out->incompatible) {
          st = MURMUR_SYNC_SQLITE;
          set_sqlrc(sqlrc, SQLITE_NOMEM);
        } else {
          done = 1;
        }
        break;
      }
      if (strcmp(before.cols[k].def, match->def) != 0) {
        out->incompatible = incompat_msg(
            "column redefined: ", rv[i].table, rv[i].table_len, ".",
            (const uint8_t *)before.cols[k].name, strlen(before.cols[k].name));
        if (!out->incompatible) {
          st = MURMUR_SYNC_SQLITE;
          set_sqlrc(sqlrc, SQLITE_NOMEM);
        } else {
          done = 1;
        }
        break;
      }
    }
    if (st == MURMUR_SYNC_OK && !done) {
      for (size_t k = 0; k < after.n_cols; k++) {
        int found = 0;
        for (size_t j = 0; j < before.n_cols; j++) {
          if (strcmp(after.cols[k].name, before.cols[j].name) == 0) {
            found = 1;
            break;
          }
        }
        if (!found) {
          if (delta_push(&out->add_columns, &out->n_columns, &ccap, rv[i].table,
                         rv[i].table_len,
                         (const uint8_t *)after.cols[k].original,
                         strlen(after.cols[k].original)) != 0) {
            st = MURMUR_SYNC_SQLITE;
            set_sqlrc(sqlrc, SQLITE_NOMEM);
            break;
          }
        }
      }
    }
    ddl_shape_free(&before);
    ddl_shape_free(&after);
  }
  /* retired local tables in local order (Go ranges local.Pairs) */
  for (size_t i = 0; i < ln && st == MURMUR_SYNC_OK && !done; i++) {
    if (!wire_lookup(rv, rn, lv[i].table, lv[i].table_len)) {
      out->incompatible = incompat_msg("table retired: ", lv[i].table,
                                       lv[i].table_len, NULL, NULL, 0);
      if (!out->incompatible) {
        st = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
      } else {
        done = 1;
      }
    }
  }
  free(lv);
  free(rv);
  if (st != MURMUR_SYNC_OK) {
    murmur_schema_diff_free(out);
    memset(out, 0, sizeof(*out));
    return st;
  }
  if (done) {
    /* Go returns the reason with no delta entries and no error. */
    for (size_t i = 0; i < out->n_tables; i++) {
      free(out->new_tables[i].table);
      free(out->new_tables[i].def);
    }
    free(out->new_tables);
    out->new_tables = NULL;
    out->n_tables = 0;
    for (size_t i = 0; i < out->n_columns; i++) {
      free(out->add_columns[i].table);
      free(out->add_columns[i].def);
    }
    free(out->add_columns);
    out->add_columns = NULL;
    out->n_columns = 0;
    out->additive = 0;
    return ok_rc(sqlrc);
  }
  out->additive = 1;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_puller_compatible(const uint8_t *local,
                                              size_t local_len,
                                              const uint8_t *puller,
                                              size_t puller_len,
                                              int *compatible, int *sqlrc) {
  if (compatible) {
    *compatible = 0;
  }
  murmur_schema_pair_t *lv = NULL, *pv = NULL;
  size_t ln = 0, pn = 0;
  int lr = decode_wire_pairs(local, local_len, &lv, &ln);
  int pr = decode_wire_pairs(puller, puller_len, &pv, &pn);
  if (lr < 0 || pr < 0) {
    free(lv);
    free(pv);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (lr == 0 || pr == 0) {
    free(lv);
    free(pv);
    return invalid_fail(sqlrc);
  }
  int ok = 1;
  for (size_t i = 0; i < ln; i++) {
    const murmur_schema_pair_t *pe =
        wire_lookup(pv, pn, lv[i].table, lv[i].table_len);
    if (!pe || !bytes_eq(pe->ddl, pe->ddl_len, lv[i].ddl, lv[i].ddl_len)) {
      ok = 0;
      break;
    }
  }
  free(lv);
  free(pv);
  if (compatible) {
    *compatible = ok;
  }
  return ok_rc(sqlrc);
}

/* ---- Discovery (Go SchemaPairs/SchemaBytes/ManifestSchemaBytes) ---- */

void murmur_schema_pairs_free(murmur_schema_entry_t *pairs, size_t n) {
  if (pairs) {
    for (size_t i = 0; i < n; i++) {
      free(pairs[i].table);
      free(pairs[i].ddl);
    }
    free(pairs);
  }
}

murmur_sync_status_t murmur_schema_pairs(sqlite3 *db,
                                         murmur_schema_entry_t **pairs,
                                         size_t *n, int *sqlrc) {
  *pairs = NULL;
  *n = 0;
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "SELECT name,sql FROM sqlite_schema WHERE type='table' AND name IN "
      "(SELECT substr(name,1,length(name)-13) FROM sqlite_schema WHERE "
      "type='table' AND substr(name,-13)='__crsql_clock') ORDER BY name",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  murmur_schema_entry_t *v = NULL;
  size_t count = 0, cap = 0;
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (;;) {
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, rc);
      break;
    }
    const uint8_t *name = sqlite3_column_text(st, 0);
    int name_n = sqlite3_column_bytes(st, 0);
    const uint8_t *ddl = sqlite3_column_text(st, 1);
    int ddl_n = sqlite3_column_bytes(st, 1);
    if (!name) {
      name_n = 0;
    }
    if (!ddl) {
      ddl_n = 0;
    }
    if (name_n >= 7 && memcmp(name, "murmur_", 7) == 0) {
      /* murmur_file_meta is the one internal table replicated through
       * the mesh (file metadata rides crsql_changes like user rows).
       * It is created identically by ensure_schema on every node, so it
       * is excluded from the replicated subset instead of failing the
       * handshake digest. Every other murmur_* CRR still fails closed.
       * (Go SchemaPairs has no such table and keeps failing.) */
      if (name_n == 16 && memcmp(name, "murmur_file_meta", 16) == 0) {
        continue;
      }
      status = MURMUR_SYNC_INVALID;
      set_sqlrc(sqlrc, SQLITE_MISUSE);
      break;
    }
    if (count >= cap) {
      size_t ncap = cap ? cap * 2 : 16;
      murmur_schema_entry_t *nv =
          (murmur_schema_entry_t *)realloc(v, ncap * sizeof(*nv));
      if (!nv) {
        status = MURMUR_SYNC_SQLITE;
        set_sqlrc(sqlrc, SQLITE_NOMEM);
        break;
      }
      v = nv;
      cap = ncap;
    }
    char *t = (char *)malloc((size_t)name_n + 1);
    char *d = (char *)malloc((size_t)ddl_n + 1);
    if (!t || !d) {
      free(t);
      free(d);
      status = MURMUR_SYNC_SQLITE;
      set_sqlrc(sqlrc, SQLITE_NOMEM);
      break;
    }
    if (name_n) {
      memcpy(t, name, (size_t)name_n);
    }
    t[name_n] = '\0';
    if (ddl_n) {
      memcpy(d, ddl, (size_t)ddl_n);
    }
    d[ddl_n] = '\0';
    v[count].table = t;
    v[count].ddl = d;
    count++;
  }
  sqlite3_finalize(st);
  if (status == MURMUR_SYNC_OK && count == 0) {
    status = MURMUR_SYNC_INVALID;
    set_sqlrc(sqlrc, SQLITE_MISUSE);
  }
  if (status != MURMUR_SYNC_OK) {
    murmur_schema_pairs_free(v, count);
    return status;
  }
  *pairs = v;
  *n = count;
  return ok_rc(sqlrc);
}

static size_t uvarint_len(uint64_t v) {
  size_t n = 1;
  while (v >= 0x80) {
    v >>= 7;
    n++;
  }
  return n;
}

/* Encodes owned entries via the golden postcard encoder. */
static murmur_sync_status_t entries_encode(const murmur_schema_entry_t *v,
                                           size_t n, uint8_t **blob, size_t *len,
                                           int *sqlrc) {
  *blob = NULL;
  *len = 0;
  murmur_schema_pair_t *views = NULL;
  if (n > 0) {
    views = (murmur_schema_pair_t *)malloc(n * sizeof(*views));
    if (!views) {
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    size_t total = uvarint_len((uint64_t)n);
    for (size_t i = 0; i < n; i++) {
      size_t tl = strlen(v[i].table), dl = strlen(v[i].ddl);
      views[i].table = tl ? (const uint8_t *)v[i].table : NULL;
      views[i].table_len = tl;
      views[i].ddl = dl ? (const uint8_t *)v[i].ddl : NULL;
      views[i].ddl_len = dl;
      total += uvarint_len((uint64_t)tl) + tl + uvarint_len((uint64_t)dl) + dl;
    }
    uint8_t *out = (uint8_t *)malloc(total ? total : 1);
    if (!out) {
      free(views);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    size_t w = murmur_schema_pairs_encode(views, n, out, total);
    free(views);
    if (w == 0 || w != total) {
      free(out);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    *blob = out;
    *len = w;
    return ok_rc(sqlrc);
  }
  uint8_t *out = (uint8_t *)malloc(1);
  if (!out) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  size_t w = murmur_schema_pairs_encode(NULL, 0, out, 1);
  if (w != 1) {
    free(out);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  *blob = out;
  *len = w;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_schema_bytes(sqlite3 *db, uint8_t **blob,
                                         size_t *len, int *sqlrc) {
  murmur_schema_entry_t *v = NULL;
  size_t n = 0;
  murmur_sync_status_t st = murmur_schema_pairs(db, &v, &n, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  st = entries_encode(v, n, blob, len, sqlrc);
  murmur_schema_pairs_free(v, n);
  return st;
}

murmur_sync_status_t murmur_schema_digest(sqlite3 *db, uint8_t digest[32],
                                          int *sqlrc) {
  uint8_t *blob = NULL;
  size_t len = 0;
  murmur_sync_status_t st = murmur_schema_bytes(db, &blob, &len, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_sha256(blob, len, digest);
  free(blob);
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_manifest_schema_bytes(sqlite3 *db, uint8_t **blob,
                                                 size_t *len, int *sqlrc) {
  *blob = NULL;
  *len = 0;
  murmur_schema_entry_t *v = NULL;
  size_t n = 0;
  murmur_sync_status_t st = murmur_schema_pairs(db, &v, &n, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  murmur_table_flags_t flags;
  memset(&flags, 0, sizeof(flags));
  st = murmur_cfg_table_flags(db, &flags, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    murmur_schema_pairs_free(v, n);
    return st;
  }
  /* compact kept entries in place, preserving order */
  size_t kept = 0;
  for (size_t i = 0; i < n; i++) {
    if (murmur_cfg_table_disabled(&flags, (const uint8_t *)v[i].table,
                                  strlen(v[i].table))) {
      free(v[i].table);
      free(v[i].ddl);
      continue;
    }
    if (kept != i) {
      v[kept] = v[i];
    }
    kept++;
  }
  murmur_cfg_table_flags_free(&flags);
  st = entries_encode(v, kept, blob, len, sqlrc);
  murmur_schema_pairs_free(v, kept);
  return st;
}

murmur_sync_status_t murmur_schema_is_crr(sqlite3 *db, const uint8_t *table,
                                          size_t table_len, int *is_crr,
                                          int *sqlrc) {
  if (is_crr) {
    *is_crr = 0;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", -1, &st,
      NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  static const char suffix[] = "__crsql_clock";
  size_t clock_n = table_len + sizeof(suffix) - 1;
  char *clock = (char *)malloc(clock_n + 1);
  if (!clock) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (table_len) {
    memcpy(clock, table, table_len);
  }
  memcpy(clock + table_len, suffix, sizeof(suffix));
  rc = sqlite3_bind_text(st, 1, clock, (int)clock_n, SQLITE_TRANSIENT);
  free(clock);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  if (is_crr) {
    *is_crr = (rc == SQLITE_ROW);
  }
  sqlite3_finalize(st);
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_schema_make_crr(sqlite3 *db, const uint8_t *table,
                                            size_t table_len, int *sqlrc) {
  int yes = 0;
  murmur_sync_status_t st = murmur_schema_is_crr(db, table, table_len, &yes,
                                                 sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (yes) {
    return ok_rc(sqlrc);
  }
  /* SELECT crsql_as_crr('main',"T") with " doubled (Go quoteIdent) */
  static const char pre[] = "SELECT crsql_as_crr('main',\"";
  static const char post[] = "\")";
  size_t quotes = 0;
  for (size_t i = 0; i < table_len; i++) {
    quotes += (table[i] == '"');
  }
  size_t total =
      (sizeof(pre) - 1) + table_len + quotes + (sizeof(post) - 1);
  char *sql = (char *)malloc(total + 1);
  if (!sql) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  size_t w = 0;
  memcpy(sql + w, pre, sizeof(pre) - 1);
  w += sizeof(pre) - 1;
  for (size_t i = 0; i < table_len; i++) {
    sql[w++] = (char)table[i];
    if (table[i] == '"') {
      sql[w++] = '"';
    }
  }
  memcpy(sql + w, post, sizeof(post) - 1);
  w += sizeof(post) - 1;
  sql[w] = '\0';
  char *errmsg = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
  if (errmsg) {
    sqlite3_free(errmsg);
  }
  free(sql);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  return ok_rc(sqlrc);
}

/* ---- Adoption (Go ApplySchemaAdditive) ---- */

static murmur_sync_status_t count_where(sqlite3 *db, const char *query,
                                        const char *arg, int64_t *n,
                                        int *sqlrc) {
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(db, query, -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_bind_text(st, 1, arg, -1, SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(st);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  *n = sqlite3_column_int64(st, 0);
  sqlite3_finalize(st);
  return ok_rc(sqlrc);
}

static murmur_sync_status_t apply_one_table(
    sqlite3 *db, const char *table, const char *ddl, int *sqlrc) {
  murmur_sync_status_t st = murmur_check_create_table(
      (const uint8_t *)table, strlen(table), (const uint8_t *)ddl, strlen(ddl),
      sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  sqlite3_stmt *q = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1", -1,
      &q, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_bind_text(q, 1, table, -1, SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(q);
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(q);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(q);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_ROW) {
    const uint8_t *existing = sqlite3_column_text(q, 0);
    int existing_n = sqlite3_column_bytes(q, 0);
    if (!existing) {
      existing_n = 0;
    }
    size_t a_len = 0, b_len = 0;
    char *a = strip_tight(existing ? existing : (const uint8_t *)"",
                          (size_t)existing_n, &a_len);
    char *b = strip_tight((const uint8_t *)ddl, strlen(ddl), &b_len);
    sqlite3_finalize(q);
    if (!a || !b) {
      free(a);
      free(b);
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    int same = (a_len == b_len && memcmp(a, b, a_len) == 0);
    free(a);
    free(b);
    if (!same) {
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
  } else {
    sqlite3_finalize(q);
    char *errmsg = NULL;
    rc = sqlite3_exec(db, ddl, NULL, NULL, &errmsg);
    if (errmsg) {
      sqlite3_free(errmsg);
    }
    if (rc != SQLITE_OK) {
      return sqlite_fail(sqlrc, rc);
    }
  }
  static const char clock_q[] =
      "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1";
  size_t table_len = strlen(table);
  static const char suffix[] = "__crsql_clock";
  char *clock = (char *)malloc(table_len + sizeof(suffix));
  if (!clock) {
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  memcpy(clock, table, table_len);
  memcpy(clock + table_len, suffix, sizeof(suffix));
  int64_t n = 0;
  st = count_where(db, clock_q, clock, &n, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    free(clock);
    return st;
  }
  if (n != 1) {
    st = murmur_schema_make_crr(db, (const uint8_t *)table, table_len, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      free(clock);
      return st;
    }
    st = count_where(db, clock_q, clock, &n, sqlrc);
    free(clock);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    if (n != 1) {
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    return ok_rc(sqlrc);
  }
  free(clock);
  return ok_rc(sqlrc);
}

static murmur_sync_status_t apply_one_column(
    sqlite3 *db, const char *table, const char *coldef, int *sqlrc) {
  if (!valid_ident((const uint8_t *)table, strlen(table))) {
    return invalid_fail(sqlrc);
  }
  char *column = NULL;
  murmur_sync_status_t st =
      murmur_check_add_column((const uint8_t *)coldef, strlen(coldef), &column,
                              sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  /* table interpolated raw, exactly like Go */
  static const char pre[] = "SELECT type FROM pragma_table_info(\"";
  static const char post[] = "\") WHERE name=?1";
  size_t table_len = strlen(table);
  size_t qlen = (sizeof(pre) - 1) + table_len + (sizeof(post) - 1);
  char *query = (char *)malloc(qlen + 1);
  if (!query) {
    free(column);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  size_t w = 0;
  memcpy(query + w, pre, sizeof(pre) - 1);
  w += sizeof(pre) - 1;
  memcpy(query + w, table, table_len);
  w += table_len;
  memcpy(query + w, post, sizeof(post) - 1);
  w += sizeof(post) - 1;
  query[w] = '\0';
  sqlite3_stmt *q = NULL;
  int rc = sqlite3_prepare_v2(db, query, -1, &q, NULL);
  if (rc != SQLITE_OK) {
    free(query);
    free(column);
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_bind_text(q, 1, column, -1, SQLITE_TRANSIENT);
  if (rc != SQLITE_OK) {
    sqlite3_finalize(q);
    free(query);
    free(column);
    return sqlite_fail(sqlrc, rc);
  }
  rc = sqlite3_step(q);
  if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
    sqlite3_finalize(q);
    free(query);
    free(column);
    return sqlite_fail(sqlrc, rc);
  }
  if (rc == SQLITE_ROW) {
    const uint8_t *aff = sqlite3_column_text(q, 0);
    int aff_n = sqlite3_column_bytes(q, 0);
    if (!aff) {
      aff_n = 0;
    }
    /* declared = second field of the def, quotes trimmed; compare
     * before finalizing (aff dangles after) */
    view_t *fields = NULL;
    size_t nfields = 0;
    int frc = split_fields((const uint8_t *)coldef, strlen(coldef), &fields,
                           &nfields);
    int same = 0;
    if (frc == 0 && nfields > 1) {
      const uint8_t *decl = fields[1].p;
      size_t decl_n = fields[1].n;
      while (decl_n > 0 && decl[0] == '"') {
        decl++;
        decl_n--;
      }
      while (decl_n > 0 && decl[decl_n - 1] == '"') {
        decl_n--;
      }
      same = equal_fold_ascii(aff ? aff : (const uint8_t *)"",
                              (size_t)aff_n, decl, decl_n);
    }
    free(fields);
    sqlite3_finalize(q);
    free(query);
    free(column);
    if (frc != 0) {
      return sqlite_fail(sqlrc, SQLITE_NOMEM);
    }
    if (!same) {
      set_sqlrc(sqlrc, SQLITE_OK);
      return MURMUR_SYNC_PROTOCOL;
    }
    return ok_rc(sqlrc);
  }
  sqlite3_finalize(q);
  static const char apre[] = "ALTER TABLE \"";
  static const char amid[] = "\" ADD COLUMN ";
  size_t alen =
      (sizeof(apre) - 1) + table_len + (sizeof(amid) - 1) + strlen(coldef);
  char *alter = (char *)malloc(alen + 1);
  if (!alter) {
    free(query);
    free(column);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  w = 0;
  memcpy(alter + w, apre, sizeof(apre) - 1);
  w += sizeof(apre) - 1;
  memcpy(alter + w, table, table_len);
  w += table_len;
  memcpy(alter + w, amid, sizeof(amid) - 1);
  w += sizeof(amid) - 1;
  memcpy(alter + w, coldef, strlen(coldef));
  w += strlen(coldef);
  alter[w] = '\0';
  char *errmsg = NULL;
  rc = sqlite3_exec(db, alter, NULL, NULL, &errmsg);
  if (errmsg) {
    sqlite3_free(errmsg);
  }
  free(alter);
  if (rc != SQLITE_OK) {
    free(query);
    free(column);
    return sqlite_fail(sqlrc, rc);
  }
  static const char cpre[] = "SELECT count(*) FROM pragma_table_info(\"";
  static const char cpost[] = "\") WHERE name=?1";
  size_t clen = (sizeof(cpre) - 1) + table_len + (sizeof(cpost) - 1);
  char *cquery = (char *)malloc(clen + 1);
  if (!cquery) {
    free(query);
    free(column);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  w = 0;
  memcpy(cquery + w, cpre, sizeof(cpre) - 1);
  w += sizeof(cpre) - 1;
  memcpy(cquery + w, table, table_len);
  w += table_len;
  memcpy(cquery + w, cpost, sizeof(cpost) - 1);
  w += sizeof(cpost) - 1;
  cquery[w] = '\0';
  int64_t n = 0;
  st = count_where(db, cquery, column, &n, sqlrc);
  free(cquery);
  free(query);
  free(column);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (n != 1) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_PROTOCOL;
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_apply_additive(
    sqlite3 *db, const murmur_schema_delta_ent_t *tables, size_t n_tables,
    const murmur_schema_delta_ent_t *columns, size_t n_columns, int *sqlrc) {
  char *errmsg = NULL;
  int rc = sqlite3_crsqlite_init(db, &errmsg, NULL);
  if (errmsg) {
    sqlite3_free(errmsg);
  }
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  for (size_t i = 0; i < n_tables; i++) {
    murmur_sync_status_t st =
        apply_one_table(db, tables[i].table, tables[i].def, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
  }
  for (size_t i = 0; i < n_columns; i++) {
    murmur_sync_status_t st =
        apply_one_column(db, columns[i].table, columns[i].def, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
  }
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_schema_params_from(sqlite3 *db,
                                              murmur_schema_params_t *out,
                                              int *sqlrc) {
  memset(out, 0, sizeof(*out));
  /* Go order: schema_master, max_batch_bytes, accept flag, master flag */
  char *raw = NULL;
  murmur_sync_status_t st = murmur_cfg_setting(db, "schema_master", &raw,
                                               sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  if (raw[0] != '\0') {
    if (murmur_cfg_parse_id((const uint8_t *)raw, strlen(raw), &out->master) !=
        0) {
      free(raw);
      return invalid_fail(sqlrc);
    }
    out->has_master = 1;
  }
  free(raw);
  char *max_raw = NULL;
  st = murmur_cfg_setting(db, "max_batch_bytes", &max_raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  uint64_t max_bytes = 0;
  if (murmur_cfg_atoi(max_raw, &max_bytes) != 0) {
    free(max_raw);
    return invalid_fail(sqlrc);
  }
  free(max_raw);
  out->max_schema_bytes = (int64_t)max_bytes;
  static const char *flags[] = {"accept_remote_schema",
                                "schema_master_enabled"};
  int *slots[] = {&out->accept_remote, &out->master_enabled};
  for (size_t i = 0; i < 2; i++) {
    char *v = NULL;
    st = murmur_cfg_setting(db, flags[i], &v, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    if (strcmp(v, "1") == 0) {
      *slots[i] = 1;
    } else if (strcmp(v, "0") != 0) {
      free(v);
      return invalid_fail(sqlrc);
    }
    free(v);
  }
  return ok_rc(sqlrc);
}
