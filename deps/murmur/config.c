/* murmur config - see config.h. */
#include "config.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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

/* ---- defaults (verbatim from config.go) ---- */

typedef struct {
  const char *name;
  const char *def;
} def_ent_t;

static const def_ent_t kDefaults[] = {
    {"group_id", ""},
    {"advertise", ""},
    {"certificate", ""},
    {"private_key", ""},
    {"ca", ""},
    {"crl_file", ""},
    {"origin_key_file", ""},
    {"trusted_origins", ""},
    {"crsqlite_extension", ""},
    {"bind", "0.0.0.0:7443"},
    {"bootstrap", "[]"},
    {"allowed_peers", "[]"},
    {"allowed_networks", "[]"},
    {"poll_ms", "100"},
    {"anti_entropy_ms", "10000"},
    {"gossip_fanout", "3"},
    {"sessions", "32"},
    {"batch_bytes", "1048576"},
    {"max_batch_bytes", "67108864"},
    {"queue_bytes", "67108864"},
    {"staging_bytes", "268435456"},
    {"staging_timeout_ms", "300000"},
    {"writer_local_share", "90"},
    {"writer_remote_share", "10"},
    {"writer_max_debt_ms", "1000"},
    {"writer_maintenance_reserve_every", "100"},
    {"retention_min_kept", "1000"},
    {"retention_max_offline_ms", "604800000"},
    {"retention_gc", "1"},
    {"table_replication", "{}"},
    {"column_policies", "{}"},
    {"snapshot_bytes", "536870912"},
    {"snapshot_staging_bytes", "536870912"},
    {"snapshot_lifetime_ms", "604800000"},
    {"snapshot_staging_transfers", "4096"},
    {"snapshot_trusted_sources", "[]"},
    {"accept_remote_schema", "1"},
    {"schema_master", ""},
    {"schema_master_enabled", "0"},
    {"kdf", "direct"},
    {"kdf_time", "3"},
    {"kdf_memory_kib", "65536"},
    {"kdf_threads", "4"},
    {"bridge_dir", ""},
    {"files_generation", "0"},
    {"max_file_bytes", "4294967296"},
    {"max_staging_bytes", "1073741824"},
    {"fetch_concurrency", "2"},
    {"fetch_interval_ms", "30000"},
    {"fetch_bind", ""},
    {"bridge_role", ""},
    {"bridge_stream", ""},
    {"bridge_max_bundle_bytes", "16777216"},
    {"bridge_max_payload_bytes", "67108864"},
    {"bridge_staging_bytes", "1073741824"},
    {"files_dir", ""},
    {NULL, NULL},
};

const char *murmur_cfg_default(const char *name) {
  if (!name) {
    return NULL;
  }
  for (const def_ent_t *e = kDefaults; e->name; e++) {
    if (strcmp(e->name, name) == 0) {
      return e->def;
    }
  }
  return NULL;
}

/* ---- integer parsing ---- */

int murmur_cfg_atoi(const char *s, uint64_t *v) {
  if (!s || !*s) {
    return -1;
  }
  uint64_t x = 0;
  for (const char *p = s; *p; p++) {
    if (*p < '0' || *p > '9') {
      return -1;
    }
    uint64_t d = (uint64_t)(*p - '0');
    if (x > (~(uint64_t)0 - d) / 10) {
      return -1;
    }
    x = x * 10 + d;
  }
  *v = x;
  return 0;
}

int murmur_cfg_parse_uint(const uint8_t *s, size_t n, uint64_t *v) {
  if (n == 0) {
    return -1;
  }
  uint64_t x = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') {
      return -1;
    }
    uint64_t d = (uint64_t)(s[i] - '0');
    if (x > (~(uint64_t)0 - d) / 10) {
      return -1;
    }
    x = x * 10 + d;
  }
  *v = x;
  return 0;
}

/* ---- node ids ---- */

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

int murmur_cfg_parse_id(const uint8_t *s, size_t n, murmur_node_t *out) {
  char flat[64];
  size_t fn = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '-') {
      continue;
    }
    if (fn >= sizeof(flat)) {
      return -1;
    }
    flat[fn++] = (char)s[i];
  }
  if (fn != 32) {
    return -1;
  }
  int allzero = 1;
  for (int i = 0; i < 16; i++) {
    int hi = hex_val(flat[2 * i]);
    int lo = hex_val(flat[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out->b[i] = (uint8_t)((hi << 4) | lo);
    if (out->b[i]) {
      allzero = 0;
    }
  }
  return allzero ? -1 : 0;
}

/* ---- host:port splitting (Go SplitHostPort semantics) ---- */

/* Splits s into host/port views. Bracketed literals keep no
 * brackets; the zone (if any) stays in the host. Returns 0 on
 * success, -1 on missing port, bad brackets, or too many colons. */
static int split_host_port(const uint8_t *s, size_t n, const uint8_t **host,
                           size_t *host_len, const uint8_t **port,
                           size_t *port_len) {
  if (n == 0) {
    return -1;
  }
  if (s[0] == '[') {
    const uint8_t *close = NULL;
    for (size_t i = 1; i < n; i++) {
      if (s[i] == ']') {
        close = s + i;
        break;
      }
    }
    if (!close) {
      return -1;
    }
    if (close + 1 >= s + n || close[1] != ':') {
      return -1; /* "[::1]" or garbage after ']' */
    }
    *host = s + 1;
    *host_len = (size_t)(close - (s + 1));
    *port = close + 2;
    *port_len = (size_t)((s + n) - (close + 2));
    return 0;
  }
  const uint8_t *colon = NULL;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == ':') {
      if (colon) {
        return -1; /* too many colons */
      }
      colon = s + i;
    }
  }
  if (!colon) {
    return -1;
  }
  *host = s;
  *host_len = (size_t)(colon - s);
  *port = colon + 1;
  *port_len = (size_t)((s + n) - (colon + 1));
  return 0;
}

/* valid_dns_name mirrors Go validDNSName verbatim: dot-separated
 * labels of letters, digits, hyphens, underscores; labels never
 * start or end with a hyphen. */
static int valid_dns_name(const uint8_t *s, size_t n) {
  if (n == 0 || n > 253) {
    return 0;
  }
  size_t m = n;
  if (s[m - 1] == '.') {
    m--;
  }
  if (m == 0) {
    return 0;
  }
  size_t start = 0;
  for (size_t i = 0; i <= m; i++) {
    if (i == m || s[i] == '.') {
      size_t llen = i - start;
      if (llen == 0 || llen > 63) {
        return 0;
      }
      for (size_t j = start; j < i; j++) {
        char c = (char)s[j];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
          return 0;
        }
      }
      if (s[start] == '-' || s[i - 1] == '-') {
        return 0;
      }
      start = i + 1;
    }
  }
  return 1;
}

/* resolve_ok mirrors the resolving half of Go ResolveTCPAddr: the
 * host must resolve (literal, hosts file, or DNS) and the port must
 * be numeric-or-service. A leading '+' on an all-digit port is
 * stripped first (Go's lookupPort runs Atoi, which takes '+'). An
 * empty host passes NULL (Go accepts empty hosts with valid ports).
 * Like Go, this may block on DNS. */
static int resolve_ok(const uint8_t *host, size_t host_len,
                      const uint8_t *port, size_t port_len) {
  if (port_len == 0) {
    return -1;
  }
  const uint8_t *ps = port;
  size_t pn = port_len;
  if (pn > 1 && ps[0] == '+') {
    int alldig = 1;
    for (size_t i = 1; i < pn; i++) {
      if (ps[i] < '0' || ps[i] > '9') {
        alldig = 0;
        break;
      }
    }
    if (alldig) {
      ps++;
      pn--;
    }
  }
  {
    /* Numeric ports range-check like Go's lookupPort (getaddrinfo
     * itself accepts out-of-range numbers on glibc). */
    int alldig = pn > 0;
    for (size_t i = 0; i < pn; i++) {
      if (ps[i] < '0' || ps[i] > '9') {
        alldig = 0;
        break;
      }
    }
    if (alldig) {
      uint64_t v = 0;
      if (murmur_cfg_parse_uint(ps, pn, &v) != 0 || v > 65535) {
        return -1;
      }
    }
  }
  char *node = NULL;
  if (host_len > 0) {
    node = (char *)malloc(host_len + 1);
    if (!node) {
      return -1;
    }
    memcpy(node, host, host_len);
    node[host_len] = '\0';
  }
  char *serv = (char *)malloc(pn + 1);
  if (!serv) {
    free(node);
    return -1;
  }
  memcpy(serv, ps, pn);
  serv[pn] = '\0';
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  int rc = getaddrinfo(node, serv, &hints, &res);
  if (rc == 0) {
    freeaddrinfo(res);
  }
  free(node);
  free(serv);
  return rc == 0 ? 0 : -1;
}

/* check_socket_or_name mirrors Go exactly: split, then the resolving
 * branch (any host that resolves, like Go's ResolveTCPAddr half),
 * else the DNS-shape branch (valid name plus numeric 1..65535 port,
 * like the SplitHostPort/Atoi half). */
static int check_socket_or_name(const uint8_t *s, size_t n) {
  const uint8_t *host = NULL, *port = NULL;
  size_t host_len = 0, port_len = 0;
  if (split_host_port(s, n, &host, &host_len, &port, &port_len) != 0) {
    return -1;
  }
  if (resolve_ok(host, host_len, port, port_len) == 0) {
    return 0;
  }
  if (!valid_dns_name(host, host_len)) {
    return -1;
  }
  uint64_t v = 0;
  /* Go runs Atoi here, which takes a leading '+'. */
  const uint8_t *ps = port;
  size_t pn = port_len;
  if (pn > 1 && ps[0] == '+') {
    ps++;
    pn--;
  }
  return murmur_cfg_parse_uint(ps, pn, &v) == 0 && v >= 1 && v <= 65535 ? 0
                                                                       : -1;
}

/* bind_ok mirrors "bind": split, a non-empty host (Go rejects the
 * resolved-nil-IP empty host), and successful resolution. */
static int bind_ok(const uint8_t *s, size_t n) {
  const uint8_t *host = NULL, *port = NULL;
  size_t host_len = 0, port_len = 0;
  if (split_host_port(s, n, &host, &host_len, &port, &port_len) != 0) {
    return -1;
  }
  if (host_len == 0) {
    return -1;
  }
  return resolve_ok(host, host_len, port, port_len);
}

/* parse_cidr mirrors Go net.ParseCIDR accept/reject: addr/prefix
 * with a literal address and a numeric in-range prefix. */
static int parse_cidr(const uint8_t *s, size_t n) {
  const uint8_t *slash = NULL;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '/') {
      if (slash) {
        return -1;
      }
      slash = s + i;
    }
  }
  if (!slash) {
    return -1;
  }
  size_t addr_len = (size_t)(slash - s);
  size_t pre_len = n - addr_len - 1;
  if (addr_len == 0 || addr_len >= 64 || pre_len == 0) {
    return -1;
  }
  char tmp[64];
  memcpy(tmp, s, addr_len);
  tmp[addr_len] = '\0';
  uint8_t b4[4], b16[16];
  int is4 = inet_pton(AF_INET, tmp, b4) == 1;
  int is6 = !is4 && inet_pton(AF_INET6, tmp, b16) == 1;
  if (!is4 && !is6) {
    return -1;
  }
  uint64_t bits = 0;
  if (murmur_cfg_parse_uint(slash + 1, pre_len, &bits) != 0) {
    return -1;
  }
  uint64_t max = is4 ? 32 : 128;
  return bits <= max ? 0 : -1;
}

/* ---- JSON-shaped validation via JSON1 ----
 *
 * Each checker takes the raw value, gates on json_type, then walks
 * json_each rows. Counts bound work (the value cap bounds rows);
 * since Validate reports accept/reject only, any rejection order
 * matches Go. Nested values surface as non-scalar rows and fail
 * exactly where Go's unmarshal would. */

static int json_is(sqlite3 *db, const uint8_t *v, size_t n, const char *want) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, "SELECT json_type(?)", -1, &st, NULL) !=
      SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(st, 1, (const char *)v, (int)n, SQLITE_TRANSIENT);
  int rc = sqlite3_step(st);
  const uint8_t *t =
      rc == SQLITE_ROW ? sqlite3_column_text(st, 0) : NULL;
  int ok = t && strcmp((const char *)t, want) == 0;
  sqlite3_finalize(st);
  return ok ? 0 : -1;
}

/* Row callback: return 0 to continue, -1 to reject. */
typedef int (*row_fn)(const uint8_t *key, size_t key_len,
                      const uint8_t *type, const uint8_t *val, size_t val_len,
                      void *ctx);

/* Walks json_each rows; stops after cap rows (caller treats a full
 * walk past cap as oversize). Returns 0 when every visited row
 * passed, -1 on rejection or JSON error. *walked counts rows. */
static int walk_json(sqlite3 *db, const uint8_t *v, size_t n, row_fn fn,
                     void *ctx, size_t cap, size_t *walked) {
  *walked = 0;
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, "SELECT key, type, value FROM json_each(?)",
                         -1, &st, NULL) != SQLITE_OK) {
    return -1;
  }
  sqlite3_bind_text(st, 1, (const char *)v, (int)n, SQLITE_TRANSIENT);
  int ok = 1;
  for (;;) {
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      ok = 0;
      break;
    }
    if (*walked >= cap) {
      ok = 0; /* oversize (cap counts unique keys where needed) */
      break;
    }
    const uint8_t *k = sqlite3_column_text(st, 0);
    int kn = sqlite3_column_bytes(st, 0);
    const uint8_t *t = sqlite3_column_text(st, 1);
    const uint8_t *val = sqlite3_column_text(st, 2);
    int vn = sqlite3_column_bytes(st, 2);
    (*walked)++;
    if (fn(k, (size_t)kn, t, val, (size_t)vn, ctx) != 0) {
      ok = 0;
      break;
    }
  }
  sqlite3_finalize(st);
  return ok ? 0 : -1;
}

static int socket_row(const uint8_t *key, size_t key_len, const uint8_t *type,
                      const uint8_t *val, size_t val_len, void *ctx) {
  (void)key;
  (void)key_len;
  (void)ctx;
  return strcmp((const char *)type, "text") == 0 &&
                 check_socket_or_name(val, val_len) == 0
             ? 0
             : -1;
}

static int id_row(const uint8_t *key, size_t key_len, const uint8_t *type,
                  const uint8_t *val, size_t val_len, void *ctx) {
  (void)key;
  (void)key_len;
  (void)ctx;
  murmur_node_t id;
  return strcmp((const char *)type, "text") == 0 &&
                 murmur_cfg_parse_id(val, val_len, &id) == 0
             ? 0
             : -1;
}

static int cidr_row(const uint8_t *key, size_t key_len, const uint8_t *type,
                    const uint8_t *val, size_t val_len, void *ctx) {
  (void)key;
  (void)key_len;
  (void)ctx;
  return strcmp((const char *)type, "text") == 0 &&
                 parse_cidr(val, val_len) == 0
             ? 0
             : -1;
}

/* table_replication rows: boolean values, 1..128-byte names, at most
 * 1024 unique keys (duplicates collapse, like Go's map). */
typedef struct {
  char keys[1025][129];
  size_t n;
} keyset_t;

static int table_row(const uint8_t *key, size_t key_len, const uint8_t *type,
                     const uint8_t *val, size_t val_len, void *ctx) {
  (void)val;
  (void)val_len;
  keyset_t *ks = (keyset_t *)ctx;
  if (strcmp((const char *)type, "true") != 0 &&
      strcmp((const char *)type, "false") != 0) {
    return -1;
  }
  if (key_len == 0 || key_len > 128) {
    return -1;
  }
  for (size_t i = 0; i < ks->n; i++) {
    if (strlen(ks->keys[i]) == key_len &&
        memcmp(ks->keys[i], key, key_len) == 0) {
      return 0;
    }
  }
  if (ks->n >= 1024) {
    return -1;
  }
  memcpy(ks->keys[ks->n], key, key_len);
  ks->keys[ks->n][key_len] = '\0';
  ks->n++;
  return 0;
}

/* column_policies rows: table.column keys, known merge policies. */
static int policy_row(const uint8_t *key, size_t key_len, const uint8_t *type,
                      const uint8_t *val, size_t val_len, void *ctx) {
  (void)ctx;
  if (strcmp((const char *)type, "text") != 0) {
    return -1;
  }
  /* Exactly one dot, both sides nonempty (Go strings.Split len==2). */
  const uint8_t *dot = NULL;
  for (size_t i = 0; i < key_len; i++) {
    if (key[i] == '.') {
      if (dot) {
        return -1;
      }
      dot = key + i;
    }
  }
  if (!dot || dot == key || dot + 1 == key + key_len) {
    return -1;
  }
  static const char *pols[] = {"Lww", "Counter", "Set", "Min", "Max"};
  for (int i = 0; i < 5; i++) {
    if (strlen(pols[i]) == val_len &&
        memcmp(pols[i], val, val_len) == 0) {
      return 0;
    }
  }
  return -1;
}

/* trusted_origins rows: 32-hex site keys, 64-hex ed25519 pubkeys. */
static int origin_row(const uint8_t *key, size_t key_len, const uint8_t *type,
                      const uint8_t *val, size_t val_len, void *ctx) {
  (void)ctx;
  if (strcmp((const char *)type, "text") != 0) {
    return -1;
  }
  if (key_len != 32 || val_len != 64) {
    return -1;
  }
  for (size_t i = 0; i < 32; i++) {
    int c = key[i];
    if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') &&
        !(c >= 'A' && c <= 'F')) {
      return -1;
    }
  }
  for (size_t i = 0; i < 64; i++) {
    int c = val[i];
    if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') &&
        !(c >= 'A' && c <= 'F')) {
      return -1;
    }
  }
  return 0;
}

/* ---- Validate ---- */

static int in_range(const uint8_t *v, size_t n, uint64_t lo, uint64_t hi) {
  uint64_t x = 0;
  return murmur_cfg_parse_uint(v, n, &x) == 0 && x >= lo && x <= hi ? 0
                                                                   : -1;
}

int murmur_cfg_validate(sqlite3 *db, const char *name, const uint8_t *value,
                        size_t len) {
  if (!name || (!value && len > 0)) {
    return -1;
  }
  if (!murmur_cfg_default(name)) {
    return -1;
  }
  if (len > 65536 || (len > 0 && memchr(value, 0, len))) {
    return -1;
  }
  if (strcmp(name, "group_id") == 0) {
    murmur_node_t id;
    return murmur_cfg_parse_id(value, len, &id);
  }
  if (strcmp(name, "bind") == 0) {
    return bind_ok(value, len);
  }
  if (strcmp(name, "advertise") == 0) {
    return len == 0 ? 0 : check_socket_or_name(value, len);
  }
  if (strcmp(name, "bootstrap") == 0 || strcmp(name, "allowed_peers") == 0 ||
      strcmp(name, "allowed_networks") == 0 ||
      strcmp(name, "snapshot_trusted_sources") == 0) {
    if (!db || json_is(db, value, len, "array") != 0) {
      return -1;
    }
    row_fn fn = socket_row;
    if (strcmp(name, "allowed_networks") == 0) {
      fn = cidr_row;
    } else if (strcmp(name, "bootstrap") != 0) {
      fn = id_row;
    }
    size_t walked = 0;
    if (walk_json(db, value, len, fn, NULL, 4096, &walked) != 0) {
      return -1;
    }
    return 0;
  }
  if (strcmp(name, "gossip_fanout") == 0) {
    return in_range(value, len, 1, 32);
  }
  if (strcmp(name, "poll_ms") == 0 || strcmp(name, "anti_entropy_ms") == 0) {
    return in_range(value, len, 10, 86400000);
  }
  if (strcmp(name, "staging_timeout_ms") == 0) {
    return in_range(value, len, 60000, 86400000);
  }
  if (strcmp(name, "sessions") == 0) {
    return in_range(value, len, 1, 256);
  }
  if (strcmp(name, "batch_bytes") == 0 ||
      strcmp(name, "max_batch_bytes") == 0 ||
      strcmp(name, "queue_bytes") == 0 || strcmp(name, "staging_bytes") == 0) {
    return in_range(value, len, 65536, 1073741824);
  }
  if (strcmp(name, "writer_local_share") == 0) {
    return in_range(value, len, 1, 99);
  }
  if (strcmp(name, "writer_max_debt_ms") == 0) {
    return in_range(value, len, 1, 60000);
  }
  if (strcmp(name, "writer_maintenance_reserve_every") == 0) {
    return in_range(value, len, 1, 1000000);
  }
  if (strcmp(name, "writer_remote_share") == 0) {
    return -1; /* derived; assign writer_local_share instead */
  }
  if (strcmp(name, "retention_min_kept") == 0) {
    return in_range(value, len, 1, 1000000);
  }
  if (strcmp(name, "retention_max_offline_ms") == 0) {
    return in_range(value, len, 60000, 2592000000);
  }
  if (strcmp(name, "table_replication") == 0) {
    if (!db || json_is(db, value, len, "object") != 0) {
      return -1;
    }
    keyset_t ks;
    memset(&ks, 0, sizeof(ks));
    size_t walked = 0;
    /* Cap counts raw rows; table_row dedupes for the 1024 unique cap.
     * Rows past the walk cap reject (a valid map has ≤1024 unique
     * keys, so longer walks are oversize regardless of dups). */
    if (walk_json(db, value, len, table_row, &ks, 65536, &walked) != 0) {
      return -1;
    }
    return 0;
  }
  if (strcmp(name, "column_policies") == 0) {
    if (!db || json_is(db, value, len, "object") != 0) {
      return -1;
    }
    size_t walked = 0;
    return walk_json(db, value, len, policy_row, NULL, 65536, &walked);
  }
  if (strcmp(name, "snapshot_bytes") == 0 ||
      strcmp(name, "snapshot_staging_bytes") == 0) {
    return in_range(value, len, 65536, (uint64_t)1 << 40);
  }
  if (strcmp(name, "snapshot_lifetime_ms") == 0) {
    return in_range(value, len, 3600000, 2592000000);
  }
  if (strcmp(name, "snapshot_staging_transfers") == 0) {
    return in_range(value, len, 1, 65536);
  }
  if (strcmp(name, "accept_remote_schema") == 0 ||
      strcmp(name, "schema_master_enabled") == 0 ||
      strcmp(name, "retention_gc") == 0) {
    return (len == 1 && (value[0] == '0' || value[0] == '1')) ? 0 : -1;
  }
  if (strcmp(name, "schema_master") == 0) {
    if (len == 0) {
      return 0;
    }
    murmur_node_t id;
    return murmur_cfg_parse_id(value, len, &id);
  }
  if (strcmp(name, "kdf") == 0) {
    return (len == 6 && memcmp(value, "direct", 6) == 0) ||
                   (len == 8 && memcmp(value, "argon2id", 8) == 0)
               ? 0
               : -1;
  }
  if (strcmp(name, "kdf_time") == 0) {
    return in_range(value, len, 1, 32);
  }
  if (strcmp(name, "kdf_memory_kib") == 0) {
    return in_range(value, len, 1024, 16777216);
  }
  if (strcmp(name, "kdf_threads") == 0) {
    return in_range(value, len, 1, 32);
  }
  if (strcmp(name, "files_dir") == 0) {
    return 0;
  }
  if (strcmp(name, "origin_key_file") == 0) {
    return 0;
  }
  if (strcmp(name, "trusted_origins") == 0) {
    if (len == 0) {
      return 0;
    }
    if (!db || json_is(db, value, len, "object") != 0) {
      return -1;
    }
    size_t walked = 0;
    return walk_json(db, value, len, origin_row, NULL, 65536, &walked);
  }
  /* Bridge/file knobs and certificates: presence-checked only. */
  return 0;
}

/* ---- Setting / SetSetting ---- */

murmur_sync_status_t murmur_cfg_setting(sqlite3 *db, const char *name,
                                        char **out, int *sqlrc) {
  *out = NULL;
  if (!db || !name) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  if (strcmp(name, "writer_remote_share") == 0) {
    char *local = NULL;
    murmur_sync_status_t st =
        murmur_cfg_setting(db, "writer_local_share", &local, sqlrc);
    if (st != MURMUR_SYNC_OK) {
      return st;
    }
    uint64_t n = 0;
    int bad = murmur_cfg_atoi(local, &n) != 0 || n < 1 || n > 99;
    free(local);
    if (bad) {
      return MURMUR_SYNC_INVALID;
    }
    char buf[24];
    snprintf(buf, sizeof(buf), "%llu",
             (unsigned long long)(100 - n));
    *out = strdup(buf);
    return *out ? ok_rc(sqlrc) : sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  const char *def = murmur_cfg_default(name);
  if (!def) {
    return MURMUR_SYNC_INVALID;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db, "SELECT value FROM murmur_config WHERE name=?", -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  if (rc == SQLITE_DONE) {
    sqlite3_finalize(st);
    *out = strdup(def);
    return *out ? ok_rc(sqlrc) : sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, rc);
  }
  const uint8_t *v = sqlite3_column_text(st, 0);
  int n = sqlite3_column_bytes(st, 0);
  char *copy = (char *)malloc((size_t)n + 1);
  if (!copy) {
    sqlite3_finalize(st);
    return sqlite_fail(sqlrc, SQLITE_NOMEM);
  }
  memcpy(copy, v, (size_t)n);
  copy[n] = '\0';
  sqlite3_finalize(st);
  *out = copy;
  return ok_rc(sqlrc);
}

murmur_sync_status_t murmur_cfg_set_setting(sqlite3 *db, const char *name,
                                            const uint8_t *value, size_t len,
                                            int *sqlrc) {
  if (!db || !name || (!value && len > 0)) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  if (murmur_cfg_validate(db, name, value, len) != 0) {
    set_sqlrc(sqlrc, SQLITE_OK);
    return MURMUR_SYNC_INVALID;
  }
  sqlite3_stmt *st = NULL;
  int rc = sqlite3_prepare_v2(
      db,
      "INSERT INTO murmur_config(name,value) VALUES(?,?) ON CONFLICT(name) "
      "DO UPDATE SET value=excluded.value",
      -1, &st, NULL);
  if (rc != SQLITE_OK) {
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(st, 2, (const char *)value, (int)len, SQLITE_TRANSIENT);
  rc = sqlite3_step(st);
  sqlite3_finalize(st);
  return rc == SQLITE_DONE ? ok_rc(sqlrc) : sqlite_fail(sqlrc, rc);
}

/* ---- table_replication map ---- */

void murmur_cfg_table_flags_free(murmur_table_flags_t *f) {
  if (f) {
    for (size_t i = 0; i < f->n; i++) {
      free(f->ents[i].table);
    }
    free(f->ents);
    memset(f, 0, sizeof(*f));
  }
}

static char *ascii_lower(const uint8_t *s, size_t n) {
  char *o = (char *)malloc(n + 1);
  if (!o) {
    return NULL;
  }
  for (size_t i = 0; i < n; i++) {
    uint8_t c = s[i];
    o[i] = (char)(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
  }
  o[n] = '\0';
  return o;
}

static int flags_set(murmur_table_flags_t *f, const uint8_t *k, size_t kn,
                     int enabled) {
  char *low = ascii_lower(k, kn);
  if (!low) {
    return -1;
  }
  for (size_t i = 0; i < f->n; i++) {
    if (strcmp(f->ents[i].table, low) == 0) {
      f->ents[i].enabled = enabled;
      free(low);
      return 0;
    }
  }
  murmur_table_flag_t *ents = (murmur_table_flag_t *)realloc(
      f->ents, (f->n + 1) * sizeof(*ents));
  if (!ents) {
    free(low);
    return -1;
  }
  f->ents = ents;
  f->ents[f->n].table = low;
  f->ents[f->n].enabled = enabled;
  f->n++;
  return 0;
}

int murmur_cfg_table_disabled(const murmur_table_flags_t *f,
                              const uint8_t *table, size_t table_len) {
  char *low = ascii_lower(table, table_len);
  if (!low) {
    return 0;
  }
  int disabled = 0;
  for (size_t i = 0; i < f->n; i++) {
    if (strcmp(f->ents[i].table, low) == 0 && !f->ents[i].enabled) {
      disabled = 1;
      break;
    }
  }
  free(low);
  return disabled;
}

int murmur_cfg_table_filtering(const murmur_table_flags_t *f) {
  for (size_t i = 0; i < f->n; i++) {
    if (!f->ents[i].enabled) {
      return 1;
    }
  }
  return 0;
}

murmur_sync_status_t murmur_cfg_table_flags(sqlite3 *db,
                                            murmur_table_flags_t *f,
                                            int *sqlrc) {
  if (!db || !f) {
    return sqlite_fail(sqlrc, SQLITE_MISUSE);
  }
  memset(f, 0, sizeof(*f));
  char *raw = NULL;
  murmur_sync_status_t st =
      murmur_cfg_setting(db, "table_replication", &raw, sqlrc);
  if (st != MURMUR_SYNC_OK) {
    return st;
  }
  sqlite3_stmt *jt = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT json_type(?)", -1, &jt, NULL);
  if (rc != SQLITE_OK) {
    free(raw);
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(jt, 1, raw, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(jt);
  const uint8_t *type =
      rc == SQLITE_ROW ? sqlite3_column_text(jt, 0) : NULL;
  int is_object = type && strcmp((const char *)type, "object") == 0;
  sqlite3_finalize(jt);
  jt = NULL;
  if (!is_object) {
    free(raw);
    return MURMUR_SYNC_INVALID;
  }
  rc = sqlite3_prepare_v2(db, "SELECT key, type FROM json_each(?)", -1, &jt,
                          NULL);
  if (rc != SQLITE_OK) {
    free(raw);
    return sqlite_fail(sqlrc, rc);
  }
  sqlite3_bind_text(jt, 1, raw, -1, SQLITE_TRANSIENT);
  murmur_sync_status_t status = MURMUR_SYNC_OK;
  for (;;) {
    rc = sqlite3_step(jt);
    if (rc == SQLITE_DONE) {
      break;
    }
    if (rc != SQLITE_ROW) {
      status = MURMUR_SYNC_INVALID;
      break;
    }
    const uint8_t *jtp = sqlite3_column_text(jt, 1);
    int enabled;
    if (strcmp((const char *)jtp, "true") == 0) {
      enabled = 1;
    } else if (strcmp((const char *)jtp, "false") == 0) {
      enabled = 0;
    } else {
      status = MURMUR_SYNC_INVALID;
      break;
    }
    const uint8_t *jk = sqlite3_column_text(jt, 0);
    int jn = sqlite3_column_bytes(jt, 0);
    if (flags_set(f, jk, (size_t)jn, enabled) != 0) {
      status = sqlite_fail(sqlrc, SQLITE_NOMEM);
      break;
    }
  }
  sqlite3_finalize(jt);
  free(raw);
  if (status != MURMUR_SYNC_OK) {
    murmur_cfg_table_flags_free(f);
    return status;
  }
  return ok_rc(sqlrc);
}
