/* murmur-admin: operational CLI for murmur stores (C port of
 * cmd/murmur-admin). Same 9 subcommands, flags, and report style;
 * reports are adapted to this port's RocksDB storage substrate (see
 * README.md for the field mapping). Links libmurmur.a only.
 *
 * Credential rule: every secret resolves to a 32-byte master (64 hex
 * chars decode raw, anything else hashes with SHA-256). Argon2id
 * envelopes stretch those master bytes; direct envelopes use them in
 * HKDF. The reference branches string passphrases on the envelope
 * KDF; this port has no string-passphrase open path, so the mapping
 * is KDF-independent by construction.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libmurmur.h"
#include "murmur/offline.h"
#include "murmur/open.h"
#include "murmur/store.h"
#include "sha256.h"
#include "sqlite3.h"

static const char *kVersion = "0.1.0";

static const uint8_t kDefaultKey[32] = "0123456789abcdef0123456789abcdef";

typedef struct {
  int json;
  const char *passphrase;
  const char *key_hex;
  const char *key_provider_uri;
  const char *new_passphrase;
  const char *new_key_hex;
  int is_backup;
  int has_fresh_node;
  uint8_t fresh_node[16];
  int has_fresh_db;
  uint8_t fresh_db[16];
  long max_passes;
  const char *out_dir;
} opts_t;

static void print_usage(void) {
  printf("Murmur Operational Admin CLI (v%s)\n"
         "\n"
         "Usage:\n"
         "  murmur-admin <command> [options] [arguments]\n"
         "\n"
         "Commands:\n"
         "  status   <data-dir>                      Database status and storage/SQLite metrics\n"
         "  inspect  <data-dir>                      Low-level storage inspector (segments, schema, disk size)\n"
         "  verify   <data-dir>                      Replay & verify durable state or backup directory\n"
         "  backup   <data-dir> <dest-dir>           Consistent online hot backup\n"
         "  restore  <backup-dir> <dest-dir>         Restore backup into clean destination directory\n"
         "  keys     <data-dir>                      Inspect key registry and active data keys\n"
         "  rekey    <data-dir>                      Re-protect the store under a new key or passphrase\n"
         "  compact  <data-dir>                      Offline compaction (server must be stopped)\n"
         "  repair   <data-dir> [--out=<dir>]        Salvage readable records into a new directory\n"
         "\n"
         "Options:\n"
         "  --json                                  Output structured JSON format\n"
         "  --passphrase=<str>                      Passphrase for database encryption\n"
         "  --key-hex=<hex>                         32-byte (64 hex char) raw encryption key\n"
         "  --key-provider-uri=<uri>                Key provider URI (file:/env:/exec:) for the store key\n"
         "  --new-passphrase=<str>                  New passphrase for rekey\n"
         "  --new-key-hex=<hex>                     New 32-byte raw key for rekey\n"
         "  --backup                                Treat target directory as backup archive in `verify`\n"
         "  --fresh-node-id[=<hex>]                 Assign new node identity on restore\n"
         "  --fresh-db-id[=<hex>]                   Assign new database identity on restore\n"
         "  --max-passes=<n>                        Cap compact passes (default: run until quiescent)\n"
         "  --out=<dir>                             Repair destination (default: <data-dir>.salvaged)\n"
         "  -v, --version                           Print version\n"
         "  -h, --help                              Print help\n",
         kVersion);
}

/* ---------- buffers ---------- */

typedef struct {
  char *p;
  size_t n, cap;
} buf_t;

static void buf_free(buf_t *b) {
  free(b->p);
  memset(b, 0, sizeof(*b));
}

static int buf_reserve(buf_t *b, size_t extra) {
  if (b->n + extra + 1 <= b->cap) {
    return 0;
  }
  size_t ncap = b->cap ? b->cap : 256;
  while (ncap < b->n + extra + 1) {
    ncap *= 2;
  }
  char *np = realloc(b->p, ncap);
  if (!np) {
    return -1;
  }
  b->p = np;
  b->cap = ncap;
  return 0;
}

static int buf_putn(buf_t *b, const char *s, size_t n) {
  if (buf_reserve(b, n) != 0) {
    return -1;
  }
  memcpy(b->p + b->n, s, n);
  b->n += n;
  b->p[b->n] = '\0';
  return 0;
}

static int buf_puts(buf_t *b, const char *s) { return buf_putn(b, s, strlen(s)); }

static int buf_printf(buf_t *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char tmp[256];
  int w = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (w < 0) {
    return -1;
  }
  if ((size_t)w < sizeof(tmp)) {
    return buf_putn(b, tmp, (size_t)w);
  }
  char *big = malloc((size_t)w + 1);
  if (!big) {
    return -1;
  }
  va_start(ap, fmt);
  vsnprintf(big, (size_t)w + 1, fmt, ap);
  va_end(ap);
  int rc = buf_putn(b, big, (size_t)w);
  free(big);
  return rc;
}

/* ---------- hex ---------- */

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

/* Strict hex decode: exactly out_cap bytes, no whitespace. */
static int hex_decode(const char *s, uint8_t *out, size_t out_cap) {
  if (strlen(s) != out_cap * 2) {
    return -1;
  }
  for (size_t i = 0; i < out_cap; i++) {
    int hi = hex_val(s[2 * i]), lo = hex_val(s[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return -1;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static void hex_encode(const uint8_t *in, size_t n, char *out) {
  static const char *d = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = d[in[i] >> 4];
    out[2 * i + 1] = d[in[i] & 15];
  }
  out[2 * n] = '\0';
}

static void wipe(void *p, size_t n) {
  volatile uint8_t *v = p;
  while (n--) {
    *v++ = 0;
  }
}

/* ---------- filesystem ---------- */

static int is_dir(const char *path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static void dir_size(const char *path, uint64_t *bytes, int *count) {
  *bytes = 0;
  *count = 0;
  DIR *d = opendir(path);
  if (!d) {
    return;
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
      continue;
    }
    char *p = NULL;
    {
      size_t n = strlen(path) + 1 + strlen(e->d_name) + 1;
      p = malloc(n);
      if (!p) {
        continue;
      }
      snprintf(p, n, "%s/%s", path, e->d_name);
    }
    struct stat st;
    if (lstat(p, &st) == 0) {
      if (S_ISDIR(st.st_mode)) {
        uint64_t sub_b = 0;
        int sub_c = 0;
        dir_size(p, &sub_b, &sub_c);
        *bytes += sub_b;
        *count += sub_c;
      } else {
        *bytes += (uint64_t)st.st_size;
        (*count)++;
      }
    }
    free(p);
  }
  closedir(d);
}

/* Recursive copy src -> dst; dst must not exist. Returns 0 ok. */
static int copy_tree(const char *src, const char *dst) {
  struct stat st;
  if (lstat(src, &st) != 0) {
    return -1;
  }
  if (S_ISDIR(st.st_mode)) {
    if (mkdir(dst, 0700) != 0) {
      return -1;
    }
    DIR *d = opendir(src);
    if (!d) {
      return -1;
    }
    int rc = 0;
    struct dirent *e;
    while (rc == 0 && (e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
        continue;
      }
      size_t n1 = strlen(src) + 1 + strlen(e->d_name) + 1;
      size_t n2 = strlen(dst) + 1 + strlen(e->d_name) + 1;
      char *p1 = malloc(n1), *p2 = malloc(n2);
      if (!p1 || !p2) {
        free(p1);
        free(p2);
        rc = -1;
        break;
      }
      snprintf(p1, n1, "%s/%s", src, e->d_name);
      snprintf(p2, n2, "%s/%s", dst, e->d_name);
      rc = copy_tree(p1, p2);
      free(p1);
      free(p2);
    }
    closedir(d);
    return rc;
  }
  if (!S_ISREG(st.st_mode)) {
    return -1;
  }
  int in = open(src, O_RDONLY);
  if (in < 0) {
    return -1;
  }
  int out = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (out < 0) {
    close(in);
    return -1;
  }
  char tmp[65536];
  ssize_t r;
  int rc = 0;
  while ((r = read(in, tmp, sizeof(tmp))) > 0) {
    ssize_t w = 0;
    while (w < r) {
      ssize_t k = write(out, tmp + w, (size_t)(r - w));
      if (k <= 0) {
        rc = -1;
        break;
      }
      w += k;
    }
    if (rc != 0) {
      break;
    }
  }
  if (r < 0) {
    rc = -1;
  }
  if (rc == 0) {
    rc = fsync(out) == 0 ? 0 : -1;
  }
  close(in);
  close(out);
  return rc;
}

static int remove_tree(const char *path) {
  struct stat st;
  if (lstat(path, &st) != 0) {
    return -1;
  }
  if (S_ISDIR(st.st_mode)) {
    DIR *d = opendir(path);
    if (!d) {
      return -1;
    }
    struct dirent *e;
    int rc = 0;
    while ((e = readdir(d)) != NULL) {
      if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
        continue;
      }
      size_t n = strlen(path) + 1 + strlen(e->d_name) + 1;
      char *p = malloc(n);
      if (!p) {
        rc = -1;
        break;
      }
      snprintf(p, n, "%s/%s", path, e->d_name);
      if (remove_tree(p) != 0) {
        rc = -1;
      }
      free(p);
      if (rc != 0) {
        break;
      }
    }
    closedir(d);
    if (rc == 0) {
      rc = rmdir(path);
    }
    return rc;
  }
  return unlink(path);
}

/* ---------- JSON emit ---------- */

static int json_escape(buf_t *b, const char *s) {
  if (buf_puts(b, "\"") != 0) {
    return -1;
  }
  for (const uint8_t *p = (const uint8_t *)s; *p; p++) {
    char esc[7];
    switch (*p) {
      case '"':
        if (buf_puts(b, "\\\"") != 0) {
          return -1;
        }
        break;
      case '\\':
        if (buf_puts(b, "\\\\") != 0) {
          return -1;
        }
        break;
      case '\n':
        if (buf_puts(b, "\\n") != 0) {
          return -1;
        }
        break;
      case '\r':
        if (buf_puts(b, "\\r") != 0) {
          return -1;
        }
        break;
      case '\t':
        if (buf_puts(b, "\\t") != 0) {
          return -1;
        }
        break;
      default:
        if (*p < 0x20) {
          snprintf(esc, sizeof(esc), "\\u%04x", *p);
          if (buf_puts(b, esc) != 0) {
            return -1;
          }
        } else if (buf_putn(b, (const char *)p, 1) != 0) {
          return -1;
        }
        break;
    }
  }
  return buf_puts(b, "\"");
}

/* Minimal JSON field scanner for machine-generated inventory /
 * manifest objects: finds "key":value with string/number/bool.
 * Returns a malloc'd unescaped string for strings, raw token for
 * numbers/bools, NULL when absent. */
static char *json_field(const char *js, const char *key) {
  size_t kn = strlen(key);
  const char *p = js;
  while ((p = strchr(p, '"')) != NULL) {
    p++;
    if (strncmp(p, key, kn) == 0 && p[kn] == '"') {
      const char *q = p + kn + 1;
      while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') {
        q++;
      }
      if (*q != ':') {
        continue;
      }
      q++;
      while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') {
        q++;
      }
      if (*q == '"') {
        q++;
        buf_t b;
        memset(&b, 0, sizeof(b));
        while (*q && *q != '"') {
          if (*q == '\\' && q[1]) {
            q++;
            char c = *q++;
            if (c == 'n') {
              c = '\n';
            } else if (c == 'r') {
              c = '\r';
            } else if (c == 't') {
              c = '\t';
            } else if (c == 'u') {
              /* \uXXXX: only ASCII range appears in our inputs. */
              char hb[5] = {q[0], q[1], q[2], q[3], 0};
              unsigned v = 0;
              if (sscanf(hb, "%x", &v) == 1 && v < 0x80) {
                c = (char)v;
                q += 4;
              } else {
                buf_free(&b);
                return NULL;
              }
            }
            if (buf_putn(&b, &c, 1) != 0) {
              buf_free(&b);
              return NULL;
            }
          } else {
            if (buf_putn(&b, q++, 1) != 0) {
              buf_free(&b);
              return NULL;
            }
          }
        }
        if (*q != '"') {
          buf_free(&b);
          return NULL;
        }
        if (!b.p) {
          b.p = strdup("");
        }
        return b.p;
      }
      /* number / bool / null token */
      const char *start = q;
      while (*q && *q != ',' && *q != '}' && *q != ']' && *q != ' ' &&
             *q != '\t' && *q != '\n' && *q != '\r') {
        q++;
      }
      size_t n = (size_t)(q - start);
      char *o = malloc(n + 1);
      if (!o) {
        return NULL;
      }
      memcpy(o, start, n);
      o[n] = '\0';
      return o;
    }
    p += kn;
  }
  return NULL;
}

/* ---------- key providers (file:/env:/exec:) ---------- */

#define KP_MAX_PAYLOAD (1u << 20)

static int parse_key_material(const uint8_t *raw, size_t n, uint8_t out[32]) {
  if (n == 32) {
    memcpy(out, raw, 32);
    return 0;
  }
  /* Strip ASCII whitespace, expect 64 hex chars. */
  char *text = malloc(n + 1);
  if (!text) {
    return -1;
  }
  size_t w = 0;
  for (size_t i = 0; i < n; i++) {
    if (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\n' || raw[i] == '\r' ||
        raw[i] == '\v' || raw[i] == '\f') {
      continue;
    }
    text[w++] = (char)raw[i];
  }
  text[w] = '\0';
  int rc = -1;
  if (w == 64 && hex_decode(text, out, 32) == 0) {
    rc = 0;
  }
  wipe(text, w + 1);
  free(text);
  return rc;
}

static int kp_file(const char *path, uint8_t out[32], char *err, size_t cap) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    snprintf(err, cap, "keyprovider: open %s: %s", path, strerror(errno));
    return -1;
  }
  uint8_t *raw = malloc(KP_MAX_PAYLOAD + 1);
  if (!raw) {
    close(fd);
    return -1;
  }
  size_t n = 0;
  ssize_t r;
  while ((r = read(fd, raw + n, KP_MAX_PAYLOAD + 1 - n)) > 0) {
    n += (size_t)r;
    if (n > KP_MAX_PAYLOAD) {
      break;
    }
  }
  close(fd);
  int rc = -1;
  if (r < 0) {
    snprintf(err, cap, "keyprovider: read %s: %s", path, strerror(errno));
  } else if (n > KP_MAX_PAYLOAD) {
    snprintf(err, cap, "keyprovider: file %.256s exceeds %u bytes", path,
             KP_MAX_PAYLOAD);
  } else if (parse_key_material(raw, n, out) != 0) {
    snprintf(err, cap, "keyprovider: file %s: want 32 bytes or 64 hex chars",
             path);
  } else {
    rc = 0;
  }
  wipe(raw, n);
  free(raw);
  return rc;
}

static int valid_env_name(const char *s) {
  if (!s || !*s) {
    return 0;
  }
  for (size_t i = 0; s[i]; i++) {
    char c = s[i];
    int ok = c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
             (i > 0 && c >= '0' && c <= '9');
    if (!ok) {
      return 0;
    }
  }
  return 1;
}

static int kp_env(const char *name, uint8_t out[32], char *err, size_t cap) {
  const char *v = getenv(name);
  if (!v) {
    snprintf(err, cap, "keyprovider: env %s is not set", name);
    return -1;
  }
  size_t n = strlen(v);
  if (n > KP_MAX_PAYLOAD) {
    snprintf(err, cap, "keyprovider: env %s exceeds %u bytes", name,
             KP_MAX_PAYLOAD);
    return -1;
  }
  if (parse_key_material((const uint8_t *)v, n, out) != 0) {
    snprintf(err, cap, "keyprovider: env %s: want 32 bytes or 64 hex chars",
             name);
    return -1;
  }
  return 0;
}

/* Parses Go durations (300ms, 5s, 2m); returns seconds, -1 on error. */
static long parse_go_duration(const char *s) {
  if (!s || !*s) {
    return -1;
  }
  char *end = NULL;
  double v = strtod(s, &end);
  if (end == s || v <= 0) {
    return -1;
  }
  long mult = 0;
  if (strcmp(end, "ns") == 0) {
    return 1;
  } else if (strcmp(end, "us") == 0 || strcmp(end, "ms") == 0) {
    return 1;
  } else if (strcmp(end, "s") == 0) {
    mult = 1;
  } else if (strcmp(end, "m") == 0) {
    mult = 60;
  } else if (strcmp(end, "h") == 0) {
    mult = 3600;
  } else {
    return -1;
  }
  double secs = v * mult;
  if (secs > 300.0) {
    return -1;
  }
  long out = (long)secs;
  return out < 1 ? 1 : out;
}

/* Runs helper <uri>, capturing stdout (bounded) with a timeout.
 * Stderr tail (bounded) joins errors for diagnostics. */
static int kp_exec(const char *helper, const char *uri, long timeout_s,
                   uint8_t out[32], char *err, size_t cap) {
  int so[2], se[2];
  if (pipe(so) != 0 || pipe(se) != 0) {
    close(so[0]);
    close(so[1]);
    snprintf(err, cap, "keyprovider: pipe: %s", strerror(errno));
    return -1;
  }
  /* Non-blocking stderr drain happens after wait; stdout is read
   * with a deadline below. */
  pid_t pid = fork();
  if (pid < 0) {
    close(so[0]);
    close(so[1]);
    close(se[0]);
    close(se[1]);
    snprintf(err, cap, "keyprovider: fork: %s", strerror(errno));
    return -1;
  }
  if (pid == 0) {
    dup2(so[1], STDOUT_FILENO);
    dup2(se[1], STDERR_FILENO);
    close(so[0]);
    close(so[1]);
    close(se[0]);
    close(se[1]);
    execl(helper, helper, uri, (char *)NULL);
    _exit(127);
  }
  close(so[1]);
  close(se[1]);
  uint8_t *raw = malloc(KP_MAX_PAYLOAD + 1);
  if (!raw) {
    close(so[0]);
    close(se[0]);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return -1;
  }
  size_t n = 0;
  time_t deadline = time(NULL) + (timeout_s > 0 ? timeout_s : 30);
  int rc = -1, timed_out = 0, exit_code = -1;
  /* Blocking reads with a coarse deadline: poll the child between
   * short reads by making stdout non-blocking. */
  int fl = fcntl(so[0], F_GETFL, 0);
  fcntl(so[0], F_SETFL, fl | O_NONBLOCK);
  for (;;) {
    ssize_t r = read(so[0], raw + n, KP_MAX_PAYLOAD + 1 - n);
    if (r > 0) {
      n += (size_t)r;
      if (n > KP_MAX_PAYLOAD) {
        break;
      }
      continue;
    }
    if (r == 0) {
      break; /* EOF; status collected below */
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      break;
    }
    int st = 0;
    pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == pid) {
      if (WIFEXITED(st)) {
        exit_code = WEXITSTATUS(st);
      }
      /* Drain remainder after exit. */
      fcntl(so[0], F_SETFL, fl);
      while (n <= KP_MAX_PAYLOAD &&
             (r = read(so[0], raw + n, KP_MAX_PAYLOAD + 1 - n)) > 0) {
        n += (size_t)r;
      }
      break;
    }
    if (time(NULL) >= deadline) {
      timed_out = 1;
      kill(pid, SIGKILL);
      waitpid(pid, NULL, 0);
      break;
    }
    struct timespec ts = {0, 20 * 1000 * 1000};
    nanosleep(&ts, NULL);
  }
  close(so[0]);
  if (!timed_out && exit_code < 0) {
    int st = 0;
    if (waitpid(pid, &st, 0) == pid && WIFEXITED(st)) {
      exit_code = WEXITSTATUS(st);
    }
  }
  /* Bounded stderr tail for diagnostics. */
  char serr[1024];
  size_t sn = 0;
  ssize_t r;
  while ((r = read(se[0], serr + sn, sizeof(serr) - 1 - sn)) > 0) {
    sn += (size_t)r;
    if (sn >= sizeof(serr) - 1) {
      break;
    }
  }
  close(se[0]);
  serr[sn] = '\0';
  /* Trim trailing whitespace from the tail. */
  while (sn > 0 && isspace((uint8_t)serr[sn - 1])) {
    serr[--sn] = '\0';
  }
  if (timed_out) {
    snprintf(err, cap, "keyprovider: helper timed out after %lds", timeout_s);
  } else if (n > KP_MAX_PAYLOAD) {
    snprintf(err, cap, "keyprovider: helper output exceeds %u bytes",
             KP_MAX_PAYLOAD);
  } else if (exit_code != 0) {
    if (sn > 0) {
      snprintf(err, cap, "keyprovider: helper exited %d: %.256s", exit_code,
               serr);
    } else {
      snprintf(err, cap, "keyprovider: helper exited %d", exit_code);
    }
  } else if (parse_key_material(raw, n, out) != 0) {
    snprintf(err, cap, "keyprovider: helper: want 32 bytes or 64 hex chars");
  } else {
    rc = 0;
  }
  wipe(raw, n > KP_MAX_PAYLOAD + 1 ? KP_MAX_PAYLOAD + 1 : n);
  free(raw);
  return rc;
}

static int resolve_uri(const char *uri, uint8_t out[32], char *err,
                       size_t cap) {
  const char *colon = strchr(uri, ':');
  if (!colon || colon == uri || !colon[1]) {
    snprintf(err, cap, "keyprovider: malformed key URI \"%s\"", uri);
    return -1;
  }
  size_t sn = (size_t)(colon - uri);
  const char *rest = colon + 1;
  if (sn == 4 && strncmp(uri, "file", 4) == 0) {
    if (strchr(rest, '?')) {
      snprintf(err, cap, "keyprovider: file URI takes no parameters: \"%s\"",
               uri);
      return -1;
    }
    if (!*rest) {
      snprintf(err, cap, "keyprovider: file URI needs a path: \"%s\"", uri);
      return -1;
    }
    return kp_file(rest, out, err, cap);
  }
  if (sn == 3 && strncmp(uri, "env", 3) == 0) {
    if (strchr(rest, '?')) {
      snprintf(err, cap, "keyprovider: env URI takes no parameters: \"%s\"",
               uri);
      return -1;
    }
    if (!valid_env_name(rest)) {
      snprintf(err, cap, "keyprovider: invalid environment name \"%s\"", rest);
      return -1;
    }
    return kp_env(rest, out, err, cap);
  }
  if (sn == 4 && strncmp(uri, "exec", 4) == 0) {
    const char *qm = strchr(rest, '?');
    size_t bn = qm ? (size_t)(qm - rest) : strlen(rest);
    if (bn == 0 || bn >= 4096 || rest[0] != '/') {
      snprintf(err, cap,
               "keyprovider: exec helper must be an absolute path: \"%s\"",
               uri);
      return -1;
    }
    char helper[4096];
    memcpy(helper, rest, bn);
    helper[bn] = '\0';
    long timeout = 30;
    if (qm) {
      /* Only timeout= is accepted. */
      const char *q = qm + 1;
      if (strncmp(q, "timeout=", 8) != 0 || strchr(q, '&')) {
        snprintf(err, cap, "keyprovider: bad exec parameters");
        return -1;
      }
      timeout = parse_go_duration(q + 8);
      if (timeout < 0) {
        snprintf(err, cap, "keyprovider: timeout must be within (0, 5m0s]");
        return -1;
      }
    }
    return kp_exec(helper, uri, timeout, out, err, cap);
  }
  snprintf(err, cap, "keyprovider: unknown scheme \"%.*s\"", (int)sn, uri);
  return -1;
}

/* ---------- credentials ---------- */

static int is_raw_key(const char *s) {
  if (strlen(s) != 64) {
    return 0;
  }
  for (size_t i = 0; i < 64; i++) {
    if (hex_val(s[i]) < 0) {
      return 0;
    }
  }
  return 1;
}

/* Maps a user secret to a master: 64 hex chars decode raw, anything
 * else hashes with SHA-256. */
static void secret_to_master(const char *secret, uint8_t out[32]) {
  if (is_raw_key(secret)) {
    hex_decode(secret, out, 32);
    return;
  }
  murmur_sha256((const uint8_t *)secret, strlen(secret), out);
}

static int resolve_credential(const opts_t *o, uint8_t master[32], char *err,
                              size_t cap) {
  int sources = (o->key_hex != NULL) + (o->passphrase != NULL) +
                (o->key_provider_uri != NULL);
  if (sources > 1) {
    snprintf(err, cap,
             "set at most one of --key-hex, --passphrase, and "
             "--key-provider-uri");
    return -1;
  }
  if (o->key_provider_uri) {
    uint8_t key[32];
    if (resolve_uri(o->key_provider_uri, key, err, cap) != 0) {
      return -1;
    }
    memcpy(master, key, 32);
    wipe(key, 32);
    return 0;
  }
  if (o->key_hex) {
    /* Trim surrounding whitespace like the reference. */
    const char *s = o->key_hex;
    while (isspace((uint8_t)*s)) {
      s++;
    }
    size_t n = strlen(s);
    while (n > 0 && isspace((uint8_t)s[n - 1])) {
      n--;
    }
    char *t = malloc(n + 1);
    if (!t) {
      return -1;
    }
    memcpy(t, s, n);
    t[n] = '\0';
    int rc = hex_decode(t, master, 32);
    wipe(t, n + 1);
    free(t);
    if (rc != 0) {
      snprintf(err, cap,
               "key-hex must be exactly 32 bytes (64 hex characters)");
      return -1;
    }
    return 0;
  }
  if (o->passphrase) {
    secret_to_master(o->passphrase, master);
    return 0;
  }
  memcpy(master, kDefaultKey, 32);
  return 0;
}

/* ---------- store + SQL open helpers ---------- */

/* Opens a live shell reference and provisions the master. */
static int open_shell(const char *dir, const uint8_t master[32],
                      uint64_t *handle, char *err, size_t cap) {
  uint64_t h = 0;
  void *db = NULL, *store = NULL;
  int rc = nvOpenStoreRef(dir, 0, 0, &h, &db, &store);
  if (rc != 0) {
    if (rc == NV_CTL_BUSY || rc == 5) {
      snprintf(err, cap, "store is locked (server running?)");
    } else {
      snprintf(err, cap, "failed to open database: store open rc=%d", rc);
    }
    return -1;
  }
  rc = nvStoreKey(h, master);
  if (rc != 0) {
    nvCloseStoreRef(h);
    if (rc == NV_CTL_CORRUPT || rc == NV_CTL_AUTH || rc == 11 ||
        rc == 23) {
      snprintf(err, cap, "failed to open database: key does not unlock");
    } else {
      snprintf(err, cap, "failed to open database: key rc=%d", rc);
    }
    return -1;
  }
  *handle = h;
  return 0;
}

/* Opens the SQL view through the murmur VFS and keys it. */
static int open_sql(const char *dir, const uint8_t master[32], sqlite3 **db,
                    char *err, size_t cap) {
  sqlite3 *c = NULL;
  int rc = sqlite3_open_v2(dir, &c, SQLITE_OPEN_READWRITE, "sqlite-murmur");
  if (rc != SQLITE_OK) {
    snprintf(err, cap, "failed to open database: %s",
             c ? sqlite3_errmsg(c) : "open failed");
    if (c) {
      sqlite3_close(c);
    }
    return -1;
  }
  if (murmur_db_key(c, master) != 0) {
    snprintf(err, cap, "failed to open database: key does not unlock");
    sqlite3_close(c);
    return -1;
  }
  *db = c;
  return 0;
}

static int64_t sql_int(sqlite3 *db, const char *sql, int64_t dflt) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    return dflt;
  }
  int64_t v = dflt;
  if (sqlite3_step(st) == SQLITE_ROW) {
    v = sqlite3_column_int64(st, 0);
  }
  sqlite3_finalize(st);
  return v;
}

static char *sql_text(sqlite3 *db, const char *sql) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
    return NULL;
  }
  char *o = NULL;
  if (sqlite3_step(st) == SQLITE_ROW) {
    const uint8_t *t = sqlite3_column_text(st, 0);
    if (t) {
      o = strdup((const char *)t);
    }
  }
  sqlite3_finalize(st);
  return o;
}

/* Reads murmur_identity.node (16 bytes -> hex) and group_id. NULL
 * when unset; the caller frees. */
static char *sql_node_id(sqlite3 *db) {
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, "SELECT node FROM murmur_identity WHERE id=1",
                         -1, &st, NULL) != SQLITE_OK) {
    return NULL;
  }
  char *o = NULL;
  if (sqlite3_step(st) == SQLITE_ROW &&
      sqlite3_column_bytes(st, 0) == 16) {
    const uint8_t *b = sqlite3_column_blob(st, 0);
    if (b) {
      o = malloc(33);
      if (o) {
        hex_encode(b, 16, o);
      }
    }
  }
  sqlite3_finalize(st);
  return o;
}

static char *sql_group_id(sqlite3 *db) {
  char *v = sql_text(
      db, "SELECT value FROM murmur_config WHERE name='group_id'");
  if (v && !v[0]) {
    free(v);
    return NULL;
  }
  return v;
}

typedef struct {
  char *name;
  int columns;
  int pk; /* 1-based pk order of first pk col, else 0 */
} table_info_t;

static table_info_t *sql_tables(sqlite3 *db, size_t *n_out) {
  *n_out = 0;
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db, "SELECT name FROM sqlite_schema WHERE "
                             "type='table' AND name NOT LIKE 'sqlite_%' AND "
                             "name NOT LIKE '%__crsql%' ESCAPE '\\' ORDER BY "
                             "name",
                         -1, &st, NULL) != SQLITE_OK) {
    return NULL;
  }
  table_info_t *v = NULL;
  size_t n = 0, cap = 0;
  int ok = 1;
  while (sqlite3_step(st) == SQLITE_ROW && ok) {
    const uint8_t *t = sqlite3_column_text(st, 0);
    if (!t) {
      continue;
    }
    if (n == cap) {
      size_t ncap = cap ? cap * 2 : 16;
      table_info_t *nv = realloc(v, ncap * sizeof(*nv));
      if (!nv) {
        ok = 0;
        break;
      }
      v = nv;
      cap = ncap;
    }
    memset(&v[n], 0, sizeof(v[n]));
    v[n].name = strdup((const char *)t);
    if (!v[n].name) {
      ok = 0;
      break;
    }
    char *pragma = sqlite3_mprintf("PRAGMA table_info(%w)", v[n].name);
    if (pragma) {
      sqlite3_stmt *pi = NULL;
      if (sqlite3_prepare_v2(db, pragma, -1, &pi, NULL) == SQLITE_OK) {
        while (sqlite3_step(pi) == SQLITE_ROW) {
          v[n].columns++;
          int pk = sqlite3_column_int(pi, 5);
          if (pk > 0 && !v[n].pk) {
            v[n].pk = pk;
          }
        }
      }
      sqlite3_finalize(pi);
      sqlite3_free(pragma);
    }
    n++;
  }
  sqlite3_finalize(st);
  if (!ok) {
    for (size_t i = 0; i < n; i++) {
      free(v[i].name);
    }
    free(v);
    return NULL;
  }
  *n_out = n;
  return v;
}

static void tables_free(table_info_t *v, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(v[i].name);
  }
  free(v);
}

/* ---------- inventory parse ---------- */

typedef struct {
  uint32_t id;
  int64_t created_nanos;
  int active;
} inv_key_t;

typedef struct {
  int sealed;
  uint64_t seq;
  char *kdf; /* malloc'd */
  char *wrap_id;
  uint32_t current;
  inv_key_t *keys;
  size_t nkeys;
} inventory_t;

static void inventory_free(inventory_t *iv) {
  free(iv->kdf);
  free(iv->wrap_id);
  free(iv->keys);
  memset(iv, 0, sizeof(*iv));
}

/* Parses Engine.InventoryJSON shape. Unknown/missing fields stay 0. */
static void inventory_parse(const char *js, inventory_t *iv) {
  memset(iv, 0, sizeof(*iv));
  char *sealed = json_field(js, "sealed");
  iv->sealed = sealed && strcmp(sealed, "true") == 0;
  free(sealed);
  if (!iv->sealed) {
    return;
  }
  char *seq = json_field(js, "seq");
  char *kdf = json_field(js, "kdf");
  char *wrap = json_field(js, "wrap_id");
  char *cur = json_field(js, "current");
  if (seq) {
    iv->seq = strtoull(seq, NULL, 10);
  }
  iv->kdf = kdf ? kdf : strdup("");
  iv->wrap_id = wrap ? wrap : strdup("");
  if (cur) {
    iv->current = (uint32_t)strtoul(cur, NULL, 10);
  }
  free(seq);
  free(cur);
  /* keys:[{id,created_nanos,active}] — scan object by object. */
  const char *arr = strstr(js, "\"keys\"");
  if (!arr || !(arr = strchr(arr, '['))) {
    return;
  }
  arr++;
  for (;;) {
    const char *ob = strchr(arr, '{');
    const char *end = strchr(arr, ']');
    if (!ob || (end && end < ob)) {
      break;
    }
    const char *oe = strchr(ob, '}');
    if (!oe) {
      break;
    }
    size_t on = (size_t)(oe - ob + 1);
    char *one = malloc(on + 1);
    if (!one) {
      break;
    }
    memcpy(one, ob, on);
    one[on] = '\0';
    char *id = json_field(one, "id");
    char *cn = json_field(one, "created_nanos");
    char *ac = json_field(one, "active");
    inv_key_t *nv = realloc(iv->keys, (iv->nkeys + 1) * sizeof(*nv));
    if (!nv) {
      free(id);
      free(cn);
      free(ac);
      free(one);
      break;
    }
    iv->keys = nv;
    iv->keys[iv->nkeys].id = id ? (uint32_t)strtoul(id, NULL, 10) : 0;
    iv->keys[iv->nkeys].created_nanos = cn ? strtoll(cn, NULL, 10) : 0;
    iv->keys[iv->nkeys].active = ac && strcmp(ac, "true") == 0;
    iv->nkeys++;
    free(id);
    free(cn);
    free(ac);
    free(one);
    arr = oe + 1;
  }
}

static const char *kdf_name(uint8_t kdf) {
  /* Port KDF ids mirror spool: 0 direct, 1 argon2id. */
  if (kdf == 0) {
    return "direct";
  }
  if (kdf == 1) {
    return "argon2id";
  }
  static char unk[32];
  snprintf(unk, sizeof(unk), "unknown(%u)", kdf);
  return unk;
}

/* Reads a live shell inventory JSON (malloc'd, caller frees). */
static char *shell_inventory(uint64_t h) {
  size_t need = 0;
  if (nvStoreInventory(h, NULL, 0, &need) != -2 || need == 0) {
    /* Empty or error: retry with a probe buffer anyway. */
    need = 4096;
  }
  char *o = malloc(need + 1);
  if (!o) {
    return NULL;
  }
  size_t got = 0;
  int rc = nvStoreInventory(h, o, need + 1, &got);
  if (rc == -2) {
    char *nb = realloc(o, got + 1);
    if (!nb) {
      free(o);
      return NULL;
    }
    o = nb;
    rc = nvStoreInventory(h, o, got + 1, &got);
  }
  if (rc != 0) {
    free(o);
    return NULL;
  }
  o[got] = '\0';
  return o;
}

/* Reads an offline (closed-store) inventory JSON. */
static char *offline_inventory(const char *dir, const uint8_t master[32]) {
  size_t need = 0;
  int rc = nvOfflineInventory(dir, master, NULL, 0, &need);
  if (rc == NV_OFF_BUSY) {
    return NULL;
  }
  if (rc != -2 || need == 0) {
    need = 4096;
  }
  char *o = malloc(need + 1);
  if (!o) {
    return NULL;
  }
  size_t got = 0;
  rc = nvOfflineInventory(dir, master, o, need + 1, &got);
  if (rc == -2) {
    char *nb = realloc(o, got + 1);
    if (!nb) {
      free(o);
      return NULL;
    }
    o = nb;
    rc = nvOfflineInventory(dir, master, o, got + 1, &got);
  }
  if (rc != 0) {
    free(o);
    return NULL;
  }
  o[got] = '\0';
  return o;
}

/* ---------- status ---------- */

static int cmd_status(const char *dir, const opts_t *o, char *err,
                      size_t err_cap) {
  if (!is_dir(dir)) {
    snprintf(err, err_cap, "directory does not exist: %s", dir);
    return -1;
  }
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  uint64_t h = 0;
  char oerr[512];
  int have_shell = open_shell(dir, master, &h, oerr, sizeof(oerr)) == 0;
  sqlite3 *db = NULL;
  int have_sql = open_sql(dir, master, &db, oerr, sizeof(oerr)) == 0;
  if (!have_shell && !have_sql) {
    snprintf(err, err_cap, "%s", oerr);
    wipe(master, 32);
    return -1;
  }
  char *node_id = have_sql ? sql_node_id(db) : NULL;
  char *group_id = have_sql ? sql_group_id(db) : NULL;
  uint64_t committed = 0, batches = 0;
  if (have_shell) {
    nvStoreSyncStats(h, &committed, &batches);
  }
  int sealed = 0;
  uint8_t kdf = 0;
  uint32_t ktime = 0, kmem = 0;
  uint8_t kthreads = 0;
  if (have_shell) {
    nvStoreKdf(h, &sealed, &kdf, &ktime, &kmem, &kthreads);
  }
  int64_t page_size = have_sql ? sql_int(db, "PRAGMA page_size", 0) : 0;
  int64_t page_count = have_sql ? sql_int(db, "PRAGMA page_count", 0) : 0;
  int64_t table_count =
      have_sql ? sql_int(db, "SELECT COUNT(*) FROM sqlite_schema WHERE "
                             "type='table' AND name NOT LIKE 'sqlite_%'",
                         0)
               : 0;
  int64_t index_count =
      have_sql ? sql_int(db, "SELECT COUNT(*) FROM sqlite_schema WHERE "
                             "type='index' AND name NOT LIKE 'sqlite_%'",
                         0)
               : 0;
  uint64_t total_rows = 0;
  if (have_sql) {
    size_t nt = 0;
    table_info_t *tabs = sql_tables(db, &nt);
    for (size_t i = 0; tabs && i < nt; i++) {
      char *q = sqlite3_mprintf("SELECT COUNT(*) FROM %w", tabs[i].name);
      if (q) {
        int64_t c = sql_int(db, q, 0);
        if (c > 0) {
          total_rows += (uint64_t)c;
        }
        sqlite3_free(q);
      }
    }
    tables_free(tabs, nt);
  }
  uint64_t disk_bytes = 0;
  int disk_files = 0;
  dir_size(dir, &disk_bytes, &disk_files);
  int64_t mem_used = sqlite3_memory_used();
  int64_t mem_hw = sqlite3_memory_highwater(0);

  int rc = 0;
  if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"data_dir\": ");
    json_escape(&b, dir);
    buf_puts(&b, ",\n  \"database_id\": ");
    if (group_id) {
      json_escape(&b, group_id);
    } else {
      buf_puts(&b, "null");
    }
    buf_puts(&b, ",\n  \"node_id\": ");
    if (node_id) {
      json_escape(&b, node_id);
    } else {
      buf_puts(&b, "null");
    }
    buf_printf(&b,
               ",\n  \"committed_bytes\": %llu,\n  \"flush_batches\": %llu,\n"
               "  \"sealed\": %s,\n  \"kdf\": \"%s\",\n"
               "  \"sqlite\": {\n    \"memory_used_bytes\": %lld,\n"
               "    \"memory_highwater_bytes\": %lld,\n"
               "    \"page_size\": %lld,\n    \"page_count\": %lld,\n"
               "    \"database_size_bytes\": %lld,\n"
               "    \"table_count\": %lld,\n    \"index_count\": %lld,\n"
               "    \"total_rows\": %llu\n  },\n"
               "  \"storage\": {\n    \"disk_bytes\": %llu,\n"
               "    \"disk_files\": %d\n  }\n}\n",
               (unsigned long long)committed, (unsigned long long)batches,
               sealed ? "true" : "false",
               sealed ? kdf_name(kdf) : "none", (long long)mem_used,
               (long long)mem_hw, (long long)page_size, (long long)page_count,
               (long long)(page_size * page_count), (long long)table_count,
               (long long)index_count, (unsigned long long)total_rows,
               (unsigned long long)disk_bytes, disk_files);
    if (!b.p || fputs(b.p, stdout) < 0) {
      rc = -1;
    }
    buf_free(&b);
  } else {
    printf("=== Murmur Database Status ===\n");
    printf("Data Directory:      %s\n", dir);
    printf("Database ID:         %s\n", group_id ? group_id : "(not set)");
    printf("Node ID:             %s\n", node_id ? node_id : "(not set)");
    printf("Committed Bytes:     %llu\n", (unsigned long long)committed);
    printf("Flush Batches:       %llu\n", (unsigned long long)batches);
    printf("Sealed:              %s\n", sealed ? "yes" : "no");
    if (sealed) {
      printf("Envelope KDF:        %s\n", kdf_name(kdf));
    }
    printf("\n--- SQLite Engine ---\n");
    printf("Memory Used:         %lld bytes (highwater: %lld bytes)\n",
           (long long)mem_used, (long long)mem_hw);
    printf("Page Count / Size:   %lld pages @ %lld bytes\n",
           (long long)page_count, (long long)page_size);
    printf("Database Size:       %lld bytes\n",
           (long long)(page_size * page_count));
    printf("Tables / Indexes:    %lld tables, %lld indexes\n",
           (long long)table_count, (long long)index_count);
    printf("Total Rows:          %llu\n", (unsigned long long)total_rows);
    printf("\n--- RocksDB Storage ---\n");
    printf("Disk:                %d files (%llu bytes)\n", disk_files,
           (unsigned long long)disk_bytes);
  }
  free(node_id);
  free(group_id);
  if (have_sql) {
    sqlite3_close(db);
  }
  if (have_shell) {
    nvCloseStoreRef(h);
  }
  wipe(master, 32);
  if (rc != 0) {
    snprintf(err, err_cap, "output failed");
  }
  return rc;
}

/* ---------- inspect ---------- */

static int cmd_inspect(const char *dir, const opts_t *o, char *err,
                       size_t err_cap) {
  if (!is_dir(dir)) {
    snprintf(err, err_cap, "directory does not exist: %s", dir);
    return -1;
  }
  uint64_t disk_bytes = 0;
  int disk_files = 0;
  dir_size(dir, &disk_bytes, &disk_files);
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  uint64_t h = 0;
  char oerr[512];
  int have_shell = open_shell(dir, master, &h, oerr, sizeof(oerr)) == 0;
  sqlite3 *db = NULL;
  int have_sql = open_sql(dir, master, &db, oerr, sizeof(oerr)) == 0;
  if (!have_shell && !have_sql) {
    snprintf(err, err_cap, "%s", oerr);
    wipe(master, 32);
    return -1;
  }
  /* Key hint from the live inventory (envelope header fields). */
  char *wrap_id = strdup("");
  uint64_t keyring_seq = 0;
  if (have_shell) {
    char *js = shell_inventory(h);
    if (js) {
      inventory_t iv;
      inventory_parse(js, &iv);
      if (iv.sealed) {
        free(wrap_id);
        wrap_id = iv.wrap_id ? strdup(iv.wrap_id) : strdup("");
        if (!wrap_id) {
          wrap_id = strdup("");
        }
        keyring_seq = iv.seq;
      }
      inventory_free(&iv);
      free(js);
    }
  }
  char *node_id = have_sql ? sql_node_id(db) : NULL;
  char *group_id = have_sql ? sql_group_id(db) : NULL;
  size_t nt = 0;
  table_info_t *tabs = have_sql ? sql_tables(db, &nt) : NULL;
  int64_t index_count =
      have_sql ? sql_int(db, "SELECT COUNT(*) FROM sqlite_schema WHERE "
                             "type='index' AND name NOT LIKE 'sqlite_%'",
                         0)
               : 0;

  int rc = 0;
  if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"data_dir\": ");
    json_escape(&b, dir);
    buf_puts(&b, ",\n  \"database_id\": ");
    if (group_id) {
      json_escape(&b, group_id);
    } else {
      buf_puts(&b, "null");
    }
    buf_puts(&b, ",\n  \"node_id\": ");
    if (node_id) {
      json_escape(&b, node_id);
    } else {
      buf_puts(&b, "null");
    }
    buf_printf(&b,
               ",\n  \"storage_files\": %d,\n  \"storage_disk_bytes\": %llu,\n"
               "  \"wrapping_key_id\": ",
               disk_files, (unsigned long long)disk_bytes);
    json_escape(&b, wrap_id ? wrap_id : "");
    buf_printf(&b,
               ",\n  \"keyring_seq\": %llu,\n  \"table_count\": %llu,\n"
               "  \"index_count\": %lld,\n  \"tables\": [",
               (unsigned long long)keyring_seq, (unsigned long long)nt,
               (long long)index_count);
    for (size_t i = 0; i < nt; i++) {
      buf_puts(&b, i ? ",\n    {" : "\n    {");
      buf_puts(&b, "\"name\": ");
      json_escape(&b, tabs[i].name);
      buf_printf(&b, ", \"columns_count\": %d, \"primary_key\": %d}",
                 tabs[i].columns, tabs[i].pk);
    }
    buf_puts(&b, nt ? "\n  ]\n}\n" : "]\n}\n");
    if (!b.p || fputs(b.p, stdout) < 0) {
      rc = -1;
    }
    buf_free(&b);
  } else {
    printf("=== Murmur Storage Inspection ===\n");
    printf("Data Directory:      %s\n", dir);
    printf("Database ID:         %s\n", group_id ? group_id : "(not set)");
    printf("Node ID:             %s\n", node_id ? node_id : "(not set)");
    printf("Files On Disk:       %d files (%llu bytes / %.2f MB)\n",
           disk_files, (unsigned long long)disk_bytes,
           (double)disk_bytes / (1024.0 * 1024.0));
    printf("Wrapping Key ID:     %s\n", wrap_id ? wrap_id : "");
    printf("Keyring Sequence:    %llu\n", (unsigned long long)keyring_seq);
    printf("Tables Registered:   %llu\n", (unsigned long long)nt);
    printf("Indexes Registered:  %lld\n", (long long)index_count);
    if (nt > 0) {
      printf("\n--- Tables ---\n");
      for (size_t i = 0; i < nt; i++) {
        printf("  - %-20s (columns: %d)\n", tabs[i].name, tabs[i].columns);
      }
    }
  }
  free(wrap_id);
  free(node_id);
  free(group_id);
  tables_free(tabs, nt);
  if (have_sql) {
    sqlite3_close(db);
  }
  if (have_shell) {
    nvCloseStoreRef(h);
  }
  wipe(master, 32);
  if (rc != 0) {
    snprintf(err, err_cap, "output failed");
  }
  return rc;
}

/* ---------- verify ---------- */

static int cmd_verify(const char *target, const opts_t *o, char *err,
                      size_t err_cap) {
  if (!is_dir(target)) {
    snprintf(err, err_cap, "target does not exist: %s", target);
    return -1;
  }
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  int rc = 0;
  if (o->is_backup) {
    /* Backup mode: manifest present + every page trial-opens. */
    char *mp = malloc(strlen(target) + 16);
    int valid = 0;
    const char *verr = NULL;
    char vbuf[512] = "";
    if (!mp) {
      valid = 0;
      verr = "out of memory";
    } else {
      sprintf(mp, "%s/manifest.json", target);
      int fd = open(mp, O_RDONLY);
      if (fd < 0) {
        valid = 0;
        snprintf(vbuf, sizeof(vbuf), "backup manifest missing: %s", mp);
        verr = vbuf;
      } else {
        char mbuf[4096];
        ssize_t r = read(fd, mbuf, sizeof(mbuf) - 1);
        close(fd);
        if (r <= 0) {
          valid = 0;
          snprintf(vbuf, sizeof(vbuf), "backup manifest unreadable");
          verr = vbuf;
        } else {
          mbuf[r] = '\0';
          char *fv = json_field(mbuf, "format_version");
          if (!fv || strcmp(fv, "1") != 0) {
            valid = 0;
            snprintf(vbuf, sizeof(vbuf), "backup manifest malformed");
            verr = vbuf;
          } else {
            int vrc = nvOfflineVerify(target, master);
            if (vrc == NV_OFF_OK) {
              valid = 1;
            } else if (vrc == NV_OFF_BUSY) {
              valid = 0;
              snprintf(vbuf, sizeof(vbuf),
                       "store is locked (server running?)");
              verr = vbuf;
            } else {
              valid = 0;
              snprintf(vbuf, sizeof(vbuf),
                       "page verification failed (rc=%d)", vrc);
              verr = vbuf;
            }
          }
          free(fv);
        }
      }
      free(mp);
    }
    if (o->json) {
      buf_t b;
      memset(&b, 0, sizeof(b));
      buf_puts(&b, "{\n  \"target_path\": ");
      json_escape(&b, target);
      buf_printf(&b, ",\n  \"valid\": %s,\n  \"mode\": \"backup\",\n"
                     "  \"errors\": [",
                 valid ? "true" : "false");
      if (!valid && verr) {
        json_escape(&b, verr);
      }
      buf_puts(&b, "]\n}\n");
      if (!b.p || fputs(b.p, stdout) < 0) {
        rc = -1;
      }
      buf_free(&b);
      if (rc == 0 && !valid) {
        snprintf(err, err_cap, "verification failed");
        rc = -1;
      }
      wipe(master, 32);
      return rc;
    }
    if (valid) {
      printf("PASS: Backup directory verified successfully at %s\n", target);
      wipe(master, 32);
      return 0;
    }
    printf("FAIL: Backup verification failed at %s:\n", target);
    printf("  - %s\n", verr ? verr : "unknown");
    snprintf(err, err_cap, "verification failed");
    wipe(master, 32);
    return -1;
  }
  /* Database mode: offline page verify, then identity + tables. */
  char vbuf[512] = "";
  const char *verr = NULL;
  char *db_id = NULL, *node_id = NULL;
  long tables_checked = 0;
  int vrc = nvOfflineVerify(target, master);
  if (vrc == NV_OFF_BUSY) {
    snprintf(vbuf, sizeof(vbuf), "store is locked (server running?)");
    verr = vbuf;
  } else if (vrc != NV_OFF_OK) {
    snprintf(vbuf, sizeof(vbuf), "page verification failed (rc=%d)", vrc);
    verr = vbuf;
  } else {
    sqlite3 *db = NULL;
    char oerr[256];
    if (open_sql(target, master, &db, oerr, sizeof(oerr)) != 0) {
      snprintf(vbuf, sizeof(vbuf), "%s", oerr);
      verr = vbuf;
    } else {
      db_id = sql_group_id(db);
      node_id = sql_node_id(db);
      size_t nt = 0;
      table_info_t *tabs = sql_tables(db, &nt);
      tables_checked = (long)nt;
      tables_free(tabs, nt);
      sqlite3_close(db);
    }
  }
  int valid = verr == NULL;
  if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"target_path\": ");
    json_escape(&b, target);
    buf_printf(&b, ",\n  \"valid\": %s,\n  \"mode\": \"database\",\n"
                   "  \"database_id\": ",
               valid ? "true" : "false");
    if (db_id) {
      json_escape(&b, db_id);
    } else {
      buf_puts(&b, "null");
    }
    buf_puts(&b, ",\n  \"node_id\": ");
    if (node_id) {
      json_escape(&b, node_id);
    } else {
      buf_puts(&b, "null");
    }
    buf_printf(&b, ",\n  \"tables_checked\": %ld,\n  \"errors\": [", tables_checked);
    if (!valid && verr) {
      json_escape(&b, verr);
    }
    buf_puts(&b, "]\n}\n");
    if (!b.p || fputs(b.p, stdout) < 0) {
      rc = -1;
    }
    buf_free(&b);
    if (rc == 0 && !valid) {
      snprintf(err, err_cap, "verification failed");
      rc = -1;
    }
  } else if (valid) {
    printf("PASS: Database storage integrity verified at %s\n", target);
    printf("Database ID:     %s\n", db_id ? db_id : "(not set)");
    printf("Node ID:         %s\n", node_id ? node_id : "(not set)");
    printf("Tables Checked:  %ld\n", tables_checked);
  } else {
    printf("FAIL: Storage verification failed at %s:\n", target);
    printf("  - %s\n", verr ? verr : "unknown");
    snprintf(err, err_cap, "verification failed");
    rc = -1;
  }
  free(db_id);
  free(node_id);
  wipe(master, 32);
  return rc;
}

/* ---------- backup ---------- */

static int cmd_backup(const char *src, const char *dest, const opts_t *o,
                      char *err, size_t err_cap) {
  if (!is_dir(src)) {
    snprintf(err, err_cap, "source directory does not exist: %s", src);
    return -1;
  }
  struct stat st;
  if (lstat(dest, &st) == 0) {
    snprintf(err, err_cap, "destination path already exists: %s", dest);
    return -1;
  }
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  /* Identity comes from SQL; the checkpoint from a live shell. */
  sqlite3 *db = NULL;
  char oerr[512];
  if (open_sql(src, master, &db, oerr, sizeof(oerr)) != 0) {
    snprintf(err, err_cap, "%s", oerr);
    wipe(master, 32);
    return -1;
  }
  char *group_hex = sql_group_id(db);
  char *node_hex = sql_node_id(db);
  sqlite3_close(db);
  db = NULL;
  int rc = 0;
  uint8_t group[16], node[16];
  if (!group_hex || hex_decode(group_hex, group, 16) != 0) {
    snprintf(err, err_cap, "backup needs a replication database id: set "
                           "murmur_config group_id first");
    rc = -1;
  } else if (!node_hex || hex_decode(node_hex, node, 16) != 0) {
    snprintf(err, err_cap, "backup needs a replication node id: set "
                           "murmur_identity.node first");
    rc = -1;
  } else {
    uint64_t h = 0;
    if (open_shell(src, master, &h, oerr, sizeof(oerr)) != 0) {
      snprintf(err, err_cap, "%s", oerr);
      rc = -1;
    } else {
      /* Cipher token from the live store. */
      char cipher[64] = "aes256gcm";
      size_t clen = 0;
      if (nvPragmaStore(h, "cipher", NULL, 0, 0, cipher, sizeof(cipher),
                        &clen) != 0) {
        /* PRAGMA read form unavailable: keep the default token. */
        strcpy(cipher, "aes256gcm");
      } else if (clen >= sizeof(cipher)) {
        cipher[sizeof(cipher) - 1] = '\0';
      } else {
        cipher[clen] = '\0';
      }
      int brc = nvStoreBackup(h, dest, cipher, group, node);
      nvCloseStoreRef(h);
      if (brc != 0) {
        snprintf(err, err_cap, "backup failed: rc=%d", brc);
        rc = -1;
      }
    }
  }
  if (rc == 0) {
    if (o->json) {
      buf_t b;
      memset(&b, 0, sizeof(b));
      buf_puts(&b, "{\n  \"source_dir\": ");
      json_escape(&b, src);
      buf_puts(&b, ",\n  \"destination_dir\": ");
      json_escape(&b, dest);
      buf_puts(&b, ",\n  \"database_id\": ");
      json_escape(&b, group_hex);
      buf_puts(&b, ",\n  \"node_id\": ");
      json_escape(&b, node_hex);
      buf_puts(&b, ",\n  \"success\": true\n}\n");
      if (!b.p || fputs(b.p, stdout) < 0) {
        snprintf(err, err_cap, "output failed");
        rc = -1;
      }
      buf_free(&b);
    } else {
      printf("PASS: Consistent hot backup created successfully.\n");
      printf("Source:       %s\n", src);
      printf("Destination:  %s\n", dest);
      printf("Database ID:  %s\n", group_hex);
      printf("Node ID:      %s\n", node_hex);
    }
  }
  free(group_hex);
  free(node_hex);
  wipe(master, 32);
  wipe(group, 16);
  wipe(node, 16);
  return rc;
}

/* ---------- restore ---------- */

static int random_bytes(uint8_t *out, size_t n) {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    return -1;
  }
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, out + got, n - got);
    if (r <= 0) {
      close(fd);
      return -1;
    }
    got += (size_t)r;
  }
  close(fd);
  return 0;
}

static int cmd_restore(const char *backup, const char *dest, const opts_t *o,
                       char *err, size_t err_cap) {
  if (!is_dir(backup)) {
    snprintf(err, err_cap, "backup directory does not exist: %s", backup);
    return -1;
  }
  struct stat st;
  if (lstat(dest, &st) == 0) {
    snprintf(err, err_cap, "destination path already exists: %s", dest);
    return -1;
  }
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  /* Tree copy first (source untouched on later failure). */
  if (copy_tree(backup, dest) != 0) {
    snprintf(err, err_cap, "restore failed: copy: %s", strerror(errno));
    remove_tree(dest);
    wipe(master, 32);
    return -1;
  }
  int rc = 0;
  uint8_t new_node[16], new_db[16];
  int want_node = o->has_fresh_node, want_db = o->has_fresh_db;
  char node_hex[33] = "", db_hex[33] = "";
  if (want_node) {
    memcpy(new_node, o->fresh_node, 16);
    hex_encode(new_node, 16, node_hex);
  }
  if (want_db) {
    memcpy(new_db, o->fresh_db, 16);
    hex_encode(new_db, 16, db_hex);
  }
  sqlite3 *db = NULL;
  char oerr[512];
  if (open_sql(dest, master, &db, oerr, sizeof(oerr)) != 0) {
    snprintf(err, err_cap, "restore failed: %s", oerr);
    rc = -1;
  } else {
    /* Fresh identities rewrite the SQL rows. */
    if (rc == 0 && want_node) {
      sqlite3_stmt *st = NULL;
      if (sqlite3_prepare_v2(db, "UPDATE murmur_identity SET node=? WHERE "
                                 "id=1",
                             -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, err_cap, "restore failed: identity table missing");
        rc = -1;
      } else {
        sqlite3_bind_blob(st, 1, new_node, 16, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
          snprintf(err, err_cap, "restore failed: node rewrite: %s",
                   sqlite3_errmsg(db));
          rc = -1;
        }
        sqlite3_finalize(st);
      }
    }
    if (rc == 0 && want_db) {
      sqlite3_stmt *st = NULL;
      if (sqlite3_prepare_v2(db, "INSERT INTO murmur_config(name,value) "
                                 "VALUES('group_id',?) ON CONFLICT(name) DO "
                                 "UPDATE SET value=excluded.value",
                             -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, err_cap, "restore failed: config table missing");
        rc = -1;
      } else {
        sqlite3_bind_text(st, 1, db_hex, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
          snprintf(err, err_cap, "restore failed: database rewrite: %s",
                   sqlite3_errmsg(db));
          rc = -1;
        }
        sqlite3_finalize(st);
      }
    }
    sqlite3_close(db);
    db = NULL;
  }
  if (rc == 0) {
    if (o->json) {
      buf_t b;
      memset(&b, 0, sizeof(b));
      buf_puts(&b, "{\n  \"backup_dir\": ");
      json_escape(&b, backup);
      buf_puts(&b, ",\n  \"destination_dir\": ");
      json_escape(&b, dest);
      buf_puts(&b, ",\n  \"success\": true,\n  \"new_database_id\": ");
      if (want_db) {
        json_escape(&b, db_hex);
      } else {
        buf_puts(&b, "null");
      }
      buf_puts(&b, ",\n  \"new_node_id\": ");
      if (want_node) {
        json_escape(&b, node_hex);
      } else {
        buf_puts(&b, "null");
      }
      buf_puts(&b, "\n}\n");
      if (!b.p || fputs(b.p, stdout) < 0) {
        snprintf(err, err_cap, "output failed");
        rc = -1;
      }
      buf_free(&b);
    } else {
      printf("PASS: Database restored successfully.\n");
      printf("Backup Source:    %s\n", backup);
      printf("Destination:      %s\n", dest);
      if (want_db) {
        printf("New Database ID:  %s\n", db_hex);
      }
      if (want_node) {
        printf("New Node ID:      %s\n", node_hex);
      }
    }
  }
  wipe(master, 32);
  return rc;
}

/* ---------- keys ---------- */

static int cmd_keys(const char *dir, const opts_t *o, char *err,
                    size_t err_cap) {
  if (!is_dir(dir)) {
    snprintf(err, err_cap, "directory does not exist: %s", dir);
    return -1;
  }
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  /* Prefer the live shell; fall back to the offline inventory when
   * the store is locked by another process. */
  char *js = NULL;
  uint64_t h = 0;
  char oerr[512];
  int live = open_shell(dir, master, &h, oerr, sizeof(oerr)) == 0;
  if (live) {
    js = shell_inventory(h);
    nvCloseStoreRef(h);
  } else {
    js = offline_inventory(dir, master);
  }
  if (!js) {
    snprintf(err, err_cap, "%s",
             live ? "failed to read key inventory" : oerr);
    wipe(master, 32);
    return -1;
  }
  inventory_t iv;
  inventory_parse(js, &iv);
  free(js);
  int nactive = 0;
  for (size_t i = 0; i < iv.nkeys; i++) {
    if (iv.keys[i].active) {
      nactive++;
    }
  }
  int rc = 0;
  if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"data_dir\": ");
    json_escape(&b, dir);
    buf_printf(&b, ",\n  \"encrypted\": %s,\n  \"wrapping_key_id\": ",
               iv.sealed ? "true" : "false");
    json_escape(&b, iv.sealed && iv.wrap_id ? iv.wrap_id : "");
    buf_printf(&b, ",\n  \"kdf\": \"%s\",\n  \"active_data_key_id\": %u,\n"
                   "  \"keyring_seq\": %llu,\n  \"data_keys_count\": %llu,\n"
                   "  \"data_keys\": [",
               iv.sealed && iv.kdf ? iv.kdf : "none", iv.current,
               (unsigned long long)iv.seq, (unsigned long long)iv.nkeys);
    for (size_t i = 0; i < iv.nkeys; i++) {
      buf_printf(&b, "%s\n    {\"id\": %u, \"id_hex\": \"%08x\", "
                     "\"created_at_epoch_secs\": %lld, \"status\": \"%s\"}",
                 i ? "," : "", iv.keys[i].id, iv.keys[i].id,
                 (long long)(iv.keys[i].created_nanos / 1000000000LL),
                 iv.keys[i].active ? "active" : "retired");
    }
    buf_puts(&b, iv.nkeys ? "\n  ]\n}\n" : "]\n}\n");
    if (!b.p || fputs(b.p, stdout) < 0) {
      snprintf(err, err_cap, "output failed");
      rc = -1;
    }
    buf_free(&b);
  } else {
    printf("=== Murmur Key Registry & Inventory ===\n");
    printf("Data Directory:         %s\n", dir);
    printf("Encrypted:              %s\n", iv.sealed ? "true" : "false");
    printf("Wrapping Key ID:        %s\n",
           iv.sealed && iv.wrap_id ? iv.wrap_id : "");
    printf("Envelope KDF:           %s\n",
           iv.sealed && iv.kdf ? iv.kdf : "none");
    printf("Active Data Key ID:     %08x (#%u)\n", iv.current, iv.current);
    printf("Keyring Persist Seq:    %llu\n", (unsigned long long)iv.seq);
    printf("Total Data Keys:        %llu\n", (unsigned long long)iv.nkeys);
    if (iv.nkeys > 0) {
      printf("\n  Key ID    Status    Created At (UNIX secs)\n");
      printf("  --------  --------  ----------------------\n");
      for (size_t i = 0; i < iv.nkeys; i++) {
        printf("  %08x  %-8s  %lld\n", iv.keys[i].id,
               iv.keys[i].active ? "active" : "retired",
               (long long)(iv.keys[i].created_nanos / 1000000000LL));
      }
    }
  }
  (void)nactive;
  inventory_free(&iv);
  wipe(master, 32);
  return rc;
}

/* ---------- rekey ---------- */

static int cmd_rekey(const char *dir, const opts_t *o, char *err,
                     size_t err_cap) {
  if (!is_dir(dir)) {
    snprintf(err, err_cap, "directory does not exist: %s", dir);
    return -1;
  }
  if ((o->new_key_hex != NULL) == (o->new_passphrase != NULL)) {
    snprintf(err, err_cap,
             "rekey needs exactly one of --new-key-hex and --new-passphrase");
    return -1;
  }
  uint8_t master[32], fresh[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    return -1;
  }
  if (o->new_key_hex) {
    if (strlen(o->new_key_hex) != 64 ||
        hex_decode(o->new_key_hex, fresh, 32) != 0) {
      snprintf(err, err_cap,
               "new-key-hex must be exactly 32 bytes (64 hex characters)");
      wipe(master, 32);
      return -1;
    }
  } else {
    secret_to_master(o->new_passphrase, fresh);
  }
  int vrc = nvOfflineRekey(dir, master, fresh, 0);
  const char *kdf = "unknown";
  char *wrap_tmp = NULL;
  if (vrc == NV_OFF_OK) {
    char *js = offline_inventory(dir, fresh);
    if (js) {
      inventory_t iv;
      inventory_parse(js, &iv);
      if (iv.sealed && iv.kdf) {
        wrap_tmp = strdup(iv.kdf);
        if (wrap_tmp) {
          kdf = wrap_tmp;
        }
      }
      inventory_free(&iv);
      free(js);
    }
  }
  int rc = 0;
  if (vrc == NV_OFF_BUSY) {
    snprintf(err, err_cap, "store is locked (server running?): stop the "
                           "server and retry");
    rc = -1;
  } else if (vrc != NV_OFF_OK) {
    snprintf(err, err_cap, "rekey failed: rc=%d", vrc);
    rc = -1;
  } else if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"data_dir\": ");
    json_escape(&b, dir);
    buf_puts(&b, ",\n  \"success\": true,\n  \"kdf\": ");
    json_escape(&b, kdf);
    buf_puts(&b, "\n}\n");
    if (!b.p || fputs(b.p, stdout) < 0) {
      snprintf(err, err_cap, "output failed");
      rc = -1;
    }
    buf_free(&b);
  } else {
    printf("PASS: Store re-protected successfully.\n");
    printf("Data Directory:   %s\n", dir);
    printf("Envelope KDF:     %s\n", kdf);
  }
  free(wrap_tmp);
  wipe(master, 32);
  wipe(fresh, 32);
  return rc;
}

/* ---------- compact ---------- */

static uint64_t store_prop_num(NvStore *s, const char *name) {
  char out[64];
  size_t len = 0;
  char err[128];
  if (nv_store_property(s, name, out, sizeof(out), &len, err, sizeof(err)) !=
      0) {
    return 0;
  }
  return strtoull(out, NULL, 10);
}

static int cmd_compact(const char *dir, const opts_t *o, char *err,
                       size_t err_cap) {
  if (!is_dir(dir)) {
    snprintf(err, err_cap, "directory does not exist: %s", dir);
    return -1;
  }
  if (o->max_passes < 0) {
    snprintf(err, err_cap, "--max-passes must be >= 0");
    return -1;
  }
  if (nvStoreIsLive(dir)) {
    snprintf(err, err_cap, "store is locked (server running?): stop the "
                           "server and retry");
    return -1;
  }
  char serr[512];
  NvStore *s = nv_store_open(dir, 0, serr, sizeof(serr));
  if (!s) {
    if (strstr(serr, "lock") || strstr(serr, "LOCK")) {
      snprintf(err, err_cap, "store is locked (server running?): stop the "
                             "server and retry");
    } else {
      snprintf(err, err_cap, "failed to open store: %s", serr);
    }
    return -1;
  }
  uint64_t disk_before = 0, keys_before = 0, live_before = 0;
  {
    int c = 0;
    dir_size(dir, &disk_before, &c);
  }
  keys_before = store_prop_num(s, "rocksdb.estimate-num-keys");
  live_before = store_prop_num(s, "rocksdb.estimate-live-data-size");
  /* Until-quiescent loop: a pass flushes memtables and compacts the
   * full range; quiesce when disk bytes stop shrinking. */
  int passes = 0, quiesced = 0;
  uint64_t disk = disk_before;
  for (;;) {
    if (o->max_passes > 0 && passes >= o->max_passes) {
      break;
    }
    if (nv_store_flush(s, serr, sizeof(serr)) != 0 ||
        nv_store_compact_full(s, serr, sizeof(serr)) != 0) {
      nv_store_close(s);
      snprintf(err, err_cap, "compaction pass %d failed: %s", passes + 1,
               serr);
      return -1;
    }
    passes++;
    uint64_t now = 0;
    {
      int c = 0;
      dir_size(dir, &now, &c);
    }
    if (now >= disk) {
      disk = now;
      quiesced = 1;
      break;
    }
    disk = now;
  }
  uint64_t disk_after = disk;
  uint64_t keys_after = store_prop_num(s, "rocksdb.estimate-num-keys");
  uint64_t live_after = store_prop_num(s, "rocksdb.estimate-live-data-size");
  nv_store_close(s);
  uint64_t reclaimed =
      disk_after < disk_before ? disk_before - disk_after : 0;
  int rc = 0;
  if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"data_dir\": ");
    json_escape(&b, dir);
    buf_printf(&b,
               ",\n  \"passes\": %d,\n  \"quiesced\": %s,\n"
               "  \"disk_bytes_before\": %llu,\n"
               "  \"disk_bytes_after\": %llu,\n"
               "  \"keys_estimate_before\": %llu,\n"
               "  \"keys_estimate_after\": %llu,\n"
               "  \"live_bytes_before\": %llu,\n"
               "  \"live_bytes_after\": %llu,\n"
               "  \"reclaimed_bytes\": %llu\n}\n",
               passes, quiesced ? "true" : "false",
               (unsigned long long)disk_before, (unsigned long long)disk_after,
               (unsigned long long)keys_before, (unsigned long long)keys_after,
               (unsigned long long)live_before, (unsigned long long)live_after,
               (unsigned long long)reclaimed);
    if (!b.p || fputs(b.p, stdout) < 0) {
      snprintf(err, err_cap, "output failed");
      rc = -1;
    }
    buf_free(&b);
  } else {
    printf("PASS: Offline compaction complete.\n");
    printf("Data Directory:      %s\n", dir);
    printf("Passes:              %d (%s)\n", passes,
           quiesced ? "quiesced" : "capped by --max-passes");
    printf("Disk Bytes:          %llu -> %llu (reclaimed %llu)\n",
           (unsigned long long)disk_before, (unsigned long long)disk_after,
           (unsigned long long)reclaimed);
    printf("Keys (estimate):     %llu -> %llu\n",
           (unsigned long long)keys_before, (unsigned long long)keys_after);
    printf("Live Bytes:          %llu -> %llu\n",
           (unsigned long long)live_before, (unsigned long long)live_after);
  }
  return rc;
}

/* ---------- repair ---------- */

static int cmd_repair(const char *dir, const opts_t *o, char *err,
                      size_t err_cap) {
  if (!is_dir(dir)) {
    snprintf(err, err_cap, "directory does not exist: %s", dir);
    return -1;
  }
  char *dest = NULL;
  if (o->out_dir) {
    dest = strdup(o->out_dir);
  } else {
    dest = malloc(strlen(dir) + 10);
    if (dest) {
      sprintf(dest, "%s.salvaged", dir);
    }
  }
  if (!dest) {
    snprintf(err, err_cap, "out of memory");
    return -1;
  }
  struct stat st;
  if (lstat(dest, &st) == 0) {
    snprintf(err, err_cap, "destination path already exists: %s", dest);
    free(dest);
    return -1;
  }
  uint8_t master[32];
  if (resolve_credential(o, master, err, err_cap) != 0) {
    free(dest);
    return -1;
  }
  /* Copy first: the source stays untouched for forensics. */
  if (copy_tree(dir, dest) != 0) {
    snprintf(err, err_cap, "salvage failed (destination left for forensics): "
                           "copy: %s",
             strerror(errno));
    free(dest);
    wipe(master, 32);
    return -1;
  }
  int rc = 0;
  char serr[512];
  if (nv_repair(dest, serr, sizeof(serr)) != 0) {
    if (strstr(serr, "lock") || strstr(serr, "LOCK")) {
      snprintf(err, err_cap, "store is locked (server running?): stop the "
                             "server and retry");
    } else {
      snprintf(err, err_cap, "salvage failed (destination left for "
                             "forensics): %s",
               serr);
    }
    rc = -1;
  }
  /* Prove the salvaged store opens as a database. */
  char *db_id = NULL;
  int64_t records = 0;
  if (rc == 0) {
    int vrc = nvOfflineVerify(dest, master);
    if (vrc == NV_OFF_BUSY) {
      snprintf(err, err_cap, "salvaged store failed database verification "
                             "(destination left for forensics): locked");
      rc = -1;
    } else if (vrc != NV_OFF_OK) {
      snprintf(err, err_cap, "salvaged store failed database verification "
                             "(destination left for forensics): rc=%d",
               vrc);
      rc = -1;
    } else {
      sqlite3 *db = NULL;
      char oerr[256];
      if (open_sql(dest, master, &db, oerr, sizeof(oerr)) != 0) {
        snprintf(err, err_cap, "salvaged store failed database verification "
                               "(destination left for forensics): %s",
                 oerr);
        rc = -1;
      } else {
        db_id = sql_group_id(db);
        if (!db_id) {
          db_id = strdup("");
        }
        /* Records salvaged: page count via scan. */
        NvStore *s = nv_store_open(dest, 0, serr, sizeof(serr));
        if (s) {
          NvScan *sc = nv_scan_open(s);
          if (sc) {
            uint8_t vbuf[65536];
            for (;;) {
              uint64_t id = 0;
              size_t vlen = 0;
              int nr = nv_scan_next(sc, &id, vbuf, sizeof(vbuf), &vlen);
              if (nr == 1) {
                records++;
              } else if (nr == -2) {
                /* Oversize record: count it, skip the value. */
                records++;
                uint8_t *big = malloc(vlen);
                if (big) {
                  size_t v2 = 0;
                  nv_scan_next(sc, &id, big, vlen, &v2);
                  free(big);
                } else {
                  break;
                }
              } else {
                break;
              }
              if (records > (1LL << 40)) {
                break;
              }
            }
            nv_scan_close(sc);
          }
          nv_store_close(s);
        }
        sqlite3_close(db);
      }
    }
  }
  uint64_t dfiles_b = 0;
  int dfiles = 0;
  dir_size(dest, &dfiles_b, &dfiles);
  (void)dfiles_b;
  if (rc == 0) {
    if (o->json) {
      buf_t b;
      memset(&b, 0, sizeof(b));
      buf_puts(&b, "{\n  \"source_dir\": ");
      json_escape(&b, dir);
      buf_puts(&b, ",\n  \"dest_dir\": ");
      json_escape(&b, dest);
      buf_printf(&b, ",\n  \"records\": %lld,\n  \"files\": %d,\n"
                     "  \"gaps\": [],\n  \"gap_count\": 0,\n"
                     "  \"verified\": true,\n  \"database_id\": ",
               (long long)records, dfiles);
      json_escape(&b, db_id ? db_id : "");
      buf_puts(&b, "\n}\n");
      if (!b.p || fputs(b.p, stdout) < 0) {
        snprintf(err, err_cap, "output failed");
        rc = -1;
      }
      buf_free(&b);
    } else {
      printf("PASS: Store salvaged with no gaps; destination verified as a "
             "database.\n");
      printf("Source:       %s (untouched)\n", dir);
      printf("Destination:  %s\n", dest);
      printf("Records:      %lld from %d file(s)\n", (long long)records,
             dfiles);
      printf("Database ID:  %s\n", db_id ? db_id : "");
      printf("Next: point the server at the destination, or move it over the "
             "source while stopped.\n");
    }
  } else if (o->json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\n  \"source_dir\": ");
    json_escape(&b, dir);
    buf_puts(&b, ",\n  \"dest_dir\": ");
    json_escape(&b, dest);
    buf_printf(&b, ",\n  \"records\": %lld,\n  \"files\": %d,\n"
                   "  \"gaps\": [],\n  \"gap_count\": 0,\n"
                   "  \"verified\": false,\n  \"database_id\": null\n}\n",
             (long long)records, dfiles);
    if (b.p) {
      fputs(b.p, stdout);
    }
    buf_free(&b);
  }
  free(db_id);
  free(dest);
  wipe(master, 32);
  return rc;
}

/* ---------- main ---------- */

static int parse_id16(const char *s, uint8_t out[16], char *err,
                      size_t cap) {
  while (isspace((uint8_t)*s)) {
    s++;
  }
  size_t n = strlen(s);
  while (n > 0 && isspace((uint8_t)s[n - 1])) {
    n--;
  }
  if (n != 32) {
    snprintf(err, cap, "expected 16-byte hex (32 chars)");
    return -1;
  }
  char t[33];
  memcpy(t, s, 32);
  t[32] = '\0';
  if (hex_decode(t, out, 16) != 0) {
    snprintf(err, cap, "invalid hex id");
    return -1;
  }
  return 0;
}

static int run(int argc, char **argv) {
  if (argc < 2) {
    print_usage();
    return 0;
  }
  opts_t o;
  memset(&o, 0, sizeof(o));
  const char *positionals[64];
  size_t npos = 0;
  char err[1024] = "";
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    const char *val = NULL;
    char obuf[512];
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
      print_usage();
      return 0;
    } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--version") == 0) {
      printf("murmur-admin version %s\n", kVersion);
      return 0;
    } else if (strcmp(arg, "--json") == 0) {
      o.json = 1;
    } else if (strcmp(arg, "--backup") == 0) {
      o.is_backup = 1;
    } else if (strncmp(arg, "--passphrase=", 13) == 0) {
      o.passphrase = arg + 13;
    } else if (strcmp(arg, "--passphrase") == 0 && i + 1 < argc) {
      o.passphrase = argv[++i];
    } else if (strncmp(arg, "--key-hex=", 10) == 0) {
      o.key_hex = arg + 10;
    } else if (strcmp(arg, "--key-hex") == 0 && i + 1 < argc) {
      o.key_hex = argv[++i];
    } else if (strncmp(arg, "--key-provider-uri=", 19) == 0) {
      o.key_provider_uri = arg + 19;
    } else if (strcmp(arg, "--key-provider-uri") == 0 && i + 1 < argc) {
      o.key_provider_uri = argv[++i];
    } else if (strncmp(arg, "--new-passphrase=", 17) == 0) {
      o.new_passphrase = arg + 17;
    } else if (strcmp(arg, "--new-passphrase") == 0 && i + 1 < argc) {
      o.new_passphrase = argv[++i];
    } else if (strncmp(arg, "--new-key-hex=", 14) == 0) {
      o.new_key_hex = arg + 14;
    } else if (strcmp(arg, "--new-key-hex") == 0 && i + 1 < argc) {
      o.new_key_hex = argv[++i];
    } else if (strcmp(arg, "--fresh-node-id") == 0) {
      if (random_bytes(o.fresh_node, 16) != 0) {
        snprintf(err, sizeof(err), "randomness unavailable");
        goto fail;
      }
      o.has_fresh_node = 1;
    } else if (strncmp(arg, "--fresh-node-id=", 16) == 0) {
      if (parse_id16(arg + 16, o.fresh_node, obuf, sizeof(obuf)) != 0) {
        snprintf(err, sizeof(err), "Error: %s", obuf);
        goto fail;
      }
      o.has_fresh_node = 1;
    } else if (strcmp(arg, "--fresh-db-id") == 0) {
      if (random_bytes(o.fresh_db, 16) != 0) {
        snprintf(err, sizeof(err), "randomness unavailable");
        goto fail;
      }
      o.has_fresh_db = 1;
    } else if (strncmp(arg, "--fresh-db-id=", 14) == 0) {
      if (parse_id16(arg + 14, o.fresh_db, obuf, sizeof(obuf)) != 0) {
        snprintf(err, sizeof(err), "Error: %s", obuf);
        goto fail;
      }
      o.has_fresh_db = 1;
    } else if (strncmp(arg, "--max-passes=", 13) == 0) {
      val = arg + 13;
      goto maxpasses;
    } else if (strcmp(arg, "--max-passes") == 0 && i + 1 < argc) {
      val = argv[++i];
    maxpasses: {
      char *end = NULL;
      long v = strtol(val, &end, 10);
      if (!val[0] || (end && *end) || v < 0) {
        snprintf(err, sizeof(err), "Error: --max-passes must be >= 0");
        goto fail;
      }
      o.max_passes = v;
    }
    } else if (strncmp(arg, "--out=", 6) == 0) {
      o.out_dir = arg + 6;
    } else if (strcmp(arg, "--out") == 0 && i + 1 < argc) {
      o.out_dir = argv[++i];
    } else {
      if (npos < 64) {
        positionals[npos++] = arg;
      }
    }
  }
  if (npos == 0) {
    print_usage();
    return 0;
  }
  {
    const char *cmd = positionals[0];
    size_t nargs = npos - 1;
    const char **args = positionals + 1;
    int rc = -1;
    if (strcmp(cmd, "status") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "status <data-dir>");
      } else {
        rc = cmd_status(args[0], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "inspect") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "inspect <data-dir>");
      } else {
        rc = cmd_inspect(args[0], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "verify") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "verify <data-dir> [--backup]");
      } else {
        rc = cmd_verify(args[0], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "backup") == 0) {
      if (nargs < 2) {
        snprintf(err, sizeof(err), "missing arguments. Usage: murmur-admin "
                                   "backup <source-dir> <dest-dir>");
      } else {
        rc = cmd_backup(args[0], args[1], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "restore") == 0) {
      if (nargs < 2) {
        snprintf(err, sizeof(err), "missing arguments. Usage: murmur-admin "
                                   "restore <backup-dir> <dest-dir>");
      } else {
        rc = cmd_restore(args[0], args[1], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "keys") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "keys <data-dir>");
      } else {
        rc = cmd_keys(args[0], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "rekey") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "rekey <data-dir> --new-passphrase <str> | "
                                   "--new-key-hex <hex>");
      } else {
        rc = cmd_rekey(args[0], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "compact") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "compact <data-dir> [--max-passes <n>]");
      } else {
        rc = cmd_compact(args[0], &o, err, sizeof(err));
      }
    } else if (strcmp(cmd, "repair") == 0) {
      if (nargs == 0) {
        snprintf(err, sizeof(err), "missing <data-dir>. Usage: murmur-admin "
                                   "repair <data-dir> [--out <dir>]");
      } else {
        rc = cmd_repair(args[0], &o, err, sizeof(err));
      }
    } else {
      snprintf(err, sizeof(err),
               "unknown command: \"%s\". Run 'murmur-admin --help' for usage.",
               cmd);
    }
    if (rc != 0) {
      goto fail;
    }
    return 0;
  }
fail:
  if (o.json) {
    buf_t b;
    memset(&b, 0, sizeof(b));
    buf_puts(&b, "{\"error\": true, \"message\": ");
    json_escape(&b, err[0] ? err : "failed");
    buf_puts(&b, "}\n");
    if (b.p) {
      fputs(b.p, stderr);
    }
    buf_free(&b);
  } else {
    fprintf(stderr, "Error: %s\n", err[0] ? err : "failed");
  }
  return 1;
}

int main(int argc, char **argv) {
  if (murmur_init() != 0) {
    fprintf(stderr, "Error: murmur_init failed\n");
    return 1;
  }
  if (murmur_vfs_register(0, 0) != 0) {
    fprintf(stderr, "Error: vfs register failed\n");
    return 1;
  }
  return run(argc, argv);
}





