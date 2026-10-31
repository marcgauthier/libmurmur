/* murmur fetch - native file fetch service. See fetch.h. */
#include "fetch.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "filecodec.h"
#include "postcard.h"
#include "sha256.h"
#include "transport.h"

#define FETCH_CHUNK (64u << 10)
#define FETCH_ACCEPT_POLL_MS 500

static void set_detail(char **out, const char *fmt, ...) {
  if (!out) {
    return;
  }
  *out = NULL;
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  *out = strdup(buf);
}

static uint64_t sat_add(uint64_t a, uint64_t b) {
  uint64_t c = a + b;
  return c < a ? UINT64_MAX : c;
}

static uint64_t div_ceil(uint64_t a, uint64_t b) {
  uint64_t q = a / b;
  if (a % b != 0) {
    q++;
  }
  return q;
}

static uint64_t now_mono_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void hex_encode(const uint8_t *b, size_t n, char *out) {
  static const char *digits = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = digits[b[i] >> 4];
    out[2 * i + 1] = digits[b[i] & 15];
  }
  out[2 * n] = 0;
}

/* ---------- CIDR allowlist (v4 collapses to v4-mapped, like Go) ---------- */

typedef struct {
  uint8_t addr[16];
  unsigned bits;
} fetch_cidr_t;

static int parse_cidr(const char *s, fetch_cidr_t *out) {
  memset(out->addr, 0, 16);
  const char *slash = strchr(s, '/');
  char ip[128];
  unsigned bits = 0;
  int has_bits = 0;
  if (slash) {
    size_t n = (size_t)(slash - s);
    if (n >= sizeof(ip)) {
      return -1;
    }
    memcpy(ip, s, n);
    ip[n] = 0;
    bits = (unsigned)atoi(slash + 1);
    has_bits = 1;
  } else {
    if (strlen(s) >= sizeof(ip)) {
      return -1;
    }
    strcpy(ip, s);
  }
  struct in_addr v4;
  struct in6_addr v6;
  if (inet_pton(AF_INET, ip, &v4) == 1) {
    if (!has_bits) {
      bits = 32;
    }
    if (bits > 32) {
      return -1;
    }
    out->addr[10] = 0xff;
    out->addr[11] = 0xff;
    memcpy(out->addr + 12, &v4, 4);
    out->bits = 96 + bits;
    return 0;
  }
  if (inet_pton(AF_INET6, ip, &v6) == 1) {
    if (!has_bits) {
      bits = 128;
    }
    if (bits > 128) {
      return -1;
    }
    memcpy(out->addr, &v6, 16);
    out->bits = bits;
    return 0;
  }
  return -1;
}

static int cidr_match(const fetch_cidr_t *c, const uint8_t key[16]) {
  for (unsigned i = 0; i < c->bits; i++) {
    unsigned bit = 7 - (i % 8);
    if (((c->addr[i / 8] >> bit) & 1) != ((key[i / 8] >> bit) & 1)) {
      return 0;
    }
  }
  return 1;
}

static int ip_to_key(const char *ip, uint8_t key[16]) {
  struct in_addr v4;
  struct in6_addr v6;
  memset(key, 0, 16);
  if (inet_pton(AF_INET, ip, &v4) == 1) {
    key[10] = 0xff;
    key[11] = 0xff;
    memcpy(key + 12, &v4, 4);
    return 0;
  }
  if (inet_pton(AF_INET6, ip, &v6) == 1) {
    memcpy(key, &v6, 16);
    return 0;
  }
  return -1;
}

/* Splits "ip:port" at the last colon (transport emits unbracketed v6). */
static int split_addr(const char *addr, char *ip, size_t ip_len) {
  const char *colon = strrchr(addr, ':');
  if (!colon) {
    return -1;
  }
  size_t n = (size_t)(colon - addr);
  if (n + 1 > ip_len) {
    return -1;
  }
  memcpy(ip, addr, n);
  ip[n] = 0;
  return 0;
}

/* ---------- counting semaphore ---------- */

typedef struct {
  pthread_mutex_t mu;
  int used;
  int cap;
} fetch_sem_t;

static void sem_init(fetch_sem_t *s, int cap) {
  pthread_mutex_init(&s->mu, NULL);
  s->used = 0;
  s->cap = cap;
}

static void sem_destroy(fetch_sem_t *s) { pthread_mutex_destroy(&s->mu); }

static int sem_try_acquire(fetch_sem_t *s) {
  pthread_mutex_lock(&s->mu);
  int ok = s->used < s->cap;
  if (ok) {
    s->used++;
  }
  pthread_mutex_unlock(&s->mu);
  return ok;
}

static void sem_release(fetch_sem_t *s) {
  pthread_mutex_lock(&s->mu);
  if (s->used > 0) {
    s->used--;
  }
  pthread_mutex_unlock(&s->mu);
}

/* ---------- service ---------- */

typedef struct {
  uint8_t digest[32];
} active_key_t;

struct murmur_fetch_t {
  murmur_quic_t *quic;
  murmur_files_t *objects;
  murmur_node_t database;
  murmur_node_t *allowed;
  size_t n_allowed;
  fetch_cidr_t *cidrs;
  size_t n_cidrs;
  uint64_t max_staging;
  pthread_t accept_thread;
  pthread_mutex_t mu; /* stop + workers + active */
  pthread_cond_t drained;
  int stop;
  int workers;
  active_key_t *active;
  size_t n_active;
  size_t cap_active;
  fetch_sem_t permits;
  fetch_sem_t staging_permits;
};

static int network_allowed(murmur_fetch_t *s, const char *addr) {
  if (s->n_cidrs == 0) {
    return 1;
  }
  char ip[128];
  if (split_addr(addr, ip, sizeof(ip)) != 0) {
    return 0;
  }
  uint8_t key[16];
  if (ip_to_key(ip, key) != 0) {
    return 0;
  }
  for (size_t i = 0; i < s->n_cidrs; i++) {
    if (cidr_match(&s->cidrs[i], key)) {
      return 1;
    }
  }
  return 0;
}

static int peer_allowed(murmur_fetch_t *s, const murmur_node_t *id) {
  if (s->n_allowed == 0) {
    return 1;
  }
  for (size_t i = 0; i < s->n_allowed; i++) {
    if (memcmp(s->allowed[i].b, id->b, 16) == 0) {
      return 1;
    }
  }
  return 0;
}

static int fetch_stopped(murmur_fetch_t *s) {
  pthread_mutex_lock(&s->mu);
  int stop = s->stop;
  pthread_mutex_unlock(&s->mu);
  return stop;
}

static void worker_add(murmur_fetch_t *s) {
  pthread_mutex_lock(&s->mu);
  s->workers++;
  pthread_mutex_unlock(&s->mu);
}

static void worker_done(murmur_fetch_t *s) {
  pthread_mutex_lock(&s->mu);
  s->workers--;
  if (s->workers == 0) {
    pthread_cond_broadcast(&s->drained);
  }
  pthread_mutex_unlock(&s->mu);
}

static int active_contains(murmur_fetch_t *s, const uint8_t digest[32]) {
  pthread_mutex_lock(&s->mu);
  int found = 0;
  for (size_t i = 0; i < s->n_active; i++) {
    if (memcmp(s->active[i].digest, digest, 32) == 0) {
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&s->mu);
  return found;
}

static void active_add(murmur_fetch_t *s, const uint8_t digest[32]) {
  pthread_mutex_lock(&s->mu);
  if (s->n_active == s->cap_active) {
    size_t cap = s->cap_active ? s->cap_active * 2 : 16;
    active_key_t *next = realloc(s->active, cap * sizeof(*next));
    if (next) {
      s->active = next;
      s->cap_active = cap;
    }
  }
  if (s->n_active < s->cap_active) {
    memcpy(s->active[s->n_active].digest, digest, 32);
    s->n_active++;
  }
  pthread_mutex_unlock(&s->mu);
}

static void active_remove(murmur_fetch_t *s, const uint8_t digest[32]) {
  pthread_mutex_lock(&s->mu);
  for (size_t i = 0; i < s->n_active; i++) {
    if (memcmp(s->active[i].digest, digest, 32) == 0) {
      s->active[i] = s->active[--s->n_active];
      break;
    }
  }
  pthread_mutex_unlock(&s->mu);
}

/* ---------- stream frame IO ---------- */

typedef struct {
  murmur_stream_t *stream;
  uint64_t deadline_ms;
  int timed_out;
  char err[256];
} frame_io_t;

static int frame_write(void *ctx, const uint8_t *b, size_t n) {
  frame_io_t *io = ctx;
  int rc = murmur_stream_write(io->stream, b, n);
  if (rc == -MURMUR_QUIC_TIMEOUT) {
    io->timed_out = 1;
  }
  if (rc != 0) {
    snprintf(io->err, sizeof(io->err), "stream write");
  }
  return rc;
}

static int frame_read_full(void *ctx, uint8_t *b, size_t n) {
  frame_io_t *io = ctx;
  size_t got = 0;
  while (got < n) {
    uint64_t now = now_mono_ms();
    if (now >= io->deadline_ms) {
      io->timed_out = 1;
      snprintf(io->err, sizeof(io->err), "stream timeout");
      return -MURMUR_QUIC_TIMEOUT;
    }
    uint64_t left = io->deadline_ms - now;
    int chunk_ms = left > (uint64_t)0x7fffffff ? 0x7fffffff : (int)left;
    size_t m = 0;
    int rc = murmur_stream_read_timeout(io->stream, b + got, n - got, &m,
                                        chunk_ms);
    if (rc == -MURMUR_QUIC_TIMEOUT) {
      io->timed_out = 1;
      snprintf(io->err, sizeof(io->err), "stream timeout");
      return rc;
    }
    if (rc != 0) {
      snprintf(io->err, sizeof(io->err), "stream read");
      return rc;
    }
    if (m == 0) {
      snprintf(io->err, sizeof(io->err), "stream closed");
      return -MURMUR_QUIC_CLOSED;
    }
    got += m;
  }
  return 0;
}

static int frame_close(void *ctx) {
  frame_io_t *io = ctx;
  return murmur_stream_close(io->stream);
}

static const char *frame_error(void *ctx) {
  frame_io_t *io = ctx;
  return io->err[0] ? io->err : NULL;
}

/* Reads one frame with the shared deadline. */
static murmur_files_status_t fetch_read_frame(frame_io_t *io,
                                              murmur_file_frame_t *f,
                                              uint8_t **owned, char **detail) {
  murmur_stream_io_t sio;
  sio.write = frame_write;
  sio.read_full = frame_read_full;
  sio.close = frame_close;
  sio.error_text = frame_error;
  sio.ctx = io;
  int sqlrc = 0;
  murmur_sync_status_t st =
      murmur_file_read_frame(&sio, f, owned, detail, &sqlrc);
  if (st == MURMUR_SYNC_OK) {
    return MURMUR_FILES_OK;
  }
  if (io->timed_out) {
    free(*detail);
    set_detail(detail, "file transfer timeout");
    return MURMUR_FILES_UNAVAILABLE;
  }
  if (st == MURMUR_SYNC_INVALID) {
    return MURMUR_FILES_INVALID;
  }
  return MURMUR_FILES_PROTOCOL;
}

static murmur_files_status_t fetch_write_frame(frame_io_t *io,
                                               const murmur_file_frame_t *f,
                                               char **detail) {
  murmur_stream_io_t sio;
  sio.write = frame_write;
  sio.read_full = frame_read_full;
  sio.close = frame_close;
  sio.error_text = frame_error;
  sio.ctx = io;
  int sqlrc = 0;
  murmur_sync_status_t st = murmur_file_write_frame(&sio, f, detail, &sqlrc);
  if (st == MURMUR_SYNC_OK) {
    return MURMUR_FILES_OK;
  }
  if (io->timed_out) {
    free(*detail);
    set_detail(detail, "file transfer timeout");
    return MURMUR_FILES_UNAVAILABLE;
  }
  if (st == MURMUR_SYNC_OVERLOADED) {
    return MURMUR_FILES_OVERLOADED;
  }
  return MURMUR_FILES_PROTOCOL;
}

/* ---------- serve ---------- */

/* Peer-driven shutdown with a bound: poll for the close event in
 * 1s slices so service stop interrupts the linger. */
static void linger_peer_close(murmur_fetch_t *s, murmur_session_t *sess) {
  uint64_t end = now_mono_ms() + MURMUR_FETCH_LINGER_MS;
  for (;;) {
    if (fetch_stopped(s)) {
      return;
    }
    uint64_t now = now_mono_ms();
    if (now >= end) {
      return;
    }
    uint64_t left = end - now;
    int slice = left > 1000 ? 1000 : (int)left;
    if (murmur_session_wait_closed(sess, slice) == 0) {
      return;
    }
  }
}

static void refuse(murmur_session_t *sess) {
  murmur_session_close_code(sess, 1);
}

/* Authenticates the far side: live network allowlist, leaf SAN
 * node id (handshake-verified), live allowed-peers set. */
static murmur_files_status_t serve_peer_id(murmur_fetch_t *s,
                                           murmur_session_t *sess,
                                           murmur_node_t *id,
                                           char **detail) {
  char addr[128];
  if (murmur_session_remote_addr(sess, addr, sizeof(addr)) != 0) {
    set_detail(detail, "remote address");
    return MURMUR_FILES_AUTH;
  }
  if (!network_allowed(s, addr)) {
    set_detail(detail, "remote network denied");
    return MURMUR_FILES_AUTH;
  }
  if (murmur_session_peer(sess, id) != 0) {
    set_detail(detail, "missing peer certificate");
    return MURMUR_FILES_AUTH;
  }
  if (!peer_allowed(s, id)) {
    set_detail(detail, "remote node denied");
    return MURMUR_FILES_AUTH;
  }
  return MURMUR_FILES_OK;
}

static int serve_network_live(murmur_fetch_t *s, murmur_session_t *sess) {
  char addr[128];
  if (murmur_session_remote_addr(sess, addr, sizeof(addr)) != 0) {
    return 0;
  }
  return network_allowed(s, addr);
}

static murmur_files_status_t serve_conn(murmur_fetch_t *s,
                                        murmur_session_t *sess) {
  char *detail = NULL;
  murmur_files_status_t fs;
  murmur_node_t peer;
  fs = serve_peer_id(s, sess, &peer, &detail);
  if (fs != MURMUR_FILES_OK) {
    goto done;
  }
  uint64_t deadline = now_mono_ms() + MURMUR_FETCH_TIMEOUT_MS;
  murmur_stream_t *stream = NULL;
  uint64_t now = now_mono_ms();
  int accept_ms =
      deadline > now && deadline - now < (uint64_t)0x7fffffff
          ? (int)(deadline - now)
          : 0x7fffffff;
  int rc = murmur_session_accept_stream(sess, &stream, accept_ms);
  if (rc == -MURMUR_QUIC_TIMEOUT) {
    set_detail(&detail, "file transfer timeout");
    fs = MURMUR_FILES_UNAVAILABLE;
    goto done;
  }
  if (rc != 0) {
    set_detail(&detail, "stream accept");
    fs = MURMUR_FILES_PROTOCOL;
    goto done;
  }
  frame_io_t io;
  memset(&io, 0, sizeof(io));
  io.stream = stream;
  io.deadline_ms = deadline;
  murmur_file_frame_t req;
  memset(&req, 0, sizeof(req));
  uint8_t *owned = NULL;
  fs = fetch_read_frame(&io, &req, &owned, &detail);
  if (fs != MURMUR_FILES_OK) {
    murmur_stream_release(stream);
    goto done;
  }
  if (req.kind != MURMUR_FILE_REQUEST) {
    free(owned);
    murmur_stream_release(stream);
    set_detail(&detail, "file request");
    fs = MURMUR_FILES_PROTOCOL;
    goto done;
  }
  if (memcmp(req.database.b, s->database.b, 16) != 0) {
    free(owned);
    murmur_stream_release(stream);
    set_detail(&detail, "file database identity");
    fs = MURMUR_FILES_AUTH;
    goto done;
  }
  uint8_t digest[32];
  memcpy(digest, req.digest, 32);
  uint64_t generation = req.generation;
  uint64_t offset = req.offset;
  free(owned);

  char *path = murmur_files_object_path(s->objects, digest, generation);
  if (!path) {
    murmur_stream_release(stream);
    set_detail(&detail, "file serve");
    fs = MURMUR_FILES_IO;
    goto done;
  }
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    murmur_file_frame_t miss;
    memset(&miss, 0, sizeof(miss));
    miss.kind = MURMUR_FILE_MISSING;
    fs = fetch_write_frame(&io, &miss, &detail);
    murmur_stream_close(stream);
    murmur_stream_release(stream);
    free(path);
    if (fs != MURMUR_FILES_OK) {
      goto done;
    }
    linger_peer_close(s, sess);
    goto done;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
    murmur_stream_release(stream);
    free(path);
    set_detail(&detail, strerror(errno));
    fs = MURMUR_FILES_IO;
    goto done;
  }
  uint64_t bytes = (uint64_t)st.st_size;
  if (offset > bytes) {
    close(fd);
    murmur_stream_release(stream);
    free(path);
    set_detail(&detail, "file resume offset");
    fs = MURMUR_FILES_PROTOCOL;
    goto done;
  }
  uint8_t header[40];
  size_t hgot = 0;
  while (hgot < sizeof(header)) {
    ssize_t r = pread(fd, header + hgot, sizeof(header) - hgot, (off_t)hgot);
    if (r <= 0) {
      break;
    }
    hgot += (size_t)r;
  }
  if (hgot != sizeof(header)) {
    close(fd);
    murmur_stream_release(stream);
    free(path);
    set_detail(&detail, "file container header");
    fs = MURMUR_FILES_PROTOCOL;
    goto done;
  }
  uint8_t identity[32];
  murmur_sha256(header, sizeof(header), identity);
  murmur_file_frame_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  hdr.kind = MURMUR_FILE_HEADER;
  hdr.bytes = bytes;
  memcpy(hdr.identity, identity, 32);
  fs = fetch_write_frame(&io, &hdr, &detail);
  if (fs != MURMUR_FILES_OK) {
    close(fd);
    murmur_stream_release(stream);
    free(path);
    goto done;
  }
  if (lseek(fd, (off_t)offset, SEEK_SET) != (off_t)offset) {
    close(fd);
    murmur_stream_release(stream);
    free(path);
    set_detail(&detail, strerror(errno));
    fs = MURMUR_FILES_IO;
    goto done;
  }
  uint8_t *chunk = malloc(FETCH_CHUNK);
  if (!chunk) {
    close(fd);
    murmur_stream_release(stream);
    free(path);
    set_detail(&detail, "file serve");
    fs = MURMUR_FILES_IO;
    goto done;
  }
  for (;;) {
    if (!serve_network_live(s, sess)) {
      free(chunk);
      close(fd);
      murmur_stream_release(stream);
      free(path);
      set_detail(&detail, "file peer migrated to denied network");
      fs = MURMUR_FILES_AUTH;
      goto done;
    }
    ssize_t r = read(fd, chunk, FETCH_CHUNK);
    if (r < 0) {
      if (errno == EINTR) {
        continue;
      }
      free(chunk);
      close(fd);
      murmur_stream_release(stream);
      free(path);
      set_detail(&detail, "%s", strerror(errno));
      fs = MURMUR_FILES_IO;
      goto done;
    }
    if (r > 0) {
      murmur_file_frame_t cf;
      memset(&cf, 0, sizeof(cf));
      cf.kind = MURMUR_FILE_CHUNK_FRAME;
      cf.data = chunk;
      cf.data_len = (size_t)r;
      fs = fetch_write_frame(&io, &cf, &detail);
      if (fs != MURMUR_FILES_OK) {
        free(chunk);
        close(fd);
        murmur_stream_release(stream);
        free(path);
        goto done;
      }
    }
    if (r == 0) {
      break;
    }
  }
  free(chunk);
  close(fd);
  free(path);
  murmur_file_frame_t done_frame;
  memset(&done_frame, 0, sizeof(done_frame));
  done_frame.kind = MURMUR_FILE_DONE;
  fs = fetch_write_frame(&io, &done_frame, &detail);
  murmur_stream_close(stream);
  murmur_stream_release(stream);
  if (fs != MURMUR_FILES_OK) {
    goto done;
  }
  linger_peer_close(s, sess);
done:
  murmur_session_close(sess);
  if (fs != MURMUR_FILES_OK) {
    murmur_files_fetch_error(s->objects, detail ? detail : "file serve");
  }
  free(detail);
  return fs;
}

typedef struct {
  murmur_fetch_t *s;
  murmur_session_t *sess;
} serve_job_t;

static void *serve_thread(void *arg) {
  serve_job_t *job = arg;
  murmur_fetch_t *s = job->s;
  serve_conn(s, job->sess);
  murmur_session_release(job->sess);
  free(job);
  worker_done(s);
  sem_release(&s->permits);
  return NULL;
}

/* ---------- accept loop ---------- */

static void *accept_thread(void *arg) {
  murmur_fetch_t *s = arg;
  for (;;) {
    if (fetch_stopped(s)) {
      return NULL;
    }
    murmur_session_t *sess = NULL;
    int rc = murmur_quic_accept(s->quic, &sess, FETCH_ACCEPT_POLL_MS);
    if (rc == -MURMUR_QUIC_TIMEOUT) {
      continue;
    }
    if (rc != 0 || !sess) {
      if (fetch_stopped(s)) {
        return NULL;
      }
      continue;
    }
    char addr[128];
    if (murmur_session_remote_addr(sess, addr, sizeof(addr)) != 0 ||
        !network_allowed(s, addr)) {
      refuse(sess);
      murmur_session_release(sess);
      continue;
    }
    if (!sem_try_acquire(&s->permits)) {
      refuse(sess);
      murmur_session_release(sess);
      continue;
    }
    serve_job_t *job = malloc(sizeof(*job));
    if (!job) {
      sem_release(&s->permits);
      refuse(sess);
      murmur_session_release(sess);
      continue;
    }
    job->s = s;
    job->sess = sess;
    worker_add(s);
    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, serve_thread, job) != 0) {
      pthread_attr_destroy(&attr);
      worker_done(s);
      sem_release(&s->permits);
      refuse(sess);
      murmur_session_release(sess);
      free(job);
      continue;
    }
    pthread_attr_destroy(&attr);
  }
}

/* ---------- start / stop ---------- */

murmur_files_status_t murmur_fetch_start(const murmur_fetch_config_t *config,
                                         murmur_files_t *objects,
                                         const murmur_node_t *database,
                                         murmur_fetch_t **out,
                                         char **detail_out) {
  if (detail_out) {
    *detail_out = NULL;
  }
  *out = NULL;
  if (!config || !objects || !database || config->concurrent_fetches <= 0 ||
      config->max_staging_bytes == 0) {
    set_detail(detail_out, "file fetch config");
    return MURMUR_FILES_INVALID;
  }
  murmur_fetch_t *s = calloc(1, sizeof(*s));
  if (!s) {
    set_detail(detail_out, "file fetch start");
    return MURMUR_FILES_IO;
  }
  s->objects = objects;
  s->database = *database;
  s->max_staging = config->max_staging_bytes;
  if (config->n_allowed) {
    s->allowed = malloc(config->n_allowed * sizeof(*s->allowed));
    if (!s->allowed) {
      free(s);
      set_detail(detail_out, "file fetch start");
      return MURMUR_FILES_IO;
    }
    memcpy(s->allowed, config->allowed,
           config->n_allowed * sizeof(*s->allowed));
    s->n_allowed = config->n_allowed;
  }
  if (config->n_cidrs) {
    s->cidrs = malloc(config->n_cidrs * sizeof(*s->cidrs));
    if (!s->cidrs) {
      free(s->allowed);
      free(s);
      set_detail(detail_out, "file fetch start");
      return MURMUR_FILES_IO;
    }
    for (size_t i = 0; i < config->n_cidrs; i++) {
      if (parse_cidr(config->allow_cidrs[i], &s->cidrs[i]) != 0) {
        free(s->cidrs);
        free(s->allowed);
        free(s);
        set_detail(detail_out, "bad allowlist CIDR");
        return MURMUR_FILES_INVALID;
      }
    }
    s->n_cidrs = config->n_cidrs;
  }
  const char *bind_ip = config->bind_ip ? config->bind_ip : "127.0.0.1";
  int rc = murmur_quic_create_alpn(
      &s->quic, bind_ip, config->bind_port, config->chain_der,
      config->chain_lens, config->chain_n, config->key_pem, config->key_len,
      config->ca_der, config->ca_lens, config->ca_n, &config->self,
      config->allowed, config->n_allowed, config->allow_cidrs,
      config->n_cidrs, config->max_conns, 32, MURMUR_FETCH_ALPN);
  if (rc != 0) {
    char err[256];
    if (s->quic) {
      murmur_last_error(s->quic, err, sizeof(err));
    } else {
      snprintf(err, sizeof(err), "endpoint create");
    }
    free(s->cidrs);
    free(s->allowed);
    free(s);
    set_detail(detail_out, "%s", err);
    return MURMUR_FILES_PROTOCOL;
  }
  uint64_t units = div_ceil(config->max_staging_bytes, 1u << 20);
  if (units > (uint64_t)0xffffffffu) {
    units = 0xffffffffu;
  }
  if (units < 1) {
    units = 1;
  }
  pthread_mutex_init(&s->mu, NULL);
  pthread_cond_init(&s->drained, NULL);
  sem_init(&s->permits, config->concurrent_fetches);
  sem_init(&s->staging_permits, (int)units);
  if (pthread_create(&s->accept_thread, NULL, accept_thread, s) != 0) {
    murmur_quic_close(s->quic);
    murmur_quic_free(s->quic);
    sem_destroy(&s->permits);
    sem_destroy(&s->staging_permits);
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->drained);
    free(s->cidrs);
    free(s->allowed);
    free(s);
    set_detail(detail_out, "file fetch start");
    return MURMUR_FILES_IO;
  }
  *out = s;
  return MURMUR_FILES_OK;
}

void murmur_fetch_stop(murmur_fetch_t *s) {
  if (!s) {
    return;
  }
  pthread_mutex_lock(&s->mu);
  s->stop = 1;
  pthread_mutex_unlock(&s->mu);
  murmur_quic_close(s->quic);
  pthread_join(s->accept_thread, NULL);
  /* Drain workers before freeing the endpoint they use. */
  pthread_mutex_lock(&s->mu);
  while (s->workers > 0) {
    pthread_cond_wait(&s->drained, &s->mu);
  }
  pthread_mutex_unlock(&s->mu);
  murmur_quic_free(s->quic);
  sem_destroy(&s->permits);
  sem_destroy(&s->staging_permits);
  pthread_mutex_destroy(&s->mu);
  pthread_cond_destroy(&s->drained);
  free(s->active);
  free(s->cidrs);
  free(s->allowed);
  free(s);
}

int murmur_fetch_local_addr(murmur_fetch_t *s, char *ip, size_t ip_len,
                            uint16_t *port) {
  char addr[128];
  if (murmur_quic_local_addr(s->quic, addr, sizeof(addr)) != 0) {
    return -1;
  }
  const char *colon = strrchr(addr, ':');
  if (!colon) {
    return -1;
  }
  size_t n = (size_t)(colon - addr);
  if (n + 1 > ip_len) {
    return -1;
  }
  memcpy(ip, addr, n);
  ip[n] = 0;
  *port = (uint16_t)atoi(colon + 1);
  return 0;
}

/* ---------- resume + publish ---------- */

static char *staging_identity_path(const char *path) {
  const char *slash = strrchr(path, '/');
  const char *dot = strrchr(slash ? slash : path, '.');
  size_t stem = dot ? (size_t)(dot - path) : strlen(path);
  const char *suffix = ".identity";
  char *out = malloc(stem + strlen(suffix) + 1);
  if (!out) {
    return NULL;
  }
  memcpy(out, path, stem);
  strcpy(out + stem, suffix);
  return out;
}

murmur_files_status_t murmur_fetch_resume_offset(const char *path,
                                                 uint64_t *offset,
                                                 char **detail_out) {
  *offset = 0;
  struct stat st;
  if (stat(path, &st) != 0) {
    if (errno == ENOENT) {
      return MURMUR_FILES_OK;
    }
    set_detail(detail_out, "%s", strerror(errno));
    return MURMUR_FILES_IO;
  }
  uint64_t off = (uint64_t)st.st_size;
  if (off > 0) {
    char *identity = staging_identity_path(path);
    if (!identity) {
      set_detail(detail_out, "file resume");
      return MURMUR_FILES_IO;
    }
    struct stat ist;
    long size = -1;
    if (stat(identity, &ist) == 0) {
      size = (long)ist.st_size;
    } else if (errno != ENOENT) {
      set_detail(detail_out, "%s", strerror(errno));
      free(identity);
      return MURMUR_FILES_IO;
    }
    free(identity);
    if (size != 32) {
      if (unlink(path) != 0) {
        set_detail(detail_out, "%s", strerror(errno));
        return MURMUR_FILES_IO;
      }
      return MURMUR_FILES_OK;
    }
  }
  *offset = off;
  return MURMUR_FILES_OK;
}

/* Publishes only an authenticated staged container, discarding
 * poisoned bytes and their resume identity. */
static murmur_files_status_t publish_staged(murmur_fetch_t *s, const char *path,
                                            const char *identity,
                                            const murmur_files_meta_t *meta,
                                            char **detail) {
  int sqlrc = 0;
  murmur_files_status_t fs = murmur_files_publish_fetched(
      s->objects, path, meta, detail, &sqlrc);
  if (fs != MURMUR_FILES_OK) {
    unlink(path);
    unlink(identity);
  }
  return fs;
}

static int mkdir_all(const char *path) {
  char *tmp = strdup(path);
  if (!tmp) {
    return -1;
  }
  size_t n = strlen(tmp);
  while (n > 0 && tmp[n - 1] == '/') {
    tmp[--n] = 0;
  }
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
        free(tmp);
        return -1;
      }
      *p = '/';
    }
  }
  if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
    free(tmp);
    return -1;
  }
  free(tmp);
  return 0;
}

/* ---------- fetch one ---------- */

static murmur_files_status_t fetch_one(murmur_fetch_t *s,
                                       const murmur_fetch_source_t *source,
                                       const murmur_files_meta_t *meta) {
  char *detail = NULL;
  murmur_files_status_t fs;
  int sqlrc = 0;
  char ip[64];
  if (source->addr.is6) {
    inet_ntop(AF_INET6, source->addr.ip, ip, sizeof(ip));
  } else {
    inet_ntop(AF_INET, source->addr.ip, ip, sizeof(ip));
  }
  char addr[128];
  snprintf(addr, sizeof(addr), "%s:%u", ip, source->addr.port);
  if (!network_allowed(s, addr)) {
    set_detail(&detail, "file source network");
    fs = MURMUR_FILES_AUTH;
    goto latch;
  }
  uint64_t maximum = s->max_staging;
  uint64_t container_limit =
      sat_add(meta->bytes, meta->bytes / FETCH_CHUNK * 20 + 256);
  if (container_limit < meta->bytes || container_limit > maximum) {
    fs = MURMUR_FILES_OVERLOADED;
    goto latch;
  }
  const char *dir = murmur_files_directory(s->objects);
  size_t staging_n = strlen(dir) + sizeof("/staging");
  char *staging = malloc(staging_n);
  if (!staging) {
    set_detail(&detail, "file fetch");
    fs = MURMUR_FILES_IO;
    goto latch;
  }
  snprintf(staging, staging_n, "%s/staging", dir);
  if (mkdir_all(staging) != 0) {
    set_detail(&detail, "%s", strerror(errno));
    free(staging);
    fs = MURMUR_FILES_IO;
    goto latch;
  }
  char nodehex[33], digesthex[65];
  hex_encode(source->node.b, 16, nodehex);
  hex_encode(meta->digest, 32, digesthex);
  size_t path_n =
      strlen(staging) + 1 + 32 + 1 + 64 + 2 + 20 + 5 + 1;
  char *path = malloc(path_n);
  if (!path) {
    free(staging);
    set_detail(&detail, "file fetch");
    fs = MURMUR_FILES_IO;
    goto latch;
  }
  snprintf(path, path_n, "%s/%s-%s.g%llu.part", staging, nodehex, digesthex,
           (unsigned long long)meta->generation);
  free(staging);
  murmur_staged_transfer_t *guard = murmur_files_protect_staging(s->objects, path);
  if (!guard) {
    free(path);
    set_detail(&detail, "file fetch");
    fs = MURMUR_FILES_IO;
    goto latch;
  }
  uint64_t offset = 0;
  fs = murmur_fetch_resume_offset(path, &offset, &detail);
  if (fs != MURMUR_FILES_OK) {
    murmur_files_staged_release(guard);
    free(path);
    goto latch;
  }
  uint64_t deadline = now_mono_ms() + MURMUR_FETCH_TIMEOUT_MS;
  uint64_t now = now_mono_ms();
  int dial_ms = deadline > now && deadline - now < (uint64_t)0x7fffffff
                    ? (int)(deadline - now)
                    : 0x7fffffff;
  murmur_session_t *sess = NULL;
  int rc = murmur_quic_dial(s->quic, ip, source->addr.port, MURMUR_FETCH_SNI,
                            &sess, dial_ms);
  if (rc == -MURMUR_QUIC_TIMEOUT) {
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "file transfer timeout");
    fs = MURMUR_FILES_UNAVAILABLE;
    goto latch;
  }
  if (rc != 0 || !sess) {
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "file dial");
    fs = MURMUR_FILES_PROTOCOL;
    goto latch;
  }
  murmur_node_t id;
  fs = serve_peer_id(s, sess, &id, &detail);
  if (fs != MURMUR_FILES_OK) {
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    goto latch;
  }
  if (memcmp(id.b, source->node.b, 16) != 0) {
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "file source identity mismatch");
    fs = MURMUR_FILES_AUTH;
    goto latch;
  }
  murmur_stream_t *stream = NULL;
  rc = murmur_session_open_stream(sess, &stream);
  if (rc != 0 || !stream) {
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "stream open");
    fs = MURMUR_FILES_PROTOCOL;
    goto latch;
  }
  frame_io_t io;
  memset(&io, 0, sizeof(io));
  io.stream = stream;
  io.deadline_ms = deadline;
  murmur_file_frame_t req;
  memset(&req, 0, sizeof(req));
  req.kind = MURMUR_FILE_REQUEST;
  req.database = s->database;
  memcpy(req.digest, meta->digest, 32);
  req.generation = meta->generation;
  req.offset = offset;
  fs = fetch_write_frame(&io, &req, &detail);
  if (fs != MURMUR_FILES_OK) {
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    goto latch;
  }
  murmur_file_frame_t frame;
  memset(&frame, 0, sizeof(frame));
  uint8_t *owned = NULL;
  fs = fetch_read_frame(&io, &frame, &owned, &detail);
  if (fs != MURMUR_FILES_OK) {
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    goto latch;
  }
  uint8_t identity[32];
  uint64_t bytes = 0;
  if (frame.kind == MURMUR_FILE_HEADER) {
    memcpy(identity, frame.identity, 32);
    bytes = frame.bytes;
    free(owned);
  } else if (frame.kind == MURMUR_FILE_MISSING) {
    free(owned);
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    fs = murmur_files_record_peer(s->objects, meta->digest, meta->generation,
                                  &source->node, 0, &detail, &sqlrc);
    murmur_files_staged_release(guard);
    free(path);
    if (fs != MURMUR_FILES_OK) {
      goto latch;
    }
    set_detail(&detail, "file source has no object");
    fs = MURMUR_FILES_UNAVAILABLE;
    goto latch;
  } else {
    free(owned);
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "file response header");
    fs = MURMUR_FILES_PROTOCOL;
    goto latch;
  }
  if (bytes > container_limit || bytes > maximum || offset > bytes) {
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    fs = MURMUR_FILES_OVERLOADED;
    goto latch;
  }
  char *identity_path = staging_identity_path(path);
  if (!identity_path) {
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "file fetch");
    fs = MURMUR_FILES_IO;
    goto latch;
  }
  if (offset > 0) {
    /* Length-sensitive compare, like Go's string compare: a
     * short sidecar is a changed source, not an IO error. */
    int ifd = open(identity_path, O_RDONLY);
    uint8_t old[33];
    size_t got = 0;
    int bad = 0;
    if (ifd < 0) {
      bad = 1;
    } else {
      for (;;) {
        ssize_t r = read(ifd, old + got, sizeof(old) - got);
        if (r < 0) {
          bad = 1;
          break;
        }
        if (r == 0) {
          break;
        }
        got += (size_t)r;
        if (got == sizeof(old)) {
          break;
        }
      }
      close(ifd);
    }
    if (bad) {
      set_detail(&detail, "%s", strerror(errno));
      fs = MURMUR_FILES_IO;
      free(identity_path);
      murmur_stream_release(stream);
      murmur_session_close(sess);
      murmur_session_release(sess);
      murmur_files_staged_release(guard);
      free(path);
      goto latch;
    }
    if (got != 32 || memcmp(old, identity, 32) != 0) {
      unlink(path);
      free(identity_path);
      murmur_stream_release(stream);
      murmur_session_close(sess);
      murmur_session_release(sess);
      murmur_files_staged_release(guard);
      free(path);
      set_detail(&detail, "source container changed; restart transfer");
      fs = MURMUR_FILES_UNAVAILABLE;
      goto latch;
    }
  } else {
    int ifd = open(identity_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (ifd < 0) {
      set_detail(&detail, "%s", strerror(errno));
      fs = MURMUR_FILES_IO;
      free(identity_path);
      murmur_stream_release(stream);
      murmur_session_close(sess);
      murmur_session_release(sess);
      murmur_files_staged_release(guard);
      free(path);
      goto latch;
    }
    size_t wrote = 0;
    int bad = 0;
    while (wrote < 32) {
      ssize_t r = write(ifd, identity + wrote, 32 - wrote);
      if (r <= 0) {
        bad = 1;
        break;
      }
      wrote += (size_t)r;
    }
    close(ifd);
    if (bad) {
      set_detail(&detail, "%s", strerror(errno));
      fs = MURMUR_FILES_IO;
      free(identity_path);
      murmur_stream_release(stream);
      murmur_session_close(sess);
      murmur_session_release(sess);
      murmur_files_staged_release(guard);
      free(path);
      goto latch;
    }
  }
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd < 0) {
    set_detail(&detail, "%s", strerror(errno));
    fs = MURMUR_FILES_IO;
    free(identity_path);
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    goto latch;
  }
  uint64_t total = offset;
  int complete = 0;
  for (;;) {
    murmur_file_frame_t fr;
    memset(&fr, 0, sizeof(fr));
    uint8_t *fowned = NULL;
    fs = fetch_read_frame(&io, &fr, &fowned, &detail);
    if (fs != MURMUR_FILES_OK) {
      close(fd);
      free(identity_path);
      murmur_stream_release(stream);
      murmur_session_close(sess);
      murmur_session_release(sess);
      murmur_files_staged_release(guard);
      free(path);
      goto latch;
    }
    if (fr.kind == MURMUR_FILE_CHUNK_FRAME) {
      if (fr.data_len > FETCH_CHUNK) {
        free(fowned);
        close(fd);
        free(identity_path);
        murmur_stream_release(stream);
        murmur_session_close(sess);
        murmur_session_release(sess);
        murmur_files_staged_release(guard);
        free(path);
        set_detail(&detail, "file chunk bounds");
        fs = MURMUR_FILES_PROTOCOL;
        goto latch;
      }
      total += (uint64_t)fr.data_len;
      if (total > bytes) {
        free(fowned);
        close(fd);
        free(identity_path);
        murmur_stream_release(stream);
        murmur_session_close(sess);
        murmur_session_release(sess);
        murmur_files_staged_release(guard);
        free(path);
        set_detail(&detail, "file container length");
        fs = MURMUR_FILES_PROTOCOL;
        goto latch;
      }
      size_t wrote = 0;
      int bad = 0;
      while (wrote < fr.data_len) {
        ssize_t r = write(fd, fr.data + wrote, fr.data_len - wrote);
        if (r <= 0) {
          bad = 1;
          break;
        }
        wrote += (size_t)r;
      }
      free(fowned);
      if (bad) {
        close(fd);
        set_detail(&detail, "%s", strerror(errno));
        fs = MURMUR_FILES_IO;
        free(identity_path);
        murmur_stream_release(stream);
        murmur_session_close(sess);
        murmur_session_release(sess);
        murmur_files_staged_release(guard);
        free(path);
        goto latch;
      }
    } else if (fr.kind == MURMUR_FILE_DONE) {
      free(fowned);
      complete = 1;
      break;
    } else {
      free(fowned);
      close(fd);
      free(identity_path);
      murmur_stream_release(stream);
      murmur_session_close(sess);
      murmur_session_release(sess);
      murmur_files_staged_release(guard);
      free(path);
      set_detail(&detail, "file transfer frame");
      fs = MURMUR_FILES_PROTOCOL;
      goto latch;
    }
  }
  (void)complete;
  if (fsync(fd) != 0) {
    close(fd);
    set_detail(&detail, "%s", strerror(errno));
    fs = MURMUR_FILES_IO;
    free(identity_path);
    murmur_stream_release(stream);
    murmur_session_close(sess);
    murmur_session_release(sess);
    murmur_files_staged_release(guard);
    free(path);
    goto latch;
  }
  close(fd);
  murmur_stream_release(stream);
  murmur_session_close(sess);
  murmur_session_release(sess);
  if (total != bytes) {
    free(identity_path);
    murmur_files_staged_release(guard);
    free(path);
    set_detail(&detail, "incomplete file container");
    fs = MURMUR_FILES_UNAVAILABLE;
    goto latch;
  }
  fs = publish_staged(s, path, identity_path, meta, &detail);
  /* Drop resume state before availability bookkeeping: once the
   * object is published the sidecar is garbage. */
  unlink(identity_path);
  free(identity_path);
  murmur_files_staged_release(guard);
  if (fs != MURMUR_FILES_OK) {
    free(path);
    goto latch;
  }
  free(path);
  fs = murmur_files_record_peer(s->objects, meta->digest, meta->generation,
                                &source->node, 1, &detail, &sqlrc);
latch:
  if (fs != MURMUR_FILES_OK) {
    murmur_files_fetch_error(s->objects, detail ? detail : "file fetch");
  }
  free(detail);
  return fs;
}

/* ---------- scheduler step ---------- */

typedef struct {
  murmur_fetch_t *s;
  murmur_fetch_source_t *sources;
  size_t n_sources;
  murmur_files_meta_t meta;
  int staging_units;
} fetch_job_t;

static void *fetch_thread(void *arg) {
  fetch_job_t *job = arg;
  murmur_fetch_t *s = job->s;
  uint64_t container =
      sat_add(job->meta.bytes, job->meta.bytes / FETCH_CHUNK * 20 + 256);
  murmur_staging_reservation_t *reservation = NULL;
  char *detail = NULL;
  if (murmur_files_reserve_staging(s->objects, container, &reservation) !=
      MURMUR_FILES_OK) {
    murmur_files_fetch_error(s->objects, "replication overloaded");
  } else {
    for (size_t i = 0; i < job->n_sources; i++) {
      murmur_files_status_t fs = fetch_one(s, &job->sources[i], &job->meta);
      if (fs == MURMUR_FILES_OK) {
        break;
      }
      /* fetch_one already latched the error. */
    }
    murmur_files_staging_release(reservation);
  }
  free(detail);
  active_remove(s, job->meta.digest);
  for (int i = 0; i < job->staging_units; i++) {
    sem_release(&s->staging_permits);
  }
  sem_release(&s->permits);
  murmur_files_meta_free(&job->meta);
  free(job->sources);
  free(job);
  worker_done(s);
  return NULL;
}

murmur_files_status_t murmur_fetch_missing(murmur_fetch_t *s,
                                           const murmur_fetch_source_t *sources,
                                           size_t n_sources, char **detail_out,
                                           int *sqlrc) {
  if (detail_out) {
    *detail_out = NULL;
  }
  murmur_files_status_t fs =
      murmur_files_reap_staging_orphans(s->objects, detail_out);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  murmur_files_meta_t *listed = NULL;
  size_t nlisted = 0;
  fs = murmur_files_list(s->objects, &listed, &nlisted, detail_out, sqlrc);
  if (fs != MURMUR_FILES_OK) {
    return fs;
  }
  for (size_t i = 0; i < nlisted; i++) {
    int avail = 0;
    fs = murmur_files_available(s->objects, listed[i].name, &avail, detail_out,
                                sqlrc);
    if (fs != MURMUR_FILES_OK) {
      break;
    }
    int dup = avail || active_contains(s, listed[i].digest);
    if (dup) {
      continue;
    }
    if (!sem_try_acquire(&s->permits)) {
      /* Permits exhausted: stop this round, retry next tick. */
      fs = MURMUR_FILES_OK;
      break;
    }
    uint64_t container = sat_add(listed[i].bytes,
                                 listed[i].bytes / FETCH_CHUNK * 20 + 256);
    if (container < listed[i].bytes) {
      sem_release(&s->permits);
      murmur_files_fetch_error(s->objects, "replication overloaded");
      continue;
    }
    if (container > s->max_staging) {
      sem_release(&s->permits);
      murmur_files_fetch_error(s->objects, "replication overloaded");
      continue;
    }
    uint64_t c1 = container > 1 ? container : 1;
    uint64_t units = div_ceil(c1, 1u << 20);
    if (units > (uint64_t)0xffffffffu) {
      units = 0xffffffffu;
    }
    int acquired = 1;
    for (uint64_t u = 0; u < units; u++) {
      if (!sem_try_acquire(&s->staging_permits)) {
        for (uint64_t v = 0; v < u; v++) {
          sem_release(&s->staging_permits);
        }
        acquired = 0;
        break;
      }
    }
    if (!acquired) {
      sem_release(&s->permits);
      continue;
    }
    fetch_job_t *job = malloc(sizeof(*job));
    murmur_fetch_source_t *scopy = NULL;
    if (n_sources) {
      scopy = malloc(n_sources * sizeof(*scopy));
    }
    if (!job || (n_sources && !scopy)) {
      free(job);
      free(scopy);
      for (uint64_t u = 0; u < units; u++) {
        sem_release(&s->staging_permits);
      }
      sem_release(&s->permits);
      set_detail(detail_out, "file fetch spawn");
      fs = MURMUR_FILES_IO;
      break;
    }
    if (n_sources) {
      memcpy(scopy, sources, n_sources * sizeof(*scopy));
    }
    memset(job, 0, sizeof(*job));
    job->s = s;
    job->sources = scopy;
    job->n_sources = n_sources;
    job->meta.name = strdup(listed[i].name);
    if (!job->meta.name) {
      free(job);
      free(scopy);
      for (uint64_t u = 0; u < units; u++) {
        sem_release(&s->staging_permits);
      }
      sem_release(&s->permits);
      set_detail(detail_out, "file fetch spawn");
      fs = MURMUR_FILES_IO;
      break;
    }
    memcpy(job->meta.digest, listed[i].digest, 32);
    job->meta.bytes = listed[i].bytes;
    job->meta.generation = listed[i].generation;
    job->meta.millis = listed[i].millis;
    job->meta.node = listed[i].node;
    job->staging_units = (int)units;
    active_add(s, listed[i].digest);
    worker_add(s);
    pthread_t th;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &attr, fetch_thread, job) != 0) {
      pthread_attr_destroy(&attr);
      worker_done(s);
      active_remove(s, listed[i].digest);
      for (uint64_t u = 0; u < units; u++) {
        sem_release(&s->staging_permits);
      }
      sem_release(&s->permits);
      murmur_files_meta_free(&job->meta);
      free(job->sources);
      free(job);
      set_detail(detail_out, "file fetch spawn");
      fs = MURMUR_FILES_IO;
      break;
    }
    pthread_attr_destroy(&attr);
  }
  murmur_files_meta_list_free(listed, nlisted);
  return fs;
}
