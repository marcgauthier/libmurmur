/* transporttest - direct QUIC transport suites over real loopback.
 *
 * Exercises murmur_quic_* / murmur_session_* / murmur_stream_* with the
 * testdata mTLS certs (node-a / node-b, test CA): handshake identity,
 * stream echo / large / parallel payloads, datagrams, timeouts, the
 * allowlist/CIDR/ALPN gates, close semantics, and argument validation.
 *
 * Usage: ./build/transporttest [testdata-dir]
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/pem.h"
#include "member.h"
#include "transport.h"

static int failures = 0;
static int suites = 0;

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static void sleep_ms(long ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000 * 1000;
  nanosleep(&ts, NULL);
}

static murmur_node_t node_fill(uint8_t b) {
  murmur_node_t n;
  memset(n.b, b, sizeof(n.b));
  return n;
}

/* ---------- PEM loading (DER via mbedtls, like fetch_selftest) ---------- */

static uint8_t *slurp(const char *path, size_t *n_out) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *b = malloc((size_t)n + 1);
  if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
    fclose(f);
    free(b);
    return NULL;
  }
  fclose(f);
  b[n] = 0;
  *n_out = (size_t)n;
  return b;
}

static int load_certs(const char *path, uint8_t ***ders, size_t **lens,
                      size_t *n) {
  *ders = NULL;
  *lens = NULL;
  *n = 0;
  size_t raw_len = 0;
  uint8_t *raw = slurp(path, &raw_len);
  if (!raw) {
    return -1;
  }
  uint8_t **ds = NULL;
  size_t *ls = NULL, nd = 0, cap = 0;
  size_t off = 0;
  int rc = 0;
  while (off < raw_len) {
    mbedtls_pem_context pc;
    mbedtls_pem_init(&pc);
    size_t used = 0;
    if (mbedtls_pem_read_buffer(&pc, "-----BEGIN CERTIFICATE-----",
                                "-----END CERTIFICATE-----", raw + off, NULL,
                                0, &used) != 0) {
      mbedtls_pem_free(&pc);
      break;
    }
    size_t blen = 0;
    const uint8_t *der = mbedtls_pem_get_buffer(&pc, &blen);
    if (nd >= cap) {
      size_t ncap = cap ? cap * 2 : 4;
      uint8_t **nders = realloc(ds, ncap * sizeof(*nders));
      size_t *nlens = realloc(ls, ncap * sizeof(*nlens));
      if (!nders || !nlens) {
        free(nders);
        free(nlens);
        mbedtls_pem_free(&pc);
        rc = -1;
        break;
      }
      ds = nders;
      ls = nlens;
      cap = ncap;
    }
    ds[nd] = malloc(blen);
    if (!ds[nd]) {
      mbedtls_pem_free(&pc);
      rc = -1;
      break;
    }
    memcpy(ds[nd], der, blen);
    ls[nd] = blen;
    nd++;
    off += used;
    mbedtls_pem_free(&pc);
  }
  free(raw);
  if (rc != 0 || nd == 0) {
    for (size_t i = 0; i < nd; i++) {
      free(ds[i]);
    }
    free(ds);
    free(ls);
    return -1;
  }
  *ders = ds;
  *lens = ls;
  *n = nd;
  return 0;
}

static void free_certs(uint8_t **ders, size_t *lens, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(ders[i]);
  }
  free(ders);
  free(lens);
}

typedef struct {
  uint8_t **chain_a, **chain_b, **ca;
  size_t *chain_a_lens, *chain_b_lens, *ca_lens;
  size_t n_chain_a, n_chain_b, n_ca;
  uint8_t *key_a, *key_b;
  size_t key_a_len, key_b_len;
  murmur_node_t node_a, node_b, node_unknown;
} creds_t;

static int creds_load(creds_t *c, const char *td) {
  memset(c, 0, sizeof(*c));
  c->node_a = node_fill(0xA0);
  c->node_b = node_fill(0xB0);
  c->node_unknown = node_fill(0xC0);
  char path[512];
  snprintf(path, sizeof(path), "%s/node-a.pem", td);
  if (load_certs(path, &c->chain_a, &c->chain_a_lens, &c->n_chain_a) != 0) {
    printf("FAIL chain %s\n", path);
    failures++;
    return 0;
  }
  snprintf(path, sizeof(path), "%s/node-b.pem", td);
  if (load_certs(path, &c->chain_b, &c->chain_b_lens, &c->n_chain_b) != 0) {
    printf("FAIL chain %s\n", path);
    failures++;
    return 0;
  }
  snprintf(path, sizeof(path), "%s/ca.pem", td);
  if (load_certs(path, &c->ca, &c->ca_lens, &c->n_ca) != 0) {
    printf("FAIL chain %s\n", path);
    failures++;
    return 0;
  }
  snprintf(path, sizeof(path), "%s/node-a-key.pem", td);
  c->key_a = slurp(path, &c->key_a_len);
  if (!c->key_a) {
    printf("FAIL key %s\n", path);
    failures++;
    return 0;
  }
  snprintf(path, sizeof(path), "%s/node-b-key.pem", td);
  c->key_b = slurp(path, &c->key_b_len);
  if (!c->key_b) {
    printf("FAIL key %s\n", path);
    failures++;
    return 0;
  }
  return 1;
}

static void creds_free(creds_t *c) {
  free_certs(c->chain_a, c->chain_a_lens, c->n_chain_a);
  free_certs(c->chain_b, c->chain_b_lens, c->n_chain_b);
  free_certs(c->ca, c->ca_lens, c->n_ca);
  free(c->key_a);
  free(c->key_b);
}

/* ---------- endpoint helpers ---------- */

/* Splits "ip:port" at the last colon. Returns 1 on success. */
static int split_addr(const char *s, char *ip, size_t ip_cap,
                      uint16_t *port) {
  const char *colon = strrchr(s, ':');
  if (!colon) {
    return 0;
  }
  size_t iplen = (size_t)(colon - s);
  if (iplen + 1 > ip_cap) {
    return 0;
  }
  memcpy(ip, s, iplen);
  ip[iplen] = 0;
  long p = atol(colon + 1);
  if (p <= 0 || p > 65535) {
    return 0;
  }
  *port = (uint16_t)p;
  return 1;
}

static int mk_endpoint(creds_t *c, int which_a, murmur_quic_t **out) {
  uint8_t **chain = which_a ? c->chain_a : c->chain_b;
  size_t *lens = which_a ? c->chain_a_lens : c->chain_b_lens;
  size_t n = which_a ? c->n_chain_a : c->n_chain_b;
  uint8_t *key = which_a ? c->key_a : c->key_b;
  size_t key_len = which_a ? c->key_a_len : c->key_b_len;
  murmur_node_t *self = which_a ? &c->node_a : &c->node_b;
  return murmur_quic_create(out, "127.0.0.1", 0,
                            (const uint8_t **)chain, lens, n, key, key_len,
                            (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0,
                            self, NULL, 0, NULL, 0, 0, 0);
}

/* Dials a->b and accepts on b. Returns 1 with both sessions set. */
static int establish(murmur_quic_t *qa, murmur_quic_t *qb,
                     murmur_session_t **sa_out,
                     murmur_session_t **sb_out) {
  char addr[96];
  char ip[80];
  uint16_t port = 0;
  if (murmur_quic_local_addr(qb, addr, sizeof(addr)) != 0 ||
      !split_addr(addr, ip, sizeof(ip), &port)) {
    return 0;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  if (murmur_quic_dial(qa, ip, port, "murmur.invalid", &sa, 10000) != 0) {
    return 0;
  }
  if (murmur_quic_accept(qb, &sb, 10000) != 0) {
    murmur_session_close(sa);
    murmur_session_release(sa);
    return 0;
  }
  *sa_out = sa;
  *sb_out = sb;
  return 1;
}

static void close_session(murmur_session_t *s) {
  if (!s) {
    return;
  }
  murmur_session_close(s);
  murmur_session_release(s);
}

/* Reads exactly n bytes (no FIN expected). Returns 1 on exact match. */
static int read_exact(murmur_stream_t *st, uint8_t *buf, size_t n) {
  size_t got = 0;
  while (got < n) {
    size_t m = 0;
    int rc = murmur_stream_read_timeout(st, buf + got, n - got, &m, 10000);
    if (rc != 0 || m == 0) {
      return 0;
    }
    got += m;
  }
  return 1;
}

/* ---------- suites ---------- */

static void suite_args(creds_t *c) {
  suites++;
  murmur_quic_t *q = NULL;
  /* NULL / empty / zero credential shapes. */
  CHECK(murmur_quic_create(NULL, "127.0.0.1", 0,
                           (const uint8_t **)c->chain_a, c->chain_a_lens,
                           c->n_chain_a, c->key_a, c->key_a_len,
                           (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0,
                           &c->node_a, NULL, 0, NULL, 0, 0,
                           0) == -MURMUR_QUIC_INVALID,
        "create NULL out");
  CHECK(murmur_quic_create(&q, "127.0.0.1", 0, NULL, NULL, 0, c->key_a,
                           c->key_a_len, (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0, &c->node_a, NULL, 0, NULL, 0, 0,
                           0) == -MURMUR_QUIC_INVALID,
        "create empty chain");
  CHECK(q == NULL, "failed create leaves NULL");
  CHECK(murmur_quic_create(&q, "127.0.0.1", 0,
                           (const uint8_t **)c->chain_a, c->chain_a_lens,
                           c->n_chain_a, NULL, 0, (const uint8_t **)c->ca,
                           c->ca_lens, c->n_ca, NULL, 0, &c->node_a, NULL, 0, NULL, 0,
                           0, 0) == -MURMUR_QUIC_INVALID,
        "create NULL key");
  CHECK(murmur_quic_create(&q, "127.0.0.1", 0,
                           (const uint8_t **)c->chain_a, c->chain_a_lens,
                           c->n_chain_a, c->key_a, c->key_a_len, NULL, NULL, 0, NULL, 0, &c->node_a, NULL, 0, NULL, 0, 0,
                           0) == -MURMUR_QUIC_INVALID,
        "create empty CA");
  CHECK(murmur_quic_create(&q, "127.0.0.1", 0,
                           (const uint8_t **)c->chain_a, c->chain_a_lens,
                           c->n_chain_a, c->key_a, c->key_a_len,
                           (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0, NULL,
                           NULL, 0, NULL, 0, 0, 0) == -MURMUR_QUIC_INVALID,
        "create NULL self");
  const char *bad_cidr[] = {"not-a-cidr"};
  CHECK(murmur_quic_create(&q, "127.0.0.1", 0,
                           (const uint8_t **)c->chain_a, c->chain_a_lens,
                           c->n_chain_a, c->key_a, c->key_a_len,
                           (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0,
                           &c->node_a, NULL, 0, bad_cidr, 1, 0,
                           0) == -MURMUR_QUIC_INVALID,
        "create bad CIDR");
  CHECK(murmur_quic_create_alpn(&q, "127.0.0.1", 0,
                                (const uint8_t **)c->chain_a, c->chain_a_lens,
                                c->n_chain_a, c->key_a, c->key_a_len,
                                (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0,
                                &c->node_a, NULL, 0, NULL, 0, 0, 0,
                                NULL) == -MURMUR_QUIC_INVALID,
        "create NULL ALPN");
  CHECK(murmur_quic_create_alpn(&q, "127.0.0.1", 0,
                                (const uint8_t **)c->chain_a, c->chain_a_lens,
                                c->n_chain_a, c->key_a, c->key_a_len,
                                (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0,
                                &c->node_a, NULL, 0, NULL, 0, 0, 0,
                                "") == -MURMUR_QUIC_INVALID,
        "create empty ALPN");
  /* Leaf identity must equal the configured self. */
  CHECK(murmur_quic_create(&q, "127.0.0.1", 0,
                           (const uint8_t **)c->chain_a, c->chain_a_lens,
                           c->n_chain_a, c->key_a, c->key_a_len,
                           (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0,
                           &c->node_b, NULL, 0, NULL, 0, 0,
                           0) == -MURMUR_QUIC_AUTH,
        "create self mismatch");
  /* Unparseable CRL bytes fail create closed. */
  {
    static const uint8_t garbage[] = "not a crl";
    q = NULL;
    CHECK(murmur_quic_create(&q, "127.0.0.1", 0,
                             (const uint8_t **)c->chain_a, c->chain_a_lens,
                             c->n_chain_a, c->key_a, c->key_a_len,
                             (const uint8_t **)c->ca, c->ca_lens, c->n_ca,
                             garbage, sizeof(garbage) - 1, &c->node_a, NULL, 0,
                             NULL, 0, 0, 0) == -MURMUR_QUIC_INVALID,
          "create garbage CRL accepted");
    CHECK(q == NULL, "garbage CRL leaves NULL");
  }
  /* NULL-handle calls fail closed (or are safe no-ops). */
  char buf[64];
  size_t n = 0;
  murmur_node_t id;
  murmur_session_t *s = NULL;
  murmur_stream_t *st = NULL;
  uint8_t byte = 0;
  CHECK(murmur_quic_local_addr(NULL, buf, sizeof(buf)) ==
            -MURMUR_QUIC_INVALID,
        "local_addr NULL");
  CHECK(murmur_quic_accept(NULL, &s, 100) == -MURMUR_QUIC_INVALID,
        "accept NULL");
  CHECK(murmur_quic_dial(NULL, "127.0.0.1", 1, NULL, &s, 100) ==
            -MURMUR_QUIC_INVALID,
        "dial NULL");
  CHECK(murmur_session_peer(NULL, &id) == -MURMUR_QUIC_INVALID,
        "peer NULL");
  CHECK(murmur_session_open_stream(NULL, &st) == -MURMUR_QUIC_INVALID,
        "open_stream NULL");
  CHECK(murmur_session_accept_stream(NULL, &st, 100) ==
            -MURMUR_QUIC_INVALID,
        "accept_stream NULL");
  CHECK(murmur_session_send_datagram(NULL, &byte, 1) ==
            -MURMUR_QUIC_INVALID,
        "send_datagram NULL");
  CHECK(murmur_session_send_datagram(s, NULL, 1) == -MURMUR_QUIC_INVALID,
        "send_datagram NULL data");
  CHECK(murmur_session_recv_datagram(NULL, &byte, 1, &n, 100) ==
            -MURMUR_QUIC_INVALID,
        "recv_datagram NULL");
  CHECK(murmur_session_wait_closed(NULL, 100) == -MURMUR_QUIC_INVALID,
        "wait_closed NULL");
  CHECK(murmur_session_remote_addr(NULL, buf, sizeof(buf)) ==
            -MURMUR_QUIC_INVALID,
        "remote_addr NULL");
  CHECK(murmur_stream_write(NULL, &byte, 1) == -MURMUR_QUIC_INVALID,
        "stream_write NULL");
  CHECK(murmur_stream_read_timeout(NULL, &byte, 1, &n, 100) ==
            -MURMUR_QUIC_INVALID,
        "stream_read NULL");
  CHECK(murmur_last_error(NULL, buf, sizeof(buf)) == -MURMUR_QUIC_INVALID,
        "last_error NULL");
  CHECK(murmur_quic_close(NULL) == 0, "quic_close NULL");
  CHECK(murmur_session_close(NULL) == 0, "session_close NULL");
  CHECK(murmur_stream_close(NULL) == 0, "stream_close NULL");
  CHECK(murmur_session_acquire(NULL) == NULL, "acquire NULL");
  murmur_quic_free(NULL);
  murmur_session_release(NULL);
  murmur_stream_release(NULL);
  /* Bind conflict surfaces BUSY: a plain UDP socket (no SO_REUSEADDR)
   * holds an ephemeral loopback port, so the endpoint bind fails. */
  {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
      struct sockaddr_in ha;
      memset(&ha, 0, sizeof(ha));
      ha.sin_family = AF_INET;
      ha.sin_port = 0;
      if (inet_pton(AF_INET, "127.0.0.1", &ha.sin_addr) == 1 &&
          bind(fd, (struct sockaddr *)&ha, sizeof(ha)) == 0) {
        socklen_t sl = sizeof(ha);
        if (getsockname(fd, (struct sockaddr *)&ha, &sl) == 0) {
          murmur_quic_t *qb = NULL;
          int rc = murmur_quic_create(
              &qb, "127.0.0.1", ntohs(ha.sin_port),
              (const uint8_t **)c->chain_b, c->chain_b_lens, c->n_chain_b,
              c->key_b, c->key_b_len, (const uint8_t **)c->ca, c->ca_lens, c->n_ca, NULL, 0, &c->node_b, NULL, 0, NULL, 0, 0, 0);
          CHECK(rc == -MURMUR_QUIC_BUSY, "bind conflict BUSY, got %d", rc);
          murmur_quic_free(qb);
        } else {
          CHECK(0, "bind holder addr");
        }
      } else {
        CHECK(0, "bind holder bind");
      }
      close(fd);
    } else {
      CHECK(0, "bind holder socket");
    }
  }
}

static void suite_handshake(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  CHECK(mk_endpoint(c, 1, &qa) == 0, "handshake qa up");
  CHECK(mk_endpoint(c, 0, &qb) == 0, "handshake qb up");
  if (!qa || !qb) {
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "handshake dial+accept");
  if (sa && sb) {
    murmur_node_t pa, pb;
    CHECK(murmur_session_peer(sa, &pa) == 0 && murmur_node_eq(&pa, &c->node_b),
          "dialer sees peer B");
    CHECK(murmur_session_peer(sb, &pb) == 0 && murmur_node_eq(&pb, &c->node_a),
          "acceptor sees peer A");
    char la[96], lb[96], ra[96], rb[96], ip[80];
    uint16_t port = 0;
    CHECK(murmur_quic_local_addr(qa, la, sizeof(la)) == 0 &&
              split_addr(la, ip, sizeof(ip), &port) &&
              strcmp(ip, "127.0.0.1") == 0 && port != 0,
          "local addr A (%s)", la);
    CHECK(murmur_quic_local_addr(qb, lb, sizeof(lb)) == 0, "local addr B");
    CHECK(murmur_session_remote_addr(sa, ra, sizeof(ra)) == 0 &&
              strcmp(ra, lb) == 0,
          "remote addr matches (%s vs %s)", ra, lb);
    CHECK(murmur_session_remote_addr(sb, rb, sizeof(rb)) == 0 &&
              strcmp(rb, la) == 0,
          "remote addr reverse");
    char err[128];
    CHECK(murmur_last_error(qa, err, sizeof(err)) == 0 && err[0] == 0,
          "last_error empty");
    /* Handle refcount: acquire returns the same handle. */
    murmur_session_t *tmp = murmur_session_acquire(sa);
    CHECK(tmp == sa, "acquire same handle");
    murmur_session_release(tmp);
    CHECK(murmur_session_acquire(NULL) == NULL, "acquire NULL");
    close_session(sa);
    close_session(sb);
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_stream_echo(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  if (mk_endpoint(c, 1, &qa) != 0 || mk_endpoint(c, 0, &qb) != 0) {
    CHECK(0, "echo endpoints up");
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "echo establish");
  if (sa && sb) {
    murmur_stream_t *w = NULL, *r = NULL;
    CHECK(murmur_session_open_stream(sa, &w) == 0, "echo open");
    const char *msg = "hello-quic";
    CHECK(w && murmur_stream_write(w, (const uint8_t *)msg, strlen(msg)) == 0,
          "echo write");
    CHECK(murmur_session_accept_stream(sb, &r, 10000) == 0, "echo accept");
    if (r) {
      uint8_t buf[32];
      CHECK(read_exact(r, buf, strlen(msg)) &&
                memcmp(buf, msg, strlen(msg)) == 0,
            "echo bytes exact");
      const char *rep = "ack";
      CHECK(murmur_stream_write(r, (const uint8_t *)rep, strlen(rep)) == 0,
            "echo reply");
      CHECK(murmur_stream_close(r) == 0, "echo reply FIN");
      uint8_t back[8];
      CHECK(read_exact(w, back, strlen(rep)) &&
                memcmp(back, rep, strlen(rep)) == 0,
            "echo reply exact");
      /* Peer FIN surfaces as a zero-length read. */
      size_t m = 0;
      uint8_t one = 0;
      int rc = murmur_stream_read_timeout(w, &one, 1, &m, 10000);
      CHECK(rc == 0 && m == 0, "echo FIN zero read, rc=%d m=%zu", rc, m);
      murmur_stream_release(r);
    }
    if (w) {
      murmur_stream_close(w);
      murmur_stream_release(w);
    }
    close_session(sa);
    close_session(sb);
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_stream_large(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  if (mk_endpoint(c, 1, &qa) != 0 || mk_endpoint(c, 0, &qb) != 0) {
    CHECK(0, "large endpoints up");
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "large establish");
  if (sa && sb) {
    const size_t total = 256u << 10;
    uint8_t *pay = malloc(total);
    uint8_t *got = malloc(total);
    if (pay && got) {
      for (size_t i = 0; i < total; i++) {
        pay[i] = (uint8_t)(i * 31u + 7u);
      }
      murmur_stream_t *w = NULL, *r = NULL;
      CHECK(murmur_session_open_stream(sa, &w) == 0, "large open");
      CHECK(w && murmur_stream_write(w, pay, total) == 0, "large write");
      if (w) {
        murmur_stream_close(w);
      }
      CHECK(murmur_session_accept_stream(sb, &r, 10000) == 0, "large accept");
      if (r) {
        size_t off = 0;
        int ok = 1;
        while (off < total) {
          size_t m = 0;
          int rc = murmur_stream_read_timeout(r, got + off, total - off, &m,
                                              10000);
          if (rc != 0 || m == 0) {
            ok = 0;
            break;
          }
          off += m;
        }
        CHECK(ok && off == total, "large drained %zu/%zu", off, total);
        CHECK(memcmp(pay, got, total) == 0, "large bytes exact");
        murmur_stream_release(r);
      }
      if (w) {
        murmur_stream_release(w);
      }
    } else {
      CHECK(0, "large alloc");
    }
    free(pay);
    free(got);
    close_session(sa);
    close_session(sb);
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_stream_parallel(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  if (mk_endpoint(c, 1, &qa) != 0 || mk_endpoint(c, 0, &qb) != 0) {
    CHECK(0, "parallel endpoints up");
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "parallel establish");
  if (sa && sb) {
    /* Open both before writing either: the transport must reserve
     * distinct stream ids up front (no cross-wired byte flows). */
    murmur_stream_t *w1 = NULL, *w2 = NULL;
    CHECK(murmur_session_open_stream(sa, &w1) == 0, "parallel open 1");
    CHECK(murmur_session_open_stream(sa, &w2) == 0, "parallel open 2");
    const char *p1 = "stream-one";
    const char *p2 = "stream-two";
    int ok = w1 && w2 &&
             murmur_stream_write(w1, (const uint8_t *)p1, strlen(p1)) == 0 &&
             murmur_stream_write(w2, (const uint8_t *)p2, strlen(p2)) == 0;
    CHECK(ok, "parallel writes");
    murmur_stream_t *r1 = NULL, *r2 = NULL;
    CHECK(murmur_session_accept_stream(sb, &r1, 10000) == 0,
          "parallel accept 1");
    CHECK(murmur_session_accept_stream(sb, &r2, 10000) == 0,
          "parallel accept 2");
    if (r1 && r2) {
      uint8_t b1[16], b2[16];
      int g1 = read_exact(r1, b1, strlen(p1));
      int g2 = read_exact(r2, b2, strlen(p2));
      CHECK(g1 && g2, "parallel drained");
      /* Accept order is unspecified: compare as a set. */
      int straight = memcmp(b1, p1, strlen(p1)) == 0 &&
                     memcmp(b2, p2, strlen(p2)) == 0;
      int swapped = memcmp(b1, p2, strlen(p2)) == 0 &&
                    memcmp(b2, p1, strlen(p1)) == 0;
      CHECK(straight || swapped, "parallel payloads distinct");
      murmur_stream_release(r1);
      murmur_stream_release(r2);
    }
    if (w1) {
      murmur_stream_close(w1);
      murmur_stream_release(w1);
    }
    if (w2) {
      murmur_stream_close(w2);
      murmur_stream_release(w2);
    }
    close_session(sa);
    close_session(sb);
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_datagrams(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  if (mk_endpoint(c, 1, &qa) != 0 || mk_endpoint(c, 0, &qb) != 0) {
    CHECK(0, "dgram endpoints up");
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "dgram establish");
  if (sa && sb) {
    const char *ping = "ping-1";
    const char *pong = "pong-1";
    uint8_t buf[1200];
    size_t n = 0;
    CHECK(murmur_session_send_datagram(sa, (const uint8_t *)ping,
                                       strlen(ping)) == 0,
          "dgram send A->B");
    CHECK(murmur_session_recv_datagram(sb, buf, sizeof(buf), &n, 10000) == 0 &&
              n == strlen(ping) && memcmp(buf, ping, n) == 0,
          "dgram recv A->B exact");
    CHECK(murmur_session_send_datagram(sb, (const uint8_t *)pong,
                                       strlen(pong)) == 0,
          "dgram send B->A");
    CHECK(murmur_session_recv_datagram(sa, buf, sizeof(buf), &n, 10000) == 0 &&
              n == strlen(pong) && memcmp(buf, pong, n) == 0,
          "dgram recv B->A exact");
    /* Oversize sends fail without touching the wire. */
    uint8_t big[1001];
    memset(big, 0x5a, sizeof(big));
    CHECK(murmur_session_send_datagram(sa, big, sizeof(big)) ==
              -MURMUR_QUIC_OVERLOADED,
          "dgram oversize rejected");
    /* Idle recv times out. */
    n = 0;
    CHECK(murmur_session_recv_datagram(sb, buf, sizeof(buf), &n, 200) ==
              -MURMUR_QUIC_TIMEOUT,
          "dgram recv timeout");
    /* A short buffer keeps the datagram queued for a retry. */
    uint8_t med[100];
    for (size_t i = 0; i < sizeof(med); i++) {
      med[i] = (uint8_t)i;
    }
    CHECK(murmur_session_send_datagram(sa, med, sizeof(med)) == 0,
          "dgram send medium");
    sleep_ms(500);
    n = 0;
    CHECK(murmur_session_recv_datagram(sb, buf, 10, &n, 10000) ==
              -MURMUR_QUIC_OVERLOADED,
          "dgram short buffer");
    n = 0;
    CHECK(murmur_session_recv_datagram(sb, buf, sizeof(buf), &n, 10000) == 0 &&
              n == sizeof(med) && memcmp(buf, med, n) == 0,
          "dgram retry exact");
    close_session(sa);
    close_session(sb);
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_timeouts(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  if (mk_endpoint(c, 1, &qa) != 0 || mk_endpoint(c, 0, &qb) != 0) {
    CHECK(0, "timeout endpoints up");
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "timeout establish");
  if (sa && sb) {
    murmur_stream_t *r = NULL;
    CHECK(murmur_session_accept_stream(sb, &r, 200) == -MURMUR_QUIC_TIMEOUT,
          "accept_stream timeout");
    /* Read timeout on a live stream with no pending bytes and no FIN. */
    murmur_stream_t *w = NULL, *rr = NULL;
    if (murmur_session_open_stream(sa, &w) == 0 && w) {
      uint8_t one = 0x42;
      CHECK(murmur_stream_write(w, &one, 1) == 0, "timeout probe write");
      CHECK(murmur_session_accept_stream(sb, &rr, 10000) == 0,
            "timeout probe accept");
      if (rr) {
        uint8_t b = 0;
        CHECK(read_exact(rr, &b, 1) && b == 0x42, "timeout probe byte");
        size_t m = 0;
        CHECK(murmur_stream_read_timeout(rr, &b, 1, &m, 200) ==
                  -MURMUR_QUIC_TIMEOUT,
              "stream read timeout");
        murmur_stream_release(rr);
      }
      murmur_stream_close(w);
      murmur_stream_release(w);
    } else {
      CHECK(0, "timeout probe open");
    }
    close_session(sa);
    close_session(sb);
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

/* Server-side gates refuse with an ordered close: the server never
 * surfaces the session, and a dial that slipped through observes the
 * close promptly. Returns 1 when the refusal is proven. */
static int expect_server_refusal(murmur_quic_t *qa, murmur_quic_t *qb,
                                 const char *what) {
  char addr[96], ip[80];
  uint16_t port = 0;
  if (murmur_quic_local_addr(qb, addr, sizeof(addr)) != 0 ||
      !split_addr(addr, ip, sizeof(ip), &port)) {
    CHECK(0, "%s addr", what);
    return 0;
  }
  murmur_session_t *sa = NULL;
  int drc =
      murmur_quic_dial(qa, ip, port, "murmur.invalid", &sa, 10000);
  murmur_session_t *sb = NULL;
  int arc = murmur_quic_accept(qb, &sb, 2000);
  CHECK(arc == -MURMUR_QUIC_TIMEOUT, "%s server accept refused (%d)", what,
        arc);
  if (sb) {
    murmur_session_close(sb);
    murmur_session_release(sb);
  }
  if (drc != 0) {
    CHECK(sa == NULL, "%s failed dial leaves NULL", what);
    return arc == -MURMUR_QUIC_TIMEOUT;
  }
  int wrc = murmur_session_wait_closed(sa, 10000);
  CHECK(wrc == 0, "%s dialer observes close (%d)", what, wrc);
  murmur_session_release(sa);
  char err[256];
  if (murmur_last_error(qb, err, sizeof(err)) == 0) {
    CHECK(err[0] != 0, "%s server records reason", what);
  }
  return arc == -MURMUR_QUIC_TIMEOUT && wrc == 0;
}

static void suite_server_allowlist(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  CHECK(mk_endpoint(c, 1, &qa) == 0, "allowlist qa up");
  int rc = murmur_quic_create(
      &qb, "127.0.0.1", 0, (const uint8_t **)c->chain_b, c->chain_b_lens,
      c->n_chain_b, c->key_b, c->key_b_len, (const uint8_t **)c->ca,
      c->ca_lens, c->n_ca, NULL, 0, &c->node_b, &c->node_unknown, 1, NULL, 0, 0, 0);
  CHECK(rc == 0, "allowlist qb up");
  if (qa && qb) {
    expect_server_refusal(qa, qb, "allowlist");
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_client_allowlist(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  int rc = murmur_quic_create(
      &qa, "127.0.0.1", 0, (const uint8_t **)c->chain_a, c->chain_a_lens,
      c->n_chain_a, c->key_a, c->key_a_len, (const uint8_t **)c->ca,
      c->ca_lens, c->n_ca, NULL, 0, &c->node_a, &c->node_unknown, 1, NULL, 0, 0, 0);
  CHECK(rc == 0, "dialer-gate qa up");
  CHECK(mk_endpoint(c, 0, &qb) == 0, "dialer-gate qb up");
  if (qa && qb) {
    char addr[96], ip[80];
    uint16_t port = 0;
    if (murmur_quic_local_addr(qb, addr, sizeof(addr)) == 0 &&
        split_addr(addr, ip, sizeof(ip), &port)) {
      murmur_session_t *sa = NULL;
      int drc =
          murmur_quic_dial(qa, ip, port, "murmur.invalid", &sa, 10000);
      CHECK(drc != 0, "dialer-gate dial refused (%d)", drc);
      CHECK(sa == NULL, "dialer-gate leaves NULL");
      if (sa) {
        murmur_session_close(sa);
        murmur_session_release(sa);
      }
      murmur_session_t *sb = NULL;
      CHECK(murmur_quic_accept(qb, &sb, 1000) == -MURMUR_QUIC_TIMEOUT,
            "dialer-gate no accept");
      if (sb) {
        murmur_session_close(sb);
        murmur_session_release(sb);
      }
    } else {
      CHECK(0, "dialer-gate addr");
    }
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_cidr_deny(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  CHECK(mk_endpoint(c, 1, &qa) == 0, "cidr qa up");
  const char *deny[] = {"10.255.255.0/24"};
  int rc = murmur_quic_create(
      &qb, "127.0.0.1", 0, (const uint8_t **)c->chain_b, c->chain_b_lens,
      c->n_chain_b, c->key_b, c->key_b_len, (const uint8_t **)c->ca,
      c->ca_lens, c->n_ca, NULL, 0, &c->node_b, NULL, 0, deny, 1, 0, 0);
  CHECK(rc == 0, "cidr qb up");
  if (qa && qb) {
    expect_server_refusal(qa, qb, "cidr");
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_cidr_allow(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  CHECK(mk_endpoint(c, 1, &qa) == 0, "cidr-allow qa up");
  const char *allow[] = {"127.0.0.0/8"};
  int rc = murmur_quic_create(
      &qb, "127.0.0.1", 0, (const uint8_t **)c->chain_b, c->chain_b_lens,
      c->n_chain_b, c->key_b, c->key_b_len, (const uint8_t **)c->ca,
      c->ca_lens, c->n_ca, NULL, 0, &c->node_b, NULL, 0, allow, 1, 0, 0);
  CHECK(rc == 0, "cidr-allow qb up");
  if (qa && qb) {
    murmur_session_t *sa = NULL, *sb = NULL;
    CHECK(establish(qa, qb, &sa, &sb), "cidr-allow handshake");
    if (sa && sb) {
      murmur_node_t p;
      CHECK(murmur_session_peer(sb, &p) == 0 &&
                murmur_node_eq(&p, &c->node_a),
            "cidr-allow peer");
      close_session(sa);
      close_session(sb);
    }
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_alpn_mismatch(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  CHECK(mk_endpoint(c, 1, &qa) == 0, "alpn qa up");
  int rc = murmur_quic_create_alpn(
      &qb, "127.0.0.1", 0, (const uint8_t **)c->chain_b, c->chain_b_lens,
      c->n_chain_b, c->key_b, c->key_b_len, (const uint8_t **)c->ca,
      c->ca_lens, c->n_ca, NULL, 0, &c->node_b, NULL, 0, NULL, 0, 0, 0,
      "murmur-sqlite/files/1");
  CHECK(rc == 0, "alpn qb up");
  if (qa && qb) {
    char addr[96], ip[80];
    uint16_t port = 0;
    if (murmur_quic_local_addr(qb, addr, sizeof(addr)) == 0 &&
        split_addr(addr, ip, sizeof(ip), &port)) {
      murmur_session_t *sa = NULL;
      int drc =
          murmur_quic_dial(qa, ip, port, "murmur.invalid", &sa, 5000);
      murmur_session_t *sb = NULL;
      int arc = murmur_quic_accept(qb, &sb, 2000);
      CHECK(arc == -MURMUR_QUIC_TIMEOUT, "alpn no accept (%d)", arc);
      if (sb) {
        murmur_session_close(sb);
        murmur_session_release(sb);
      }
      if (drc == 0 && sa) {
        /* A handshake that slipped through must not stay usable. */
        int wrc = murmur_session_wait_closed(sa, 10000);
        CHECK(wrc == 0, "alpn stray session closes (%d)", wrc);
        murmur_session_release(sa);
      } else {
        CHECK(sa == NULL, "alpn failed dial leaves NULL");
      }
    } else {
      CHECK(0, "alpn addr");
    }
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_close(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qb = NULL;
  if (mk_endpoint(c, 1, &qa) != 0 || mk_endpoint(c, 0, &qb) != 0) {
    CHECK(0, "close endpoints up");
    murmur_quic_free(qa);
    murmur_quic_free(qb);
    return;
  }
  murmur_session_t *sa = NULL, *sb = NULL;
  CHECK(establish(qa, qb, &sa, &sb), "close establish");
  if (sa && sb) {
    murmur_stream_t *w = NULL;
    CHECK(murmur_session_open_stream(sa, &w) == 0, "close probe open");
    CHECK(murmur_session_close(sa) == 0, "close dialer");
    CHECK(murmur_session_wait_closed(sb, 10000) == 0, "close observed");
    murmur_stream_t *late = NULL;
    CHECK(murmur_session_open_stream(sa, &late) == -MURMUR_QUIC_CLOSED,
          "open after close");
    uint8_t b = 0;
    CHECK(w && murmur_stream_write(w, &b, 1) == -MURMUR_QUIC_CLOSED,
          "write after close");
    if (w) {
      murmur_stream_release(w);
    }
    murmur_session_release(sa);
    murmur_session_release(sb);
    /* Endpoint close unblocks acceptors with CLOSED. */
    CHECK(murmur_quic_close(qa) == 0, "endpoint close");
    murmur_session_t *x = NULL;
    CHECK(murmur_quic_accept(qa, &x, 2000) == -MURMUR_QUIC_CLOSED,
          "accept after close");
    if (x) {
      murmur_session_close(x);
      murmur_session_release(x);
    }
  }
  murmur_quic_free(qa);
  murmur_quic_free(qb);
}

static void suite_dial_timeout(creds_t *c) {
  suites++;
  murmur_quic_t *qa = NULL, *qt = NULL;
  CHECK(mk_endpoint(c, 1, &qa) == 0, "dial-timeout qa up");
  CHECK(mk_endpoint(c, 0, &qt) == 0, "dial-timeout temp up");
  if (qa && qt) {
    char addr[96], ip[80];
    uint16_t port = 0;
    if (murmur_quic_local_addr(qt, addr, sizeof(addr)) == 0 &&
        split_addr(addr, ip, sizeof(ip), &port)) {
      murmur_quic_free(qt);
      qt = NULL;
      sleep_ms(200);
      murmur_session_t *sa = NULL;
      int rc = murmur_quic_dial(qa, "127.0.0.1", port, "murmur.invalid",
                                &sa, 2000);
      CHECK(rc == -MURMUR_QUIC_TIMEOUT, "dial timeout, got %d", rc);
      CHECK(sa == NULL, "dial timeout leaves NULL");
      if (sa) {
        murmur_session_close(sa);
        murmur_session_release(sa);
      }
    } else {
      CHECK(0, "dial-timeout addr");
    }
  }
  murmur_quic_free(qa);
  murmur_quic_free(qt);
}

int main(int argc, char **argv) {
  const char *td = argc > 1 ? argv[1] : "deps/murmur/testdata";
  creds_t c;
  if (!creds_load(&c, td)) {
    return 1;
  }
  suite_args(&c);
  suite_handshake(&c);
  suite_stream_echo(&c);
  suite_stream_large(&c);
  suite_stream_parallel(&c);
  suite_datagrams(&c);
  suite_timeouts(&c);
  suite_server_allowlist(&c);
  suite_client_allowlist(&c);
  suite_cidr_deny(&c);
  suite_cidr_allow(&c);
  suite_alpn_mismatch(&c);
  suite_close(&c);
  suite_dial_timeout(&c);
  creds_free(&c);
  if (failures == 0) {
    printf("TRANSPORT-OK (%d suites)\n", suites);
    return 0;
  }
  printf("TRANSPORT-FAIL (%d)\n", failures);
  return 1;
}
