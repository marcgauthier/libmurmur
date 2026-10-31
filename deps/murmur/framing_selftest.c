/* framing_selftest - ports TestPacketRoundTrip and TestGoldenPackets
 * (membership_test.go) against the vec_pkt_*.bin goldens, plus
 * strictness cases the Go suite implies (bad state/family/port,
 * oversize member list, varint overflow, short buffers).
 *
 * Usage: framingtest [testdata-dir]
 * Or: make selftest
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "framing.h"
#include "member.h"

static int failures = 0;
static const char *vecdir = "clients/go/pkgs/replication/testdata";

#define CHECK(cond, ...)                                                 \
  do {                                                                   \
    if (!(cond)) {                                                       \
      printf("FAIL %s:%d: ", __func__, __LINE__);                        \
      printf(__VA_ARGS__);                                               \
      printf("\n");                                                      \
      failures++;                                                        \
    }                                                                    \
  } while (0)

static murmur_node_t node_fill(uint8_t b) {
  murmur_node_t n;
  memset(n.b, b, sizeof(n.b));
  return n;
}

static uint8_t *load_vec(const char *name, size_t *len) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", vecdir, name);
  FILE *f = fopen(path, "rb");
  if (!f) {
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0 || n > 1 << 20) {
    fclose(f);
    return NULL;
  }
  uint8_t *b = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
  if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return b;
}

static int member_eq(const murmur_member_t *a, const murmur_member_t *b) {
  return murmur_node_eq(&a->node, &b->node) &&
         memcmp(a->addr.ip, b->addr.ip, sizeof(a->addr.ip)) == 0 &&
         a->addr.port == b->addr.port && a->addr.is6 == b->addr.is6 &&
         a->incarnation == b->incarnation && a->state == b->state;
}

/* Golden fixtures mirror TestGoldenPackets exactly. */
typedef struct {
  murmur_node_t g, n1, n2, n3, n4;
  murmur_member_t m, v6m;
} golden_t;

static void golden_init(golden_t *t) {
  t->g = node_fill(0xaa);
  t->n1 = node_fill(0x11);
  t->n2 = node_fill(0x22);
  t->n3 = node_fill(0x33);
  t->n4 = node_fill(0x44);
  t->m.node = t->n3;
  if (murmur_addr_parse(&t->m.addr, "127.0.0.1:7443") != 0) {
    CHECK(0, "addr parse v4");
  }
  t->m.incarnation = 5;
  t->m.state = MURMUR_SUSPECT;
  t->v6m.node = t->n4;
  if (murmur_addr_parse(&t->v6m.addr, "[::1]:7443") != 0) {
    CHECK(0, "addr parse v6");
  }
  t->v6m.incarnation = 300;
  t->v6m.state = MURMUR_ALIVE;
}

static void test_golden_encode(void) {
  golden_t t;
  murmur_member_t gm[2], pm[1];
  golden_init(&t);
  gm[0] = t.m;
  gm[1] = t.v6m;
  pm[0] = t.m;
  struct {
    const char *name;
    murmur_pkt_t pkt;
  } cases[] = {
      {"vec_pkt_gossip.bin",
       {.tag = MURMUR_PKT_GOSSIP, .members = gm, .n_members = 2}},
      {"vec_pkt_indirectack.bin",
       {.tag = MURMUR_PKT_INDIRECT_ACK, .nonce = 9}},
      {"vec_pkt_ping.bin",
       {.tag = MURMUR_PKT_PING, .nonce = 7, .members = pm, .n_members = 1}},
      {"vec_pkt_ack.bin", {.tag = MURMUR_PKT_ACK, .nonce = 8}},
      {"vec_pkt_pingreq.bin",
       {.tag = MURMUR_PKT_PINGREQ, .nonce = 10}},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    cases[i].pkt.database = t.g;
    cases[i].pkt.sender = t.n1;
    if (cases[i].pkt.tag == MURMUR_PKT_INDIRECT_ACK ||
        cases[i].pkt.tag == MURMUR_PKT_PINGREQ) {
      cases[i].pkt.target = t.n2;
    }
    size_t want_len = 0;
    uint8_t *want = load_vec(cases[i].name, &want_len);
    if (!want) {
      CHECK(0, "%s: cannot load", cases[i].name);
      continue;
    }
    uint8_t got[2048];
    size_t n = murmur_pkt_encode(&cases[i].pkt, got, sizeof(got));
    CHECK(n == want_len && memcmp(got, want, n) == 0, "%s: encode mismatch",
          cases[i].name);
    free(want);
  }
}

static void test_golden_decode(void) {
  golden_t t;
  golden_init(&t);
  /* (name, tag, nonce, expected members, has target) */
  struct {
    const char *name;
    murmur_pkt_tag_t tag;
    uint64_t nonce;
    int n_members;
  } cases[] = {
      {"vec_pkt_gossip.bin", MURMUR_PKT_GOSSIP, 0, 2},
      {"vec_pkt_indirectack.bin", MURMUR_PKT_INDIRECT_ACK, 9, 0},
      {"vec_pkt_ping.bin", MURMUR_PKT_PING, 7, 1},
      {"vec_pkt_ack.bin", MURMUR_PKT_ACK, 8, 0},
      {"vec_pkt_pingreq.bin", MURMUR_PKT_PINGREQ, 10, 0},
  };
  murmur_member_t want_m[2];
  memset(want_m, 0, sizeof(want_m));
  want_m[0] = t.m;
  want_m[1] = t.v6m;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t len = 0;
    uint8_t *raw = load_vec(cases[i].name, &len);
    if (!raw) {
      CHECK(0, "%s: cannot load", cases[i].name);
      continue;
    }
    murmur_pkt_t p;
    murmur_member_t mem[4];
    murmur_mship_status_t st =
        murmur_pkt_decode(raw, len, &p, mem, sizeof(mem) / sizeof(mem[0]));
    CHECK(st == MURMUR_OK, "%s: decode st=%d", cases[i].name, (int)st);
    if (st != MURMUR_OK) {
      free(raw);
      continue;
    }
    CHECK(p.tag == cases[i].tag, "%s: tag", cases[i].name);
    CHECK(murmur_node_eq(&p.database, &t.g), "%s: database", cases[i].name);
    CHECK(murmur_node_eq(&p.sender, &t.n1), "%s: sender", cases[i].name);
    CHECK(p.nonce == cases[i].nonce, "%s: nonce", cases[i].name);
    CHECK(p.n_members == (size_t)cases[i].n_members, "%s: n=%zu",
          cases[i].name, p.n_members);
    if (p.tag == MURMUR_PKT_INDIRECT_ACK || p.tag == MURMUR_PKT_PINGREQ) {
      CHECK(murmur_node_eq(&p.target, &t.n2), "%s: target", cases[i].name);
    }
    for (size_t k = 0; k < p.n_members; k++) {
      CHECK(member_eq(&p.members[k], &want_m[k]), "%s: member %zu",
            cases[i].name, k);
    }
    uint8_t rt[2048];
    size_t n = murmur_pkt_encode(&p, rt, sizeof(rt));
    CHECK(n == len && memcmp(rt, raw, n) == 0, "%s: unstable", cases[i].name);
    free(raw);
  }
}

static void test_strictness(void) {
  size_t ping_len = 0;
  uint8_t *ping = load_vec("vec_pkt_ping.bin", &ping_len);
  CHECK(ping != NULL, "load ping vector");
  if (!ping) {
    return;
  }
  murmur_pkt_t p;
  murmur_member_t mem[4];
  /* Trailing byte. */
  uint8_t trail[2048];
  memcpy(trail, ping, ping_len);
  trail[ping_len] = 0;
  CHECK(murmur_pkt_decode(trail, ping_len + 1, &p, mem, 4) ==
            MURMUR_MSHIP_PROTOCOL,
        "trailing byte accepted");
  /* Unknown tag. */
  CHECK(murmur_pkt_decode((const uint8_t *)"\x09", 1, &p, mem, 4) ==
            MURMUR_MSHIP_PROTOCOL,
        "unknown tag accepted");
  /* Truncation. */
  CHECK(murmur_pkt_decode(ping, 5, &p, mem, 4) == MURMUR_MSHIP_PROTOCOL,
        "truncation accepted");
  CHECK(murmur_pkt_decode(NULL, 0, &p, mem, 4) != MURMUR_OK,
        "null input accepted");
  /* Bad member state: gossip vector ends with the v6 member whose
   * state varint is the last byte (0=alive); flip it to 4. */
  size_t g_len = 0;
  uint8_t *gossip = load_vec("vec_pkt_gossip.bin", &g_len);
  CHECK(gossip != NULL, "load gossip vector");
  if (gossip) {
    CHECK(gossip[g_len - 1] == 0, "vector tail assumption");
    gossip[g_len - 1] = 4;
    CHECK(murmur_pkt_decode(gossip, g_len, &p, mem, 4) ==
              MURMUR_MSHIP_PROTOCOL,
          "state 4 accepted");
    free(gossip);
  }
  /* Bad address family: ping member addr family sits after
   * tag(1)+db(16)+sender(16)+nonce(1)+count(1)+node(16) = offset 51. */
  uint8_t badfam[2048];
  memcpy(badfam, ping, ping_len);
  CHECK(ping_len > 51 && ping[51] == 0, "vector layout assumption");
  badfam[51] = 2;
  CHECK(murmur_pkt_decode(badfam, ping_len, &p, mem, 4) ==
            MURMUR_MSHIP_PROTOCOL,
        "family 2 accepted");
  /* Port overflow: bytes 56.. hold the port varint (7443 = 0x93 0x3A). */
  uint8_t badport[2048];
  memcpy(badport, ping, ping_len);
  CHECK(ping_len > 58 && ping[56] == 0x93 && ping[57] == 0x3A,
        "vector port assumption");
  /* Rewrite the port as 65536 (0x80 0x80 0x04): same length. */
  badport[56] = 0x80;
  badport[57] = 0x80;
  memmove(badport + 59, badport + 58, ping_len - 58);
  badport[58] = 0x04;
  CHECK(murmur_pkt_decode(badport, ping_len + 1, &p, mem, 4) ==
            MURMUR_MSHIP_PROTOCOL,
        "port 65536 accepted");
  /* Member count over the 4096 cap. */
  uint8_t bigcount[64];
  size_t o = 0;
  bigcount[o++] = 0; /* gossip */
  memset(bigcount + o, 0xAA, 16);
  o += 16;
  memset(bigcount + o, 0x11, 16);
  o += 16;
  bigcount[o++] = 0x81;
  bigcount[o++] = 0x20; /* 4097 */
  CHECK(murmur_pkt_decode(bigcount, o, &p, mem, 4) == MURMUR_MSHIP_PROTOCOL,
        "count 4097 accepted");
  /* Varint overflow: tag never terminates. */
  uint8_t runaway[12];
  memset(runaway, 0x80, sizeof(runaway));
  CHECK(murmur_pkt_decode(runaway, sizeof(runaway), &p, mem, 4) ==
            MURMUR_MSHIP_PROTOCOL,
        "runaway varint accepted");
  /* Members array short for the decoded count. */
  CHECK(murmur_pkt_decode(ping, ping_len, &p, mem, 0) ==
            MURMUR_MSHIP_OVERLOADED,
        "short members array not reported");
  free(ping);
}

static void test_roundtrip(void) {
  murmur_member_t ms[3];
  memset(ms, 0, sizeof(ms));
  ms[0].node = node_fill(0x33);
  murmur_addr_parse(&ms[0].addr, "127.0.0.1:7443");
  ms[0].incarnation = 5;
  ms[0].state = MURMUR_SUSPECT;
  ms[1].node = node_fill(0x44);
  murmur_addr_parse(&ms[1].addr, "[::1]:7443");
  ms[1].incarnation = 300;
  ms[1].state = MURMUR_ALIVE;
  ms[2].node = node_fill(0x55);
  murmur_addr_parse(&ms[2].addr, "10.0.0.9:65535");
  ms[2].incarnation = ~0ULL;
  ms[2].state = MURMUR_LEFT;
  murmur_pkt_t pkts[] = {
      {.tag = MURMUR_PKT_GOSSIP, .members = ms, .n_members = 3},
      {.tag = MURMUR_PKT_INDIRECT_ACK, .nonce = ~0ULL},
      {.tag = MURMUR_PKT_PING, .nonce = 7, .members = ms, .n_members = 1},
      {.tag = MURMUR_PKT_ACK, .nonce = 8},
      {.tag = MURMUR_PKT_PINGREQ, .nonce = 10},
  };
  for (size_t i = 0; i < sizeof(pkts) / sizeof(pkts[0]); i++) {
    pkts[i].database = node_fill(0xaa);
    pkts[i].sender = node_fill(0x11);
    pkts[i].target = node_fill(0x22);
    uint8_t raw[2048];
    size_t n = murmur_pkt_encode(&pkts[i], raw, sizeof(raw));
    CHECK(n > 0 && n <= MURMUR_MAX_DATAGRAM_BYTES, "encode %zu", i);
    if (n == 0) {
      continue;
    }
    /* Short buffer fails cleanly. */
    CHECK(murmur_pkt_encode(&pkts[i], raw, n - 1) == 0, "short encode %zu", i);
    murmur_pkt_t back;
    murmur_member_t mem[4];
    CHECK(murmur_pkt_decode(raw, n, &back, mem, 4) == MURMUR_OK,
          "decode %zu", i);
    uint8_t rt[2048];
    size_t n2 = murmur_pkt_encode(&back, rt, sizeof(rt));
    CHECK(n2 == n && memcmp(rt, raw, n) == 0, "unstable %zu", i);
  }
  /* Invalid tag fails cleanly. */
  murmur_pkt_t bad;
  memset(&bad, 0, sizeof(bad));
  bad.tag = (murmur_pkt_tag_t)9;
  uint8_t scratch[64];
  CHECK(murmur_pkt_encode(&bad, scratch, sizeof(scratch)) == 0,
        "bad tag encoded");
}

int main(int argc, char **argv) {
  if (argc > 1) {
    vecdir = argv[1];
  }
  test_golden_encode();
  test_golden_decode();
  test_strictness();
  test_roundtrip();
  if (failures == 0) {
    printf("FRAMING-OK (4 suites)\n");
    return 0;
  }
  printf("FRAMING-FAIL (%d)\n", failures);
  return 1;
}

