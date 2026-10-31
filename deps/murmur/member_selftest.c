/* member_selftest - ports of the Go membership cases that do not need
 * the packet codec (membership_test.go minus TestPacketRoundTrip and
 * TestGoldenPackets, which belong to framing.c's selftest). The stub
 * send records packet STRUCTS, so no encoder is linked.
 *
 * Build: cc -Ideps/murmur deps/murmur/member.c
 *        deps/murmur/member_selftest.c -o /tmp/membertest
 * Or: make selftest
 */
#include <stdio.h>
#include <string.h>

#include "member.h"

static int failures = 0;

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

static murmur_member_t test_member(uint8_t b, uint64_t inc,
                                   murmur_state_t st) {
  murmur_member_t m;
  m.node = node_fill(b);
  if (murmur_addr_parse(&m.addr, "127.0.0.1:7443") != 0) {
    CHECK(0, "addr parse");
  }
  m.incarnation = inc;
  m.state = st;
  return m;
}

/* Fake word source: array-driven, errors when exhausted. */
typedef struct {
  const uint64_t *words;
  size_t n;
  size_t i;
} fake_words_t;

static int fake_word(void *ctx, uint64_t *w) {
  fake_words_t *f = (fake_words_t *)ctx;
  if (f->i >= f->n) {
    return -1;
  }
  *w = f->words[f->i++];
  return 0;
}

/* Stub IO: records sends, persists, notifies, closes. */
typedef struct {
  murmur_node_t peer;
  murmur_pkt_tag_t tag;
  murmur_node_t sender;
  murmur_node_t target;
  uint64_t nonce;
  size_t n_members;
} sent_pkt_t;

typedef struct {
  sent_pkt_t sent[64];
  size_t n_sent;
  uint64_t persisted;
  int n_persist;
  int n_notify;
  murmur_node_t closed[16];
  size_t n_closed;
} stub_t;

static int stub_send(void *ctx, const murmur_node_t *peer,
                     const murmur_pkt_t *pkt) {
  stub_t *s = (stub_t *)ctx;
  if (s->n_sent >= sizeof(s->sent) / sizeof(s->sent[0])) {
    return -1;
  }
  sent_pkt_t *o = &s->sent[s->n_sent++];
  o->peer = *peer;
  o->tag = pkt->tag;
  o->sender = pkt->sender;
  o->target = pkt->target;
  o->nonce = pkt->nonce;
  o->n_members = pkt->n_members;
  return 0;
}

static int stub_persist(void *ctx, uint64_t incarnation) {
  stub_t *s = (stub_t *)ctx;
  s->persisted = incarnation;
  s->n_persist++;
  return 0;
}

static void stub_notify(void *ctx) { ((stub_t *)ctx)->n_notify++; }

static void stub_close(void *ctx, const murmur_node_t *peer) {
  stub_t *s = (stub_t *)ctx;
  if (s->n_closed < sizeof(s->closed) / sizeof(s->closed[0])) {
    s->closed[s->n_closed++] = *peer;
  }
}

static murmur_mship_t *open_mship(stub_t *stub, uint8_t group_b, uint8_t node_b,
                                  uint64_t incarnation) {
  murmur_node_t group = node_fill(group_b);
  murmur_node_t node = node_fill(node_b);
  murmur_member_t local = test_member(node_b, incarnation, MURMUR_ALIVE);
  murmur_mship_t *m = murmur_mship_new(&group, &node, &local);
  murmur_mship_set_io(m, stub_send, stub, stub_persist, stub, stub_notify,
                      stub, stub_close, stub);
  return m;
}

static void test_merge_rules(void) {
  murmur_member_t local = test_member(1, 1, MURMUR_ALIVE);
  murmur_view_t *v = murmur_view_new(&local);
  murmur_member_t m;
  m = test_member(2, 3, MURMUR_DEAD);
  murmur_view_merge(v, &m);
  m = test_member(2, 2, MURMUR_ALIVE);
  murmur_view_merge(v, &m);
  murmur_node_t n2 = node_fill(2);
  const murmur_member_t *got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_DEAD, "stale gossip revived");
  m = test_member(2, 4, MURMUR_ALIVE);
  murmur_view_merge(v, &m);
  got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_ALIVE, "newer incarnation ignored");
  /* Excluded nodes never merge (via mship-level exclude path: direct
   * array here would bypass the API; exclusion is covered in the
   * remove-node test). Self refutes bump the local incarnation. */
  m = test_member(1, 10, MURMUR_SUSPECT);
  murmur_view_merge(v, &m);
  CHECK(murmur_view_local(v)->incarnation == 11, "local incarnation = %llu",
        (unsigned long long)murmur_view_local(v)->incarnation);
  CHECK(murmur_view_local(v)->state == MURMUR_ALIVE, "local state changed");
  /* Same-incarnation ties never regress; higher rank wins. */
  m = test_member(2, 4, MURMUR_ALIVE);
  murmur_view_merge(v, &m);
  murmur_view_merge(v, &m);
  got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_ALIVE, "tie regressed");
  m = test_member(2, 4, MURMUR_SUSPECT);
  murmur_view_merge(v, &m);
  got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_SUSPECT, "rank tie-break ignored");
  murmur_view_free(v);
}

static void test_ack_nonce(void) {
  murmur_member_t local = test_member(1, 1, MURMUR_ALIVE);
  murmur_view_t *v = murmur_view_new(&local);
  murmur_node_t n2 = node_fill(2);
  murmur_view_add_pending(v, &n2, 1000, 4);
  murmur_view_ack(v, &n2, 3);
  CHECK(murmur_view_pending(v) == 1, "wrong nonce cleared");
  murmur_view_ack(v, &n2, 4);
  CHECK(murmur_view_pending(v) == 0, "ack not cleared");
  murmur_view_free(v);
}

static void test_expire_lifecycle(void) {
  murmur_member_t local = test_member(1, 1, MURMUR_ALIVE);
  murmur_addr_parse(&local.addr, "127.0.0.1:1");
  murmur_view_t *v = murmur_view_new(&local);
  murmur_member_t m2 = test_member(2, 1, MURMUR_ALIVE);
  murmur_addr_parse(&m2.addr, "127.0.0.1:2");
  murmur_view_merge(v, &m2);
  murmur_node_t n2 = node_fill(2);
  uint64_t now = 1000000;
  murmur_view_add_pending(v, &n2, now - 10000, 7);
  murmur_probe_req_t reqs[8];
  size_t n = murmur_view_expire(v, now, reqs, 8);
  CHECK(n == 1 && murmur_node_eq(&reqs[0].target, &n2) && reqs[0].nonce == 7,
        "indirect reqs = %zu", n);
  const murmur_member_t *got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_ALIVE, "premature suspicion");
  murmur_view_rewind_pending(v, &n2, now - 10000);
  murmur_view_expire(v, now, reqs, 8);
  got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_SUSPECT, "no suspicion after indirect");
  /* Suspect expiry is internal; force it by advancing the clock past the
   * 5s*(awareness+1) window (awareness is 1 now: 10s). */
  murmur_view_expire(v, now + 11000, reqs, 8);
  got = murmur_view_lookup(v, &n2);
  CHECK(got && got->state == MURMUR_DEAD, "no death after suspect expiry");
  murmur_view_free(v);
}

static void test_below(void) {
  uint64_t w1[] = {0, 4};
  fake_words_t f1 = {w1, 2, 0};
  uint64_t n = 99;
  /* 0 is rejected for bound 3 (threshold 1), then 4 % 3 = 1. */
  CHECK(murmur_below(fake_word, &f1, 3, &n) == 0 && n == 1, "below = %llu",
        (unsigned long long)n);
  fake_words_t f2 = {NULL, 0, 0};
  CHECK(murmur_below(fake_word, &f2, 1, &n) == 0 && n == 0,
        "bound 1 must yield 0 without drawing");
  uint64_t w3[] = {~0ull};
  fake_words_t f3 = {w3, 1, 0};
  CHECK(murmur_below(fake_word, &f3, 2, &n) == 0 && n == 1, "max word mod 2");
  fake_words_t f4 = {NULL, 0, 0};
  CHECK(murmur_below(fake_word, &f4, 2, &n) != 0, "empty source accepted");
  uint64_t w5[] = {3, 3};
  fake_words_t f5 = {w5, 2, 0};
  size_t idx[4];
  size_t n_idx = 0;
  CHECK(murmur_sample_idx(fake_word, &f5, 4, 2, idx, &n_idx) == 0 &&
            n_idx == 2 && idx[0] == 2 && idx[1] == 1,
        "sample mismatch");
  uint64_t w6[] = {0};
  fake_words_t f6 = {w6, 1, 0};
  CHECK(murmur_sample_idx(fake_word, &f6, 2, 1, idx, &n_idx) == 0 &&
            n_idx == 1 && idx[0] == 1,
        "choose mismatch");
  fake_words_t f7 = {NULL, 0, 0};
  CHECK(murmur_sample_idx(fake_word, &f7, 2, 1, idx, &n_idx) != 0,
        "sample without entropy accepted");
}

static void test_handle_gossip(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 1);
  murmur_node_t group = node_fill(0xaa);
  murmur_node_t peer = node_fill(0x22);
  murmur_member_t mm = test_member(3, 2, MURMUR_ALIVE);
  murmur_pkt_t pkt;
  pkt.tag = MURMUR_PKT_GOSSIP;
  pkt.database = group;
  pkt.sender = peer;
  pkt.members = &mm;
  pkt.n_members = 1;
  murmur_mship_status_t rc = murmur_mship_on_packet(m, &peer, &pkt, 1000);
  CHECK(rc == MURMUR_OK, "gossip: %s", murmur_mship_status_str(rc));
  CHECK(murmur_view_lookup(murmur_mship_view(m), &mm.node) != NULL,
        "member not merged");
  murmur_node_t other = node_fill(0xbb);
  pkt.database = other;
  CHECK(murmur_mship_on_packet(m, &peer, &pkt, 1000) == MURMUR_MSHIP_AUTH,
        "wrong db accepted");
  pkt.database = group;
  pkt.sender = other;
  pkt.n_members = 0;
  CHECK(murmur_mship_on_packet(m, &peer, &pkt, 1000) == MURMUR_MSHIP_AUTH,
        "wrong sender accepted");
  pkt.sender = peer;
  murmur_member_t big[5] = {mm, mm, mm, mm, mm};
  pkt.members = big;
  pkt.n_members = 5;
  CHECK(murmur_mship_on_packet(m, &peer, &pkt, 1000) == MURMUR_MSHIP_AUTH,
        "oversize members accepted");
  murmur_mship_free(m);
}

static void test_handle_ping_ack(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 1);
  murmur_node_t group = node_fill(0xaa);
  murmur_node_t peer = node_fill(0x22);
  murmur_node_t node = node_fill(0x11);
  murmur_mship_add_conn(m, &peer);
  murmur_view_add_pending(murmur_mship_view(m), &peer, 900, 7);
  murmur_member_t mm = test_member(3, 2, MURMUR_ALIVE);
  murmur_pkt_t pkt;
  pkt.tag = MURMUR_PKT_PING;
  pkt.database = group;
  pkt.sender = peer;
  pkt.nonce = 7;
  pkt.members = &mm;
  pkt.n_members = 1;
  CHECK(murmur_mship_on_packet(m, &peer, &pkt, 1000) == MURMUR_OK, "ping");
  CHECK(murmur_view_lookup(murmur_mship_view(m), &mm.node) != NULL,
        "ping members not merged");
  CHECK(murmur_view_pending(murmur_mship_view(m)) == 0, "pending not acked");
  CHECK(stub.n_sent == 1, "replies = %zu", stub.n_sent);
  if (stub.n_sent == 1) {
    CHECK(stub.sent[0].tag == MURMUR_PKT_ACK && stub.sent[0].nonce == 7 &&
              murmur_node_eq(&stub.sent[0].sender, &node),
          "reply tag=%d nonce=%llu", (int)stub.sent[0].tag,
          (unsigned long long)stub.sent[0].nonce);
  }
  /* Zero-nonce pings merge without replying. */
  stub.n_sent = 0;
  pkt.nonce = 0;
  CHECK(murmur_mship_on_packet(m, &peer, &pkt, 1000) == MURMUR_OK,
        "zero-nonce ping");
  CHECK(stub.n_sent == 0, "zero-nonce ping got a reply");
  murmur_mship_free(m);
}

static void test_relay(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 1);
  murmur_node_t group = node_fill(0xaa);
  murmur_node_t peer = node_fill(0x22);
  murmur_node_t target = node_fill(0x33);
  murmur_node_t node = node_fill(0x11);
  murmur_mship_add_conn(m, &peer);
  murmur_mship_add_conn(m, &target);
  murmur_pkt_t req;
  req.tag = MURMUR_PKT_PINGREQ;
  req.database = group;
  req.sender = peer;
  req.target = target;
  req.nonce = 5;
  req.members = NULL;
  req.n_members = 0;
  CHECK(murmur_mship_on_packet(m, &peer, &req, 1000) == MURMUR_OK, "pingreq");
  CHECK(stub.n_sent == 1, "forwards = %zu", stub.n_sent);
  if (stub.n_sent == 1) {
    CHECK(stub.sent[0].tag == MURMUR_PKT_PING && stub.sent[0].nonce == 5 &&
              murmur_node_eq(&stub.sent[0].sender, &node) &&
              murmur_node_eq(&stub.sent[0].peer, &target),
          "forward mismatch");
  }
  /* The relayed ack routes back to the requester as IndirectAck. */
  stub.n_sent = 0;
  murmur_pkt_t ack;
  ack.tag = MURMUR_PKT_ACK;
  ack.database = group;
  ack.sender = target;
  ack.nonce = 5;
  ack.members = NULL;
  ack.n_members = 0;
  CHECK(murmur_mship_on_packet(m, &target, &ack, 1000) == MURMUR_OK, "ack");
  CHECK(stub.n_sent == 1, "indirect acks = %zu", stub.n_sent);
  if (stub.n_sent == 1) {
    CHECK(stub.sent[0].tag == MURMUR_PKT_INDIRECT_ACK &&
              murmur_node_eq(&stub.sent[0].peer, &peer),
          "relay reply tag=%d", (int)stub.sent[0].tag);
  }
  murmur_mship_free(m);
}

static void test_refute(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 7);
  murmur_node_t group = node_fill(0xaa);
  murmur_node_t peer = node_fill(0x22);
  murmur_node_t node = node_fill(0x11);
  murmur_member_t self;
  self.node = node;
  murmur_addr_parse(&self.addr, "127.0.0.1:7443");
  self.incarnation = 7;
  self.state = MURMUR_SUSPECT;
  murmur_pkt_t pkt;
  pkt.tag = MURMUR_PKT_GOSSIP;
  pkt.database = group;
  pkt.sender = peer;
  pkt.members = &self;
  pkt.n_members = 1;
  CHECK(murmur_mship_on_packet(m, &peer, &pkt, 1000) == MURMUR_OK, "refute");
  CHECK(murmur_view_local(murmur_mship_view(m))->incarnation == 8,
        "incarnation = %llu",
        (unsigned long long)murmur_view_local(murmur_mship_view(m))
            ->incarnation);
  CHECK(stub.n_persist == 1 && stub.persisted == 8, "persisted = %llu x%d",
        (unsigned long long)stub.persisted, stub.n_persist);
  murmur_mship_free(m);
}

static void test_probe(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 1);
  murmur_node_t peer = node_fill(0x22);
  murmur_mship_add_conn(m, &peer);
  uint64_t w[] = {0, 42};
  fake_words_t f = {w, 2, 0};
  murmur_mship_probe(m, 1000, fake_word, &f);
  CHECK(stub.n_sent == 1, "pings = %zu", stub.n_sent);
  if (stub.n_sent == 1) {
    CHECK(stub.sent[0].tag == MURMUR_PKT_PING, "probe tag=%d",
          (int)stub.sent[0].tag);
  }
  CHECK(murmur_view_pending(murmur_mship_view(m)) == 1, "no pending probe");
  murmur_mship_free(m);
}

static void test_add_remove(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 1);
  CHECK(murmur_mship_add_seed(m, "not-an-address") == MURMUR_MSHIP_INVALID,
        "bad addr accepted");
  CHECK(murmur_mship_add_seed(m, "127.0.0.1:7443") == MURMUR_OK, "add seed");
  CHECK(murmur_mship_has_seed(m, "127.0.0.1:7443"), "seed not stored");
  CHECK(stub.n_notify == 1, "no sync notify");
  murmur_node_t peer = node_fill(0x22);
  murmur_mship_add_conn(m, &peer);
  murmur_member_t mm = test_member(0x22, 1, MURMUR_ALIVE);
  mm.node = peer;
  murmur_addr_parse(&mm.addr, "127.0.0.1:7443");
  murmur_view_merge(murmur_mship_view(m), &mm);
  murmur_mship_remove_node(m, &peer);
  CHECK(stub.n_closed == 1 && murmur_node_eq(&stub.closed[0], &peer),
        "session not closed");
  CHECK(!murmur_mship_has_conn(m, &peer), "conn not dropped");
  const murmur_member_t *got =
      murmur_view_lookup(murmur_mship_view(m), &peer);
  CHECK(got && got->state == MURMUR_LEFT, "view not marked left");
  /* Excluded nodes no longer merge. */
  murmur_member_t alive = test_member(0x22, 5, MURMUR_ALIVE);
  alive.node = peer;
  murmur_view_merge(murmur_mship_view(m), &alive);
  got = murmur_view_lookup(murmur_mship_view(m), &peer);
  CHECK(got && got->state == MURMUR_LEFT, "excluded node merged");
  CHECK(!murmur_mship_has_seed(m, "127.0.0.1:7443"), "seed not forgotten");
  murmur_mship_free(m);
}

static void test_fetch_sources(void) {
  stub_t stub;
  memset(&stub, 0, sizeof(stub));
  murmur_mship_t *m = open_mship(&stub, 0xaa, 0x11, 1);
  murmur_member_t a = test_member(2, 1, MURMUR_ALIVE);
  murmur_member_t s = test_member(3, 1, MURMUR_SUSPECT);
  murmur_member_t d = test_member(4, 1, MURMUR_DEAD);
  murmur_view_merge(murmur_mship_view(m), &a);
  murmur_view_merge(murmur_mship_view(m), &s);
  murmur_view_merge(murmur_mship_view(m), &d);
  murmur_fetch_source_t out[8];
  size_t n = murmur_mship_fetch_sources(m, 7555, out, 8);
  CHECK(n == 2, "sources = %zu", n);
  for (size_t i = 0; i < n; i++) {
    CHECK(out[i].addr.port == 7555 && !out[i].addr.is6 &&
              out[i].addr.ip[0] == 127 && out[i].addr.ip[3] == 1,
          "source addr mismatch");
  }
  murmur_mship_free(m);
}

int main(void) {
  test_merge_rules();
  test_ack_nonce();
  test_expire_lifecycle();
  test_below();
  test_handle_gossip();
  test_handle_ping_ack();
  test_relay();
  test_refute();
  test_probe();
  test_add_remove();
  test_fetch_sources();
  if (failures == 0) {
    printf("MEMBER-OK (11 suites)\n");
    return 0;
  }
  printf("MEMBER-FAIL (%d)\n", failures);
  return 1;
}
