/* murmur membership - see member.h. Ports membership.go below the packet
 * codec: random selection, the SWIM view, and the engine gossip / probe /
 * packet path. Single-threaded; the integrator serializes calls. */
#include "member.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#endif

const char *murmur_mship_status_str(murmur_mship_status_t st) {
  switch (st) {
    case MURMUR_OK:
      return "Ok";
    case MURMUR_MSHIP_AUTH:
      return "Auth";
    case MURMUR_MSHIP_PROTOCOL:
      return "Protocol";
    case MURMUR_MSHIP_OVERLOADED:
      return "Overloaded";
    case MURMUR_MSHIP_INVALID:
      return "Invalid";
  }
  return "Unknown";
}

int murmur_node_eq(const murmur_node_t *a, const murmur_node_t *b) {
  return memcmp(a->b, b->b, sizeof(a->b)) == 0;
}

int murmur_addr_parse(murmur_addr_t *out, const char *s) {
  /* Forms: 1.2.3.4:5678 or [::1]:5678. */
  const char *host_end = NULL;
  const char *port_s = NULL;
  char host[64];
  memset(out, 0, sizeof(*out));
  if (s[0] == '[') {
    const char *br = strchr(s, ']');
    if (!br || br[1] != ':' || (size_t)(br - s - 1) >= sizeof(host)) {
      return -1;
    }
    memcpy(host, s + 1, (size_t)(br - s - 1));
    host[br - s - 1] = '\0';
    port_s = br + 2;
    host_end = host;
    (void)host_end;
    if (inet_pton(AF_INET6, host, out->ip) != 1) {
      return -1;
    }
    out->is6 = 1;
  } else {
    const char *colon = strrchr(s, ':');
    if (!colon || (size_t)(colon - s) >= sizeof(host)) {
      return -1;
    }
    memcpy(host, s, (size_t)(colon - s));
    host[colon - s] = '\0';
    port_s = colon + 1;
    if (inet_pton(AF_INET, host, out->ip) != 1) {
      return -1;
    }
    out->is6 = 0;
  }
  char *end = NULL;
  long port = strtol(port_s, &end, 10);
  if (!end || *end != '\0' || port < 0 || port > 65535) {
    return -1;
  }
  out->port = (uint16_t)port;
  return 0;
}

void murmur_addr_format(const murmur_addr_t *a, char *out, size_t cap) {
  char host[64];
  if (a->is6) {
    inet_ntop(AF_INET6, a->ip, host, sizeof(host));
    snprintf(out, cap, "[%s]:%u", host, a->port);
  } else {
    inet_ntop(AF_INET, a->ip, host, sizeof(host));
    snprintf(out, cap, "%s:%u", host, a->port);
  }
}

int murmur_below(murmur_word_fn wf, void *wctx, uint64_t upper,
                 uint64_t *out) {
  if (upper == 0) {
    return -1;
  }
  if (upper == 1) {
    *out = 0;
    return 0;
  }
  /* Reject the short remainder of the 2^64 domain before reducing. */
  uint64_t threshold = (0u - upper) % upper;
  for (;;) {
    uint64_t w;
    if (wf(wctx, &w) != 0) {
      return -1;
    }
    if (w >= threshold) {
      *out = w % upper;
      return 0;
    }
  }
}

int murmur_sample_idx(murmur_word_fn wf, void *wctx, size_t n, size_t amount,
                      size_t *out_idx, size_t *out_n) {
  size_t kept = 0;
  if (amount == 0 || n == 0) {
    *out_n = 0;
    return 0;
  }
  if (amount > n) {
    amount = n;
  }
  for (size_t i = 0; i < n; i++) {
    if (kept < amount) {
      out_idx[kept++] = i;
      continue;
    }
    uint64_t slot;
    if (murmur_below(wf, wctx, (uint64_t)(i + 1), &slot) != 0) {
      return -1;
    }
    if (slot < amount) {
      out_idx[slot] = i;
    }
  }
  *out_n = kept;
  return 0;
}

int murmur_word_crypto(void *ctx, uint64_t *word) {
  (void)ctx;
#if defined(__linux__) || defined(__APPLE__)
  /* getentropy caps at 256 bytes; 8 always succeeds or fails cleanly. */
  extern int getentropy(void *, size_t);
  if (getentropy(word, sizeof(*word)) == 0) {
    return 0;
  }
#endif
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) {
    return -1;
  }
  size_t n = fread(word, 1, sizeof(*word), f);
  fclose(f);
  return n == sizeof(*word) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* View                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
  murmur_node_t node;
  uint64_t at_ms;
  uint64_t nonce;
  int indirect;
} pending_probe_t;

typedef struct {
  murmur_node_t node;
  uint64_t at_ms;
} suspect_entry_t;

struct murmur_view {
  murmur_member_t *members;
  size_t n_members;
  murmur_member_t local;
  murmur_node_t *excluded;
  size_t n_excluded;
  pending_probe_t *pending;
  size_t n_pending;
  suspect_entry_t *suspect;
  size_t n_suspect;
  uint32_t awareness;
};

static int find_member(const murmur_view_t *v, const murmur_node_t *node) {
  for (size_t i = 0; i < v->n_members; i++) {
    if (murmur_node_eq(&v->members[i].node, node)) {
      return (int)i;
    }
  }
  return -1;
}

static int find_excluded(const murmur_view_t *v, const murmur_node_t *node) {
  for (size_t i = 0; i < v->n_excluded; i++) {
    if (murmur_node_eq(&v->excluded[i], node)) {
      return (int)i;
    }
  }
  return -1;
}

static int find_pending(const murmur_view_t *v, const murmur_node_t *node) {
  for (size_t i = 0; i < v->n_pending; i++) {
    if (murmur_node_eq(&v->pending[i].node, node)) {
      return (int)i;
    }
  }
  return -1;
}

static int find_suspect(const murmur_view_t *v, const murmur_node_t *node) {
  for (size_t i = 0; i < v->n_suspect; i++) {
    if (murmur_node_eq(&v->suspect[i].node, node)) {
      return (int)i;
    }
  }
  return -1;
}

murmur_view_t *murmur_view_new(const murmur_member_t *local) {
  murmur_view_t *v = (murmur_view_t *)calloc(1, sizeof(*v));
  if (!v) {
    return NULL;
  }
  v->members =
      (murmur_member_t *)calloc(MURMUR_MAX_VIEW_MEMBERS, sizeof(*v->members));
  v->excluded =
      (murmur_node_t *)calloc(MURMUR_MAX_VIEW_MEMBERS, sizeof(*v->excluded));
  v->pending =
      (pending_probe_t *)calloc(MURMUR_MAX_VIEW_MEMBERS, sizeof(*v->pending));
  v->suspect = (suspect_entry_t *)calloc(MURMUR_MAX_VIEW_MEMBERS,
                                         sizeof(*v->suspect));
  if (!v->members || !v->excluded || !v->pending || !v->suspect) {
    murmur_view_free(v);
    return NULL;
  }
  v->local = *local;
  return v;
}

void murmur_view_free(murmur_view_t *v) {
  if (!v) {
    return;
  }
  free(v->members);
  free(v->excluded);
  free(v->pending);
  free(v->suspect);
  free(v);
}

void murmur_view_merge(murmur_view_t *v, const murmur_member_t *m) {
  if (murmur_node_eq(&m->node, &v->local.node)) {
    if (m->incarnation >= v->local.incarnation &&
        m->state != MURMUR_ALIVE) {
      v->local.incarnation = m->incarnation + 1;
    }
    return;
  }
  if (find_excluded(v, &m->node) >= 0) {
    return;
  }
  int idx = find_member(v, &m->node);
  if (idx < 0) {
    if (v->n_members >= MURMUR_MAX_VIEW_MEMBERS) {
      return;
    }
    v->members[v->n_members++] = *m;
    return;
  }
  murmur_member_t *old = &v->members[idx];
  if (m->incarnation > old->incarnation ||
      (m->incarnation == old->incarnation && (int)m->state > (int)old->state)) {
    if (m->state == MURMUR_ALIVE) {
      int s = find_suspect(v, &m->node);
      if (s >= 0) {
        v->suspect[s] = v->suspect[--v->n_suspect];
      }
    }
    *old = *m;
  }
}

size_t murmur_view_gossip(murmur_view_t *v, murmur_member_t *out, size_t cap,
                          murmur_word_fn wf, void *wctx) {
  if (cap == 0) {
    return 0;
  }
  out[0] = v->local;
  size_t n = 1;
  if (v->n_members == 0 || cap == 1) {
    return n;
  }
  size_t idx[MURMUR_GOSSIP_FANOUT_DEFAULT];
  size_t n_idx = 0;
  if (murmur_sample_idx(wf, wctx, v->n_members, MURMUR_GOSSIP_FANOUT_DEFAULT,
                        idx, &n_idx) != 0) {
    return n;
  }
  for (size_t i = 0; i < n_idx && n < cap; i++) {
    out[n++] = v->members[idx[i]];
  }
  return n;
}

void murmur_view_ack(murmur_view_t *v, const murmur_node_t *node,
                     uint64_t nonce) {
  int idx = find_pending(v, node);
  if (idx >= 0 && v->pending[idx].nonce == nonce) {
    v->pending[idx] = v->pending[--v->n_pending];
    if (v->awareness > 0) {
      v->awareness--;
    }
  }
}

size_t murmur_view_expire(murmur_view_t *v, uint64_t now_ms,
                          murmur_probe_req_t *reqs, size_t cap) {
  uint64_t timeout_ms = 500u * ((uint64_t)v->awareness + 1);
  size_t n_req = 0;
  /* Timed-out direct probes request one indirect round; timed-out
   * indirect probes mark Suspect. */
  size_t i = 0;
  while (i < v->n_pending) {
    pending_probe_t *p = &v->pending[i];
    if (now_ms - p->at_ms < timeout_ms) {
      i++;
      continue;
    }
    if (!p->indirect) {
      p->at_ms = now_ms;
      p->indirect = 1;
      if (n_req < cap) {
        reqs[n_req].target = p->node;
        reqs[n_req].nonce = p->nonce;
        n_req++;
      }
      i++;
    } else {
      murmur_node_t lost = p->node;
      v->pending[i] = v->pending[--v->n_pending];
      int m = find_member(v, &lost);
      if (m >= 0) {
        v->members[m].state = MURMUR_SUSPECT;
        if (find_suspect(v, &lost) < 0 && v->n_suspect < MURMUR_MAX_VIEW_MEMBERS) {
          v->suspect[v->n_suspect].node = lost;
          v->suspect[v->n_suspect].at_ms = now_ms;
          v->n_suspect++;
        }
      }
      if (v->awareness < 8) {
        v->awareness++;
      }
    }
  }
  /* Long-suspect members go Dead. */
  uint64_t expiry_ms = 5000u * ((uint64_t)v->awareness + 1);
  i = 0;
  while (i < v->n_suspect) {
    if (now_ms - v->suspect[i].at_ms < expiry_ms) {
      i++;
      continue;
    }
    int m = find_member(v, &v->suspect[i].node);
    if (m >= 0) {
      v->members[m].state = MURMUR_DEAD;
    }
    v->suspect[i] = v->suspect[--v->n_suspect];
  }
  return n_req;
}

size_t murmur_view_size(const murmur_view_t *v) { return v->n_members; }

size_t murmur_view_members(const murmur_view_t *v, murmur_member_t *out,
                           size_t cap) {
  size_t n = v->n_members < cap ? v->n_members : cap;
  for (size_t i = 0; i < n; i++) {
    out[i] = v->members[i];
  }
  return v->n_members;
}
size_t murmur_view_pending(const murmur_view_t *v) { return v->n_pending; }

const murmur_member_t *murmur_view_lookup(const murmur_view_t *v,
                                          const murmur_node_t *node) {
  int idx = find_member(v, node);
  return idx < 0 ? NULL : &v->members[idx];
}

const murmur_member_t *murmur_view_local(const murmur_view_t *v) {
  return &v->local;
}

uint32_t murmur_view_awareness(const murmur_view_t *v) { return v->awareness; }

int murmur_view_rewind_pending(murmur_view_t *v, const murmur_node_t *node,
                               uint64_t at_ms) {
  int idx = find_pending(v, node);
  if (idx < 0) {
    return -1;
  }
  v->pending[idx].at_ms = at_ms;
  return 0;
}

int murmur_view_add_pending(murmur_view_t *v, const murmur_node_t *node,
                            uint64_t at_ms, uint64_t nonce) {
  if (v->n_pending >= MURMUR_MAX_VIEW_MEMBERS) {
    return -1;
  }
  int idx = find_pending(v, node);
  if (idx >= 0) {
    v->pending[idx].at_ms = at_ms;
    v->pending[idx].nonce = nonce;
    return 0;
  }
  v->pending[v->n_pending].node = *node;
  v->pending[v->n_pending].at_ms = at_ms;
  v->pending[v->n_pending].nonce = nonce;
  v->pending[v->n_pending].indirect = 0;
  v->n_pending++;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Engine membership                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
  murmur_node_t target;
  uint64_t nonce;
  murmur_node_t requester;
  uint64_t at_ms;
} relay_entry_t;


struct murmur_mship {
  murmur_view_t *view;
  murmur_node_t group;
  murmur_node_t node;
  murmur_node_t *conns;
  size_t n_conns;
  relay_entry_t *relays;
  size_t n_relays;
  char *seeds; /* n_seeds x MURMUR_SEED_STRLEN */
  size_t n_seeds;
  uint64_t persisted_incarnation;
  uint64_t incarnation;
  int gossip_fanout;
  murmur_send_fn send;
  void *send_ctx;
  murmur_persist_fn persist;
  void *persist_ctx;
  murmur_notify_fn notify;
  void *notify_ctx;
  murmur_close_fn close_fn;
  void *close_ctx;
};

murmur_mship_t *murmur_mship_new(const murmur_node_t *group,
                                 const murmur_node_t *node,
                                 const murmur_member_t *local) {
  murmur_mship_t *m =
      (murmur_mship_t *)calloc(1, sizeof(*m));
  if (!m) {
    return NULL;
  }
  m->view = murmur_view_new(local);
  m->conns = (murmur_node_t *)calloc(MURMUR_MAX_VIEW_MEMBERS, sizeof(*m->conns));
  m->relays =
      (relay_entry_t *)calloc(MURMUR_MAX_VIEW_MEMBERS, sizeof(*m->relays));
  m->seeds = (char *)calloc(MURMUR_MAX_VIEW_MEMBERS, MURMUR_SEED_STRLEN);
  if (!m->view || !m->conns || !m->relays || !m->seeds) {
    murmur_mship_free(m);
    return NULL;
  }
  m->group = *group;
  m->node = *node;
  m->gossip_fanout = MURMUR_GOSSIP_FANOUT_DEFAULT;
  m->incarnation = local->incarnation;
  m->persisted_incarnation = local->incarnation;
  return m;
}

void murmur_mship_free(murmur_mship_t *m) {
  if (!m) {
    return;
  }
  murmur_view_free(m->view);
  free(m->conns);
  free(m->relays);
  free(m->seeds);
  free(m);
}

void murmur_mship_set_io(murmur_mship_t *m, murmur_send_fn send, void *send_ctx,
                         murmur_persist_fn persist, void *persist_ctx,
                         murmur_notify_fn notify, void *notify_ctx,
                         murmur_close_fn close_fn, void *close_ctx) {
  m->send = send;
  m->send_ctx = send_ctx;
  m->persist = persist;
  m->persist_ctx = persist_ctx;
  m->notify = notify;
  m->notify_ctx = notify_ctx;
  m->close_fn = close_fn;
  m->close_ctx = close_ctx;
}

void murmur_mship_set_fanout(murmur_mship_t *m, int fanout) {
  m->gossip_fanout = fanout;
}

int murmur_mship_add_conn(murmur_mship_t *m, const murmur_node_t *peer) {
  for (size_t i = 0; i < m->n_conns; i++) {
    if (murmur_node_eq(&m->conns[i], peer)) {
      return 0;
    }
  }
  if (m->n_conns >= MURMUR_MAX_VIEW_MEMBERS) {
    return -1;
  }
  m->conns[m->n_conns++] = *peer;
  return 0;
}

int murmur_mship_has_conn(const murmur_mship_t *m, const murmur_node_t *peer) {
  for (size_t i = 0; i < m->n_conns; i++) {
    if (murmur_node_eq(&m->conns[i], peer)) {
      return 1;
    }
  }
  return 0;
}

static void send_packet(murmur_mship_t *m, const murmur_node_t *peer,
                        const murmur_pkt_t *pkt) {
  /* Size cap is enforced by the integrator's send (it encodes). */
  if (!murmur_mship_has_conn(m, peer)) {
    return;
  }
  if (m->send) {
    m->send(m->send_ctx, peer, pkt);
  }
}

static void broadcast(murmur_mship_t *m, const murmur_pkt_t *pkt,
                      murmur_word_fn wf, void *wctx) {
  if (m->n_conns == 0 || !m->send) {
    return;
  }
  size_t *idx = (size_t *)malloc(m->n_conns * sizeof(*idx));
  size_t n_idx = 0;
  size_t fanout =
      m->gossip_fanout < 0 ? 0 : (size_t)m->gossip_fanout;
  if (!idx || murmur_sample_idx(wf, wctx, m->n_conns, fanout, idx, &n_idx) != 0) {
    free(idx);
    return;
  }
  for (size_t i = 0; i < n_idx; i++) {
    m->send(m->send_ctx, &m->conns[idx[i]], pkt);
  }
  free(idx);
}

void murmur_mship_gossip(murmur_mship_t *m, murmur_word_fn wf, void *wctx) {
  murmur_member_t members[1 + MURMUR_GOSSIP_FANOUT_DEFAULT];
  murmur_pkt_t pkt;
  size_t n = murmur_view_gossip(m->view, members, sizeof(members) / sizeof(members[0]), wf, wctx);
  pkt.tag = MURMUR_PKT_GOSSIP;
  pkt.database = m->group;
  pkt.sender = m->node;
  memset(&pkt.target, 0, sizeof(pkt.target));
  pkt.nonce = 0;
  pkt.members = members;
  pkt.n_members = n;
  broadcast(m, &pkt, wf, wctx);
}

void murmur_mship_probe(murmur_mship_t *m, uint64_t now_ms, murmur_word_fn wf,
                        void *wctx) {
  size_t pend_cap = murmur_view_pending(m->view) + 1;
  murmur_probe_req_t *lost =
      (murmur_probe_req_t *)malloc(pend_cap * sizeof(*lost));
  if (!lost) {
    return;
  }
  size_t n_lost = murmur_view_expire(m->view, now_ms, lost, pend_cap);
  if (m->n_conns > 0) {
    uint64_t slot = 0;
    if (murmur_below(wf, wctx, (uint64_t)m->n_conns, &slot) == 0) {
      const murmur_node_t *target = &m->conns[slot];
      uint64_t nonce = 0;
      /* Reuse a pending nonce on duplicates (Go probe). */
      int dup = 0;
      for (size_t i = 0; i < m->view->n_pending; i++) {
        if (murmur_node_eq(&m->view->pending[i].node, target)) {
          nonce = m->view->pending[i].nonce;
          dup = 1;
          break;
        }
      }
      if (!dup) {
        if (wf(wctx, &nonce) != 0) {
          nonce = 0;
        }
        murmur_view_add_pending(m->view, target, now_ms, nonce);
      }
      murmur_member_t members[1 + MURMUR_GOSSIP_FANOUT_DEFAULT];
      murmur_pkt_t pkt;
      size_t n = murmur_view_gossip(m->view, members,
                                    sizeof(members) / sizeof(members[0]), wf, wctx);
      pkt.tag = MURMUR_PKT_PING;
      pkt.database = m->group;
      pkt.sender = m->node;
      memset(&pkt.target, 0, sizeof(pkt.target));
      pkt.nonce = nonce;
      pkt.members = members;
      pkt.n_members = n;
      send_packet(m, target, &pkt);
    }
  }
  for (size_t r = 0; r < n_lost; r++) {
    murmur_node_t *relays =
        (murmur_node_t *)malloc(m->n_conns * sizeof(*relays));
    if (!relays) {
      continue;
    }
    size_t n_relays = 0;
    for (size_t i = 0; i < m->n_conns; i++) {
      if (!murmur_node_eq(&m->conns[i], &lost[r].target)) {
        relays[n_relays++] = m->conns[i];
      }
    }
    size_t idx[3];
    size_t n_idx = 0;
    if (murmur_sample_idx(wf, wctx, n_relays, 3, idx, &n_idx) == 0) {
      for (size_t i = 0; i < n_idx; i++) {
        murmur_pkt_t pkt;
        pkt.tag = MURMUR_PKT_PINGREQ;
        pkt.database = m->group;
        pkt.sender = m->node;
        pkt.target = lost[r].target;
        pkt.nonce = lost[r].nonce;
        pkt.members = NULL;
        pkt.n_members = 0;
        send_packet(m, &relays[idx[i]], &pkt);
      }
    }
    free(relays);
  }
  free(lost);
}

/* Envelope database check. Callers also check sender-vs-peer and the
 * member-list bound (Go envelope closure). */
static murmur_mship_status_t envelope_ok(const murmur_mship_t *m,
                                         const murmur_pkt_t *pkt) {
  if (!murmur_node_eq(&pkt->database, &m->group)) {
    return MURMUR_MSHIP_AUTH;
  }
  return MURMUR_OK;
}

static void merge_all(murmur_mship_t *m, const murmur_pkt_t *pkt) {
  for (size_t i = 0; i < pkt->n_members; i++) {
    murmur_view_merge(m->view, &pkt->members[i]);
  }
}

/* Look up and consume a relay entry. Returns 1 when found. */
static int take_relay(murmur_mship_t *m, const murmur_node_t *target,
                      uint64_t nonce, murmur_node_t *requester) {
  for (size_t i = 0; i < m->n_relays; i++) {
    if (murmur_node_eq(&m->relays[i].target, target) &&
        m->relays[i].nonce == nonce) {
      *requester = m->relays[i].requester;
      m->relays[i] = m->relays[--m->n_relays];
      return 1;
    }
  }
  return 0;
}

static void send_ack(murmur_mship_t *m, const murmur_node_t *peer,
                     uint64_t nonce, murmur_word_fn wf, void *wctx) {
  murmur_member_t members[1 + MURMUR_GOSSIP_FANOUT_DEFAULT];
  murmur_pkt_t pkt;
  size_t n = murmur_view_gossip(m->view, members,
                                sizeof(members) / sizeof(members[0]), wf, wctx);
  pkt.tag = MURMUR_PKT_ACK;
  pkt.database = m->group;
  pkt.sender = m->node;
  memset(&pkt.target, 0, sizeof(pkt.target));
  pkt.nonce = nonce;
  pkt.members = members;
  pkt.n_members = n;
  send_packet(m, peer, &pkt);
}

/* NOTE: on_packet takes an already-decoded packet. The integrator
 * enforces the 1000-byte datagram cap on the wire bytes before decode
 * (Go handlePacket's first check). */
murmur_mship_status_t murmur_mship_on_packet(murmur_mship_t *m,
                                             const murmur_node_t *peer,
                                             const murmur_pkt_t *pkt,
                                             uint64_t now_ms) {
  (void)now_ms;
  /* Word source for reply gossip: production crypto. Replies never
   * depend on test fakes; gossip content is unordered either way. */
  murmur_word_fn wf = murmur_word_crypto;
  switch (pkt->tag) {
    case MURMUR_PKT_GOSSIP: {
      if (envelope_ok(m, pkt) != MURMUR_OK ||
          pkt->n_members > MURMUR_MAX_ENVELOPE_MEMBERS ||
          !murmur_node_eq(&pkt->sender, peer)) {
        return MURMUR_MSHIP_AUTH;
      }
      merge_all(m, pkt);
      break;
    }
    case MURMUR_PKT_PING: {
      if (pkt->nonce == 0) {
        if (envelope_ok(m, pkt) != MURMUR_OK ||
            pkt->n_members > MURMUR_MAX_ENVELOPE_MEMBERS ||
            !murmur_node_eq(&pkt->sender, peer)) {
          return MURMUR_MSHIP_AUTH;
        }
        merge_all(m, pkt);
        break;
      }
      if (envelope_ok(m, pkt) != MURMUR_OK ||
          pkt->n_members > MURMUR_MAX_ENVELOPE_MEMBERS ||
          !murmur_node_eq(&pkt->sender, peer)) {
        return MURMUR_MSHIP_AUTH;
      }
      merge_all(m, pkt);
      murmur_view_ack(m->view, peer, pkt->nonce);
      murmur_node_t requester;
      if (take_relay(m, peer, pkt->nonce, &requester)) {
        murmur_pkt_t ia;
        ia.tag = MURMUR_PKT_INDIRECT_ACK;
        ia.database = m->group;
        ia.sender = m->node;
        ia.target = *peer;
        ia.nonce = pkt->nonce;
        ia.members = NULL;
        ia.n_members = 0;
        send_packet(m, &requester, &ia);
      }
      send_ack(m, peer, pkt->nonce, wf, NULL);
      break;
    }
    case MURMUR_PKT_ACK: {
      if (envelope_ok(m, pkt) != MURMUR_OK ||
          pkt->n_members > MURMUR_MAX_ENVELOPE_MEMBERS ||
          !murmur_node_eq(&pkt->sender, peer)) {
        return MURMUR_MSHIP_AUTH;
      }
      merge_all(m, pkt);
      murmur_view_ack(m->view, peer, pkt->nonce);
      murmur_node_t requester;
      if (take_relay(m, peer, pkt->nonce, &requester)) {
        murmur_pkt_t ia;
        ia.tag = MURMUR_PKT_INDIRECT_ACK;
        ia.database = m->group;
        ia.sender = m->node;
        ia.target = *peer;
        ia.nonce = pkt->nonce;
        ia.members = NULL;
        ia.n_members = 0;
        send_packet(m, &requester, &ia);
      }
      break;
    }
    case MURMUR_PKT_INDIRECT_ACK: {
      if (!murmur_node_eq(&pkt->database, &m->group) ||
          !murmur_node_eq(&pkt->sender, peer)) {
        return MURMUR_MSHIP_AUTH;
      }
      murmur_view_ack(m->view, &pkt->target, pkt->nonce);
      break;
    }
    case MURMUR_PKT_PINGREQ: {
      if (!murmur_node_eq(&pkt->database, &m->group) ||
          !murmur_node_eq(&pkt->sender, peer)) {
        return MURMUR_MSHIP_AUTH;
      }
      size_t i = 0;
      while (i < m->n_relays) {
        if (now_ms - m->relays[i].at_ms >= 5000) {
          m->relays[i] = m->relays[--m->n_relays];
        } else {
          i++;
        }
      }
      if (m->n_relays >= MURMUR_MAX_VIEW_MEMBERS) {
        return MURMUR_MSHIP_OVERLOADED;
      }
      m->relays[m->n_relays].target = pkt->target;
      m->relays[m->n_relays].nonce = pkt->nonce;
      m->relays[m->n_relays].requester = *peer;
      m->relays[m->n_relays].at_ms = now_ms;
      m->n_relays++;
      murmur_member_t members[1 + MURMUR_GOSSIP_FANOUT_DEFAULT];
      murmur_pkt_t fwd;
      size_t n = murmur_view_gossip(m->view, members,
                                    sizeof(members) / sizeof(members[0]), wf, NULL);
      fwd.tag = MURMUR_PKT_PING;
      fwd.database = m->group;
      fwd.sender = m->node;
      memset(&fwd.target, 0, sizeof(fwd.target));
      fwd.nonce = pkt->nonce;
      fwd.members = members;
      fwd.n_members = n;
      send_packet(m, &pkt->target, &fwd);
      break;
    }
    default:
      return MURMUR_MSHIP_PROTOCOL;
  }
  /* A refuted incarnation persists so the next boot starts ahead. */
  uint64_t incarnation = m->view->local.incarnation;
  if (incarnation > m->persisted_incarnation && m->persist) {
    /* Best-effort: on failure the stale persisted value retries on
     * the next packet (Go returns the error; no caller acts on it). */
    if (m->persist(m->persist_ctx, incarnation) == 0) {
      if (incarnation > m->persisted_incarnation) {
        m->persisted_incarnation = incarnation;
        m->incarnation = incarnation;
      }
    }
  }
  return MURMUR_OK;
}

murmur_mship_status_t murmur_mship_add_seed(murmur_mship_t *m,
                                            const char *addr) {
  murmur_addr_t ap;
  char canon[MURMUR_SEED_STRLEN];
  if (murmur_addr_parse(&ap, addr) != 0) {
    return MURMUR_MSHIP_INVALID;
  }
  murmur_addr_format(&ap, canon, sizeof(canon));
  for (size_t i = 0; i < m->n_seeds; i++) {
    if (strcmp(m->seeds + i * MURMUR_SEED_STRLEN, canon) == 0) {
      return MURMUR_OK;
    }
  }
  if (m->n_seeds >= MURMUR_MAX_VIEW_MEMBERS) {
    return MURMUR_MSHIP_OVERLOADED;
  }
  memcpy(m->seeds + m->n_seeds * MURMUR_SEED_STRLEN, canon, sizeof(canon));
  m->n_seeds++;
  if (m->notify) {
    m->notify(m->notify_ctx);
  }
  return MURMUR_OK;
}

void murmur_mship_add_seed_raw(murmur_mship_t *m, const char *addr) {
  for (size_t i = 0; i < m->n_seeds; i++) {
    if (strcmp(m->seeds + i * MURMUR_SEED_STRLEN, addr) == 0) {
      return;
    }
  }
  if (m->n_seeds >= MURMUR_MAX_VIEW_MEMBERS) {
    return;
  }
  char *slot = m->seeds + m->n_seeds * MURMUR_SEED_STRLEN;
  strncpy(slot, addr, MURMUR_SEED_STRLEN - 1);
  slot[MURMUR_SEED_STRLEN - 1] = '\0';
  m->n_seeds++;
}

int murmur_mship_has_seed(const murmur_mship_t *m, const char *addr) {
  murmur_addr_t ap;
  char canon[MURMUR_SEED_STRLEN];
  if (murmur_addr_parse(&ap, addr) != 0) {
    /* Fall back to raw compare for non-address keys. */
    for (size_t i = 0; i < m->n_seeds; i++) {
      if (strcmp(m->seeds + i * MURMUR_SEED_STRLEN, addr) == 0) {
        return 1;
      }
    }
    return 0;
  }
  murmur_addr_format(&ap, canon, sizeof(canon));
  for (size_t i = 0; i < m->n_seeds; i++) {
    if (strcmp(m->seeds + i * MURMUR_SEED_STRLEN, canon) == 0) {
      return 1;
    }
  }
  return 0;
}

size_t murmur_mship_seeds(const murmur_mship_t *m, char *out, size_t cap) {
  if (!m || !out) {
    return 0;
  }
  size_t n = m->n_seeds < cap ? m->n_seeds : cap;
  for (size_t i = 0; i < n; i++) {
    memcpy(out + i * MURMUR_SEED_STRLEN,
           m->seeds + i * MURMUR_SEED_STRLEN, MURMUR_SEED_STRLEN);
  }
  return n;
}

void murmur_mship_remove_node(murmur_mship_t *m, const murmur_node_t *node) {
  murmur_view_t *v = m->view;
  if (find_excluded(v, node) < 0 && v->n_excluded < MURMUR_MAX_VIEW_MEMBERS) {
    v->excluded[v->n_excluded++] = *node;
  }
  int p = find_pending(v, node);
  if (p >= 0) {
    v->pending[p] = v->pending[--v->n_pending];
  }
  int s = find_suspect(v, node);
  if (s >= 0) {
    v->suspect[s] = v->suspect[--v->n_suspect];
  }
  int idx = find_member(v, node);
  if (idx >= 0) {
    v->members[idx].state = MURMUR_LEFT;
    char canon[MURMUR_SEED_STRLEN];
    murmur_addr_format(&v->members[idx].addr, canon, sizeof(canon));
    for (size_t i = 0; i < m->n_seeds; i++) {
      if (strcmp(m->seeds + i * MURMUR_SEED_STRLEN, canon) == 0) {
        memmove(m->seeds + i * MURMUR_SEED_STRLEN,
                m->seeds + (m->n_seeds - 1) * MURMUR_SEED_STRLEN,
                MURMUR_SEED_STRLEN);
        m->n_seeds--;
        break;
      }
    }
  }
  for (size_t i = 0; i < m->n_conns; i++) {
    if (murmur_node_eq(&m->conns[i], node)) {
      m->conns[i] = m->conns[--m->n_conns];
      if (m->close_fn) {
        m->close_fn(m->close_ctx, node);
      }
      break;
    }
  }
}

size_t murmur_mship_fetch_sources(murmur_mship_t *m, uint16_t port,
                                 murmur_fetch_source_t *out, size_t cap) {
  size_t n = 0;
  murmur_view_t *v = m->view;
  for (size_t i = 0; i < v->n_members && n < cap; i++) {
    const murmur_member_t *mem = &v->members[i];
    if (murmur_node_eq(&mem->node, &v->local.node)) {
      continue;
    }
    if (find_excluded(v, &mem->node) >= 0) {
      continue;
    }
    if (mem->state != MURMUR_ALIVE && mem->state != MURMUR_SUSPECT) {
      continue;
    }
    out[n].node = mem->node;
    out[n].addr = mem->addr;
    out[n].addr.port = port;
    n++;
  }
  return n;
}

murmur_view_t *murmur_mship_view(murmur_mship_t *m) { return m->view; }
