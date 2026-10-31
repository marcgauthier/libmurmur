/* murmur framing - see framing.h. Ports the membership.go packet
 * codec byte for byte; testdata/vec_pkt_*.bin are the goldens. */
#include "framing.h"

#include <string.h>

#define SHORT ((size_t)-1)

/* Appends a LEB128 varint; returns the new position or SHORT. */
static size_t put_uvarint(uint8_t *out, size_t cap, size_t pos, uint64_t v) {
  do {
    if (pos >= cap) {
      return SHORT;
    }
    uint8_t b = (uint8_t)(v & 0x7f);
    v >>= 7;
    if (v) {
      b |= 0x80;
    }
    out[pos++] = b;
  } while (v);
  return pos;
}

/* Reads a LEB128 varint with Go binary.Uvarint overflow rules: at
 * most 10 bytes, and the 10th payload byte may only carry bit 63.
 * Returns 0 on success, -1 on truncation or overflow. */
static int get_uvarint(const uint8_t *buf, size_t len, size_t *pos,
                       uint64_t *v) {
  uint64_t x = 0;
  unsigned shift = 0;
  for (int i = 0; i < 10; i++) {
    if (*pos >= len) {
      return -1;
    }
    uint8_t b = buf[(*pos)++];
    if (b < 0x80) {
      if (i == 9 && b > 1) {
        return -1;
      }
      x |= (uint64_t)b << shift;
      *v = x;
      return 0;
    }
    x |= (uint64_t)(b & 0x7f) << shift;
    shift += 7;
  }
  return -1;
}

static size_t put_fixed(uint8_t *out, size_t cap, size_t pos, const void *p,
                        size_t n) {
  if (n > cap - pos) {
    return SHORT;
  }
  memcpy(out + pos, p, n);
  return pos + n;
}

static int get_fixed(const uint8_t *buf, size_t len, size_t *pos, void *p,
                     size_t n) {
  if (n > len - *pos) {
    return -1;
  }
  memcpy(p, buf + *pos, n);
  *pos += n;
  return 0;
}

static size_t put_node(uint8_t *out, size_t cap, size_t pos,
                       const murmur_node_t *n) {
  return put_fixed(out, cap, pos, n->b, sizeof(n->b));
}

static int get_node(const uint8_t *buf, size_t len, size_t *pos,
                    murmur_node_t *n) {
  return get_fixed(buf, len, pos, n->b, sizeof(n->b));
}

static size_t put_addr(uint8_t *out, size_t cap, size_t pos,
                       const murmur_addr_t *a) {
  pos = put_uvarint(out, cap, pos, a->is6 ? 1 : 0);
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_fixed(out, cap, pos, a->ip, a->is6 ? 16 : 4);
  if (pos == SHORT) {
    return SHORT;
  }
  return put_uvarint(out, cap, pos, a->port);
}

static int get_addr(const uint8_t *buf, size_t len, size_t *pos,
                    murmur_addr_t *a) {
  uint64_t fam = 0;
  if (get_uvarint(buf, len, pos, &fam) != 0) {
    return -1;
  }
  memset(a->ip, 0, sizeof(a->ip));
  if (fam == 0) {
    if (get_fixed(buf, len, pos, a->ip, 4) != 0) {
      return -1;
    }
    a->is6 = 0;
  } else if (fam == 1) {
    if (get_fixed(buf, len, pos, a->ip, 16) != 0) {
      return -1;
    }
    a->is6 = 1;
  } else {
    return -1;
  }
  uint64_t port = 0;
  if (get_uvarint(buf, len, pos, &port) != 0 || port > 65535) {
    return -1;
  }
  a->port = (uint16_t)port;
  return 0;
}

static size_t put_member(uint8_t *out, size_t cap, size_t pos,
                         const murmur_member_t *m) {
  pos = put_node(out, cap, pos, &m->node);
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_addr(out, cap, pos, &m->addr);
  if (pos == SHORT) {
    return SHORT;
  }
  pos = put_uvarint(out, cap, pos, m->incarnation);
  if (pos == SHORT) {
    return SHORT;
  }
  return put_uvarint(out, cap, pos, (uint64_t)m->state);
}

static int get_member(const uint8_t *buf, size_t len, size_t *pos,
                      murmur_member_t *m) {
  if (get_node(buf, len, pos, &m->node) != 0) {
    return -1;
  }
  if (get_addr(buf, len, pos, &m->addr) != 0) {
    return -1;
  }
  if (get_uvarint(buf, len, pos, &m->incarnation) != 0) {
    return -1;
  }
  uint64_t st = 0;
  if (get_uvarint(buf, len, pos, &st) != 0 || st > 3) {
    return -1;
  }
  m->state = (murmur_state_t)st;
  return 0;
}

size_t murmur_pkt_encode(const murmur_pkt_t *pkt, uint8_t *out, size_t cap) {
  if (!pkt || !out) {
    return 0;
  }
  size_t pos = 0;
  switch (pkt->tag) {
    case MURMUR_PKT_GOSSIP:
    case MURMUR_PKT_PING:
    case MURMUR_PKT_ACK:
    case MURMUR_PKT_INDIRECT_ACK:
    case MURMUR_PKT_PINGREQ:
      break;
    default:
      return 0;
  }
  pos = put_uvarint(out, cap, pos, (uint64_t)pkt->tag);
  if (pos == SHORT) {
    return 0;
  }
  pos = put_node(out, cap, pos, &pkt->database);
  if (pos == SHORT) {
    return 0;
  }
  pos = put_node(out, cap, pos, &pkt->sender);
  if (pos == SHORT) {
    return 0;
  }
  if (pkt->tag == MURMUR_PKT_INDIRECT_ACK ||
      pkt->tag == MURMUR_PKT_PINGREQ) {
    pos = put_node(out, cap, pos, &pkt->target);
    if (pos == SHORT) {
      return 0;
    }
    pos = put_uvarint(out, cap, pos, pkt->nonce);
    return pos == SHORT ? 0 : pos;
  }
  if (pkt->tag == MURMUR_PKT_PING || pkt->tag == MURMUR_PKT_ACK) {
    pos = put_uvarint(out, cap, pos, pkt->nonce);
    if (pos == SHORT) {
      return 0;
    }
  }
  if (!pkt->members && pkt->n_members > 0) {
    return 0;
  }
  pos = put_uvarint(out, cap, pos, (uint64_t)pkt->n_members);
  if (pos == SHORT) {
    return 0;
  }
  for (size_t i = 0; i < pkt->n_members; i++) {
    pos = put_member(out, cap, pos, &pkt->members[i]);
    if (pos == SHORT) {
      return 0;
    }
  }
  return pos;
}

murmur_mship_status_t murmur_pkt_decode(const uint8_t *buf, size_t len,
                                        murmur_pkt_t *out,
                                        murmur_member_t *members,
                                        size_t members_cap) {
  if (!buf || !out) {
    return MURMUR_MSHIP_INVALID;
  }
  size_t pos = 0;
  uint64_t tag = 0;
  if (get_uvarint(buf, len, &pos, &tag) != 0 || tag > 4) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  memset(out, 0, sizeof(*out));
  out->tag = (murmur_pkt_tag_t)tag;
  if (get_node(buf, len, &pos, &out->database) != 0 ||
      get_node(buf, len, &pos, &out->sender) != 0) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  if (out->tag == MURMUR_PKT_INDIRECT_ACK ||
      out->tag == MURMUR_PKT_PINGREQ) {
    if (get_node(buf, len, &pos, &out->target) != 0 ||
        get_uvarint(buf, len, &pos, &out->nonce) != 0) {
      return MURMUR_MSHIP_PROTOCOL;
    }
  } else {
    if ((out->tag == MURMUR_PKT_PING || out->tag == MURMUR_PKT_ACK) &&
        get_uvarint(buf, len, &pos, &out->nonce) != 0) {
      return MURMUR_MSHIP_PROTOCOL;
    }
    uint64_t n = 0;
    if (get_uvarint(buf, len, &pos, &n) != 0 ||
        n > MURMUR_MAX_VIEW_MEMBERS) {
      return MURMUR_MSHIP_PROTOCOL;
    }
    if (n > members_cap) {
      return MURMUR_MSHIP_OVERLOADED;
    }
    if (n > 0 && !members) {
      return MURMUR_MSHIP_INVALID;
    }
    for (uint64_t i = 0; i < n; i++) {
      if (get_member(buf, len, &pos, &members[i]) != 0) {
        return MURMUR_MSHIP_PROTOCOL;
      }
    }
    out->members = members;
    out->n_members = (size_t)n;
  }
  if (pos != len) {
    return MURMUR_MSHIP_PROTOCOL;
  }
  return MURMUR_OK;
}
