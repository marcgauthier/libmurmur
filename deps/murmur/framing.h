/* murmur framing - membership packet codec (postcard layout).
 *
 * Native port of EncodePacket/DecodePacket (membership.go) over the
 * member.h packet structs. Integers are unsigned LEB128 varints (Go
 * binary.Uvarint semantics, including overflow rejection); node ids
 * are 16 raw bytes; addresses are a varint family plus fixed bytes
 * plus a varint port; member lists carry a varint count capped at
 * 4096 members.
 *
 * Encode returns bytes written, or 0 when out is short or the tag is
 * invalid (valid encodings are never empty). Decode returns a
 * murmur_mship_status_t: PROTOCOL for malformed input (truncation,
 * trailing bytes, unknown tag, bad state/family/port, oversize
 * member list), OVERLOADED when members_cap is short for the
 * decoded count.
 */
#ifndef MURMUR_FRAMING_H
#define MURMUR_FRAMING_H

#include <stddef.h>
#include <stdint.h>

#include "member.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Encodes pkt into out[0,cap). Members come from
 * pkt->members[0,n_members); indirect-ack and ping-request carry
 * none. */
size_t murmur_pkt_encode(const murmur_pkt_t *pkt, uint8_t *out, size_t cap);

/* Decodes buf[0,len) into out; members land in the caller-owned
 * members[0,members_cap) array, which out->members aliases. */
murmur_mship_status_t murmur_pkt_decode(const uint8_t *buf, size_t len,
                                        murmur_pkt_t *out,
                                        murmur_member_t *members,
                                        size_t members_cap);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_FRAMING_H */
