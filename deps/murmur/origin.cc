#include "origin.h"
#include "sqlite3.h"
#include "../aws-lc/include/openssl/curve25519.h"
#include "../aws-lc/include/openssl/sha.h"
#include "../aws-lc/include/openssl/mem.h"
#include <string.h>

/* Native protocol domain; intentionally distinct from the Go wire format.
 * Integers are little endian; C struct padding never enters signatures. */
static size_t preimage(const murmur_origin_envelope_t *e, uint8_t *out) {
  static const char domain[] = "murmur/native-origin/v2";
  uint8_t *p = out;
  memcpy(p, domain, sizeof(domain)-1); p += sizeof(domain)-1;
  memcpy(p, e->database, 16); p += 16;
  memcpy(p, e->origin, 16); p += 16;
  memcpy(p, e->transaction, 16); p += 16;
  for (unsigned i=0;i<8;++i) *p++ = (uint8_t)(e->sequence >> (8*i));
  for (unsigned i=0;i<8;++i) *p++ = (uint8_t)(e->millis >> (8*i));
  for (unsigned i=0;i<4;++i) *p++ = (uint8_t)(e->logical >> (8*i));
  memcpy(p, e->schema, 32); p += 32;
  memcpy(p, e->payload_digest, 32); p += 32;
  return (size_t)(p-out);
}
extern "C" int murmur_origin_public_key(const uint8_t seed[32], uint8_t pub[32]) {
  if (!seed || !pub) return SQLITE_MISUSE;
  uint8_t priv[64];
  ED25519_keypair_from_seed(pub, priv, seed);
  OPENSSL_cleanse(priv, sizeof(priv));
  return SQLITE_OK;
}
extern "C" int murmur_origin_sign(murmur_origin_envelope_t *e,
    const uint8_t seed[32], const void *payload, size_t n) {
  if (!e || !seed || (!payload && n) || !e->sequence) return SQLITE_MISUSE;
  SHA256((const uint8_t *)(payload ? payload : ""), n, e->payload_digest);
  uint8_t pub[32], priv[64], bytes[192];
  ED25519_keypair_from_seed(pub, priv, seed);
  size_t len = preimage(e, bytes);
  int ok = ED25519_sign(e->signature, bytes, len, priv);
  OPENSSL_cleanse(priv, sizeof(priv));
  return ok ? SQLITE_OK : SQLITE_ERROR;
}
extern "C" int murmur_origin_verify(const murmur_origin_envelope_t *e,
    const uint8_t database[16], const uint8_t origin[16], const uint8_t pub[32],
    const void *payload, size_t n, size_t max) {
  if (!e || !database || !origin || !pub || (!payload && n)) return SQLITE_MISUSE;
  if (!e->sequence || n > max || memcmp(e->database, database, 16) ||
      memcmp(e->origin, origin, 16)) return SQLITE_AUTH;
  uint8_t digest[32], bytes[192];
  SHA256((const uint8_t *)(payload ? payload : ""), n, digest);
  if (CRYPTO_memcmp(digest, e->payload_digest, 32)) return SQLITE_AUTH;
  size_t len = preimage(e, bytes);
  return ED25519_verify(bytes, len, e->signature, pub) ? SQLITE_OK : SQLITE_AUTH;
}
extern "C" int murmur_origin_envelope_encode(const murmur_origin_envelope_t *e,void *out,size_t cap) {
  if(!e || !out || !e->sequence) return SQLITE_MISUSE;
  if(cap<MURMUR_ORIGIN_ENVELOPE_BYTES) return SQLITE_TOOBIG;
  auto *p=(uint8_t *)out; memcpy(p,"MOR2",4); p+=4;
  memcpy(p,e->database,16); p+=16; memcpy(p,e->origin,16); p+=16; memcpy(p,e->transaction,16); p+=16;
  for(unsigned i=0;i<8;++i) *p++=(uint8_t)(e->sequence>>(8*i));
  for(unsigned i=0;i<8;++i) *p++=(uint8_t)(e->millis>>(8*i));
  for(unsigned i=0;i<4;++i) *p++=(uint8_t)(e->logical>>(8*i));
  memcpy(p,e->schema,32); p+=32; memcpy(p,e->payload_digest,32); p+=32; memcpy(p,e->signature,64);
  return SQLITE_OK;
}
extern "C" int murmur_origin_envelope_decode(const void *input,size_t n,murmur_origin_envelope_t *e) {
  if(!input || !e) return SQLITE_MISUSE;
  if(n!=MURMUR_ORIGIN_ENVELOPE_BYTES || memcmp(input,"MOR2",4)) return SQLITE_CORRUPT;
  auto *p=(const uint8_t *)input+4; murmur_origin_envelope_t out{};
  memcpy(out.database,p,16); p+=16; memcpy(out.origin,p,16); p+=16; memcpy(out.transaction,p,16); p+=16;
  for(unsigned i=0;i<8;++i) out.sequence|=(uint64_t)*p++<<(8*i);
  for(unsigned i=0;i<8;++i) out.millis|=(uint64_t)*p++<<(8*i);
  for(unsigned i=0;i<4;++i) out.logical|=(uint32_t)*p++<<(8*i);
  memcpy(out.schema,p,32); p+=32; memcpy(out.payload_digest,p,32); p+=32; memcpy(out.signature,p,64);
  if(!out.sequence) return SQLITE_CORRUPT;
  *e=out; return SQLITE_OK;
}
