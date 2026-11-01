#include "origin.h"
#include "sqlite3.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  uint8_t seed[32]={1},pub[32],wrong[32]={7};
  murmur_origin_envelope_t e={0},other;
  e.database[0]=1; e.origin[0]=2; e.transaction[0]=3; e.sequence=1;
  assert(murmur_origin_public_key(seed,pub)==SQLITE_OK);
  assert(murmur_origin_sign(&e,seed,"hello",5)==SQLITE_OK);
  uint8_t wire[MURMUR_ORIGIN_ENVELOPE_BYTES]; murmur_origin_envelope_t decoded;
  assert(murmur_origin_envelope_encode(&e,wire,sizeof(wire))==SQLITE_OK);
  assert(!memcmp(wire,"MOR2",4));
  assert(murmur_origin_envelope_decode(wire,sizeof(wire),&decoded)==SQLITE_OK);
  assert(decoded.sequence==e.sequence && !memcmp(decoded.signature,e.signature,64));
  assert(murmur_origin_envelope_decode(wire,sizeof(wire)-1,&decoded)==SQLITE_CORRUPT);
  assert(murmur_origin_verify(&e,e.database,e.origin,pub,"hello",5,5)==SQLITE_OK);
  other=e; other.logical++;
  assert(murmur_origin_verify(&other,e.database,e.origin,pub,"hello",5,5)==SQLITE_AUTH);
  other=e; other.schema[0]^=1;
  assert(murmur_origin_verify(&other,e.database,e.origin,pub,"hello",5,5)==SQLITE_AUTH);
  other=e; other.signature[0]^=1;
  assert(murmur_origin_verify(&other,e.database,e.origin,pub,"hello",5,5)==SQLITE_AUTH);
  other=e; other.sequence=0;
  assert(murmur_origin_verify(&other,e.database,e.origin,pub,"hello",5,5)==SQLITE_AUTH);
  assert(murmur_origin_verify(&e,e.database,e.origin,pub,"jello",5,5)==SQLITE_AUTH);
  assert(murmur_origin_verify(&e,e.database,e.origin,pub,"hello",5,4)==SQLITE_AUTH);
  assert(murmur_origin_verify(&e,e.database,e.origin,wrong,"hello",5,5)==SQLITE_AUTH);
  assert(murmur_origin_verify(&e,wrong,e.origin,pub,"hello",5,5)==SQLITE_AUTH);
  assert(murmur_origin_verify(&e,e.database,wrong,pub,"hello",5,5)==SQLITE_AUTH);
  assert(murmur_origin_sign(&e,seed,NULL,0)==SQLITE_OK);
  assert(murmur_origin_verify(&e,e.database,e.origin,pub,NULL,0,0)==SQLITE_OK);
  puts("ORIGIN-OK"); return 0;
}
