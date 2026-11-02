#include "murmur_codec.h"
#include "keyring.h"
#include "scrypt.h"
#include "crc32c.h"
#include "sqlite3.h"
#include "libmurmur.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"failed: %s line %d\n",#x,__LINE__);exit(1); } } while(0)
int main(void) {
  /* RFC 7914 section 12, empty password/salt, first 32 bytes. */
  const unsigned char expected[32]={0x77,0xd6,0x57,0x62,0x38,0x65,0x7b,0x20,0x3b,0x19,0xca,0x42,0xc1,0x8a,0x04,0x97,0xf1,0x6b,0x48,0x44,0xe3,0x07,0x4a,0xe8,0xdf,0xdf,0xfa,0x3f,0xed,0xe2,0x14,0x42};
  unsigned char out[32];
  CHECK(murmur_scrypt_derive(NULL,0,NULL,0,16,1,1,out,32)==0);
  CHECK(memcmp(out,expected,32)==0);
  CHECK(!murmur_scrypt_params_valid(3,8,1));
  CHECK(!murmur_scrypt_params_valid(1u<<30,8,1));
  CHECK(!murmur_scrypt_params_valid(65536,32,16));
  unsigned char sid[16]={0},ctx[16]={1},master[32]={2};
  const unsigned char pass[]="correct horse battery staple";
  unsigned char *env=NULL;size_t length=0;
  CHECK(murmur_kr_create(MURMUR_KDF_SCRYPT,16,8,1,NULL,0,sid,ctx,NULL,0,pass,sizeof(pass)-1,&env,&length)==MURMUR_KR_OK);
  CHECK(env[6]==2);
  int rc=-1; murmur_keyring_t *ring=murmur_kr_open(env,length,NULL,0,pass,sizeof(pass)-1,sid,ctx,&rc);
  CHECK(ring && rc==MURMUR_KR_OK && ring->scrypt_n==16 && ring->scrypt_r==8 && ring->scrypt_p==1);
  uint8_t *rotated=NULL;size_t rotated_len=0;uint32_t next=0;
  CHECK(murmur_kr_rotate(ring,sid,NULL,0,pass,sizeof(pass)-1,&rotated,&rotated_len,&next)==MURMUR_KR_OK && next==2);
  murmur_kr_free_ring(ring);murmur_kr_free(rotated);
  CHECK(!murmur_kr_open(env,length,NULL,0,(const uint8_t *)"wrong",5,sid,ctx,&rc) && rc==MURMUR_KR_AUTH);
  unsigned char saved_n[4]; memcpy(saved_n,env+47,4);
  memset(env+47,0xff,4);
  uint32_t crc=murmur_crc32c(env,57);
  for(int i=0;i<4;i++) env[57+i]=(uint8_t)(crc>>(8*i));
  CHECK(!murmur_kr_open(env,length,NULL,0,pass,sizeof(pass)-1,sid,ctx,&rc) && rc==MURMUR_KR_CORRUPT);
  memcpy(env+47,saved_n,4);
  env[6]=1;
  crc=murmur_crc32c(env,57);
  for(int i=0;i<4;i++) env[57+i]=(uint8_t)(crc>>(8*i));
  CHECK(!murmur_kr_open(env,length,NULL,0,pass,sizeof(pass)-1,sid,ctx,&rc));
  murmur_kr_free(env);
  CHECK(murmur_kr_create(1,16,8,1,NULL,0,sid,ctx,NULL,0,pass,sizeof(pass)-1,&env,&length)==MURMUR_KR_MISUSE);
  CHECK(!murmur_codec_create(2,0,master,0,NULL,0,NULL,NULL,0,master));
  MurmurCodec *codec=murmur_codec_create(1,0,master,0,NULL,0,NULL,NULL,0,master);CHECK(codec);
  CHECK(murmur_codec_set_cipher(codec,2)<0);
  unsigned char page[4096]={0},record[8192],plain[4096];
  CHECK(murmur_codec_seal(codec,1,page,record,sizeof(record),NULL)>0);
  CHECK(memcmp(record,"EXP1",4)==0);
  memcpy(record,"EXP2",4);CHECK(murmur_codec_open(codec,1,record,4096,plain,4096)<0);
  murmur_codec_destroy(codec);
  puts("CRYPTO-POLICY-OK");return 0;
}
