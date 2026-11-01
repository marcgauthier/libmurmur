#include "causal.h"
#include "sqlite3.h"
#include <cassert>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include <cstdio>
using Bytes=std::string;
static Bytes encoded(murmur_causal_t *s) {
  uint8_t *p=nullptr; size_t n=0;
  assert(murmur_causal_encode(s,&p,&n)==SQLITE_OK);
  Bytes out((const char *)p,n); free(p); return out;
}
static murmur_causal_t *make(murmur_causal_kind_t k) {
  murmur_causal_t *s=nullptr; assert(murmur_causal_create(k,&s)==SQLITE_OK); return s;
}
static murmur_causal_t *clone(murmur_causal_t *s) {
  auto b=encoded(s); murmur_causal_t *out=nullptr;
  assert(murmur_causal_decode(b.data(),b.size(),&out)==SQLITE_OK); return out;
}
static murmur_causal_tag_t tag(uint32_t op) {
  murmur_causal_tag_t t{}; t.database[0]=1; t.node[0]=2; t.transaction[0]=3; t.operation=op; return t;
}
static void add(murmur_causal_t *s,const Bytes &v,uint32_t op,const Bytes &path="") {
  auto t=tag(op);
  assert(murmur_causal_apply(s,MURMUR_CAUSAL_ADD,path.data(),path.size(),v.data(),v.size(),&t)==SQLITE_OK);
}
static void remove(murmur_causal_t *s,const Bytes &v,const Bytes &path="") {
  assert(murmur_causal_apply(s,MURMUR_CAUSAL_REMOVE,path.data(),path.size(),v.data(),v.size(),nullptr)==SQLITE_OK);
}
using Values=std::vector<std::pair<Bytes,Bytes>>;
static int visit(void *ctx,const void *p,size_t pn,const void *v,size_t vn) {
  ((Values *)ctx)->push_back({Bytes(p?(const char *)p:"",pn),Bytes((const char *)v,vn)}); return 0;
}
static Values values(murmur_causal_t *s) {
  Values out; assert(murmur_causal_values(s,visit,&out)==SQLITE_OK); return out;
}
static std::map<Bytes,Bytes> fixtures(const char *path) {
  std::ifstream in(path); assert(in.good()); std::map<Bytes,Bytes> out;
  Bytes name,hex;
  while(in>>name>>hex) {
    Bytes raw;
    for(size_t i=0;i<hex.size();i+=2) raw.push_back((char)std::stoul(hex.substr(i,2),nullptr,16));
    out[name]=raw;
  }
  assert(out.size()==9); return out;
}
static void proof(murmur_causal_t *s) {
  auto b=encoded(s); auto *copy=clone(s);
  assert(encoded(copy)==b);
  assert(murmur_causal_join(s,copy)==SQLITE_OK && encoded(s)==b);
  murmur_causal_free(copy);
  for(size_t n=0;n<b.size();++n) {
    murmur_causal_t *bad=nullptr;
    assert(murmur_causal_decode(b.data(),n,&bad)==SQLITE_CORRUPT && !bad);
  }
  b+='\0'; murmur_causal_t *bad=nullptr;
  assert(murmur_causal_decode(b.data(),b.size(),&bad)==SQLITE_CORRUPT && !bad);
}
static void authorization() {
  uint8_t db[16]={1},alice[16]={2},bob[16]={4};
  for(auto kind:{MURMUR_CAUSAL_COUNTER,MURMUR_CAUSAL_SET,MURMUR_CAUSAL_JSON,MURMUR_CAUSAL_LIST}) {
    auto *empty=make(kind),*a=make(kind),*b=make(kind);
    if(kind==MURMUR_CAUSAL_COUNTER) {
      assert(murmur_causal_counter_add(a,db,alice,5)==SQLITE_OK);
      assert(murmur_causal_counter_add(b,db,bob,7)==SQLITE_OK);
    } else {
      auto ta=tag(1),tb=tag(2); memcpy(tb.node,bob,16);
      const char *path=kind==MURMUR_CAUSAL_JSON?"field":"";
      assert(murmur_causal_apply(a,MURMUR_CAUSAL_ADD,path,strlen(path),"a",1,&ta)==SQLITE_OK);
      assert(murmur_causal_apply(b,MURMUR_CAUSAL_ADD,path,strlen(path),"b",1,&tb)==SQLITE_OK);
    }
    assert(murmur_causal_authorize(empty,a,db,alice)==SQLITE_OK);
    assert(murmur_causal_authorize(empty,a,db,bob)==SQLITE_BUSY);
    assert(murmur_causal_authorize(empty,b,db,alice)==SQLITE_BUSY);
    auto *forwarded=clone(a); assert(murmur_causal_join(forwarded,b)==SQLITE_OK);
    auto before=encoded(empty),payload=encoded(forwarded);
    /* A valid signature by Bob cannot attest Alice's missing history. */
    assert(murmur_causal_authorize(empty,forwarded,db,bob)==SQLITE_BUSY);
    assert(encoded(empty)==before && encoded(forwarded)==payload);
    assert(murmur_causal_authorize(a,forwarded,db,bob)==SQLITE_OK);
    assert(murmur_causal_authorize(b,forwarded,db,alice)==SQLITE_OK);
    if(kind!=MURMUR_CAUSAL_COUNTER) {
      remove(forwarded,"a",kind==MURMUR_CAUSAL_JSON?"field":"");
      assert(murmur_causal_authorize(a,forwarded,db,bob)==SQLITE_OK);
      /* A removal for an unseen tag also waits for the signed addition. */
      Bytes missing=kind==MURMUR_CAUSAL_JSON?Bytes("\2\0\1\5field\1",10):Bytes(kind==MURMUR_CAUSAL_SET?"\1\0\1":"\3\0\1",3);
      auto ta=tag(99); missing.append((const char *)&ta.database,16); missing.append((const char *)&ta.node,16); missing.append((const char *)&ta.transaction,16); missing+=(char)ta.operation;
      murmur_causal_t *unseen=nullptr; assert(murmur_causal_decode(missing.data(),missing.size(),&unseen)==SQLITE_OK);
      assert(murmur_causal_authorize(empty,unseen,db,bob)==SQLITE_BUSY); murmur_causal_free(unseen);
    }
    for(auto *p:{empty,a,b,forwarded}) murmur_causal_free(p);
  }
}
int main(int argc,char **argv) {
  authorization();
  auto gold=fixtures(argc>1?argv[1]:"deps/murmur/testdata/causal_vectors.txt");
  uint8_t db[16]={1},node[16]={2},other[16]={4};
  auto *c=make(MURMUR_CAUSAL_COUNTER); assert(encoded(c)==gold["counter-empty"]);
  assert(murmur_causal_counter_add(c,db,node,5)==SQLITE_OK);
  assert(murmur_causal_counter_add(c,db,node,-2)==SQLITE_OK);
  assert(murmur_causal_counter_add(c,db,other,10)==SQLITE_OK);
  int64_t v=0; assert(murmur_causal_counter_value(c,&v)==SQLITE_OK && v==13);
  assert(encoded(c)==gold["counter"]); proof(c);
  auto *minimum=make(MURMUR_CAUSAL_COUNTER);
  assert(murmur_causal_counter_add(minimum,db,node,INT64_MIN)==SQLITE_OK);
  assert(murmur_causal_counter_value(minimum,&v)==SQLITE_OK && v==INT64_MIN);
  assert(encoded(minimum)==gold["counter-min"]);
  assert(murmur_causal_counter_add(minimum,db,node,INT64_MIN)==SQLITE_TOOBIG);
  auto *wide=make(MURMUR_CAUSAL_COUNTER);
  assert(murmur_causal_counter_add(wide,db,node,INT64_MAX)==SQLITE_OK);
  assert(murmur_causal_counter_add(wide,db,other,1)==SQLITE_OK);
  assert(murmur_causal_counter_value(wide,&v)==SQLITE_TOOBIG);
  assert(murmur_causal_counter_add(wide,db,node,INT64_MIN)==SQLITE_OK);
  assert(murmur_causal_counter_value(wide,&v)==SQLITE_OK && v==0);
  auto *s=make(MURMUR_CAUSAL_SET); assert(encoded(s)==gold["set-empty"]);
  add(s,"b",1); add(s,"a",2); remove(s,"b"); add(s,"b",3); add(s,Bytes("\xff\0",2),4);
  assert(encoded(s)==gold["set"] && values(s).size()==3); proof(s);
  auto *j=make(MURMUR_CAUSAL_JSON); assert(encoded(j)==gold["json-empty"]);
  add(j,"old",1,"a"); add(j,"new",2,"a"); add(j,"gone",3,"b"); remove(j,"","b");
  auto *concurrent=make(MURMUR_CAUSAL_JSON); add(concurrent,"survives",4,"b");
  assert(murmur_causal_join(j,concurrent)==SQLITE_OK);
  assert(encoded(j)==gold["json"] && values(j).size()==2 && values(j)[0].second=="new"); proof(j);
  auto *l=make(MURMUR_CAUSAL_LIST); assert(encoded(l)==gold["list-empty"]);
  add(l,"a",1); add(l,"a",2); remove(l,"a"); add(l,"a",3); add(l,"b",4);
  assert(encoded(l)==gold["list"] && values(l).size()==2); proof(l);
  /* Concurrent append survives observed remove; joins are commutative. */
  auto *left=clone(l),*right=clone(l);
  remove(left,"a"); add(right,"a",5);
  auto *a=clone(left),*b=clone(right);
  assert(murmur_causal_join(a,right)==SQLITE_OK);
  assert(murmur_causal_join(b,left)==SQLITE_OK);
  assert(encoded(a)==encoded(b) && values(a).size()==2);
  auto before=encoded(a);
  assert(murmur_causal_join(a,j)==SQLITE_MISMATCH && encoded(a)==before);
  /* Conflicting reuse of one operation identity is rejected atomically. */
  auto *collision=make(MURMUR_CAUSAL_LIST); add(collision,"wrong",5);
  assert(murmur_causal_join(a,collision)==SQLITE_CORRUPT && encoded(a)==before);
  uint8_t bad[]={0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f};
  murmur_causal_t *invalid=nullptr;
  assert(murmur_causal_decode(bad,sizeof(bad),&invalid)==SQLITE_CORRUPT);
  for(auto *p:{c,minimum,wide,s,j,concurrent,l,left,right,a,b,collision}) murmur_causal_free(p);
  puts("CAUSAL-OK (9 Go vectors, joins, signer authorization, malformed codecs)");
}
