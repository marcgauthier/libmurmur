#include "managed_row.h"
#include "managed_policy_state.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>

static std::string id(char c) { return std::string(16,c); }
static ManagedValue integer(int64_t n) { ManagedValue v; v.type=MURMUR_INTEGER; v.integer=n; return v; }
static ManagedValue text(const std::string &s) { ManagedValue v; v.type=MURMUR_TEXT; v.data=s; return v; }
static ManagedVersion version(uint64_t time,uint8_t node) { ManagedVersion v; v.millis=time; v.origin[0]=node; return v; }
static ManagedRowColumn cell(sqlite3 *db,int policy,const ManagedValue &value) {
  ManagedRowColumn c; c.policy=policy;
  if(policy==MURMUR_POLICY_LWW) { c.value=value; c.version=version(1,1); }
  else if(policy==MURMUR_POLICY_MIN || policy==MURMUR_POLICY_MAX) c.value=value;
  else {
    auto state=managed_policy_initial(db,policy,value,id('e'));
    c.baseline=managed_encode_value(value); c.causal=managed_causal_bytes(state.causal.get());
  }
  return c;
}
static ManagedRow base(sqlite3 *db) {
  ManagedRow r; r.table=id('t'); r.key=managed_encode_values({integer(42)}); r.epoch=id('e'); r.generation=version(1,1);
  r.columns[id('0')]=cell(db,MURMUR_POLICY_LWW,text("base"));
  r.columns[id('1')]=cell(db,MURMUR_POLICY_COUNTER,integer(10));
  r.columns[id('2')]=cell(db,MURMUR_POLICY_SET,ManagedValue{});
  r.columns[id('3')]=cell(db,MURMUR_POLICY_MIN,integer(10));
  r.columns[id('4')]=cell(db,MURMUR_POLICY_MAX,integer(10));
  r.columns[id('5')]=cell(db,MURMUR_POLICY_JSON,text("{}"));
  r.columns[id('6')]=cell(db,MURMUR_POLICY_LIST,text("[]")); return r;
}
static void mutate(ManagedRowColumn &c,int node,int64_t delta,const char *value,const char *path="") {
  auto state=managed_policy_decode(c.policy,c.baseline,c.causal);
  uint8_t db[16]={1},origin[16]={(uint8_t)node};
  if(c.policy==MURMUR_POLICY_COUNTER) managed_check(murmur_causal_counter_add(state.causal.get(),db,origin,delta));
  else {
    murmur_causal_tag_t tag{}; memcpy(tag.database,db,16); memcpy(tag.node,origin,16); tag.transaction[0]=1;
    auto encoded=managed_encode_value(text(value));
    managed_check(murmur_causal_apply(state.causal.get(),MURMUR_CAUSAL_ADD,path,strlen(path),encoded.data(),encoded.size(),&tag));
  }
  c.causal=managed_causal_bytes(state.causal.get());
}
static void unchanged_error(const ManagedRow &a,const ManagedRow &b,int code) {
  auto before=managed_row_encode(a),other=managed_row_encode(b); bool failed=false;
  try { managed_row_join(a,b); } catch(const ManagedError &e) { failed=e.code==code; }
  assert(failed && managed_row_encode(a)==before && managed_row_encode(b)==other);
}
int main() {
  sqlite3 *db=nullptr; assert(sqlite3_open(":memory:",&db)==SQLITE_OK);
  auto seed=base(db); auto a=seed,b=seed,c=seed;
  auto change=[&](ManagedRow &r,int node,int64_t delta,const char *label,const char *path,int minimum,int maximum) {
    r.columns[id('0')].value=text(label); r.columns[id('0')].version=version(10,node);
    mutate(r.columns[id('1')],node,delta,label);
    mutate(r.columns[id('2')],node,0,label);
    r.columns[id('3')].value=integer(minimum); r.columns[id('4')].value=integer(maximum);
    mutate(r.columns[id('5')],node,0,label,path); mutate(r.columns[id('6')],node,0,label);
  };
  change(a,1,2,"x","a",5,20); change(b,2,3,"y","b",7,15); change(c,3,-1,"x","c",9,30);
  uint8_t database[16]={1},alice[16]={1},bob[16]={2};
  managed_row_authorize(db,nullptr,a,database,alice);
  managed_row_authorize(db,&seed,b,database,bob);
  auto ab=managed_row_join(a,b);
  auto auth_error=[&](const ManagedRow *known,const ManagedRow &incoming,const uint8_t signer[16],int code) {
    bool failed=false;
    try { managed_row_authorize(db,known,incoming,database,signer); } catch(const ManagedError &e) { failed=e.code==code; }
    assert(failed);
  };
  auth_error(nullptr,b,bob,SQLITE_BUSY);
  auth_error(&seed,ab,bob,SQLITE_BUSY);
  managed_row_authorize(db,&a,ab,database,bob);
  auto joined=managed_row_join(managed_row_join(a,b),c);
  auto encoded=managed_row_encode(joined);
  assert(managed_row_encode(managed_row_decode(encoded))==encoded);
  assert(managed_row_project(joined.columns[id('0')]).data=="x");
  assert(managed_row_project(joined.columns[id('1')]).integer==14);
  assert(managed_decode_values(managed_row_project(joined.columns[id('2')]).data).size()==2);
  assert(managed_row_project(joined.columns[id('3')]).integer==5);
  assert(managed_row_project(joined.columns[id('4')]).integer==30);
  assert(managed_row_project(joined.columns[id('5')]).data=="{\"a\":\"x\",\"b\":\"y\",\"c\":\"x\"}");
  assert(managed_row_project(joined.columns[id('6')]).data=="[\"x\",\"y\",\"x\"]");
  int order[]={0,1,2}; ManagedRow rows[]={a,b,c};
  do {
    auto result=managed_row_join(managed_row_join(rows[order[0]],rows[order[1]]),rows[order[2]]);
    assert(managed_row_encode(result)==encoded);
    assert(managed_row_encode(managed_row_join(rows[order[0]],managed_row_join(rows[order[1]],rows[order[2]])))==encoded);
    assert(managed_row_encode(managed_row_join(result,result))==encoded);
  } while(std::next_permutation(order,order+3));
  /* Edits cannot resurrect a deleted generation even with newer clocks. */
  auto dead=seed; dead.tombstone=version(2,2);
  managed_row_authorize(db,&seed,dead,database,bob);
  auth_error(&seed,dead,alice,SQLITE_BUSY);
  auto deleted=managed_row_join(joined,dead); assert(!deleted.alive());
  auto fresh=base(db); fresh.generation=version(4,1); fresh.epoch=id('f');
  fresh.columns[id('1')]=cell(db,MURMUR_POLICY_COUNTER,integer(100));
  auto replacement=managed_row_join(fresh,deleted);
  assert(replacement.alive() && replacement.epoch==fresh.epoch && managed_row_project(replacement.columns[id('1')]).integer==100);
  assert(managed_row_encode(managed_row_join(replacement,a))==managed_row_encode(replacement));
  assert(managed_row_encode(managed_row_join(deleted,fresh))==managed_row_encode(replacement));
  /* A simultaneous insert has its own baselines; the generation wins whole. */
  auto rival=fresh; rival.generation=version(4,2); rival.epoch=id('g'); rival.columns[id('1')]=cell(db,MURMUR_POLICY_COUNTER,integer(-5));
  assert(managed_row_project(managed_row_join(fresh,rival).columns[id('1')]).integer==-5);
  auto bad=a; bad.columns[id('1')].baseline=managed_encode_value(integer(11)); unchanged_error(a,bad,SQLITE_CORRUPT);
  bad=a; bad.epoch=id('z'); unchanged_error(a,bad,SQLITE_CORRUPT);
  bad=a; bad.generation=version(5,1); unchanged_error(a,bad,SQLITE_CORRUPT);
  bad=a; bad.table=id('u'); unchanged_error(a,bad,SQLITE_MISMATCH);
  bad=a; bad.columns[id('0')].value=text("collision"); unchanged_error(a,bad,SQLITE_CORRUPT);
  auth_error(&a,bad,alice,SQLITE_CORRUPT);
  /* Numerically equal int/REAL min/max values choose one canonical encoding. */
  auto equal=a; equal.columns[id('3')].value.type=MURMUR_REAL; equal.columns[id('3')].value.real=5.0;
  assert(managed_row_encode(managed_row_join(a,equal))==managed_row_encode(managed_row_join(equal,a)));
  for(size_t n=0;n<encoded.size();++n) {
    bool failed=false; try { managed_row_decode(encoded.substr(0,n)); } catch(const ManagedError &e) { failed=e.code==SQLITE_CORRUPT; }
    assert(failed);
  }
  bool failed=false;
  try { managed_row_decode(encoded+std::string(1,'\0')); } catch(const ManagedError &e) { failed=e.code==SQLITE_CORRUPT; }
  assert(failed);
  sqlite3_close(db); puts("MANAGED-ROW-OK (all policies, permutations, generations, malformed codec)");
}
