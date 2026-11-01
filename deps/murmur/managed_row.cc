#include "managed_row.h"
#include "managed_codec.h"
#include "managed_policy_state.h"
#include <algorithm>
#include <climits>
#include <cstring>

int ManagedVersion::compare(const ManagedVersion &other) const {
  if(millis!=other.millis) return millis<other.millis?-1:1;
  if(logical!=other.logical) return logical<other.logical?-1:1;
  return origin==other.origin?0:(origin<other.origin?-1:1);
}
bool ManagedVersion::empty() const { return !millis && !logical && origin==std::array<uint8_t,16>{}; }
namespace {
bool causal_policy(int policy) {
  return policy==MURMUR_POLICY_COUNTER || policy==MURMUR_POLICY_SET || policy==MURMUR_POLICY_JSON || policy==MURMUR_POLICY_LIST;
}
void valid_version(const ManagedVersion &v,bool optional=false) {
  if(optional && v.empty()) return;
  if(v.millis>INT64_MAX || (!v.millis && !v.logical) || v.origin==std::array<uint8_t,16>{}) throw ManagedError{SQLITE_CORRUPT};
}
void put_version(ManagedEncoder &e,const ManagedVersion &v) {
  e.number(v.millis); e.number(v.logical); e.raw(v.origin.data(),16);
}
ManagedVersion get_version(ManagedDecoder &d) {
  ManagedVersion v; v.millis=d.number(); auto logical=d.number();
  if(logical>UINT32_MAX) throw ManagedError{SQLITE_CORRUPT};
  v.logical=(uint32_t)logical; auto origin=d.raw(16); std::copy(origin.begin(),origin.end(),v.origin.begin()); return v;
}
void valid_identity(const ManagedRow &r) {
  if(r.table.size()!=16 || r.epoch.size()!=16) throw ManagedError{SQLITE_CORRUPT};
  auto key=managed_decode_values(r.key);
  if(key.empty() || managed_encode_values(key)!=r.key) throw ManagedError{SQLITE_CORRUPT};
  for(auto &v:key) if(v.type==MURMUR_NULL) throw ManagedError{SQLITE_CORRUPT};
  valid_version(r.generation); valid_version(r.tombstone,true);
}
ManagedRowColumn join_column(const ManagedRowColumn &a,const ManagedRowColumn &b) {
  if(a.policy!=b.policy) throw ManagedError{SQLITE_MISMATCH};
  auto out=a;
  if(a.policy==MURMUR_POLICY_LWW) {
    int order=a.version.compare(b.version);
    if(!order && managed_encode_value(a.value)!=managed_encode_value(b.value)) throw ManagedError{SQLITE_CORRUPT};
    if(order<0) out=b;
  } else if(a.policy==MURMUR_POLICY_MIN || a.policy==MURMUR_POLICY_MAX) {
    int order=managed_compare(a.value,b.value);
    if(a.policy==MURMUR_POLICY_MIN?order>0:order<0) out=b;
    /* Numeric equality may have different integer/REAL encodings. Resolve
     * ties by canonical bytes so join remains commutative. */
    else if(!order && managed_encode_value(b.value)<managed_encode_value(a.value)) out=b;
  } else {
    if(a.baseline!=b.baseline) throw ManagedError{SQLITE_CORRUPT};
    auto left=managed_policy_decode(a.policy,a.baseline,a.causal);
    auto right=managed_policy_decode(b.policy,b.baseline,b.causal);
    managed_check(murmur_causal_join(left.causal.get(),right.causal.get()));
    out.causal=managed_causal_bytes(left.causal.get());
  }
  return out;
}
}
ManagedValue managed_row_project(const ManagedRowColumn &column) {
  if(column.policy<0 || column.policy>6) throw ManagedError{SQLITE_CORRUPT};
  if(!causal_policy(column.policy)) return column.value;
  auto state=managed_policy_decode(column.policy,column.baseline,column.causal);
  return managed_policy_project(column.policy,state);
}
std::string managed_row_encode(const ManagedRow &r) {
  valid_identity(r);
  ManagedEncoder e; e.raw("MMR2",4); e.raw(r.table.data(),16); e.blob(r.key); e.raw(r.epoch.data(),16);
  put_version(e,r.generation); put_version(e,r.tombstone); e.number(r.columns.size());
  if(r.columns.size()>32766) throw ManagedError{SQLITE_TOOBIG};
  for(auto &entry:r.columns) {
    if(entry.first.size()!=16) throw ManagedError{SQLITE_CORRUPT};
    auto &c=entry.second;
    if(c.policy<0 || c.policy>6) throw ManagedError{SQLITE_CORRUPT};
    e.raw(entry.first.data(),16); e.number(c.policy);
    if(c.policy==MURMUR_POLICY_LWW) {
      valid_version(c.version); put_version(e,c.version); e.blob(managed_encode_value(c.value));
    } else if(causal_policy(c.policy)) {
      /* Validate type/canonical encoding without requiring an int64
       * projection. A joined counter can be temporarily out of range. */
      auto state=managed_policy_decode(c.policy,c.baseline,c.causal);
      e.blob(c.baseline); e.blob(c.causal);
    } else e.blob(managed_encode_value(c.value));
  }
  return e.bytes;
}
ManagedRow managed_row_decode(const std::string &bytes) {
  ManagedDecoder d(bytes.data(),bytes.size()); if(d.raw(4)!="MMR2") throw ManagedError{SQLITE_CORRUPT};
  ManagedRow out; out.table=d.raw(16); out.key=d.blob(); out.epoch=d.raw(16);
  out.generation=get_version(d); out.tombstone=get_version(d);
  for(size_t n=d.count(32766);n;--n) {
    auto id=d.raw(16); ManagedRowColumn c; auto policy=d.number();
    if(policy>6) throw ManagedError{SQLITE_CORRUPT};
    c.policy=(int)policy;
    if(c.policy==MURMUR_POLICY_LWW) { c.version=get_version(d); c.value=managed_decode_value(d.blob()); }
    else if(causal_policy(c.policy)) { c.baseline=d.blob(); c.causal=d.blob(); }
    else c.value=managed_decode_value(d.blob());
    if(!out.columns.emplace(id,std::move(c)).second) throw ManagedError{SQLITE_CORRUPT};
  }
  d.end(); if(managed_row_encode(out)!=bytes) throw ManagedError{SQLITE_CORRUPT}; return out;
}
ManagedRow managed_row_join(const ManagedRow &a,const ManagedRow &b) {
  /* Validate both even if one generation will be discarded. */
  managed_row_encode(a); managed_row_encode(b);
  if(a.table!=b.table || a.key!=b.key) throw ManagedError{SQLITE_MISMATCH};
  int order=a.generation.compare(b.generation);
  if(order && a.epoch==b.epoch) throw ManagedError{SQLITE_CORRUPT};
  auto out=order<0?b:a;
  if(!order) {
    if(a.epoch!=b.epoch) throw ManagedError{SQLITE_CORRUPT};
    for(auto &entry:b.columns) {
      auto old=out.columns.find(entry.first);
      if(old==out.columns.end()) out.columns.emplace(entry);
      else old->second=join_column(old->second,entry.second);
    }
  }
  if(a.tombstone.compare(b.tombstone)>0) out.tombstone=a.tombstone;
  else out.tombstone=b.tombstone;
  managed_row_encode(out);
  return out;
}
void managed_row_authorize(sqlite3 *db,const ManagedRow *known,const ManagedRow &incoming,
    const uint8_t database[16],const uint8_t signer[16]) {
  if(!db || !database || !signer) throw ManagedError{SQLITE_MISUSE};
  managed_row_encode(incoming);
  if(known) {
    managed_row_encode(*known);
    if(known->table!=incoming.table || known->key!=incoming.key) throw ManagedError{SQLITE_MISMATCH};
    if(known->generation.compare(incoming.generation) || known->epoch!=incoming.epoch) throw ManagedError{SQLITE_BUSY};
  } else if(memcmp(incoming.generation.origin.data(),signer,16)) throw ManagedError{SQLITE_BUSY};
  if(!incoming.tombstone.empty() && memcmp(incoming.tombstone.origin.data(),signer,16) &&
      (!known || known->tombstone.compare(incoming.tombstone)<0)) throw ManagedError{SQLITE_BUSY};
  for(auto &entry:incoming.columns) {
    auto &next=entry.second;
    const ManagedRowColumn *prior=nullptr;
    if(known) { auto found=known->columns.find(entry.first); if(found!=known->columns.end()) prior=&found->second; }
    if(prior && prior->policy!=next.policy) throw ManagedError{SQLITE_MISMATCH};
    if(next.policy==MURMUR_POLICY_LWW) {
      if(memcmp(next.version.origin.data(),signer,16) && (!prior || prior->version.compare(next.version)<0)) throw ManagedError{SQLITE_BUSY};
      if(prior && !prior->version.compare(next.version) && managed_encode_value(prior->value)!=managed_encode_value(next.value)) throw ManagedError{SQLITE_CORRUPT};
    } else if(causal_policy(next.policy)) {
      auto state=managed_policy_decode(next.policy,next.baseline,next.causal);
      ManagedPolicyState trusted;
      if(prior) {
        if(prior->baseline!=next.baseline) throw ManagedError{SQLITE_CORRUPT};
        trusted=managed_policy_decode(prior->policy,prior->baseline,prior->causal);
      } else {
        /* Establishing a baseline requires the original insertion signer.
         * A later schema-policy activation needs a separate signed anchor. */
        if(memcmp(incoming.generation.origin.data(),signer,16)) throw ManagedError{SQLITE_BUSY};
        trusted=managed_policy_initial(db,next.policy,state.baseline,incoming.epoch);
      }
      managed_check(murmur_causal_authorize(trusted.causal.get(),state.causal.get(),database,signer));
    }
  }
}
