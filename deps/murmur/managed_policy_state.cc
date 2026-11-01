#include "managed_policy_state.h"
#include <cstring>
#include <cstdlib>
#include <map>

std::string managed_causal_bytes(const murmur_causal_t *c) {
  uint8_t *raw=nullptr; size_t n=0; managed_check(murmur_causal_encode(c,&raw,&n));
  std::unique_ptr<uint8_t,decltype(&free)> owned(raw,free); return std::string((char *)raw,n);
}
ManagedPolicyState managed_policy_initial(sqlite3 *db,int policy,const ManagedValue &baseline,const std::string &epoch) {
  if(epoch.size()!=16 || (policy!=MURMUR_POLICY_COUNTER && policy!=MURMUR_POLICY_SET && policy!=MURMUR_POLICY_JSON && policy!=MURMUR_POLICY_LIST)) throw ManagedError{SQLITE_MISUSE};
  ManagedPolicyState state; state.baseline=baseline;
  auto kind=policy==MURMUR_POLICY_COUNTER?MURMUR_CAUSAL_COUNTER:(policy==MURMUR_POLICY_SET?MURMUR_CAUSAL_SET:(policy==MURMUR_POLICY_JSON?MURMUR_CAUSAL_JSON:MURMUR_CAUSAL_LIST));
  murmur_causal_t *raw=nullptr; managed_check(murmur_causal_create(kind,&raw)); state.causal.reset(raw);
  if(policy==MURMUR_POLICY_COUNTER) {
    if(baseline.type!=MURMUR_INTEGER) throw ManagedError{SQLITE_MISMATCH};
    return state;
  }
  std::vector<std::pair<std::string,ManagedValue>> seeds;
  if(policy==MURMUR_POLICY_SET) {
    if(baseline.type==MURMUR_BLOB) for(auto &v:managed_decode_values(baseline.data)) seeds.emplace_back("",v);
    else if(baseline.type!=MURMUR_NULL) throw ManagedError{SQLITE_MISMATCH};
  } else seeds=managed_json_parse(db,baseline,policy==MURMUR_POLICY_JSON);
  if(policy==MURMUR_POLICY_JSON) {
    std::map<std::string,ManagedValue> sorted; for(auto &seed:seeds) sorted[seed.first]=seed.second;
    seeds.assign(sorted.begin(),sorted.end());
  }
  uint32_t i=0;
  for(auto &seed:seeds) {
    murmur_causal_tag_t tag{}; memcpy(tag.transaction,epoch.data(),16); tag.operation=i++;
    auto value=managed_encode_value(seed.second);
    managed_check(murmur_causal_apply(raw,MURMUR_CAUSAL_ADD,seed.first.data(),seed.first.size(),value.data(),value.size(),&tag));
  }
  return state;
}
namespace {
using Projection=std::vector<std::pair<std::string,ManagedValue>>;
int collect(void *ctx,const void *path,size_t pn,const void *value,size_t vn) {
  ((Projection *)ctx)->emplace_back(std::string(path?(const char *)path:"",pn),managed_decode_value(std::string((const char *)value,vn)));
  return 0;
}
}
ManagedValue managed_policy_project(int policy,ManagedPolicyState &state) {
  ManagedValue out;
  if(policy==MURMUR_POLICY_COUNTER) {
    out.type=MURMUR_INTEGER;
    managed_check(murmur_causal_counter_project(state.causal.get(),state.baseline.integer,&out.integer)); return out;
  }
  Projection values; managed_check(murmur_causal_values(state.causal.get(),collect,&values));
  if(policy==MURMUR_POLICY_SET) {
    std::vector<ManagedValue> plain; for(auto &v:values) plain.push_back(v.second);
    out.type=MURMUR_BLOB; out.data=managed_encode_values(plain); return out;
  }
  out.type=MURMUR_TEXT; out.data=policy==MURMUR_POLICY_JSON?"{":"[";
  bool first=true;
  for(auto &v:values) {
    if(!first) out.data+=',';
    first=false;
    if(policy==MURMUR_POLICY_JSON) out.data+=managed_json_quote(v.first)+":";
    out.data+=managed_json_scalar(v.second);
  }
  out.data+=policy==MURMUR_POLICY_JSON?'}':']'; return out;
}
ManagedPolicyState managed_policy_decode(int policy,const std::string &baseline,const std::string &causal) {
  ManagedPolicyState state; state.baseline=managed_decode_value(baseline);
  if(managed_encode_value(state.baseline)!=baseline) throw ManagedError{SQLITE_CORRUPT};
  murmur_causal_t *raw=nullptr; managed_check(murmur_causal_decode(causal.data(),causal.size(),&raw)); state.causal.reset(raw);
  murmur_causal_kind_t kind; managed_check(murmur_causal_kind(raw,&kind));
  int expected=policy==MURMUR_POLICY_COUNTER?MURMUR_CAUSAL_COUNTER:(policy==MURMUR_POLICY_SET?MURMUR_CAUSAL_SET:(policy==MURMUR_POLICY_JSON?MURMUR_CAUSAL_JSON:(policy==MURMUR_POLICY_LIST?MURMUR_CAUSAL_LIST:-1)));
  if(expected<0 || (int)kind!=expected || managed_causal_bytes(raw)!=causal) throw ManagedError{SQLITE_CORRUPT};
  if(policy==MURMUR_POLICY_COUNTER && state.baseline.type!=MURMUR_INTEGER) throw ManagedError{SQLITE_CORRUPT};
  return state;
}
