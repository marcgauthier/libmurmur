#include "causal.h"
#include "postcard.h"
#include "sqlite3.h"
#include <array>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <stdexcept>

namespace {
using Bytes=std::string;
using Actor=std::array<uint8_t,32>;
struct Tag {
  std::array<uint8_t,48> id{};
  uint32_t operation=0;
  bool operator<(const Tag &other) const {
    return id!=other.id ? id<other.id : operation<other.operation;
  }
};
using Tags=std::set<Tag>;
using Writes=std::map<Tag,Bytes>;
Tag tag_of(const murmur_causal_tag_t &t) {
  Tag tag;
  memcpy(tag.id.data(),t.database,16); memcpy(tag.id.data()+16,t.node,16);
  memcpy(tag.id.data()+32,t.transaction,16); tag.operation=t.operation;
  return tag;
}
Bytes bytes(const void *v,size_t n) { return Bytes(v?(const char *)v:"",n); }
constexpr size_t limit=64u<<20;
}
struct murmur_causal {
  murmur_causal_kind_t kind;
  std::map<Actor,uint64_t> positive,negative;
  std::map<Bytes,Tags> additions;
  Tags removals;
  std::map<Bytes,Writes> paths;
  std::map<Bytes,Tags> tombs;
  Writes appends;
};
namespace {
template<class Fn> int mutate(murmur_causal *s,Fn fn) {
  try {
    murmur_causal next=*s;
    int rc=fn(next);
    if (!rc) *s=std::move(next);
    return rc;
  } catch (...) { return SQLITE_NOMEM; }
}
int merge_writes(Writes &to,const Writes &from) {
  for (auto &w:from) {
    auto it=to.find(w.first);
    if (it!=to.end() && it->second!=w.second) return SQLITE_CORRUPT;
    to[w.first]=w.second;
  }
  return SQLITE_OK;
}
struct Encoder {
  std::vector<uint8_t> b;
  void raw(const void *p,size_t n) {
    if (n>limit-b.size()) throw std::length_error("causal size limit");
    const uint8_t *data=(const uint8_t *)p;
    if(n) b.insert(b.end(),data,data+n);
  }
  void u64(uint64_t v) {
    uint8_t buf[10]; size_t n=0;
    do { buf[n++]=(v&127)|(v>=128?128:0); v>>=7; } while(v);
    raw(buf,n);
  }
  void blob(const Bytes &v) { u64(v.size()); raw(v.data(),v.size()); }
  void tag(const Tag &t) { raw(t.id.data(),48); u64(t.operation); }
  void tags(const Tags &v) { u64(v.size()); for(auto &t:v) tag(t); }
  void writes(const Writes &v) { u64(v.size()); for(auto &w:v) { tag(w.first); blob(w.second); } }
};
struct Decoder {
  murmur_pc_dec_t d{};
  Decoder(const void *p,size_t n) { murmur_pc_dec_init(&d,(const uint8_t *)p,n); }
  void valid() { if(d.err) throw std::invalid_argument("invalid causal bytes"); }
  size_t count() {
    size_t n=murmur_pc_g_len(&d); valid();
    if(n>d.len-d.off) throw std::invalid_argument("causal count exceeds input");
    return n;
  }
  template<size_t N> std::array<uint8_t,N> fixed() {
    auto *p=murmur_pc_g_raw(&d,N); valid();
    std::array<uint8_t,N> out; memcpy(out.data(),p,N); return out;
  }
  Bytes blob() {
    size_t n=0; auto *p=murmur_pc_g_bytes(&d,&n); valid(); return bytes(p,n);
  }
  Tag tag() { Tag t; t.id=fixed<48>(); t.operation=murmur_pc_g_u32(&d); valid(); return t; }
  Tags tags() { Tags v; for(size_t n=count();n;--n) v.insert(tag()); return v; }
  Writes writes() {
    Writes v;
    for(size_t n=count();n;--n) { auto t=tag(); v[t]=blob(); }
    return v;
  }
};
}
extern "C" {
int murmur_causal_create(murmur_causal_kind_t kind,murmur_causal_t **out) {
  if(!out) return SQLITE_MISUSE;
  *out=nullptr;
  if(kind<MURMUR_CAUSAL_COUNTER || kind>MURMUR_CAUSAL_LIST) return SQLITE_MISUSE;
  try { auto p=std::make_unique<murmur_causal>(); p->kind=kind; *out=p.release(); return SQLITE_OK; }
  catch (...) { return SQLITE_NOMEM; }
}
void murmur_causal_free(murmur_causal_t *s) { delete s; }
int murmur_causal_kind(const murmur_causal_t *s,murmur_causal_kind_t *out) {
  if(!s || !out) return SQLITE_MISUSE;
  *out=s->kind; return SQLITE_OK;
}
int murmur_causal_counter_add(murmur_causal_t *s,const uint8_t db[16],const uint8_t node[16],int64_t delta) {
  if(!s || !db || !node) return SQLITE_MISUSE;
  if(s->kind!=MURMUR_CAUSAL_COUNTER) return SQLITE_MISMATCH;
  return mutate(s,[&](murmur_causal &next) {
    Actor actor; memcpy(actor.data(),db,16); memcpy(actor.data()+16,node,16);
    auto &component=(delta<0?next.negative:next.positive)[actor];
    uint64_t amount=delta<0?(uint64_t)(-(delta+1))+1:(uint64_t)delta;
    if(amount>UINT64_MAX-component) return SQLITE_TOOBIG;
    component+=amount; return SQLITE_OK;
  });
}
int murmur_causal_counter_value(const murmur_causal_t *s,int64_t *out) {
  return murmur_causal_counter_project(s,0,out);
}
int murmur_causal_counter_project(const murmur_causal_t *s,int64_t baseline,int64_t *out) {
  if(!s || !out) return SQLITE_MISUSE;
  if(s->kind!=MURMUR_CAUSAL_COUNTER) return SQLITE_MISMATCH;
  unsigned __int128 positive=0,negative=0;
  if(baseline>=0) positive=(uint64_t)baseline;
  else negative=(uint64_t)(-(baseline+1))+1;
  for(auto &v:s->positive) { auto before=positive; positive+=v.second; if(positive<before) return SQLITE_TOOBIG; }
  for(auto &v:s->negative) { auto before=negative; negative+=v.second; if(negative<before) return SQLITE_TOOBIG; }
  if(positive>=negative) {
    auto diff=positive-negative; if(diff>INT64_MAX) return SQLITE_TOOBIG;
    *out=(int64_t)diff;
  } else {
    auto diff=negative-positive; if(diff>((unsigned __int128)1<<63)) return SQLITE_TOOBIG;
    *out=diff==((unsigned __int128)1<<63)?INT64_MIN:-(int64_t)diff;
  }
  return SQLITE_OK;
}
int murmur_causal_apply(murmur_causal_t *s,murmur_causal_op_t op,
    const void *path,size_t pn,const void *value,size_t vn,const murmur_causal_tag_t *t) {
  if(!s || (!path && pn) || (!value && vn) || (op!=MURMUR_CAUSAL_ADD && op!=MURMUR_CAUSAL_REMOVE) ||
      (op==MURMUR_CAUSAL_ADD && !t)) return SQLITE_MISUSE;
  if(pn>limit || vn>limit) return SQLITE_TOOBIG;
  if(s->kind==MURMUR_CAUSAL_COUNTER) return SQLITE_MISMATCH;
  return mutate(s,[&](murmur_causal &next) {
    auto key=bytes(path,pn),v=bytes(value,vn); Tag tag=t?tag_of(*t):Tag{};
    if(next.kind==MURMUR_CAUSAL_SET) {
      if(op==MURMUR_CAUSAL_ADD) next.additions[v].insert(tag);
      else {
        auto it=next.additions.find(v);
        if(it!=next.additions.end()) next.removals.insert(it->second.begin(),it->second.end());
      }
    } else if(next.kind==MURMUR_CAUSAL_JSON) {
      auto it=next.paths.find(key);
      if(it!=next.paths.end() && !it->second.empty())
        for(auto &w:it->second) next.tombs[key].insert(w.first);
      if(op==MURMUR_CAUSAL_ADD) {
        auto &writes=next.paths[key]; auto old=writes.find(tag);
        if(old!=writes.end() && old->second!=v) return SQLITE_CORRUPT;
        writes[tag]=v;
      }
    } else if(op==MURMUR_CAUSAL_ADD) {
      auto it=next.appends.find(tag);
      if(it!=next.appends.end() && it->second!=v) return SQLITE_CORRUPT;
      next.appends[tag]=v;
    } else for(auto &w:next.appends) if(w.second==v) next.removals.insert(w.first);
    return SQLITE_OK;
  });
}
int murmur_causal_join(murmur_causal_t *s,const murmur_causal_t *other) {
  if(!s || !other) return SQLITE_MISUSE;
  if(s->kind!=other->kind) return SQLITE_MISMATCH;
  return mutate(s,[&](murmur_causal &next) {
    if(next.kind==MURMUR_CAUSAL_COUNTER) {
      for(auto &v:other->positive) next.positive[v.first]=std::max(next.positive[v.first],v.second);
      for(auto &v:other->negative) next.negative[v.first]=std::max(next.negative[v.first],v.second);
    } else if(next.kind==MURMUR_CAUSAL_SET) {
      for(auto &v:other->additions) next.additions[v.first].insert(v.second.begin(),v.second.end());
      next.removals.insert(other->removals.begin(),other->removals.end());
    } else if(next.kind==MURMUR_CAUSAL_JSON) {
      for(auto &p:other->paths) { int rc=merge_writes(next.paths[p.first],p.second); if(rc) return rc; }
      for(auto &p:other->tombs) next.tombs[p.first].insert(p.second.begin(),p.second.end());
    } else {
      int rc=merge_writes(next.appends,other->appends); if(rc) return rc;
      next.removals.insert(other->removals.begin(),other->removals.end());
    }
    return SQLITE_OK;
  });
}
int murmur_causal_authorize(const murmur_causal_t *known,const murmur_causal_t *incoming,
    const uint8_t database[16],const uint8_t signer[16]) {
  if(!known || !incoming || !database || !signer) return SQLITE_MISUSE;
  if(known->kind!=incoming->kind) return SQLITE_MISMATCH;
  try {
  auto owned=[&](const Tag &tag) {
    return !memcmp(tag.id.data(),database,16) && !memcmp(tag.id.data()+16,signer,16);
  };
  auto writes=[&](const Writes &old,const Writes &next) {
    for(auto &w:next) {
      auto prior=old.find(w.first);
      if(prior!=old.end() && prior->second!=w.second) return SQLITE_CORRUPT;
      if(!owned(w.first) && prior==old.end()) return SQLITE_BUSY;
    }
    return SQLITE_OK;
  };
  if(incoming->kind==MURMUR_CAUSAL_COUNTER) {
    Actor actor; memcpy(actor.data(),database,16); memcpy(actor.data()+16,signer,16);
    for(auto pair:{std::pair<const std::map<Actor,uint64_t> *,const std::map<Actor,uint64_t> *>{&known->positive,&incoming->positive},
                   {&known->negative,&incoming->negative}}) {
      for(auto &component:*pair.second) if(component.first!=actor) {
        auto prior=pair.first->find(component.first);
        if(prior==pair.first->end() || component.second>prior->second) return SQLITE_BUSY;
      }
    }
  } else if(incoming->kind==MURMUR_CAUSAL_SET) {
    std::map<Tag,Bytes> seen;
    for(auto &entry:known->additions) for(auto &tag:entry.second) {
      auto prior=seen.emplace(tag,entry.first);
      if(!prior.second && prior.first->second!=entry.first) return SQLITE_CORRUPT;
    }
    for(auto &entry:incoming->additions) {
      auto prior=known->additions.find(entry.first);
      for(auto &tag:entry.second) {
        if(!owned(tag) && (prior==known->additions.end() || !prior->second.count(tag))) return SQLITE_BUSY;
        auto identity=seen.emplace(tag,entry.first);
        if(!identity.second && identity.first->second!=entry.first) return SQLITE_CORRUPT;
      }
    }
    for(auto &tag:incoming->removals)
      if(!known->removals.count(tag) && !seen.count(tag)) return SQLITE_BUSY;
  } else if(incoming->kind==MURMUR_CAUSAL_JSON) {
    const Writes empty;
    for(auto &path:incoming->paths) {
      auto prior=known->paths.find(path.first);
      int rc=writes(prior==known->paths.end()?empty:prior->second,path.second); if(rc) return rc;
    }
    for(auto &path:incoming->tombs) for(auto &tag:path.second) {
      auto tombs=known->tombs.find(path.first);
      bool seen=tombs!=known->tombs.end() && tombs->second.count(tag);
      for(auto *state:{known,incoming}) {
        auto additions=state->paths.find(path.first);
        if(additions!=state->paths.end() && additions->second.count(tag)) seen=true;
      }
      if(!seen) return SQLITE_BUSY;
    }
  } else {
    int rc=writes(known->appends,incoming->appends); if(rc) return rc;
    for(auto &tag:incoming->removals)
      if(!known->removals.count(tag) && !known->appends.count(tag) && !incoming->appends.count(tag)) return SQLITE_BUSY;
  }
  return SQLITE_OK;
  } catch(...) { return SQLITE_NOMEM; }
}
int murmur_causal_values(const murmur_causal_t *s,murmur_causal_visit_fn visit,void *ctx) {
  if(!s || !visit) return SQLITE_MISUSE;
  if(s->kind==MURMUR_CAUSAL_COUNTER) return SQLITE_MISMATCH;
  try {
    if(s->kind==MURMUR_CAUSAL_SET) {
      for(auto &v:s->additions) for(auto &tag:v.second) if(!s->removals.count(tag)) {
        if(visit(ctx,nullptr,0,v.first.data(),v.first.size())) return SQLITE_ABORT;
        break;
      }
    } else if(s->kind==MURMUR_CAUSAL_JSON) {
      for(auto &path:s->paths) {
        auto tombs=s->tombs.find(path.first);
        for(auto w=path.second.rbegin();w!=path.second.rend();++w)
          if(tombs==s->tombs.end() || !tombs->second.count(w->first)) {
            if(visit(ctx,path.first.data(),path.first.size(),w->second.data(),w->second.size())) return SQLITE_ABORT;
            break;
          }
      }
    } else for(auto &w:s->appends) if(!s->removals.count(w.first))
      if(visit(ctx,nullptr,0,w.second.data(),w.second.size())) return SQLITE_ABORT;
    return SQLITE_OK;
  } catch (...) { return SQLITE_ABORT; }
}
int murmur_causal_encode(const murmur_causal_t *s,uint8_t **out,size_t *len) {
  if(!out || !len) return SQLITE_MISUSE;
  *out=nullptr; *len=0; if(!s) return SQLITE_MISUSE;
  try {
    Encoder e; e.u64(s->kind);
    if(s->kind==MURMUR_CAUSAL_COUNTER) {
      for(auto *map:{&s->positive,&s->negative}) {
        e.u64(map->size()); for(auto &v:*map) { e.raw(v.first.data(),32); e.u64(v.second); }
      }
    } else if(s->kind==MURMUR_CAUSAL_SET) {
      e.u64(s->additions.size()); for(auto &v:s->additions) { e.blob(v.first); e.tags(v.second); }
      e.tags(s->removals);
    } else if(s->kind==MURMUR_CAUSAL_JSON) {
      e.u64(s->paths.size()); for(auto &p:s->paths) { e.blob(p.first); e.writes(p.second); }
      e.u64(s->tombs.size()); for(auto &p:s->tombs) { e.blob(p.first); e.tags(p.second); }
    } else { e.writes(s->appends); e.tags(s->removals); }
    auto *p=(uint8_t *)malloc(e.b.size()); if(!p) return SQLITE_NOMEM;
    memcpy(p,e.b.data(),e.b.size()); *out=p; *len=e.b.size(); return SQLITE_OK;
  } catch(const std::length_error &) { return SQLITE_TOOBIG; }
    catch (...) { return SQLITE_NOMEM; }
}
int murmur_causal_decode(const void *p,size_t n,murmur_causal_t **out) {
  if(!out) return SQLITE_MISUSE;
  *out=nullptr; if(!p && n) return SQLITE_MISUSE;
  if(n>limit) return SQLITE_TOOBIG;
  try {
    Decoder d(p,n); auto kind=murmur_pc_g_disc(&d.d); d.valid();
    if(kind>3) return SQLITE_CORRUPT;
    auto s=std::make_unique<murmur_causal>(); s->kind=(murmur_causal_kind_t)kind;
    if(kind==MURMUR_CAUSAL_COUNTER) {
      for(auto *map:{&s->positive,&s->negative}) for(size_t count=d.count();count;--count) {
        auto actor=d.fixed<32>(); auto value=murmur_pc_g_u64(&d.d); d.valid(); (*map)[actor]=value;
      }
    } else if(kind==MURMUR_CAUSAL_SET) {
      for(size_t count=d.count();count;--count) { auto key=d.blob(); s->additions[key]=d.tags(); }
      s->removals=d.tags();
    } else if(kind==MURMUR_CAUSAL_JSON) {
      for(size_t count=d.count();count;--count) { auto path=d.blob(); s->paths[path]=d.writes(); }
      for(size_t count=d.count();count;--count) { auto path=d.blob(); s->tombs[path]=d.tags(); }
    } else { s->appends=d.writes(); s->removals=d.tags(); }
    if(murmur_pc_end(&d.d)!=MURMUR_PC_OK) return SQLITE_CORRUPT;
    *out=s.release(); return SQLITE_OK;
  } catch(const std::invalid_argument &) { return SQLITE_CORRUPT; }
    catch (...) { return SQLITE_NOMEM; }
}
}
