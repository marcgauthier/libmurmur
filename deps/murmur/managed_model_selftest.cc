#include "test_managed_support.h"
#include "managed_replica.h"
#include "managed_codec.h"
#include <algorithm>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <tuple>

using namespace managed_test;
namespace {
enum Kind { Insert,Delete,Lww,Counter,SetAdd,SetRemove,Minimum,Maximum,JsonSet,JsonRemove,ListAdd,ListRemove };
using Tag=std::pair<std::string,uint64_t>;
struct Event {
  Kind kind=Insert;
  size_t writer=0;
  int operand=0;
  std::string epoch,value,path;
  std::set<size_t> removed;
  std::set<size_t> dependencies;
  Tag tag;
  Record record;
};
auto stamp(const Event &e) {
  auto &v=e.record.value.envelope;
  return std::make_tuple(v.millis,v.logical,std::string((const char *)v.origin,16));
}
/* This reads operation identity only. The oracle never calls the native
 * causal join, projection, row join, or row-version comparison functions. */
std::set<Tag> addition_tags(const std::string &bytes) {
  ManagedDecoder d(bytes.data(),bytes.size()); auto kind=d.number(); std::set<Tag> tags;
  auto tag=[&] { auto identity=d.raw(48); auto operation=d.number(); tags.emplace(identity,operation); };
  if(kind==MURMUR_CAUSAL_SET) {
    for(size_t n=d.count(100000);n;--n) { d.blob(); for(size_t k=d.count(100000);k;--k) tag(); }
  } else if(kind==MURMUR_CAUSAL_JSON) {
    for(size_t n=d.count(100000);n;--n) { d.blob(); for(size_t k=d.count(100000);k;--k) { tag(); d.blob(); } }
  } else if(kind==MURMUR_CAUSAL_LIST) {
    for(size_t n=d.count(100000);n;--n) { tag(); d.blob(); }
  } else require(false,"unexpected causal policy tag encoding");
  return tags;
}
struct Projection {
  bool alive=false;
  std::string epoch,lww;
  int64_t counter=0,minimum=100,maximum=-100;
  std::set<std::string> labels;
  std::string json="{}",list="[]";
};
struct Model {
  uint64_t seed;
  std::mt19937_64 random;
  Cluster cluster;
  std::vector<Event> events;
  std::vector<std::set<size_t>> seen;
  std::vector<std::set<size_t>> visible;
  std::vector<uint64_t> sequence;
  std::set<Tag> issued;
  std::ostringstream trace;
  Model(uint64_t seed,size_t nodes):seed(seed),random(seed),cluster(nodes),seen(nodes),visible(nodes),sequence(nodes) {
    trace<<"seed="<<seed<<" nodes="<<nodes<<"\n";
    check(murmur_managed_migrate(cluster.nodes[0].db,"CREATE TABLE item(id INTEGER NOT NULL PRIMARY KEY,v TEXT,n INTEGER,labels BLOB,lo,hi,settings TEXT,events TEXT)"),"model schema");
    const char *columns[]={"n","labels","lo","hi","settings","events"};
    for(int p=1;p<=6;++p) check(murmur_managed_set_policy(cluster.nodes[0].db,"item",columns[p-1],(murmur_merge_policy_t)p),"model policy");
    check(murmur_managed_set_replication(cluster.nodes[0].db,"item",1),"model replication"); cluster.schema();
  }
  ~Model() {
    if(std::uncaught_exceptions()) {
      cluster.preserve=true;
      trace<<"FAILURE receipts\n";
      for(size_t n=0;n<seen.size();++n) { trace<<n<<':'; for(auto id:seen[n]) trace<<' '<<id; trace<<'\n'; }
      for(size_t n=0;n<cluster.nodes.size();++n) if(cluster.nodes[n].db) {
        Request progress{{},{}}; int rc=murmur_managed_origin_progress(cluster.nodes[n].db,collect,&progress);
        trace<<"actual-progress node="<<n<<" rc="<<rc;
        for(auto &row:progress.rows) trace<<' '<<hex(row[0].data.data(),row[0].data.size())<<':'<<row[1].integer;
        trace<<'\n';
      }
      std::ofstream file(cluster.root+"/model-trace.txt"); file<<trace.str();
      fprintf(stderr,"seed=%llu artifacts=%s/model-trace.txt\n",(unsigned long long)seed,cluster.root.c_str());
    }
  }
  Projection project(size_t node) const {
    Projection out; const Event *generation=nullptr,*tombstone=nullptr,*lww=nullptr;
    for(auto id:visible[node]) {
      auto &e=events[id];
      if(e.kind==Insert && (!generation || stamp(e)>stamp(*generation))) generation=&e;
      if(e.kind==Delete && (!tombstone || stamp(e)>stamp(*tombstone))) tombstone=&e;
    }
    if(!generation || (tombstone && stamp(*tombstone)>=stamp(*generation))) return out;
    out.alive=true; out.epoch=generation->epoch; out.counter=generation->operand; lww=generation;
    std::set<size_t> retired;
    for(auto id:visible[node]) if(events[id].epoch==out.epoch)
      retired.insert(events[id].removed.begin(),events[id].removed.end());
    std::map<std::string,const Event *> json;
    std::vector<const Event *> list;
    for(auto id:visible[node]) {
      auto &e=events[id]; if(e.epoch!=out.epoch) continue;
      if(e.kind==Counter) out.counter+=e.operand;
      else if(e.kind==Minimum) out.minimum=std::min(out.minimum,(int64_t)e.operand);
      else if(e.kind==Maximum) out.maximum=std::max(out.maximum,(int64_t)e.operand);
      else if(e.kind==Lww && stamp(e)>stamp(*lww)) lww=&e;
      else if(!retired.count(id)) {
        if(e.kind==SetAdd) out.labels.insert(e.value);
        else if(e.kind==JsonSet) { auto &winner=json[e.path]; if(!winner || winner->tag<e.tag) winner=&e; }
        else if(e.kind==ListAdd) list.push_back(&e);
      }
    }
    out.lww=lww->value; out.json="{";
    for(auto &entry:json) { if(out.json.size()>1) out.json+=','; out.json+='"'+entry.first+"\":\""+entry.second->value+'"'; }
    out.json+='}'; std::sort(list.begin(),list.end(),[](auto *a,auto *b){return a->tag<b->tag;}); out.list="[";
    for(auto *e:list) { if(out.list.size()>1) out.list+=','; out.list+='"'+e->value+'"'; } out.list+=']'; return out;
  }
  void verify(size_t node) {
    auto expected=project(node); auto rows=query(cluster.nodes[node].db,"SELECT v,n,labels,lo,hi,settings,events FROM item WHERE id=1");
    auto prefix="seed="+std::to_string(seed)+" node="+std::to_string(node)+" events="+std::to_string(events.size())+" ";
    std::map<std::string,uint64_t> wanted,actual_progress;
    for(auto id:seen[node]) {
      auto &e=events[id].record.value.envelope; auto origin=std::string((const char *)e.origin,16);
      wanted[origin]=std::max(wanted[origin],e.sequence);
    }
    Request progress{{},{}}; check(murmur_managed_origin_progress(cluster.nodes[node].db,collect,&progress),"model origin progress");
    for(auto &row:progress.rows) {
      require(row.size()==2 && row[0].type==MURMUR_BLOB && row[0].data.size()==16 && row[1].type==MURMUR_INTEGER,prefix+"origin progress shape");
      actual_progress[row[0].data]=(uint64_t)row[1].integer;
    }
    require(wanted==actual_progress,prefix+"origin progress differs from acknowledged records");
    require(rows.size()==(expected.alive?1u:0u),prefix+"row existence differs"); if(!expected.alive) return;
    auto &r=rows[0]; require(r.size()==7,prefix+"row shape");
    require(r[0].type==MURMUR_TEXT && r[0].data==expected.lww,prefix+"LWW differs");
    require(r[1].type==MURMUR_INTEGER && r[1].integer==expected.counter,prefix+"counter expected="+std::to_string(expected.counter)+" actual="+std::to_string(r[1].integer));
    std::set<std::string> actual;
    if(r[2].type==MURMUR_BLOB) for(auto &v:managed_decode_values(r[2].data)) { require(v.type==MURMUR_TEXT,prefix+"set value type"); actual.insert(v.data); }
    else require(r[2].type==MURMUR_NULL,prefix+"set projection type");
    require(actual==expected.labels,prefix+"observed-remove set differs");
    require(r[3].type==MURMUR_INTEGER && r[3].integer==expected.minimum,prefix+"minimum expected="+std::to_string(expected.minimum)+" actual="+std::to_string(r[3].integer));
    require(r[4].type==MURMUR_INTEGER && r[4].integer==expected.maximum,prefix+"maximum expected="+std::to_string(expected.maximum)+" actual="+std::to_string(r[4].integer));
    require(r[5].type==MURMUR_TEXT && r[5].data==expected.json,prefix+"JSON expected="+expected.json+" actual="+r[5].data);
    require(r[6].type==MURMUR_TEXT && r[6].data==expected.list,prefix+"list expected="+expected.list+" actual="+r[6].data);
  }
  void write(size_t node,Kind kind) {
    auto prior=project(node); if(!prior.alive) kind=Insert;
    Event e; e.writer=node; e.kind=kind; e.epoch=prior.epoch;
    e.dependencies=visible[node];
    e.operand=(int)(random()%21)-10; e.value="v"+std::to_string(random()%4); e.path="k"+std::to_string(random()%4);
    std::string statement;
    auto call=[&](const char *function,const char *column,const std::string &operand) { return std::string("SELECT ")+function+"('item','[1]','"+column+"',"+operand+")"; };
    if(kind==Insert) {
      e.value="insert"+std::to_string(events.size());
      statement="INSERT OR REPLACE INTO item VALUES(1,'"+e.value+"',"+std::to_string(e.operand)+",NULL,100,-100,'{}','[]')";
    } else if(kind==Delete) statement="DELETE FROM item WHERE id=1";
    else if(kind==Lww) { e.value="write"+std::to_string(events.size()); statement="UPDATE item SET v='"+e.value+"' WHERE id=1"; }
    else if(kind==Counter) statement=call("murmur_counter_add","n",std::to_string(e.operand));
    else if(kind==SetAdd || kind==SetRemove) statement=call(kind==SetAdd?"murmur_set_add":"murmur_set_remove","labels","'"+e.value+"'");
    else if(kind==Minimum || kind==Maximum) statement=call(kind==Minimum?"murmur_min":"murmur_max",kind==Minimum?"lo":"hi",std::to_string(e.operand));
    else if(kind==JsonSet || kind==JsonRemove) statement=call(kind==JsonSet?"murmur_json_set":"murmur_json_remove","settings","'"+e.path+"'"+(kind==JsonSet?",'"+e.value+"'":""));
    else statement=call(kind==ListAdd?"murmur_list_append":"murmur_list_remove","events","'"+e.value+"'");
    for(auto id:visible[node]) {
      auto &old=events[id]; if(old.epoch!=e.epoch) continue;
      if((kind==SetRemove && old.kind==SetAdd && old.value==e.value) ||
         ((kind==JsonSet || kind==JsonRemove) && old.kind==JsonSet && old.path==e.path) ||
         (kind==ListRemove && old.kind==ListAdd && old.value==e.value)) e.removed.insert(id);
    }
    trace<<"write node="<<node<<" event="<<events.size()<<" sql="<<statement<<'\n';
    sql(cluster.nodes[node].db,{statement}); e.record=cluster.next(node,sequence[node]++);
    auto batch=managed_replica_decode(e.record.value); require(batch.rows.size()==1,"one-row model batch");
    if(kind==Insert) e.epoch=batch.rows[0].epoch;
    if(kind==SetAdd || kind==JsonSet || kind==ListAdd) {
      int policy=kind==SetAdd?MURMUR_POLICY_SET:(kind==JsonSet?MURMUR_POLICY_JSON:MURMUR_POLICY_LIST);
      std::vector<Tag> fresh;
      for(auto &entry:batch.rows[0].columns) if(entry.second.policy==policy)
        for(auto &tag:addition_tags(entry.second.causal)) if(!issued.count(tag)) fresh.push_back(tag);
      require(fresh.size()==1,"exactly one new operation tag"); e.tag=fresh[0]; issued.insert(e.tag);
    }
    uint8_t wire[MURMUR_ORIGIN_ENVELOPE_BYTES]; check(murmur_origin_envelope_encode(&e.record.value.envelope,wire,sizeof(wire)),"trace envelope");
    trace<<"record "<<hex(wire,sizeof(wire))<<' '<<hex(e.record.value.payload,e.record.value.bytes)<<'\n';
    seen[node].insert(events.size()); visible[node].insert(events.size()); events.push_back(std::move(e)); verify(node);
  }
  bool deliver(size_t node,size_t id) {
    int applied=-1; int rc=murmur_managed_origin_apply(cluster.nodes[node].db,&events[id].record.value,&applied);
    trace<<"deliver node="<<node<<" event="<<id<<" rc="<<rc<<" applied="<<applied<<'\n';
    require(rc==SQLITE_OK || rc==SQLITE_BUSY,"unexpected delivery error rc="+std::to_string(rc));
    bool known=seen[node].count(id);
    if(rc==SQLITE_BUSY) require(!known && applied==0,"pending delivery changed receipt");
    else {
      require(applied==(known?0:1),"incorrect replay/application flag"); seen[node].insert(id);
      /* Full row states carry the sender's observed effects. In particular,
       * min/max values can arrive through a relay before the original scalar
       * operation's receipt. Keep effects separate from origin receipts. */
      visible[node].insert(events[id].dependencies.begin(),events[id].dependencies.end()); visible[node].insert(id);
    }
    verify(node); return rc==SQLITE_OK && !known;
  }
  void drain() {
    for(;;) {
      size_t pending=0; bool progress=false;
      std::vector<size_t> order(events.size()); for(size_t i=0;i<order.size();++i) order[i]=i;
      std::shuffle(order.begin(),order.end(),random);
      for(size_t node=0;node<seen.size();++node) for(auto id:order) if(!seen[node].count(id)) { ++pending; progress=deliver(node,id)||progress; }
      if(!pending) break;
      require(progress,"causal delivery deadlocked after complete record availability");
    }
  }
  void run(size_t steps) {
    write(0,Insert); drain();
    /* Guarantee every policy path before randomized scheduling. */
    for(int kind=Lww;kind<=ListRemove;++kind) { write((size_t)kind%seen.size(),(Kind)kind); drain(); }
    /* Always exercise a late old-generation operation and concurrent new
     * baselines, independently of which actions the random seed chooses. */
    write(0,Counter); auto late=events.size()-1;
    write(1,Delete); auto deletion=events.size()-1; deliver(2,deletion);
    write(2,Insert); auto replacement=events.size()-1;
    deliver(1,replacement); deliver(0,deletion); deliver(0,replacement); deliver(1,late); drain();
    write(0,Insert); write(1,Insert); drain();
    for(size_t step=0;step<steps;++step) {
      auto node=random()%seen.size(),action=random()%100;
      if(action<57) write(node,(Kind)(random()%12));
      else if(action<92) deliver(node,random()%events.size());
      else { trace<<"reopen node="<<node<<'\n'; cluster.reopen(node); verify(node); }
      if(step%31==30) drain();
    }
    drain();
    for(size_t node=0;node<seen.size();++node) { cluster.reopen(node); verify(node); for(size_t i=0;i<events.size();++i) deliver(node,i); }
    printf("MANAGED-MODEL-OK seed=%llu nodes=%zu steps=%zu records=%zu\n",(unsigned long long)seed,seen.size(),steps,events.size());
  }
};
}
int main(int argc,char **argv) {
  uint64_t seed=argc>1?strtoull(argv[1],nullptr,0):17;
  size_t steps=argc>2?strtoull(argv[2],nullptr,0):96;
  size_t nodes=argc>3?strtoull(argv[3],nullptr,0):3+seed%3;
  try { require(nodes>=3 && nodes<=5 && steps<=10000,"usage: managedmodeltest [seed] [steps<=10000] [nodes=3..5]"); Model model(seed,nodes); model.run(steps); }
  catch(const std::exception &e) { fprintf(stderr,"MANAGED-MODEL-FAIL %s\n",e.what()); return 1; }
  catch(const ManagedError &e) { fprintf(stderr,"MANAGED-MODEL-FAIL native rc=%d\n",e.code); return 1; }
}
