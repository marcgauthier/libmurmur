#include "test_managed_support.h"
#include "managed_codec.h"
#include "managed_replica.h"
#include "managed_schema_internal.h"
#include "sha256.h"
#include <algorithm>
#include <fstream>
#include <iterator>
#include <random>
#include <map>

using namespace managed_test;
bool managed_codec_fuzz_one(const uint8_t *,size_t);
namespace {
std::string packet(const ManagedReplicaBatch &batch) {
  ManagedEncoder e; e.raw("MMT2",4); e.blob(batch.cells); e.number(batch.rows.size()); for(auto &row:batch.rows) e.blob(managed_row_encode(row)); return e.bytes;
}
struct Fixture {
  Cluster cluster{2};
  Record schema,record;
  ManagedReplicaBatch batch;
  std::vector<std::string> corpus;
  std::string last_signed;
  size_t last_case=0;
  Fixture() {
    auto *a=cluster.nodes[0].db;
    check(murmur_managed_migrate(a,"CREATE TABLE item(id INTEGER NOT NULL PRIMARY KEY,v TEXT,n INTEGER,labels BLOB,lo,hi,settings TEXT,events TEXT); CREATE TABLE ordinary(id INTEGER NOT NULL PRIMARY KEY,v TEXT)"),"fuzz schema");
    const char *columns[]={"n","labels","lo","hi","settings","events"};
    for(int policy=1;policy<=6;++policy) check(murmur_managed_set_policy(a,"item",columns[policy-1],(murmur_merge_policy_t)policy),"fuzz policy");
    check(murmur_managed_set_replication(a,"item",1),"fuzz replication"); check(murmur_managed_set_replication(a,"ordinary",1),"fuzz ordinary replication"); cluster.schema();
    check(murmur_managed_schema_export(a,&schema.value),"fuzz schema export");
    sql(a,{"INSERT INTO item VALUES(1,'base',10,NULL,100,-100,'{}','[]')","INSERT INTO ordinary VALUES(1,'base')"}); auto first=cluster.next(0,0);
    int applied=0; check(murmur_managed_origin_apply(cluster.nodes[1].db,&first.value,&applied),"fuzz baseline apply");
    sql(a,{"UPDATE ordinary SET v='changed' WHERE id=1","UPDATE item SET v='changed' WHERE id=1","SELECT murmur_counter_add('item','[1]','n',3)","SELECT murmur_set_add('item','[1]','labels','x')","SELECT murmur_min('item','[1]','lo',7)","SELECT murmur_max('item','[1]','hi',4)","SELECT murmur_json_set('item','[1]','settings','key','value')","SELECT murmur_list_append('item','[1]','events','entry')"});
    record=cluster.next(0,1); batch=managed_replica_decode(record.value);
    uint8_t wire[MURMUR_ORIGIN_ENVELOPE_BYTES]; check(murmur_origin_envelope_encode(&record.value.envelope,wire,sizeof(wire)),"fuzz envelope");
    add(0,std::string((const char *)wire,sizeof(wire))); add(1,std::string((const char *)schema.value.payload,schema.value.bytes));
    add(2,managed_row_encode(batch.rows.at(0))); for(auto &col:batch.rows[0].columns) if(!col.second.causal.empty()) add(3,col.second.causal);
    std::vector<ManagedValue> values;
    for(int64_t n:{INT64_MIN,INT64_MAX,INT64_C(9007199254740993),INT64_C(0)}) { ManagedValue v; v.type=MURMUR_INTEGER; v.integer=n; values.push_back(v); }
    values.push_back(ManagedValue{}); ManagedValue text; text.type=MURMUR_TEXT; text.data=std::string("a\0\xe2\x98\x83",5); values.push_back(text);
    for(double n:{0.0,-0.0,1.25}) { ManagedValue v; v.type=MURMUR_REAL; v.real=n; values.push_back(v); }
    ManagedValue blob; blob.type=MURMUR_BLOB; blob.data=std::string("\0\xff",2); values.push_back(blob);
    for(auto &v:values) add(4,managed_encode_value(v));
    add(5,managed_encode_values(values));
    add(6,packet(batch)); add(7,batch.cells);
  }
  ~Fixture() {
    if(std::uncaught_exceptions()) {
      cluster.preserve=true;
      std::ofstream file(cluster.root+"/signed-failure.bin",std::ios::binary); file.write(last_signed.data(),last_signed.size());
      fprintf(stderr,"signed fuzz case=%zu stores=%s record=%s/signed-failure.bin\n",last_case,cluster.root.c_str(),cluster.root.c_str());
    }
  }
  void add(unsigned kind,const std::string &body) { corpus.push_back(std::string(1,(char)kind)+body); }
  std::string state() {
    auto *b=cluster.nodes[1].db; std::string out;
    for(auto *sql:{"SELECT * FROM item","SELECT * FROM ordinary"}) for(auto &row:query(b,sql)) out+=managed_encode_values(row);
    Request progress{{},{}}; check(murmur_managed_origin_progress(b,collect,&progress),"fuzz receipts"); for(auto &row:progress.rows) out+=managed_encode_values(row);
    return out+persistent_snapshot(b);
  }
  void signed_rejections(std::mt19937_64 &random,size_t cases) {
    auto before=state(); auto *b=cluster.nodes[1].db;
    for(size_t i=0;i<cases;++i) {
      auto candidate=record.value; auto body=packet(batch); auto malformed=batch;
      switch(i%16) {
        case 0: body.resize(random()%body.size()); break;
        case 1: body+=(char)random(); break;
        case 2:
          for(auto &col:malformed.rows[0].columns) if(col.second.policy==MURMUR_POLICY_COUNTER) { ManagedValue wrong; wrong.type=MURMUR_INTEGER; wrong.integer=11+(int64_t)(random()%1000); col.second.baseline=managed_encode_value(wrong); }
          body=packet(malformed); break;
        case 3: malformed.rows.push_back(malformed.rows[0]); body=packet(malformed); break;
        case 4: malformed.rows[0].table[0]^=0xff; body=packet(malformed); break;
        case 5: malformed.rows[0].epoch[0]^=0xff; body=packet(malformed); break;
        case 6: candidate.envelope.schema[random()%32]^=1; break;
        case 7: candidate.envelope.sequence+=1+random()%8; break;
        case 8: candidate.envelope.database[random()%16]^=1; break;
        case 9: malformed.rows[0].generation.millis=candidate.envelope.millis+1; body=packet(malformed); break;
        case 10: break; /* Tamper after signing below. */
        case 11: break; /* Wrong signing key below. */
        case 12: candidate.envelope.sequence=1; break;
        case 13: malformed.rows.clear(); body=packet(malformed); break;
        case 14: {
          murmur_cell_t cell{}; const char *table="item",*cid="n",*key="key";
          cell.table=(const uint8_t *)table; cell.table_len=4; cell.cid=(const uint8_t *)cid; cell.cid_len=1; cell.pk=(const uint8_t *)key; cell.pk_len=3;
          cell.site=cluster.nodes[0].identity.site; cell.site_len=16; cell.val_tag=MURMUR_INTEGER; cell.val_int=999; cell.col_version=1; cell.db_version=1; cell.cl=1;
          uint8_t encoded[256]; auto count=murmur_cell_encode(&cell,encoded,sizeof(encoded)); require(count!=0,"encode raw policy attack");
          malformed.cells=std::string("CRSB\1\0\0\0\1\0\0\0",12)+std::string((const char *)encoded,count); body=packet(malformed); break;
        }
        case 15:
          for(auto it=malformed.rows[0].columns.begin();it!=malformed.rows[0].columns.end();++it) if(it->second.policy==MURMUR_POLICY_COUNTER) { malformed.rows[0].columns.erase(it); break; }
          body=packet(malformed); break;
      }
      candidate.payload=(uint8_t *)body.data(); candidate.bytes=body.size();
      check(murmur_origin_sign(&candidate.envelope,cluster.nodes[i%16==11?1:0].seed.data(),candidate.payload,candidate.bytes),"sign malformed input");
      if(i%16==10) body[random()%body.size()]^=1;
      uint8_t header[MURMUR_ORIGIN_ENVELOPE_BYTES]; check(murmur_origin_envelope_encode(&candidate.envelope,header,sizeof(header)),"save signed input"); last_signed=std::string((const char *)header,sizeof(header))+body; last_case=i;
      int applied=-1; int rc=murmur_managed_origin_apply(b,&candidate,&applied);
      require(rc!=SQLITE_OK && applied==0,"authenticated malformed record accepted: case="+std::to_string(i));
      require(state()==before,"rejected signed record changed data/receipts: case="+std::to_string(i));
    }
    int applied=0; check(murmur_managed_origin_apply(b,&record.value,&applied),"honest record after signed fuzz"); require(applied==1,"signed fuzz poisoned honest receipt");
    auto result=query(b,"SELECT n FROM item"); require(result[0][0].integer==13,"signed fuzz poisoned counter baseline");
    auto before_schema=state(); auto source=managed_schema_decode(std::string((const char *)schema.value.payload,schema.value.bytes));
    for(size_t i=0;i<64;++i) {
      auto malformed=source; auto item=std::find_if(malformed.tables.begin(),malformed.tables.end(),[](auto &table){return table.name=="item";}); require(item!=malformed.tables.end(),"schema fuzz item");
      switch(i%8) {
        case 0: item->columns[1].id=item->columns[0].id; break;
        case 1: item->id[0]^=0xff; break;
        case 2: item->columns[1].id[0]^=0xff; break;
        case 3: item->columns[1].dimensions=8193; break;
        case 4: malformed.indexes.push_back({"fuzz_index",item->id,"DELETE FROM item"}); break;
        case 5: item->ddl="CREATE TABLE murmur_origin_log(x)"; break;
        case 6: break; /* Truncation below. */
        case 7: break; /* Trailing data below. */
      }
      auto body=managed_schema_encode(malformed);
      if(i%8==6) body.resize(random()%body.size());
      if(i%8==7) body+='\0';
      auto candidate=schema.value; candidate.envelope.sequence+=100+i; candidate.payload=(uint8_t *)body.data(); candidate.bytes=body.size();
      murmur_sha256((const uint8_t *)body.data(),body.size(),candidate.envelope.schema); check(murmur_origin_sign(&candidate.envelope,cluster.nodes[0].seed.data(),body.data(),body.size()),"sign invalid schema");
      uint8_t header[MURMUR_ORIGIN_ENVELOPE_BYTES]; check(murmur_origin_envelope_encode(&candidate.envelope,header,sizeof(header)),"save signed schema"); last_signed=std::string((const char *)header,sizeof(header))+body; last_case=cases+i;
      int changed=-1; int rc=murmur_managed_schema_adopt(b,&candidate,&changed);
      require(rc!=SQLITE_OK && changed==0,"signed invalid schema accepted: case="+std::to_string(i));
      require(state()==before_schema,"rejected schema changed persistent state: case="+std::to_string(i));
    }
    sql(cluster.nodes[0].db,{"SELECT murmur_counter_add('item','[1]','n',1)","UPDATE ordinary SET v='after-fuzz' WHERE id=1"});
    auto after=cluster.next(0,2); applied=0; check(murmur_managed_origin_apply(b,&after.value,&applied),"honest transaction after schema fuzz");
    require(applied==1 && query(b,"SELECT n FROM item")[0][0].integer==14,"schema fuzz poisoned writer/apply state");
  }
};
}
int main(int argc,char **argv) {
  uint64_t seed=0x5eed1234; size_t steps=15000; std::string last;
  try {
    if(argc==3 && std::string(argv[1])=="--replay") {
      std::ifstream file(argv[2],std::ios::binary); require(file.good(),"open fuzz input"); last.assign(std::istreambuf_iterator<char>(file),{});
      managed_codec_fuzz_one((const uint8_t *)last.data(),last.size()); puts("MANAGED-FUZZ-REPLAY-OK"); return 0;
    }
    if(argc>1) seed=strtoull(argv[1],nullptr,0);
    if(argc>2) steps=strtoull(argv[2],nullptr,0);
    require(steps<=1000000,"fuzz steps exceed bound");
    Fixture fixture;
    if(const char *directory=getenv("MURMUR_FUZZ_CORPUS")) {
      std::filesystem::create_directories(directory);
      for(size_t i=0;i<fixture.corpus.size();++i) {
        std::ofstream file(std::string(directory)+"/seed-"+std::to_string(i),std::ios::binary);
        require(file.good(),"open corpus seed");
        file.write(fixture.corpus[i].data(),fixture.corpus[i].size());
        require(file.good(),"write corpus seed");
      }
    }
    std::mt19937_64 random(seed); auto pool=fixture.corpus; const size_t initial=pool.size(); size_t accepted=0;
    for(auto &input:pool) require(managed_codec_fuzz_one((const uint8_t *)input.data(),input.size()),"valid fuzz seed rejected");
    for(size_t step=0;step<steps;++step) {
      last=pool[random()%pool.size()]; size_t position=last.empty()?0:random()%last.size();
      switch(step%6) {
        case 0: if(!last.empty()) last[position]^=(char)(1u<<(random()%8)); break;
        case 1: last.resize(random()%(last.size()+1)); break;
        case 2: last.insert(position,1+random()%16,(char)0xff); break;
        case 3: if(!last.empty()) last.erase(position,std::min<size_t>(1+random()%16,last.size()-position)); break;
        case 4: last.append(1+random()%16,(char)random()); break;
        case 5: for(size_t i=0;i<1+random()%4 && !last.empty();++i) last[random()%last.size()]=(char)random(); break;
      }
      bool valid=managed_codec_fuzz_one((const uint8_t *)last.data(),last.size());
      if(valid) { ++accepted; if(last.size()<=65536) { if(pool.size()<256) pool.push_back(last); else pool[initial+random()%(pool.size()-initial)]=last; } }
    }
    fixture.signed_rejections(random,400);
    printf("MANAGED-FUZZ-OK seed=%llu mutations=%zu accepted=%zu signed_rejections=464\n",(unsigned long long)seed,steps,accepted);
  } catch(const std::exception &e) {
    char path[]="/tmp/murmur-fuzz-failure-XXXXXX"; int fd=mkstemp(path); if(fd>=0) { close(fd); std::ofstream file(path,std::ios::binary); file.write(last.data(),last.size()); }
    fprintf(stderr,"MANAGED-FUZZ-FAIL seed=%llu input=%s error=%s\n",(unsigned long long)seed,path,e.what()); return 1;
  } catch(const ManagedError &e) { fprintf(stderr,"MANAGED-FUZZ-FAIL native rc=%d\n",e.code); return 1; }
}
