#include "../../libmurmur.h"
#include "sqlite3.h"
#include "managed_replica.h"
#include "managed_codec.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
struct Request { std::vector<std::string> sql; int64_t value=-1; std::string blob{}; };
static int row(void *ctx,int n,const murmur_value_t *v) {
  assert(n==1); auto &r=*(Request *)ctx; r.value=v[0].integer;
  if(v[0].type==MURMUR_BLOB) r.blob=std::string((const char *)v[0].data,v[0].bytes);
  return 0;
}
static int callback(murmur_transaction_t *tx,void *ctx) {
  auto &r=*(Request *)ctx;
  for(auto &sql:r.sql) { int rc=murmur_transaction_execute(tx,sql.c_str(),nullptr,0,row,&r); if(rc) return rc; }
  return SQLITE_OK;
}
static int run(murmur_managed_t *m,const std::vector<std::string> &sql,int64_t *out=nullptr) {
  Request r{sql}; int rc=murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,callback,&r); if(out) *out=r.value; return rc;
}
static void ok(murmur_managed_t *m,const std::vector<std::string> &sql) {
  int rc=run(m,sql); if(rc) fprintf(stderr,"transaction rc=%d sql=%s\n",rc,sql.front().c_str()); assert(!rc);
}
static int64_t query(murmur_managed_t *m,const char *sql) { int64_t out=-1; assert(run(m,{sql},&out)==SQLITE_OK); return out; }
static murmur_origin_record_t next(murmur_managed_t *m,const uint8_t origin[16],uint64_t &cursor) {
  murmur_origin_record_t r{}; assert(murmur_managed_origin_next(m,origin,cursor,&r)==SQLITE_OK); assert(r.envelope.sequence==cursor+1); ++cursor; return r;
}
static void apply(murmur_managed_t *m,const murmur_origin_record_t &r,int expected=SQLITE_OK) {
  int changed=-1,rc=murmur_managed_origin_apply(m,&r,&changed);
  if(rc!=expected) fprintf(stderr,"apply node=%u seq=%llu rc=%d expected=%d\n",r.envelope.origin[0],(unsigned long long)r.envelope.sequence,rc,expected);
  assert(rc==expected && changed==(rc?0:1));
}
static std::string encode(const ManagedReplicaBatch &batch) {
  ManagedEncoder e; e.raw("MMT2",4); e.blob(batch.cells); e.number(batch.rows.size()); for(auto &r:batch.rows) e.blob(managed_row_encode(r)); return e.bytes;
}
static int crash_before(murmur_transaction_t *tx,void *) {
  assert(murmur_transaction_execute(tx,"INSERT INTO crash_rows VALUES(1,10)",nullptr,0,nullptr,nullptr)==SQLITE_OK);
  assert(murmur_transaction_execute(tx,"SELECT murmur_counter_add('crash_rows','[1]','n',3)",nullptr,0,nullptr,nullptr)==SQLITE_OK);
  _exit(41);
}
static void crash_child(const char *mode,const char *path) {
  uint8_t key[32]={1},database[16]={7},node[16]={8},seed[32]={9}; murmur_managed_t *m=nullptr;
  assert(murmur_managed_open(path,key,&m)==SQLITE_OK);
  assert(murmur_managed_origin_configure(m,database,node,seed)==SQLITE_OK);
  assert(murmur_managed_migrate(m,"CREATE TABLE IF NOT EXISTS crash_rows(id INTEGER NOT NULL PRIMARY KEY,n INTEGER)")==SQLITE_OK);
  assert(murmur_managed_set_policy(m,"crash_rows","n",MURMUR_POLICY_COUNTER)==SQLITE_OK);
  assert(murmur_managed_set_replication(m,"crash_rows",1)==SQLITE_OK);
  if(!strcmp(mode,"--before")) murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,crash_before,nullptr);
  ok(m,{"INSERT INTO crash_rows VALUES(1,10)","SELECT murmur_counter_add('crash_rows','[1]','n',3)"}); _exit(42);
}
static void subprocess(const char *binary,const char *mode,const char *path,int expected) {
  pid_t child=fork(); assert(child>=0);
  if(!child) { execl(binary,binary,mode,path,(char *)nullptr); _exit(99); }
  int status=0; assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==expected);
}
int main(int argc,char **argv) {
  if(argc==3) crash_child(argv[1],argv[2]);
  char root[]="/tmp/murmur-managed-replica-XXXXXX",path[256]; assert(mkdtemp(root));
  uint8_t key[32]={1},database[16]={9},nodes[3][16]={{1},{2},{3}},seeds[3][32]={{4},{5},{6}};
  murmur_managed_t *handles[3]{}; murmur_origin_identity_t identities[3]{};
  for(int i=0;i<3;++i) {
    snprintf(path,sizeof(path),"%s/%d",root,i); assert(murmur_managed_open(path,key,&handles[i])==SQLITE_OK);
    assert(murmur_managed_origin_configure(handles[i],database,nodes[i],seeds[i])==SQLITE_OK);
    assert(murmur_managed_origin_identity(handles[i],&identities[i])==SQLITE_OK);
  }
  auto *a=handles[0],*b=handles[1],*c=handles[2];
  for(int i=0;i<3;++i) for(int j=0;j<3;++j) if(i!=j) assert(murmur_managed_origin_trust(handles[i],&identities[j],1)==SQLITE_OK);
  assert(murmur_managed_migrate(a,"CREATE TABLE items(id INTEGER NOT NULL PRIMARY KEY,value TEXT,n INTEGER,labels BLOB,low,high,settings TEXT,events TEXT)")==SQLITE_OK);
  const char *columns[]={"n","labels","low","high","settings","events"};
  for(int i=0;i<6;++i) assert(murmur_managed_set_policy(a,"items",columns[i],(murmur_merge_policy_t)(i+1))==SQLITE_OK);
  assert(murmur_managed_set_replication(a,"items",1)==SQLITE_OK);
  murmur_origin_record_t schema{}; assert(murmur_managed_schema_export(a,&schema)==SQLITE_OK);
  for(auto *peer:{b,c}) { assert(murmur_managed_schema_master(peer,nodes[0])==SQLITE_OK); int changed=0; assert(murmur_managed_schema_adopt(peer,&schema,&changed)==SQLITE_OK && changed); }
  uint64_t ca=0,cb=0,cc=0; std::vector<murmur_origin_record_t> records;
  ok(a,{"INSERT INTO items VALUES(1,'base',10,NULL,100,100,'{\"base\":0}','[\"seed\"]')"});
  records.push_back(next(a,nodes[0],ca)); apply(b,records.back()); apply(c,records.back());
  assert(query(b,"SELECT n FROM items WHERE id=1")==10);
  ok(a,{"SELECT murmur_counter_add('items','[1]','n',2)","SELECT murmur_set_add('items','[1]','labels','x')","SELECT murmur_min('items','[1]','low',5)","SELECT murmur_max('items','[1]','high',200)","SELECT murmur_json_set('items','[1]','settings','a','A')","SELECT murmur_list_append('items','[1]','events','x')","UPDATE items SET value='a' WHERE id=1"});
  auto a2=next(a,nodes[0],ca); records.push_back(a2);
  ok(b,{"SELECT murmur_counter_add('items','[1]','n',3)","SELECT murmur_set_add('items','[1]','labels','y')","SELECT murmur_min('items','[1]','low',7)","SELECT murmur_max('items','[1]','high',300)","SELECT murmur_json_set('items','[1]','settings','b','B')","SELECT murmur_list_append('items','[1]','events','y')","UPDATE items SET value='b' WHERE id=1"});
  auto b1=next(b,nodes[1],cb); records.push_back(b1);
  apply(a,b1); apply(b,a2); apply(c,b1);
  for(auto *peer:{a,b}) assert(query(peer,"SELECT n=15 AND low=5 AND high=300 AND json_extract(settings,'$.a')='A' AND json_extract(settings,'$.b')='B' AND json_array_length(events)=3 FROM items WHERE id=1")==1);
  ok(b,{"SELECT murmur_counter_add('items','[1]','n',1)","SELECT murmur_set_add('items','[1]','labels','z')"});
  auto b2=next(b,nodes[1],cb); records.push_back(b2);
  /* Bob's signature cannot authenticate Alice's missing operations. */
  apply(c,b2,SQLITE_BUSY); assert(query(c,"SELECT n FROM items WHERE id=1")==13);
  apply(c,a2); apply(c,b2); apply(a,b2);
  for(auto *peer:{a,b,c}) assert(query(peer,"SELECT n FROM items WHERE id=1")==16);
  ok(a,{"SELECT murmur_set_remove('items','[1]','labels','x')","SELECT murmur_json_remove('items','[1]','settings','a')","SELECT murmur_list_remove('items','[1]','events','seed')"}); auto a3=next(a,nodes[0],ca); records.push_back(a3);
  ok(b,{"SELECT murmur_set_add('items','[1]','labels','x')","SELECT murmur_json_set('items','[1]','settings','a','new')","SELECT murmur_list_append('items','[1]','events','seed')"}); auto b3=next(b,nodes[1],cb); records.push_back(b3);
  apply(a,b3); apply(b,a3); apply(c,a3); apply(c,b3);
  for(auto *peer:{a,b,c}) {
    Request labels{{"SELECT labels FROM items WHERE id=1"}};
    assert(murmur_managed_transaction(peer,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,callback,&labels)==SQLITE_OK);
    std::vector<std::string> values; for(auto &v:managed_decode_values(labels.blob)) values.push_back(v.data);
    assert((values==std::vector<std::string>{"x","y","z"}));
    assert(query(peer,"SELECT json_extract(settings,'$.a')='new' AND json_array_length(events)=3 FROM items WHERE id=1")==1);
    assert(query(peer,"SELECT count(*) FROM items,json_each(items.events) WHERE json_each.value='seed'")==1);
  }
  /* Save an offline edit to the old generation for delivery after replacement. */
  ok(c,{"SELECT murmur_counter_add('items','[1]','n',99)"}); auto c1=next(c,nodes[2],cc); records.push_back(c1);
  ok(a,{"DELETE FROM items WHERE id=1"}); auto a4=next(a,nodes[0],ca); records.push_back(a4);
  ok(b,{"SELECT murmur_counter_add('items','[1]','n',100)"}); auto b4=next(b,nodes[1],cb); records.push_back(b4);
  apply(a,b4); assert(query(a,"SELECT count(*) FROM items")==0);
  apply(b,a4); apply(c,b4); apply(c,a4); assert(query(b,"SELECT count(*) FROM items")==0);
  ok(b,{"INSERT INTO items VALUES(1,'fresh',1000,NULL,50,50,NULL,NULL)"}); auto b5=next(b,nodes[1],cb); records.push_back(b5);
  apply(a,b5); apply(c,b5); apply(a,c1); apply(b,c1);
  for(auto *peer:{a,b,c}) assert(query(peer,"SELECT n=1000 AND value='fresh' AND typeof(labels)='blob' AND hex(labels)='00' AND settings='{}' AND events='[]' FROM items WHERE id=1")==1);
  /* Competing inserts select one whole generation, without mixing baselines. */
  ok(a,{"INSERT INTO items VALUES(2,'left',5,NULL,1,1,'{}','[]')"}); auto a5=next(a,nodes[0],ca); records.push_back(a5);
  ok(b,{"INSERT INTO items VALUES(2,'right',20,NULL,2,2,'{}','[]')"}); auto b6=next(b,nodes[1],cb); records.push_back(b6);
  apply(a,b6); apply(b,a5); apply(c,b6); apply(c,a5);
  int64_t winner=query(a,"SELECT n FROM items WHERE id=2"); assert(winner==5 || winner==20);
  for(auto *peer:{b,c}) assert(query(peer,"SELECT n FROM items WHERE id=2")==winner);
  /* Reopen preserves original actor identity, epochs and joined causal state. */
  murmur_managed_close(b); snprintf(path,sizeof(path),"%s/1",root); assert(murmur_managed_open(path,key,&b)==SQLITE_OK); handles[1]=b;
  assert(run(b,{"SELECT murmur_counter_add('items','[1]','n',1)"})==SQLITE_AUTH);
  assert(query(b,"SELECT n FROM items WHERE id=1")==1000);
  assert(murmur_managed_origin_configure(b,database,nodes[1],seeds[1])==SQLITE_OK);
  ok(b,{"SELECT murmur_counter_add('items','[1]','n',1)"}); auto b7=next(b,nodes[1],cb); records.push_back(b7); apply(a,b7); apply(c,b7);
  for(auto *peer:{a,b,c}) assert(query(peer,"SELECT n FROM items WHERE id=1")==1001);
  /* Mixed ordinary/policy writes and historical IDs survive migrations. */
  assert(murmur_managed_migrate(a,"CREATE TABLE ledger(id INTEGER NOT NULL PRIMARY KEY,value TEXT)")==SQLITE_OK);
  assert(murmur_managed_set_replication(a,"ledger",1)==SQLITE_OK);
  murmur_origin_record_t middle{},latest{}; assert(murmur_managed_schema_export(a,&middle)==SQLITE_OK);
  for(auto *peer:{b,c}) { int changed=0; assert(murmur_managed_schema_adopt(peer,&middle,&changed)==SQLITE_OK && changed); }
  ok(a,{"INSERT INTO ledger VALUES(1,'mixed')","SELECT murmur_counter_add('items','[1]','n',4)"}); auto a6=next(a,nodes[0],ca); records.push_back(a6);
  auto mixed=managed_replica_decode(a6); assert(!mixed.rows.empty() && mixed.cells.size()>12);
  murmur_rename_t maps[]={{"items",nullptr,"n","visits"},{"items","records",nullptr,nullptr}};
  assert(murmur_managed_migrate_mapped(a,"ALTER TABLE items RENAME COLUMN n TO visits; ALTER TABLE items RENAME TO records; ALTER TABLE records ADD COLUMN note TEXT DEFAULT 'unchanged'",maps,2)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"records","value",1,0,0)==SQLITE_OK);
  assert(murmur_managed_schema_export(a,&latest)==SQLITE_OK);
  for(auto *peer:{b,c}) { int changed=0; assert(murmur_managed_schema_adopt(peer,&latest,&changed)==SQLITE_OK && changed); apply(peer,a6); }
  for(auto *peer:{a,b,c}) {
    assert(query(peer,"SELECT visits=1005 AND note='unchanged' FROM records WHERE id=1")==1);
    assert(query(peer,"SELECT count(*) FROM ledger")==1); assert(murmur_managed_refresh_indexes(peer)==SQLITE_OK);
  }
  ok(a,{"SELECT murmur_counter_add('records','[1]','visits',1)"}); auto a7=next(a,nodes[0],ca); records.push_back(a7);
  auto original=managed_replica_decode(a7),bad=original;
  std::string counter_id; for(auto &col:bad.rows[0].columns) if(col.second.policy==MURMUR_POLICY_COUNTER) counter_id=col.first;
  assert(!counter_id.empty());
  auto reject=[&](const ManagedReplicaBatch &batch,int code) {
    auto body=encode(batch); auto forged=a7; forged.payload=(uint8_t *)body.data(); forged.bytes=body.size();
    assert(murmur_origin_sign(&forged.envelope,seeds[0],body.data(),body.size())==SQLITE_OK); apply(b,forged,code);
    assert(query(b,"SELECT visits FROM records WHERE id=1")==1005);
  };
  ManagedValue wrong; wrong.type=MURMUR_INTEGER; wrong.integer=999;
  bad.rows[0].columns[counter_id].baseline=managed_encode_value(wrong); reject(bad,SQLITE_CORRUPT);
  bad=original; bad.rows[0].columns.erase(counter_id); reject(bad,SQLITE_CORRUPT);
  bad=original; bad.rows.push_back(bad.rows.front()); reject(bad,SQLITE_CORRUPT);
  bad=original; bad.rows[0].generation.millis=a7.envelope.millis+1; reject(bad,SQLITE_AUTH);
  /* An authenticated raw cell cannot overwrite a policy projection. */
  bad=original; murmur_cell_t raw{}; const char table[]="records",cid[]="visits",pk[]="key";
  raw.table=(const uint8_t *)table; raw.table_len=strlen(table); raw.cid=(const uint8_t *)cid; raw.cid_len=strlen(cid); raw.pk=(const uint8_t *)pk; raw.pk_len=strlen(pk);
  raw.site=identities[0].site; raw.site_len=16; raw.val_tag=MURMUR_INTEGER; raw.val_int=999; raw.col_version=1; raw.db_version=1; raw.cl=1;
  uint8_t cell[256]; auto length=murmur_cell_encode(&raw,cell,sizeof(cell)); assert(length);
  bad.cells=std::string("CRSB\1\0\0\0\1\0\0\0",12)+std::string((const char *)cell,length); reject(bad,SQLITE_AUTH);
  apply(b,a7); apply(c,a7);
  assert(run(a,{"INSERT INTO ledger VALUES(2,'rollback')","SELECT murmur_counter_add('records','[1]','visits',9223372036854775807)"})==SQLITE_TOOBIG);
  assert(query(a,"SELECT count(*) FROM ledger")==1);
  murmur_origin_record_t absent{}; assert(murmur_managed_origin_next(a,nodes[0],ca,&absent)==SQLITE_NOTFOUND);
  assert(murmur_managed_origin_next(c,nodes[2],cc,&absent)==SQLITE_NOTFOUND);
  murmur_origin_record_free(&middle); murmur_origin_record_free(&latest);
  /* Policy materialization preserves composite/BLOB primary key types. */
  assert(murmur_managed_migrate(a,"CREATE TABLE pairs(k BLOB NOT NULL,part TEXT NOT NULL,n INTEGER,PRIMARY KEY(k,part))")==SQLITE_OK);
  assert(murmur_managed_set_policy(a,"pairs","n",MURMUR_POLICY_COUNTER)==SQLITE_OK);
  assert(murmur_managed_set_replication(a,"pairs",1)==SQLITE_OK);
  murmur_origin_record_t pairs_schema{}; assert(murmur_managed_schema_export(a,&pairs_schema)==SQLITE_OK);
  for(auto *peer:{b,c}) { int changed=0; assert(murmur_managed_schema_adopt(peer,&pairs_schema,&changed)==SQLITE_OK && changed); }
  ok(a,{"INSERT INTO pairs VALUES(x'01ff','p',7)","SELECT murmur_counter_add('pairs',murmur_policy_key(x'01ff','p'),'n',3)"}); auto a8=next(a,nodes[0],ca); records.push_back(a8);
  apply(b,a8); apply(c,a8);
  ok(b,{"SELECT murmur_counter_add('pairs',murmur_policy_key(x'01ff','p'),'n',2)"}); auto b8=next(b,nodes[1],cb); records.push_back(b8); apply(a,b8); apply(c,b8);
  for(auto *peer:{a,b,c}) assert(query(peer,"SELECT n FROM pairs WHERE k=x'01ff' AND part='p'")==12);
  murmur_origin_record_free(&pairs_schema);
  /* Disabled tables preserve local data and advance authenticated history;
   * re-enabling requires a checkpoint rather than silently missing writes. */
  ok(b,{"INSERT INTO ledger VALUES(2,'late')"}); auto b9=next(b,nodes[1],cb); records.push_back(b9);
  assert(murmur_managed_set_replication(a,"ledger",0)==SQLITE_OK);
  murmur_origin_record_t disabled{}; assert(murmur_managed_schema_export(a,&disabled)==SQLITE_OK);
  for(auto *peer:{b,c}) { int changed=0; assert(murmur_managed_schema_adopt(peer,&disabled,&changed)==SQLITE_OK && changed); }
  ok(a,{"DELETE FROM ledger"}); assert(murmur_managed_set_replication(a,"ledger",1)==SQLITE_CONSTRAINT);
  apply(a,b9); apply(c,b9);
  assert(query(a,"SELECT count(*) FROM ledger")==0 && query(b,"SELECT count(*) FROM ledger")==2 && query(c,"SELECT count(*) FROM ledger")==1);
  murmur_origin_record_free(&disabled);
  ok(a,{"INSERT INTO records(id,value,visits,labels,low,high,settings,events) VALUES(3,'canonical',7,NULL,0,0,'{ \"b\": 2, \"a\": 1 }','[ 1, 2 ]')"}); auto a9=next(a,nodes[0],ca); records.push_back(a9); apply(b,a9); apply(c,a9);
  for(auto *peer:{a,b,c}) assert(query(peer,"SELECT settings='{\"a\":1,\"b\":2}' AND events='[1,2]' AND hex(labels)='00' FROM records WHERE id=3")==1);
  for(auto &r:records) murmur_origin_record_free(&r);
  murmur_origin_record_free(&schema);
  for(auto *peer:handles) murmur_managed_close(peer);
  /* Abrupt process exit preserves effects, epochs, causal state and signed
   * log together, including policy operations before/after SQL COMMIT. */
  snprintf(path,sizeof(path),"%s/crash",root); subprocess(argv[0],"--before",path,41);
  murmur_managed_t *recovered=nullptr; assert(murmur_managed_open(path,key,&recovered)==SQLITE_OK);
  assert(query(recovered,"SELECT count(*) FROM crash_rows")==0);
  uint8_t crash_node[16]={8}; assert(murmur_managed_origin_next(recovered,crash_node,0,&absent)==SQLITE_NOTFOUND); murmur_managed_close(recovered);
  subprocess(argv[0],"--after",path,42); assert(murmur_managed_open(path,key,&recovered)==SQLITE_OK);
  assert(query(recovered,"SELECT n FROM crash_rows WHERE id=1")==13);
  assert(murmur_managed_origin_next(recovered,crash_node,0,&absent)==SQLITE_OK);
  auto durable=managed_replica_decode(absent); assert(durable.rows.size()==1);
  murmur_origin_record_free(&absent); murmur_managed_close(recovered);
  puts("MANAGED-REPLICA-OK (three-node policies, dependency catch-up, generations, reopen)");
}
