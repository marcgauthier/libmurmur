#include "../../libmurmur.h"
#include "sqlite3.h"
#include "engine.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
struct Query { std::string sql; int64_t value=-1; bool abort=false; };
static int row(void *ctx,int n,const murmur_value_t *v) { assert(n==1); ((Query *)ctx)->value=v[0].integer; return 0; }
static int query(murmur_transaction_t *tx,void *ctx) {
  auto &q=*(Query *)ctx; int rc=murmur_transaction_execute(tx,q.sql.c_str(),nullptr,0,row,&q);
  return rc?rc:(q.abort?SQLITE_ABORT:SQLITE_OK);
}
static int run(murmur_managed_t *m,const std::string &sql,int64_t *value=nullptr,bool abort=false) {
  Query q{sql,-1,abort}; int rc=murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,query,&q);
  if(value) *value=q.value;
  return rc;
}
static void ok(murmur_managed_t *m,const std::string &sql) {
  int rc=run(m,sql); if(rc) fprintf(stderr,"rc=%d sql=%s\n",rc,sql.c_str()); assert(rc==SQLITE_OK);
}
static int64_t count(murmur_managed_t *m) { int64_t n=-1; assert(run(m,"SELECT count(*) FROM items",&n)==SQLITE_OK); return n; }
static void apply(murmur_managed_t *m,const murmur_origin_record_t &r,int expected=1) {
  int changed=-1; int rc=murmur_managed_origin_apply(m,&r,&changed);
  if(rc) fprintf(stderr,"apply rc=%d sequence=%llu bytes=%zu\n",rc,(unsigned long long)r.envelope.sequence,r.bytes);
  assert(rc==SQLITE_OK && changed==expected);
}
static int crash_before_commit(murmur_transaction_t *tx,void *) {
  assert(murmur_transaction_execute(tx,"INSERT INTO crash_rows VALUES(1,'uncommitted')",nullptr,0,nullptr,nullptr)==SQLITE_OK);
  _exit(31);
}
static void crash_writer(const char *mode,const char *path) {
  uint8_t key[32]={1},db[16]={7},node[16]={8},seed[32]={9}; murmur_managed_t *m=nullptr;
  assert(murmur_managed_open(path,key,&m)==SQLITE_OK);
  assert(murmur_managed_migrate(m,"CREATE TABLE IF NOT EXISTS crash_rows(id INTEGER NOT NULL PRIMARY KEY,value TEXT)")==SQLITE_OK);
  assert(murmur_managed_origin_configure(m,db,node,seed)==SQLITE_OK);
  assert(murmur_managed_set_replication(m,"crash_rows",1)==SQLITE_OK);
  if(!strcmp(mode,"--abort")) murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,crash_before_commit,nullptr);
  ok(m,"INSERT INTO crash_rows VALUES(1,'committed')");
  _exit(32); /* no SQLite/cr-sqlite/store destructors run */
}
static void subprocess(const char *binary,const char *mode,const char *path,int expected) {
  pid_t pid=fork(); assert(pid>=0);
  if(!pid) { execl(binary,binary,mode,path,(char *)nullptr); _exit(99); }
  int status=0; assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==expected);
}
int main(int argc,char **argv) {
  if(argc==3) crash_writer(argv[1],argv[2]);
  char root[]="/tmp/murmur-managed-origin-XXXXXX",a_path[256],b_path[256],c_path[256]; assert(mkdtemp(root));
  snprintf(a_path,sizeof(a_path),"%s/a",root); snprintf(b_path,sizeof(b_path),"%s/b",root); snprintf(c_path,sizeof(c_path),"%s/c",root);
  uint8_t key[32]={1},database[16]={9},node_a[16]={1},node_b[16]={2},node_c[16]={3},seed_a[32]={4},seed_b[32]={5},seed_c[32]={6};
  murmur_managed_t *a=nullptr,*b=nullptr,*c=nullptr;
  assert(murmur_managed_open(a_path,key,&a)==SQLITE_OK); assert(murmur_managed_open(b_path,key,&b)==SQLITE_OK); assert(murmur_managed_open(c_path,key,&c)==SQLITE_OK);
  const char *schema="CREATE TABLE items(id INTEGER NOT NULL PRIMARY KEY,value TEXT)";
  for(auto *m:{a,b,c}) assert(murmur_managed_migrate(m,schema)==SQLITE_OK);
  assert(murmur_managed_origin_configure(a,database,node_a,seed_a)==SQLITE_OK);
  assert(murmur_managed_origin_configure(b,database,node_b,seed_b)==SQLITE_OK);
  assert(murmur_managed_origin_configure(c,database,node_c,seed_c)==SQLITE_OK);
  for(auto *m:{a,b,c}) assert(murmur_managed_set_replication(m,"items",1)==SQLITE_OK);
  murmur_origin_identity_t ia,ib,ic;
  assert(murmur_managed_origin_identity(a,&ia)==SQLITE_OK); assert(murmur_managed_origin_identity(b,&ib)==SQLITE_OK); assert(murmur_managed_origin_identity(c,&ic)==SQLITE_OK);
  assert(murmur_managed_origin_trust(b,&ia,1)==SQLITE_OK); assert(murmur_managed_origin_trust(a,&ib,1)==SQLITE_OK); assert(murmur_managed_origin_trust(c,&ia,1)==SQLITE_OK);
  assert(murmur_managed_schema_master(b,node_a)==SQLITE_OK); assert(murmur_managed_schema_master(c,node_a)==SQLITE_OK);
  /* Pre-history authority repinning must not reuse signed schema sequences. */
  assert(murmur_managed_schema_master(b,node_b)==SQLITE_OK);
  murmur_origin_record_t own_schema{}; assert(murmur_managed_schema_export(b,&own_schema)==SQLITE_OK); murmur_origin_record_free(&own_schema);
  assert(murmur_managed_schema_master(b,node_a)==SQLITE_OK);
  murmur_origin_record_t schema_record{}; assert(murmur_managed_schema_export(a,&schema_record)==SQLITE_OK);
  int schema_changed=0; assert(murmur_managed_schema_adopt(b,&schema_record,&schema_changed)==SQLITE_OK && schema_changed);
  assert(murmur_managed_schema_adopt(c,&schema_record,&schema_changed)==SQLITE_OK && schema_changed);
  murmur_origin_record_free(&schema_record);
  auto changed_key=ia; changed_key.public_key[0]^=1;
  assert(murmur_managed_origin_trust(b,&changed_key,1)==SQLITE_AUTH);
  auto changed_site=ia; changed_site.site[0]^=1;
  assert(murmur_managed_origin_trust(b,&changed_site,1)==SQLITE_AUTH);
  assert(murmur_managed_origin_configure(a,database,node_a,seed_b)==SQLITE_AUTH);
  ok(a,"INSERT INTO items VALUES(1,'first')");
  assert(murmur_managed_set_policy(a,"items","value",MURMUR_POLICY_JSON)==SQLITE_CONSTRAINT);
  murmur_origin_record_t first{},second{},forwarded{};
  assert(murmur_managed_origin_next(a,node_a,0,&first)==SQLITE_OK && first.envelope.sequence==1);
  assert(murmur_origin_verify(&first.envelope,database,node_a,ia.public_key,first.payload,first.bytes,64u<<20)==SQLITE_OK);
  auto *payload=first.payload; payload[first.bytes-1]^=1; int applied=-1;
  assert(murmur_managed_origin_apply(b,&first,&applied)==SQLITE_AUTH && applied==0 && count(b)==0);
  payload[first.bytes-1]^=1; apply(b,first); apply(b,first,0); assert(count(b)==1);
  assert(murmur_managed_origin_next(b,node_a,0,&forwarded)==SQLITE_OK);
  uint8_t first_header[200],forwarded_header[200];
  assert(murmur_origin_envelope_encode(&first.envelope,first_header,sizeof(first_header))==SQLITE_OK);
  assert(murmur_origin_envelope_encode(&forwarded.envelope,forwarded_header,sizeof(forwarded_header))==SQLITE_OK);
  assert(!memcmp(first_header,forwarded_header,200) && first.bytes==forwarded.bytes && !memcmp(first.payload,forwarded.payload,first.bytes));
  apply(c,forwarded); assert(count(c)==1);
  murmur_origin_record_t own{}; assert(murmur_managed_origin_next(b,node_b,0,&own)==SQLITE_NOTFOUND); /* no re-origination */
  ok(a,"INSERT INTO items VALUES(2,'second')"); assert(murmur_managed_origin_next(a,node_a,1,&second)==SQLITE_OK && second.envelope.sequence==2);
  /* A fresh receiver rejects gaps without progress/effects. */
  auto gap=second; gap.envelope.sequence=4; assert(murmur_origin_sign(&gap.envelope,seed_a,gap.payload,gap.bytes)==SQLITE_OK);
  assert(murmur_managed_origin_apply(b,&gap,&applied)==SQLITE_BUSY && count(b)==1);
  apply(b,second); assert(count(b)==2);
  /* Validly signed equivocation under an existing sequence is refused. */
  auto equivocation=first; equivocation.envelope.transaction[0]^=1;
  assert(murmur_origin_sign(&equivocation.envelope,seed_a,equivocation.payload,equivocation.bytes)==SQLITE_OK);
  assert(murmur_managed_origin_apply(b,&equivocation,&applied)==SQLITE_AUTH && count(b)==2);
  auto wrong_database=second; wrong_database.envelope.database[0]^=1;
  assert(murmur_origin_sign(&wrong_database.envelope,seed_a,wrong_database.payload,wrong_database.bytes)==SQLITE_OK);
  assert(murmur_managed_origin_apply(b,&wrong_database,&applied)==SQLITE_AUTH);
  /* Even a trusted signer cannot forge another origin's cr-sqlite site. */
  std::vector<murmur_cell_t> cells(64); size_t cell_count=0;
  assert(murmur_cells_decode(first.payload,first.bytes,cells.data(),cells.size(),&cell_count)==MURMUR_OK);
  std::vector<uint8_t> forged_body(first.payload,first.payload+first.bytes);
  size_t site_offset=cells[0].site-first.payload; forged_body[site_offset]^=1;
  auto forged=first; forged.payload=forged_body.data(); forged.envelope.sequence=3;
  assert(murmur_origin_sign(&forged.envelope,seed_a,forged.payload,forged.bytes)==SQLITE_OK);
  assert(murmur_managed_origin_apply(b,&forged,&applied)==SQLITE_AUTH);
  assert(run(a,"INSERT INTO items VALUES(3,'rolled back')",nullptr,true)==SQLITE_ABORT);
  assert(murmur_managed_origin_next(a,node_a,2,&own)==SQLITE_NOTFOUND);
  assert(murmur_managed_origin_trust(b,&ia,0)==SQLITE_OK);
  assert(murmur_managed_origin_apply(b,&first,&applied)==SQLITE_AUTH);
  assert(murmur_managed_origin_trust(b,&ia,1)==SQLITE_OK);
  /* Receiver's own writes use its signer and preserve both origin streams. */
  ok(b,"INSERT INTO items VALUES(4,'from b')"); assert(murmur_managed_origin_next(b,node_b,0,&own)==SQLITE_OK); apply(a,own); assert(count(a)==3);
  /* Once activated, ordinary handles cannot write unsigned replicated data. */
  murmur_managed_t *unsigned_handle=nullptr; assert(murmur_managed_open(a_path,key,&unsigned_handle)==SQLITE_OK);
  assert(run(unsigned_handle,"INSERT INTO items VALUES(5,'unsigned')")==SQLITE_AUTH && count(a)==3);
  murmur_managed_close(unsigned_handle);
  murmur_managed_close(a); murmur_managed_close(b); murmur_managed_close(c);
  assert(murmur_managed_open(a_path,key,&a)==SQLITE_OK);
  assert(murmur_managed_origin_configure(a,database,node_a,seed_a)==SQLITE_OK);
  ok(a,"INSERT INTO items VALUES(6,'reopen')"); murmur_origin_record_t third{};
  assert(murmur_managed_origin_next(a,node_a,2,&third)==SQLITE_OK && third.envelope.sequence==3);
  assert(murmur_managed_open(b_path,key,&b)==SQLITE_OK);
  apply(b,third); assert(count(b)==4);
  assert(murmur_managed_origin_configure(b,database,node_b,seed_b)==SQLITE_OK);
  ok(a,"UPDATE items SET value='left' WHERE id=1"); ok(b,"UPDATE items SET value='right' WHERE id=1");
  murmur_origin_record_t left{},right{},deleted{};
  assert(murmur_managed_origin_next(a,node_a,3,&left)==SQLITE_OK);
  assert(murmur_managed_origin_next(b,node_b,1,&right)==SQLITE_OK);
  apply(b,left); apply(a,right);
  int64_t av=-1,bv=-1; assert(run(a,"SELECT value='left' FROM items WHERE id=1",&av)==SQLITE_OK);
  assert(run(b,"SELECT value='left' FROM items WHERE id=1",&bv)==SQLITE_OK && av==bv);
  ok(a,"DELETE FROM items WHERE id=2"); assert(murmur_managed_origin_next(a,node_a,4,&deleted)==SQLITE_OK);
  apply(b,deleted); assert(count(a)==3 && count(b)==3);
  /* Legacy engine refuses signed stores even with otherwise valid startup. */
  sqlite3 *raw=nullptr; assert(sqlite3_open_v2(b_path,&raw,SQLITE_OPEN_READWRITE,"sqlite-murmur")==SQLITE_OK); assert(murmur_db_key(raw,key)==SQLITE_OK);
  murmur_engine_t engine; murmur_engine_init(&engine,raw); murmur_engine_set_transport(&engine,"127.0.0.1:7443");
  char *detail=nullptr; int sqlrc=0; assert(murmur_engine_start(&engine,&detail,&sqlrc)==MURMUR_SYNC_AUTH);
  free(detail); murmur_engine_destroy(&engine); sqlite3_close(raw);
  murmur_managed_close(a); murmur_managed_close(b);
  for(auto *r:{&first,&second,&forwarded,&own,&third,&left,&right,&deleted}) murmur_origin_record_free(r);
  /* Restart from an actual abrupt process exit before/after commit. */
  char crash_path[256]; snprintf(crash_path,sizeof(crash_path),"%s/crash",root);
  subprocess(argv[0],"--abort",crash_path,31);
  murmur_managed_t *recovered=nullptr; assert(murmur_managed_open(crash_path,key,&recovered)==SQLITE_OK);
  int64_t rows=-1; assert(run(recovered,"SELECT count(*) FROM crash_rows",&rows)==SQLITE_OK && rows==0);
  uint8_t crash_node[16]={8}; murmur_origin_record_t recovered_record{};
  assert(murmur_managed_origin_next(recovered,crash_node,0,&recovered_record)==SQLITE_NOTFOUND);
  murmur_managed_close(recovered);
  subprocess(argv[0],"--commit",crash_path,32);
  assert(murmur_managed_open(crash_path,key,&recovered)==SQLITE_OK);
  assert(run(recovered,"SELECT count(*) FROM crash_rows",&rows)==SQLITE_OK && rows==1);
  assert(murmur_managed_origin_next(recovered,crash_node,0,&recovered_record)==SQLITE_OK && recovered_record.envelope.sequence==1);
  murmur_origin_record_free(&recovered_record); murmur_managed_close(recovered);
  puts("MANAGED-ORIGIN-OK");
}
