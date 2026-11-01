#include "../../libmurmur.h"
#include "sqlite3.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
struct Result { murmur_value_type_t type=MURMUR_NULL; int64_t integer=0; double real=0; std::string text; };
static int row(void *ctx,int n,const murmur_value_t *v) {
  assert(n==1); auto &out=*(Result *)ctx; out.type=v[0].type; out.integer=v[0].integer; out.real=v[0].real;
  if(v[0].type==MURMUR_TEXT || v[0].type==MURMUR_BLOB) out.text.assign((const char *)v[0].data,v[0].bytes);
  return 0;
}
struct Query { std::string sql; Result result; };
static int query(murmur_transaction_t *tx,void *ctx) {
  auto &q=*(Query *)ctx; return murmur_transaction_execute(tx,q.sql.c_str(),nullptr,0,row,&q.result);
}
static int run(murmur_managed_t *m,const std::string &sql,Result *out=nullptr) {
  Query q{sql,{}}; int rc=murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,query,&q);
  if(out) *out=q.result;
  return rc;
}
static void ok(murmur_managed_t *m,const std::string &sql) {
  int rc=run(m,sql); if(rc) fprintf(stderr,"rc=%d sql=%s\n",rc,sql.c_str()); assert(rc==SQLITE_OK);
}
static Result get(murmur_managed_t *m,const std::string &column) {
  Result out; int rc=run(m,"SELECT "+column+" FROM records WHERE a=1 AND b='x'",&out);
  if(rc) fprintf(stderr,"select rc=%d column=%s\n",rc,column.c_str());
  assert(rc==SQLITE_OK); return out;
}
static std::string call(const std::string &op,const std::string &col,const std::string &value) {
  return "SELECT murmur_"+op+"('records','[1,\"x\"]','"+col+"',"+value+")";
}
static int c_counter(murmur_transaction_t *tx,void *ctx) {
  murmur_value_t key[2]{}; key[0].type=MURMUR_INTEGER; key[0].integer=1;
  key[1].type=MURMUR_TEXT; key[1].data="x"; key[1].bytes=1;
  murmur_policy_operation_t op{}; op.kind=MURMUR_OP_COUNTER_ADD; op.delta=-3;
  int rc=murmur_transaction_policy(tx,"records",key,2,"counter",&op);
  return rc?rc:(ctx?SQLITE_ABORT:SQLITE_OK);
}
static int rolled_generation(murmur_transaction_t *tx,void *) {
  assert(murmur_transaction_execute(tx,"DELETE FROM records",nullptr,0,nullptr,nullptr)==SQLITE_OK);
  assert(murmur_transaction_execute(tx,"INSERT INTO records VALUES(1,'x',500,NULL,0,0,'{}','[]','fresh')",nullptr,0,nullptr,nullptr)==SQLITE_OK);
  assert(c_counter(tx,nullptr)==SQLITE_OK); return SQLITE_ABORT;
}
static int policy_row(void *ctx,int n,const murmur_value_t *v) { assert(n==3 && v[2].type==MURMUR_INTEGER); ++*(int *)ctx; return 0; }
static int catch_error(murmur_transaction_t *tx,void *) {
  murmur_value_t key[2]{}; key[0].type=MURMUR_INTEGER; key[0].integer=1;
  key[1].type=MURMUR_TEXT; key[1].data="x"; key[1].bytes=1;
  murmur_policy_operation_t op{}; op.kind=MURMUR_OP_COUNTER_ADD; op.delta=INT64_MAX;
  assert(murmur_transaction_policy(tx,"records",key,2,"count",&op)==SQLITE_TOOBIG);
  op.delta=1;
  return murmur_transaction_policy(tx,"records",key,2,"count",&op);
}
int main() {
  char root[]="/tmp/murmur-managed-policy-XXXXXX",path[256]; assert(mkdtemp(root)); snprintf(path,sizeof(path),"%s/store",root);
  uint8_t key[32]={6}; murmur_managed_t *m=nullptr,*other=nullptr;
  assert(murmur_managed_open(path,key,&m)==SQLITE_OK);
  assert(murmur_managed_migrate(m,"CREATE TABLE records(a INTEGER,b TEXT,counter INTEGER,tags BLOB,low,high,doc TEXT,items TEXT,note TEXT,PRIMARY KEY(a,b)) WITHOUT ROWID")==SQLITE_OK);
  ok(m,"INSERT INTO records VALUES(1,'x',10,NULL,10,10,'{\"hello\":\"world\"}','[\"seed\",1]','untouched')");
  const char *cols[]={"counter","tags","low","high","doc","items"};
  for(int i=0;i<6;++i) assert(murmur_managed_set_policy(m,"records",cols[i],(murmur_merge_policy_t)(i+1))==SQLITE_OK);
  assert(murmur_managed_set_policy(m,"records","a",MURMUR_POLICY_COUNTER)!=SQLITE_OK);
  assert(murmur_managed_set_policy(m,"records","counter",MURMUR_POLICY_SET)==SQLITE_CONSTRAINT);
  assert(murmur_managed_set_policy(m,"records","counter",MURMUR_POLICY_LWW)==SQLITE_CONSTRAINT);
  int count=0; assert(murmur_managed_policy_status(m,policy_row,&count)==SQLITE_OK && count==6);
  assert(run(m,"UPDATE records SET counter=0")==SQLITE_AUTH);
  assert(run(m,"UPDATE records SET a=2")==SQLITE_AUTH);
  assert(murmur_managed_migrate(m,"DROP TABLE records")!=SQLITE_OK);
  assert(murmur_managed_migrate(m,"ALTER TABLE records RENAME TO scratch; DROP TABLE scratch; CREATE TABLE records(a,b,counter)")!=SQLITE_OK);
  ok(m,"UPDATE records SET note='allowed'");
  assert(murmur_managed_set_policy(m,"records","note",MURMUR_POLICY_LWW)==SQLITE_OK);
  ok(m,"UPDATE records SET note='still allowed'");
  ok(m,call("counter_add","counter","5")); assert(get(m,"counter").integer==15);
  assert(murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,c_counter,nullptr)==SQLITE_OK);
  assert(get(m,"counter").integer==12);
  assert(murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,c_counter,(void *)1)==SQLITE_ABORT);
  assert(get(m,"counter").integer==12);
  ok(m,call("set_add","tags","'go'")); assert(get(m,"hex(tags)").text=="010302676F");
  ok(m,call("set_add","tags","5")); assert(get(m,"hex(tags)").text=="02010A0302676F");
  ok(m,call("set_remove","tags","'go'")); assert(get(m,"hex(tags)").text=="01010A");
  ok(m,call("min","low","4")); ok(m,call("min","low","8")); assert(get(m,"low").integer==4);
  ok(m,call("max","high","20")); assert(get(m,"high").integer==20);
  ok(m,call("json_set","doc","'color','<>&'"));
  assert(get(m,"doc").text=="{\"color\":\"\\u003c\\u003e\\u0026\",\"hello\":\"world\"}");
  ok(m,call("json_remove","doc","'hello'")); assert(get(m,"doc").text=="{\"color\":\"\\u003c\\u003e\\u0026\"}");
  ok(m,call("list_append","items","'go'")); assert(get(m,"items").text=="[\"seed\",1,\"go\"]");
  ok(m,call("list_remove","items","'seed'")); assert(get(m,"items").text=="[1,\"go\"]");
  /* Failed policy operations can be caught without committing partial state. */
  assert(run(m,call("list_append","items","x'00'"))!=SQLITE_OK);
  assert(get(m,"items").text=="[1,\"go\"]");
  assert(run(m,call("counter_add","counter","9223372036854775807"))!=SQLITE_OK);
  assert(get(m,"counter").integer==12);
  assert(run(m,"SELECT murmur_counter_add('records','[99,\"x\"]','counter',1)")==SQLITE_NOTFOUND);
  assert(murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,rolled_generation,nullptr)==SQLITE_ABORT);
  assert(get(m,"counter").integer==12);
  ok(m,call("counter_add","counter","1")); assert(get(m,"counter").integer==13);
  /* New handles refresh policy guards and share persisted actor/state. */
  assert(murmur_managed_open(path,key,&other)==SQLITE_OK);
  assert(run(other,"UPDATE records SET counter=0")==SQLITE_AUTH);
  ok(other,call("counter_add","counter","2")); assert(get(m,"counter").integer==15);
  murmur_managed_close(other); murmur_managed_close(m);
  assert(murmur_managed_open(path,key,&m)==SQLITE_OK);
  ok(m,call("counter_add","counter","1")); assert(get(m,"counter").integer==16);
  /* A reinserted primary key gets a fresh baseline, including REPLACE. */
  ok(m,"DELETE FROM records");
  ok(m,"INSERT INTO records VALUES(1,'x',100,NULL,0,0,'{}','[]','new')");
  ok(m,call("counter_add","counter","1")); assert(get(m,"counter").integer==101);
  assert(get(m,"doc").text=="{}");
  ok(m,"INSERT OR REPLACE INTO records VALUES(1,'x',200,NULL,0,0,'{}','[]','replace')");
  ok(m,call("counter_add","counter","1")); assert(get(m,"counter").integer==201);
  /* Established policy metadata follows explicit renames and rejects drops. */
  murmur_rename_t rename={"records",nullptr,"counter","count"};
  assert(murmur_managed_migrate_mapped(m,"ALTER TABLE records RENAME COLUMN counter TO count",&rename,1)==SQLITE_OK);
  ok(m,call("counter_add","count","1")); assert(get(m,"count").integer==202);
  assert(murmur_managed_migrate(m,"ALTER TABLE records DROP COLUMN count")!=SQLITE_OK);
  ok(m,call("counter_add","count","1")); assert(get(m,"count").integer==203);
  assert(murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,catch_error,nullptr)==SQLITE_OK);
  assert(get(m,"count").integer==204);
  /* Binary primary keys use the same canonical key BLOB as C callers. */
  assert(murmur_managed_migrate(m,"CREATE TABLE binary_keys(id BLOB PRIMARY KEY,n INTEGER)")==SQLITE_OK);
  assert(murmur_managed_set_policy(m,"binary_keys","n",MURMUR_POLICY_COUNTER)==SQLITE_OK);
  ok(m,"INSERT INTO binary_keys VALUES(x'00ff',-9223372036854775808)");
  ok(m,"SELECT murmur_counter_add('binary_keys',murmur_policy_key(x'00ff'),'n',9223372036854775807)");
  ok(m,"SELECT murmur_counter_add('binary_keys',murmur_policy_key(x'00ff'),'n',1)");
  Result binary; assert(run(m,"SELECT n FROM binary_keys",&binary)==SQLITE_OK && binary.integer==0);
  /* Missing/null keys and failed baselines do not leave partial effects. */
  assert(run(m,"INSERT INTO binary_keys VALUES(NULL,0)")!=SQLITE_OK);
  assert(run(m,"SELECT count(*) FROM binary_keys",&binary)==SQLITE_OK && binary.integer==1);
  assert(murmur_managed_migrate(m,"CREATE TABLE nullable_keys(id TEXT PRIMARY KEY,n INTEGER)")==SQLITE_OK);
  ok(m,"INSERT INTO nullable_keys VALUES(NULL,1)");
  assert(murmur_managed_set_policy(m,"nullable_keys","n",MURMUR_POLICY_COUNTER)!=SQLITE_OK);
  ok(m,"UPDATE nullable_keys SET n=2");
  /* Failed installation restored the other tables' epoch triggers. */
  ok(m,"INSERT OR REPLACE INTO binary_keys VALUES(x'00ff',7)");
  ok(m,"SELECT murmur_counter_add('binary_keys',murmur_policy_key(x'00ff'),'n',1)");
  assert(run(m,"SELECT n FROM binary_keys",&binary)==SQLITE_OK && binary.integer==8);
  murmur_managed_close(m); puts("MANAGED-POLICY-OK");
}
