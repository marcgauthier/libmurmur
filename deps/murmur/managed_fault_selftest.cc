#include "test_managed_support.h"
#include "managed_internal.h"
#include <cerrno>
#include <cstring>

using namespace managed_test;
/* Linker wrapping keeps fault injection out of the production library.
 * Thread-local arming prevents a background flusher/other store consuming
 * the fault intended for the transaction under test. */
enum Fault { None,BeforeCommit,WalWrite,BeforeSync,AfterSync };
struct Injection { Fault fault=None; int error=EIO; unsigned fired=0; };
static thread_local Injection injection;
static void failure_text(char *err,size_t cap) {
  errno=injection.error;
  if(err && cap) snprintf(err,cap,"injected %s",strerror(injection.error));
}
extern "C" {
int __real_sqlite3_exec(sqlite3 *,const char *,int (*)(void *,int,char **,char **),void *,char **);
int __wrap_sqlite3_exec(sqlite3 *db,const char *sql,int (*callback)(void *,int,char **,char **),void *ctx,char **error) {
  if(injection.fault==BeforeCommit && !strcmp(sql,"COMMIT")) {
    injection.fault=None; ++injection.fired; return SQLITE_IOERR;
  }
  return __real_sqlite3_exec(db,sql,callback,ctx,error);
}
struct NvStore;
int __real_nv_store_write_batch(NvStore *,size_t,const uint8_t **,const size_t *,const uint8_t **,const size_t *,char *,size_t);
int __wrap_nv_store_write_batch(NvStore *store,size_t count,const uint8_t **keys,const size_t *klens,const uint8_t **values,const size_t *vlens,char *err,size_t cap) {
  if(injection.fault==WalWrite) {
    injection.fault=None; ++injection.fired; failure_text(err,cap); return -1;
  }
  return __real_nv_store_write_batch(store,count,keys,klens,values,vlens,err,cap);
}
int __real_nv_store_sync(NvStore *,char *,size_t);
int __wrap_nv_store_sync(NvStore *store,char *err,size_t cap) {
  if(injection.fault==BeforeSync || injection.fault==AfterSync) {
    bool sync_first=injection.fault==AfterSync; injection.fault=None; ++injection.fired;
    if(sync_first) { int rc=__real_nv_store_sync(store,err,cap); if(rc<0) return rc; }
    failure_text(err,cap); return -1;
  }
  return __real_nv_store_sync(store,err,cap);
}
}
namespace {
struct Grant {
  murmur_managed *db; int previous;
  explicit Grant(murmur_managed *db):db(db),previous(0) {
    check(murmur_scheduler_acquire(db->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr),"metadata admission"); previous=db->access; db->access=3;
  }
  ~Grant() { db->access=previous; murmur_scheduler_release(db->coordinator->scheduler); }
};
Rows metadata(murmur_managed *db,const std::string &sql) {
  Grant grant(db); sqlite3_stmt *st=nullptr; check(sqlite3_prepare_v2(db->db,sql.c_str(),-1,&st,nullptr),"metadata prepare");
  std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> owned(st,sqlite3_finalize); Rows rows;
  int rc;
  while((rc=sqlite3_step(st))==SQLITE_ROW) {
    std::vector<ManagedValue> row; for(int i=0;i<sqlite3_column_count(st);++i) row.push_back(ManagedValue::column(st,i)); rows.push_back(std::move(row));
  }
  require(rc==SQLITE_DONE,"metadata read"); return rows;
}
std::string snapshot(murmur_managed *db) {
  return persistent_snapshot(db);
}
int64_t scalar(murmur_managed *db,const char *sql) {
  auto rows=query(db,sql); require(rows.size()==1 && rows[0].size()==1,"scalar shape"); return rows[0][0].integer;
}
bool complete(murmur_managed *db) {
  auto rows=query(db,"SELECT n,(SELECT count(*) FROM ledger),(SELECT coalesce(sum(length(value)),0) FROM ledger) FROM item WHERE id=1");
  require(rows.size()==1,"baseline row lost"); auto &r=rows[0];
  bool before=r[0].integer==10 && r[1].integer==0 && r[2].integer==0;
  bool after=r[0].integer==13 && r[1].integer==2 && r[2].integer==6000;
  require(before || after,"partial policy/ordinary transaction"); return after;
}
void prepare(Cluster &cluster) {
  auto *a=cluster.nodes[0].db;
  check(murmur_managed_migrate(a,"CREATE TABLE item(id INTEGER NOT NULL PRIMARY KEY,n INTEGER); CREATE TABLE ledger(id INTEGER NOT NULL PRIMARY KEY,value TEXT)"),"fault schema");
  check(murmur_managed_set_policy(a,"item","n",MURMUR_POLICY_COUNTER),"fault policy");
  check(murmur_managed_set_replication(a,"item",1),"fault policy replication");
  check(murmur_managed_set_replication(a,"ledger",1),"fault ordinary replication"); cluster.schema();
  sql(a,{"INSERT INTO item VALUES(1,10)"}); auto record=cluster.next(0,0);
  int applied=0; check(murmur_managed_origin_apply(cluster.nodes[1].db,&record.value,&applied),"fault baseline apply"); require(applied==1,"baseline receipt");
}
struct Work { Fault fault; int error; };
int work(murmur_transaction_t *tx,void *ctx) {
  auto &w=*(Work *)ctx;
  for(auto *sql:{"INSERT INTO ledger VALUES(1,printf('%.*c',3000,'a'))",
                 "SELECT murmur_counter_add('item','[1]','n',3)",
                 "INSERT INTO ledger VALUES(2,printf('%.*c',3000,'b'))"}) {
    int rc=murmur_transaction_execute(tx,sql,nullptr,0,nullptr,nullptr); if(rc) return rc;
  }
  injection={w.fault,w.error,0}; return SQLITE_OK;
}
void local(Fault fault,int error) {
  Cluster cluster(2); prepare(cluster); auto *a=cluster.nodes[0].db; auto before=snapshot(a); Work request{fault,error};
  int rc=murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,work,&request);
  require(rc==SQLITE_IOERR,"local injected write must return IOERR rc="+std::to_string(rc)); require(injection.fired==1,"local failure point not reached"); injection={};
  bool committed=complete(a);
  if(fault==BeforeCommit) require(!committed,"precommit failure committed effects");
  if(!committed) require(snapshot(a)==before,"failed commit did not roll back private state");
  if(fault==AfterSync) require(committed,"durably synced transaction missing");
  auto settled=snapshot(a);
  check(murmur_managed_flush(a),"retry durability barrier"); cluster.reopen(0); a=cluster.nodes[0].db;
  require(complete(a)==committed,"retry/reopen changed outcome");
  require(snapshot(a)==settled,"durability retry/reopen changed private state");
  Record record; int exported=murmur_managed_origin_next(a,cluster.nodes[0].id.data(),1,&record.value);
  if(committed) {
    check(exported,"committed log entry"); require(record.value.envelope.sequence==2,"committed sequence");
    auto state=metadata(a,"SELECT baseline,causal FROM murmur_managed_policy_state"); require(state.size()==1,"committed causal state missing");
    int applied=0; check(murmur_managed_origin_apply(cluster.nodes[1].db,&record.value,&applied),"forward recovered record"); require(applied==1 && complete(cluster.nodes[1].db),"forward lost effects");
  } else require(exported==SQLITE_NOTFOUND,"rolled-back transaction exported a record");
  sql(a,{"SELECT murmur_counter_add('item','[1]','n',1)"});
  require(scalar(a,"SELECT n FROM item WHERE id=1")== (committed?14:11),"connection not usable after fault");
  printf("MANAGED-FAULT local phase=%d errno=%d committed=%d\n",fault,error,committed);
}
void remote(Fault fault,int error) {
  Cluster cluster(2); prepare(cluster); auto *a=cluster.nodes[0].db,*b=cluster.nodes[1].db; Work request{None,error};
  check(murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,work,&request),"source transaction"); auto record=cluster.next(0,1);
  auto before=snapshot(b); injection={fault,error,0}; int applied=-1;
  int rc=murmur_managed_origin_apply(b,&record.value,&applied);
  require(rc==SQLITE_IOERR && applied==0,"remote failure return/apply flag"); require(injection.fired==1,"remote failure point not reached"); injection={};
  bool committed=complete(b);
  if(fault==BeforeCommit) require(!committed,"remote precommit failure committed effects");
  if(!committed) require(snapshot(b)==before,"failed remote apply advanced private state");
  if(fault==AfterSync) require(committed,"remote synced effects missing");
  check(murmur_managed_origin_apply(b,&record.value,&applied),"retry remote record"); require(applied==(committed?0:1),"retry applied twice or skipped rollback"); require(complete(b),"retry incomplete");
  auto stable=snapshot(b); applied=-1; check(murmur_managed_origin_apply(b,&record.value,&applied),"duplicate remote record"); require(applied==0 && snapshot(b)==stable,"duplicate changed causal state/receipt/clock");
  cluster.reopen(1); require(complete(cluster.nodes[1].db),"remote reopen lost committed effects");
  require(snapshot(cluster.nodes[1].db)==stable,"remote reopen changed private state");
  printf("MANAGED-FAULT remote phase=%d errno=%d committed=%d\n",fault,error,committed);
}
}
int main() {
  try {
    for(auto fault:{BeforeCommit,WalWrite,BeforeSync,AfterSync}) for(int error:{EIO,ENOSPC}) { local(fault,error); remote(fault,error); }
    puts("MANAGED-FAULT-OK (local/remote precommit, WAL, sync and uncertain-outcome retry)");
  } catch(const std::exception &e) { injection={}; fprintf(stderr,"MANAGED-FAULT-FAIL %s\n",e.what()); return 1; }
  catch(const ManagedError &e) { injection={}; fprintf(stderr,"MANAGED-FAULT-FAIL native rc=%d\n",e.code); return 1; }
}
