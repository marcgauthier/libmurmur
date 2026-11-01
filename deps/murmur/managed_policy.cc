#include "managed_internal.h"
#include "managed_value.h"
#include "causal.h"
#include "managed_policy_state.h"
#include "managed_replica.h"
#include "managed_schema_internal.h"
#include "open.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <memory>

namespace {
struct Column { std::string name,id; int policy; };
struct Table { std::string name,id; std::vector<std::string> keys; std::vector<Column> columns; };
struct Access {
  murmur_managed *m; int old;
  Access(murmur_managed *m):m(m),old(m->access) { m->access=3; }
  ~Access() { m->access=old; }
};
struct Statement {
  sqlite3_stmt *p=nullptr;
  Statement(sqlite3 *db,const std::string &sql) { managed_check(sqlite3_prepare_v2(db,sql.c_str(),-1,&p,nullptr)); }
  ~Statement() { sqlite3_finalize(p); }
  void text(int i,const std::string &v) { managed_check(sqlite3_bind_text64(p,i,v.data(),v.size(),SQLITE_TRANSIENT,SQLITE_UTF8)); }
  void blob(int i,const std::string &v) { managed_check(sqlite3_bind_blob64(p,i,v.data(),v.size(),SQLITE_TRANSIENT)); }
  bool row() { int rc=sqlite3_step(p); if(rc==SQLITE_ROW) return true; if(rc!=SQLITE_DONE) throw ManagedError{rc}; return false; }
  void done() { if(row()) throw ManagedError{SQLITE_ERROR}; }
};
struct Grant {
  murmur_scheduler_t *s;
  Grant(murmur_managed *m):s(m->coordinator->scheduler) { managed_check(murmur_scheduler_acquire(s,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr)); }
  ~Grant() { murmur_scheduler_release(s); }
};
void exec(sqlite3 *db,const std::string &sql) { managed_check(sqlite3_exec(db,sql.c_str(),nullptr,nullptr,nullptr)); }
std::string text(sqlite3_stmt *st,int i) { auto v=ManagedValue::column(st,i); if(v.type!=MURMUR_TEXT) throw ManagedError{SQLITE_CORRUPT}; return v.data; }
std::string blob(sqlite3_stmt *st,int i) { auto v=ManagedValue::column(st,i); if(v.type!=MURMUR_BLOB) throw ManagedError{SQLITE_CORRUPT}; return v.data; }
std::string quote(const std::string &name) {
  char *p=sqlite3_mprintf("\"%w\"",name.c_str()); if(!p) throw ManagedError{SQLITE_NOMEM};
  std::unique_ptr<char,decltype(&sqlite3_free)> owned(p,sqlite3_free); return p;
}
template<class Fn> int checked(Fn fn) {
  try { fn(); return SQLITE_OK; }
  catch(const ManagedError &e) { return e.code; }
  catch(...) { return SQLITE_NOMEM; }
}
void key_function(sqlite3_context *ctx,int argc,sqlite3_value **argv) {
  int rc=checked([&] {
    std::vector<ManagedValue> values;
    for(int i=0;i<argc;++i) {
      auto v=ManagedValue::argument(argv[i]);
      if(v.type==MURMUR_NULL) throw ManagedError{SQLITE_MISMATCH};
      values.push_back(std::move(v));
    }
    auto bytes=managed_encode_values(values);
    sqlite3_result_blob64(ctx,bytes.data(),bytes.size(),SQLITE_TRANSIENT);
  });
  if(rc) sqlite3_result_error_code(ctx,rc);
}
struct SqlOperation { murmur_managed *m; murmur_policy_op_t kind; };
void sql_operation(sqlite3_context *,int,sqlite3_value **);
struct SqlFunction { const char *name; int argc; murmur_policy_op_t op; };
const SqlFunction functions[]={
  {"murmur_counter_add",4,MURMUR_OP_COUNTER_ADD}, {"murmur_set_add",4,MURMUR_OP_SET_ADD},
  {"murmur_set_remove",4,MURMUR_OP_SET_REMOVE}, {"murmur_min",4,MURMUR_OP_MIN},
  {"murmur_max",4,MURMUR_OP_MAX}, {"murmur_json_set",5,MURMUR_OP_JSON_SET},
  {"murmur_json_remove",4,MURMUR_OP_JSON_REMOVE}, {"murmur_list_append",4,MURMUR_OP_LIST_APPEND},
  {"murmur_list_remove",4,MURMUR_OP_LIST_REMOVE}
};
}
struct ManagedPolicies {
  int64_t generation=-1;
  std::array<uint8_t,16> database{},node{};
  std::map<std::string,Table> tables;
  std::set<std::string> triggers;
};
namespace {
std::shared_ptr<ManagedPolicies> load(murmur_managed *m) {
  auto policies=std::make_shared<ManagedPolicies>();
  {
    Statement st(m->db,"SELECT generation FROM murmur_managed_generation WHERE singleton=1");
    if(!st.row()) throw ManagedError{SQLITE_CORRUPT};
    policies->generation=sqlite3_column_int64(st.p,0);
  }
  {
    Statement st(m->db,"SELECT database_id,node_id FROM murmur_managed_actor WHERE singleton=1");
    if(!st.row()) throw ManagedError{SQLITE_CORRUPT};
    auto db=blob(st.p,0),node=blob(st.p,1);
    if(db.size()!=16 || node.size()!=16) throw ManagedError{SQLITE_CORRUPT};
    memcpy(policies->database.data(),db.data(),16); memcpy(policies->node.data(),node.data(),16);
  }
  Statement st(m->db,"SELECT t.name,lower(hex(t.id)),c.name,lower(hex(c.id)),p.policy FROM murmur_managed_policies p LEFT JOIN murmur_managed_columns c ON c.id=p.column_id LEFT JOIN murmur_managed_tables t ON t.id=c.table_id WHERE p.policy<>0 ORDER BY t.name,c.name");
  while(st.row()) {
    if(sqlite3_column_type(st.p,0)==SQLITE_NULL) throw ManagedError{SQLITE_CONSTRAINT};
    auto name=text(st.p,0); auto &t=policies->tables[name]; t.name=name; t.id=text(st.p,1);
    int policy=sqlite3_column_int(st.p,4);
    if(policy<1 || policy>6) throw ManagedError{SQLITE_CORRUPT};
    t.columns.push_back({text(st.p,2),text(st.p,3),policy});
  }
  for(auto &pair:policies->tables) {
    auto &t=pair.second; std::map<int,std::string> keys;
    Statement info(m->db,"SELECT name,pk,hidden FROM pragma_table_xinfo(?1)"); info.text(1,t.name);
    std::set<std::string> writable;
    while(info.row()) {
      auto name=text(info.p,0); int pk=sqlite3_column_int(info.p,1);
      if(pk) keys[pk]=name;
      if(!sqlite3_column_int(info.p,2)) writable.insert(name);
    }
    if(keys.empty()) throw ManagedError{SQLITE_MISMATCH};
    for(auto &k:keys) t.keys.push_back(k.second);
    for(auto &c:t.columns) {
      if(!writable.count(c.name) || std::find(t.keys.begin(),t.keys.end(),c.name)!=t.keys.end()) throw ManagedError{SQLITE_CONSTRAINT};
    }
    policies->triggers.insert("murmur_policy_insert_"+t.id);
    policies->triggers.insert("murmur_policy_delete_"+t.id);
    policies->triggers.insert("murmur_policy_update_"+t.id);
  }
  return policies;
}
void install(murmur_managed *m,const ManagedPolicies &policies) {
  std::vector<std::string> names;
  {
    Statement st(m->db,"SELECT name FROM sqlite_schema WHERE type='trigger' AND name GLOB 'murmur_policy_*'");
    while(st.row()) names.push_back(text(st.p,0));
  }
  for(auto &name:names) exec(m->db,"DROP TRIGGER "+quote(name));
  for(auto &pair:policies.tables) {
    auto &t=pair.second;
    std::string columns,oldkeys,newkeys;
    for(auto &key:t.keys) {
      if(!columns.empty()) { columns+=','; oldkeys+=','; newkeys+=','; }
      columns+=quote(key); oldkeys+="OLD."+quote(key); newkeys+="NEW."+quote(key);
    }
    auto tid="x'"+t.id+"'";
    auto mark=[&](const std::string &keys) { return " INSERT OR IGNORE INTO murmur_managed_policy_dirty VALUES("+tid+",murmur_policy_key("+keys+"));"; };
    exec(m->db,"INSERT OR IGNORE INTO murmur_managed_row_epochs SELECT "+tid+",murmur_policy_key("+columns+"),randomblob(16),1 FROM "+quote(t.name));
    exec(m->db,"CREATE TRIGGER "+quote("murmur_policy_insert_"+t.id)+" AFTER INSERT ON "+quote(t.name)+
      " WHEN crsql_internal_sync_bit()=0 BEGIN INSERT INTO murmur_managed_row_epochs VALUES("+tid+",murmur_policy_key("+newkeys+"),randomblob(16),1) ON CONFLICT(table_id,row_key) DO UPDATE SET epoch=excluded.epoch,alive=1;"+mark(newkeys)+" END");
    exec(m->db,"CREATE TRIGGER "+quote("murmur_policy_delete_"+t.id)+" AFTER DELETE ON "+quote(t.name)+
      " WHEN crsql_internal_sync_bit()=0 BEGIN INSERT INTO murmur_managed_row_epochs VALUES("+tid+",murmur_policy_key("+oldkeys+"),randomblob(16),0) ON CONFLICT(table_id,row_key) DO UPDATE SET alive=0;"+mark(oldkeys)+" END");
    exec(m->db,"CREATE TRIGGER "+quote("murmur_policy_update_"+t.id)+" AFTER UPDATE ON "+quote(t.name)+
      " WHEN crsql_internal_sync_bit()=0 BEGIN"+mark(newkeys)+" END");
  }
}
const Table &table_for(murmur_managed *m,const char *name) {
  if(!m->policies) throw ManagedError{SQLITE_MISMATCH};
  for(auto &p:m->policies->tables) if(!sqlite3_stricmp(name,p.first.c_str())) return p.second;
  throw ManagedError{SQLITE_MISMATCH};
}
const Column &column_for(const Table &t,const char *name) {
  for(auto &c:t.columns) if(!sqlite3_stricmp(c.name.c_str(),name)) return c;
  throw ManagedError{SQLITE_MISMATCH};
}
}
bool managed_policy_has_table(murmur_managed *m,const char *table) {
  if(!m->policies || !table) return false;
  for(auto &entry:m->policies->tables) if(!sqlite3_stricmp(entry.first.c_str(),table)) return true;
  return false;
}
bool managed_policy_sql_function(const char *name) {
  if(!sqlite3_stricmp(name,"murmur_policy_key")) return true;
  for(auto &f:functions) if(!sqlite3_stricmp(name,f.name)) return true;
  return false;
}
bool managed_policy_trusted_trigger(murmur_managed *m,const char *name) {
  return name && m->policies && m->policies->triggers.count(name);
}
bool managed_policy_update_denied(murmur_managed *m,const char *table,const char *column) {
  if(!table || !column || !m->policies) return false;
  for(auto &p:m->policies->tables) if(!sqlite3_stricmp(table,p.first.c_str())) {
    for(auto &c:p.second.columns) if(!sqlite3_stricmp(column,c.name.c_str())) return true;
    for(auto &k:p.second.keys) if(!sqlite3_stricmp(column,k.c_str())) return true;
  }
  return false;
}
bool managed_policy_ddl_denied(murmur_managed *m,int action,const char *name) {
  bool protected_table=false;
  if(name && m->policies) for(auto &t:m->policies->tables)
    if(!sqlite3_stricmp(t.first.c_str(),name)) protected_table=true;
  if(action==SQLITE_ALTER_TABLE && protected_table) m->policy_altered=true;
  /* A renamed protected table must not be dropped under an intermediate
   * name and recreated with the original name, reusing old row epochs. */
  return action==SQLITE_DROP_TABLE && (protected_table || m->policy_altered);
}
int managed_policy_initialize(murmur_managed *m) {
  return checked([&] {
    Access access(m);
    exec(m->db,"BEGIN IMMEDIATE;"
      "CREATE TABLE IF NOT EXISTS murmur_managed_actor(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_id BLOB NOT NULL CHECK(length(database_id)=16),node_id BLOB NOT NULL CHECK(length(node_id)=16));"
      "INSERT OR IGNORE INTO murmur_managed_actor VALUES(1,randomblob(16),randomblob(16));"
      "CREATE TABLE IF NOT EXISTS murmur_managed_policies(column_id BLOB PRIMARY KEY,policy INTEGER NOT NULL CHECK(policy BETWEEN 0 AND 6));"
      "CREATE TABLE IF NOT EXISTS murmur_managed_row_epochs(table_id BLOB,row_key BLOB,epoch BLOB NOT NULL CHECK(length(epoch)=16),alive INTEGER NOT NULL,PRIMARY KEY(table_id,row_key));"
      "CREATE TABLE IF NOT EXISTS murmur_managed_policy_state(column_id BLOB,row_key BLOB,epoch BLOB,baseline BLOB NOT NULL,causal BLOB NOT NULL,PRIMARY KEY(column_id,row_key,epoch));"
      "CREATE TABLE IF NOT EXISTS murmur_managed_policy_dirty(table_id BLOB,row_key BLOB,PRIMARY KEY(table_id,row_key));"
      "CREATE TABLE IF NOT EXISTS murmur_replica_rows(table_id BLOB,row_key BLOB,epoch BLOB,body BLOB NOT NULL,PRIMARY KEY(table_id,row_key,epoch));"
      "CREATE TABLE IF NOT EXISTS murmur_replica_current(table_id BLOB,row_key BLOB,body BLOB NOT NULL,PRIMARY KEY(table_id,row_key));"
      "CREATE TABLE IF NOT EXISTS murmur_replication_history(table_id BLOB PRIMARY KEY); COMMIT;");
    managed_check(sqlite3_create_function_v2(m->db,"murmur_policy_key",-1,SQLITE_UTF8|SQLITE_DETERMINISTIC|SQLITE_INNOCUOUS,nullptr,key_function,nullptr,nullptr,nullptr));
    for(auto &f:functions) {
      auto *data=new SqlOperation{m,f.op};
      managed_check(sqlite3_create_function_v2(m->db,f.name,f.argc,SQLITE_UTF8|SQLITE_DIRECTONLY,data,sql_operation,nullptr,nullptr,
        [](void *p) { delete (SqlOperation *)p; }));
    }
    exec(m->db,"BEGIN IMMEDIATE");
    int rc=checked([&] { managed_check(managed_policy_sync(m,true)); exec(m->db,"COMMIT"); });
    if(rc) { sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr); throw ManagedError{rc}; }
  });
}
int managed_policy_sync(murmur_managed *m,bool rebuild) {
  return checked([&] {
    Access access(m);
    if(!rebuild && m->policies) {
      Statement st(m->db,"SELECT generation FROM murmur_managed_generation WHERE singleton=1");
      if(st.row() && sqlite3_column_int64(st.p,0)==m->policies->generation) return;
    }
    auto candidate=load(m);
    if(rebuild) install(m,*candidate);
    m->policies=std::move(candidate);
  });
}
extern "C" int murmur_managed_set_policy(murmur_managed_t *m,const char *table,const char *column,murmur_merge_policy_t policy) {
  if(!m || !table || !column || policy<0 || policy>6) return SQLITE_MISUSE;
  return checked([&] {
    Grant grant(m); Access access(m);
    managed_check(managed_origin_sync(m));
    managed_check(managed_schema_require_authority(m,table));
    managed_check(managed_policy_sync(m));
    auto before=m->policies;
    exec(m->db,"BEGIN IMMEDIATE");
    int rc=checked([&] {
      std::string id;
      {
        Statement st(m->db,"SELECT c.id FROM murmur_managed_columns c JOIN murmur_managed_tables t ON t.id=c.table_id WHERE t.name=?1 COLLATE NOCASE AND c.name=?2 COLLATE NOCASE");
        st.text(1,table); st.text(2,column);
        if(!st.row()) throw ManagedError{SQLITE_NOTFOUND};
        id=blob(st.p,0);
      }
      {
        Statement st(m->db,"SELECT policy FROM murmur_managed_policies WHERE column_id=?1"); st.blob(1,id);
        int old=st.row()?sqlite3_column_int(st.p,0):0;
        if(old && old!=policy) throw ManagedError{SQLITE_CONSTRAINT};
        if(!old && policy) {
          /* An existing CRR history cannot acquire new policy baselines
           * without a coordinated signed anchor, even when disabled. */
          Statement clock(m->db,"SELECT name FROM sqlite_schema WHERE type='table' AND name=?1"); clock.text(1,std::string(table)+"__crsql_clock");
          if(clock.row()) {
            Statement history(m->db,"SELECT 1 FROM "+quote(text(clock.p,0))+" LIMIT 1"); if(history.row()) throw ManagedError{SQLITE_CONSTRAINT};
          }
        }
        if(!old && policy && managed_origin_replicated(m,table)) {
          Statement rows(m->db,"SELECT 1 FROM "+quote(table)+" LIMIT 1"); if(rows.row()) throw ManagedError{SQLITE_CONSTRAINT};
          Statement history(m->db,"SELECT 1 FROM murmur_replica_current WHERE table_id=(SELECT id FROM murmur_managed_tables WHERE name=?1 COLLATE NOCASE) LIMIT 1"); history.text(1,table); if(history.row()) throw ManagedError{SQLITE_CONSTRAINT};
        }
      }
      {
        Statement st(m->db,"INSERT INTO murmur_managed_policies VALUES(?1,?2) ON CONFLICT(column_id) DO UPDATE SET policy=excluded.policy");
        st.blob(1,id); managed_check(sqlite3_bind_int(st.p,2,policy)); st.done();
      }
      exec(m->db,"UPDATE murmur_managed_generation SET generation=generation+1 WHERE singleton=1");
      managed_check(managed_policy_sync(m,true));
      managed_check(managed_schema_publish(m));
      exec(m->db,"COMMIT");
    });
    if(rc) { sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr); m->policies=std::move(before); throw ManagedError{rc}; }
    managed_check(nvStoreFlush(m->store_ref));
  });
}
namespace {
void operation(murmur_transaction *tx,const char *name,const std::vector<ManagedValue> &key,const char *col,const murmur_policy_operation_t &op) {
  auto *m=tx->owner; auto &table=table_for(m,name); auto &column=column_for(table,col);
  static const int required[]={MURMUR_POLICY_COUNTER,MURMUR_POLICY_SET,MURMUR_POLICY_SET,MURMUR_POLICY_MIN,MURMUR_POLICY_MAX,MURMUR_POLICY_JSON,MURMUR_POLICY_JSON,MURMUR_POLICY_LIST,MURMUR_POLICY_LIST};
  if(op.kind<0 || op.kind>8 || required[op.kind]!=column.policy || key.size()!=table.keys.size()) throw ManagedError{SQLITE_MISMATCH};
  if(tx->policy_operations>=10000) throw ManagedError{SQLITE_TOOBIG};
  if((op.kind==MURMUR_OP_JSON_SET || op.kind==MURMUR_OP_JSON_REMOVE) && (!op.path || !*op.path)) throw ManagedError{SQLITE_MISUSE};
  ManagedValue value;
  if(op.kind!=MURMUR_OP_COUNTER_ADD && op.kind!=MURMUR_OP_JSON_REMOVE) value=ManagedValue::from(op.value);
  if(op.kind==MURMUR_OP_JSON_SET || op.kind==MURMUR_OP_LIST_APPEND || op.kind==MURMUR_OP_LIST_REMOVE) managed_json_scalar(value);
  std::string predicate,keys;
  for(size_t i=0;i<key.size();++i) {
    if(key[i].type==MURMUR_NULL) throw ManagedError{SQLITE_MISMATCH};
    if(i) { predicate+=" AND "; keys+=','; }
    predicate+=quote(table.keys[i])+" IS ?"+std::to_string(i+1); keys+=quote(table.keys[i]);
  }
  ManagedValue current; std::vector<ManagedValue> actual_key;
  {
    Statement st(m->db,"SELECT "+quote(column.name)+","+keys+" FROM "+quote(table.name)+" WHERE "+predicate);
    for(size_t i=0;i<key.size();++i) managed_check(key[i].bind(st.p,i+1));
    if(!st.row()) throw ManagedError{SQLITE_NOTFOUND};
    current=ManagedValue::column(st.p,0);
    for(size_t i=0;i<key.size();++i) actual_key.push_back(ManagedValue::column(st.p,i+1));
    if(st.row()) throw ManagedError{SQLITE_CONSTRAINT};
  }
  auto row_key=managed_encode_values(actual_key); ManagedValue after;
  if(column.policy==MURMUR_POLICY_MIN || column.policy==MURMUR_POLICY_MAX) {
    int order=managed_compare(value,current);
    after=(column.policy==MURMUR_POLICY_MIN?order<0:order>0)?value:current;
  } else {
    std::string epoch;
    {
      Statement st(m->db,"SELECT epoch FROM murmur_managed_row_epochs WHERE table_id=x'"+table.id+"' AND row_key=?1 AND alive=1");
      st.blob(1,row_key); if(!st.row()) throw ManagedError{SQLITE_CORRUPT}; epoch=blob(st.p,0);
      if(epoch.size()!=16) throw ManagedError{SQLITE_CORRUPT};
    }
    ManagedPolicyState state=managed_policy_initial(m->db,column.policy,current,epoch);
    {
      Statement st(m->db,"SELECT baseline,causal FROM murmur_managed_policy_state WHERE column_id=x'"+column.id+"' AND row_key=?1 AND epoch=?2");
      st.blob(1,row_key); st.blob(2,epoch);
      if(st.row()) {
        state.baseline=managed_decode_value(blob(st.p,0)); auto bytes=blob(st.p,1);
        murmur_causal_t *raw=nullptr; managed_check(murmur_causal_decode(bytes.data(),bytes.size(),&raw)); state.causal.reset(raw);
        murmur_causal_kind_t kind;
        managed_check(murmur_causal_kind(raw,&kind));
        auto expected=column.policy==MURMUR_POLICY_COUNTER?MURMUR_CAUSAL_COUNTER:(column.policy==MURMUR_POLICY_SET?MURMUR_CAUSAL_SET:(column.policy==MURMUR_POLICY_JSON?MURMUR_CAUSAL_JSON:MURMUR_CAUSAL_LIST));
        if(kind!=expected) throw ManagedError{SQLITE_CORRUPT};
      }
    }
    if(column.policy==MURMUR_POLICY_COUNTER) {
      if(state.baseline.type!=MURMUR_INTEGER) throw ManagedError{SQLITE_CORRUPT};
      managed_check(murmur_causal_counter_add(state.causal.get(),m->policies->database.data(),m->policies->node.data(),op.delta));
    } else {
      murmur_causal_tag_t tag{}; memcpy(tag.database,m->policies->database.data(),16); memcpy(tag.node,m->policies->node.data(),16); sqlite3_randomness(16,tag.transaction);
      auto bytes=managed_encode_value(value);
      bool remove=op.kind==MURMUR_OP_SET_REMOVE || op.kind==MURMUR_OP_JSON_REMOVE || op.kind==MURMUR_OP_LIST_REMOVE;
      const char *path=column.policy==MURMUR_POLICY_JSON?op.path:"";
      managed_check(murmur_causal_apply(state.causal.get(),remove?MURMUR_CAUSAL_REMOVE:MURMUR_CAUSAL_ADD,path,strlen(path),bytes.data(),bytes.size(),&tag));
    }
    after=managed_policy_project(column.policy,state);
    auto encoded=managed_causal_bytes(state.causal.get()),baseline=managed_encode_value(state.baseline);
    Statement st(m->db,"INSERT INTO murmur_managed_policy_state VALUES(x'"+column.id+"',?1,?2,?3,?4) ON CONFLICT(column_id,row_key,epoch) DO UPDATE SET causal=excluded.causal");
    st.blob(1,row_key); st.blob(2,epoch); st.blob(3,baseline); st.blob(4,encoded); st.done();
  }
  Statement update(m->db,"UPDATE "+quote(table.name)+" SET "+quote(column.name)+"=?"+std::to_string(key.size()+1)+" WHERE "+predicate);
  for(size_t i=0;i<key.size();++i) managed_check(key[i].bind(update.p,i+1));
  managed_check(after.bind(update.p,key.size()+1)); update.done();
  ++tx->policy_operations;
}
void sql_operation(sqlite3_context *ctx,int argc,sqlite3_value **argv) {
  auto *data=(SqlOperation *)sqlite3_user_data(ctx); auto *tx=data->m->active_transaction;
  int rc=checked([&] {
    if(!tx) throw ManagedError{SQLITE_MISUSE};
    auto table=ManagedValue::argument(argv[0]),key=ManagedValue::argument(argv[1]),column=ManagedValue::argument(argv[2]);
    if(table.type!=MURMUR_TEXT || column.type!=MURMUR_TEXT || table.data.find('\0')!=std::string::npos || column.data.find('\0')!=std::string::npos) throw ManagedError{SQLITE_MISUSE};
    std::vector<ManagedValue> keys;
    Access access(data->m);
    if(key.type==MURMUR_BLOB) keys=managed_decode_values(key.data);
    else { for(auto &v:managed_json_parse(data->m->db,key,false)) keys.push_back(v.second); }
    murmur_policy_operation_t op{}; op.kind=data->kind;
    ManagedValue value; std::string path;
    if(op.kind==MURMUR_OP_COUNTER_ADD) {
      if(sqlite3_value_type(argv[3])!=SQLITE_INTEGER) throw ManagedError{SQLITE_MISMATCH};
      op.delta=sqlite3_value_int64(argv[3]);
    } else if(op.kind==MURMUR_OP_JSON_SET || op.kind==MURMUR_OP_JSON_REMOVE) {
      auto p=ManagedValue::argument(argv[3]);
      if(p.type!=MURMUR_TEXT || p.data.find('\0')!=std::string::npos) throw ManagedError{SQLITE_MISUSE};
      path=p.data; op.path=path.c_str(); if(argc==5) value=ManagedValue::argument(argv[4]);
    } else value=ManagedValue::argument(argv[3]);
    op.value={value.type,value.integer,value.real,value.data.data(),value.data.size()};
    std::vector<murmur_value_t> args;
    for(auto &v:keys) args.push_back({v.type,v.integer,v.real,v.data.data(),v.data.size()});
    managed_check(murmur_transaction_policy(tx,table.data.c_str(),args.data(),args.size(),column.data.c_str(),&op));
    sqlite3_result_int(ctx,1);
  });
  if(rc) sqlite3_result_error_code(ctx,rc);
}
}
extern "C" int murmur_transaction_policy(murmur_transaction_t *tx,const char *table,const murmur_value_t *key,size_t n,const char *column,const murmur_policy_operation_t *op) {
  if(!tx || !table || !column || !op || (n && !key) || n>32766 || tx->thread!=std::this_thread::get_id() || tx->owner->active_transaction!=tx) return SQLITE_MISUSE;
  return checked([&] {
    Access access(tx->owner); std::vector<ManagedValue> keys;
    for(size_t i=0;i<n;++i) keys.push_back(ManagedValue::from(key[i]));
    exec(tx->owner->db,"SAVEPOINT murmur_policy_operation");
    int rc=checked([&] { operation(tx,table,keys,column,*op); exec(tx->owner->db,"RELEASE murmur_policy_operation"); });
    if(rc) { sqlite3_exec(tx->owner->db,"ROLLBACK TO murmur_policy_operation; RELEASE murmur_policy_operation",nullptr,nullptr,nullptr); throw ManagedError{rc}; }
  });
}
extern "C" int murmur_managed_policy_status(murmur_managed_t *m,murmur_row_fn fn,void *ctx) {
  if(!m || !fn) return SQLITE_MISUSE;
  return checked([&] {
    Grant grant(m); Access access(m); managed_check(managed_policy_sync(m));
    Statement st(m->db,"SELECT t.name,c.name,p.policy FROM murmur_managed_policies p JOIN murmur_managed_columns c ON c.id=p.column_id JOIN murmur_managed_tables t ON t.id=c.table_id ORDER BY t.name,c.name");
    while(st.row()) {
      auto table=text(st.p,0),column=text(st.p,1);
      murmur_value_t values[3]{};
      values[0]={MURMUR_TEXT,0,0,table.data(),table.size()}; values[1]={MURMUR_TEXT,0,0,column.data(),column.size()};
      values[2].type=MURMUR_INTEGER; values[2].integer=sqlite3_column_int(st.p,2);
      if(fn(ctx,3,values)) throw ManagedError{SQLITE_ABORT};
    }
  });
}
