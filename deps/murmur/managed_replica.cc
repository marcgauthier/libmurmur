#include "managed_replica.h"
#include "managed_schema_internal.h"
#include "managed_policy_state.h"
#include "managed_codec.h"
#include <algorithm>
#include <cstring>
#include <set>

namespace {
struct Statement {
  sqlite3_stmt *p=nullptr;
  Statement(sqlite3 *db,const std::string &sql) { managed_check(sqlite3_prepare_v2(db,sql.c_str(),-1,&p,nullptr)); }
  ~Statement() { sqlite3_finalize(p); }
  void blob(int n,const std::string &s) { managed_check(sqlite3_bind_blob64(p,n,s.data(),s.size(),SQLITE_TRANSIENT)); }
  void text(int n,const std::string &s) { managed_check(sqlite3_bind_text64(p,n,s.data(),s.size(),SQLITE_TRANSIENT,SQLITE_UTF8)); }
  bool row() { int rc=sqlite3_step(p); if(rc==SQLITE_ROW) return true; if(rc!=SQLITE_DONE) throw ManagedError{rc}; return false; }
  void done() { if(row()) throw ManagedError{SQLITE_ERROR}; }
};
std::string bytes(sqlite3_stmt *st,int n,murmur_value_type_t type) {
  auto v=ManagedValue::column(st,n); if(v.type!=type) throw ManagedError{SQLITE_CORRUPT}; return v.data;
}
std::string quote(const std::string &s) {
  char *raw=sqlite3_mprintf("\"%w\"",s.c_str()); if(!raw) throw ManagedError{SQLITE_NOMEM};
  std::unique_ptr<char,decltype(&sqlite3_free)> p(raw,sqlite3_free); return raw;
}
void exec(murmur_managed *m,const std::string &sql) { managed_check(sqlite3_exec(m->db,sql.c_str(),nullptr,nullptr,nullptr)); }
bool causal(int policy) { return policy==1 || policy==2 || policy==5 || policy==6; }
bool policy_table(const ManagedSchemaTable &t) { for(auto &c:t.columns) if(c.policy) return true; return false; }
struct Table {
  ManagedSchemaTable schema;
  std::vector<std::string> keys;
  std::set<std::string> key_ids;
};
Table table_view(murmur_managed *m,const ManagedSchemaTable &schema) {
  Table out; out.schema=schema;
  Statement st(m->db,"SELECT name FROM pragma_table_info(?1) WHERE pk>0 ORDER BY pk"); st.text(1,schema.name);
  while(st.row()) {
    auto name=bytes(st.p,0,MURMUR_TEXT); out.keys.push_back(name);
    for(auto &c:schema.columns) if(c.name==name) out.key_ids.insert(c.id);
  }
  if(out.keys.empty() || out.keys.size()!=out.key_ids.size()) throw ManagedError{SQLITE_SCHEMA};
  return out;
}
std::string predicate(const Table &table) {
  std::string out; for(size_t i=0;i<table.keys.size();++i) {
    if(i) out+=" AND ";
    out+=quote(table.keys[i])+" IS ?"+std::to_string(i+1);
  } return out;
}
void bind_key(Statement &st,const Table &table,const std::string &key) {
  auto values=managed_decode_values(key); if(values.size()!=table.keys.size()) throw ManagedError{SQLITE_SCHEMA};
  for(size_t i=0;i<values.size();++i) managed_check(values[i].bind(st.p,i+1));
}
bool load(murmur_managed *m,const std::string &table,const std::string &key,const std::string *epoch,ManagedRow &out) {
  Statement st(m->db,epoch?"SELECT body FROM murmur_replica_rows WHERE table_id=?1 AND row_key=?2 AND epoch=?3":"SELECT body FROM murmur_replica_current WHERE table_id=?1 AND row_key=?2");
  st.blob(1,table); st.blob(2,key); if(epoch) st.blob(3,*epoch);
  if(!st.row()) return false;
  out=managed_row_decode(bytes(st.p,0,MURMUR_BLOB)); return true;
}
void save(murmur_managed *m,const ManagedRow &r,bool current) {
  auto body=managed_row_encode(r);
  Statement st(m->db,current?"INSERT INTO murmur_replica_current VALUES(?1,?2,?3) ON CONFLICT(table_id,row_key) DO UPDATE SET body=excluded.body":"INSERT INTO murmur_replica_rows VALUES(?1,?2,?3,?4) ON CONFLICT(table_id,row_key,epoch) DO UPDATE SET body=excluded.body");
  st.blob(1,r.table); st.blob(2,r.key); if(current) st.blob(3,body); else { st.blob(3,r.epoch); st.blob(4,body); } st.done();
  Statement history(m->db,"INSERT OR IGNORE INTO murmur_replication_history VALUES(?1)"); history.blob(1,r.table); history.done();
}
ManagedVersion version(const murmur_origin_envelope_t &e) {
  ManagedVersion v; v.millis=e.millis; v.logical=e.logical; memcpy(v.origin.data(),e.origin,16); return v;
}
void save_policy(murmur_managed *m,const ManagedRow &r) {
  for(auto &entry:r.columns) if(causal(entry.second.policy)) {
    Statement st(m->db,"INSERT INTO murmur_managed_policy_state VALUES(?1,?2,?3,?4,?5) ON CONFLICT(column_id,row_key,epoch) DO UPDATE SET baseline=excluded.baseline,causal=excluded.causal");
    st.blob(1,entry.first); st.blob(2,r.key); st.blob(3,r.epoch); st.blob(4,entry.second.baseline); st.blob(5,entry.second.causal); st.done();
  }
}
void materialize(murmur_managed *m,const Table &table,const ManagedRow &r) {
  /* Policy rows use managed versions for every field. CRR cells remain a
   * local capture implementation detail and are never merged as projections. */
  struct SyncBit {
    murmur_managed *m;
    SyncBit(murmur_managed *m):m(m) { exec(m,"SELECT crsql_internal_sync_bit(1)"); }
    ~SyncBit() { sqlite3_exec(m->db,"SELECT crsql_internal_sync_bit(0)",nullptr,nullptr,nullptr); }
  } sync(m);
  if(!r.alive()) {
    Statement st(m->db,"DELETE FROM "+quote(table.schema.name)+" WHERE "+predicate(table)); bind_key(st,table,r.key); st.done();
  } else {
    auto values=managed_decode_values(r.key); std::string names,params,updates,conflict;
    for(size_t i=0;i<table.keys.size();++i) {
      if(i) { names+=','; params+=','; conflict+=','; }
      names+=quote(table.keys[i]); params+='?'+std::to_string(i+1); conflict+=quote(table.keys[i]);
    }
    for(auto &c:table.schema.columns) if(!table.key_ids.count(c.id)) {
      auto found=r.columns.find(c.id); if(found==r.columns.end()) continue;
      names+=','+quote(c.name); params+=",?"+std::to_string(values.size()+1);
      if(!updates.empty()) updates+=',';
      updates+=quote(c.name)+"=excluded."+quote(c.name); values.push_back(managed_row_project(found->second));
    }
    Statement st(m->db,"INSERT INTO "+quote(table.schema.name)+"("+names+") VALUES("+params+") ON CONFLICT("+conflict+") DO "+(updates.empty()?"NOTHING":"UPDATE SET "+updates));
    for(size_t i=0;i<values.size();++i) managed_check(values[i].bind(st.p,i+1));
    st.done();
  }
  Statement epoch(m->db,"INSERT INTO murmur_managed_row_epochs VALUES(?1,?2,?3,?4) ON CONFLICT(table_id,row_key) DO UPDATE SET epoch=excluded.epoch,alive=excluded.alive");
  epoch.blob(1,r.table); epoch.blob(2,r.key); epoch.blob(3,r.epoch); managed_check(sqlite3_bind_int(epoch.p,4,r.alive())); epoch.done(); save_policy(m,r);
}
ManagedSchema source_schema(murmur_managed *m,const uint8_t digest[32]) {
  auto active=managed_schema_digest(m);
  if(!memcmp(active.data(),digest,32)) return managed_schema_capture(m);
  Statement st(m->db,"SELECT a.payload FROM murmur_schema_artifacts a JOIN murmur_schema_control c ON c.master=a.master WHERE a.digest=?1 ORDER BY a.sequence DESC LIMIT 1"); st.blob(1,std::string((const char *)digest,32));
  if(!st.row()) throw ManagedError{SQLITE_SCHEMA};
  return managed_schema_decode(bytes(st.p,0,MURMUR_BLOB));
}
void validate_columns(const ManagedRow &r,const ManagedSchemaTable &table) {
  for(auto &entry:r.columns) {
    auto col=std::find_if(table.columns.begin(),table.columns.end(),[&](auto &c){return c.id==entry.first;});
    if(col==table.columns.end() || col->policy!=(unsigned)entry.second.policy) throw ManagedError{SQLITE_SCHEMA};
  }
}
}
bool managed_replica_dirty(murmur_managed *m) {
  Statement st(m->db,"SELECT 1 FROM murmur_managed_policy_dirty d JOIN murmur_managed_replication r ON r.table_id=d.table_id AND r.enabled=1 LIMIT 1"); return st.row();
}
void managed_replica_clear_dirty(murmur_managed *m) { exec(m,"DELETE FROM murmur_managed_policy_dirty"); }
std::string managed_replica_capture(murmur_managed *m,const murmur_origin_envelope_t &e,const std::string &cells) {
  auto schema=managed_schema_capture(m); std::map<std::string,Table> tables;
  for(auto &t:schema.tables) if(policy_table(t)) tables.emplace(t.id,table_view(m,t));
  std::vector<ManagedRow> rows;
  Statement dirty(m->db,"SELECT table_id,row_key FROM murmur_managed_policy_dirty ORDER BY table_id,row_key");
  while(dirty.row()) {
    auto tid=bytes(dirty.p,0,MURMUR_BLOB),key=bytes(dirty.p,1,MURMUR_BLOB); auto found=tables.find(tid); if(found==tables.end()) continue;
    auto &table=found->second; std::string epoch; bool alive=false;
    { Statement st(m->db,"SELECT epoch,alive FROM murmur_managed_row_epochs WHERE table_id=?1 AND row_key=?2"); st.blob(1,tid); st.blob(2,key); if(!st.row()) throw ManagedError{SQLITE_CORRUPT}; epoch=bytes(st.p,0,MURMUR_BLOB); alive=sqlite3_column_int(st.p,1)!=0; }
    ManagedRow row,previous; bool existing=load(m,tid,key,&epoch,row),have_previous=load(m,tid,key,nullptr,previous);
    if(!existing) { row.table=tid; row.key=key; row.epoch=epoch; row.generation=version(e); }
    if(have_previous && previous.tombstone.compare(row.tombstone)>0) row.tombstone=previous.tombstone;
    bool normalize=false;
    if(!alive) row.tombstone=version(e);
    else {
      std::string names; for(auto &c:table.schema.columns) { if(!names.empty()) names+=','; names+=quote(c.name); }
      Statement values(m->db,"SELECT "+names+" FROM "+quote(table.schema.name)+" WHERE "+predicate(table)); bind_key(values,table,key);
      if(!values.row()) throw ManagedError{SQLITE_CORRUPT};
      for(size_t i=0;i<table.schema.columns.size();++i) {
        auto &c=table.schema.columns[i]; if(table.key_ids.count(c.id)) continue;
        ManagedRowColumn col; col.policy=c.policy; auto value=ManagedValue::column(values.p,i);
        if(causal(c.policy)) {
          Statement st(m->db,"SELECT baseline,causal FROM murmur_managed_policy_state WHERE column_id=?1 AND row_key=?2 AND epoch=?3"); st.blob(1,c.id); st.blob(2,key); st.blob(3,epoch);
          if(st.row()) { col.baseline=bytes(st.p,0,MURMUR_BLOB); col.causal=bytes(st.p,1,MURMUR_BLOB); }
          else { auto state=managed_policy_initial(m->db,c.policy,value,epoch); col.baseline=managed_encode_value(value); col.causal=managed_causal_bytes(state.causal.get()); }
          /* Keep the originating SQL row identical to a remote projection.
           * The immutable baseline may be NULL or noncanonical JSON, but
           * the visible value must be the causal state's canonical form. */
          normalize=normalize || managed_encode_value(managed_row_project(col))!=managed_encode_value(value);
        } else {
          col.value=value;
          if(!c.policy) {
            auto old=row.columns.find(c.id);
            col.version=old!=row.columns.end() && managed_encode_value(old->second.value)==managed_encode_value(value)?old->second.version:version(e);
          }
        }
        row.columns[c.id]=std::move(col);
      }
    }
    save(m,row,false); save(m,row,true);
    if(normalize) materialize(m,table,row); else save_policy(m,row);
    rows.push_back(std::move(row));
    if(rows.size()>10000) throw ManagedError{SQLITE_TOOBIG};
  }
  managed_replica_clear_dirty(m);
  if(rows.empty()) return cells;
  ManagedEncoder out; out.raw("MMT2",4); out.blob(cells.empty()?std::string("CRSB\1\0\0\0\0\0\0\0",12):cells); out.number(rows.size());
  for(auto &r:rows) out.blob(managed_row_encode(r));
  return out.bytes;
}
ManagedReplicaBatch managed_replica_decode(const murmur_origin_record_t &r) {
  ManagedReplicaBatch out;
  if(r.bytes<4 || memcmp(r.payload,"MMT2",4)) { out.cells=std::string((const char *)r.payload,r.bytes); return out; }
  ManagedDecoder d(r.payload,r.bytes); d.raw(4); out.cells=d.blob(); std::pair<std::string,std::string> previous; bool first=true;
  for(size_t n=d.count(10000);n;--n) {
    auto row=managed_row_decode(d.blob()); auto key=std::make_pair(row.table,row.key);
    if(!first && key<=previous) throw ManagedError{SQLITE_CORRUPT};
    first=false; previous=std::move(key); out.rows.push_back(std::move(row));
  }
  d.end(); if(out.rows.empty()) throw ManagedError{SQLITE_CORRUPT};
  ManagedEncoder canonical; canonical.raw("MMT2",4); canonical.blob(out.cells); canonical.number(out.rows.size());
  for(auto &row:out.rows) canonical.blob(managed_row_encode(row));
  if(canonical.bytes!=std::string((const char *)r.payload,r.bytes)) throw ManagedError{SQLITE_CORRUPT};
  return out;
}
void managed_replica_apply(murmur_managed *m,const murmur_origin_envelope_t &e,const ManagedReplicaBatch &batch) {
  auto source=source_schema(m,e.schema),current=managed_schema_capture(m); auto bound=version(e);
  std::map<std::string,const ManagedSchemaTable *> old,live,names;
  std::map<std::string,Table> views;
  for(auto &t:source.tables) { old[t.id]=&t; names[t.name]=&t; }
  for(auto &t:current.tables) live[t.id]=&t;
  /* Raw cells must never set policy projections, even in an older CRSB frame. */
  if(batch.cells.size()<12) throw ManagedError{SQLITE_CORRUPT};
  uint32_t n=0; for(unsigned i=0;i<4;++i) n|=(uint32_t)(uint8_t)batch.cells[8+i]<<(8*i);
  if(n>(1u<<20) || n>(batch.cells.size()-12)/49) throw ManagedError{SQLITE_CORRUPT};
  std::vector<murmur_cell_t> cells(n); size_t count=0;
  if(murmur_cells_decode((const uint8_t *)batch.cells.data(),batch.cells.size(),cells.data(),cells.size(),&count)!=MURMUR_OK) throw ManagedError{SQLITE_CORRUPT};
  for(auto &cell:cells) {
    auto declared=names.find(std::string((const char *)cell.table,cell.table_len));
    if(declared==names.end()) throw ManagedError{SQLITE_AUTH};
    auto active=live.find(declared->second->id);
    if(policy_table(*declared->second) || (active!=live.end() && policy_table(*active->second))) throw ManagedError{SQLITE_AUTH};
    Statement history(m->db,"INSERT OR IGNORE INTO murmur_replication_history VALUES(?1)"); history.blob(1,declared->second->id); history.done();
  }
  for(auto &incoming:batch.rows) {
    auto declared=old.find(incoming.table); if(declared==old.end() || !policy_table(*declared->second)) throw ManagedError{SQLITE_SCHEMA};
    validate_columns(incoming,*declared->second);
    if(incoming.generation.compare(bound)>0 || incoming.tombstone.compare(bound)>0) throw ManagedError{SQLITE_AUTH};
    for(auto &c:incoming.columns) if(!c.second.policy && c.second.version.compare(bound)>0) throw ManagedError{SQLITE_AUTH};
    ManagedRow known,prior; bool have=load(m,incoming.table,incoming.key,&incoming.epoch,known);
    bool present=load(m,incoming.table,incoming.key,nullptr,prior);
    auto trusted=known; bool covered=have;
    if(!covered && !memcmp(incoming.generation.origin.data(),e.origin,16)) {
      trusted.table=incoming.table; trusted.key=incoming.key; trusted.epoch=incoming.epoch; trusted.generation=incoming.generation; covered=true;
    }
    if(covered && present && prior.tombstone.compare(trusted.tombstone)>0) trusted.tombstone=prior.tombstone;
    managed_row_authorize(m->db,covered?&trusted:nullptr,incoming,e.database,e.origin);
    auto generation=have?managed_row_join(known,incoming):incoming;
    save(m,generation,false);
    auto enabled=live.find(incoming.table); if(enabled==live.end()) continue;
    auto view=views.find(incoming.table); if(view==views.end()) view=views.emplace(incoming.table,table_view(m,*enabled->second)).first;
    auto &table=view->second; validate_columns(generation,table.schema);
    for(auto &key:table.key_ids) if(generation.columns.count(key)) throw ManagedError{SQLITE_SCHEMA};
    if(incoming.alive()) for(auto &col:declared->second->columns)
      if(!table.key_ids.count(col.id) && !incoming.columns.count(col.id)) throw ManagedError{SQLITE_CORRUPT};
    auto joined=present?managed_row_join(prior,generation):generation;
    save(m,joined,true); save(m,joined,false); materialize(m,table,joined);
  }
}
