#include "managed_schema.h"
#include "managed_schema_internal.h"
#include "managed_codec.h"
#include "schema.h"
#include "sha256.h"
#include "open.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <map>
#include <set>

namespace {
struct Access {
  murmur_managed *m; int old;
  Access(murmur_managed *m,int mode=3):m(m),old(m->access) { m->access=mode; }
  ~Access() { m->access=old; }
};
struct Grant {
  murmur_scheduler_t *s;
  Grant(murmur_managed *m,murmur_writer_class_t cls=MURMUR_WRITER_MAINTENANCE):s(m->coordinator->scheduler) { managed_check(murmur_scheduler_acquire(s,cls,-1,nullptr,nullptr)); }
  ~Grant() { murmur_scheduler_release(s); }
};
struct Statement {
  sqlite3_stmt *p=nullptr;
  Statement(sqlite3 *db,const std::string &sql) { managed_check(sqlite3_prepare_v2(db,sql.c_str(),-1,&p,nullptr)); }
  ~Statement() { sqlite3_finalize(p); }
  void blob(int n,const std::string &s) { managed_check(sqlite3_bind_blob64(p,n,s.data(),s.size(),SQLITE_TRANSIENT)); }
  void text(int n,const std::string &s) { managed_check(sqlite3_bind_text64(p,n,s.data(),s.size(),SQLITE_TRANSIENT,SQLITE_UTF8)); }
  void integer(int n,uint64_t v) { if(v>INT64_MAX) throw ManagedError{SQLITE_TOOBIG}; managed_check(sqlite3_bind_int64(p,n,v)); }
  bool row() { int rc=sqlite3_step(p); if(rc==SQLITE_ROW) return true; if(rc!=SQLITE_DONE) throw ManagedError{rc}; return false; }
  void done() { if(row()) throw ManagedError{SQLITE_ERROR}; }
};
template<class Fn> int checked(Fn fn) { try { fn(); return SQLITE_OK; } catch(const ManagedError &e) { return e.code; } catch(...) { return SQLITE_NOMEM; } }
void exec(murmur_managed *m,const std::string &sql) { managed_check(sqlite3_exec(m->db,sql.c_str(),nullptr,nullptr,nullptr)); }
std::string value(sqlite3_stmt *st,int n,murmur_value_type_t type) { auto v=ManagedValue::column(st,n); if(v.type!=type) throw ManagedError{SQLITE_CORRUPT}; return v.data; }
std::string text(sqlite3_stmt *st,int n) { return value(st,n,MURMUR_TEXT); }
std::string blob(sqlite3_stmt *st,int n) { return value(st,n,MURMUR_BLOB); }
std::string quote(const std::string &s) { char *p=sqlite3_mprintf("\"%w\"",s.c_str()); if(!p) throw ManagedError{SQLITE_NOMEM}; std::unique_ptr<char,decltype(&sqlite3_free)> owned(p,sqlite3_free); return p; }
std::string trim(const std::string &s) {
  size_t a=0,b=s.size(); while(a<b && std::isspace((unsigned char)s[a])) ++a; while(b>a && std::isspace((unsigned char)s[b-1])) --b; return s.substr(a,b-a);
}
/* SQLite's rename-quotefix makes equivalent DDL depend on rename order.
 * Canonicalize only syntactic table/column identifiers, never expressions
 * or string literals. Actual SQLite constraints/default text is retained. */
std::string canonical_ddl(const std::string &sql,const std::string &table,const std::vector<std::string> &columns) {
  auto skip=[&](size_t &i) {
    if(sql[i]=='\'' || sql[i]=='"' || sql[i]=='`' || sql[i]=='[') {
      char end=sql[i]=='['?']':sql[i]; ++i;
      while(i<sql.size()) { if(sql[i++]==end) { if(i<sql.size() && sql[i]==end) ++i; else return; } }
    } else if(sql[i]=='-' && i+1<sql.size() && sql[i+1]=='-') { i+=2; while(i<sql.size() && sql[i]!='\n') ++i; }
    else if(sql[i]=='/' && i+1<sql.size() && sql[i+1]=='*') { i+=2; while(i+1<sql.size() && !(sql[i]=='*'&&sql[i+1]=='/')) ++i; i=std::min(sql.size(),i+2); }
    else ++i;
  };
  size_t open=0; while(open<sql.size() && sql[open]!='(') skip(open);
  if(open==sql.size()) throw ManagedError{SQLITE_SCHEMA};
  std::vector<std::string> segments; size_t start=open+1,i=start; int depth=1;
  for(;i<sql.size() && depth;) {
    if(sql[i]=='(') { ++depth; ++i; }
    else if(sql[i]==')') { if(!--depth) { segments.push_back(sql.substr(start,i-start)); ++i; break; } ++i; }
    else if(sql[i]==',' && depth==1) { segments.push_back(sql.substr(start,i-start)); start=++i; }
    else skip(i);
  }
  if(depth) throw ManagedError{SQLITE_SCHEMA};
  std::string out="CREATE TABLE "+quote(table)+"("; bool first=true;
  for(auto segment:segments) {
    segment=trim(segment); size_t end=0; std::string name; bool quoted=false;
    while(segment.size()>1 && (segment.compare(0,2,"/*")==0 || segment.compare(0,2,"--")==0)) {
      size_t after=segment[0]=='/'?segment.find("*/",2):segment.find('\n',2);
      if(after==std::string::npos) throw ManagedError{SQLITE_SCHEMA};
      segment=trim(segment.substr(after+(segment[0]=='/'?2:1)));
    }
    if(!segment.empty() && (segment[0]=='"'||segment[0]=='`'||segment[0]=='[')) {
      quoted=true; char close=segment[0]=='['?']':segment[0]; end=1;
      while(end<segment.size()) { char c=segment[end++]; if(c==close) { if(end<segment.size() && segment[end]==close) { name+=c; ++end; } else break; } else name+=c; }
    } else {
      while(end<segment.size() && !std::isspace((unsigned char)segment[end]) && segment[end]!='(') ++end;
      name=segment.substr(0,end);
    }
    bool constraint=false;
    if(!quoted) for(auto *keyword:{"PRIMARY","UNIQUE","CHECK","FOREIGN","CONSTRAINT"}) if(!sqlite3_stricmp(name.c_str(),keyword)) constraint=true;
    if(!constraint && std::find(columns.begin(),columns.end(),name)!=columns.end()) {
      auto rest=trim(segment.substr(end)); segment=quote(name)+(rest.empty()?"":" "+rest);
    }
    if(!first) out+=',';
    first=false; out+=segment;
  }
  auto suffix=trim(sql.substr(i)); return out+")"+(suffix.empty()?"":" "+suffix);
}
std::string hash(const std::string &bytes) { std::string out(32,'\0'); murmur_sha256((const uint8_t *)bytes.data(),bytes.size(),(uint8_t *)out.data()); return out; }
std::string master(murmur_managed *m) { Statement st(m->db,"SELECT master FROM murmur_schema_control WHERE singleton=1"); if(!st.row()) return {}; return blob(st.p,0); }
std::string local_origin(murmur_managed *m) { murmur_origin_identity_t id{}; managed_check(managed_origin_identity_internal(m,&id)); return std::string((const char *)id.origin,16); }
bool exists(murmur_managed *m,const std::string &name,const char *type="table") {
  Statement st(m->db,"SELECT 1 FROM sqlite_schema WHERE name=?1 AND type=?2"); st.text(1,name); st.text(2,type); return st.row();
}
bool reserved(const std::string &name) {
  return !sqlite3_strnicmp(name.c_str(),"sqlite_",7) || !sqlite3_strnicmp(name.c_str(),"murmur_",7) ||
    !sqlite3_strnicmp(name.c_str(),"crsql_",6) || name.find("__crsql")!=std::string::npos;
}
void execute_ddl(murmur_managed *m,const std::string &sql,int action,const std::string &name,const std::string &table) {
  struct Restore { murmur_managed *m; ~Restore() { m->ddl_action=0; m->ddl_name.clear(); m->ddl_table.clear(); } } restore{m};
  Access access(m,5); m->ddl_action=action; m->ddl_name=name; m->ddl_table=table;
  sqlite3_stmt *raw=nullptr; const char *tail=nullptr;
  managed_check(sqlite3_prepare_v2(m->db,sql.c_str(),-1,&raw,&tail));
  std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)> st(raw,sqlite3_finalize);
  if(!raw) throw ManagedError{SQLITE_SCHEMA};
  sqlite3_stmt *extra=nullptr; int rc=sqlite3_prepare_v2(m->db,tail,-1,&extra,nullptr);
  bool more=extra!=nullptr; sqlite3_finalize(extra); if(rc || more) throw ManagedError{SQLITE_SCHEMA};
  if(sqlite3_step(raw)!=SQLITE_DONE) throw ManagedError{sqlite3_errcode(m->db)};
}
bool is_crr(murmur_managed *m,const std::string &name) {
  int yes=0,sqlrc=0; auto status=murmur_schema_is_crr(m->db,(const uint8_t *)name.data(),name.size(),&yes,&sqlrc);
  if(status!=MURMUR_SYNC_OK) throw ManagedError{sqlrc?sqlrc:SQLITE_ERROR};
  return yes;
}
void lifecycle(murmur_managed *m,const char *function,const std::string &table) {
  Statement st(m->db,std::string("SELECT ")+function+"(?1)"); st.text(1,table); while(st.row()) {}
}
void rename_table(murmur_managed *m,const std::string &old,const std::string &name) {
  exec(m,"ALTER TABLE "+quote(old)+" RENAME TO "+quote(name));
  for(auto suffix:{"__crsql_clock","__crsql_pks"}) if(exists(m,old+suffix)) exec(m,"ALTER TABLE "+quote(old+suffix)+" RENAME TO "+quote(name+suffix));
}
void rename_clock_column(murmur_managed *m,const std::string &table,const std::string &old,const std::string &name) {
  if(!is_crr(m,table)) return;
  Statement clock(m->db,"UPDATE "+quote(table+"__crsql_clock")+" SET col_name=?1 WHERE col_name=?2"); clock.text(1,name); clock.text(2,old); clock.done();
  Statement pk(m->db,"SELECT 1 FROM pragma_table_info(?1) WHERE name=?2"); pk.text(1,table+"__crsql_pks"); pk.text(2,old);
  if(pk.row()) exec(m,"ALTER TABLE "+quote(table+"__crsql_pks")+" RENAME COLUMN "+quote(old)+" TO "+quote(name));
}
std::string pairs(const std::string &name,const std::string &ddl) {
  murmur_schema_pair_t pair{}; pair.table=(const uint8_t *)name.data(); pair.table_len=name.size(); pair.ddl=(const uint8_t *)ddl.data(); pair.ddl_len=ddl.size();
  std::string out(name.size()+ddl.size()+32,'\0'); auto n=murmur_schema_pairs_encode(&pair,1,(uint8_t *)out.data(),out.size());
  if(!n) throw ManagedError{SQLITE_TOOBIG};
  out.resize(n); return out;
}
void compare_additive(murmur_managed *m,const ManagedSchemaTable &remote) {
  std::string current;
  { Statement st(m->db,"SELECT sql FROM sqlite_schema WHERE name=?1 AND type='table'"); st.text(1,remote.name); if(!st.row()) throw ManagedError{SQLITE_SCHEMA}; current=text(st.p,0); }
  std::vector<std::string> names;
  { Statement st(m->db,"SELECT name FROM pragma_table_info(?1)"); st.text(1,remote.name); while(st.row()) names.push_back(text(st.p,0)); }
  current=canonical_ddl(current,remote.name,names);
  if(current==remote.ddl) return;
  auto local=pairs(remote.name,current),peer=pairs(remote.name,remote.ddl); murmur_schema_diff_t diff{}; int sqlrc=0;
  auto status=murmur_schema_diff((const uint8_t *)local.data(),local.size(),(const uint8_t *)peer.data(),peer.size(),&diff,&sqlrc);
  struct Free { murmur_schema_diff_t *d; ~Free() { murmur_schema_diff_free(d); } } owned{&diff};
  if(status!=MURMUR_SYNC_OK || !diff.additive || diff.n_tables) throw ManagedError{sqlrc?sqlrc:SQLITE_SCHEMA};
  for(size_t i=0;i<diff.n_columns;++i) {
    char *column=nullptr; int checked_rc=0;
    /* The legacy validator screens the first unquoted word and supports a
     * narrower identifier grammar. Validate the rest under a dummy name;
     * SQLite and the constrained DDL authorizer validate the actual name. */
    std::string definition=diff.add_columns[i].def,validation=definition;
    if(!definition.empty() && definition[0]=='"') {
      size_t end=1;
      while(end<definition.size()) {
        char c=definition[end++];
        if(c=='"') {
          if(end<definition.size() && definition[end]=='"') ++end;
          else break;
        }
      }
      validation="managed_added_column"+definition.substr(end);
    }
    auto checked_status=murmur_check_add_column((const uint8_t *)validation.data(),validation.size(),&column,&checked_rc);
    free(column); if(checked_status!=MURMUR_SYNC_OK) throw ManagedError{checked_rc?checked_rc:SQLITE_SCHEMA};
    execute_ddl(m,"ALTER TABLE "+quote(remote.name)+" ADD COLUMN "+diff.add_columns[i].def,SQLITE_ALTER_TABLE,remote.name,remote.name);
  }
}
void artifact_store(murmur_managed *m,const murmur_origin_record_t &r) {
  uint8_t wire[MURMUR_ORIGIN_ENVELOPE_BYTES]; managed_check(murmur_origin_envelope_encode(&r.envelope,wire,sizeof(wire)));
  Statement old(m->db,"SELECT envelope FROM murmur_schema_artifacts WHERE master=?1 AND sequence=?2"); old.blob(1,std::string((const char *)r.envelope.origin,16)); old.integer(2,r.envelope.sequence);
  if(old.row()) { if(blob(old.p,0)!=std::string((const char *)wire,sizeof(wire))) throw ManagedError{SQLITE_AUTH}; return; }
  Statement insert(m->db,"INSERT INTO murmur_schema_artifacts VALUES(?1,?2,?3,?4,?5)");
  insert.blob(1,std::string((const char *)r.envelope.origin,16)); insert.integer(2,r.envelope.sequence); insert.blob(3,std::string((const char *)r.envelope.schema,32)); insert.blob(4,std::string((const char *)wire,sizeof(wire))); insert.blob(5,std::string((const char *)r.payload,r.bytes)); insert.done();
}
void copy_record(sqlite3_stmt *st,int header,int payload,murmur_origin_record_t *out) {
  auto envelope=blob(st,header),body=blob(st,payload); murmur_origin_envelope_t e{};
  managed_check(murmur_origin_envelope_decode(envelope.data(),envelope.size(),&e));
  auto *p=(uint8_t *)malloc(body.size()); if(!p) throw ManagedError{SQLITE_NOMEM}; memcpy(p,body.data(),body.size());
  out->envelope=e; out->payload=p; out->bytes=body.size();
}
void rebind_table(murmur_managed *m,const std::string &old,const std::string &id) {
  if(old==id) return;
  { Statement used(m->db,"SELECT 1 FROM murmur_replication_history WHERE table_id=?1"); used.blob(1,old); if(used.row()) throw ManagedError{SQLITE_SCHEMA}; }
  { Statement used(m->db,"SELECT 1 FROM murmur_managed_row_epochs WHERE table_id=?1 LIMIT 1"); used.blob(1,old); if(used.row()) throw ManagedError{SQLITE_SCHEMA}; }
  for(auto spec:{std::pair<const char *,const char *>{"murmur_managed_tables","id"},{"murmur_managed_columns","table_id"},{"murmur_managed_replication","table_id"}}) {
    Statement update(m->db,std::string("UPDATE ")+spec.first+" SET "+spec.second+"=?1 WHERE "+spec.second+"=?2"); update.blob(1,id); update.blob(2,old); update.done();
  }
}
void rebind_column(murmur_managed *m,const std::string &old,const std::string &id) {
  if(old==id) return;
  { Statement used(m->db,"SELECT 1 FROM murmur_replication_history h JOIN murmur_managed_columns c ON c.table_id=h.table_id WHERE c.id=?1"); used.blob(1,old); if(used.row()) throw ManagedError{SQLITE_SCHEMA}; }
  { Statement used(m->db,"SELECT 1 FROM murmur_managed_policy_state WHERE column_id=?1 LIMIT 1"); used.blob(1,old); if(used.row()) throw ManagedError{SQLITE_SCHEMA}; }
  for(auto spec:{std::pair<const char *,const char *>{"murmur_managed_columns","id"},{"murmur_managed_policies","column_id"},{"murmur_managed_search","column_id"}}) {
    Statement update(m->db,std::string("UPDATE ")+spec.first+" SET "+spec.second+"=?1 WHERE "+spec.second+"=?2"); update.blob(1,id); update.blob(2,old); update.done();
  }
}
void apply_schema(murmur_managed *m,const ManagedSchema &schema) {
  std::set<std::string> enabled;
  for(auto &table:schema.tables) {
    int validation_rc=0;
    if(reserved(table.name) || murmur_check_create_table((const uint8_t *)table.name.data(),table.name.size(),(const uint8_t *)table.ddl.data(),table.ddl.size(),&validation_rc)!=MURMUR_SYNC_OK) throw ManagedError{validation_rc?validation_rc:SQLITE_SCHEMA};
    enabled.insert(table.id); std::string old_name,old_id;
    { Statement history(m->db,"SELECT 1 FROM murmur_replication_history h JOIN murmur_managed_replication r ON r.table_id=h.table_id WHERE h.table_id=?1 AND r.enabled=0"); history.blob(1,table.id); if(history.row()) throw ManagedError{SQLITE_CONSTRAINT}; }
    { Statement id(m->db,"SELECT name,id FROM murmur_managed_tables WHERE id=?1 OR name=?2 COLLATE NOCASE ORDER BY id=?1 DESC LIMIT 1"); id.blob(1,table.id); id.text(2,table.name); if(id.row()) { old_name=text(id.p,0); old_id=blob(id.p,1); } }
    bool present=!old_name.empty(),crr=present && is_crr(m,old_name);
    if(present && old_id!=table.id) {
      Statement rows(m->db,"SELECT 1 FROM "+quote(old_name)+" LIMIT 1"); if(rows.row()) throw ManagedError{SQLITE_SCHEMA};
    }
    if(crr) lifecycle(m,"crsql_begin_alter",old_name);
    if(present && old_name!=table.name) rename_table(m,old_name,table.name);
    if(!present) {
      int sqlrc=0; auto status=murmur_check_create_table((const uint8_t *)table.name.data(),table.name.size(),(const uint8_t *)table.ddl.data(),table.ddl.size(),&sqlrc);
      if(status!=MURMUR_SYNC_OK) throw ManagedError{sqlrc?sqlrc:SQLITE_SCHEMA};
      execute_ddl(m,table.ddl,SQLITE_CREATE_TABLE,table.name,table.name);
      Statement insert(m->db,"INSERT INTO murmur_managed_tables VALUES(?1,?2)"); insert.text(1,table.name); insert.blob(2,table.id); insert.done();
    } else {
      for(auto &col:table.columns) {
        std::string old_col;
        { Statement st(m->db,"SELECT name FROM murmur_managed_columns WHERE table_id=?1 AND id=?2"); st.blob(1,old_id); st.blob(2,col.id); if(st.row()) old_col=text(st.p,0); }
        if(!old_col.empty() && old_col!=col.name) {
          exec(m,"ALTER TABLE "+quote(table.name)+" RENAME COLUMN "+quote(old_col)+" TO "+quote(col.name));
          if(crr) rename_clock_column(m,table.name,old_col,col.name);
          Statement rename(m->db,"UPDATE murmur_managed_columns SET name=?1 WHERE table_id=?2 AND id=?3"); rename.text(1,col.name); rename.blob(2,old_id); rename.blob(3,col.id); rename.done();
        }
      }
      compare_additive(m,table);
      rebind_table(m,old_id,table.id);
      Statement rename(m->db,"UPDATE murmur_managed_tables SET name=?1 WHERE id=?2"); rename.text(1,table.name); rename.blob(2,table.id); rename.done();
    }
    if(crr) lifecycle(m,"crsql_commit_alter",table.name);
    else { int sqlrc=0; auto status=murmur_schema_make_crr(m->db,(const uint8_t *)table.name.data(),table.name.size(),&sqlrc); if(status!=MURMUR_SYNC_OK) throw ManagedError{sqlrc?sqlrc:SQLITE_SCHEMA}; }
    std::vector<std::string> physical;
    { Statement st(m->db,"SELECT name FROM pragma_table_info(?1) ORDER BY cid"); st.text(1,table.name); while(st.row()) physical.push_back(text(st.p,0)); }
    if(physical.size()!=table.columns.size()) throw ManagedError{SQLITE_SCHEMA};
    for(size_t i=0;i<table.columns.size();++i) {
      auto &col=table.columns[i]; if(col.name!=physical[i]) throw ManagedError{SQLITE_SCHEMA};
      {
        /* Existing data needs an explicit signed baseline anchor before a
         * new non-LWW declaration can be adopted. Initial empty schemas and
         * unchanged policy identities are supported. */
        Statement previous(m->db,"SELECT policy FROM murmur_managed_policies WHERE column_id=?1"); previous.blob(1,col.id);
        unsigned before=previous.row()?(unsigned)sqlite3_column_int(previous.p,0):0;
        if(before && before!=col.policy) throw ManagedError{SQLITE_CONSTRAINT};
        if(!before && col.policy) {
          Statement rows(m->db,"SELECT 1 FROM "+quote(table.name)+" LIMIT 1"); if(rows.row()) throw ManagedError{SQLITE_CONSTRAINT};
          Statement history(m->db,"SELECT 1 FROM murmur_replica_current WHERE table_id=?1 LIMIT 1"); history.blob(1,table.id); if(history.row()) throw ManagedError{SQLITE_CONSTRAINT};
        }
      }
      std::string old;
      { Statement st(m->db,"SELECT id FROM murmur_managed_columns WHERE table_id=?1 AND name=?2"); st.blob(1,table.id); st.text(2,col.name); if(st.row()) old=blob(st.p,0); }
      if(!old.empty()) rebind_column(m,old,col.id);
      { Statement st(m->db,"INSERT INTO murmur_managed_columns VALUES(?1,?2,?3) ON CONFLICT(table_id,name) DO UPDATE SET id=excluded.id"); st.blob(1,table.id); st.text(2,col.name); st.blob(3,col.id); st.done(); }
      { Statement st(m->db,"INSERT INTO murmur_managed_policies VALUES(?1,?2) ON CONFLICT(column_id) DO UPDATE SET policy=excluded.policy"); st.blob(1,col.id); st.integer(2,col.policy); st.done(); }
      { Statement st(m->db,"INSERT INTO murmur_managed_search VALUES(?1,?2,?3,?4) ON CONFLICT(column_id) DO UPDATE SET fts=excluded.fts,dimensions=excluded.dimensions,distance=excluded.distance"); st.blob(1,col.id); st.integer(2,col.fts); st.integer(3,col.dimensions); st.integer(4,col.distance); st.done(); }
    }
    Statement flag(m->db,"INSERT INTO murmur_managed_replication VALUES(?1,1) ON CONFLICT(table_id) DO UPDATE SET enabled=1"); flag.blob(1,table.id); flag.done();
  }
  std::vector<std::string> old_enabled;
  { Statement st(m->db,"SELECT table_id FROM murmur_managed_replication WHERE enabled=1"); while(st.row()) old_enabled.push_back(blob(st.p,0)); }
  for(auto &id:old_enabled) if(!enabled.count(id)) { Statement st(m->db,"UPDATE murmur_managed_replication SET enabled=0 WHERE table_id=?1"); st.blob(1,id); st.done(); }
  std::map<std::string,ManagedSchemaIndex> indexes;
  for(auto &idx:schema.indexes) indexes[idx.name]=idx;
  for(auto &table:schema.tables) {
    std::vector<std::pair<std::string,std::string>> local;
    { Statement st(m->db,"SELECT name,sql FROM sqlite_schema WHERE type='index' AND sql IS NOT NULL AND tbl_name=?1"); st.text(1,table.name); while(st.row()) local.emplace_back(text(st.p,0),text(st.p,1)); }
    for(auto &idx:local) {
      auto remote=indexes.find(idx.first);
      if(remote==indexes.end() || remote->second.ddl!=idx.second) exec(m,"DROP INDEX "+quote(idx.first));
    }
  }
  for(auto &idx:schema.indexes) if(!exists(m,idx.name,"index")) {
    if(reserved(idx.name)) throw ManagedError{SQLITE_SCHEMA};
    auto table=std::find_if(schema.tables.begin(),schema.tables.end(),[&](auto &t){return t.id==idx.table;});
    if(table==schema.tables.end()) throw ManagedError{SQLITE_SCHEMA};
    execute_ddl(m,idx.ddl,SQLITE_CREATE_INDEX,idx.name,table->name);
  }
}
}
int managed_schema_authorize(murmur_managed *m,int action,const char *a,const char *b,const char *database) {
  auto same=[](const char *name,const std::string &expected) { return name && !sqlite3_stricmp(name,expected.c_str()); };
  auto schema=[](const char *name) { return name && (!sqlite3_stricmp(name,"sqlite_master")||!sqlite3_stricmp(name,"sqlite_schema")||!sqlite3_stricmp(name,"sqlite_temp_master")); };
  switch(action) {
    case SQLITE_CREATE_TABLE: return m->ddl_action==action && same(a,m->ddl_name) && database && !strcmp(database,"main")?SQLITE_OK:SQLITE_DENY;
    case SQLITE_CREATE_INDEX:
      return (m->ddl_action==action && same(a,m->ddl_name) && same(b,m->ddl_table)) ||
        (m->ddl_action==SQLITE_CREATE_TABLE && a && !sqlite3_strnicmp(a,"sqlite_autoindex_",17) && same(b,m->ddl_table))?SQLITE_OK:SQLITE_DENY;
    case SQLITE_ALTER_TABLE: return m->ddl_action==action && same(b,m->ddl_table)?SQLITE_OK:SQLITE_DENY;
    case SQLITE_REINDEX: return m->ddl_action==SQLITE_CREATE_INDEX && same(a,m->ddl_name)?SQLITE_OK:SQLITE_DENY;
    case SQLITE_INSERT: case SQLITE_UPDATE: case SQLITE_DELETE: return schema(a)?SQLITE_OK:SQLITE_DENY;
    case SQLITE_READ: return schema(a) || same(a,m->ddl_table)?SQLITE_OK:SQLITE_DENY;
    case SQLITE_SELECT: case SQLITE_RECURSIVE: return SQLITE_OK;
    case SQLITE_FUNCTION:
      return b && (reserved(b) && sqlite3_strnicmp(b,"sqlite_",7))?SQLITE_DENY:(b && !sqlite3_stricmp(b,"load_extension")?SQLITE_DENY:SQLITE_OK);
    case SQLITE_PRAGMA: return a && !b && (!strcmp(a,"schema_version")||!strcmp(a,"data_version"))?SQLITE_OK:SQLITE_DENY;
    default: return SQLITE_DENY;
  }
}
ManagedSchema managed_schema_capture(murmur_managed *m) {
  Access access(m); ManagedSchema schema;
  Statement tables(m->db,"SELECT t.id,t.name,s.sql FROM murmur_managed_tables t JOIN murmur_managed_replication r ON r.table_id=t.id AND r.enabled=1 JOIN sqlite_schema s ON s.type='table' AND s.name=t.name ORDER BY t.id");
  while(tables.row()) {
    ManagedSchemaTable table{blob(tables.p,0),text(tables.p,1),text(tables.p,2),{}};
    Statement cols(m->db,"SELECT c.id,c.name,coalesce(p.policy,0),coalesce(s.fts,0),coalesce(s.dimensions,0),coalesce(s.distance,0) FROM murmur_managed_columns c JOIN pragma_table_info(?1) i ON i.name=c.name LEFT JOIN murmur_managed_policies p ON p.column_id=c.id LEFT JOIN murmur_managed_search s ON s.column_id=c.id WHERE c.table_id=?2 ORDER BY i.cid"); cols.text(1,table.name); cols.blob(2,table.id);
    while(cols.row()) table.columns.push_back({blob(cols.p,0),text(cols.p,1),(unsigned)sqlite3_column_int(cols.p,2),(unsigned)sqlite3_column_int(cols.p,3),(unsigned)sqlite3_column_int(cols.p,4),(unsigned)sqlite3_column_int(cols.p,5)});
    std::vector<std::string> column_names; for(auto &col:table.columns) column_names.push_back(col.name);
    table.ddl=canonical_ddl(table.ddl,table.name,column_names);
    Statement idx(m->db,"SELECT name,sql FROM sqlite_schema WHERE type='index' AND sql IS NOT NULL AND tbl_name=?1 ORDER BY name"); idx.text(1,table.name); while(idx.row()) schema.indexes.push_back({text(idx.p,0),table.id,text(idx.p,1)});
    schema.tables.push_back(std::move(table));
  }
  std::sort(schema.indexes.begin(),schema.indexes.end(),[](auto &a,auto &b){return a.name<b.name;}); return schema;
}
std::string managed_schema_encode(const ManagedSchema &schema) {
  ManagedEncoder e; e.raw("MMS2",4); e.number(schema.tables.size());
  for(auto &t:schema.tables) {
    e.raw(t.id.data(),16); e.blob(t.name); e.blob(t.ddl); e.number(t.columns.size());
    for(auto &c:t.columns) { e.raw(c.id.data(),16); e.blob(c.name); e.number(c.policy); e.number(c.fts); e.number(c.dimensions); e.number(c.distance); }
  }
  e.number(schema.indexes.size()); for(auto &i:schema.indexes) { e.blob(i.name); e.raw(i.table.data(),16); e.blob(i.ddl); } return e.bytes;
}
ManagedSchema managed_schema_decode(const std::string &bytes) {
  ManagedDecoder d(bytes.data(),bytes.size()); if(d.raw(4)!="MMS2") throw ManagedError{SQLITE_CORRUPT};
  ManagedSchema out; std::set<std::string> ids,names,table_ids,index_names;
  for(size_t n=d.count(4096);n;--n) {
    ManagedSchemaTable t; t.id=d.raw(16); t.name=d.text(); t.ddl=d.text();
    if(!ids.insert(t.id).second || !names.insert(t.name).second || t.name.empty()) throw ManagedError{SQLITE_CORRUPT};
    table_ids.insert(t.id);
    std::set<std::string> columns;
    for(size_t k=d.count(32766);k;--k) {
      ManagedSchemaColumn c; c.id=d.raw(16); c.name=d.text(); c.policy=d.number(); c.fts=d.number(); c.dimensions=d.number(); c.distance=d.number();
      if(!ids.insert(c.id).second || !columns.insert(c.name).second || c.name.empty() || c.policy>6 || c.fts>1 || c.dimensions>8192 || c.distance>2) throw ManagedError{SQLITE_CORRUPT};
      t.columns.push_back(std::move(c));
    }
    out.tables.push_back(std::move(t));
  }
  for(size_t n=d.count(65536);n;--n) {
    ManagedSchemaIndex idx{d.text(),d.raw(16),d.text()};
    if(!index_names.insert(idx.name).second || !table_ids.count(idx.table)) throw ManagedError{SQLITE_CORRUPT};
    out.indexes.push_back(std::move(idx));
  }
  d.end(); if(managed_schema_encode(out)!=bytes) throw ManagedError{SQLITE_CORRUPT}; return out;
}
std::array<uint8_t,32> managed_schema_digest(murmur_managed *m) {
  auto digest=hash(managed_schema_encode(managed_schema_capture(m))); std::array<uint8_t,32> out; memcpy(out.data(),digest.data(),32); return out;
}
int managed_schema_initialize(murmur_managed *m) {
  return checked([&] { Access access(m); exec(m,"CREATE TABLE IF NOT EXISTS murmur_schema_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),master BLOB NOT NULL,sent_sequence INTEGER NOT NULL DEFAULT 0,current_sequence INTEGER NOT NULL DEFAULT 0,current_digest BLOB); CREATE TABLE IF NOT EXISTS murmur_schema_artifacts(master BLOB,sequence INTEGER,digest BLOB NOT NULL,envelope BLOB NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(master,sequence)); CREATE INDEX IF NOT EXISTS murmur_schema_by_digest ON murmur_schema_artifacts(digest)"); });
}
int managed_schema_activate(murmur_managed *m,const uint8_t node[16]) {
  return checked([&] { Access access(m); Statement st(m->db,"INSERT OR IGNORE INTO murmur_schema_control(singleton,master) VALUES(1,?1)"); st.blob(1,std::string((const char *)node,16)); st.done(); });
}
bool managed_schema_authority(murmur_managed *m) {
  Access access(m); auto owner=master(m); if(owner.empty()) return false;
  murmur_origin_identity_t id{}; return managed_origin_identity_internal(m,&id)==SQLITE_OK && owner==std::string((const char *)id.origin,16);
}
int managed_schema_require_authority(murmur_managed *m,const char *table) {
  return checked([&] { Access access(m); if(!table || managed_origin_replicated(m,table)) {
    if(!master(m).empty() && !managed_schema_authority(m)) throw ManagedError{SQLITE_AUTH};
  } });
}
int managed_schema_publish(murmur_managed *m) {
  return checked([&] {
    Access access(m); if(master(m).empty()) return;
    auto body=managed_schema_encode(managed_schema_capture(m)),digest=hash(body);
    managed_schema_decode(body); /* Never publish a manifest we cannot parse. */
    uint64_t sent=0;
    { Statement st(m->db,"SELECT sent_sequence,current_digest FROM murmur_schema_control WHERE singleton=1"); if(!st.row()) throw ManagedError{SQLITE_CORRUPT}; sent=sqlite3_column_int64(st.p,0); if(sqlite3_column_type(st.p,1)==SQLITE_BLOB && blob(st.p,1)==digest) return; }
    if(!managed_schema_authority(m)) throw ManagedError{SQLITE_AUTH};
    if(sent>=INT64_MAX) throw ManagedError{SQLITE_TOOBIG};
    murmur_origin_record_t r{}; r.envelope.sequence=sent+1; memcpy(r.envelope.schema,digest.data(),32); r.payload=(uint8_t *)body.data(); r.bytes=body.size();
    managed_check(managed_origin_sign_record(m,&r.envelope,r.payload,r.bytes)); artifact_store(m,r);
    Statement st(m->db,"UPDATE murmur_schema_control SET sent_sequence=?1,current_sequence=?1,current_digest=?2 WHERE singleton=1"); st.integer(1,sent+1); st.blob(2,digest); st.done();
  });
}
extern "C" int murmur_managed_schema_master(murmur_managed_t *m,const uint8_t origin[16]) {
  if(!m || !origin) return SQLITE_MISUSE;
  return checked([&] {
    Grant grant(m); Access access(m);
    Statement key(m->db,"SELECT 1 FROM murmur_origin_keys WHERE origin=?1 AND enabled=1"); key.blob(1,std::string((const char *)origin,16)); if(!key.row()) throw ManagedError{SQLITE_AUTH};
    { Statement log(m->db,"SELECT 1 FROM murmur_origin_log LIMIT 1"); if(log.row() && master(m)!=std::string((const char *)origin,16)) throw ManagedError{SQLITE_CONSTRAINT}; }
    exec(m,"BEGIN IMMEDIATE"); int rc=checked([&] {
      Statement st(m->db,"UPDATE murmur_schema_control SET master=?1,sent_sequence=coalesce((SELECT max(sequence) FROM murmur_schema_artifacts WHERE master=?1),0),current_sequence=0,current_digest=NULL WHERE singleton=1 AND master<>?1"); st.blob(1,std::string((const char *)origin,16)); st.done(); exec(m,"COMMIT");
    }); if(rc) { sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr); throw ManagedError{rc}; } managed_check(nvStoreFlush(m->store_ref));
  });
}
extern "C" int murmur_managed_schema_export(murmur_managed_t *m,murmur_origin_record_t *out) {
  if(!m || !out) return SQLITE_MISUSE;
  *out={};
  return checked([&] {
    Grant grant(m); Access access(m); exec(m,"BEGIN IMMEDIATE"); int rc=checked([&] { managed_check(managed_schema_publish(m)); exec(m,"COMMIT"); });
    if(rc) { sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr); throw ManagedError{rc}; }
    managed_check(nvStoreFlush(m->store_ref));
    Statement st(m->db,"SELECT a.envelope,a.payload FROM murmur_schema_artifacts a JOIN murmur_schema_control c ON c.master=a.master AND c.current_sequence=a.sequence WHERE c.singleton=1"); if(!st.row()) throw ManagedError{SQLITE_NOTFOUND}; copy_record(st.p,0,1,out);
  });
}
extern "C" int murmur_managed_schema_find(murmur_managed_t *m,const uint8_t digest[32],murmur_origin_record_t *out) {
  if(!m || !digest || !out) return SQLITE_MISUSE;
  *out={};
  return checked([&] { Grant grant(m); Access access(m); managed_check(nvStoreFlush(m->store_ref));
    Statement st(m->db,"SELECT envelope,payload FROM murmur_schema_artifacts WHERE digest=?1 AND master=?2 ORDER BY sequence DESC LIMIT 1"); st.blob(1,std::string((const char *)digest,32)); st.blob(2,master(m)); if(!st.row()) throw ManagedError{SQLITE_NOTFOUND}; copy_record(st.p,0,1,out);
  });
}
extern "C" int murmur_managed_schema_adopt(murmur_managed_t *m,const murmur_origin_record_t *record,int *changed) {
  if(!m || !record || !changed || (!record->payload && record->bytes)) return SQLITE_MISUSE;
  *changed=0;
  return checked([&] {
    Grant grant(m,MURMUR_WRITER_REMOTE); Access access(m); managed_check(managed_origin_sync(m)); managed_check(managed_policy_sync(m));
    managed_check(managed_origin_verify_record(m,record));
    if(master(m)!=std::string((const char *)record->envelope.origin,16)) throw ManagedError{SQLITE_AUTH};
    std::string body((const char *)record->payload,record->bytes),digest=hash(body);
    if(digest!=std::string((const char *)record->envelope.schema,32)) throw ManagedError{SQLITE_AUTH};
    auto schema=managed_schema_decode(body);
    auto old_policies=m->policies; ManagedSearchChange search; bool adopted=false;
    exec(m,"BEGIN IMMEDIATE"); int rc=checked([&] {
      artifact_store(m,*record); uint64_t current=0;
      managed_check(managed_origin_observe_record(m,&record->envelope));
      { Statement st(m->db,"SELECT current_sequence FROM murmur_schema_control WHERE singleton=1"); if(!st.row()) throw ManagedError{SQLITE_AUTH}; current=sqlite3_column_int64(st.p,0); }
      if(record->envelope.sequence<=current) return;
      apply_schema(m,schema);
      if(managed_schema_encode(managed_schema_capture(m))!=body) throw ManagedError{SQLITE_SCHEMA};
      exec(m,"UPDATE murmur_managed_generation SET generation=generation+1 WHERE singleton=1");
      managed_check(managed_policy_sync(m,true)); managed_check(managed_search_change(m,search));
      Statement st(m->db,"UPDATE murmur_schema_control SET current_sequence=?1,current_digest=?2 WHERE singleton=1"); st.integer(1,record->envelope.sequence); st.blob(2,digest); st.done(); adopted=true;
      exec(m,"COMMIT");
    });
    /* Historical imports also need to commit their retained artifact. */
    if(!rc && !sqlite3_get_autocommit(m->db)) rc=sqlite3_exec(m->db,"COMMIT",nullptr,nullptr,nullptr);
    if(rc) { sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr); m->policies=std::move(old_policies); }
    managed_search_complete(m,search,!rc); managed_check(rc); managed_check(managed_origin_sync(m)); managed_check(nvStoreFlush(m->store_ref)); *changed=adopted;
  });
}
int managed_schema_migration_begin(murmur_managed *m,const murmur_rename_t *maps,size_t n) {
  return checked([&] {
    Access access(m); auto plan=std::make_shared<ManagedSchemaMigration>(); plan->before=managed_schema_capture(m); if(n) plan->mappings.assign(maps,maps+n);
    if(!plan->before.tables.empty()) managed_check(managed_schema_require_authority(m));
    managed_check(managed_schema_publish(m));
    for(auto &table:plan->before.tables) {
      Statement st(m->db,"SELECT name,type,\"notnull\",dflt_value,pk FROM pragma_table_info(?1) ORDER BY cid"); st.text(1,table.name);
      while(st.row()) plan->shapes[table.id].push_back({text(st.p,0),text(st.p,1),sqlite3_column_type(st.p,3)==SQLITE_NULL?std::string():text(st.p,3),sqlite3_column_int(st.p,2),sqlite3_column_int(st.p,4)});
      lifecycle(m,"crsql_begin_alter",table.name);
    }
    m->schema_migration=std::move(plan);
  });
}
int managed_schema_migration_finish(murmur_managed *m) {
  return checked([&] {
    Access access(m); if(!m->schema_migration) return;
    for(auto &table:m->schema_migration->before.tables) {
      std::string name=table.name;
      for(auto &map:m->schema_migration->mappings) if(!map.column && map.new_table && !sqlite3_stricmp(map.table,table.name.c_str())) name=map.new_table;
      if(!exists(m,name)) throw ManagedError{SQLITE_SCHEMA};
      std::map<std::string,ManagedSchemaMigration::Shape> after;
      { Statement st(m->db,"SELECT name,type,\"notnull\",dflt_value,pk FROM pragma_table_info(?1) ORDER BY cid"); st.text(1,name);
        while(st.row()) { auto column=text(st.p,0); after[column]={column,text(st.p,1),sqlite3_column_type(st.p,3)==SQLITE_NULL?std::string():text(st.p,3),sqlite3_column_int(st.p,2),sqlite3_column_int(st.p,4)}; }
      }
      for(auto shape:m->schema_migration->shapes[table.id]) {
        for(auto &map:m->schema_migration->mappings) if(map.column && map.new_column && !sqlite3_stricmp(map.table,table.name.c_str()) && !sqlite3_stricmp(map.column,shape.name.c_str())) shape.name=map.new_column;
        auto found=after.find(shape.name);
        if(found==after.end() || shape.type!=found->second.type || shape.not_null!=found->second.not_null || shape.pk!=found->second.pk || shape.default_sql!=found->second.default_sql) throw ManagedError{SQLITE_SCHEMA};
      }
      if(name!=table.name) for(auto suffix:{"__crsql_clock","__crsql_pks"}) if(exists(m,table.name+suffix)) exec(m,"ALTER TABLE "+quote(table.name+suffix)+" RENAME TO "+quote(name+suffix));
      for(auto &map:m->schema_migration->mappings) if(map.column && map.new_column && !sqlite3_stricmp(map.table,table.name.c_str())) rename_clock_column(m,name,map.column,map.new_column);
      lifecycle(m,"crsql_commit_alter",name);
    }
  });
}
std::string managed_schema_translate_cells(murmur_managed *m,const uint8_t digest_bytes[32],const uint8_t *payload,size_t bytes) {
  Access access(m); auto current=managed_schema_capture(m); auto digest=std::string((const char *)digest_bytes,32);
  auto active=managed_schema_digest(m);
  ManagedSchema source;
  if(digest==std::string((const char *)active.data(),32)) source=current;
  else {
    std::string historical;
    { Statement st(m->db,"SELECT payload FROM murmur_schema_artifacts WHERE digest=?1 AND master=?2 ORDER BY sequence DESC LIMIT 1"); st.blob(1,digest); st.blob(2,master(m)); if(!st.row()) throw ManagedError{SQLITE_SCHEMA}; historical=blob(st.p,0); }
    source=managed_schema_decode(historical);
  }
  if(bytes<12) throw ManagedError{SQLITE_CORRUPT};
  uint32_t n=(uint32_t)payload[8]|(uint32_t)payload[9]<<8|(uint32_t)payload[10]<<16|(uint32_t)payload[11]<<24;
  if(n>(1u<<20) || n>(bytes-12)/49) throw ManagedError{SQLITE_CORRUPT};
  std::vector<murmur_cell_t> cells(n); size_t count=0;
  if(murmur_cells_decode(payload,bytes,cells.data(),cells.size(),&count)!=MURMUR_OK) throw ManagedError{SQLITE_CORRUPT};
  std::map<std::string,const ManagedSchemaTable *> old,new_tables; for(auto &t:source.tables) old[t.name]=&t; for(auto &t:current.tables) new_tables[t.id]=&t;
  std::string out("CRSB\1\0\0\0\0\0\0\0",12); uint32_t written=0;
  for(auto c:cells) {
    auto found=old.find(std::string((const char *)c.table,c.table_len)); if(found==old.end()) throw ManagedError{SQLITE_AUTH};
    auto target=new_tables.find(found->second->id); if(target==new_tables.end()) continue;
    auto *table=target->second; std::string cid((const char *)c.cid,c.cid_len),new_cid=cid;
    if(cid!="-1") {
      std::string id; for(auto &col:found->second->columns) if(col.name==cid) id=col.id;
      if(id.empty()) throw ManagedError{SQLITE_SCHEMA};
      new_cid.clear(); for(auto &col:table->columns) if(col.id==id) new_cid=col.name;
      if(new_cid.empty()) throw ManagedError{SQLITE_SCHEMA};
    }
    c.table=(const uint8_t *)table->name.data(); c.table_len=table->name.size(); c.cid=(const uint8_t *)new_cid.data(); c.cid_len=new_cid.size();
    std::string encoded(c.table_len+c.pk_len+c.cid_len+c.site_len+c.val_blob_len+128,'\0'); auto size=murmur_cell_encode(&c,(uint8_t *)encoded.data(),encoded.size());
    if(!size || size>(64u<<20)-out.size()) throw ManagedError{SQLITE_TOOBIG};
    out.append(encoded.data(),size); ++written;
  }
  for(unsigned i=0;i<4;++i) out[8+i]=(char)(written>>(8*i));
  return out;
}
