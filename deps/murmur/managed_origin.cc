#include "managed_internal.h"
#include "managed_origin.h"
#include "managed_value.h"
#include "managed_schema_internal.h"
#include "managed_replica.h"
#include "open.h"
#include "schema.h"
#include "sync.h"
#include "sha256.h"
#include <array>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>

struct ManagedOrigin {
  bool required=false,have_seed=false;
  std::array<uint8_t,32> seed{};
  murmur_origin_identity_t identity{};
  std::set<std::string> tables,triggers;
  ~ManagedOrigin() { volatile uint8_t *p=seed.data(); for(size_t i=0;i<seed.size();++i) p[i]=0; }
};
namespace {
constexpr size_t max_payload=64u<<20;
struct Access {
  murmur_managed *m; int old;
  Access(murmur_managed *m):m(m),old(m->access) { m->access=3; }
  ~Access() { m->access=old; }
};
struct Grant {
  murmur_scheduler_t *s;
  Grant(murmur_managed *m,murmur_writer_class_t cls=MURMUR_WRITER_MAINTENANCE):s(m->coordinator->scheduler) {
    managed_check(murmur_scheduler_acquire(s,cls,-1,nullptr,nullptr));
  }
  ~Grant() { murmur_scheduler_release(s); }
};
struct Statement {
  sqlite3_stmt *p=nullptr;
  Statement(sqlite3 *db,const std::string &sql) { managed_check(sqlite3_prepare_v2(db,sql.c_str(),-1,&p,nullptr)); }
  ~Statement() { sqlite3_finalize(p); }
  void blob(int i,const void *v,size_t n) { managed_check(sqlite3_bind_blob64(p,i,v,n,SQLITE_TRANSIENT)); }
  void text(int i,const std::string &v) { managed_check(sqlite3_bind_text64(p,i,v.data(),v.size(),SQLITE_TRANSIENT,SQLITE_UTF8)); }
  void integer(int i,uint64_t v) { if(v>INT64_MAX) throw ManagedError{SQLITE_TOOBIG}; managed_check(sqlite3_bind_int64(p,i,v)); }
  bool row() { int rc=sqlite3_step(p); if(rc==SQLITE_ROW) return true; if(rc!=SQLITE_DONE) throw ManagedError{rc}; return false; }
  void done() { if(row()) throw ManagedError{SQLITE_ERROR}; }
};
template<class Fn> int checked(Fn fn) {
  try { fn(); return SQLITE_OK; } catch(const ManagedError &e) { return e.code; } catch(...) { return SQLITE_NOMEM; }
}
void exec(murmur_managed *m,const std::string &sql) { managed_check(sqlite3_exec(m->db,sql.c_str(),nullptr,nullptr,nullptr)); }
template<class Fn> void atomic(murmur_managed *m,Fn fn) {
  exec(m,"BEGIN IMMEDIATE");
  int rc=checked([&] { fn(); exec(m,"COMMIT"); });
  if(rc) { sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr); throw ManagedError{rc}; }
}
std::string blob(sqlite3_stmt *st,int i) {
  auto v=ManagedValue::column(st,i); if(v.type!=MURMUR_BLOB) throw ManagedError{SQLITE_CORRUPT}; return v.data;
}
std::string text(sqlite3_stmt *st,int i) {
  auto v=ManagedValue::column(st,i); if(v.type!=MURMUR_TEXT) throw ManagedError{SQLITE_CORRUPT}; return v.data;
}
template<size_t N> void fixed(sqlite3_stmt *st,int col,uint8_t (&out)[N]) {
  auto value=blob(st,col); if(value.size()!=N) throw ManagedError{SQLITE_CORRUPT}; memcpy(out,value.data(),N);
}
bool nonzero(const uint8_t *p,size_t n) { uint8_t v=0; for(size_t i=0;i<n;++i) v|=p[i]; return v!=0; }
std::string quote(const std::string &s) {
  char *p=sqlite3_mprintf("\"%w\"",s.c_str()); if(!p) throw ManagedError{SQLITE_NOMEM};
  std::unique_ptr<char,decltype(&sqlite3_free)> owned(p,sqlite3_free); return p;
}
int64_t number(murmur_managed *m,const char *sql) {
  Statement st(m->db,sql); if(!st.row()) throw ManagedError{SQLITE_CORRUPT}; return sqlite3_column_int64(st.p,0);
}
void reload(murmur_managed *m) {
  if(!m->origin) m->origin=std::make_shared<ManagedOrigin>();
  auto &o=*m->origin;
  murmur_origin_identity_t identity{}; bool required=false;
  {
    Statement st(m->db,"SELECT database_id,node_id,site,public_key FROM murmur_origin_config WHERE singleton=1");
    if(st.row()) { fixed(st.p,0,identity.database); fixed(st.p,1,identity.origin); fixed(st.p,2,identity.site); fixed(st.p,3,identity.public_key); required=true; }
  }
  if(required && o.have_seed) {
    uint8_t pub[32]; managed_check(murmur_origin_public_key(o.seed.data(),pub));
    if(memcmp(pub,identity.public_key,32)) throw ManagedError{SQLITE_AUTH};
  }
  std::set<std::string> tables,triggers;
  Statement st(m->db,"SELECT t.name,r.enabled FROM murmur_managed_replication r JOIN murmur_managed_tables t ON t.id=r.table_id ORDER BY t.name");
  while(st.row()) {
    auto name=text(st.p,0); if(sqlite3_column_int(st.p,1)) tables.insert(name);
    /* Disabled tables still keep native CRR triggers for local writes. */
    for(auto suffix:{"__crsql_itrig","__crsql_utrig","__crsql_dtrig"}) triggers.insert(name+suffix);
  }
  o.identity=identity; o.required=required; o.tables=std::move(tables); o.triggers=std::move(triggers);
}
std::array<uint8_t,32> schema_digest(murmur_managed *m) {
  return managed_schema_digest(m);
}
uint64_t head(murmur_managed *m,const uint8_t node[16]) {
  Statement st(m->db,"SELECT sequence FROM murmur_origin_heads WHERE origin=?1"); st.blob(1,node,16);
  if(!st.row()) return 0;
  auto value=sqlite3_column_int64(st.p,0);
  if(value<0) throw ManagedError{SQLITE_CORRUPT};
  return value;
}
std::array<uint8_t,MURMUR_ORIGIN_ENVELOPE_BYTES> wire(const murmur_origin_envelope_t &e) {
  std::array<uint8_t,MURMUR_ORIGIN_ENVELOPE_BYTES> out;
  managed_check(murmur_origin_envelope_encode(&e,out.data(),out.size())); return out;
}
void store(murmur_managed *m,const murmur_origin_envelope_t &e,const void *payload,size_t n) {
  auto bytes=wire(e);
  Statement log(m->db,"INSERT INTO murmur_origin_log VALUES(?1,?2,?3,?4)");
  log.blob(1,e.origin,16); log.integer(2,e.sequence); log.blob(3,bytes.data(),bytes.size()); log.blob(4,payload,n); log.done();
  Statement progress(m->db,"INSERT INTO murmur_origin_heads VALUES(?1,?2) ON CONFLICT(origin) DO UPDATE SET sequence=excluded.sequence");
  progress.blob(1,e.origin,16); progress.integer(2,e.sequence); progress.done();
}
void clock(murmur_managed *m,murmur_origin_envelope_t &e,bool local) {
  Statement st(m->db,"SELECT clock_ms,clock_logic FROM murmur_origin_config WHERE singleton=1");
  if(!st.row()) throw ManagedError{SQLITE_AUTH};
  uint64_t ms=sqlite3_column_int64(st.p,0); uint64_t logical=sqlite3_column_int64(st.p,1);
  if(ms>INT64_MAX || logical>UINT32_MAX) throw ManagedError{SQLITE_CORRUPT};
  if(local) {
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if(now<0) throw ManagedError{SQLITE_ERROR};
    if((uint64_t)now>ms) { ms=now; logical=0; }
    else if(logical==UINT32_MAX) { ++ms; logical=0; } else ++logical;
    e.millis=ms; e.logical=(uint32_t)logical;
  } else if(e.millis>ms) { ms=e.millis; logical=e.logical; }
  else if(e.millis==ms) logical=std::max<uint64_t>(logical,e.logical);
  Statement update(m->db,"UPDATE murmur_origin_config SET clock_ms=?1,clock_logic=?2 WHERE singleton=1");
  update.integer(1,ms); update.integer(2,logical); update.done();
}
std::string capture(murmur_managed *m,int64_t from) {
  std::string payload("CRSB\1\0\0\0\0\0\0\0",12); uint32_t count=0;
  Statement st(m->db,"SELECT \"table\",pk,cid,val,col_version,db_version,site_id,cl,seq FROM crsql_changes WHERE db_version>?1 ORDER BY db_version,seq,\"table\",pk,cid");
  managed_check(sqlite3_bind_int64(st.p,1,from));
  while(st.row()) {
    auto table=text(st.p,0); if(!managed_origin_replicated(m,table.c_str()) || managed_policy_has_table(m,table.c_str())) continue;
    { Statement used(m->db,"INSERT OR IGNORE INTO murmur_replication_history SELECT id FROM murmur_managed_tables WHERE name=?1"); used.text(1,table); used.done(); }
    auto pk=blob(st.p,1),cid=text(st.p,2),site=blob(st.p,6); auto val=ManagedValue::column(st.p,3);
    if(site.size()!=16 || memcmp(site.data(),m->origin->identity.site,16)) throw ManagedError{SQLITE_AUTH};
    murmur_cell_t cell{};
    cell.table=(const uint8_t *)table.data(); cell.table_len=table.size(); cell.pk=(const uint8_t *)pk.data(); cell.pk_len=pk.size();
    cell.cid=(const uint8_t *)cid.data(); cell.cid_len=cid.size(); cell.site=(const uint8_t *)site.data(); cell.site_len=site.size();
    cell.val_tag=(uint8_t)val.type; cell.val_int=val.integer; cell.val_real=val.real;
    cell.val_blob=(const uint8_t *)val.data.data(); cell.val_blob_len=val.data.size();
    cell.col_version=sqlite3_column_int64(st.p,4); cell.db_version=sqlite3_column_int64(st.p,5);
    cell.cl=sqlite3_column_int64(st.p,7); cell.seq=sqlite3_column_int64(st.p,8);
    size_t cap=table.size()+pk.size()+cid.size()+site.size()+val.data.size()+128;
    if(cap>max_payload || count==(1u<<20)) throw ManagedError{SQLITE_TOOBIG};
    std::string encoded(cap,'\0'); size_t n=murmur_cell_encode(&cell,(uint8_t *)encoded.data(),encoded.size());
    if(!n || n>max_payload-payload.size()) throw ManagedError{SQLITE_TOOBIG};
    payload.append(encoded.data(),n); ++count;
  }
  for(unsigned i=0;i<4;++i) payload[8+i]=(char)(count>>(8*i));
  return count?payload:std::string();
}
void validate_cells(murmur_managed *m,const murmur_origin_record_t &record,const uint8_t site[16],bool check_names=true,bool allow_empty=false) {
  if(record.bytes<12 || record.bytes>max_payload) throw ManagedError{SQLITE_CORRUPT};
  auto *p=record.payload;
  uint32_t n=(uint32_t)p[8]|(uint32_t)p[9]<<8|(uint32_t)p[10]<<16|(uint32_t)p[11]<<24;
  if((!n && !allow_empty) || n>(1u<<20) || n>(record.bytes-12)/49) throw ManagedError{SQLITE_CORRUPT};
  std::vector<murmur_cell_t> cells(n); size_t count=0;
  if(murmur_cells_decode(p,record.bytes,cells.data(),cells.size(),&count)!=MURMUR_OK) throw ManagedError{SQLITE_CORRUPT};
  for(auto &c:cells) {
    std::string table((const char *)c.table,c.table_len);
    if(table.find('\0')!=std::string::npos || (check_names && !managed_origin_replicated(m,table.c_str())) || c.site_len!=16 || memcmp(c.site,site,16)) throw ManagedError{SQLITE_AUTH};
    if(c.col_version<0 || c.db_version<0 || c.cl<0 || c.seq<0) throw ManagedError{SQLITE_CORRUPT};
  }
}
}
int managed_origin_initialize(murmur_managed *m) {
  return checked([&] {
    Access access(m);
    atomic(m,[&] {
      exec(m,"CREATE TABLE IF NOT EXISTS murmur_managed_replication(table_id BLOB PRIMARY KEY,enabled INTEGER NOT NULL CHECK(enabled IN(0,1)));"
        "CREATE TABLE IF NOT EXISTS murmur_origin_config(singleton INTEGER PRIMARY KEY CHECK(singleton=1),database_id BLOB NOT NULL,node_id BLOB NOT NULL,site BLOB NOT NULL,public_key BLOB NOT NULL,clock_ms INTEGER NOT NULL DEFAULT 0,clock_logic INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS murmur_origin_keys(origin BLOB PRIMARY KEY,public_key BLOB NOT NULL,site BLOB NOT NULL,enabled INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS murmur_origin_heads(origin BLOB PRIMARY KEY,sequence INTEGER NOT NULL CHECK(sequence>=0));"
        "CREATE TABLE IF NOT EXISTS murmur_origin_log(origin BLOB,sequence INTEGER,envelope BLOB NOT NULL,payload BLOB NOT NULL,PRIMARY KEY(origin,sequence));"
        "CREATE TABLE IF NOT EXISTS murmur_replication_history_bootstrap(singleton INTEGER PRIMARY KEY CHECK(singleton=1));"
        /* Older signed stores lack per-table markers. Conservatively retain
         * every configured table's identity once any signed history exists. */
        "INSERT OR IGNORE INTO murmur_replication_history SELECT table_id FROM murmur_managed_replication WHERE EXISTS(SELECT 1 FROM murmur_origin_log) AND NOT EXISTS(SELECT 1 FROM murmur_replication_history_bootstrap);"
        "INSERT OR IGNORE INTO murmur_replication_history_bootstrap VALUES(1);");
    });
    reload(m);
  });
}
int managed_origin_sync(murmur_managed *m) { return checked([&] { Access access(m); reload(m); }); }
bool managed_origin_replicated(murmur_managed *m,const char *table) {
  if(!table || !m->origin) return false;
  for(auto &name:m->origin->tables) if(!sqlite3_stricmp(name.c_str(),table)) return true;
  return false;
}
bool managed_origin_trusted_trigger(murmur_managed *m,const char *trigger) { return trigger && m->origin && m->origin->triggers.count(trigger); }
bool managed_origin_ddl_denied(murmur_managed *m,int action,const char *table) {
  return (action==SQLITE_DROP_TABLE || (action==SQLITE_ALTER_TABLE && !m->schema_migration)) && managed_origin_replicated(m,table);
}
int managed_origin_begin(murmur_managed *m,int64_t *from) {
  *from=-1;
  return checked([&] { Access access(m); if(m->origin->required) *from=number(m,"SELECT crsql_db_version()"); });
}
int managed_origin_finish(murmur_managed *m,int64_t from,bool *signed_record) {
  *signed_record=false;
  return checked([&] {
    Access access(m);
    if(from<0) { managed_replica_clear_dirty(m); return; }
    auto payload=capture(m,from);
    if(payload.empty() && !managed_replica_dirty(m)) { managed_replica_clear_dirty(m); return; }
    auto &o=*m->origin; if(!o.have_seed) throw ManagedError{SQLITE_AUTH};
    murmur_origin_record_t captured{}; captured.payload=(uint8_t *)payload.data(); captured.bytes=payload.size();
    if(!payload.empty()) validate_cells(m,captured,o.identity.site);
    managed_check(managed_schema_publish(m));
    murmur_origin_envelope_t e{}; memcpy(e.database,o.identity.database,16); memcpy(e.origin,o.identity.origin,16);
    auto seq=head(m,e.origin); if(seq==INT64_MAX) throw ManagedError{SQLITE_TOOBIG}; e.sequence=seq+1;
    sqlite3_randomness(16,e.transaction); auto digest=schema_digest(m); memcpy(e.schema,digest.data(),32); clock(m,e,true);
    payload=managed_replica_capture(m,e,payload);
    managed_check(murmur_origin_sign(&e,o.seed.data(),payload.data(),payload.size()));
    store(m,e,payload.data(),payload.size()); *signed_record=true;
  });
}
extern "C" int murmur_managed_origin_configure(murmur_managed_t *m,const uint8_t database[16],const uint8_t origin[16],const uint8_t seed[32]) {
  if(!m || !database || !origin || !seed || !nonzero(database,16) || !nonzero(origin,16)) return SQLITE_MISUSE;
  return checked([&] {
    Grant grant(m); Access access(m); reload(m); uint8_t pub[32]; managed_check(murmur_origin_public_key(seed,pub));
    atomic(m,[&] {
      if(m->origin->required) {
        auto &old=m->origin->identity;
        if(memcmp(old.database,database,16)||memcmp(old.origin,origin,16)||memcmp(old.public_key,pub,32)) throw ManagedError{SQLITE_AUTH};
        return;
      }
      if(number(m,"SELECT crsql_db_version()") || number(m,"SELECT count(*) FROM murmur_managed_policy_state")) throw ManagedError{SQLITE_CONSTRAINT};
      std::string site;
      { Statement st(m->db,"SELECT crsql_site_id()"); if(!st.row()) throw ManagedError{SQLITE_CORRUPT}; site=blob(st.p,0); }
      if(site.size()!=16) throw ManagedError{SQLITE_CORRUPT};
      Statement config(m->db,"INSERT INTO murmur_origin_config(singleton,database_id,node_id,site,public_key) VALUES(1,?1,?2,?3,?4)");
      config.blob(1,database,16); config.blob(2,origin,16); config.blob(3,site.data(),16); config.blob(4,pub,32); config.done();
      Statement keys(m->db,"INSERT INTO murmur_origin_keys VALUES(?1,?2,?3,1)"); keys.blob(1,origin,16); keys.blob(2,pub,32); keys.blob(3,site.data(),16); keys.done();
      Statement actor(m->db,"UPDATE murmur_managed_actor SET database_id=?1,node_id=?2 WHERE singleton=1"); actor.blob(1,database,16); actor.blob(2,origin,16); actor.done();
      exec(m,"UPDATE murmur_managed_generation SET generation=generation+1 WHERE singleton=1");
      managed_check(managed_schema_activate(m,origin));
    });
    memcpy(m->origin->seed.data(),seed,32); m->origin->have_seed=true; reload(m); managed_check(nvStoreFlush(m->store_ref));
  });
}
extern "C" int murmur_managed_origin_identity(murmur_managed_t *m,murmur_origin_identity_t *out) {
  if(!m || !out) return SQLITE_MISUSE;
  return checked([&] { Grant grant(m); Access access(m); reload(m); if(!m->origin->required) throw ManagedError{SQLITE_NOTFOUND}; *out=m->origin->identity; });
}
extern "C" int murmur_managed_origin_trust(murmur_managed_t *m,const murmur_origin_identity_t *id,int enabled) {
  if(!m || !id || (enabled!=0 && enabled!=1) || !nonzero(id->origin,16)) return SQLITE_MISUSE;
  return checked([&] {
    Grant grant(m); Access access(m); reload(m);
    if(!m->origin->required || memcmp(id->database,m->origin->identity.database,16)) throw ManagedError{SQLITE_AUTH};
    if(!enabled && !memcmp(id->origin,m->origin->identity.origin,16)) throw ManagedError{SQLITE_MISUSE};
    atomic(m,[&] {
      bool present=false;
      { Statement alias(m->db,"SELECT 1 FROM murmur_origin_keys WHERE site=?1 AND origin<>?2");
        alias.blob(1,id->site,16); alias.blob(2,id->origin,16); if(alias.row()) throw ManagedError{SQLITE_AUTH};
      }
      { Statement old(m->db,"SELECT public_key,site FROM murmur_origin_keys WHERE origin=?1"); old.blob(1,id->origin,16);
        if(old.row()) { present=true; if(blob(old.p,0)!=std::string((const char *)id->public_key,32)||blob(old.p,1)!=std::string((const char *)id->site,16)) throw ManagedError{SQLITE_AUTH}; }
      }
      if(!present && number(m,"SELECT count(*) FROM murmur_origin_keys")>=4096) throw ManagedError{SQLITE_TOOBIG};
      Statement st(m->db,"INSERT INTO murmur_origin_keys VALUES(?1,?2,?3,?4) ON CONFLICT(origin) DO UPDATE SET enabled=excluded.enabled");
      st.blob(1,id->origin,16); st.blob(2,id->public_key,32); st.blob(3,id->site,16); st.integer(4,enabled); st.done();
    });
    managed_check(nvStoreFlush(m->store_ref));
  });
}
extern "C" int murmur_managed_set_replication(murmur_managed_t *m,const char *table,int enabled) {
  if(!m || !table || (enabled!=0 && enabled!=1)) return SQLITE_MISUSE;
  return checked([&] {
    Grant grant(m); Access access(m); reload(m);
    managed_check(managed_schema_require_authority(m));
    atomic(m,[&] {
      std::string id,name;
      { Statement st(m->db,"SELECT id,name FROM murmur_managed_tables WHERE name=?1 COLLATE NOCASE"); st.text(1,table); if(!st.row()) throw ManagedError{SQLITE_NOTFOUND}; id=blob(st.p,0); name=text(st.p,1); }
      bool was_enabled=managed_origin_replicated(m,name.c_str());
      if(enabled && !was_enabled) {
        { Statement history(m->db,"SELECT 1 FROM murmur_replication_history WHERE table_id=?1"); history.blob(1,id.data(),id.size()); if(history.row()) throw ManagedError{SQLITE_CONSTRAINT}; }
        if(number(m,("SELECT EXISTS(SELECT 1 FROM "+quote(name)+" LIMIT 1)").c_str())) throw ManagedError{SQLITE_CONSTRAINT};
        int sqlrc=0; auto status=murmur_schema_make_crr(m->db,(const uint8_t *)name.data(),name.size(),&sqlrc);
        if(status!=MURMUR_SYNC_OK) throw ManagedError{sqlrc?sqlrc:SQLITE_ERROR};
      }
      Statement flag(m->db,"INSERT INTO murmur_managed_replication VALUES(?1,?2) ON CONFLICT(table_id) DO UPDATE SET enabled=excluded.enabled"); flag.blob(1,id.data(),id.size()); flag.integer(2,enabled); flag.done();
      exec(m,"UPDATE murmur_managed_generation SET generation=generation+1 WHERE singleton=1");
      managed_check(managed_schema_publish(m));
    });
    reload(m); managed_check(nvStoreFlush(m->store_ref));
  });
}
extern "C" void murmur_origin_record_free(murmur_origin_record_t *record) { if(record) { free(record->payload); *record={}; } }
extern "C" int murmur_managed_origin_next(murmur_managed_t *m,const uint8_t origin[16],uint64_t after,murmur_origin_record_t *out) {
  if(!m || !origin || !out || after>INT64_MAX) return SQLITE_MISUSE;
  *out={};
  return checked([&] {
    Grant grant(m); Access access(m); managed_check(nvStoreFlush(m->store_ref));
    Statement st(m->db,"SELECT envelope,payload FROM murmur_origin_log WHERE origin=?1 AND sequence>?2 ORDER BY sequence LIMIT 1"); st.blob(1,origin,16); st.integer(2,after);
    if(!st.row()) throw ManagedError{SQLITE_NOTFOUND};
    auto envelope=blob(st.p,0),payload=blob(st.p,1);
    murmur_origin_envelope_t e{}; managed_check(murmur_origin_envelope_decode(envelope.data(),envelope.size(),&e));
    auto *data=(uint8_t *)malloc(payload.size()); if(!data) throw ManagedError{SQLITE_NOMEM};
    memcpy(data,payload.data(),payload.size()); out->payload=data; out->bytes=payload.size(); out->envelope=e;
  });
}
extern "C" int murmur_managed_origin_apply(murmur_managed_t *m,const murmur_origin_record_t *record,int *applied) {
  if(!m || !record || !applied || (!record->payload && record->bytes)) return SQLITE_MISUSE;
  *applied=0;
  return checked([&] {
    Grant grant(m,MURMUR_WRITER_REMOTE); Access access(m); reload(m); managed_check(managed_policy_sync(m));
    if(!m->origin->required) throw ManagedError{SQLITE_AUTH};
    auto &e=record->envelope; bool changed=false;
    atomic(m,[&] {
      uint8_t pub[32],site[16];
      { Statement key(m->db,"SELECT public_key,site FROM murmur_origin_keys WHERE origin=?1 AND enabled=1"); key.blob(1,e.origin,16);
        if(!key.row()) throw ManagedError{SQLITE_AUTH};
        fixed(key.p,0,pub); fixed(key.p,1,site);
      }
      managed_check(murmur_origin_verify(&e,m->origin->identity.database,e.origin,pub,record->payload,record->bytes,max_payload));
      if(e.sequence>INT64_MAX || e.millis>INT64_MAX) throw ManagedError{SQLITE_TOOBIG};
      auto seq=head(m,e.origin);
      if(e.sequence<=seq) {
        Statement old(m->db,"SELECT envelope FROM murmur_origin_log WHERE origin=?1 AND sequence=?2"); old.blob(1,e.origin,16); old.integer(2,e.sequence);
        auto bytes=wire(e);
        if(!old.row() || blob(old.p,0)!=std::string((const char *)bytes.data(),bytes.size())) throw ManagedError{SQLITE_AUTH};
        return;
      }
      if(e.sequence!=seq+1) throw ManagedError{SQLITE_BUSY};
      auto batch=managed_replica_decode(*record);
      murmur_origin_record_t raw=*record; raw.payload=(uint8_t *)batch.cells.data(); raw.bytes=batch.cells.size();
      validate_cells(m,raw,site,false,!batch.rows.empty());
      managed_replica_apply(m,e,batch);
      auto translated=managed_schema_translate_cells(m,e.schema,raw.payload,raw.bytes);
      int sqlrc=0; auto status=murmur_sync_ingest_blob(m->db,(const uint8_t *)translated.data(),translated.size(),&sqlrc);
      if(status!=MURMUR_SYNC_OK) throw ManagedError{sqlrc?sqlrc:SQLITE_CORRUPT};
      store(m,e,record->payload,record->bytes); auto observed=e; clock(m,observed,false); changed=true;
    });
    managed_check(nvStoreFlush(m->store_ref)); *applied=changed;
  });
}
extern "C" int murmur_managed_origin_progress(murmur_managed_t *m,murmur_row_fn fn,void *ctx) {
  if(!m || !fn) return SQLITE_MISUSE;
  return checked([&] { Grant grant(m); Access access(m); Statement st(m->db,"SELECT origin,sequence FROM murmur_origin_heads ORDER BY origin");
    while(st.row()) { auto node=blob(st.p,0); murmur_value_t values[2]{};
      values[0]={MURMUR_BLOB,0,0,node.data(),node.size()}; values[1].type=MURMUR_INTEGER; values[1].integer=sqlite3_column_int64(st.p,1);
      if(fn(ctx,2,values)) throw ManagedError{SQLITE_ABORT};
    }
  });
}
extern "C" int murmur_managed_flush(murmur_managed_t *m) {
  if(!m) return SQLITE_MISUSE;
  return checked([&] { Grant grant(m); managed_check(nvStoreFlush(m->store_ref)); });
}
int managed_origin_identity_internal(murmur_managed *m,murmur_origin_identity_t *out) {
  return checked([&] { Access access(m); reload(m); if(!m->origin->required) throw ManagedError{SQLITE_NOTFOUND}; *out=m->origin->identity; });
}
int managed_origin_sign_record(murmur_managed *m,murmur_origin_envelope_t *e,const void *payload,size_t n) {
  return checked([&] {
    Access access(m); reload(m); auto &o=*m->origin;
    if(!o.required || !o.have_seed || !e->sequence || e->sequence>INT64_MAX) throw ManagedError{SQLITE_AUTH};
    memcpy(e->database,o.identity.database,16); memcpy(e->origin,o.identity.origin,16); sqlite3_randomness(16,e->transaction); clock(m,*e,true);
    managed_check(murmur_origin_sign(e,o.seed.data(),payload,n));
  });
}
int managed_origin_verify_record(murmur_managed *m,const murmur_origin_record_t *r) {
  return checked([&] {
    Access access(m); reload(m); if(!m->origin->required || r->envelope.sequence>INT64_MAX || r->envelope.millis>INT64_MAX) throw ManagedError{SQLITE_AUTH};
    Statement key(m->db,"SELECT public_key FROM murmur_origin_keys WHERE origin=?1 AND enabled=1"); key.blob(1,r->envelope.origin,16);
    if(!key.row()) throw ManagedError{SQLITE_AUTH};
    uint8_t pub[32]; fixed(key.p,0,pub);
    managed_check(murmur_origin_verify(&r->envelope,m->origin->identity.database,r->envelope.origin,pub,r->payload,r->bytes,max_payload));
  });
}
int managed_origin_observe_record(murmur_managed *m,const murmur_origin_envelope_t *e) {
  return checked([&] { Access access(m); auto observed=*e; clock(m,observed,false); });
}
