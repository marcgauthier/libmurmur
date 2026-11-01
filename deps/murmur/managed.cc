#include "managed.h"
#include "managed_internal.h"
#include "managed_schema_internal.h"
#include "../../libmurmur.h"
#include "open.h"
#include "sqlite3.h"
#include <algorithm>
#include <climits>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

static std::mutex registry_mu;
static std::unordered_map<std::string, std::weak_ptr<Coordinator>> registry;
static bool reserved(const char *s) {
  return s && (!sqlite3_strnicmp(s,"murmur_",7) || !sqlite3_strnicmp(s,"crsql_",6) ||
               strstr(s,"__crsql") || !sqlite3_strnicmp(s,"sqlite_",7));
}
static int authorize(void *ctx, int action, const char *a, const char *b,
                     const char *database, const char *trigger) {
  auto *m = (murmur_managed *)ctx;
  if (m->access == 5) return managed_schema_authorize(m,action,a,b,database);
  if (m->access == 3 || m->access == 4) return SQLITE_OK;
  if (managed_policy_trusted_trigger(m,trigger) || managed_origin_trusted_trigger(m,trigger)) return SQLITE_OK;
  switch (action) {
    /* FTS5 reconnects after schema rollback using this read-only PRAGMA. */
    case SQLITE_PRAGMA:
      return a && !sqlite3_stricmp(a,"data_version") && !b ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_SELECT: case SQLITE_FUNCTION: case SQLITE_RECURSIVE:
      /* Extension functions can bypass the authorizer's write checks. */
      if (action == SQLITE_FUNCTION && b &&
          (!sqlite3_strnicmp(b,"crsql_",6) || (!sqlite3_strnicmp(b,"murmur_",7) && !managed_policy_sql_function(b)) ||
           !sqlite3_stricmp(b,"load_extension"))) return SQLITE_DENY;
      return SQLITE_OK;
    case SQLITE_READ: {
      int ready = 0;
      if (database && !sqlite3_stricmp(database,"temp") &&
          murmur_search_guard_ready(m->search,a,&ready))
        return ready && !murmur_search_pending(m->search) ? SQLITE_OK : SQLITE_DENY;
      return m->access == 2 || !reserved(a) ? SQLITE_OK : SQLITE_DENY;
    }
    case SQLITE_INSERT: case SQLITE_UPDATE: case SQLITE_DELETE:
      if (m->access == 2 && a && (!sqlite3_stricmp(a,"sqlite_master") ||
          !sqlite3_stricmp(a,"sqlite_temp_master"))) return SQLITE_OK;
      if (action==SQLITE_UPDATE && managed_policy_update_denied(m,a,b)) return SQLITE_DENY;
      return m->access == 1 && !reserved(a) ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_CREATE_INDEX:
      return m->access == 2 && !reserved(b) &&
        (!reserved(a) || (a && !sqlite3_strnicmp(a,"sqlite_autoindex_",17))) ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_DROP_INDEX:
      return m->access == 2 && !reserved(a) && !reserved(b) ? SQLITE_OK : SQLITE_DENY;
    case SQLITE_REINDEX:
      return m->access==2 && !reserved(a)?SQLITE_OK:SQLITE_DENY;
    case SQLITE_CREATE_TABLE: case SQLITE_DROP_TABLE: case SQLITE_ALTER_TABLE:
      if (m->access==2 && managed_policy_ddl_denied(m,action,action==SQLITE_ALTER_TABLE?b:a)) return SQLITE_DENY;
      if (m->access==2 && managed_origin_ddl_denied(m,action,action==SQLITE_ALTER_TABLE?b:a)) return SQLITE_DENY;
      return m->access == 2 && !reserved(action == SQLITE_ALTER_TABLE ? b : a)
          ? SQLITE_OK : SQLITE_DENY;
    default: return SQLITE_DENY;
  }
}
static int exec(murmur_managed *m, const char *sql, int access) {
  m->access = access;
  int rc = sqlite3_exec(m->db,sql,nullptr,nullptr,nullptr);
  m->access = 0;
  return rc;
}
static void close_database(murmur_managed *m) {
  if (!m->db) return;
  sqlite3_set_authorizer(m->db,nullptr,nullptr);
  if (!sqlite3_get_autocommit(m->db)) sqlite3_exec(m->db,"ROLLBACK",nullptr,nullptr,nullptr);
  /* Like the Go binding, release cr-sqlite's cached statements before close. */
  if (m->crsqlite) sqlite3_exec(m->db,"SELECT crsql_finalize()",nullptr,nullptr,nullptr);
  sqlite3_close_v2(m->db);
  m->db=nullptr;
  if(m->store_ref) { nvCloseStoreRef(m->store_ref); m->store_ref=0; }
  m->origin.reset();
}
extern "C" int murmur_managed_open(const char *path, const uint8_t key[32], murmur_managed_t **out) {
  if (!out) return SQLITE_MISUSE;
  *out = nullptr;
  if (!path || !*path || !key) return SQLITE_MISUSE;
  try {
    std::string canon = murmurCanonName(path);
    auto m = std::make_unique<murmur_managed>();
    {
      std::lock_guard<std::mutex> lock(registry_mu);
      m->coordinator = registry[canon].lock();
      if (!m->coordinator) registry[canon] = m->coordinator = std::make_shared<Coordinator>();
    }
    if (!m->coordinator->scheduler) return SQLITE_NOMEM;
    int rc = murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr);
    if (rc) return rc;
    rc = murmur_vfs_register(0,0);
    if (!rc) rc = sqlite3_open_v2(canon.c_str(), &m->db,
        SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,"sqlite-murmur");
    if (!rc) rc = murmur_db_key(m->db,key);
    if (!rc) { void *db_ref=nullptr,*store=nullptr; rc=nvOpenStoreRef(canon.c_str(),0,0,&m->store_ref,&db_ref,&store); }
    if (!rc) { rc = murmur_crsqlite_init(m->db); m->crsqlite=!rc; }
    if (!rc) rc = sqlite3_exec(m->db,"PRAGMA temp_store=MEMORY",nullptr,nullptr,nullptr);
    if (!rc) rc = sqlite3_exec(m->db,
      "BEGIN IMMEDIATE;"
      "CREATE TABLE IF NOT EXISTS murmur_managed_generation(singleton INTEGER PRIMARY KEY CHECK(singleton=1), generation INTEGER NOT NULL);"
      "INSERT OR IGNORE INTO murmur_managed_generation VALUES(1,0);"
      "CREATE TABLE IF NOT EXISTS murmur_managed_tables(name TEXT PRIMARY KEY,id BLOB NOT NULL UNIQUE CHECK(length(id)=16));"
      "CREATE TABLE IF NOT EXISTS murmur_managed_columns(table_id BLOB NOT NULL,name TEXT NOT NULL,id BLOB NOT NULL UNIQUE CHECK(length(id)=16),PRIMARY KEY(table_id,name));"
      "CREATE TABLE IF NOT EXISTS murmur_managed_search(column_id BLOB PRIMARY KEY,fts INTEGER NOT NULL,dimensions INTEGER NOT NULL,distance INTEGER NOT NULL);"
      "COMMIT;",nullptr,nullptr,nullptr);
    if (!rc) rc = managed_policy_initialize(m.get());
    if (!rc) rc = managed_origin_initialize(m.get());
    if (!rc) rc = managed_schema_initialize(m.get());
    if (!rc) rc = managed_search_sync(m.get());
    murmur_scheduler_release(m->coordinator->scheduler);
    if (rc) { managed_search_stop(m.get()); close_database(m.get()); return rc; }
    sqlite3_set_authorizer(m->db,authorize,m.get());
    try { managed_search_start(m.get()); }
    catch (...) {
      managed_search_stop(m.get());
      close_database(m.get());
      return SQLITE_NOMEM;
    }
    *out = m.release();
    return SQLITE_OK;
  } catch (...) { return SQLITE_NOMEM; }
}
extern "C" void murmur_managed_close(murmur_managed_t *m) {
  if (!m) return;
  managed_search_stop(m);
  close_database(m);
  delete m;
}
extern "C" void murmur_managed_scheduler_stats(murmur_managed_t *m,murmur_scheduler_stats_t *out) {
  if (m) murmur_scheduler_snapshot(m->coordinator->scheduler,out);
}
extern "C" int murmur_managed_transaction(murmur_managed_t *m, murmur_writer_class_t cls,
    int64_t timeout, murmur_cancel_fn cancel, void *cancel_ctx,
    murmur_transaction_fn fn, void *ctx) {
  if (!m || !fn) return SQLITE_MISUSE;
  int rc = murmur_scheduler_acquire(m->coordinator->scheduler,cls,timeout,cancel,cancel_ctx);
  if (rc) return rc;
  rc = managed_search_sync(m);
  if (!rc) rc=managed_policy_sync(m);
  if (!rc) rc=managed_origin_sync(m);
  if (rc) { murmur_scheduler_release(m->coordinator->scheduler); return rc; }
  rc = exec(m,"BEGIN IMMEDIATE",3);
  int64_t from=-1;
  bool signed_record=false;
  if (!rc) {
    rc=managed_origin_begin(m,&from);
    murmur_transaction tx{m,std::this_thread::get_id()};
    m->active_transaction=&tx;
    try { if(!rc) rc = fn(&tx,ctx); } catch (...) { rc = SQLITE_ABORT; }
    m->active_transaction=nullptr;
    if (!rc && cancel && cancel(cancel_ctx)) rc = SQLITE_ABORT;
    if (!rc) rc=managed_origin_finish(m,from,&signed_record);
    if (!rc) rc = exec(m,"COMMIT",3);
    if (rc) exec(m,"ROLLBACK",3);
    else if(signed_record) rc=nvStoreFlush(m->store_ref);
  }
  murmur_scheduler_release(m->coordinator->scheduler);
  return rc;
}
extern "C" int murmur_transaction_execute(murmur_transaction_t *tx,const char *sql,
    const murmur_value_t *args,size_t count,murmur_row_fn row,void *ctx) {
  if (!tx || !sql || (count && !args) || count > INT_MAX || tx->thread != std::this_thread::get_id()) return SQLITE_MISUSE;
  auto *m = tx->owner;
  struct RestoreAccess { murmur_managed *m; int old; ~RestoreAccess() { m->access=old; } } restore{m,m->access};
  sqlite3_stmt *st = nullptr;
  const char *tail = nullptr;
  m->access = 1;
  /* Legacy prepare deliberately disables automatic reprepare at step time.
   * Application SQL is authorized here, while engine SQL issued by vetted
   * extension functions executes under access=4 below. Schema invalidation
   * returns SQLITE_SCHEMA instead of recompiling application SQL privileged. */
  int rc = sqlite3_prepare(m->db,sql,-1,&st,&tail);
  m->access = 0;
  if (!rc && (!st || (size_t)sqlite3_bind_parameter_count(st) != count)) rc = SQLITE_MISUSE;
  /* Permit whitespace/comments, but never execute a second statement. */
  if (!rc) {
    sqlite3_stmt *extra = nullptr;
    m->access = 1;
    int more = sqlite3_prepare_v2(m->db,tail,-1,&extra,nullptr);
    m->access = 0;
    if (more || extra) rc = SQLITE_MISUSE;
    sqlite3_finalize(extra);
  }
  for (size_t i=0; !rc && i<count; ++i) {
    const auto &v = args[i];
    if (v.bytes > INT_MAX || (!v.data && v.bytes)) { rc = SQLITE_MISUSE; break; }
    switch(v.type) {
      case MURMUR_NULL: rc=sqlite3_bind_null(st,i+1); break;
      case MURMUR_INTEGER: rc=sqlite3_bind_int64(st,i+1,v.integer); break;
      case MURMUR_REAL: rc=sqlite3_bind_double(st,i+1,v.real); break;
      case MURMUR_TEXT: rc=sqlite3_bind_text(st,i+1,(const char *)(v.data?v.data:""),v.bytes,SQLITE_TRANSIENT); break;
      case MURMUR_BLOB: rc=sqlite3_bind_blob(st,i+1,v.data?v.data:"",v.bytes,SQLITE_TRANSIENT); break;
      default: rc=SQLITE_MISUSE;
    }
  }
  if (!rc) {
    m->access = 4;
    try {
      while ((rc=sqlite3_step(st))==SQLITE_ROW) {
        if (!row) continue;
        std::vector<murmur_value_t> values(sqlite3_column_count(st));
        for (size_t i=0;i<values.size();++i) {
          auto &v=values[i];
          switch(sqlite3_column_type(st,i)) {
            case SQLITE_INTEGER: v.type=MURMUR_INTEGER; v.integer=sqlite3_column_int64(st,i); break;
            case SQLITE_FLOAT: v.type=MURMUR_REAL; v.real=sqlite3_column_double(st,i); break;
            case SQLITE_TEXT: v.type=MURMUR_TEXT; v.data=sqlite3_column_text(st,i); v.bytes=sqlite3_column_bytes(st,i); break;
            case SQLITE_BLOB: v.type=MURMUR_BLOB; v.data=sqlite3_column_blob(st,i); v.bytes=sqlite3_column_bytes(st,i); break;
            default: v.type=MURMUR_NULL;
          }
        }
        if (row(ctx,values.size(),values.data())) { rc=SQLITE_ABORT; break; }
      }
    } catch (...) { rc=SQLITE_NOMEM; }
    m->access = 0;
    if (rc==SQLITE_DONE) rc=SQLITE_OK;
  }
  int final_rc=sqlite3_finalize(st);
  if(rc==SQLITE_ERROR && final_rc!=SQLITE_OK) return final_rc;
  return rc ? rc : final_rc;
}
extern "C" int murmur_managed_migrate_mapped(murmur_managed_t *m,const char *sql,
    const murmur_rename_t *maps,size_t n) {
  if (!m || !sql || (n && !maps)) return SQLITE_MISUSE;
  int rc=murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr);
  if (rc) return rc;
  rc=managed_search_sync(m);
  if (!rc) rc=managed_policy_sync(m);
  if (!rc) rc=managed_origin_sync(m);
  if (rc) { murmur_scheduler_release(m->coordinator->scheduler); return rc; }
  rc=exec(m,"BEGIN IMMEDIATE",3);
  ManagedSearchChange search_change;
  auto previous_policies=m->policies;
  m->policy_altered=false;
  m->schema_migration.reset();
  if (!rc) {
    rc=managed_schema_migration_begin(m,maps,n);
    for (size_t i=0;!rc && i<n;++i) {
      const auto &map=maps[i];
      if (!map.table || (map.column && !map.new_column) || (!map.column && !map.new_table)) { rc=SQLITE_MISUSE; break; }
      sqlite3_stmt *st=nullptr;
      m->access=3;
      rc=sqlite3_prepare_v2(m->db,map.column ?
        "UPDATE murmur_managed_columns SET name=?1 WHERE name=?2 AND table_id=(SELECT id FROM murmur_managed_tables WHERE name=?3)" :
        "UPDATE murmur_managed_tables SET name=?1 WHERE name=?2",-1,&st,nullptr);
      if (!rc) rc=sqlite3_bind_text(st,1,map.column?map.new_column:map.new_table,-1,SQLITE_TRANSIENT);
      if (!rc) rc=sqlite3_bind_text(st,2,map.column?map.column:map.table,-1,SQLITE_TRANSIENT);
      if (!rc && map.column) rc=sqlite3_bind_text(st,3,map.table,-1,SQLITE_TRANSIENT);
      if (!rc) { int step=sqlite3_step(st); rc=step==SQLITE_DONE ? (sqlite3_changes(m->db)==1?SQLITE_OK:SQLITE_NOTFOUND):step; }
      sqlite3_finalize(st); m->access=0;
      /* A mapping entry describes either a column or table rename, not both. */
      if (!rc && map.column && map.new_table) rc=SQLITE_MISUSE;
    }
    if (!rc) rc=exec(m,sql,2);
    if (!rc) rc=managed_schema_migration_finish(m);
    if (!rc) rc=exec(m,
      "INSERT OR IGNORE INTO murmur_managed_tables SELECT name,randomblob(16) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'murmur_%' AND name NOT LIKE '%__crsql%' AND name NOT LIKE 'crsql_%';"
      "INSERT OR IGNORE INTO murmur_managed_columns SELECT t.id,p.name,randomblob(16) FROM murmur_managed_tables t JOIN pragma_table_info(t.name) p;"
      "DELETE FROM murmur_managed_columns WHERE NOT EXISTS(SELECT 1 FROM murmur_managed_tables t JOIN pragma_table_info(t.name) p WHERE t.id=murmur_managed_columns.table_id AND p.name=murmur_managed_columns.name);"
      "DELETE FROM murmur_managed_columns WHERE table_id IN (SELECT id FROM murmur_managed_tables WHERE name NOT IN (SELECT name FROM sqlite_schema WHERE type='table'));"
      "DELETE FROM murmur_managed_tables WHERE name NOT IN (SELECT name FROM sqlite_schema WHERE type='table');"
      "DELETE FROM murmur_managed_search WHERE column_id NOT IN(SELECT id FROM murmur_managed_columns);"
      "UPDATE murmur_managed_generation SET generation=generation+1 WHERE singleton=1;",3);
    if (!rc) rc=managed_policy_sync(m,true);
    if (!rc) rc=managed_search_change(m,search_change);
    if (!rc) rc=managed_schema_publish(m);
    if (!rc) rc=exec(m,"COMMIT",3);
    if (rc) exec(m,"ROLLBACK",3);
    if (rc) m->policies=std::move(previous_policies);
    managed_search_complete(m,search_change,!rc);
  }
  m->policy_altered=false;
  m->schema_migration.reset();
  if (!rc) rc=nvStoreFlush(m->store_ref);
  murmur_scheduler_release(m->coordinator->scheduler);
  return rc;
}
extern "C" int murmur_managed_migrate(murmur_managed_t *m,const char *sql) {
  return murmur_managed_migrate_mapped(m,sql,nullptr,0);
}
extern "C" int murmur_managed_set_search(murmur_managed_t *m,const char *table,
    const char *column,int fts,int dims,int distance) {
  if (!m || !table || !column || (fts!=0 && fts!=1) || dims<0 || dims>8192 || distance<0 || distance>2) return SQLITE_MISUSE;
  int rc=murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr);
  if (rc) return rc;
  rc=managed_search_sync(m);
  if (!rc) rc=managed_origin_sync(m);
  if (!rc) rc=managed_schema_require_authority(m,table);
  if (rc) { murmur_scheduler_release(m->coordinator->scheduler); return rc; }
  rc=exec(m,"BEGIN IMMEDIATE",3);
  ManagedSearchChange search_change;
  if (!rc) {
    sqlite3_stmt *st=nullptr;
    m->access=3;
    rc=sqlite3_prepare_v2(m->db,
      "INSERT INTO murmur_managed_search SELECT c.id,?1,?2,?3 FROM murmur_managed_columns c JOIN murmur_managed_tables t ON t.id=c.table_id WHERE t.name=?4 AND c.name=?5 ON CONFLICT(column_id) DO UPDATE SET fts=excluded.fts,dimensions=excluded.dimensions,distance=excluded.distance",-1,&st,nullptr);
    if (!rc) rc=sqlite3_bind_int(st,1,fts);
    if (!rc) rc=sqlite3_bind_int(st,2,dims);
    if (!rc) rc=sqlite3_bind_int(st,3,distance);
    if (!rc) rc=sqlite3_bind_text(st,4,table,-1,SQLITE_TRANSIENT);
    if (!rc) rc=sqlite3_bind_text(st,5,column,-1,SQLITE_TRANSIENT);
    if (!rc) { int step=sqlite3_step(st); rc=step==SQLITE_DONE ? (sqlite3_changes(m->db)==1?SQLITE_OK:SQLITE_NOTFOUND):step; }
    sqlite3_finalize(st); m->access=0;
    if (!rc) rc=exec(m,"UPDATE murmur_managed_generation SET generation=generation+1 WHERE singleton=1",3);
    if (!rc) rc=managed_search_change(m,search_change);
    if (!rc) rc=managed_schema_publish(m);
    if (!rc) rc=exec(m,"COMMIT",3);
    if (rc) exec(m,"ROLLBACK",3);
    managed_search_complete(m,search_change,!rc);
  }
  if (!rc) rc=nvStoreFlush(m->store_ref);
  murmur_scheduler_release(m->coordinator->scheduler);
  return rc;
}
extern "C" int murmur_managed_schema(murmur_managed_t *m,murmur_row_fn row,void *ctx) {
  if (!m || !row) return SQLITE_MISUSE;
  int rc=murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr);
  if (rc) return rc;
  sqlite3_stmt *st=nullptr;
  m->access=3;
  rc=sqlite3_prepare_v2(m->db,"SELECT t.name,t.id,c.name,c.id,coalesce(s.fts,0),coalesce(s.dimensions,0),coalesce(s.distance,0),g.generation FROM murmur_managed_tables t JOIN murmur_managed_columns c ON c.table_id=t.id LEFT JOIN murmur_managed_search s ON s.column_id=c.id CROSS JOIN murmur_managed_generation g ORDER BY t.name,c.name",-1,&st,nullptr);
  if (!rc) {
    while ((rc=sqlite3_step(st))==SQLITE_ROW) {
      murmur_value_t values[8]{};
      for (int i=0;i<8;++i) {
        auto &v=values[i];
        if (i==0 || i==2) { v.type=MURMUR_TEXT; v.data=sqlite3_column_text(st,i); v.bytes=sqlite3_column_bytes(st,i); }
        else if(i==1 || i==3) { v.type=MURMUR_BLOB; v.data=sqlite3_column_blob(st,i); v.bytes=sqlite3_column_bytes(st,i); }
        else { v.type=MURMUR_INTEGER; v.integer=sqlite3_column_int64(st,i); }
      }
      if (row(ctx,8,values)) { rc=SQLITE_ABORT; break; }
    }
    if (rc==SQLITE_DONE) rc=SQLITE_OK;
  }
  sqlite3_finalize(st); m->access=0;
  murmur_scheduler_release(m->coordinator->scheduler);
  return rc;
}
