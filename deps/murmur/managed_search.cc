#include "managed_internal.h"
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <utility>

namespace {
struct Access {
  murmur_managed *m;
  int previous;
  Access(murmur_managed *m):m(m),previous(m->access) { m->access=3; }
  ~Access() { m->access=previous; }
};
struct Statement {
  sqlite3_stmt *p=nullptr;
  ~Statement() { sqlite3_finalize(p); }
};
struct SearchDelete { void operator()(murmur_search_manager_t *p) const { murmur_search_close(p); } };
using Search=std::unique_ptr<murmur_search_manager_t,SearchDelete>;
int result(murmur_managed *m,murmur_search_status_t status,int sqlrc,char *detail) {
  std::unique_ptr<char,decltype(&free)> owned(detail,&free);
  if (status!=MURMUR_SEARCH_OK) m->search_error=detail?detail:"search maintenance failed";
  if (status==MURMUR_SEARCH_OK) return SQLITE_OK;
  if (status==MURMUR_SEARCH_NOMEM) return SQLITE_NOMEM;
  return sqlrc?sqlrc:SQLITE_ERROR;
}
int number(murmur_managed *m,const char *sql,int64_t &out) {
  Statement st;
  int rc=sqlite3_prepare_v2(m->db,sql,-1,&st.p,nullptr);
  if (rc) return rc;
  rc=sqlite3_step(st.p);
  if (rc!=SQLITE_ROW) return rc==SQLITE_DONE?SQLITE_CORRUPT:rc;
  out=sqlite3_column_int64(st.p,0);
  return SQLITE_OK;
}
struct Definition {
  std::string name,source,column;
  std::vector<std::string> columns;
  std::vector<const char *> pointers;
  int dims=0,distance=0;
};
int definitions(murmur_managed *m,Search &search,std::vector<std::string> &sources) {
  Statement st;
  int rc=sqlite3_prepare_v2(m->db,
    "SELECT t.name,lower(hex(t.id)),c.name,lower(hex(c.id)),s.fts,s.dimensions,s.distance "
    "FROM murmur_managed_search s JOIN murmur_managed_columns c ON c.id=s.column_id "
    "JOIN murmur_managed_tables t ON t.id=c.table_id ORDER BY t.id,c.id",-1,&st.p,nullptr);
  if (rc) return rc;
  std::map<std::string,Definition> owned;
  while ((rc=sqlite3_step(st.p))==SQLITE_ROW) {
    auto text=[&](int i) { return std::string((const char *)sqlite3_column_text(st.p,i)); };
    auto table=text(0),tid=text(1),col=text(2),cid=text(3);
    if (sqlite3_column_int(st.p,4)) {
      auto name="murmur_fts_"+tid;
      auto &d=owned[name]; d.name=name; d.source=table; d.columns.push_back(col);
    }
    int dims=sqlite3_column_int(st.p,5);
    if (dims) {
      auto name="murmur_vec_"+tid+"_"+cid;
      auto &d=owned[name]; d.name=name; d.source=table; d.column=col;
      d.dims=dims; d.distance=sqlite3_column_int(st.p,6);
    }
  }
  if (rc!=SQLITE_DONE) return rc;
  std::vector<murmur_search_def_t> defs;
  for (auto &pair:owned) {
    auto &d=pair.second;
    murmur_search_def_t def{};
    def.name=d.name.c_str(); def.source_table=d.source.c_str();
    if (d.dims) {
      def.tag=MURMUR_SEARCH_VECTOR; def.vector_column=d.column.c_str();
      def.dimensions=d.dims; def.distance=(murmur_distance_t)d.distance;
    } else {
      def.tag=MURMUR_SEARCH_FTS5;
      for (auto &c:d.columns) d.pointers.push_back(c.c_str());
      def.columns=d.pointers.data(); def.n_columns=d.pointers.size();
    }
    defs.push_back(def);
    sources.push_back(d.source);
  }
  murmur_search_manager_t *p=nullptr;
  char *detail=nullptr;
  auto status=murmur_search_open(defs.data(),defs.size(),8u<<20,256,&p,&detail);
  search.reset(p);
  return result(m,status,0,detail);
}
}

int managed_search_change(murmur_managed *m,ManagedSearchChange &change) {
  Access access(m);
  try {
    Search candidate;
    std::vector<std::string> sources;
    int rc=definitions(m,candidate,sources);
    if (rc) return rc;
    change.generation=m->search_generation;
    change.sources=m->search_sources;
    if (m->search) {
      change.old=murmur_search_clone(m->search);
      if (!change.old) return SQLITE_NOMEM;
    }
    change.changed=true;
    int sqlrc=0; char *detail=nullptr;
    if (m->search) {
      auto status=murmur_search_drop(m->search,m->db,&detail,&sqlrc);
      rc=result(m,status,sqlrc,detail);
      if (rc) return rc;
    }
    detail=nullptr; sqlrc=0;
    auto status=murmur_search_register(m->db,candidate.get(),&detail,&sqlrc);
    rc=result(m,status,sqlrc,detail);
    if (rc) return rc;
    detail=nullptr; sqlrc=0;
    status=murmur_search_sync_schema(candidate.get(),m->db,0,&detail,&sqlrc);
    rc=result(m,status,sqlrc,detail);
    if (rc) return rc;
    if (m->search) murmur_search_detach(m->search,m->db);
    murmur_search_close(m->search);
    m->search=candidate.release();
    murmur_search_attach(m->search,m->db);
    m->search_sources=std::move(sources);
    return number(m,"SELECT generation FROM murmur_managed_generation WHERE singleton=1",m->search_generation);
  } catch (...) { return SQLITE_NOMEM; }
}
void managed_search_complete(murmur_managed *m,ManagedSearchChange &change,bool commit) {
  if (!change.changed) return;
  if (!commit) {
    if (m->search) murmur_search_detach(m->search,m->db);
    murmur_search_close(m->search);
    m->search=change.old; change.old=nullptr;
    m->search_generation=change.generation;
    m->search_sources=std::move(change.sources);
    if (m->search) murmur_search_attach(m->search,m->db);
  }
  murmur_search_close(change.old); change.old=nullptr;
  change.changed=false;
}
int managed_search_sync(murmur_managed *m,bool force) {
  Access access(m);
  int64_t generation=0,version=0;
  int rc=number(m,"SELECT generation FROM murmur_managed_generation WHERE singleton=1",generation);
  if (!rc) rc=number(m,"PRAGMA data_version",version);
  if (rc) return rc;
  if (!m->search || generation!=m->search_generation || force) {
    rc=sqlite3_exec(m->db,"SAVEPOINT murmur_managed_search",nullptr,nullptr,nullptr);
    if (rc) return rc;
    ManagedSearchChange change;
    rc=managed_search_change(m,change);
    if (!rc) rc=sqlite3_exec(m->db,"RELEASE murmur_managed_search",nullptr,nullptr,nullptr);
    if (rc) sqlite3_exec(m->db,"ROLLBACK TO murmur_managed_search; RELEASE murmur_managed_search",nullptr,nullptr,nullptr);
    managed_search_complete(m,change,!rc);
  } else if (version!=m->search_data_version) {
    for (auto &source:m->search_sources) murmur_search_note_table(m->search,source.c_str());
  }
  if (!rc) m->search_data_version=version;
  return rc;
}
int managed_search_work(murmur_managed *m,bool drain) {
  Access access(m);
  int rc=managed_search_sync(m);
  if (rc) return rc;
  char *detail=nullptr; int sqlrc=0;
  auto status=drain?murmur_search_refresh(m->search,m->db,nullptr,nullptr,&detail,&sqlrc):
    murmur_search_tick(m->search,m->db,nullptr,nullptr,&detail,&sqlrc);
  rc=result(m,status,sqlrc,detail);
  if (!rc) m->search_error.clear();
  return rc;
}
void managed_search_start(murmur_managed *m) {
  m->search_worker=std::thread([m] {
    std::unique_lock<std::mutex> lock(m->worker_mu);
    while (!m->worker_cv.wait_for(lock,std::chrono::milliseconds(100),[m]{return m->worker_stop;})) {
      lock.unlock();
      int rc=murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,0,nullptr,nullptr);
      if (!rc) {
        try { managed_search_work(m,false); }
        catch (...) { /* Retry on the next bounded turn. */ }
        murmur_scheduler_release(m->coordinator->scheduler);
      }
      lock.lock();
    }
  });
}
void managed_search_stop(murmur_managed *m) {
  { std::lock_guard<std::mutex> lock(m->worker_mu); m->worker_stop=true; }
  m->worker_cv.notify_all();
  if (m->search_worker.joinable()) m->search_worker.join();
  if (m->search) murmur_search_detach(m->search,m->db);
  murmur_search_close(m->search); m->search=nullptr;
}
extern "C" int murmur_managed_refresh_indexes(murmur_managed_t *m) {
  if (!m) return SQLITE_MISUSE;
  int rc=murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr);
  if (rc) return rc;
  try { rc=managed_search_work(m,true); } catch (...) { rc=SQLITE_NOMEM; }
  murmur_scheduler_release(m->coordinator->scheduler);
  return rc;
}
extern "C" int murmur_managed_search_status(murmur_managed_t *m,murmur_row_fn row,void *ctx) {
  if (!m || !row) return SQLITE_MISUSE;
  int rc=murmur_scheduler_acquire(m->coordinator->scheduler,MURMUR_WRITER_MAINTENANCE,-1,nullptr,nullptr);
  if (rc) return rc;
  murmur_search_index_status_t *states=nullptr;
  size_t n=0;
  try {
    rc=managed_search_sync(m);
    if (!rc) rc=result(m,murmur_search_status(m->search,&states,&n),0,nullptr);
    bool pending=murmur_search_pending(m->search);
    for (size_t i=0;!rc && i<n;++i) {
      auto &s=states[i]; murmur_value_t values[6]{};
      values[0].type=MURMUR_TEXT; values[0].data=s.name; values[0].bytes=strlen(s.name);
      for (int j=1;j<5;++j) values[j].type=MURMUR_INTEGER;
      values[1].integer=s.ready && !pending; values[2].integer=s.rebuilding;
      values[3].integer=s.pending_keys; values[4].integer=s.queued_bytes;
      if (s.error) { values[5].type=MURMUR_TEXT; values[5].data=s.error; values[5].bytes=strlen(s.error); }
      if (row(ctx,6,values)) rc=SQLITE_ABORT;
    }
  } catch (...) { rc=SQLITE_NOMEM; }
  murmur_search_status_free(states,n);
  murmur_scheduler_release(m->coordinator->scheduler);
  return rc;
}
