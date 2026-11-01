#include "native.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <unistd.h>

#ifdef MURMUR_MIGRATION_CRASH
#include <fcntl.h>
static thread_local int migration_crash=0;
static thread_local const char *hold_marker=nullptr;
extern "C" int __real_sqlite3_exec(sqlite3 *,const char *,int (*)(void *,int,char **,char **),void *,char **);
extern "C" int __wrap_sqlite3_exec(sqlite3 *db,const char *sql,int (*callback)(void *,int,char **,char **),void *ctx,char **error) {
  if(migration_crash==1 && !strcmp(sql,"COMMIT")) _exit(83);
  if(migration_crash==3 && !strcmp(sql,"COMMIT")) {
    int fd=open(hold_marker,O_CREAT|O_EXCL|O_WRONLY,0600);
    if(fd<0 || write(fd,"1",1)!=1) _exit(85);
    close(fd);
    for(;;) pause(); /* Actual rows/state/log are staged, COMMIT has not run. */
  }
  return __real_sqlite3_exec(db,sql,callback,ctx,error);
}
#endif

namespace {
struct Rows { std::string json="["; bool first=true; };
int row(void *ctx,int count,const murmur_value_t *values) {
  try {
    auto &out=*(Rows *)ctx;
    if(!out.first) out.json+=',';
    out.first=false; out.json+='[';
    static const char digits[]="0123456789abcdef";
    for(int i=0;i<count;++i) {
      if(i) out.json+=',';
      auto &v=values[i]; out.json+="{\"type\":"+std::to_string(v.type)+",\"integer\":"+std::to_string(v.integer)+",\"real\":\"";
      char real[64]; snprintf(real,sizeof(real),"%.17g",v.real); out.json+=real; out.json+="\",\"hex\":\"";
      if(v.bytes>(16u<<20) || out.json.size()>(32u<<20)-v.bytes*2) return 1;
      auto *p=(const uint8_t *)v.data;
      for(size_t n=0;n<v.bytes;++n) { out.json+=digits[p[n]>>4]; out.json+=digits[p[n]&15]; }
      out.json+="\"}";
    }
    out.json+=']'; return 0;
  } catch(...) { return 1; }
}
int finish(Rows &rows,mh_result *out,int rc) {
  if(rc) return rc;
  rows.json+=']'; out->json=(char *)malloc(rows.json.size()); if(!out->json) return 7;
  memcpy(out->json,rows.json.data(),rows.json.size()); out->bytes=rows.json.size(); return 0;
}
struct Transaction { const char **sql; size_t count; Rows rows; };
int transaction(murmur_transaction_t *tx,void *ctx) {
  auto &work=*(Transaction *)ctx;
  for(size_t i=0;i<work.count;++i) { int rc=murmur_transaction_execute(tx,work.sql[i],nullptr,0,row,&work.rows); if(rc) return rc; }
  return 0;
}
}
extern "C" int mh_execute(murmur_managed_t *db,int cls,const char **sql,size_t count,mh_result *out) {
  *out={}; try {
    Transaction work{sql,count,{}};
    int rc=murmur_managed_transaction(db,(murmur_writer_class_t)cls,10000,nullptr,nullptr,transaction,&work);
    return finish(work.rows,out,rc);
  } catch(...) { return 7; }
}
extern "C" int mh_rows(murmur_managed_t *db,int which,mh_result *out) {
  *out={}; try {
    Rows rows; int rc=21;
    if(which==0) rc=murmur_managed_origin_progress(db,row,&rows);
    if(which==1) rc=murmur_managed_search_status(db,row,&rows);
    if(which==2) rc=murmur_managed_schema(db,row,&rows);
    if(which==3) rc=murmur_managed_policy_status(db,row,&rows);
    return finish(rows,out,rc);
  } catch(...) { return 7; }
}
extern "C" int mh_apply(murmur_managed_t *db,const void *data,size_t bytes,int schema,int *changed) {
  *changed=0; if(bytes<MURMUR_ORIGIN_ENVELOPE_BYTES || bytes>(64u<<20)+MURMUR_ORIGIN_ENVELOPE_BYTES) return 11;
  murmur_origin_record_t r{}; int rc=murmur_origin_envelope_decode(data,MURMUR_ORIGIN_ENVELOPE_BYTES,&r.envelope); if(rc) return rc;
  r.payload=(uint8_t *)data+MURMUR_ORIGIN_ENVELOPE_BYTES; r.bytes=bytes-MURMUR_ORIGIN_ENVELOPE_BYTES;
  return schema?murmur_managed_schema_adopt(db,&r,changed):murmur_managed_origin_apply(db,&r,changed);
}
extern "C" int mh_capabilities(void) {
#ifdef MURMUR_MIGRATION_CRASH
  return 1;
#else
  return 0;
#endif
}
extern "C" int mh_migrate(murmur_managed_t *db,const char *sql,const murmur_rename_t *maps,size_t count,int crash) {
  if(crash<0 || crash>2) return 21;
#ifdef MURMUR_MIGRATION_CRASH
  migration_crash=crash;
  int rc=murmur_managed_migrate_mapped(db,sql,maps,count); migration_crash=0;
  if(!rc && crash==2) _exit(84);
  return rc;
#else
  return crash?21:murmur_managed_migrate_mapped(db,sql,maps,count);
#endif
}
extern "C" int mh_execute_hold(murmur_managed_t *db,int cls,const char **sql,size_t count,const char *marker,mh_result *out) {
#ifdef MURMUR_MIGRATION_CRASH
  migration_crash=3; hold_marker=marker;
  int rc=mh_execute(db,cls,sql,count,out); migration_crash=0; hold_marker=nullptr; return rc;
#else
  (void)db; (void)cls; (void)sql; (void)count; (void)marker; *out={}; return 21;
#endif
}
