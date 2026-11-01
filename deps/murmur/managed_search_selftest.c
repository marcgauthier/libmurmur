#include "../../libmurmur.h"
#include "sqlite3.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct indexes { char fts[128],vec[128]; int n,ready,errors; };
static int status(void *ctx,int n,const murmur_value_t *v) {
  struct indexes *s=ctx; assert(n==6 && v[0].bytes<128);
  char *out=!memcmp(v[0].data,"murmur_fts_",11)?s->fts:s->vec;
  memcpy(out,v[0].data,v[0].bytes); out[v[0].bytes]=0;
  s->n++; s->ready+=(int)v[1].integer; s->errors+=v[5].type!=MURMUR_NULL;
  return 0;
}
static int scalar(void *ctx,int n,const murmur_value_t *v) {
  assert(n==1 && v[0].type==MURMUR_INTEGER); *(int64_t *)ctx=v[0].integer; return 0;
}
struct query { const char *sql; int64_t value; };
static int query(murmur_transaction_t *tx,void *ctx) {
  struct query *q=ctx; q->value=-1;
  return murmur_transaction_execute(tx,q->sql,NULL,0,scalar,&q->value);
}
static int run(murmur_managed_t *m,const char *sql,int64_t *value) {
  struct query q={sql,-1};
  int rc=murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,NULL,NULL,query,&q);
  if(value) *value=q.value;
  return rc;
}
static struct indexes indexes(murmur_managed_t *m) {
  struct indexes s={0}; assert(murmur_managed_search_status(m,status,&s)==SQLITE_OK); return s;
}
static void found(murmur_managed_t *m,const char *idx,const char *term,int64_t count) {
  char sql[512]; int64_t value=-1;
  snprintf(sql,sizeof(sql),"SELECT count(*) FROM temp.\"%s\" WHERE \"%s\" MATCH '%s'",idx,idx,term);
  int rc=run(m,sql,&value);
  if(rc || value!=count) fprintf(stderr,"search rc=%d count=%lld expected=%lld sql=%s\n",rc,(long long)value,(long long)count,sql);
  assert(rc==SQLITE_OK && value==count);
}
int main(void) {
  char root[]="/tmp/murmur-managed-search-XXXXXX",path[256];
  assert(mkdtemp(root)); snprintf(path,sizeof(path),"%s/store",root);
  uint8_t key[32]={4}; murmur_managed_t *a=NULL,*b=NULL;
  assert(murmur_managed_open(path,key,&a)==SQLITE_OK);
  assert(murmur_managed_migrate(a,"CREATE TABLE docs(id INTEGER PRIMARY KEY,body TEXT,title TEXT,embedding BLOB)")==SQLITE_OK);
  assert(run(a,"INSERT INTO docs VALUES(1,'hello world','first',x'0000803f00000000')",NULL)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","id",1,0,0)!=SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","body",1,0,0)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","embedding",0,2,0)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  struct indexes s=indexes(a); assert(s.n==2 && s.ready==2 && s.errors==0);
  found(a,s.fts,"hello",1);
  /* A rejected declaration must restore the existing manager and temp tables. */
  assert(murmur_managed_set_search(a,"docs","embedding",1,2,0)!=SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  found(a,s.fts,"hello",1);
  char sql[512]; int64_t value=-1;
  snprintf(sql,sizeof(sql),"SELECT rowid FROM temp.\"%s\" WHERE embedding MATCH '[1,0]' AND k=1",s.vec);
  assert(run(a,sql,&value)==SQLITE_OK && value==1);
  /* A second handle gets its own temp indexes, sees data and metadata changes. */
  assert(murmur_managed_open(path,key,&b)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(b)==SQLITE_OK);
  found(b,s.fts,"hello",1);
  assert(run(a,"UPDATE docs SET body='changed' WHERE id=1",NULL)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(b)==SQLITE_OK);
  found(b,s.fts,"changed",1); found(b,s.fts,"hello",0);
  assert(murmur_managed_set_search(b,"docs","title",1,0,0)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  found(a,s.fts,"first",1);
  /* Renames preserve stable names; failed DDL leaves old indexes usable. */
  murmur_rename_t map={"docs",NULL,"body","content"};
  assert(murmur_managed_migrate_mapped(a,"ALTER TABLE docs RENAME COLUMN body TO content",&map,1)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  struct indexes renamed=indexes(a); assert(!strcmp(s.fts,renamed.fts));
  assert(murmur_managed_migrate(a,"ALTER TABLE docs RENAME TO abandoned; CREATE TABLE abandoned(x)")!=SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  found(a,s.fts,"changed",1);
  /* Persist declarations across close/reopen, and report recoverable build errors. */
  murmur_managed_close(b); murmur_managed_close(a);
  assert(murmur_managed_open(path,key,&a)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  found(a,s.fts,"changed",1);
  assert(run(a,"UPDATE docs SET embedding=x'00' WHERE id=1",NULL)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)!=SQLITE_OK);
  struct indexes broken=indexes(a); assert(broken.errors>=1 && broken.ready<2);
  assert(run(a,sql,&value)!=SQLITE_OK);
  assert(run(a,"UPDATE docs SET embedding=x'0000803f00000000' WHERE id=1",NULL)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  assert(run(a,sql,&value)==SQLITE_OK && value==1);
  /* Two failures in one turn retain separate owned diagnostics. */
  assert(murmur_managed_migrate(a,"ALTER TABLE docs ADD COLUMN second BLOB")==SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","second",0,2,0)==SQLITE_OK);
  assert(run(a,"UPDATE docs SET embedding=x'00',second=x'00'",NULL)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)!=SQLITE_OK);
  assert(indexes(a).errors==2);
  assert(run(a,"UPDATE docs SET embedding=x'0000803f00000000',second=x'000000000000803f'",NULL)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","second",0,0,0)==SQLITE_OK);
  /* Turning an index off drops its tables; background turns publish new ones. */
  assert(murmur_managed_set_search(a,"docs","embedding",0,0,0)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  assert(indexes(a).n==1);
  assert(run(a,sql,&value)!=SQLITE_OK);
  assert(run(a,"INSERT INTO docs(id,content,title) VALUES(2,'background','second')",NULL)==SQLITE_OK);
  for(int i=0;i<100;++i) { if(indexes(a).ready==1) break; usleep(10000); }
  assert(indexes(a).ready==1); found(a,s.fts,"background",1);
  murmur_rename_t table_map={"docs","papers",NULL,NULL};
  assert(murmur_managed_migrate_mapped(a,"ALTER TABLE docs RENAME TO papers",&table_map,1)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  assert(!strcmp(indexes(a).fts,s.fts)); found(a,s.fts,"background",1);
  murmur_managed_close(a);
  assert(murmur_managed_open(path,key,&a)==SQLITE_OK);
  assert(murmur_managed_refresh_indexes(a)==SQLITE_OK);
  found(a,s.fts,"background",1);
  murmur_managed_close(a);
  puts("MANAGED-SEARCH-OK"); return 0;
}
