#include "../../libmurmur.h"
#include "sqlite3.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int count_row(void *ctx,int n,const murmur_value_t *v) {
  assert(n==1 && v[0].type==MURMUR_INTEGER);
  *(int64_t *)ctx=v[0].integer;
  return 0;
}
static int insert(murmur_transaction_t *tx,void *ctx) {
  murmur_value_t v={0}; v.type=MURMUR_INTEGER; v.integer=ctx?8:7;
  int rc=murmur_transaction_execute(tx,"INSERT INTO items VALUES(?)",&v,1,NULL,NULL);
  return rc ? rc : (ctx ? SQLITE_ABORT : SQLITE_OK);
}
static int count(murmur_transaction_t *tx,void *ctx) {
  return murmur_transaction_execute(tx,"SELECT count(*) FROM items",NULL,0,count_row,ctx);
}
static int guards(murmur_transaction_t *tx,void *ctx) {
  (void)ctx;
  assert(murmur_transaction_execute(tx,"COMMIT",NULL,0,NULL,NULL)==SQLITE_AUTH);
  assert(murmur_transaction_execute(tx,"CREATE TABLE bypass(x)",NULL,0,NULL,NULL)==SQLITE_AUTH);
  assert(murmur_transaction_execute(tx,"DELETE FROM murmur_managed_tables",NULL,0,NULL,NULL)==SQLITE_AUTH);
  assert(murmur_transaction_execute(tx,"SELECT crsql_site_id()",NULL,0,NULL,NULL)!=SQLITE_OK);
  assert(murmur_transaction_execute(tx,"SELECT 1; SELECT 2",NULL,0,NULL,NULL)==SQLITE_MISUSE);
  return SQLITE_OK;
}
static uint8_t column_id[16];
static int metadata(void *ctx,int n,const murmur_value_t *v) {
  assert(n==8 && v[1].bytes==16 && v[3].bytes==16);
  if (ctx) {
    assert(!memcmp(column_id,v[3].data,16));
    assert(v[4].integer==0 && v[5].integer==0 && v[6].integer==0);
  } else memcpy(column_id,v[3].data,16);
  return 0;
}
int main(void) {
  char root[]="/tmp/murmur-managed-XXXXXX",path[256];
  assert(mkdtemp(root)); snprintf(path,sizeof(path),"%s/store",root);
  uint8_t key[32]={9}; murmur_managed_t *a=NULL,*b=NULL;
  assert(murmur_managed_open(path,key,&a)==SQLITE_OK);
  assert(murmur_managed_migrate(a,"CREATE TABLE items(id INTEGER PRIMARY KEY)")==SQLITE_OK);
  assert(murmur_managed_migrate(a,"CREATE TABLE undone(x); CREATE TABLE items(x)")!=SQLITE_OK);
  assert(murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,NULL,NULL,insert,NULL)==SQLITE_OK);
  assert(murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,NULL,NULL,insert,(void *)1)!=SQLITE_OK);
  int64_t rows=-1;
  assert(murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,NULL,NULL,count,&rows)==SQLITE_OK && rows==1);
  assert(murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,NULL,NULL,guards,NULL)==SQLITE_OK);
  assert(murmur_managed_open(path,key,&b)==SQLITE_OK);
  murmur_scheduler_stats_t sa,sb;
  murmur_managed_scheduler_stats(a,&sa); murmur_managed_scheduler_stats(b,&sb);
  assert(sa.classes[0].acquisitions==sb.classes[0].acquisitions);
  assert(murmur_managed_schema(a,metadata,NULL)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"items","id",1,3,1)!=SQLITE_OK);
  assert(murmur_managed_set_search(a,"items","id",0,0,0)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"items","missing",1,0,0)==SQLITE_NOTFOUND);
  murmur_rename_t map={"items",NULL,"id","renamed"};
  assert(murmur_managed_migrate_mapped(a,"ALTER TABLE items RENAME COLUMN id TO renamed",&map,1)==SQLITE_OK);
  assert(murmur_managed_schema(a,metadata,(void *)1)==SQLITE_OK);
  murmur_managed_close(a); murmur_managed_close(b);
  assert(murmur_managed_open(path,key,&a)==SQLITE_OK);
  assert(murmur_managed_schema(a,metadata,(void *)1)==SQLITE_OK);
  assert(murmur_managed_transaction(a,MURMUR_WRITER_LOCAL,-1,NULL,NULL,count,&rows)==SQLITE_OK && rows==1);
  murmur_managed_close(a);
  printf("MANAGED-OK (%s)\n",root);
  return 0;
}
