#include "../../libmurmur.h"
#include "managed_schema_internal.h"
#include "sha256.h"
#include "sqlite3.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
struct Query { std::string sql; int64_t value=-1; };
static int row(void *ctx,int n,const murmur_value_t *v) { assert(n==1); ((Query *)ctx)->value=v[0].integer; return 0; }
static int transaction(murmur_transaction_t *tx,void *ctx) { auto &q=*(Query *)ctx; return murmur_transaction_execute(tx,q.sql.c_str(),nullptr,0,row,&q); }
static int run(murmur_managed_t *m,const std::string &sql,int64_t *value=nullptr) {
  Query q{sql}; int rc=murmur_managed_transaction(m,MURMUR_WRITER_LOCAL,-1,nullptr,nullptr,transaction,&q);
  if(value) *value=q.value;
  return rc;
}
static void ok(murmur_managed_t *m,const std::string &sql) { int rc=run(m,sql); if(rc) fprintf(stderr,"rc=%d sql=%s\n",rc,sql.c_str()); assert(rc==SQLITE_OK); }
static void adopt(murmur_managed_t *m,const murmur_origin_record_t &r,int changed=1) {
  int applied=-1; int rc=murmur_managed_schema_adopt(m,&r,&applied);
  if(rc) fprintf(stderr,"adopt rc=%d schema sequence=%llu\n",rc,(unsigned long long)r.envelope.sequence);
  assert(rc==SQLITE_OK && applied==changed);
}
static void apply(murmur_managed_t *m,const murmur_origin_record_t &r) { int changed=0; int rc=murmur_managed_origin_apply(m,&r,&changed); if(rc) fprintf(stderr,"apply rc=%d sequence=%llu\n",rc,(unsigned long long)r.envelope.sequence); assert(rc==SQLITE_OK && changed); }
static int fts_status(void *ctx,int n,const murmur_value_t *v) { assert(n==6); if(!memcmp(v[0].data,"murmur_fts_",11)) *(std::string *)ctx=std::string((const char *)v[0].data,v[0].bytes); return 0; }
static std::string fts(murmur_managed_t *m) { std::string name; assert(murmur_managed_refresh_indexes(m)==SQLITE_OK); assert(murmur_managed_search_status(m,fts_status,&name)==SQLITE_OK); assert(!name.empty()); return name; }
static murmur_origin_record_t forged(const murmur_origin_record_t &base,std::string &body,const uint8_t seed[32],uint64_t sequence) {
  auto r=base; r.payload=(uint8_t *)body.data(); r.bytes=body.size(); r.envelope.sequence=sequence;
  murmur_sha256((const uint8_t *)body.data(),body.size(),r.envelope.schema);
  assert(murmur_origin_sign(&r.envelope,seed,r.payload,r.bytes)==SQLITE_OK); return r;
}
int main() {
  char root[]="/tmp/murmur-managed-schema-XXXXXX",pa[256],pb[256],pc[256]; assert(mkdtemp(root));
  snprintf(pa,sizeof(pa),"%s/a",root); snprintf(pb,sizeof(pb),"%s/b",root); snprintf(pc,sizeof(pc),"%s/c",root);
  uint8_t key[32]={1},db[16]={9},na[16]={1},nb[16]={2},nc[16]={3},sa[32]={4},sb[32]={5},sc[32]={6};
  murmur_managed_t *a=nullptr,*b=nullptr,*c=nullptr;
  assert(murmur_managed_open(pa,key,&a)==SQLITE_OK); assert(murmur_managed_open(pb,key,&b)==SQLITE_OK); assert(murmur_managed_open(pc,key,&c)==SQLITE_OK);
  assert(murmur_managed_migrate(a,"CREATE TABLE docs(id INTEGER NOT NULL PRIMARY KEY,body TEXT,embedding BLOB)")==SQLITE_OK);
  assert(murmur_managed_origin_configure(a,db,na,sa)==SQLITE_OK); assert(murmur_managed_origin_configure(b,db,nb,sb)==SQLITE_OK); assert(murmur_managed_origin_configure(c,db,nc,sc)==SQLITE_OK);
  murmur_origin_identity_t ia; assert(murmur_managed_origin_identity(a,&ia)==SQLITE_OK);
  for(auto *peer:{b,c}) { assert(murmur_managed_origin_trust(peer,&ia,1)==SQLITE_OK); assert(murmur_managed_schema_master(peer,na)==SQLITE_OK); }
  assert(murmur_managed_set_replication(a,"docs",1)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","body",1,0,0)==SQLITE_OK);
  assert(murmur_managed_set_search(a,"docs","embedding",0,2,0)==SQLITE_OK);
  assert(murmur_managed_migrate(a,"CREATE INDEX docs_body ON docs(body)")==SQLITE_OK);
  murmur_origin_record_t original{},first{},middle{},second{},latest{};
  assert(murmur_managed_schema_export(a,&original)==SQLITE_OK); adopt(b,original); adopt(b,original,0);
  assert(murmur_managed_migrate(b,"ALTER TABLE docs ADD COLUMN forbidden TEXT")==SQLITE_AUTH);
  assert(murmur_managed_set_search(b,"docs","body",0,0,0)==SQLITE_AUTH);
  assert(fts(a)==fts(b));
  ok(a,"INSERT INTO docs VALUES(1,'hello',x'0000803f00000000')");
  assert(murmur_managed_origin_next(a,na,0,&first)==SQLITE_OK); apply(b,first);
  int64_t count=-1; assert(run(b,"SELECT count(*) FROM docs INDEXED BY docs_body",&count)==SQLITE_OK && count==1);
  /* A validly signed artifact still cannot execute arbitrary DDL. */
  auto model=managed_schema_decode(std::string((const char *)original.payload,original.bytes));
  auto bad=model; bad.indexes[0].ddl="CREATE TABLE injected(x)"; auto body=managed_schema_encode(bad);
  auto unsafe=forged(original,body,sa,original.envelope.sequence+100); int changed=0;
  assert(murmur_managed_schema_adopt(b,&unsafe,&changed)!=SQLITE_OK && !changed);
  assert(run(b,"SELECT count(*) FROM docs INDEXED BY docs_body",&count)==SQLITE_OK && count==1);
  bad=model; bad.tables[0].columns[1].id=bad.tables[0].columns[0].id; body=managed_schema_encode(bad); unsafe=forged(original,body,sa,original.envelope.sequence+100);
  assert(murmur_managed_schema_adopt(b,&unsafe,&changed)==SQLITE_CORRUPT);
  body=managed_schema_encode(model); unsafe=forged(original,body,sb,original.envelope.sequence+100); memcpy(unsafe.envelope.origin,nb,16); assert(murmur_origin_sign(&unsafe.envelope,sb,unsafe.payload,unsafe.bytes)==SQLITE_OK);
  assert(murmur_managed_schema_adopt(b,&unsafe,&changed)==SQLITE_AUTH);
  /* A master cannot replace a previously accepted sequence. */
  bad=model; bad.tables[0].columns[1].fts=0; body=managed_schema_encode(bad);
  unsafe=forged(original,body,sa,original.envelope.sequence);
  assert(murmur_managed_schema_adopt(b,&unsafe,&changed)==SQLITE_AUTH && !changed);
  /* Additive migrations publish a new manifest and retain the old one. */
  assert(murmur_managed_migrate(a,"ALTER TABLE docs ADD COLUMN extra TEXT DEFAULT 'fallback'")==SQLITE_OK);
  assert(murmur_managed_schema_export(a,&middle)==SQLITE_OK); assert(middle.envelope.sequence>original.envelope.sequence);
  ok(a,"UPDATE docs SET extra='newvalue' WHERE id=1"); assert(murmur_managed_origin_next(a,na,1,&second)==SQLITE_OK);
  assert(murmur_managed_origin_apply(b,&second,&changed)==SQLITE_SCHEMA);
  adopt(b,middle); apply(b,second); assert(run(b,"SELECT extra='newvalue' FROM docs WHERE id=1",&count)==SQLITE_OK && count==1);
  /* Column/table renames preserve identities and old transaction mapping. */
  murmur_rename_t maps[]={{"docs",nullptr,"body","content"},{"docs","papers",nullptr,nullptr}};
  assert(murmur_managed_migrate_mapped(a,"ALTER TABLE docs RENAME COLUMN body TO content; ALTER TABLE docs RENAME TO papers",maps,2)==SQLITE_OK);
  assert(murmur_managed_schema_export(a,&latest)==SQLITE_OK); adopt(b,latest);
  assert(fts(a)==fts(b)); assert(run(b,"SELECT content='hello' FROM papers WHERE id=1",&count)==SQLITE_OK && count==1);
  assert(murmur_managed_migrate(a,"ALTER TABLE papers DROP COLUMN content")!=SQLITE_OK);
  ok(a,"UPDATE papers SET content='renamed' WHERE id=1"); murmur_origin_record_t third{}; assert(murmur_managed_origin_next(a,na,2,&third)==SQLITE_OK); apply(b,third);
  assert(run(b,"SELECT content='renamed' FROM papers WHERE id=1",&count)==SQLITE_OK && count==1);
  /* A fresh node may receive the newest schema before older data/artifacts. */
  adopt(c,latest); adopt(c,original,0); apply(c,first); adopt(c,middle,0); apply(c,second); apply(c,third);
  assert(run(c,"SELECT content='renamed' AND extra='newvalue' FROM papers WHERE id=1",&count)==SQLITE_OK && count==1);
  murmur_origin_record_t historical{}; assert(murmur_managed_schema_find(a,first.envelope.schema,&historical)==SQLITE_OK);
  assert(historical.bytes==original.bytes && !memcmp(historical.payload,original.payload,original.bytes)); murmur_origin_record_free(&historical);
  /* Reopen retains accepted authority, artifacts, IDs and index flags. */
  murmur_managed_close(c); assert(murmur_managed_open(pc,key,&c)==SQLITE_OK); assert(fts(c)==fts(a));
  assert(run(c,"SELECT count(*) FROM papers INDEXED BY docs_body",&count)==SQLITE_OK && count==1);
  /* An aborted migration restores CRR triggers, metadata and publications. */
  assert(murmur_managed_migrate(a,"ALTER TABLE papers ADD COLUMN transient TEXT; CREATE TABLE broken(")!=SQLITE_OK);
  murmur_origin_record_t unchanged{};
  assert(murmur_managed_schema_export(a,&unchanged)==SQLITE_OK);
  assert(unchanged.bytes==latest.bytes && !memcmp(unchanged.payload,latest.payload,latest.bytes));
  murmur_origin_record_free(&unchanged);
  /* PK renames also rename the CRR key shadow column without losing data. */
  murmur_rename_t pkmap={"papers",nullptr,"id","paper_id"};
  assert(murmur_managed_migrate_mapped(a,"ALTER TABLE papers RENAME COLUMN id TO paper_id",&pkmap,1)==SQLITE_OK);
  murmur_origin_record_t pk_schema{},fourth{};
  assert(murmur_managed_schema_export(a,&pk_schema)==SQLITE_OK); adopt(b,pk_schema); adopt(c,pk_schema);
  ok(a,"UPDATE papers SET content='key renamed' WHERE paper_id=1");
  assert(murmur_managed_origin_next(a,na,3,&fourth)==SQLITE_OK); apply(b,fourth); apply(c,fourth);
  assert(run(b,"SELECT content='key renamed' FROM papers WHERE paper_id=1",&count)==SQLITE_OK && count==1);
  /* New replicated tables may be published after application history. */
  assert(murmur_managed_migrate(a,"CREATE TABLE notes(id INTEGER NOT NULL PRIMARY KEY, text TEXT DEFAULT 'a, b (c)', CHECK(length(text)>0))")==SQLITE_OK);
  assert(murmur_managed_set_replication(a,"notes",1)==SQLITE_OK);
  murmur_origin_record_t new_schema{},fifth{};
  assert(murmur_managed_schema_export(a,&new_schema)==SQLITE_OK); adopt(b,new_schema); adopt(c,new_schema);
  ok(a,"INSERT INTO notes(id) VALUES(1)");
  assert(murmur_managed_origin_next(a,na,4,&fifth)==SQLITE_OK); apply(b,fifth); apply(c,fifth);
  assert(run(b,"SELECT text='a, b (c)' FROM notes WHERE id=1",&count)==SQLITE_OK && count==1);
  for(auto *record:{&pk_schema,&fourth,&new_schema,&fifth}) murmur_origin_record_free(record);
  for(auto *record:{&original,&first,&middle,&second,&latest,&third}) murmur_origin_record_free(record);
  murmur_managed_close(a); murmur_managed_close(b); murmur_managed_close(c);
  puts("MANAGED-SCHEMA-OK");
}
