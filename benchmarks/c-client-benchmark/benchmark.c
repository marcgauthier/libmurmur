#define _POSIX_C_SOURCE 200809L
#include <sqlite3.h>
#include <libmurmur.h>
#include <inttypes.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


static void fail(sqlite3 *db, const char *where) {
    fprintf(stderr, "%s: %s\n", where, db ? sqlite3_errmsg(db) : "libmurmur initialization failed");
    exit(EXIT_FAILURE);
}
static void exec_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err ? err : sqlite3_errmsg(db));
        sqlite3_free(err);
        fail(db, "sqlite3_exec");
    }
}
static double now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) { perror("clock_gettime"); exit(1); }
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static uint64_t tree_bytes(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    uint64_t total = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[4096];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;
        struct stat st;
        if (stat(child, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) total += tree_bytes(child);
        else if (S_ISREG(st.st_mode)) total += (uint64_t)st.st_size;
    }
    closedir(dir);
    return total;
}
static uint64_t scalar_u64(sqlite3 *db, const char *query) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, query, -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW)
        fail(db, query);
    uint64_t value = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return value;
}
static void usage(const char *p) {
    fprintf(stderr, "Usage: %s [--seconds=N] [--seed-rows=N] [--batch-size=1|10|100] [--database=PATH]\n", p);
}
int main(int argc, char **argv) {
    unsigned seconds = 15, seed = 50000, batch = 1;
    char temp_path[] = "/tmp/c-client-benchmark-XXXXXX";
    const char *path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strncmp(argv[i], "--seconds=", 10)) seconds = strtoul(argv[i] + 10, NULL, 10);
        else if (!strncmp(argv[i], "--seed-rows=", 12)) seed = strtoul(argv[i] + 12, NULL, 10);
        else if (!strncmp(argv[i], "--batch-size=", 13)) batch = strtoul(argv[i] + 13, NULL, 10);
        else if (!strncmp(argv[i], "--database=", 11)) path = argv[i] + 11;
        else { usage(argv[0]); return 1; }
    }
    if (!seconds || !seed || (batch != 1 && batch != 10 && batch != 100)) { usage(argv[0]); return 1; }
    if (murmur_init() != SQLITE_OK) fail(NULL, "murmur_init");
    if (!path) {
        if (!mkdtemp(temp_path)) { perror("mkdtemp"); return 1; }
        path = temp_path;
    }
    if (murmur_vfs_register(16384, 100) != SQLITE_OK) fail(NULL, "murmur_vfs_register");
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "sqlite-murmur") != SQLITE_OK)
        fail(db, "sqlite3_open_v2");
    uint8_t key[32];
    for (unsigned i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(i * 17u + 3u);
    if (murmur_db_key(db, key) != SQLITE_OK) fail(db, "murmur_db_key");
    exec_sql(db, "PRAGMA cipher='aes256gcm'; PRAGMA compression='zstd3'; PRAGMA flush_interval_ms=100;"
        "CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE murmur_config(name TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE murmur_identity(id INTEGER PRIMARY KEY CHECK(id=1),node BLOB,site BLOB,incarnation INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO murmur_identity(id) VALUES(1);"
        "CREATE TABLE murmur_progress(node BLOB PRIMARY KEY,site BLOB NOT NULL,cursor BLOB NOT NULL,sent BLOB);"
        "CREATE TABLE murmur_excluded(node BLOB PRIMARY KEY);"
        "CREATE TABLE murmur_stage(node BLOB NOT NULL,idx INTEGER NOT NULL,data BLOB NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(node,idx));"
        "CREATE TABLE murmur_kv(key BLOB PRIMARY KEY,value BLOB NOT NULL);"
        "CREATE TABLE murmur_file_chunks(digest BLOB NOT NULL,generation INTEGER NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(digest,generation,idx));"
        "CREATE TABLE murmur_file_transfers(transfer BLOB PRIMARY KEY,digest BLOB,generation INTEGER,total_bytes INTEGER,identity BLOB,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL);"
        "CREATE TABLE murmur_file_staging(transfer BLOB NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(transfer,idx));");
    if (murmur_crsqlite_init(db) != SQLITE_OK) {
        fail(db, "murmur_crsqlite_init");
    }
    sqlite3_stmt *ins = NULL, *read = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO records(id,body) VALUES(?1,?2)", -1, &ins, NULL) != SQLITE_OK) fail(db, "prepare insert");
    if (sqlite3_prepare_v2(db, "SELECT body FROM records WHERE id=?1", -1, &read, NULL) != SQLITE_OK) fail(db, "prepare read");
    for (unsigned i = 1; i <= seed; ++i) {
        sqlite3_bind_int64(ins, 1, i); sqlite3_bind_text(ins, 2, "benchmark-payload-0123456789", -1, SQLITE_STATIC);
        if (sqlite3_step(ins) != SQLITE_DONE) fail(db, "seed insert");
        sqlite3_reset(ins); sqlite3_clear_bindings(ins);
    }
    sqlite3_finalize(ins);
    exec_sql(db, "SELECT crsql_as_crr('main','records')");
    sqlite3_stmt *version = NULL;
    if (sqlite3_prepare_v2(db, "SELECT crsql_db_version()", -1, &version, NULL) != SQLITE_OK ||
        sqlite3_step(version) != SQLITE_ROW) fail(db, "read seed db version");
    sqlite3_int64 seed_version = sqlite3_column_int64(version, 0);
    sqlite3_finalize(version);
    if (sqlite3_prepare_v2(db, "INSERT INTO records(id,body) VALUES(?1,?2)", -1, &ins, NULL) != SQLITE_OK) fail(db, "prepare timed insert");
    uint64_t writes = 0, txns = 0, rng = UINT64_C(1234) * UINT64_C(0x9e3779b97f4a7c15);
    double start = now();
    while (now() - start < seconds) {
        if (batch > 1) exec_sql(db, "BEGIN IMMEDIATE");
        for (unsigned n = 0; n < batch; ++n) {
            ++writes;
            sqlite3_bind_int64(ins, 1, (sqlite3_int64)seed + writes);
            sqlite3_bind_text(ins, 2, "benchmark-payload-0123456789", -1, SQLITE_STATIC);
            if (sqlite3_step(ins) != SQLITE_DONE) fail(db, "timed insert");
            sqlite3_reset(ins); sqlite3_clear_bindings(ins);
            for (unsigned r = 0; r < 4; ++r) {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                sqlite3_bind_int64(read, 1, (sqlite3_int64)(rng % seed) + 1);
                if (sqlite3_step(read) != SQLITE_ROW) fail(db, "timed read");
                sqlite3_reset(read); sqlite3_clear_bindings(read);
            }
        }
        if (batch > 1) exec_sql(db, "COMMIT");
        ++txns;
    }
    double elapsed = now() - start;
    sqlite3_stmt *verify = NULL;
    char verify_sql[256];
    snprintf(verify_sql, sizeof(verify_sql), "SELECT count(*) FROM crsql_changes WHERE \"table\"='records' AND cid='body' AND db_version > %lld", (long long)seed_version);
    if (sqlite3_prepare_v2(db, verify_sql, -1, &verify, NULL) != SQLITE_OK ||
        sqlite3_step(verify) != SQLITE_ROW) fail(db, "verify changes");
    uint64_t tracked = sqlite3_column_int64(verify, 0);
    sqlite3_finalize(verify);
    if (tracked != writes) {
        fprintf(stderr, "tracked change mismatch: got=%" PRIu64 " expected=%" PRIu64 "\n", tracked, writes);
        return 1;
    }
    uint64_t raw_bytes = scalar_u64(db, "PRAGMA page_count") * scalar_u64(db, "PRAGMA page_size");
    sqlite3_finalize(read); sqlite3_finalize(ins);
    exec_sql(db, "SELECT crsql_finalize()");
    if (sqlite3_close(db) != SQLITE_OK) fail(db, "sqlite3_close");
    db = NULL;
    uint64_t disk_bytes = tree_bytes(path);
    double disk_pct = raw_bytes ? 100.0 * (double)disk_bytes / (double)raw_bytes : 0.0;
    puts("seconds,writes,transactions,ops_per_second,write_ops_per_second,tracked_changes,batch_size,read_write_mix,encryption,cipher,compression,replication,replication_crdt,raw_database_bytes,store_disk_bytes,disk_to_raw_pct");
    printf("%.6f,%" PRIu64 ",%" PRIu64 ",%.3f,%.3f,%" PRIu64 ",%u,80_read_20_write,on,aes256gcm,zstd3,on,cr_sqlite_crdt,%" PRIu64 ",%" PRIu64 ",%.2f\n",
        elapsed, writes, txns, writes * 5.0 / elapsed, writes / elapsed, tracked, batch, raw_bytes, disk_bytes, disk_pct);
    murmur_shutdown();
    return 0;
}
