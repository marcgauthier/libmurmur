package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	drv "github.com/marcgauthier/libmurmur/clients/go/bindings/driver"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/murmurdb"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/murmur"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/replication"
)

// runDatabaseSQL runs the single-suite workload through database/sql
// (the murmurdb driver) instead of the fused direct bindings. Store
// setup, schema, seed rows, RNG stream, batching, checks, and report
// lines match run(); only the access path differs, so the ops/s
// columns compare directly with the murmur backend.
func runDatabaseSQL(o options) result {
	if o.ingest != "local" {
		fail(fmt.Errorf("murmurdb backend supports local ingest only"))
	}
	path := filepath.Join(os.TempDir(), fmt.Sprintf("sqlite-murmur-benchmark-%d", time.Now().UnixNano()))
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	if rc := murmur.Register(key, uint32(o.flushInterval), int(o.cachePages)); rc != murmur.CodeOK {
		fail(fmt.Errorf("register: rc %d", rc))
	}
	defer func() {
		murmur.Unregister()
		_ = os.RemoveAll(path)
		_ = os.Remove(path + "-wal")
		_ = os.Remove(path + "-shm")
		_ = os.Remove(path + "-journal")
	}()
	dsn := path + "?key=" + hex.EncodeToString(key) +
		"&cache_pages=" + strconv.Itoa(int(o.cachePages)) +
		"&flush_ms=" + strconv.Itoa(int(o.flushInterval))

	// Replication setup needs the raw handle (EnsureSchema/MakeCRR);
	// it runs on a setup connection that closes before measuring.
	if err := drv.Init(int(o.cachePages), uint(o.flushInterval)); err != nil {
		fail(fmt.Errorf("init: %w", err))
	}
	setup, err := sqlite.OpenVFS(path, sqlite.OpenReadWrite|sqlite.OpenCreate, "sqlite-murmur")
	if err != nil {
		fail(fmt.Errorf("open setup: %w", err))
	}
	var keyArr [32]byte
	copy(keyArr[:], key)
	if rc := setup.SetKey(keyArr); rc != 0 {
		fail(fmt.Errorf("setup key: rc %d", rc))
	}
	execDB(setup, "PRAGMA page_size="+strconv.Itoa(int(o.pageSize)))
	execDB(setup, "PRAGMA mmap_size=0")
	// Cipher/compression are connection-scoped: set them here so
	// setup-written data uses them, and again on the measured
	// connection below.
	execDB(setup, "PRAGMA cipher='"+o.cipher+"'; PRAGMA compression='"+o.compression+
		"'; PRAGMA flush_interval_ms="+strconv.Itoa(int(o.flushInterval))+
		"; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL")
	if o.backgroundThreads != 0 {
		execDB(setup, "PRAGMA background_threads="+strconv.Itoa(int(o.backgroundThreads)))
	}
	execDB(setup, "PRAGMA cache_size=-"+strconv.Itoa(int(o.sqliteCacheKiB)))
	enableReplication(setup, o.replication)
	execDB(setup, "CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '')")
	if o.replication {
		if err := replication.MakeCRR(setup, "records"); err != nil {
			fail(fmt.Errorf("make crr: %w", err))
		}
	}
	if err := setup.Close(); err != nil {
		fail(fmt.Errorf("close setup: %w", err))
	}

	db, err := murmurdb.Open(dsn)
	if err != nil {
		fail(fmt.Errorf("open murmurdb: %w", err))
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA cipher='" + o.cipher + "'; PRAGMA compression='" + o.compression +
		"'; PRAGMA flush_interval_ms=" + strconv.Itoa(int(o.flushInterval))); err != nil {
		fail(fmt.Errorf("connection pragmas: %w", err))
	}
	if _, err := db.Exec("PRAGMA cache_size=-" + strconv.Itoa(int(o.sqliteCacheKiB))); err != nil {
		fail(fmt.Errorf("connection cache: %w", err))
	}
	if o.backgroundThreads != 0 {
		if _, err := db.Exec("PRAGMA background_threads=" + strconv.Itoa(int(o.backgroundThreads))); err != nil {
			fail(fmt.Errorf("connection threads: %w", err))
		}
	}
	q1 := func(query string, args ...any) int64 {
		var n int64
		if err := db.QueryRow(query, args...).Scan(&n); err != nil {
			fail(fmt.Errorf("%s: %w", query, err))
		}
		return n
	}
	qs := func(query string) string {
		var s string
		if err := db.QueryRow(query).Scan(&s); err != nil {
			fail(fmt.Errorf("%s: %w", query, err))
		}
		return s
	}
	if q1("PRAGMA page_size") != int64(o.pageSize) ||
		q1("PRAGMA cache_size") != -int64(o.sqliteCacheKiB) ||
		qs("PRAGMA journal_mode") != "delete" ||
		q1("PRAGMA synchronous") != 2 ||
		qs("PRAGMA cipher") != o.cipher ||
		qs("PRAGMA compression") != o.compression ||
		q1("PRAGMA flush_interval_ms") != int64(o.flushInterval) {
		fail(fmt.Errorf("benchmark configuration did not take effect"))
	}
	if !o.replication && q1("SELECT count(*) FROM sqlite_schema WHERE name GLOB 'crsql*' OR name GLOB 'murmur_*'") != 0 {
		fail(fmt.Errorf("storage benchmark unexpectedly initialized replication metadata"))
	}
	o.backgroundThreads = uint(q1("PRAGMA background_threads"))
	rocksdbCacheBytes := uint64(q1("PRAGMA rocksdb_block_cache_bytes"))

	tx, err := db.Begin()
	if err != nil {
		fail(fmt.Errorf("seed begin: %w", err))
	}
	for base := uint64(0); base < seedRows; base++ {
		if _, err := tx.Exec(`INSERT INTO records(id,body) VALUES(?,?)`, base+1, payload); err != nil {
			fail(fmt.Errorf("seed: %w", err))
		}
	}
	if err := tx.Commit(); err != nil {
		fail(fmt.Errorf("seed commit: %w", err))
	}
	if rc := murmur.Checkpoint(path); rc != murmur.CodeOK {
		fail(fmt.Errorf("persist Murmur database: rc %d", rc))
	}

	journal := qs("PRAGMA journal_mode")
	synchronous := q1("PRAGMA synchronous")
	fmt.Printf("BENCH_CONFIG,suite=%s,backend=%s,encryption=%s,journal_mode=%s,synchronous=%d,persistence=%s,cipher=%s,flush_interval_ms=%s,page_size=%d,sqlite_cache_size=%d,sqlite_cache_bytes=%d,vfs_block_size=%s,cache_pages=%s,cache_bytes=%s,rocksdb_cache_bytes=%s,compression=%s,zstd_level=%d,background_threads=%s,replication=%s,crsqlite_version=%s,ingest=%s,timing=%s,connections=%d,source_storage=%s,rocksdb_sync=%s,batch_size=%d,seed_rows=%d,payload_bytes=%d,target_seconds=%v\n",
		o.suite, o.backend, "on", journal, synchronous, "periodic_flush",
		o.cipher, strconv.Itoa(int(o.flushInterval)), o.pageSize, -int64(o.sqliteCacheKiB), uint64(o.sqliteCacheKiB)*1024,
		"4096", strconv.Itoa(int(o.cachePages)), strconv.FormatUint(uint64(o.cachePages)*4096, 10), strconv.FormatUint(rocksdbCacheBytes, 10), o.compression, o.compressionLevel,
		strconv.Itoa(int(o.backgroundThreads)), map[bool]string{true: "on", false: "off"}[o.replication], "go-native", o.ingest, "wall", 1, "none",
		"1", o.batchSize, seedRows, len(payload), o.duration)

	var seedVersion int64
	if o.replication {
		seedVersion = q1("SELECT crsql_db_version()")
	}
	var writes, transactions uint64
	var seconds, persistenceSeconds, transactionSeconds, wallSeconds float64
	random := uint64(1234)
	random *= 0x9e3779b97f4a7c15
	start := time.Now()
	for {
		txStart := time.Now()
		var wtx *sql.Tx
		if o.batchSize > 1 {
			var err error
			wtx, err = db.Begin()
			if err != nil {
				fail(fmt.Errorf("begin: %w", err))
			}
		}
		var ids [4]uint64
		for n := uint(0); n < o.batchSize; n++ {
			writes++
			if wtx != nil {
				_, err = wtx.Exec(`INSERT INTO records(id,body) VALUES(?,?)`, seedRows+writes, payload)
			} else {
				_, err = db.Exec(`INSERT INTO records(id,body) VALUES(?,?)`, seedRows+writes, payload)
			}
			if err != nil {
				fail(fmt.Errorf("insert: %w", err))
			}
			if o.batchSize == 1 {
				transactionSeconds += time.Since(txStart).Seconds()
			}
			for i := range ids {
				ids[i] = randomID(&random, seedRows+writes)
			}
			for _, id := range ids {
				var body string
				// Reads must reuse the open batch transaction:
				// the pool holds one connection and the tx
				// owns it, so db.QueryRow would wait forever.
				var err error
				if wtx != nil {
					err = wtx.QueryRow(`SELECT body FROM records WHERE id=?`, id).Scan(&body)
				} else {
					err = db.QueryRow(`SELECT body FROM records WHERE id=?`, id).Scan(&body)
				}
				if err != nil {
					fail(fmt.Errorf("read: %w", err))
				}
				if body != payload {
					fail(fmt.Errorf("incorrect read payload"))
				}
			}
		}
		if wtx != nil {
			if err := wtx.Commit(); err != nil {
				fail(fmt.Errorf("commit: %w", err))
			}
			transactionSeconds += time.Since(txStart).Seconds()
		}
		transactions++
		if time.Since(start).Seconds() >= o.duration {
			break
		}
	}
	seconds = time.Since(start).Seconds()
	stop := time.Now()
	wallSeconds = stop.Sub(start).Seconds()
	if rc := murmur.Checkpoint(path); rc != murmur.CodeOK {
		fail(fmt.Errorf("persist Murmur database: rc %d", rc))
	}
	persistenceSeconds = time.Since(stop).Seconds()

	var trackedChanges uint64
	if o.replication {
		trackedChanges = uint64(q1("SELECT count(*) FROM crsql_changes WHERE \"table\"='records' AND cid='body' AND db_version > " + strconv.FormatInt(seedVersion, 10)))
		if trackedChanges != writes {
			fail(fmt.Errorf("timed replication change count mismatch"))
		}
	}
	stats, rc := murmur.GetStats(path)
	if rc != murmur.CodeOK {
		fail(fmt.Errorf("read storage statistics: rc %d", rc))
	}
	db.Close()
	diskBytes := dirSize(path)

	// Reopen-verify through the driver, like run().
	db2, err := murmurdb.Open(dsn)
	if err != nil {
		fail(fmt.Errorf("reopen: %w", err))
	}
	var rows, changes uint64
	var integrity string
	if err := db2.QueryRow("SELECT count(*) FROM records").Scan(&rows); err != nil {
		fail(fmt.Errorf("reopen count: %w", err))
	}
	if rows != seedRows+writes {
		fail(fmt.Errorf("reopened row count mismatch"))
	}
	if o.replication {
		if err := db2.QueryRow(`SELECT count(*) FROM crsql_changes WHERE "table"='records' AND cid='body'`).Scan(&changes); err != nil {
			fail(fmt.Errorf("reopen changes: %w", err))
		}
		if changes != seedRows+writes {
			fail(fmt.Errorf("reopened replication change count mismatch"))
		}
	}
	if err := db2.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		fail(fmt.Errorf("reopened integrity check failed"))
	}
	db2.Close()

	operations := writes * 5
	savings := 0.0
	if stats.UncompressedBytes != 0 {
		savings = 100.0 * (1.0 - float64(stats.CompressedPayloadBytes)/float64(stats.UncompressedBytes))
	}
	fmt.Println("BENCH_HEADER,seconds,reads,writes,operations,ops_per_second,read_ops_per_second,write_ops_per_second,persistence_seconds,ops_per_second_including_persistence,logical_database_bytes,rocksdb_files_bytes,disk_bytes,zstd_level,compression_savings_pct,transactions,mean_write_transaction_ms,tracked_changes,wall_seconds,source_prepare_seconds,packed_bytes,applied_changes,wall_ops_per_second_including_persistence,suite,backend,replication,batch_size")
	fmt.Printf("BENCH_CSV,%f,%d,%d,%d,%f,%f,%f,%f,%f,%d,%s,%d,%d,%s,%d,%f,%d,%f,%f,%d,%d,%f,%s,%s,%s,%d\nBENCH_DONE\n",
		seconds, writes*4, writes, operations,
		float64(operations)/seconds, float64(writes*4)/seconds, float64(writes)/seconds,
		persistenceSeconds, float64(operations)/(seconds+persistenceSeconds),
		stats.LogicalSizeBytes, strconv.FormatUint(diskBytes, 10), diskBytes, o.compressionLevel, strconv.FormatFloat(savings, 'f', -1, 64),
		transactions, transactionSeconds*1000/float64(transactions), trackedChanges, wallSeconds, 0.0, 0, 0,
		float64(operations)/(wallSeconds+persistenceSeconds),
		o.suite, o.backend, map[bool]string{true: "on", false: "off"}[o.replication], o.batchSize)
	return result{o.backend, o.batchSize, float64(operations) / seconds,
		float64(operations) / (seconds + persistenceSeconds),
		transactionSeconds * 1000 / float64(transactions), stats.LogicalSizeBytes, diskBytes}
}
