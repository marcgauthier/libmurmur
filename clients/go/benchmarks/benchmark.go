// Backend comparison suite: 80% destination reads and 20% local or
// replicated row writes. Go port of benchmarks/benchmark.cpp: same
// schema, payload, RNG, suites, flags, and BENCH_* report lines.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/murmur"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/replication"
)

const seedRows = 50000
const payload = "sqlite-murmur-benchmark-payload-abcdefghijklmnopqrstuvwxyz-0123456789"

type options struct {
	duration          float64
	flushInterval     uint
	cachePages        uint
	sqliteCacheKiB    uint
	pageSize          uint
	cipher            string
	compression       string
	compressionLevel  uint
	batchSize         uint
	backgroundThreads uint
	replication       bool
	ingest            string
	suite             string
	backend           string
}

func defaultOptions() options {
	return options{
		duration:       60,
		flushInterval:  100,
		cachePages:     16384,
		sqliteCacheKiB: 1048576,
		pageSize:       4096,
		cipher:         "aegis256",
		compression:    "zstd3",
		batchSize:      1,
		ingest:         "local",
		suite:          "all",
		backend:        "murmur",
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "benchmark:", err)
	os.Exit(1)
}

func number(value string, maximum uint64) uint64 {
	if value == "" {
		fail(fmt.Errorf("missing numeric value"))
	}
	var parsed uint64
	for _, c := range value {
		if c < '0' || c > '9' || parsed > maximum/10 ||
			(parsed == maximum/10 && uint64(c-'0') > maximum%10) {
			fail(fmt.Errorf("invalid numeric value: %s", value))
		}
		parsed = parsed*10 + uint64(c-'0')
	}
	if parsed == 0 {
		fail(fmt.Errorf("numeric value must be positive"))
	}
	return parsed
}

func parseArgs(args []string) options {
	o := defaultOptions()
	singleOverride, backendOverride := false, false
	for _, arg := range args {
		if arg == "--help" {
			fmt.Println("Usage: benchmark [--suite=all|no-replication|crsqlite|single] [--seconds=60] [--flush-interval-ms=100] [--cache-pages=16384] [--sqlite-cache-kib=1048576]")
			fmt.Println("                 [--compression=zstd3|zstd1..zstd22] [--cipher=aegis256|aes256gcm] [--page-size=4096] [--batch-size=1] [--replication=off|on] [--ingest=local|row|blob] [--background-threads=auto|1..256]")
			fmt.Println("Default: 8 cases, 60 seconds each. --suite=single supports --backend=murmur|murmurdb|sqlite-disk.")
			fmt.Println("Batch/replication/ingest/backend overrides require --suite=single; row/blob ingest enables replication; --seconds measures destination active time, excluding source export/packing.")
			os.Exit(0)
		}
		switch {
		case strings.HasPrefix(arg, "--suite="):
			o.suite = arg[len("--suite="):]
			if o.suite != "all" && o.suite != "no-replication" && o.suite != "crsqlite" && o.suite != "single" {
				fail(fmt.Errorf("invalid suite"))
			}
		case strings.HasPrefix(arg, "--backend="):
			o.backend = arg[len("--backend="):]
			if o.backend != "murmur" && o.backend != "murmurdb" && o.backend != "sqlite-disk" {
				fail(fmt.Errorf("invalid backend"))
			}
			backendOverride = true
		case strings.HasPrefix(arg, "--seconds="):
			v, err := strconv.ParseFloat(arg[len("--seconds="):], 64)
			if err != nil || v <= 0 {
				fail(fmt.Errorf("invalid seconds"))
			}
			o.duration = v
		case strings.HasPrefix(arg, "--flush-interval-ms="):
			o.flushInterval = uint(number(arg[len("--flush-interval-ms="):], 3600000))
		case strings.HasPrefix(arg, "--cache-pages="):
			o.cachePages = uint(number(arg[len("--cache-pages="):], 1<<30))
		case strings.HasPrefix(arg, "--sqlite-cache-kib="):
			o.sqliteCacheKiB = uint(number(arg[len("--sqlite-cache-kib="):], 1<<30))
		case strings.HasPrefix(arg, "--page-size="):
			o.pageSize = uint(number(arg[len("--page-size="):], 65536))
		case strings.HasPrefix(arg, "--batch-size="):
			o.batchSize = uint(number(arg[len("--batch-size="):], 100000))
			singleOverride = true
		case strings.HasPrefix(arg, "--replication="):
			v := arg[len("--replication="):]
			if v != "off" && v != "on" {
				fail(fmt.Errorf("invalid replication"))
			}
			o.replication = v == "on"
			singleOverride = true
		case strings.HasPrefix(arg, "--ingest="):
			o.ingest = arg[len("--ingest="):]
			if o.ingest != "local" && o.ingest != "row" && o.ingest != "blob" {
				fail(fmt.Errorf("invalid ingest"))
			}
			singleOverride = true
		case strings.HasPrefix(arg, "--background-threads="):
			v := arg[len("--background-threads="):]
			if v == "auto" {
				o.backgroundThreads = 0
			} else {
				o.backgroundThreads = uint(number(v, 256))
			}
		case strings.HasPrefix(arg, "--cipher="):
			o.cipher = arg[len("--cipher="):]
			if o.cipher != "aegis256" && o.cipher != "aes256gcm" {
				fail(fmt.Errorf("invalid cipher"))
			}
		case strings.HasPrefix(arg, "--compression="):
			o.compression = arg[len("--compression="):]
			if o.compression == "none" || !strings.HasPrefix(o.compression, "zstd") {
				fail(fmt.Errorf("invalid compression"))
			}
		default:
			fail(fmt.Errorf("unknown flag %s", arg))
		}
	}
	if o.suite != "single" && (singleOverride || backendOverride) {
		fail(fmt.Errorf("batch/replication/ingest/backend overrides require --suite=single"))
	}
	if o.ingest != "local" {
		o.replication = true
	}
	if o.suite == "single" && o.ingest != "local" && o.backend != "murmur" {
		// Ingest applies replicate through the murmur apply path on
		// both backends; the destination backend still varies.
	}
	lvl, err := strconv.Atoi(strings.TrimPrefix(o.compression, "zstd"))
	if err != nil || lvl < 1 || lvl > 22 {
		fail(fmt.Errorf("invalid compression"))
	}
	o.compressionLevel = uint(lvl)
	return o
}

func openDB(path string, sqliteCacheKiB uint, isMurmur bool) *sqlite.Conn {
	flags := sqlite.OpenReadWrite | sqlite.OpenCreate | sqlite.OpenFullMutex
	var db *sqlite.Conn
	if isMurmur {
		var rc int
		db, rc = murmur.Open(path, nil)
		if rc != murmur.CodeOK {
			fail(fmt.Errorf("open database: rc %d", rc))
		}
	} else {
		var err error
		db, err = sqlite.Open(path, flags)
		if err != nil {
			fail(fmt.Errorf("open database: %w", err))
		}
	}
	if err := db.Exec("PRAGMA cache_size=-" + strconv.Itoa(int(sqliteCacheKiB))); err != nil {
		fail(fmt.Errorf("set SQLite cache_size: %w", err))
	}
	return db
}

func closeDB(db *sqlite.Conn, isMurmur bool) {
	if isMurmur {
		if rc := murmur.Close(db); rc != murmur.CodeOK {
			fail(fmt.Errorf("close database: rc %d", rc))
		}
		return
	}
	if err := db.Close(); err != nil {
		fail(fmt.Errorf("close database: %w", err))
	}
}

func execDB(db *sqlite.Conn, sql string) {
	if err := db.Exec(sql); err != nil {
		fail(fmt.Errorf("%s: %w", sql, err))
	}
}

type statement struct {
	db     *sqlite.Conn
	st     *sqlite.Stmt
	args   []sqlite.Arg
	arena  []byte
	cells  []sqlite.Cell
	types  []sqlite.ColType
	mkeys  []int64
	mcells []sqlite.Cell
	mtypes []sqlite.ColType
	marena []byte
	mhits  []bool
}

func prepare(db *sqlite.Conn, sql string) *statement {
	st, err := db.Prepare(sql)
	if err != nil {
		fail(fmt.Errorf("prepare: %w", err))
	}
	return &statement{db: db, st: st}
}

func (s *statement) close() {
	_ = s.st.Close()
}

func (s *statement) reset() {
	if err := s.st.Reset(); err != nil {
		fail(fmt.Errorf("reset statement: %w", err))
	}
}

func (s *statement) insert(id uint64) {
	// One row per crossing: bind+step+reset fused.
	s.args = s.args[:0]
	s.arena = s.arena[:0]
	s.args = append(s.args, sqlite.IntArg(int64(id)))
	var a sqlite.Arg
	a, s.arena = sqlite.TextArg(s.arena, payload)
	s.args = append(s.args, a)
	if err := s.st.ExecBatch(s.args, s.arena, 2); err != nil {
		fail(fmt.Errorf("insert: %w", err))
	}
}

// insertBatch writes ids in as few crossings as chunking allows.
func (s *statement) insertBatch(first, n uint64) {
	const chunk = 4096
	for base := uint64(0); base < n; base += chunk {
		m := chunk
		if base+uint64(m) > n {
			m = int(n - base)
		}
		s.args = s.args[:0]
		s.arena = s.arena[:0]
		for i := 0; i < m; i++ {
			s.args = append(s.args, sqlite.IntArg(int64(first+base+uint64(i))))
			var a sqlite.Arg
			a, s.arena = sqlite.TextArg(s.arena, payload)
			s.args = append(s.args, a)
		}
		if err := s.st.ExecBatch(s.args, s.arena, 2); err != nil {
			fail(fmt.Errorf("insert batch: %w", err))
		}
	}
}

func (s *statement) read(id uint64) {
	// Fused point lookup: reset+bind+step+decode in one crossing.
	if s.types == nil {
		s.types = []sqlite.ColType{sqlite.ColText}
		s.cells = make([]sqlite.Cell, 1)
		s.arena = make([]byte, 256)
	}
	ok, err := s.st.FetchInt64(int64(id), s.types, s.cells, s.arena)
	if err != nil {
		fail(fmt.Errorf("read: %w", err))
	}
	if !ok || s.cells[0].BlobLen() != len(payload) || s.cells[0].TextView(s.arena) != payload {
		fail(fmt.Errorf("incorrect read payload"))
	}
	// The fused fetch leaves no read lock held past return: entry
	// reset on the next call releases like the explicit reset above.
}

// readMany fetches len(ids) point lookups in one crossing, then
// validates each body in Go (no extra crossings).
func (s *statement) readMany(ids []uint64) {
	if s.mkeys == nil {
		s.mtypes = []sqlite.ColType{sqlite.ColText}
		s.mkeys = make([]int64, 4)
		s.mcells = make([]sqlite.Cell, 4)
		s.marena = make([]byte, 1024)
		s.mhits = make([]bool, 4)
	}
	for i, id := range ids {
		s.mkeys[i] = int64(id)
	}
	if err := s.st.FetchManyInt64(s.mkeys[:len(ids)], s.mtypes, s.mcells, s.marena, s.mhits[:len(ids)]); err != nil {
		fail(fmt.Errorf("readMany: %w", err))
	}
	for i := range ids {
		if !s.mhits[i] || s.mcells[i].BlobLen() != len(payload) || s.mcells[i].TextView(s.marena) != payload {
			fail(fmt.Errorf("incorrect readMany payload"))
		}
	}
}

func randomID(state *uint64, rows uint64) uint64 {
	*state ^= *state >> 12
	*state ^= *state << 25
	*state ^= *state >> 27
	return 1 + (*state * 2685821657736338717 % rows)
}

func scalar(db *sqlite.Conn, sql string) int64 {
	st, err := db.Prepare(sql)
	if err != nil {
		fail(fmt.Errorf("prepare: %w", err))
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil || done {
		fail(fmt.Errorf("%s: %v", sql, err))
	}
	return st.ColumnInt64(0)
}

func textScalar(db *sqlite.Conn, sql string) string {
	st, err := db.Prepare(sql)
	if err != nil {
		fail(fmt.Errorf("prepare: %w", err))
	}
	defer st.Close()
	done, err := st.Step()
	if err != nil || done {
		fail(fmt.Errorf("missing setting: %s", sql))
	}
	return st.ColumnText(0)
}

func verify(db *sqlite.Conn, rows uint64, withReplication bool) {
	if withReplication && scalar(db, `SELECT count(*) FROM crsql_changes WHERE "table"='records' AND cid='body'`) != int64(rows) {
		fail(fmt.Errorf("reopened replication change count mismatch"))
	}
	if scalar(db, "SELECT count(*) FROM records") != int64(rows) {
		fail(fmt.Errorf("reopened row count mismatch"))
	}
	if textScalar(db, "PRAGMA integrity_check") != "ok" {
		fail(fmt.Errorf("reopened integrity check failed"))
	}
}

func persist(db *sqlite.Conn, path string, isMurmur bool) {
	if isMurmur {
		if rc := murmur.Checkpoint(path); rc != murmur.CodeOK {
			fail(fmt.Errorf("persist Murmur database: rc %d", rc))
		}
		return
	}
	execDB(db, "PRAGMA wal_checkpoint(TRUNCATE)")
}

// enableReplication installs the Go CRR layer: metadata schema,
// counters/site tables, per-connection functions.
func enableReplication(db *sqlite.Conn, enabled bool) {
	if !enabled {
		return
	}
	if err := replication.EnsureSchema(db); err != nil {
		fail(fmt.Errorf("replication schema: %w", err))
	}
	if err := sqlite.CrsqliteInit(db); err != nil {
		fail(fmt.Errorf("replication crr: %w", err))
	}
}

type result struct {
	backend             string
	batchSize           uint
	throughput          float64
	persistedThroughput float64
	transactionMs       float64
	logicalBytes        uint64
	diskBytes           uint64
}

func dirSize(path string) uint64 {
	var total uint64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += uint64(info.Size())
		}
		return nil
	})
	return total
}

func fileSize(path string) uint64 {
	var total uint64
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if info, err := os.Stat(path + suffix); err == nil && info.Mode().IsRegular() {
			total += uint64(info.Size())
		}
	}
	return total
}

func run(o options) result {
	isMurmur := o.backend == "murmur"
	path := filepath.Join(os.TempDir(), fmt.Sprintf("sqlite-murmur-benchmark-%d", time.Now().UnixNano()))
	cleanup := func(unregistered *bool) {
		if isMurmur && !*unregistered {
			_ = murmur.Unregister()
		}
		_ = os.RemoveAll(path)
		_ = os.Remove(path + "-wal")
		_ = os.Remove(path + "-shm")
		_ = os.Remove(path + "-journal")
	}
	unregistered := false
	defer func() { cleanup(&unregistered) }()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 11)
	}
	if isMurmur {
		if rc := murmur.Register(key, uint32(o.flushInterval), int(o.cachePages)); rc != murmur.CodeOK {
			fail(fmt.Errorf("register VFS: rc %d", rc))
		}
	}

	var writes, transactions uint64
	var rocksdbCacheBytes uint64
	var trackedChanges uint64
	var seconds, persistenceSeconds, transactionSeconds, wallSeconds, sourceSeconds float64
	var packedBytes, appliedChanges uint64
	var stats murmur.Stats

	func() {
		db := openDB(path, o.sqliteCacheKiB, isMurmur)
		defer closeDB(db, isMurmur)
		execDB(db, "PRAGMA page_size="+strconv.Itoa(int(o.pageSize)))
		execDB(db, "PRAGMA mmap_size=0")
		if isMurmur {
			execDB(db, "PRAGMA cipher='"+o.cipher+"'; PRAGMA compression='"+o.compression+
				"'; PRAGMA flush_interval_ms="+strconv.Itoa(int(o.flushInterval))+
				"; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL")
			if o.backgroundThreads != 0 {
				execDB(db, "PRAGMA background_threads="+strconv.Itoa(int(o.backgroundThreads)))
			}
			o.backgroundThreads = uint(scalar(db, "PRAGMA background_threads"))
			rocksdbCacheBytes = uint64(scalar(db, "PRAGMA rocksdb_block_cache_bytes"))
			if textScalar(db, "PRAGMA cipher") != o.cipher ||
				textScalar(db, "PRAGMA compression") != o.compression ||
				scalar(db, "PRAGMA flush_interval_ms") != int64(o.flushInterval) {
				fail(fmt.Errorf("Murmur encryption/compression configuration did not take effect"))
			}
		} else {
			execDB(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL")
		}
		// Set the KiB target after page size selection for every backend.
		execDB(db, "PRAGMA cache_size=-"+strconv.Itoa(int(o.sqliteCacheKiB)))
		journal := textScalar(db, "PRAGMA journal_mode")
		synchronous := scalar(db, "PRAGMA synchronous")
		wantJournal := "wal"
		wantSync := int64(1)
		if isMurmur {
			wantJournal, wantSync = "delete", 2
		}
		if scalar(db, "PRAGMA page_size") != int64(o.pageSize) ||
			scalar(db, "PRAGMA cache_size") != -int64(o.sqliteCacheKiB) ||
			journal != wantJournal || synchronous != wantSync {
			fail(fmt.Errorf("benchmark configuration did not take effect"))
		}
		if !o.replication && scalar(db, "SELECT count(*) FROM sqlite_schema WHERE name GLOB 'crsql*' OR name GLOB 'murmur_*'") != 0 {
			fail(fmt.Errorf("storage benchmark unexpectedly initialized replication metadata"))
		}
		enableReplication(db, o.replication)
		execDB(db, "CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '')")
		if o.replication {
			if err := replication.MakeCRR(db, "records"); err != nil {
				fail(fmt.Errorf("make crr: %w", err))
			}
		}
		insert := prepare(db, "INSERT INTO records(id,body) VALUES(?1,?2)")
		defer insert.close()
		read := prepare(db, "SELECT body FROM records WHERE id=?1")
		defer read.close()
		execDB(db, "BEGIN IMMEDIATE")
		insert.insertBatch(1, seedRows)
		execDB(db, "COMMIT")
		persist(db, path, isMurmur)

		var source *sqlite.Conn
		if o.ingest != "local" {
			var err error
			source, err = sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
			if err != nil {
				fail(fmt.Errorf("open source: %w", err))
			}
			defer source.Close()
			enableReplication(source, true)
			execDB(source, "CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '')")
			if err := replication.MakeCRR(source, "records"); err != nil {
				fail(fmt.Errorf("make source crr: %w", err))
			}
		}
		connections, sourceStorage := 1, "none"
		if source != nil {
			connections, sourceStorage = 2, "memory"
		}
		enc, ciph, flushMS := "off", "none", "NA"
		vfsBlock, cachePgs, cacheB, rocksB := "NA", "NA", "NA", "NA"
		comp, bgThreads := "none", "NA"
		if isMurmur {
			enc, ciph = "on", o.cipher
			flushMS = strconv.Itoa(int(o.flushInterval))
			vfsBlock = "4096"
			cachePgs = strconv.Itoa(int(o.cachePages))
			cacheB = strconv.FormatUint(uint64(o.cachePages)*4096, 10)
			rocksB = strconv.FormatUint(rocksdbCacheBytes, 10)
			comp = o.compression
			bgThreads = strconv.Itoa(int(o.backgroundThreads))
		}
		rep, crsqliteVer := "off", "none"
		if o.replication {
			rep, crsqliteVer = "on", "go-native"
		}
		timing := "wall"
		if o.ingest != "local" {
			timing = "destination_active"
		}
		fmt.Printf("BENCH_CONFIG,suite=%s,backend=%s,encryption=%s,journal_mode=%s,synchronous=%d,persistence=%s,cipher=%s,flush_interval_ms=%s,page_size=%d,sqlite_cache_size=%d,sqlite_cache_bytes=%d,vfs_block_size=%s,cache_pages=%s,cache_bytes=%s,rocksdb_cache_bytes=%s,compression=%s,zstd_level=%d,background_threads=%s,replication=%s,crsqlite_version=%s,ingest=%s,timing=%s,connections=%d,source_storage=%s,rocksdb_sync=%s,batch_size=%d,seed_rows=%d,payload_bytes=%d,target_seconds=%v\n",
			o.suite, o.backend, enc, journal, synchronous, map[bool]string{true: "periodic_flush", false: "wal_checkpoint"}[isMurmur],
			ciph, flushMS, o.pageSize, -int64(o.sqliteCacheKiB), uint64(o.sqliteCacheKiB)*1024,
			vfsBlock, cachePgs, cacheB, rocksB, comp, map[bool]uint{true: o.compressionLevel}[isMurmur],
			bgThreads, rep, crsqliteVer, o.ingest, timing, connections, sourceStorage,
			map[bool]string{true: "1", false: "NA"}[isMurmur], o.batchSize, seedRows, len(payload), o.duration)

		var seedVersion int64
		if o.replication {
			var err error
			seedVersion, err = replication.DbVersion(db)
			if err != nil {
				fail(fmt.Errorf("db version: %w", err))
			}
		}
		random := uint64(1234)
		random *= 0x9e3779b97f4a7c15 // Wraps mod 2^64 like the C++ driver.
		start := time.Now()
		if o.ingest == "local" {
			for {
				txStart := time.Now()
				if o.batchSize > 1 {
					execDB(db, "BEGIN IMMEDIATE")
				}
				var ids [4]uint64
				for n := uint(0); n < o.batchSize; n++ {
					writes++
					insert.insert(seedRows + writes)
					if o.batchSize == 1 {
						transactionSeconds += time.Since(txStart).Seconds()
					}
					// Same RNG stream as four single reads (same
					// ids in the same order), one crossing.
					for i := range ids {
						ids[i] = randomID(&random, seedRows+writes)
					}
					read.readMany(ids[:])
				}
				if o.batchSize > 1 {
					execDB(db, "COMMIT")
					transactionSeconds += time.Since(txStart).Seconds()
				}
				transactions++
				if time.Since(start).Seconds() >= o.duration {
					break
				}
			}
			seconds = time.Since(start).Seconds()
		} else {
			runIngest(db, source, read, o, &random, &writes, &transactions, &transactionSeconds, &sourceSeconds, &seconds, &packedBytes, &appliedChanges)
		}
		stop := time.Now()
		wallSeconds = stop.Sub(start).Seconds()
		persist(db, path, isMurmur)
		persistenceSeconds = time.Since(stop).Seconds()
		if o.replication {
			trackedChanges = uint64(scalar(db, "SELECT count(*) FROM crsql_changes WHERE \"table\"='records' AND cid='body' AND db_version > "+strconv.FormatInt(seedVersion, 10)))
			if trackedChanges != writes {
				fail(fmt.Errorf("timed replication change count mismatch"))
			}
		}
		if isMurmur {
			var rc int
			stats, rc = murmur.GetStats(path)
			if rc != murmur.CodeOK {
				fail(fmt.Errorf("read storage statistics: rc %d", rc))
			}
		} else {
			stats.LogicalSizeBytes = uint64(scalar(db, "PRAGMA page_count")) * uint64(o.pageSize)
		}
	}()

	var diskBytes uint64
	if isMurmur {
		diskBytes = dirSize(path)
	} else {
		diskBytes = fileSize(path)
	}
	func() {
		db := openDB(path, o.sqliteCacheKiB, isMurmur)
		defer closeDB(db, isMurmur)
		enableReplication(db, o.replication)
		verify(db, seedRows+writes, o.replication)
	}()
	if isMurmur {
		if rc := murmur.Unregister(); rc != murmur.CodeOK {
			fail(fmt.Errorf("unregister VFS: rc %d", rc))
		}
		unregistered = true
	}
	operations := writes * 5
	savings := 0.0
	if stats.UncompressedBytes != 0 {
		savings = 100.0 * (1.0 - float64(stats.CompressedPayloadBytes)/float64(stats.UncompressedBytes))
	}
	zstdLevel := uint(0)
	rocksdbFiles, savingsText := "NA", "NA"
	if isMurmur {
		zstdLevel = o.compressionLevel
		rocksdbFiles = strconv.FormatUint(diskBytes, 10)
		savingsText = strconv.FormatFloat(savings, 'f', -1, 64)
	}
	fmt.Println("BENCH_HEADER,seconds,reads,writes,operations,ops_per_second,read_ops_per_second,write_ops_per_second,persistence_seconds,ops_per_second_including_persistence,logical_database_bytes,rocksdb_files_bytes,disk_bytes,zstd_level,compression_savings_pct,transactions,mean_write_transaction_ms,tracked_changes,wall_seconds,source_prepare_seconds,packed_bytes,applied_changes,wall_ops_per_second_including_persistence,suite,backend,replication,batch_size")
	fmt.Printf("BENCH_CSV,%f,%d,%d,%d,%f,%f,%f,%f,%f,%d,%s,%d,%d,%s,%d,%f,%d,%f,%f,%d,%d,%f,%s,%s,%s,%d\nBENCH_DONE\n",
		seconds, writes*4, writes, operations,
		float64(operations)/seconds, float64(writes*4)/seconds, float64(writes)/seconds,
		persistenceSeconds, float64(operations)/(seconds+persistenceSeconds),
		stats.LogicalSizeBytes, rocksdbFiles, diskBytes, zstdLevel, savingsText,
		transactions, transactionSeconds*1000/float64(transactions), trackedChanges, wallSeconds, sourceSeconds, packedBytes, appliedChanges,
		float64(operations)/(wallSeconds+persistenceSeconds),
		o.suite, o.backend, map[bool]string{true: "on", false: "off"}[o.replication], o.batchSize)
	return result{o.backend, o.batchSize, float64(operations) / seconds,
		float64(operations) / (seconds + persistenceSeconds),
		transactionSeconds * 1000 / float64(transactions), stats.LogicalSizeBytes, diskBytes}
}

// runIngest drives replicated writes: source inserts plus export are
// source-side (excluded from the active timer); stage+apply on the
// destination plus interleaved reads are timed. Blob mode applies one
// batch per transfer; row mode applies one row per transfer.
func runIngest(db, source *sqlite.Conn, read *statement, o options, random *uint64, writes, transactions *uint64, transactionSeconds, sourceSeconds, seconds *float64, packedBytes, appliedChanges *uint64) {
	srcSite, err := replication.SiteID(source)
	if err != nil {
		fail(fmt.Errorf("source site: %w", err))
	}
	node := srcSite
	if err := replication.Reset(db, node, srcSite); err != nil {
		fail(fmt.Errorf("reset progress: %w", err))
	}
	var cursor replication.Cursor
	version, err := replication.DbVersion(source)
	if err != nil {
		fail(fmt.Errorf("source version: %w", err))
	}
	cursor.From = version
	sourceInsert := prepare(source, "INSERT INTO records(id,body) VALUES(?1,?2)")
	defer sourceInsert.close()
	batchBytes := 1 << 20
	if o.ingest == "row" {
		batchBytes = 1
	}
	for *seconds < o.duration {
		sourceStart := time.Now()
		execDB(source, "BEGIN IMMEDIATE")
		for n := uint(0); n < o.batchSize; n++ {
			sourceInsert.insert(seedRows + *writes + uint64(n) + 1)
		}
		execDB(source, "COMMIT")
		exports := []replication.BatchExport{}
		for {
			exp, err := replication.Export(source, cursor, batchBytes, 64<<20)
			if err != nil {
				fail(fmt.Errorf("export: %w", err))
			}
			exports = append(exports, exp)
			*packedBytes += uint64(len(exp.Blob))
			cursor = exp.Next
			if exp.Next.Through == nil {
				break
			}
		}
		*sourceSeconds += time.Since(sourceStart).Seconds()
		activeStart := time.Now()
		for _, exp := range exports {
			if err := replication.StageBegin(db, node, 60000); err != nil {
				fail(fmt.Errorf("stage begin: %w", err))
			}
			if err := replication.Stage(db, node, 0, exp.Blob, 64<<20); err != nil {
				fail(fmt.Errorf("stage: %w", err))
			}
			digest := sha256.Sum256(exp.Blob)
			storedSite, stored, err := replication.Progress(db, node)
			if err != nil || storedSite == nil {
				fail(fmt.Errorf("progress: %v", err))
			}
			if err := replication.Apply(db, node, srcSite, stored, exp.Next, uint64(len(exp.Blob)), digest); err != nil {
				fail(fmt.Errorf("apply: %w", err))
			}
			cells, err := replication.DecodeCells(exp.Blob)
			if err != nil {
				fail(fmt.Errorf("decode: %w", err))
			}
			*appliedChanges += uint64(len(cells))
		}
		*writes += uint64(o.batchSize)
		*transactionSeconds += time.Since(activeStart).Seconds()
		for i := uint64(0); i < uint64(o.batchSize)*4; i++ {
			read.read(randomID(random, seedRows+*writes))
		}
		*seconds += time.Since(activeStart).Seconds()
		*transactions++
	}
}

func comparison(results []result, withReplication bool) {
	test := 1
	label := "no replication"
	if withReplication {
		test, label = 2, "cr-sqlite local change tracking"
	}
	fmt.Printf("\nTest %d: %s\n", test, label)
	fmt.Println("| Backend | Inserts/tx | Ops/s | Ops/s incl. persistence | Mean tx ms | Logical bytes | Disk bytes |")
	fmt.Println("|---|---:|---:|---:|---:|---:|---:|")
	for _, r := range results {
		fmt.Printf("| %s | %d | %v | %v | %v | %d | %d |\n", r.backend, r.batchSize, r.throughput, r.persistedThroughput, r.transactionMs, r.logicalBytes, r.diskBytes)
	}
	fmt.Println("| Inserts/tx | Murmur / SQLite disk ops/s | Murmur / disk incl. persistence |")
	fmt.Println("|---:|---:|---:|")
	for _, batch := range []uint{1, 100} {
		var mp, dp *result
		for i := range results {
			if results[i].batchSize == batch {
				if results[i].backend == "murmur" {
					mp = &results[i]
				} else if results[i].backend == "sqlite-disk" {
					dp = &results[i]
				}
			}
		}
		fmt.Printf("| %d | %vx | %vx |\n", batch, mp.throughput/dp.throughput, mp.persistedThroughput/dp.persistedThroughput)
	}
}

func main() {
	o := parseArgs(os.Args[1:])
	switch o.suite {
	case "all", "no-replication", "crsqlite":
		groups := []bool{false, true}
		if o.suite == "no-replication" {
			groups = []bool{false}
		} else if o.suite == "crsqlite" {
			groups = []bool{true}
		}
		for _, rep := range groups {
			var results []result
			for _, backend := range []string{"murmur", "sqlite-disk"} {
				for _, batch := range []uint{1, 100} {
					c := o
					c.backend, c.batchSize, c.replication = backend, batch, rep
					results = append(results, run(c))
				}
			}
			comparison(results, rep)
		}
	case "single":
		if o.backend == "murmurdb" {
			runDatabaseSQL(o)
		} else {
			run(o)
		}
	}
	fmt.Println("BENCH_SUITE_DONE")
}
