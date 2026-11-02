package main

import (
	"fmt"
	"os"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/murmur"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/replication"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

const payload = "sqlite-murmur-benchmark-payload-abcdefghijklmnopqrstuvwxyz-0123456789"

func main() {
	// 1. Pure SQLite+trigger cost: :memory:, Go CRR, autocommit inserts.
	db, err := sqlite.Open(":memory:", sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		panic(err)
	}
	mustExec(db, "CREATE TABLE records (id INTEGER PRIMARY KEY NOT NULL, body TEXT)")
	mustExec(db, "PRAGMA journal_mode=DELETE")
	mustExec(db, "PRAGMA synchronous=FULL")
	if err := replication.EnsureSchema(db); err != nil {
		panic(err)
	}
	if err := sqlite.CrsqliteInit(db); err != nil {
		panic(err)
	}
	if err := replication.MakeCRR(db, "records"); err != nil {
		panic(err)
	}
	mustExec(db, "INSERT INTO records VALUES (0, 'seed')")
	st, err := db.Prepare("INSERT INTO records (id, body) VALUES (?, ?)")
	if err != nil {
		panic(err)
	}
	const n = 2000
	t0 := time.Now()
	for i := 1; i <= n; i++ {
		if err := st.BindInt64(1, int64(i)); err != nil {
			panic(err)
		}
		if err := st.BindText(2, payload); err != nil {
			panic(err)
		}
		if _, err := st.Step(); err != nil {
			panic(err)
		}
		if err := st.Reset(); err != nil {
			panic(err)
		}
	}
	fmt.Printf(":memory:+CRR autocommit insert: %v/op\n", time.Since(t0)/n)
	st.Close()
	db.Close()

	// 2. Raw page cost: dir engine WriteAt 4KB (seal+put+cgo, no SQLite).
	dir, _ := os.MkdirTemp("", "pagecost")
	defer os.RemoveAll(dir)
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	eng, err := storage.OpenDir(dir, key, true)
	if err != nil {
		panic(err)
	}
	blk := make([]byte, 4096)
	for i := range blk {
		blk[i] = byte(i*31 + 7)
	}
	big := make([]byte, 4096*64)
	if err := eng.WriteAt(big, 0); err != nil {
		panic(err)
	}
	t0 = time.Now()
	const m = 2000
	for i := 0; i < m; i++ {
		off := int64((i % 64) * 4096)
		if err := eng.WriteAt(blk, off); err != nil {
			panic(err)
		}
	}
	fmt.Printf("dir WriteAt 4KB overwrite: %v/op\n", time.Since(t0)/m)
	s0 := eng.SnapshotStats()
	fmt.Printf("  PagesWritten=%d Uncompressed=%d Payload=%d Stored=%d\n",
		s0.PagesWritten, s0.UncompressedBytes, s0.CompressedPayloadSum, s0.StoredBytes)
	eng.Close()

	// 3. Pages per commit: murmur open + N single-row commits.
	dir2, _ := os.MkdirTemp("", "pagecommit")
	defer os.RemoveAll(dir2)
	keyb := append([]byte(nil), key[:]...)
	if rc := murmur.Register(keyb, 100, 16384); rc != murmur.CodeOK {
		panic("register")
	}
	defer murmur.Unregister()
	db2, rc := murmur.Open(dir2+"/micro.db", &murmur.OpenOptions{Cipher: "aes256gcm", Compression: "zstd3"})
	if rc != murmur.CodeOK {
		panic("open")
	}
	mustExec(db2, "PRAGMA journal_mode=DELETE")
	mustExec(db2, "PRAGMA synchronous=FULL")
	mustExec(db2, "CREATE TABLE records (id INTEGER PRIMARY KEY NOT NULL, body TEXT)")
	if err := replication.EnsureSchema(db2); err != nil {
		panic(err)
	}
	if err := sqlite.CrsqliteInit(db2); err != nil {
		panic(err)
	}
	if err := replication.MakeCRR(db2, "records"); err != nil {
		panic(err)
	}
	mustExec(db2, "INSERT INTO records VALUES (0, 'seed')")
	st2, err := db2.Prepare("INSERT INTO records (id, body) VALUES (?, ?)")
	if err != nil {
		panic(err)
	}
	t0 = time.Now()
	for i := 1; i <= n; i++ {
		if err := st2.BindInt64(1, int64(i)); err != nil {
			panic(err)
		}
		if err := st2.BindText(2, payload); err != nil {
			panic(err)
		}
		if _, err := st2.Step(); err != nil {
			panic(err)
		}
		if err := st2.Reset(); err != nil {
			panic(err)
		}
	}
	el := time.Since(t0)
	fmt.Printf("murmur+CRR autocommit insert: %v/op\n", el/n)
	st2.Close()
	db2.Close()
}

func mustExec(db *sqlite.Conn, sql string) {
	if err := db.Exec(sql); err != nil {
		panic(sql + ": " + err.Error())
	}
}
