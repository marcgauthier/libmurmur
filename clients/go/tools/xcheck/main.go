// Cross-implementation format check, Go driver. Same CLI and output
// tags as the C driver (tests/format_xcheck.c, used for the Rust
// side): tools/format_xcheck.sh runs both against each other's
// databases and diffs the tagged lines.
//
// Usage: xcheck <write|append|read|rekey|readnew> <dir> [cipher]
package main

import (
	"fmt"
	"os"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/murmur"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/storage"
)

var fails int

func fail(format string, args ...any) {
	fmt.Printf("FAIL "+format+"\n", args...)
	fails++
}

func master(base byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = base + byte(i)
	}
	return key
}

func doRegister(base byte) bool {
	if rc := murmur.Register(master(base), 0, 0); rc != murmur.CodeOK {
		fail("register")
		return false
	}
	return true
}

func doUnregister() {
	if rc := murmur.Unregister(); rc != murmur.CodeOK {
		fail("unregister")
	}
}

func doOpen(dir, cipher string) *sqlite.Conn {
	opts := &murmur.OpenOptions{Cipher: cipher, Compression: "zstd6"}
	db, rc := murmur.Open(dir, opts)
	if rc != murmur.CodeOK {
		fail("open: %d", rc)
		return nil
	}
	return db
}

func execAll(db *sqlite.Conn, sql, what string) {
	if err := db.Exec(sql); err != nil {
		fail("%s: %v", what, err)
	}
}

func queryPrint(db *sqlite.Conn, sql, tag string) {
	st, err := db.Prepare(sql)
	if err != nil {
		fail("prepare %s", tag)
		return
	}
	defer st.Close()
	fmt.Printf("%s:", tag)
	for {
		done, err := st.Step()
		if err != nil {
			fail("step %s", tag)
			return
		}
		if done {
			break
		}
		fmt.Printf(" %s", st.ColumnText(0))
	}
	fmt.Printf("\n")
}

func doWrite(dir, cipher string) int {
	if !doRegister(0xA0) {
		return 1
	}
	db := doOpen(dir, cipher)
	if db == nil {
		return 1
	}
	execAll(db, "CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT);"+
		"INSERT INTO t(b) VALUES('alpha'),('beta'),('gamma');", "seed rows")
	// Seal after seeding: legacy pages plus keyed pages.
	if rc := murmur.SetKeyringParam(dir, storage.KeyringParamKDF, 0); rc != murmur.CodeOK {
		fail("seal")
	}
	execAll(db, "INSERT INTO t(b) VALUES('delta');", "keyed row")
	if _, rc := murmur.KeyringRotate(dir); rc != murmur.CodeOK {
		fail("rotate")
	}
	execAll(db, "INSERT INTO t(b) VALUES('epsilon');", "rotated row")
	if rc := murmur.Flush(dir); rc != murmur.CodeOK {
		fail("flush")
	}
	if rc := murmur.Close(db); rc != murmur.CodeOK {
		fail("close")
	}
	doUnregister()
	if fails == 0 {
		fmt.Printf("WRITE-OK %s\n", cipher)
	}
	return boolInt(fails != 0)
}

func doAppend(dir string) int {
	if !doRegister(0xA0) {
		return 1
	}
	db := doOpen(dir, "")
	if db == nil {
		return 1
	}
	execAll(db, "INSERT INTO t(b) VALUES('zeta');", "append row")
	if rc := murmur.Close(db); rc != murmur.CodeOK {
		fail("close")
	}
	doUnregister()
	if fails == 0 {
		fmt.Printf("APPEND-OK\n")
	}
	return boolInt(fails != 0)
}

func doRead(dir string, base byte, tag string) int {
	if !doRegister(base) {
		return 1
	}
	db := doOpen(dir, "")
	if db == nil {
		return 1
	}
	queryPrint(db, "SELECT b FROM t ORDER BY a", "ROWS")
	queryPrint(db, "PRAGMA cipher", "CIPHER")
	queryPrint(db, "PRAGMA compression", "COMPRESSION")
	// Inventory is offline-only: close first. The script greps tagged
	// lines, so INV-after-close still matches.
	if rc := murmur.Close(db); rc != murmur.CodeOK {
		fail("close")
	}
	if js, rc := murmur.KeyInventory(dir); rc != murmur.CodeOK {
		fail("inventory")
	} else {
		fmt.Printf("INV: %s\n", js)
	}
	doUnregister()
	if fails == 0 {
		fmt.Printf("READ-OK %s\n", tag)
	}
	return boolInt(fails != 0)
}

func doRekey(dir string) int {
	oldM := master(0xA0)
	newM := master(0xC0)
	var oldB, newB [32]byte
	copy(oldB[:], oldM)
	copy(newB[:], newM)
	if !doRegister(0xA0) {
		return 1
	}
	if rc := murmur.Rekey(dir, oldB, newB, 0); rc != murmur.CodeOK {
		fail("rekey: %d", rc)
		return 1
	}
	doUnregister()
	fmt.Printf("REKEY-OK\n")
	return 0
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("usage: xcheck <write|append|read|rekey|readnew> <dir> [cipher]\n")
		os.Exit(2)
	}
	mode, dir := os.Args[1], os.Args[2]
	cipher := "aes256gcm"
	if len(os.Args) > 3 {
		cipher = os.Args[3]
	}
	switch mode {
	case "write":
		os.Exit(doWrite(dir, cipher))
	case "append":
		os.Exit(doAppend(dir))
	case "read":
		os.Exit(doRead(dir, 0xA0, "old"))
	case "rekey":
		os.Exit(doRekey(dir))
	case "readnew":
		os.Exit(doRead(dir, 0xC0, "new"))
	default:
		fmt.Printf("unknown mode %s\n", mode)
		os.Exit(2)
	}
}
