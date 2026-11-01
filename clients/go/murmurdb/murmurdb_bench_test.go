package murmurdb

import (
	"fmt"
	"testing"

	drv "github.com/marcgauthier/libmurmur/clients/go/bindings/driver"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// seedRows pre-inserts n rows through a raw connection.
func seedRows(conn *sqlite.Conn, n int) error {
	if err := conn.Exec(`CREATE TABLE bench(id INTEGER PRIMARY KEY, body TEXT)`); err != nil {
		return err
	}
	st, err := conn.Prepare(`INSERT INTO bench(id,body) VALUES(?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for i := 0; i < n; i++ {
		if err := st.Bind(i, fmt.Sprintf("body-%d", i)); err != nil {
			return err
		}
		if done, err := st.Step(); err != nil || !done {
			return err
		}
		if err := st.Reset(); err != nil {
			return err
		}
	}
	return nil
}

func openDirect(t *testing.B, seed int) *sqlite.Conn {
	t.Helper()
	if err := drv.Init(0, 0); err != nil {
		t.Fatal(err)
	}
	conn, err := sqlite.OpenVFS(t.TempDir()+"/store",
		sqlite.OpenReadWrite|sqlite.OpenCreate, "sqlite-murmur")
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	if rc := conn.SetKey(key); rc != 0 {
		t.Fatalf("SetKey rc=%d", rc)
	}
	if err := sqlite.CrsqliteInit(conn); err != nil {
		t.Fatal(err)
	}
	if err := seedRows(conn, seed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// BenchmarkDirect is the hand-tuned baseline: prepared statements
// reused across iterations, one insert plus four point selects per op.
func BenchmarkDirect(b *testing.B) {
	const seed = 1000
	conn := openDirect(b, seed)
	ins, err := conn.Prepare(`INSERT INTO bench(id,body) VALUES(?,?)`)
	if err != nil {
		b.Fatal(err)
	}
	defer ins.Close()
	sel, err := conn.Prepare(`SELECT body FROM bench WHERE id = ?`)
	if err != nil {
		b.Fatal(err)
	}
	defer sel.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := seed + i
		if err := ins.Bind(id, "fresh"); err != nil {
			b.Fatal(err)
		}
		if done, err := ins.Step(); err != nil || !done {
			b.Fatalf("insert: done=%v err=%v", done, err)
		}
		if err := ins.Reset(); err != nil {
			b.Fatal(err)
		}
		for k := 0; k < 4; k++ {
			if err := sel.Bind((id + k) % (seed + i + 1)); err != nil {
				b.Fatal(err)
			}
			if done, err := sel.Step(); err != nil || done {
				b.Fatalf("select: done=%v err=%v", done, err)
			}
			_ = sel.ColumnText(0)
			if err := sel.Reset(); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkDatabaseSQL runs the same mix through database/sql.
func BenchmarkDatabaseSQL(b *testing.B) {
	const seed = 1000
	var keyHex string
	for i := 0; i < 32; i++ {
		keyHex += fmt.Sprintf("%02x", i)
	}
	db, err := Open(b.TempDir() + "/store?key=" + keyHex)
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE bench(id INTEGER PRIMARY KEY, body TEXT)`); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < seed; i++ {
		if _, err := db.Exec(`INSERT INTO bench(id,body) VALUES(?,?)`, i, fmt.Sprintf("body-%d", i)); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := seed + i
		if _, err := db.Exec(`INSERT INTO bench(id,body) VALUES(?,?)`, id, "fresh"); err != nil {
			b.Fatal(err)
		}
		for k := 0; k < 4; k++ {
			var body string
			if err := db.QueryRow(`SELECT body FROM bench WHERE id = ?`,
				(id+k)%(seed+i+1)).Scan(&body); err != nil {
				b.Fatal(err)
			}
		}
	}
}
