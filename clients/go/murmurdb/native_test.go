package murmurdb

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

func TestWithConnectionUsesSQLPoolStore(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "store") + "?key=0101010101010101010101010101010101010101010101010101010101010101")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = WithConnection(context.Background(), db, func(c *sqlite.Conn) error {
		return c.Exec("CREATE TABLE native_access(id INTEGER PRIMARY KEY)")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO native_access VALUES(1)"); err != nil {
		t.Fatal(err)
	}
	want := errors.New("callback failed")
	if err := WithConnection(context.Background(), db, func(*sqlite.Conn) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WithConnection(ctx, db, func(*sqlite.Conn) error { t.Fatal("canceled callback ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("pool unusable: %v", err)
	}
}
