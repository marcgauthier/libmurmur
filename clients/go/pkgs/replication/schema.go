package replication

import (
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
)

// SchemaDDL creates the replication metadata tables. It mirrors the
// Rust create_tables batch (minus the CRR-ification, which the query
// layer owns).
const SchemaDDL = `
CREATE TABLE IF NOT EXISTS murmur_config(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS murmur_identity(id INTEGER PRIMARY KEY CHECK(id=1),node BLOB,site BLOB,incarnation INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO murmur_identity(id) VALUES(1);
CREATE TABLE IF NOT EXISTS murmur_progress(node BLOB PRIMARY KEY,site BLOB NOT NULL,cursor BLOB NOT NULL,sent BLOB);
CREATE TABLE IF NOT EXISTS murmur_excluded(node BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS murmur_stage(node BLOB NOT NULL,idx INTEGER NOT NULL,data BLOB NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(node,idx));
CREATE TABLE IF NOT EXISTS murmur_kv(key BLOB PRIMARY KEY,value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS murmur_file_chunks(digest BLOB NOT NULL,generation INTEGER NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(digest,generation,idx));
CREATE TABLE IF NOT EXISTS murmur_file_transfers(transfer BLOB PRIMARY KEY,digest BLOB,generation INTEGER,total_bytes INTEGER,identity BLOB,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS murmur_file_staging(transfer BLOB NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(transfer,idx));
`

// EnsureSchema installs the metadata tables on db.
func EnsureSchema(db *sqlite.Conn) error {
	return db.Exec(SchemaDDL)
}

// Setting reads one stripped setting: persisted value or default.
// writer_remote_share derives from writer_local_share and never
// persists.
func Setting(db *sqlite.Conn, name string) (string, error) {
	if name == "writer_remote_share" {
		local, err := Setting(db, "writer_local_share")
		if err != nil {
			return "", err
		}
		n, err := atoi(local)
		if err != nil || n < 1 || n > 99 {
			return "", errInvalid("invalid writer_local_share")
		}
		return itoa(100 - n), nil
	}
	def, ok := DefaultValue(name)
	if !ok {
		return "", errInvalidf("unknown PRAGMA murmur_%s", name)
	}
	st, err := db.Prepare("SELECT value FROM murmur_config WHERE name=?")
	if err != nil {
		return "", err
	}
	defer st.Close()
	if err := st.BindText(1, name); err != nil {
		return "", err
	}
	done, err := st.Step()
	if err != nil {
		return "", err
	}
	if done {
		return def, nil
	}
	return st.ColumnText(0), nil
}

// SetSetting validates and persists one stripped setting.
func SetSetting(db *sqlite.Conn, name, value string) error {
	if err := Validate(name, value); err != nil {
		return err
	}
	st, err := db.Prepare("INSERT INTO murmur_config(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value")
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BindText(1, name); err != nil {
		return err
	}
	if err := st.BindText(2, value); err != nil {
		return err
	}
	done, err := st.Step()
	if err != nil || !done {
		if err == nil {
			return errInvalid("setting write did not complete")
		}
		return err
	}
	return nil
}

// IsCRR reports whether table is replicated (its clock table
// exists).
func IsCRR(db *sqlite.Conn, table string) (bool, error) {
	st, err := db.Prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?")
	if err != nil {
		return false, err
	}
	defer st.Close()
	if err := st.BindText(1, table+"__crsql_clock"); err != nil {
		return false, err
	}
	done, err := st.Step()
	if err != nil {
		return false, err
	}
	return !done, nil
}

// MakeCRR enables replication on a table with a non-null primary
// key: cr-sqlite installs its triggers and clock tables and
// backfills existing rows as versioned cells. Re-running on a CRR
// table is a no-op.
func MakeCRR(db *sqlite.Conn, table string) error {
	yes, err := IsCRR(db, table)
	if err != nil {
		return err
	}
	if yes {
		return nil
	}
	// Same text as the reference (ownership.rs): the name travels
	// as a double-quoted SQL identifier, which SQLite resolves to
	// the table-name string.
	return db.Exec("SELECT crsql_as_crr('main'," + quoteIdent(table) + ")")
}
