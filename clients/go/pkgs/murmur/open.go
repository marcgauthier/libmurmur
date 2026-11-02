package murmur

import (
	"errors"
	"strings"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// OpenOptions carries per-open selections. The zero value opens
// read-write, creating the store when missing, with default cipher
// and compression. Cipher and Compression are validated PRAGMA
// tokens; empty leaves the store default.
type OpenOptions struct {
	ReadOnly    bool
	Cipher      string
	Compression string
}

// Open opens an integrated connection through the registered VFS. It
// fails with MISUSE before any Register.
func Open(path string, opts *OpenOptions) (*sqlite.Conn, int) {
	if !isRegistered() {
		return nil, CodeMisuse
	}
	var cipher, compression string
	readOnly := false
	if opts != nil {
		readOnly = opts.ReadOnly
		cipher, compression = opts.Cipher, opts.Compression
	}
	flags := sqlite.OpenReadWrite
	if readOnly {
		flags = sqlite.OpenReadOnly
	} else {
		flags |= sqlite.OpenCreate
	}
	uri := "file:" + path + "?vfs=" + VFSName
	db, err := sqlite.Open(uri, flags|sqlite.OpenURI)
	if err != nil {
		return nil, codeOf(err)
	}
	// No cr-sqlite init here: init writes metadata tables, so it
	// runs only on replication connections (CrsqliteInit at engine
	// start), after this open configured the cold
	// cipher/compression PRAGMAs below. Storage-only databases stay
	// free of crsql_* tables, like the reference.
	trackHandle(db)
	// Stores open keyless; the registered master provisions first
	// through the public key API (PRAGMA key stays for SQL-only
	// clients).
	stateMu.Lock()
	k := master
	stateMu.Unlock()
	if rc := db.SetKey(k); rc != CodeOK {
		return db, rc
	}
	if cipher != "" {
		if !validCipherToken(cipher) {
			return db, CodeMisuse
		}
		if rc := execPragma(db, "cipher", cipher); rc != CodeOK {
			return db, rc
		}
	}
	if compression != "" {
		if !validCompressToken(compression) {
			return db, CodeMisuse
		}
		if rc := execPragma(db, "compression", compression); rc != CodeOK {
			return db, rc
		}
	}
	return db, CodeOK
}

// Close releases an integrated connection. Untracked handles (opened
// around us) still close; only the accounting differs.
func Close(db *sqlite.Conn) int {
	if db == nil {
		return CodeMisuse
	}
	untrackHandle(db)
	return codeOf(db.Close())
}

// execPragma runs PRAGMA name='value' on db. Tokens are validated by
// the caller; quoting stays defensive regardless.
func execPragma(db *sqlite.Conn, name, value string) int {
	if strings.ContainsAny(value, "'\\") {
		return CodeMisuse
	}
	return codeOf(db.Exec("PRAGMA " + name + "='" + value + "'"))
}

func validCipherToken(s string) bool {
	return s == "aes256gcm"
}

func validCompressToken(s string) bool {
	if s == "none" {
		return true
	}
	if len(s) < 5 || !strings.HasPrefix(s, "zstd") {
		return false
	}
	for _, c := range s[4:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// codeOf maps sqlite failures to primary result codes.
func codeOf(err error) int {
	if err == nil {
		return CodeOK
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code
	}
	return CodeError
}
