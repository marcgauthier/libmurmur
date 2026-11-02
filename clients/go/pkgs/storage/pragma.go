package storage

import (
	"strings"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/zstd"
)

func rocksdbIsIOError(err error) bool {
	return err != nil && isIOError(err.Error())
}

// ExtensionPragma handles murmur_* names on behalf of the replication
// extension. It is nil until the extension registers one; the engine
// then rejects murmur_* with the documented hint.
type ExtensionPragma func(store *Engine, name string, value *string, readOnly bool) (int, string)

// Pragma serves the engine PRAGMA table. value is nil for read-back.
// locked reports whether any connection holds a lock on the store (the
// VFS supplies it). Return codes are SQLite result codes; NOTFOUND lets
// SQLite handle names the engine does not own.
func (e *Engine) Pragma(name string, value *string, readOnly, locked bool) (int, string) {
	e.mu.Lock()
	live, handle, closed := e.live, e.handle, e.closed
	e.mu.Unlock()
	if live {
		// Registry shells serve the C++ table (locked is
		// computed in C++ from the lock table).
		if closed {
			return CodeIOErr, ""
		}
		return nvfs.PragmaStore(handle, name, value, readOnly)
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "murmur_") {
		return e.murmurPragma(lower, value, readOnly)
	}
	switch lower {
	case "background_threads":
		return e.pragmaBackgroundThreads(value, readOnly)
	case "compression":
		return e.pragmaCompression(value, readOnly)
	case "flush_interval_ms":
		return e.pragmaFlushInterval(value)
	case "cipher":
		return e.pragmaCipher(value, readOnly, locked)
	case "journal_mode":
		if value != nil && !strings.EqualFold(*value, "delete") {
			return CodeError, "sqlite-murmur requires journal_mode=DELETE"
		}
		return CodeNotFound, ""
	case "mmap_size":
		return CodeOK, "0"
	default:
		if strings.HasPrefix(lower, "rocksdb_") {
			return e.pragmaRocksDB(name, value, readOnly)
		}
		return CodeNotFound, ""
	}
}

func (e *Engine) pragmaRocksDB(name string, value *string, readOnly bool) (int, string) {
	type option struct {
		backend string // live backend knob, "" for engine-side
		minimum uint64
		maximum uint64
	}
	var opt option
	var which int // 0 sync, 1 wbuf, 2 wbufnum, 3 cache, 4 bgjobs
	switch strings.ToLower(name) {
	case "rocksdb_sync":
		opt = option{"", 0, 1}
		which = 0
	case "rocksdb_write_buffer_size":
		opt = option{"write_buffer_size", 65536, 9223372036854775807}
		which = 1
	case "rocksdb_max_write_buffer_number":
		opt = option{"max_write_buffer_number", 2, 2147483647}
		which = 2
	case "rocksdb_block_cache_bytes":
		opt = option{"", 0, 9223372036854775807}
		which = 3
	case "rocksdb_max_background_jobs":
		opt = option{"max_background_jobs", 1, 2147483647}
		which = 4
	default:
		return CodeNotFound, ""
	}
	rb, hasRocks := e.RocksBackend()
	if !hasRocks {
		// File-backed engines own no RocksDB knobs.
		return CodeNotFound, ""
	}
	if value != nil && readOnly {
		return CodeReadOnly, "cannot set " + name + " on a read-only connection"
	}
	var number uint64
	if value != nil {
		n, ok := parseUint(*value)
		if !ok || n < opt.minimum || n > opt.maximum {
			return CodeError, name + " requires an integer from " + utoa(opt.minimum) + " through " + utoa(opt.maximum)
		}
		number = n
	}
	if value != nil {
		var failed error
		switch which {
		case 0:
			e.SetRocksSync(number != 0)
		case 3:
			rb.setCacheCapacity(int(number))
		case 1, 2:
			failed = rb.setCFOptions(map[string]string{opt.backend: utoa(number)})
		case 4:
			failed = rb.setDBOption(opt.backend, utoa(number))
		}
		if failed != nil {
			text := name + ": " + failed.Error()
			if rocksdbIsIOError(failed) {
				return CodeIOErr, text
			}
			return CodeError, text
		}
	}
	switch which {
	case 0:
		if e.RocksSync() {
			number = 1
		} else {
			number = 0
		}
	case 3:
		number = uint64(rb.cacheCapacity())
	default:
		live, err := rb.liveOption(opt.backend)
		if err != nil {
			return CodeError, name + ": " + err.Error()
		}
		number = live
	}
	return CodeOK, utoa(number)
}

var extensionPragma ExtensionPragma

// RegisterExtensionPragma installs the murmur_* handler. Only the
// replication package calls this.
func RegisterExtensionPragma(fn ExtensionPragma) {
	extensionPragma = fn
}

func (e *Engine) murmurPragma(name string, value *string, readOnly bool) (int, string) {
	switch name {
	case "murmur_kdf", "murmur_scrypt_n", "murmur_scrypt_r", "murmur_scrypt_p":
		return e.pragmaKDF(name, value, readOnly)
	}
	if extensionPragma != nil {
		return extensionPragma(e, name, value, readOnly)
	}
	return CodeError, "load murmur-replication before using murmur PRAGMAs"
}

func (e *Engine) pragmaKDF(name string, value *string, readOnly bool) (int, string) {
	kdf, time, mem, threads := e.StagedKDF()
	sealed := e.Sealed()
	current := ""
	var param int
	switch name {
	case "murmur_kdf":
		if sealed {
			e.mu.Lock()
			k := e.ring.KDF
			e.mu.Unlock()
			if k == KDFScrypt {
				current = "scrypt"
			} else {
				current = "direct"
			}
		} else if kdf == KDFScrypt {
			current = "scrypt"
		} else {
			current = "direct"
		}
		param = KeyringParamKDF
	case "murmur_scrypt_n":
		if sealed {
			e.mu.Lock()
			time = e.ring.ScryptN
			e.mu.Unlock()
		}
		current = utoa(uint64(time))
		param = KeyringParamScryptN
	case "murmur_scrypt_r":
		if sealed {
			e.mu.Lock()
			mem = e.ring.ScryptR
			e.mu.Unlock()
		}
		current = utoa(uint64(mem))
		param = KeyringParamScryptR
	case "murmur_scrypt_p":
		if sealed {
			e.mu.Lock()
			threads = e.ring.ScryptP
			e.mu.Unlock()
		}
		current = utoa(uint64(threads))
		param = KeyringParamScryptP
	}
	if value == nil {
		return CodeOK, current
	}
	if readOnly {
		return CodeReadOnly, "cannot set " + name + " on a read-only connection"
	}
	if sealed {
		return CodeBusy, name + " cannot change once sealed"
	}
	if param == KeyringParamKDF {
		var v uint64
		switch strings.ToLower(*value) {
		case "direct":
			v = KDFDirectHKDF
		case "scrypt":
			v = KDFScrypt
		default:
			return CodeError, "murmur_kdf must be direct or scrypt"
		}
		if rc := e.SetParam(param, v, readOnly); rc != CodeOK {
			return rc, ""
		}
		if v == KDFScrypt {
			return CodeOK, "scrypt"
		}
		return CodeOK, "direct"
	}
	v, ok := parseUint(*value)
	if !ok {
		return CodeError, name + " requires an unsigned integer"
	}
	if rc := e.SetParam(param, v, readOnly); rc != CodeOK {
		if rc == CodeError {
			return rc, name + " out of range"
		}
		return rc, ""
	}
	_, t, m, th := e.StagedKDF()
	switch param {
	case KeyringParamScryptN:
		return CodeOK, utoa(uint64(t))
	case KeyringParamScryptR:
		return CodeOK, utoa(uint64(m))
	default:
		return CodeOK, utoa(uint64(th))
	}
}

func (e *Engine) pragmaBackgroundThreads(value *string, readOnly bool) (int, string) {
	if value != nil && readOnly {
		return CodeReadOnly, ""
	}
	if value != nil {
		n, ok := parseUint(*value)
		if !ok || n == 0 || n > 256 {
			return CodeError, "background_threads requires an integer from 1 through 256"
		}
		e.mu.Lock()
		e.bgThreads = uint32(n)
		e.mu.Unlock()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return CodeOK, utoa(uint64(e.bgThreads))
}

func (e *Engine) pragmaCompression(value *string, readOnly bool) (int, string) {
	level := int32(-1)
	if value != nil {
		if readOnly {
			return CodeReadOnly, "cannot set compression on a read-only connection"
		}
		text := *value
		if strings.EqualFold(text, "none") {
			level = 0
		} else if len(text) >= 4 && strings.EqualFold(text[:4], "zstd") {
			if n, ok := parseUint(text[4:]); ok && n >= 1 && n <= uint64(zstd.MaxLevel) {
				level = int32(n)
			}
		}
		if level < 0 {
			return CodeError, "compression must be none or zstd1 through zstd22"
		}
		e.mu.Lock()
		if err := e.pushLevel(level); err != nil {
			e.mu.Unlock()
			return CodeError, "could not apply compression setting"
		}
		e.compression = level
		e.mu.Unlock()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.compression == 0 {
		return CodeOK, "none"
	}
	return CodeOK, "zstd" + utoa(uint64(e.compression))
}

func (e *Engine) pragmaFlushInterval(value *string) (int, string) {
	if value != nil {
		n, ok := parseUint(*value)
		if !ok {
			return CodeError, "flush_interval_ms requires an unsigned integer"
		}
		if n == 0 {
			n = 250
		}
		if n > 0xFFFFFFFF {
			return CodeError, "flush_interval_ms requires an unsigned integer"
		}
		e.mu.Lock()
		e.flushInterval = uint32(n)
		e.mu.Unlock()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return CodeOK, utoa(uint64(e.flushInterval))
}

func (e *Engine) pragmaCipher(value *string, readOnly, locked bool) (int, string) {
	if value != nil {
		if readOnly {
			return CodeReadOnly, "cannot set cipher on a read-only connection"
		}
		var c Cipher
		switch {
		case strings.EqualFold(*value, "aes256gcm"):
			c = CipherAES256GCM
		default:
			return CodeError, "cipher must be aes256gcm"
		}
		if rc := e.SetCipher(c, readOnly, locked); rc != CodeOK {
			if rc == CodeBusy {
				return rc, "cipher can only be changed on an empty database outside a transaction"
			}
			return rc, "could not persist cipher setting"
		}
	}
	return CodeOK, e.CipherName()
}

// parseUint parses a decimal unsigned integer with overflow rejection.
func parseUint(text string) (uint64, bool) {
	if text == "" {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint64(c - '0')
		if v > (^(uint64(0))-d)/10 {
			return 0, false
		}
		v = v*10 + d
	}
	return v, true
}
