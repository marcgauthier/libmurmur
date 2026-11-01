package replication

import (
	"fmt"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// Error categories mirror the Rust replication errors.
type Error struct {
	Kind string
	Msg  string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return e.Kind
	}
	return e.Kind + ": " + e.Msg
}

func errInvalid(msg string) *Error    { return &Error{Kind: "Invalid", Msg: msg} }
func errBusy(msg string) *Error       { return &Error{Kind: "Busy", Msg: msg} }
func errClosed(msg string) *Error     { return &Error{Kind: "Closed", Msg: msg} }
func errProtocol(msg string) *Error   { return &Error{Kind: "Protocol", Msg: msg} }
func errOverloaded(msg string) *Error { return &Error{Kind: "Overloaded", Msg: msg} }
func errAuth(msg string) *Error       { return &Error{Kind: "Auth", Msg: msg} }

func errInvalidf(format string, args ...any) *Error {
	return &Error{Kind: "Invalid", Msg: fmt.Sprintf(format, args...)}
}

// Murmur extended result codes (facility 0x53xx, SQLite primary in
// the low byte). Mirror include/sqlite_murmur_errors.h.
const (
	codeInvalid     = (0x5301 << 8) | 1  // SQLITE_ERROR
	codeCorrupt     = (0x5302 << 8) | 11 // SQLITE_CORRUPT
	codeWrongKey    = (0x5303 << 8) | 26 // SQLITE_NOTADB
	codeSchema      = (0x5304 << 8) | 17 // SQLITE_SCHEMA
	codeBusy        = (0x5305 << 8) | 5  // SQLITE_BUSY
	codeClosed      = (0x5306 << 8) | 21 // SQLITE_MISUSE
	codePanicked    = (0x5307 << 8) | 4  // SQLITE_ABORT
	codeStorage     = (0x5308 << 8) | 10 // SQLITE_IOERR
	codeIO          = (0x5309 << 8) | 10 // SQLITE_IOERR
	codeLimit       = (0x530A << 8) | 18 // SQLITE_TOOBIG
	codeProtocol    = (0x530B << 8) | 15 // SQLITE_PROTOCOL
	codeAuth        = (0x530C << 8) | 23 // SQLITE_AUTH
	codeUnavailable = (0x530D << 8) | 14 // SQLITE_CANTOPEN
	codeOverloaded  = (0x530E << 8) | 5  // SQLITE_BUSY
	codeCanceled    = (0x530F << 8) | 9  // SQLITE_INTERRUPT
)

// murmurCode projects an error onto an extended result code. Native
// SQLite failures pass through untouched; other errors map by kind.
func murmurCode(err error) int32 {
	if e, ok := err.(*Error); ok {
		switch e.Kind {
		case "Invalid":
			return codeInvalid
		case "Protocol":
			return codeProtocol
		case "Auth":
			return codeAuth
		case "Unavailable", "Closed":
			return codeUnavailable
		case "Overloaded", "Busy":
			return codeOverloaded
		case "Limit":
			return codeLimit
		case "Conflict":
			return codeProtocol
		}
		return codeStorage
	}
	if e, ok := err.(*sqlite.Error); ok {
		if e.ExtCode != 0 {
			return int32(e.ExtCode)
		}
		if e.Code != 0 {
			return int32(e.Code)
		}
		return codeStorage
	}
	return codeStorage
}

// murmurKind reports the taxonomy kind for status surfaces.
func murmurKind(err error) string {
	if e, ok := err.(*Error); ok {
		switch e.Kind {
		case "Invalid", "Protocol", "Auth", "Unavailable", "Overloaded", "Limit":
			return e.Kind
		case "Busy":
			return "Overloaded"
		case "Closed":
			return "Unavailable"
		case "Conflict":
			return "Protocol"
		}
		return "Storage"
	}
	if _, ok := err.(*sqlite.Error); ok {
		return "Native"
	}
	return "Storage"
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func atoi(s string) (uint64, error) {
	var v uint64
	if s == "" {
		return 0, errInvalid("expected integer")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errInvalid("expected integer")
		}
		d := uint64(c - '0')
		if v > (^(uint64(0))-d)/10 {
			return 0, errInvalid("expected integer")
		}
		v = v*10 + d
	}
	return v, nil
}
