// Package goharness drives live multi-node murmur clusters for
// scenario tests. Nodes are native replication drivers over
// VFS-backed stores, run in-process by default or as child
// processes (for kill/crash/partition legs) through tests-live/node.
package goharness

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// SkipUnlessLive short-circuits suites unless live runs are opted in.
func SkipUnlessLive(t *testing.T) {
	t.Helper()
	if os.Getenv("MURMUR_ENGINE_INTEGRATION") != "1" {
		t.Skip("live scenarios are opt-in (set MURMUR_ENGINE_INTEGRATION=1)")
	}
}

// Hex renders bytes lowercase hex.
func Hex(b []byte) string { return hex.EncodeToString(b) }

// DecodeHex32 decodes 64 hex chars into 32 bytes.
func DecodeHex32(s string) ([32]byte, bool) {
	var out [32]byte
	if len(s) != 64 {
		return out, false
	}
	n, err := hex.Decode(out[:], []byte(s))
	if err != nil || n != 32 {
		return out, false
	}
	return out, true
}

// DecodeHex16 decodes 32 hex chars into a node id.
func DecodeHex16(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 32 {
		return out, false
	}
	n, err := hex.Decode(out[:], []byte(s))
	if err != nil || n != 16 {
		return out, false
	}
	return out, true
}

// EnvSeconds reads a duration env override in seconds.
func EnvSeconds(name string, fallbackSecs uint64) time.Duration {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(fallbackSecs) * time.Second
}

// WaitUntil polls cond until true or timeout.
func WaitUntil(timeout, poll time.Duration, cond func() bool) bool {
	end := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if !time.Now().Before(end) {
			return false
		}
		time.Sleep(poll)
	}
}

// SQLLiteral quotes a string literal.
func SQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// TranslateParams rewrites $N placeholders (pgwire style, as the
// ported suites were written) to ? for SQLite. $N must appear in
// order starting at 1; anything else is left untouched.
func TranslateParams(sql string) string {
	var b strings.Builder
	next := 1
	for i := 0; i < len(sql); {
		if sql[i] == '$' {
			j := i + 1
			for j < len(sql) && sql[j] >= '0' && sql[j] <= '9' {
				j++
			}
			if j > i+1 {
				if n, err := strconv.Atoi(sql[i+1 : j]); err == nil && n == next {
					b.WriteByte('?')
					next++
					i = j
					continue
				}
			}
		}
		b.WriteByte(sql[i])
		i++
	}
	return b.String()
}

// ErrorCode extracts a coarse error class for convergence polling:
// "noparam" for missing-table/column style errors that resolve as
// fixtures converge, "" otherwise.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no such table") ||
		strings.Contains(msg, "no such column") {
		return "noparam"
	}
	return ""
}

func fmtErr(op string, err error) error {
	return fmt.Errorf("%s: %w", op, err)
}
