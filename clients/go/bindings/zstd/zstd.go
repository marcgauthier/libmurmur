// Package zstd is the thin Go API over the vendored zstd core in
// deps/zstd (compiled into this package): the only zstd in the
// binary, shared with the C++ page codec. Compression levels match
// upstream zstd (1-22); decompression is always output-bounded
// against hostile frames.
package zstd

/*
#cgo CFLAGS: -I../../../../deps/zstd -DZSTD_DISABLE_ASM=1 -O2
#cgo LDFLAGS: ${SRCDIR}/../../../../libmurmur.a
#include <stdlib.h>
#include "zstd.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Levels mirror the PRAGMA surface (zstd1-zstd22).
const (
	DefaultLevel = 3
	MaxLevel     = 22
)

// ErrTooLarge reports a frame whose output exceeds the caller's bound.
var ErrTooLarge = errors.New("zstd: output exceeds bound")

// CompressBound reports the worst-case output size for n input bytes.
func CompressBound(n int) int {
	return int(C.ZSTD_compressBound(C.size_t(n)))
}

func zstdErr(op string, code C.size_t) error {
	if C.ZSTD_getErrorCode(code) == C.ZSTD_error_dstSize_tooSmall {
		return ErrTooLarge
	}
	return errors.New("zstd: " + op + ": " + C.GoString(C.ZSTD_getErrorName(code)))
}

// Compress compresses src at level (1-22).
func Compress(src []byte, level int) ([]byte, error) {
	if level < 1 || level > MaxLevel {
		return nil, errors.New("zstd: level out of range")
	}
	bound := C.ZSTD_compressBound(C.size_t(len(src)))
	dst := make([]byte, int(bound))
	var sptr unsafe.Pointer
	if len(src) > 0 {
		sptr = unsafe.Pointer(&src[0])
	}
	n := C.ZSTD_compress(unsafe.Pointer(&dst[0]), bound, sptr, C.size_t(len(src)), C.int(level))
	if C.ZSTD_isError(n) != 0 {
		return nil, zstdErr("compress", n)
	}
	return dst[:int(n)], nil
}

// DecompressInto decompresses src into dst, which must already size
// the output. It reports the bytes written.
func DecompressInto(dst, src []byte) (int, error) {
	if len(src) == 0 {
		return 0, errors.New("zstd: empty input")
	}
	if len(dst) == 0 {
		return 0, ErrTooLarge
	}
	n := C.ZSTD_decompress(unsafe.Pointer(&dst[0]), C.size_t(len(dst)), unsafe.Pointer(&src[0]), C.size_t(len(src)))
	if C.ZSTD_isError(n) != 0 {
		return 0, zstdErr("decompress", n)
	}
	return int(n), nil
}

// Decompress decompresses src with output capped at maxOut bytes.
func Decompress(src []byte, maxOut int) ([]byte, error) {
	if maxOut <= 0 {
		return nil, ErrTooLarge
	}
	if len(src) == 0 {
		return nil, errors.New("zstd: empty input")
	}
	dst := make([]byte, maxOut)
	n, err := DecompressInto(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
