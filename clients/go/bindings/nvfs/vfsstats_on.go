//go:build murmurvfsstats

package nvfs

// Enables the vfs.cc per-op timing counters (diagnosis builds only).
//
// The counters live in libmurmur.a, so this tag alone is not enough:
// rebuild the library with the matching define first, then build Go
// with -tags murmurvfsstats and read VFSStats:
//
//	make clean && make MURMUR_VFS_STATS=1
//	cd clients/go && go test -tags murmurvfsstats ./bindings/nvfs/
//
// This file carries no cgo directives; it only documents the tag.
