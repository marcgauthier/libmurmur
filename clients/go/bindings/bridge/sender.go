package bridge

/*
#include <stdlib.h>
#include "bridge_sender.h"
#include "sqlite3.h"
*/
import "C"

import (
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

type SenderStatus struct {
	Published, BaselineRows, FileParts uint64
	BaselineComplete                   bool
	LastResult                         int
}

// Sender drains Low's durable outbox to an immutable directory and optionally
// prepares existing rows in resumable batches. Close BEFORE closing db or
// changing capture/table registrations. Use WithNativeControl for lifecycle.
type Sender struct {
	mu  sync.Mutex
	ptr *C.murmur_bridge_sender_t
}

func NewSender(db *sqlite.Conn, source [16]byte, stream, directory string, prepareBaseline bool) (*Sender, error) {
	if db == nil || directory == "" || strings.IndexByte(directory, 0) >= 0 {
		return nil, &Error{Code: int(C.SQLITE_MISUSE)}
	}
	if _, err := native(Header{Stream: stream}); err != nil {
		return nil, err
	}
	s, d := C.CString(stream), C.CString(directory)
	defer C.free(unsafe.Pointer(s))
	defer C.free(unsafe.Pointer(d))
	var prepare C.int
	if prepareBaseline {
		prepare = 1
	}
	out := &Sender{}
	err := result(C.murmur_bridge_sender_new((*C.sqlite3)(db.NativeDB()), (*C.uint8_t)(unsafe.Pointer(&source[0])), s, d, prepare, &out.ptr))
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Sender) Poll(maxArtifacts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil || maxArtifacts < 1 || maxArtifacts > 256 {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_sender_poll(s.ptr, C.size_t(maxArtifacts)))
}
func (s *Sender) Start(interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil || interval < 10*time.Millisecond || interval > 60*time.Second {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_sender_start(s.ptr, C.uint(interval/time.Millisecond)))
}
func (s *Sender) Stop() { s.mu.Lock(); defer s.mu.Unlock(); C.murmur_bridge_sender_stop(s.ptr) }
func (s *Sender) Status() SenderStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out C.murmur_bridge_sender_status_t
	C.murmur_bridge_sender_status(s.ptr, &out)
	return SenderStatus{Published: uint64(out.published), BaselineRows: uint64(out.baseline_rows), FileParts: uint64(out.file_parts), BaselineComplete: out.baseline_complete != 0, LastResult: int(out.last_result)}
}
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	C.murmur_bridge_sender_free(s.ptr)
	s.ptr = nil
	return nil
}

// Files attaches a borrowed native file store while the sender is stopped.
// The store must use this sender's SQL handle and outlive the sender.
func (s *Sender) Files(store unsafe.Pointer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ptr == nil || store == nil {
		return &Error{Code: int(C.SQLITE_MISUSE)}
	}
	return result(C.murmur_bridge_sender_files(s.ptr, (*C.murmur_files_t)(store)))
}
