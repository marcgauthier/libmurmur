package storage

import (
	"errors"
	"sync"
)

// BlockStore is a byte-addressable main-database page store. It mirrors
// the VFS contract: ReadAt reports short reads by returning n < len(p)
// with a nil error. Backends (SQLite-native files, RocksDB) plug in here;
// the VFS shell never depends on a specific one.
type BlockStore interface {
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) error
	Truncate(size int64) error
	Size() int64
	Sync() error
}

// MemBlockStore is an in-memory BlockStore for tests and temp databases.
type MemBlockStore struct {
	mu    sync.RWMutex
	bytes []byte
	size  int64
	syncs int64
}

// ReadAt implements BlockStore.
func (m *MemBlockStore) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("storage: negative read offset")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if off >= m.size {
		return 0, nil
	}
	n := copy(p, m.bytes[off:m.size])
	return n, nil
}

// WriteAt implements BlockStore.
func (m *MemBlockStore) WriteAt(p []byte, off int64) error {
	if off < 0 {
		return errors.New("storage: negative write offset")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	end := off + int64(len(p))
	if end > int64(len(m.bytes)) {
		m.bytes = append(m.bytes, make([]byte, end-int64(len(m.bytes)))...)
	}
	copy(m.bytes[off:], p)
	if end > m.size {
		m.size = end
	}
	return nil
}

// Truncate implements BlockStore.
func (m *MemBlockStore) Truncate(size int64) error {
	if size < 0 {
		return errors.New("storage: negative truncate")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if size > int64(len(m.bytes)) {
		m.bytes = append(m.bytes, make([]byte, size-int64(len(m.bytes)))...)
	} else {
		clear(m.bytes[size:])
		m.bytes = m.bytes[:size]
	}
	m.size = size
	return nil
}

// Size implements BlockStore.
func (m *MemBlockStore) Size() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size
}

// Sync implements BlockStore. Memory stores have nothing to flush.
func (m *MemBlockStore) Sync() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncs++
	return nil
}
