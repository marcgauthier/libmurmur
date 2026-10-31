package storage

import (
	"errors"
	"os"
	"sync"
)

// FileBlockStore is a BlockStore over one regular file.
type FileBlockStore struct {
	mu sync.RWMutex
	f  *os.File
}

func openFileStore(path string, create bool) (*FileBlockStore, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	return &FileBlockStore{f: f}, nil
}

// ReadAt implements BlockStore.
func (s *FileBlockStore) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("storage: negative read offset")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int
	for total < len(p) {
		n, err := s.f.ReadAt(p[total:], off+int64(total))
		total += n
		if err != nil {
			// Short reads (EOF) are normal for sparse tails.
			return total, nil
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

// WriteAt implements BlockStore.
func (s *FileBlockStore) WriteAt(p []byte, off int64) error {
	if off < 0 {
		return errors.New("storage: negative write offset")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var done int
	for done < len(p) {
		n, err := s.f.WriteAt(p[done:], off+int64(done))
		done += n
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("storage: short file write")
		}
	}
	return nil
}

// Truncate implements BlockStore.
func (s *FileBlockStore) Truncate(size int64) error {
	if size < 0 {
		return errors.New("storage: negative truncate")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Truncate(size)
}

// Size implements BlockStore.
func (s *FileBlockStore) Size() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, err := s.f.Stat()
	if err != nil {
		return 0
	}
	return st.Size()
}

// Sync implements BlockStore.
func (s *FileBlockStore) Sync() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.f.Sync()
}

// Close releases the file handle.
func (s *FileBlockStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
