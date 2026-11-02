package storage

import (
	"encoding/binary"
	"errors"
	"os"
)

// File layout for single-file engines: a 4096-byte header followed by
// fixed-size page slots. A slot holds a u32le record length plus the
// EXP record, sized for the largest envelope (keyed AES-256-GCM) so
// switching ciphers never relocates pages.
const (
	headerSize  = 4096
	headerMagic = "MMG1"
	headerVer   = 1

	maxRecordOverhead = 4 + 1 + 4 + 32 + 32 // magic, flag, key id, nonce, tag
	// SlotSize is the fixed stride of one page slot in the raw store.
	SlotSize = 4 + Block + maxRecordOverhead
)

// Header field offsets.
const (
	offMagic  = 0
	offVer    = 4
	offCipher = 5
	offSize   = 8
	offStore  = 16
)

// fileRecords is a recordStore over a raw BlockStore with a header page
// and fixed slots. It backs memory and single-file engines; directory
// engines use RocksDB for cross-implementation format compatibility.
type fileRecords struct {
	raw     BlockStore
	srcPath string // main file; "" for memory stores (not backupable)
	krPath  string // keyring sidecar; "" keeps the ring in memory
	batches uint64
	dirty   bool
	closed  bool
}

func slotOffset(id uint64) int64 {
	return int64(headerSize + id*SlotSize)
}

func (f *fileRecords) load() (recordMeta, error) {
	var meta recordMeta
	meta.cipher = CipherAES256GCM
	if f.raw.Size() == 0 {
		if err := f.persistHeader(&meta); err != nil {
			return meta, err
		}
		return meta, nil
	}
	hdr := make([]byte, headerSize)
	n, err := f.raw.ReadAt(hdr, 0)
	if err != nil || n < headerSize {
		return meta, errors.New("storage: truncated header")
	}
	if string(hdr[offMagic:offMagic+4]) != headerMagic || hdr[offVer] != headerVer {
		return meta, errors.New("storage: bad magic or version")
	}
	switch Cipher(hdr[offCipher]) {
	case CipherAES256GCM:
		meta.cipher = Cipher(hdr[offCipher])
	default:
		return meta, errors.New("storage: unknown cipher")
	}
	meta.size = binary.LittleEndian.Uint64(hdr[offSize:])
	copy(meta.storeID[:], hdr[offStore:offStore+16])
	meta.hasSID = true
	if f.krPath == "" {
		return meta, nil
	}
	env, err := os.ReadFile(f.krPath)
	if err != nil {
		if os.IsNotExist(err) {
			return meta, nil
		}
		return meta, err
	}
	meta.envelope = env
	return meta, nil
}

func (f *fileRecords) persistHeader(meta *recordMeta) error {
	hdr := make([]byte, headerSize)
	copy(hdr[offMagic:], headerMagic)
	hdr[offVer] = headerVer
	hdr[offCipher] = byte(meta.cipher)
	binary.LittleEndian.PutUint64(hdr[offSize:], meta.size)
	copy(hdr[offStore:], meta.storeID[:])
	if err := f.raw.WriteAt(hdr, 0); err != nil {
		return err
	}
	return f.raw.Sync()
}

func (f *fileRecords) saveCipher(c Cipher, sync bool) error {
	meta, err := f.loadHeaderOnly()
	if err != nil {
		return err
	}
	meta.cipher = c
	f.dirty = true
	if err := f.persistHeader(&meta); err != nil {
		return err
	}
	if sync {
		return f.raw.Sync()
	}
	return nil
}

func (f *fileRecords) loadHeaderOnly() (recordMeta, error) {
	var meta recordMeta
	// Fresh stores read as zeros; the open path (load) owns magic
	// validation, so mutations tolerate a missing header.
	if f.raw.Size() < headerSize {
		return meta, nil
	}
	hdr := make([]byte, headerSize)
	n, err := f.raw.ReadAt(hdr, 0)
	if err != nil || n < headerSize {
		return meta, errors.New("storage: truncated header")
	}
	meta.cipher = Cipher(hdr[offCipher])
	meta.size = binary.LittleEndian.Uint64(hdr[offSize:])
	copy(meta.storeID[:], hdr[offStore:offStore+16])
	meta.hasSID = meta.storeID != [16]byte{}
	return meta, nil
}

func (f *fileRecords) saveSize(size uint64) error {
	meta, err := f.loadHeaderOnly()
	if err != nil {
		return err
	}
	meta.size = size
	f.dirty = true
	return f.persistHeader(&meta)
}

func (f *fileRecords) saveStoreID(id [16]byte, sync bool) error {
	meta, err := f.loadHeaderOnly()
	if err != nil {
		return err
	}
	meta.storeID = id
	meta.hasSID = true
	f.dirty = true
	if err := f.persistHeader(&meta); err != nil {
		return err
	}
	if sync {
		return f.raw.Sync()
	}
	return nil
}

func (f *fileRecords) saveKeyring(env []byte, sync bool) error {
	if f.krPath == "" {
		return nil
	}
	f.dirty = true
	if env == nil {
		os.Remove(f.krPath)
		return nil
	}
	tmp := f.krPath + ".tmp"
	if err := os.WriteFile(tmp, env, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, f.krPath); err != nil {
		return err
	}
	if sync {
		if d, err := os.Open(f.krPath); err == nil {
			d.Sync()
			d.Close()
		}
	}
	return nil
}

func (f *fileRecords) getPage(id uint64) ([]byte, bool, error) {
	buf := make([]byte, SlotSize)
	n, err := f.raw.ReadAt(buf, slotOffset(id))
	if err != nil {
		return nil, false, err
	}
	if n < 4 {
		return nil, false, nil
	}
	ln := binary.LittleEndian.Uint32(buf)
	if ln == 0 {
		return nil, false, nil
	}
	if ln > uint32(len(buf)-4) || n < 4+int(ln) {
		return nil, false, ErrCorrupt
	}
	out := make([]byte, ln)
	copy(out, buf[4:4+ln])
	for i := range buf {
		buf[i] = 0
	}
	return out, true, nil
}

func (f *fileRecords) putPage(id uint64, rec []byte) error {
	if len(rec) > SlotSize-4 {
		return errors.New("storage: record exceeds slot")
	}
	slot := make([]byte, SlotSize)
	binary.LittleEndian.PutUint32(slot, uint32(len(rec)))
	copy(slot[4:], rec)
	f.dirty = true
	return f.raw.WriteAt(slot, slotOffset(id))
}

func (f *fileRecords) deletePagesFrom(first uint64) error {
	f.dirty = true
	return f.raw.Truncate(slotOffset(first))
}

func (f *fileRecords) scanPages(fn func(id uint64, rec []byte) error) error {
	raw := f.raw.Size()
	if raw <= headerSize {
		return nil
	}
	blocks := (uint64(raw) - headerSize) / SlotSize
	for id := uint64(0); id < blocks; id++ {
		rec, found, err := f.getPage(id)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if err := fn(id, rec); err != nil {
			return err
		}
	}
	return nil
}

func (f *fileRecords) sync() (uint64, error) {
	if err := f.raw.Sync(); err != nil {
		return 0, err
	}
	if !f.dirty {
		return 0, nil
	}
	f.dirty = false
	f.batches++
	return 1, nil
}

func (f *fileRecords) backupTo(dest, cipher string, group, node []byte) (uint64, error) {
	if f.srcPath == "" {
		return 0, errors.New("storage: memory stores cannot back up")
	}
	if !DestFree(dest) {
		return 0, errors.New("storage: backup destination exists")
	}
	if err := os.MkdirAll(dest, 0700); err != nil {
		RemoveBackup(dest)
		return 0, err
	}
	body, err := os.ReadFile(f.srcPath)
	if err != nil {
		RemoveBackup(dest)
		return 0, err
	}
	if err := os.WriteFile(dest+"/data.mm", body, 0600); err != nil {
		RemoveBackup(dest)
		return 0, err
	}
	if f.krPath != "" {
		if kr, err := os.ReadFile(f.krPath); err == nil {
			if err := os.WriteFile(dest+"/keyring.mm", kr, 0600); err != nil {
				RemoveBackup(dest)
				return 0, err
			}
		}
	}
	if err := WriteBackupManifest(dest, cipher, group, node, 0); err != nil {
		RemoveBackup(dest)
		return 0, err
	}
	return 0, nil
}

func (f *fileRecords) close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	if c, ok := f.raw.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}
