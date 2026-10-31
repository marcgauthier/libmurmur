package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Manifest schema pins (sqlite_murmur_backup.h).
const (
	backupManifestName = "manifest.json"
	backupFormatVer    = 1
)

// CipherCharsetOK reports valid manifest cipher tokens ([a-z0-9]+).
func CipherCharsetOK(cipher string) bool {
	if cipher == "" {
		return false
	}
	for i := 0; i < len(cipher); i++ {
		c := cipher[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func hexLowerBytes(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// WriteBackupManifest writes the byte-exact manifest: flat object, no
// spaces, trailing newline. rocksdb_seq carries the checkpoint
// sequence (0 for the file backend; the field name stays for schema
// compatibility with manifest validators).
func WriteBackupManifest(dest, cipher string, group, node []byte, seq uint64) error {
	if len(group) != 16 || len(node) != 16 {
		return errors.New("storage: manifest ids must be 16 bytes")
	}
	now := time.Now().UnixMilli()
	if now < 0 {
		now = 0
	}
	body := fmt.Sprintf(
		`{"format_version":%d,"cipher":"%s","group_id":"%s","node_id":"%s","rocksdb_seq":%d,"created_unix_ms":%d}`+"\n",
		backupFormatVer, cipher, hexLowerBytes(group), hexLowerBytes(node), seq, now,
	)
	f, err := os.OpenFile(filepath.Join(dest, backupManifestName), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	if _, err := f.Write([]byte(body)); err == nil {
		ok = f.Sync() == nil
	}
	if err := f.Close(); err != nil {
		ok = false
	}
	if !ok {
		os.Remove(filepath.Join(dest, backupManifestName))
		return errors.New("storage: manifest write failed")
	}
	if d, err := os.Open(dest); err == nil {
		d.Sync()
		d.Close()
	}
	if parent := filepath.Dir(dest); parent != "" {
		if d, err := os.Open(parent); err == nil {
			d.Sync()
			d.Close()
		}
	}
	return nil
}

// RemoveBackup cleans a failed backup artifact best-effort.
func RemoveBackup(dest string) {
	os.RemoveAll(dest)
}

// DestFree reports whether dest does not exist (symlinks included).
func DestFree(dest string) bool {
	_, err := os.Lstat(dest)
	return err != nil
}
