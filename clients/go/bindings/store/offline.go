package store

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
)

// VerifyBackup validates the checkpoint manifest and decrypts every stored page.
// The checkpoint must be offline.
func VerifyBackup(path string, key [32]byte) error {
	defer clear(key[:])
	file, err := os.Open(filepath.Join(path, "manifest.json"))
	if err != nil {
		return err
	}
	defer file.Close()
	var manifest struct {
		Version int    `json:"format_version"`
		Cipher  string `json:"cipher"`
		Group   string `json:"group_id"`
		Node    string `json:"node_id"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	if err := decoder.Decode(&manifest); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid backup manifest trailing content")
	}
	if manifest.Version != 1 || (manifest.Cipher != "aes256gcm" && manifest.Cipher != "aegis256") {
		return fmt.Errorf("unsupported native backup manifest")
	}
	for _, id := range []string{manifest.Group, manifest.Node} {
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != 16 {
			return fmt.Errorf("invalid backup identity")
		}
	}
	if rc := nvfs.OfflineVerify(path, key); rc != 0 {
		return fmt.Errorf("verify native backup: rc=%d", rc)
	}
	return nil
}

// Restore verifies and copies an offline native checkpoint into a new path.
// Existing destinations and symbolic links are refused.
func Restore(source, destination string, key [32]byte) error {
	defer clear(key[:])
	if err := VerifyBackup(source, key); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(destination)
		}
	}()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		target := filepath.Join(destination, relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup contains symbolic link")
		}
		if entry.IsDir() {
			return os.Mkdir(target, 0700)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup contains nonregular file")
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		if copyErr == nil {
			copyErr = out.Sync()
		}
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	if err := VerifyBackup(destination, key); err != nil {
		return err
	}
	complete = true
	return nil
}

// Rekey changes the encryption master of an offline native store.
func Rekey(path string, oldKey, newKey [32]byte) error {
	defer clear(oldKey[:])
	defer clear(newKey[:])
	if rc := nvfs.OfflineRekey(path, oldKey, newKey, 0); rc != 0 {
		return fmt.Errorf("rekey native store: rc=%d", rc)
	}
	return nil
}
