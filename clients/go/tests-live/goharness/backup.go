// Cluster backup/restore built on the native store ops.
package goharness

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/store"
)

// Backup checkpoints node i's live store plus manifest into dest.
func (c *Cluster) Backup(i int, dest string) error {
	n := c.nodes[i]
	var nodeID [16]byte
	copy(nodeID[:], n.ID[:])
	return store.Backup(n.DataDir, c.Key, dest, c.Group, nodeID)
}

// RestoreOptions carries optional fresh identities for Restore.
type RestoreOptions struct {
	FreshNode  *[16]byte
	FreshGroup *[16]byte
}

// Restore copies a backup tree to dest and rewrites identities.
func (c *Cluster) Restore(backupDir, destDir string, opts *RestoreOptions) error {
	if err := copyTree(backupDir, destDir); err != nil {
		return fmt.Errorf("restore copy: %w", err)
	}
	if err := ensureInit(); err != nil {
		return err
	}
	dataDir := destDir
	if _, err := os.Stat(filepath.Join(destDir, "data")); err == nil {
		dataDir = filepath.Join(destDir, "data")
	}
	// Backups of live stores are store dirs directly.
	conn, err := sqlite.OpenVFS(dataDir, sqlite.OpenReadWrite, "sqlite-murmur")
	if err != nil {
		return fmt.Errorf("restore open: %w", err)
	}
	defer conn.Close()
	if rc := conn.SetKey(c.Key); rc != 0 {
		return fmt.Errorf("restore key: rc=%d", rc)
	}
	if opts != nil && opts.FreshNode != nil {
		if err := conn.Exec(fmt.Sprintf("UPDATE murmur_identity SET node=x'%s' WHERE id=1", Hex(opts.FreshNode[:]))); err != nil {
			return fmt.Errorf("restore node id: %w", err)
		}
	}
	if opts != nil && opts.FreshGroup != nil {
		if err := conn.Exec(fmt.Sprintf("INSERT INTO murmur_config(name,value) VALUES('group_id','%s') ON CONFLICT(name) DO UPDATE SET value=excluded.value", Hex(opts.FreshGroup[:]))); err != nil {
			return fmt.Errorf("restore group id: %w", err)
		}
	}
	return nil
}

func copyTree(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return copyFile(src, dst)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
