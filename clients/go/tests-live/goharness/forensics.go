// Best-effort node forensics (never fails the test).
package goharness

import (
	"fmt"
	"os"
	"path/filepath"
)

// DumpNodeForensics writes a small diagnostic bundle for nodeDir.
func DumpNodeForensics(label, nodeDir, reason string) {
	defer func() { _ = recover() }()
	out := filepath.Join(nodeDir, "forensics.txt")
	f, err := os.Create(out)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "label: %s\nreason: %s\n", label, reason)
	filepath.Walk(nodeDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(nodeDir, p)
		fmt.Fprintf(f, "file: %s (%d bytes)\n", rel, info.Size())
		return nil
	})
}
