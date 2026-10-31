// Runtime/forensics artifact lifecycle.
package goharness

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// TestsLiveDir returns the tests-live source dir (for locating helpers).
func TestsLiveDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file))
}

// RuntimeDir returns runtime/<scenario>/ under tests-live.
func RuntimeDir(scenario string) string {
	return filepath.Join(TestsLiveDir(), "runtime", scenario)
}

// FailuresDir returns the retained-failures dir.
func FailuresDir() string {
	return filepath.Join(TestsLiveDir(), "failures")
}

// PrepareRuntimeDir wipes and recreates runtime/<scenario>/.
func PrepareRuntimeDir(scenario string) (string, error) {
	dir := RuntimeDir(scenario)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// FinishArtifacts retains the runtime dir under failures/ on failure,
// else removes it.
func FinishArtifacts(scenario, runtimeDir string, failed bool) {
	if !failed {
		os.RemoveAll(runtimeDir)
		return
	}
	dest := filepath.Join(FailuresDir(), UTCStamp()+"-"+scenario)
	os.MkdirAll(FailuresDir(), 0o755)
	if err := os.Rename(runtimeDir, dest); err != nil {
		fmt.Fprintf(os.Stderr, "retain runtime dir: %v\n", err)
	}
}

// UTCStamp returns a filename-safe UTC timestamp.
func UTCStamp() string {
	return time.Now().UTC().Format("20060102-150405")
}
