package managedharness

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func SampleResources(storePath string) (*Resources, error) {
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	out := &Resources{Goroutines: runtime.NumGoroutine(), Heap: memory.HeapAlloc}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("descriptor and RSS measurements require Linux /proc")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}
	out.FDs = len(entries)
	out.FDTargets = make(map[string]int)
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		out.FDTargets[target]++
		if strings.HasPrefix(target, storePath+string(os.PathSeparator)) && strings.HasSuffix(target, ".sst") {
			out.StorageFDs++
		}
	}
	files, err := os.ReadDir(storePath)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".sst") {
			out.SSTFiles++
		}
	}
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid process statm")
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return nil, err
	}
	out.RSS = pages * uint64(os.Getpagesize())
	return out, nil
}
