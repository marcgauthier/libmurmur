package murmur

import (
	"github.com/marcgauthier/libmurmur/clients/go/bindings/nvfs"
	"github.com/marcgauthier/libmurmur/clients/go/pkgs/storage"
)

// Register installs the VFS and captures the master key plus
// defaults. Re-registering updates the configuration; live stores
// keep running with their own keys.
func Register(key []byte, flush uint32, cache int) int {
	if len(key) != 32 {
		return CodeMisuse
	}
	stateMu.Lock()
	copy(master[:], key)
	if flush == 0 {
		flush = 250
	}
	flushMS = flush
	if cache > 0 {
		cachePages = cache
	} else {
		cachePages = storage.CachePagesDefault
	}
	stateMu.Unlock()

	stateMu.Lock()
	pages := cachePages
	flushCfg := flushMS
	stateMu.Unlock()
	cfg := nvfs.VFSConfig{
		FileExt: func(file uint64, name string, value *string) (string, int) {
			if out, rc, ok := runExtension(file, name, value); ok {
				return out, rc
			}
			return nvfs.NoExtensionHint, CodeError
		},
		OnCloseFile: func(handle uint64) {
			dropExtension(handle)
		},
		CachePages: pages,
		FlushMS:    flushCfg,
	}
	if err := nvfs.RegisterVFS(VFSName, cfg); err != nil {
		return CodeError
	}
	stateMu.Lock()
	registered = true
	stateMu.Unlock()
	return CodeOK
}

// Unregister removes the registration. Open handles or live stores
// refuse with BUSY; otherwise keys are wiped.
func Unregister() int {
	stateMu.Lock()
	handlesBusy := len(handles) > 0
	stateMu.Unlock()
	if handlesBusy || nvfs.StoreLiveCount() > 0 {
		return CodeBusy
	}
	stateMu.Lock()
	defer stateMu.Unlock()
	for i := range master {
		master[i] = 0
	}
	for i := range fileKeyCur {
		fileKeyCur[i] = 0
	}
	for i := range fileKeyPrev {
		fileKeyPrev[i] = 0
	}
	haveFileCur, haveFilePrev = false, false
	registered = false
	return CodeOK
}

// RegisterFileKey installs the current (and optional previous) file
// key. A second install fails with MISUSE.
func RegisterFileKey(current, previous []byte) int {
	stateMu.Lock()
	defer stateMu.Unlock()
	if len(current) != 32 || (previous != nil && len(previous) != 32) {
		return CodeMisuse
	}
	if haveFileCur {
		return CodeMisuse
	}
	copy(fileKeyCur[:], current)
	haveFileCur = true
	if previous != nil {
		copy(fileKeyPrev[:], previous)
		haveFilePrev = true
	}
	return CodeOK
}

// FileKeyCurrent reports the current file key, if installed.
func FileKeyCurrent() ([]byte, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if !haveFileCur {
		return nil, false
	}
	return append([]byte(nil), fileKeyCur[:]...), true
}

// FileKeyPrevious reports the previous file key, if installed.
func FileKeyPrevious() ([]byte, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if !haveFilePrev {
		return nil, false
	}
	return append([]byte(nil), fileKeyPrev[:]...), true
}

// InstallExtension claims a file's extension slot. A second install
// fails with MISUSE.
func InstallExtension(handle uint64, ext Extension) int {
	stateMu.Lock()
	defer stateMu.Unlock()
	if _, dup := extensions[handle]; dup {
		return CodeMisuse
	}
	extensions[handle] = ext
	return CodeOK
}

// runExtension invokes the file's installed PRAGMA callback. value
// may be nil.
func runExtension(handle uint64, name string, value *string) (string, int, bool) {
	stateMu.Lock()
	ext, ok := extensions[handle]
	stateMu.Unlock()
	if !ok || ext == nil {
		return "", 0, false
	}
	out, rc := ext.Pragma(name, value)
	return out, rc, true
}

// dropExtension destroys a file's slot on close.
func dropExtension(handle uint64) {
	stateMu.Lock()
	ext, ok := extensions[handle]
	if ok {
		delete(extensions, handle)
	}
	stateMu.Unlock()
	if ok && ext != nil {
		ext.Close()
	}
}
