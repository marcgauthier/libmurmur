package managedharness

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

var binaryOnce sync.Once
var binaryPath string
var binaryError error

// BuildNode builds the test-only migration fault hook into the child, while
// ordinary Go clients never link the wrapper or acquire a crash switch.
func BuildNode() (string, error) {
	binaryOnce.Do(func() {
		if configured := os.Getenv("MURMUR_MANAGED_NODE_BIN"); configured != "" {
			binaryPath = configured
			return
		}
		_, source, _, _ := runtime.Caller(0)
		module := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
		binaryPath = filepath.Clean(filepath.Join(module, "../../build/managed-live-node"))
		archive, err := os.Stat(filepath.Join(module, "../../libmurmur.a"))
		if err != nil {
			binaryError = err
			return
		}
		if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
			binaryError = err
			return
		}
		temporary := fmt.Sprintf("%s.%d.tmp", binaryPath, os.Getpid())
		defer os.Remove(temporary)
		cmd := exec.Command("go", "build", "-ldflags=-linkmode=external -extldflags=-Wl,--wrap=sqlite3_exec", "-o", temporary, "./tests-live/managed-node")
		cmd.Dir = module
		// Go's cache does not track external static archives. Include the
		// archive revision in cgo flags so a native rebuild forces relinking.
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1", fmt.Sprintf("CGO_CXXFLAGS=%s -DMURMUR_MIGRATION_CRASH -DMURMUR_TEST_LIBRARY_REV=%d", os.Getenv("CGO_CXXFLAGS"), archive.ModTime().UnixNano()))
		if output, err := cmd.CombinedOutput(); err != nil {
			binaryError = fmt.Errorf("build managed node: %w\n%s", err, output)
			return
		}
		binaryError = os.Rename(temporary, binaryPath)
	})
	return binaryPath, binaryError
}

type Config struct {
	Path             string
	Key, Seed        [32]byte
	Database, Origin [16]byte
}

type Process struct {
	Config     Config
	Identity   Identity
	cmd        *exec.Cmd
	input      io.WriteCloser
	writeMu    sync.Mutex
	mu         sync.Mutex
	nextID     uint64
	pending    map[uint64]chan Response
	dead       bool
	done       chan struct{}
	readerDone chan struct{}
	exitErr    error
	traceMu    sync.Mutex
	trace      [][]byte
	traceBytes int
}

func Start(ctx context.Context, config Config) (*Process, error) {
	binary, err := BuildNode()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, "--path", config.Path, "--key", hex.EncodeToString(config.Key[:]), "--database", hex.EncodeToString(config.Database[:]), "--origin", hex.EncodeToString(config.Origin[:]), "--seed", hex.EncodeToString(config.Seed[:]))
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(config.Path), 0755); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	stderr, err := os.OpenFile(config.Path+".stderr", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	cmd.Stderr = stderr
	p := &Process{Config: config, cmd: cmd, input: input, pending: make(map[uint64]chan Response), done: make(chan struct{}), readerDone: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		stderr.Close()
		input.Close()
		output.Close()
		return nil, err
	}
	ready := make(chan Response, 1)
	go p.read(output, ready)
	go func() {
		err := cmd.Wait()
		stderr.Close()
		p.mu.Lock()
		p.exitErr = err
		p.mu.Unlock()
		close(p.done)
	}()
	select {
	case response := <-ready:
		if response.RC != 0 || response.Identity == nil || response.Capabilities&1 == 0 {
			p.Kill()
			return nil, fmt.Errorf("managed child readiness/capabilities: %+v; build with test migration hook", response)
		}
		p.Identity = *response.Identity
		return p, nil
	case <-p.done:
		p.input.Close()
		<-p.readerDone
		return nil, fmt.Errorf("managed child exited during startup: %v (see %s.stderr)", p.exitErr, config.Path)
	case <-ctx.Done():
		p.Kill()
		return nil, ctx.Err()
	}
}

func (p *Process) remember(kind string, data []byte) {
	entry, _ := json.Marshal(struct {
		Kind string
		At   int64
		Data json.RawMessage
	}{kind, time.Now().UnixNano(), append([]byte(nil), data...)})
	p.traceMu.Lock()
	defer p.traceMu.Unlock()
	p.trace = append(p.trace, entry)
	p.traceBytes += len(entry)
	for p.traceBytes > 16<<20 && len(p.trace) > 1 {
		p.traceBytes -= len(p.trace[0])
		p.trace[0] = nil
		p.trace = p.trace[1:]
	}
}

func (p *Process) read(output io.Reader, ready chan Response) {
	defer close(p.readerDone)
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 64<<10), 128<<20)
	for scanner.Scan() {
		var response Response
		if err := json.Unmarshal(scanner.Bytes(), &response); err != nil {
			break
		}
		p.remember("response", scanner.Bytes())
		if response.ID == 0 {
			select {
			case ready <- response:
			default:
			}
			continue
		}
		p.mu.Lock()
		waiter := p.pending[response.ID]
		delete(p.pending, response.ID)
		p.mu.Unlock()
		if waiter != nil {
			waiter <- response
		}
	}
	p.mu.Lock()
	p.dead = true
	for id, waiter := range p.pending {
		waiter <- Response{ID: id, RC: -1, Error: "managed child stream closed"}
		delete(p.pending, id)
	}
	p.mu.Unlock()
}

func (p *Process) Call(ctx context.Context, request Request) (Response, error) {
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	p.mu.Lock()
	if p.dead {
		p.mu.Unlock()
		return Response{}, errors.New("managed process closed")
	}
	p.nextID++
	request.ID = p.nextID
	waiter := make(chan Response, 1)
	p.pending[request.ID] = waiter
	p.mu.Unlock()
	data, err := json.Marshal(request)
	if err != nil {
		p.mu.Lock()
		delete(p.pending, request.ID)
		p.mu.Unlock()
		return Response{}, err
	}
	p.remember("request", data)
	p.writeMu.Lock()
	_, err = p.input.Write(append(data, '\n'))
	p.writeMu.Unlock()
	if err != nil {
		p.mu.Lock()
		delete(p.pending, request.ID)
		p.mu.Unlock()
		return Response{}, err
	}
	select {
	case response := <-waiter:
		if response.RC < 0 {
			return response, errors.New(response.Error)
		}
		return response, nil
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, request.ID)
		p.mu.Unlock()
		return Response{}, ctx.Err()
	}
}

func (p *Process) Kill() error {
	// No RPC, flush, pre-kill sleep, or progress inspection may precede kill.
	err := p.cmd.Process.Kill()
	p.input.Close()
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		return errors.New("managed child did not reap after SIGKILL")
	}
	select {
	case <-p.readerDone:
	case <-time.After(10 * time.Second):
		return errors.New("managed output reader did not stop after SIGKILL")
	}
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (p *Process) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := p.Call(ctx, Request{Op: "close"})
	p.input.Close()
	select {
	case <-p.done:
	case <-ctx.Done():
		p.Kill()
		return ctx.Err()
	}
	select {
	case <-p.readerDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	return err
}

func (p *Process) Alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *Process) PID() int { return p.cmd.Process.Pid }

func (p *Process) ExitCode() int {
	if p.Alive() {
		return -1
	}
	return p.cmd.ProcessState.ExitCode()
}

func (p *Process) WaitExitCode(ctx context.Context) (int, error) {
	select {
	case <-p.done:
	case <-ctx.Done():
		return -1, ctx.Err()
	}
	select {
	case <-p.readerDone:
	case <-ctx.Done():
		return -1, ctx.Err()
	}
	return p.ExitCode(), nil
}

func (p *Process) WasSIGKILL() bool {
	if p.Alive() {
		return false
	}
	status, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func (p *Process) SaveTrace(path string) error {
	p.traceMu.Lock()
	defer p.traceMu.Unlock()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, entry := range p.trace {
		if _, err := file.Write(append(append([]byte(nil), entry...), '\n')); err != nil {
			return err
		}
	}
	return nil
}
