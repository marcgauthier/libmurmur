package managedharness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Serve exposes test-only JSON requests over stdio. Concurrent requests
// reach native admission directly; output frames cannot interleave.
func Serve(db *Native, input io.Reader, output io.Writer) error {
	var outputMu sync.Mutex
	encode := func(response Response) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		return json.NewEncoder(output).Encode(response)
	}
	ready := db.Do(Request{Op: "identity"})
	ready.Capabilities = db.Do(Request{Op: "capabilities"}).Capabilities
	if err := encode(ready); err != nil {
		return err
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), 128<<20)
	for scanner.Scan() {
		var request Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return fmt.Errorf("managed request: %w", err)
		}
		workers.Add(1)
		go func(request Request) {
			defer workers.Done()
			if request.Op == "close" {
				db.Close()
				_ = encode(Response{ID: request.ID})
				return
			}
			if request.Op == "resources" {
				response := db.Do(Request{ID: request.ID, Op: "stats"})
				var err error
				response.Resources, err = SampleResources(db.path)
				if err != nil {
					response.RC, response.Error = 1, err.Error()
				}
				_ = encode(response)
				return
			}
			_ = encode(db.Do(request))
		}(request)
	}
	return scanner.Err()
}
