// Read-your-write and bounded-staleness waits over backend progress.
//
// Go port of wait.rs: SQL scalars run on application threads with no
// async runtime, so waits poll Backend progress every PollInterval
// until the condition holds or the timeout elapses. A zero timeout
// polls exactly once.
package replication

import (
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/tx"
)

// PollInterval paces wait polling.
const PollInterval = 100 * time.Millisecond

// backendErr maps tx errors onto engine errors. Storage reads as
// Unavailable (only teardown closes the store).
func backendErr(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*tx.Error); ok {
		switch e.Kind {
		case "Invalid":
			return errInvalid(e.Msg)
		case "Protocol":
			return errProtocol(e.Msg)
		case "Auth":
			return errAuth(e.Msg)
		case "Storage", "Unavailable":
			return errClosed(e.Msg)
		case "Overloaded":
			return errOverloaded(e.Msg)
		}
		return errProtocol(e.Msg)
	}
	return err
}

// ObservedDeficit is the worst per-origin applied deficit behind
// observed heads: how stale this node is against the newest versions
// it has seen.
func ObservedDeficit(heads []tx.Progress) uint64 {
	var worst uint64
	for _, p := range heads {
		if p.Observed > p.Applied && p.Observed-p.Applied > worst {
			worst = p.Observed - p.Applied
		}
	}
	return worst
}

// WaitForApplied blocks until origin's applied head reaches seq or
// timeout elapses. Waiting for zero returns immediately. True when
// the head was reached, false on timeout.
func WaitForApplied(backend tx.Backend, origin NodeID, seq uint64, timeout time.Duration) (bool, error) {
	if seq == 0 {
		return true, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		heads, err := backend.Progress()
		if err != nil {
			return false, backendErr(err)
		}
		for _, p := range heads {
			if p.Origin == origin && p.Applied >= seq {
				return true, nil
			}
		}
		now := time.Now()
		if !now.Before(deadline) {
			return false, nil
		}
		rest := deadline.Sub(now)
		if rest > PollInterval {
			rest = PollInterval
		}
		time.Sleep(rest)
	}
}

// WaitForLag blocks until the worst observed deficit is at most
// bound, or timeout elapses. With no known-newer state the deficit
// is zero and any bound holds.
func WaitForLag(backend tx.Backend, bound uint64, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		heads, err := backend.Progress()
		if err != nil {
			return false, backendErr(err)
		}
		if ObservedDeficit(heads) <= bound {
			return true, nil
		}
		now := time.Now()
		if !now.Before(deadline) {
			return false, nil
		}
		rest := deadline.Sub(now)
		if rest > PollInterval {
			rest = PollInterval
		}
		time.Sleep(rest)
	}
}
