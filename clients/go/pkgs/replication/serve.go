// Serve plane: handshake, pull, serve_pull, and stream dispatch.
//
// Go port of the Engine choreography in murmur-replication
// (crates/murmur-replication/src/engine.rs: session, handshake,
// pull_loop, pull, pull_once, serve_pull). The QUIC specifics stay
// behind the Transport interface; this file runs the message
// choreography over any (io.Writer, io.Reader) stream pair, which is
// also what the loopback test exercises.
//
// Deferred to their steps: schema adoption retry (schema), snapshot
// verbs (snapshot), vet/fetch compat (fetch), retention touch
// (retention/tx), gossip datagrams (membership), dial/listen sessions
// (transport).
package replication

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/netip"
	"strings"
	"sync"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/tx"
)

// serveParams are the numeric replication budgets plus identity,
// loaded from settings.
type serveParams struct {
	sessions         int
	queueBytes       int
	batchBytes       int
	maxBatchBytes    int
	stagingBytes     int
	stagingTimeoutMs int64
	gossipFanout     int
}

// loadServeParams reads the serve budgets. Settings carry validated
// ranges; a corrupt value fails Invalid like the Rust loader.
func loadServeParams(db *sqlite.Conn) (serveParams, error) {
	var p serveParams
	num := func(name string) (uint64, error) {
		raw, err := Setting(db, name)
		if err != nil {
			return 0, err
		}
		v, err := atoi(raw)
		if err != nil {
			return 0, errInvalidf("invalid %s", name)
		}
		return v, nil
	}
	get := func(name string, dst *int) error {
		v, err := num(name)
		if err != nil {
			return err
		}
		if v > uint64(math_MaxInt64) {
			return errInvalidf("invalid %s", name)
		}
		*dst = int(v)
		return nil
	}
	if err := get("sessions", &p.sessions); err != nil {
		return p, err
	}
	if err := get("queue_bytes", &p.queueBytes); err != nil {
		return p, err
	}
	if err := get("batch_bytes", &p.batchBytes); err != nil {
		return p, err
	}
	if err := get("max_batch_bytes", &p.maxBatchBytes); err != nil {
		return p, err
	}
	if err := get("staging_bytes", &p.stagingBytes); err != nil {
		return p, err
	}
	if err := get("gossip_fanout", &p.gossipFanout); err != nil {
		return p, err
	}
	v, err := num("staging_timeout_ms")
	if err != nil {
		return p, err
	}
	if v > uint64(math_MaxInt64) {
		return p, errInvalid("invalid staging_timeout_ms")
	}
	p.stagingTimeoutMs = int64(v)
	// Loader invariant: the export budget must fit the serving and
	// staging budgets, so semaphore acquisition can never wedge.
	if p.batchBytes > p.maxBatchBytes ||
		p.maxBatchBytes > 64<<20 ||
		p.maxBatchBytes > p.queueBytes ||
		p.maxBatchBytes > p.stagingBytes {
		return p, errInvalid("require batch_bytes <= max_batch_bytes <= min(queue_bytes, staging_bytes, 64 MiB)")
	}
	return p, nil
}

// byteSem is a counting semaphore for byte budgets. The zero value is
// unusable; use newByteSem. A nil *byteSem skips accounting (offline
// engines without Start).
type byteSem struct {
	mu    sync.Mutex
	cond  sync.Cond
	avail int
	cap   int
}

func newByteSem(n int) *byteSem {
	s := &byteSem{avail: n, cap: n}
	s.cond.L = &s.mu
	return s
}

// inUse reports bytes currently reserved (health only).
func (s *byteSem) inUse() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cap < s.avail {
		return 0
	}
	return s.cap - s.avail
}

func (s *byteSem) acquire(n int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.avail < n {
		s.cond.Wait()
	}
	s.avail -= n
}

func (s *byteSem) release(n int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.avail += n
	s.cond.Broadcast()
}

// claimSite pins murmur_identity.site to the CRR site id, refusing to
// run when a previous claim differs (cloned database).
func claimSite(db *sqlite.Conn) (NodeID, error) {
	var zero NodeID
	site, err := SiteID(db)
	if err != nil {
		return zero, err
	}
	st, err := db.Prepare("SELECT site FROM murmur_identity WHERE id=1")
	if err != nil {
		return zero, err
	}
	defer st.Close()
	stepDone, err := st.Step()
	if err != nil {
		return zero, err
	}
	if !stepDone && st.ColumnType(0) != sqlite.TypeNull {
		old := st.ColumnBlob(0)
		if string(old) != string(site[:]) {
			return zero, errAuth("site identity changed")
		}
	}
	st.Close()
	if err := execArgs(db, "UPDATE murmur_identity SET site=?1 WHERE id=1", site[:]); err != nil {
		return zero, err
	}
	return site, nil
}

// claimNode loads the persisted node id, minting and storing one on
// first boot. A TLS transport overrides this with the certificate
// identity once sessions authenticate.
func claimNode(db *sqlite.Conn) (NodeID, error) {
	var id NodeID
	st, err := db.Prepare("SELECT node FROM murmur_identity WHERE id=1")
	if err != nil {
		return id, err
	}
	defer st.Close()
	stepDone, err := st.Step()
	if err != nil {
		return id, err
	}
	if !stepDone && st.ColumnType(0) != sqlite.TypeNull {
		raw := st.ColumnBlob(0)
		if len(raw) != 16 {
			return id, errInvalid("stored node id")
		}
		copy(id[:], raw)
		return id, nil
	}
	st.Close()
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	if id == (NodeID{}) {
		id[0] = 1
	}
	if err := execArgs(db, "UPDATE murmur_identity SET node=?1 WHERE id=1", id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// bumpIncarnation increments the boot counter and returns it.
func bumpIncarnation(db *sqlite.Conn) (uint64, error) {
	st, err := db.Prepare("UPDATE murmur_identity SET incarnation=incarnation+1 WHERE id=1 RETURNING incarnation")
	if err != nil {
		return 0, err
	}
	defer st.Close()
	stepDone, err := st.Step()
	if err != nil {
		return 0, err
	}
	if stepDone {
		return 0, errInvalid("identity row missing")
	}
	v := st.ColumnInt64(0)
	if v < 0 {
		return 0, errInvalid("identity incarnation")
	}
	return uint64(v), nil
}

// acceptRemoteSchema reads the adoption flag ("1" enables).
func acceptRemoteSchema(db *sqlite.Conn) (bool, error) {
	raw, err := Setting(db, "accept_remote_schema")
	if err != nil {
		return false, err
	}
	switch raw {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, errInvalid("invalid accept_remote_schema")
	}
}

// Handshake runs the Hello exchange over one stream and returns the
// peer's (incarnation, address). The dialer writes first; the
// acceptor reads first. peer is the transport-authenticated node id.
func (e *Engine) Handshake(w io.Writer, r io.Reader, outgoing bool, peer NodeID) (uint64, netip.AddrPort, error) {
	var zeroAddr netip.AddrPort
	schema, err := Schema(e.db)
	if err != nil {
		return 0, zeroAddr, err
	}
	e.mu.Lock()
	hello := MsgHello{
		Group: e.group, Node: e.node, Site: e.site, Schema: schema,
		Incarnation: e.incarnation, Addr: e.advertise,
	}
	selfSite := e.site
	e.mu.Unlock()
	if outgoing {
		if err := WriteFrame(w, hello); err != nil {
			return 0, zeroAddr, err
		}
	}
	remote, err := ReadFrame(r)
	if err != nil {
		return 0, zeroAddr, err
	}
	h, ok := remote.(MsgHello)
	if !ok {
		return 0, zeroAddr, errProtocol("expected session hello")
	}
	if h.Group != hello.Group || h.Node != peer || h.Site == selfSite || h.Site.IsZero() {
		return 0, zeroAddr, errAuth("session group or identity mismatch")
	}
	// Handshake schemas are a fast-fail hint only when adoption is
	// off; adopters proceed and converge through manifests.
	if h.Schema != schema {
		accept, err := acceptRemoteSchema(e.db)
		if err != nil {
			return 0, zeroAddr, err
		}
		if !accept {
			return 0, zeroAddr, errProtocol("CRR schema mismatch; provision matching table definitions")
		}
	}
	if !outgoing {
		if err := WriteFrame(w, hello); err != nil {
			return 0, zeroAddr, err
		}
	}
	return h.Incarnation, h.Addr, nil
}

// PullOnce pulls one batch from peer over a fresh stream and applies
// it. It reports whether the donor has more (partial cursor). Schema
// adoption retry arrives with the schema step; until then a mismatch
// surfaces as a Protocol error.
func (e *Engine) PullOnce(peer NodeID, w io.Writer, r io.Reader) (bool, error) {
	p, err := loadServeParams(e.db)
	if err != nil {
		return false, err
	}
	expected, cursor, err := Progress(e.db, peer)
	if err != nil {
		return false, err
	}
	schema, err := Schema(e.db)
	if err != nil {
		return false, err
	}
	e.mu.Lock()
	group, node, site := e.group, e.node, e.site
	receiving := e.receiving
	e.mu.Unlock()
	req := MsgPull{
		Group: group, Node: node, Site: site, Schema: schema,
		ExpectedSite: expected, Cursor: cursor,
	}
	if err := WriteFrame(w, req); err != nil {
		return false, err
	}
	reply, err := ReadFrame(r)
	if err != nil {
		return false, err
	}
	switch m := reply.(type) {
	case MsgIdle:
		return false, nil
	case MsgReset:
		if m.Site == site {
			return false, errAuth("remote cloned local site identity")
		}
		if err := Reset(e.db, peer, m.Site); err != nil {
			return false, err
		}
		return true, nil
	case MsgBatch:
		if expected == nil || *expected != m.Site ||
			m.Site == site ||
			m.Bytes < emptyCRSBLen || m.Bytes > uint64(p.maxBatchBytes) {
			return false, errProtocol("batch identity or length")
		}
		next := m.Cursor
		if next.From < cursor.From ||
			(next.Through != nil && *next.Through < next.From) ||
			(next.After != nil && (next.Through == nil || next.After.Version > *next.Through)) {
			return false, errProtocol("batch cursor")
		}
		receiving.acquire(int(m.Bytes))
		defer receiving.release(int(m.Bytes))
		if err := StageBegin(e.db, peer, p.stagingTimeoutMs); err != nil {
			return false, err
		}
		var received uint64
		var index uint32
		for {
			f, err := ReadFrame(r)
			if err != nil {
				return false, err
			}
			chunk, ok := f.(MsgChunk)
			if !ok {
				if _, isEnd := f.(MsgEnd); isEnd {
					break
				}
				return false, errProtocol("expected sequential batch chunks")
			}
			if chunk.Index != index || len(chunk.Data) == 0 || len(chunk.Data) > ChunkBytes {
				return false, errProtocol("expected sequential batch chunks")
			}
			if received+uint64(len(chunk.Data)) > m.Bytes {
				return false, errProtocol("excess chunk bytes")
			}
			received += uint64(len(chunk.Data))
			if err := Stage(e.db, peer, index, chunk.Data, p.stagingBytes); err != nil {
				return false, err
			}
			index++
		}
		if received != m.Bytes {
			return false, errProtocol("incomplete batch")
		}
		more := next.Through != nil
		changed := !cursorsEqual(next, cursor)
		if err := Apply(e.db, peer, m.Site, cursor, next, m.Bytes, m.Digest); err != nil {
			return false, err
		}
		e.touchPeer(peer, nil)
		if err := WriteFrame(w, MsgAck{Digest: m.Digest}); err != nil {
			return false, err
		}
		if changed {
			e.mu.Lock()
			e.applied++
			e.mu.Unlock()
		}
		return more, nil
	case MsgError:
		return false, errProtocol(m.Text)
	default:
		return false, errProtocol("expected batch header")
	}
}

// ServePull serves one pull request from the transport-authenticated
// peer. req is the already-read Pull message.
func (e *Engine) ServePull(peer NodeID, w io.Writer, r io.Reader, req MsgPull) error {
	p, err := loadServeParams(e.db)
	if err != nil {
		return err
	}
	e.mu.Lock()
	group, node, site := e.group, e.node, e.site
	serving := e.serving
	e.mu.Unlock()
	select {
	case e.serveSem <- struct{}{}:
		defer func() { <-e.serveSem }()
	default:
		if e.serveSem != nil {
			return errOverloaded("session capacity")
		}
	}
	if req.Group != group || req.Node != peer || req.Site == site {
		return errAuth("replication group or identity mismatch")
	}
	localSchema, err := Schema(e.db)
	if err != nil {
		return err
	}
	if localSchema != req.Schema && !e.compatVetted(peer, req.Schema) {
		return errProtocol("CRR schema mismatch; provision matching table definitions")
	}
	if req.ExpectedSite == nil || *req.ExpectedSite != site {
		return WriteFrame(w, MsgReset{Site: site})
	}
	serving.acquire(p.maxBatchBytes)
	defer serving.release(p.maxBatchBytes)
	previous := req.Cursor
	// GC watermark: cursors older than pruned history fail loud so the
	// peer snapshots instead of converging through a silent gap.
	watermark, err := GCWatermark(e.db)
	if err != nil {
		return err
	}
	from := previous.From
	if from < 0 {
		from = 0
	}
	if uint64(from) < watermark {
		return errProtocol("cursor pruned; snapshot required")
	}
	batch, err := Export(e.db, previous, p.batchBytes, p.maxBatchBytes)
	if err != nil {
		return err
	}
	if cursorsEqual(batch.Next, previous) && len(batch.Blob) == emptyCRSBLen {
		return WriteFrame(w, MsgIdle{})
	}
	digest := sha256.Sum256(batch.Blob)
	if err := WriteFrame(w, MsgBatch{Site: site, Cursor: batch.Next, Bytes: uint64(len(batch.Blob)), Digest: digest}); err != nil {
		return err
	}
	for i := 0; i < len(batch.Blob); i += ChunkBytes {
		end := i + ChunkBytes
		if end > len(batch.Blob) {
			end = len(batch.Blob)
		}
		if err := WriteFrame(w, MsgChunk{Index: uint32(i / ChunkBytes), Data: batch.Blob[i:end]}); err != nil {
			return err
		}
	}
	if err := WriteFrame(w, MsgEnd{}); err != nil {
		return err
	}
	reply, err := ReadFrame(r)
	if err != nil {
		return err
	}
	ack, ok := reply.(MsgAck)
	if !ok || ack.Digest != digest {
		return errProtocol("batch acknowledgement mismatch")
	}
	// The puller applied our data through its request cursor: record
	// it as observed self-progress for waits/retention. Idle pulls
	// skip this (a worker round trip per poll).
	acked := uint64(0)
	if previous.From > 0 {
		acked = uint64(previous.From)
	}
	if err := execArgs(e.db, "UPDATE murmur_progress SET sent=?1 WHERE node=?2", EncodeCursor(batch.Next), peer[:]); err != nil {
		return err
	}
	if err := ObservedMax(e.db, node, acked); err != nil {
		return err
	}
	ackedThrough := uint64(0)
	through := batch.Next.From
	if batch.Next.Through != nil {
		through = *batch.Next.Through
	}
	if through > 0 {
		ackedThrough = uint64(through)
	}
	e.touchPeer(peer, []tx.Progress{{Origin: node, Applied: ackedThrough, Observed: ackedThrough}})
	e.mu.Lock()
	e.sent++
	e.mu.Unlock()
	return nil
}

// ServeStream dispatches one inbound stream by its first message,
// replying Error on failure like the session loop.
func (e *Engine) ServeStream(peer NodeID, w io.Writer, r io.Reader) error {
	first, err := ReadFrame(r)
	if err != nil {
		e.record(err.Error())
		_ = WriteFrame(w, MsgError{Text: err.Error()})
		return err
	}
	var result error
	switch m := first.(type) {
	case MsgPull:
		result = e.ServePull(peer, w, r, m)
		e.mu.Lock()
		switch {
		case result == nil:
			e.serveOK++
		case isMismatch(result):
			e.serveReject++
		default:
			e.serveError++
		}
		e.mu.Unlock()
	case MsgSnapshotRequest:
		result = e.ServeSnapshot(peer, w, r, m)
	case MsgSchemaRequest:
		result = e.ServeSchemaRequest(w)
	case MsgSchemaManifest:
		result = e.ReceiveSchemaPush(peer, w, m.Manifest)
	default:
		result = errProtocol("expected pull, snapshot, or schema request")
	}
	if result != nil {
		e.record(result.Error())
		_ = WriteFrame(w, MsgError{Text: result.Error()})
	}
	return result
}

func isMismatch(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "mismatch")
}

// touchPeer records peer contact and max-merges acknowledged
// progress for retention floors. Best-effort like the serve path.
func (e *Engine) touchPeer(peer NodeID, progress []tx.Progress) {
	e.mu.Lock()
	group, node := e.group, e.node
	e.mu.Unlock()
	backend := NewBackend(e.db, group, node)
	_ = tx.Touch(backend, peer, progress)
}

// record stores the last engine error for status reporting.
func (e *Engine) record(msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastErrorText = msg
}

// recordedError is a SQL-verb failure kept for status surfaces.
type recordedError struct {
	code    int32
	kind    string
	message string
}

// fail records a verb failure and returns it for the SQL result.
func (e *Engine) fail(err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastErr = &recordedError{code: murmurCode(err), kind: murmurKind(err), message: err.Error()}
	return err
}
