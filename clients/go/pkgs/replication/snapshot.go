// Snapshot join over CRR state.
//
// Go port of snapshot.rs: the downstream adapter over the tx snapshot
// chunk/pin/receipt state machine. Policy (budgets, trust) comes from
// the embedded settings, not the archived transport Config:
//
//   - Sizes, lifetime, transfer counts: murmur_snapshot_* settings.
//   - Trust: mutual TLS already authenticates both endpoints, so
//     manifest signatures are replaced by transport authentication —
//     the donor must be the authenticated source AND listed in
//     snapshot_trusted_sources — plus the identity/expiry/budget
//     checks verbatim. The signature field stays empty.
//   - Payload: prefix-consistent CRSB segments (a full export from
//     version 0), not a point-in-time image; concurrent writes arrive
//     via follow-up pulls. Install applies them through Backend
//     apply, which is idempotent.
package replication

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/bindings/sqlite"
	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/tx"
)

// SnapshotParams are the snapshot budgets and trust set.
type SnapshotParams struct {
	SnapshotBytes        int
	SnapshotStagingBytes int
	TransferLifetimeMs   uint64
	StagingTransfers     int
	MaxTransactionBytes  int
	BatchBytes           int
	TrustedSources       map[NodeID]bool
}

// snapshotDeadline bounds a transfer lifetime.
func snapshotDeadline(params *SnapshotParams, now uint64) uint64 {
	if ^uint64(0)-now < params.TransferLifetimeMs {
		return ^uint64(0)
	}
	return now + params.TransferLifetimeMs
}

// SnapshotParamsFrom loads snapshot params from settings. Batch knobs
// come from the shared batch settings; trust defaults to empty (deny)
// until the operator lists donors.
func SnapshotParamsFrom(db *sqlite.Conn) (*SnapshotParams, error) {
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
	raw, err := Setting(db, "snapshot_trusted_sources")
	if err != nil {
		return nil, err
	}
	var trusted []string
	if err := json.Unmarshal([]byte(raw), &trusted); err != nil {
		return nil, errInvalidf("snapshot_trusted_sources: %v", err)
	}
	sources := map[NodeID]bool{}
	for _, id := range trusted {
		parsed, err := ParseID(id)
		if err != nil {
			return nil, err
		}
		sources[parsed] = true
	}
	intOf := func(name string) (int, error) {
		v, err := num(name)
		if err != nil {
			return 0, err
		}
		if v > uint64(math_MaxInt64) {
			return 0, errInvalidf("invalid %s", name)
		}
		return int(v), nil
	}
	p := &SnapshotParams{TrustedSources: sources}
	if p.SnapshotBytes, err = intOf("snapshot_bytes"); err != nil {
		return nil, err
	}
	if p.SnapshotStagingBytes, err = intOf("snapshot_staging_bytes"); err != nil {
		return nil, err
	}
	if p.TransferLifetimeMs, err = num("snapshot_lifetime_ms"); err != nil {
		return nil, err
	}
	if p.StagingTransfers, err = intOf("snapshot_staging_transfers"); err != nil {
		return nil, err
	}
	if p.MaxTransactionBytes, err = intOf("max_batch_bytes"); err != nil {
		return nil, err
	}
	if p.BatchBytes, err = intOf("batch_bytes"); err != nil {
		return nil, err
	}
	return p, nil
}

// snapshotTxErr maps tx errors onto engine errors.
func snapshotTxErr(err error) error {
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
		case "Storage":
			return &sqlite.Error{Code: -1, Msg: e.Msg}
		case "Overloaded":
			return errOverloaded(e.Msg)
		case "Unavailable":
			return errClosed(e.Msg)
		default:
			return errProtocol(e.Msg)
		}
	}
	return err
}

// VerifySnapshotTransport is Manifest::verify minus the Ed25519 check:
// mutual TLS binds the donor identity instead.
func VerifySnapshotTransport(m *tx.Manifest, backend tx.Backend, params *SnapshotParams, source NodeID, now uint64) error {
	database, recipient := backend.Identity()
	if m.Database != database || m.Donor != source || m.Recipient != recipient ||
		!params.TrustedSources[source] || m.Expires <= now {
		return errAuth("snapshot identity, trust or expiry")
	}
	if m.Bytes > uint64(params.SnapshotBytes) || m.Bytes > uint64(params.SnapshotStagingBytes) ||
		len(m.Progress) > 4096 || len(m.Chunks) != ceilDiv(int(m.Bytes), tx.ChunkBytes) {
		return errOverloaded("snapshot size")
	}
	origins := map[NodeID]bool{}
	for _, p := range m.Progress {
		if origins[p.Origin] || p.Observed < p.Applied ||
			(p.RetainedFrom > p.RetainedThrough && p.RetainedThrough != 0) {
			return errProtocol("snapshot progress")
		}
		origins[p.Origin] = true
	}
	return nil
}

func ceilDiv(n, d int) int { return (n + d - 1) / d }

// BuildSnapshotStreaming builds a record-stream snapshot without
// materializing its payload. pages are CRSB export segments; emit
// persists bounded groups; only the final group publishes the signed
// manifest and retention pin.
func BuildSnapshotStreaming(identity [2]NodeID, recipient NodeID, pages [][]byte, progress []tx.Progress, schema [32]byte, params *SnapshotParams, now uint64, emit func([]tx.Record) error) (tx.Manifest, error) {
	var zero tx.Manifest
	if len(progress) > 4096 {
		return zero, errOverloaded("snapshot progress too large")
	}
	var transfer NodeID
	if _, err := rand.Read(transfer[:]); err != nil {
		return zero, err
	}
	// Phase 1: preliminary pin+header, chunkless by construction.
	prelim := tx.Manifest{
		Database: identity[0], Donor: identity[1], Recipient: recipient,
		Transfer: transfer, Expires: saturatingAdd(now, tx.BUILD_GRACE_MILLIS),
		Schema: schema, Progress: progress,
	}
	boundary := map[NodeID]uint64{}
	for _, p := range progress {
		boundary[p.Origin] = p.Applied
	}
	if err := emit([]tx.Record{
		tx.Put(tx.PinKey(transfer), tx.EncodePin(tx.Pin{Recipient: recipient, Boundary: boundary, Expires: prelim.Expires})),
		tx.Put(tx.HeaderKey(tx.OUT, transfer), tx.EncodeManifest(prelim)),
	}); err != nil {
		return zero, err
	}
	var hashes [][32]byte
	digest := sha256.New()
	buffer := make([]byte, 0, tx.ChunkBytes)
	var records []tx.Record
	total := 0
	flush := func() error {
		if len(records) == 0 {
			return nil
		}
		out := records
		records = nil
		return emit(out)
	}
	push := func(b []byte) error {
		if ^uint(0)-uint(total) < uint(len(b)) {
			return errOverloaded("snapshot too large")
		}
		total += len(b)
		if total > params.SnapshotBytes || total > params.SnapshotStagingBytes {
			return errOverloaded("snapshot too large")
		}
		digest.Write(b)
		rest := b
		for len(rest) > 0 {
			n := tx.ChunkBytes - len(buffer)
			if n > len(rest) {
				n = len(rest)
			}
			buffer = append(buffer, rest[:n]...)
			rest = rest[n:]
			if len(buffer) == tx.ChunkBytes {
				hashes = append(hashes, sha256.Sum256(buffer))
				cp := append([]byte(nil), buffer...)
				records = append(records, tx.Put(tx.ChunkKey(tx.OUT, transfer, uint32(len(hashes)-1)), cp))
				buffer = buffer[:0]
				if len(records) == 16 {
					if err := flush(); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := push(tx.STREAM_MAGIC); err != nil {
		return zero, err
	}
	for _, page := range pages {
		if len(page) == 0 || len(page) > params.MaxTransactionBytes {
			return zero, errOverloaded("snapshot page size")
		}
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(page)))
		if err := push(ln[:]); err != nil {
			return zero, err
		}
		if err := push(page); err != nil {
			return zero, err
		}
	}
	if len(buffer) > 0 {
		hashes = append(hashes, sha256.Sum256(buffer))
		records = append(records, tx.Put(tx.ChunkKey(tx.OUT, transfer, uint32(len(hashes)-1)), append([]byte(nil), buffer...)))
	}
	manifest := tx.Manifest{
		Database: identity[0], Donor: identity[1], Recipient: recipient,
		Transfer: transfer, Expires: snapshotDeadline(params, now),
		Bytes: uint64(total), Schema: schema, Progress: progress, Chunks: hashes,
	}
	copy(manifest.Digest[:], digest.Sum(nil))
	pin := tx.Pin{Recipient: recipient, Boundary: boundary, Expires: manifest.Expires, Digest: manifest.Digest}
	records = append(records, tx.Put(tx.PinKey(transfer), tx.EncodePin(pin)))
	records = append(records, tx.Put(tx.HeaderKey(tx.OUT, transfer), tx.EncodeManifest(manifest)))
	if err := flush(); err != nil {
		return zero, err
	}
	if err := emit(records); err != nil {
		return zero, err
	}
	return manifest, nil
}

func saturatingAdd(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

// AcceptSnapshot stages a verified manifest for install.
func AcceptSnapshot(backend tx.Backend, params *SnapshotParams, source NodeID, m tx.Manifest, now uint64) error {
	if err := VerifySnapshotTransport(&m, backend, params, source, now); err != nil {
		return err
	}
	if len(m.Chunks) == 0 {
		return errClosed("snapshot build in progress")
	}
	if raw, ok, err := backend.Get(tx.ReceiptKey(m.Transfer)); err != nil {
		return snapshotTxErr(err)
	} else if ok {
		done, err := tx.DecodeIncoming(raw)
		if err != nil {
			return snapshotTxErr(err)
		}
		if !bytes.Equal(tx.EncodeManifest(done.Manifest), tx.EncodeManifest(m)) {
			return errAuth("conflicting snapshot receipt")
		}
		return nil
	}
	if old, err := tx.LoadIncoming(backend); err != nil {
		return snapshotTxErr(err)
	} else if old != nil {
		if !bytes.Equal(tx.EncodeManifest(old.Manifest), tx.EncodeManifest(m)) {
			return errClosed("another snapshot is staged")
		}
		return nil
	}
	keys, err := backend.Keys(tx.RECEIPTS)
	if err != nil {
		return snapshotTxErr(err)
	}
	if len(keys) >= params.StagingTransfers {
		return errOverloaded("snapshot staging transfers")
	}
	used := m.Bytes
	keys, err = backend.Keys(tx.IN)
	if err != nil {
		return snapshotTxErr(err)
	}
	for _, k := range keys {
		if strings.HasSuffix(string(k), "/header") {
			continue
		}
		raw, ok, err := backend.Get(k)
		if err != nil {
			return snapshotTxErr(err)
		}
		if !ok {
			continue
		}
		used += uint64(len(raw))
		if used < uint64(len(raw)) || used > uint64(params.SnapshotStagingBytes) {
			return errOverloaded("snapshot staging bytes")
		}
	}
	deadline := m.Expires
	if d := snapshotDeadline(params, now); d < deadline {
		deadline = d
	}
	staged := tx.Incoming{Manifest: m, Deadline: deadline}
	return snapshotTxErr(backend.Commit([]tx.Record{tx.Put(tx.HeaderKey(tx.IN, m.Transfer), tx.EncodeIncoming(staged))}))
}

// FinishSnapshot installs staged chunks; true once the receipt is
// durable (big streams take several calls).
func FinishSnapshot(backend tx.Backend, params *SnapshotParams, source, transfer NodeID, now uint64) (bool, error) {
	if raw, ok, err := backend.Get(tx.ReceiptKey(transfer)); err != nil {
		return false, snapshotTxErr(err)
	} else if ok {
		r, err := tx.DecodeIncoming(raw)
		if err != nil {
			return false, snapshotTxErr(err)
		}
		if r.Manifest.Donor != source {
			return false, errAuth("snapshot receipt donor")
		}
		return true, nil
	}
	raw, ok, err := backend.Get(tx.HeaderKey(tx.IN, transfer))
	if err != nil {
		return false, snapshotTxErr(err)
	}
	if !ok {
		return false, nil
	}
	r, err := tx.DecodeIncoming(raw)
	if err != nil {
		return false, snapshotTxErr(err)
	}
	if err := VerifySnapshotTransport(&r.Manifest, backend, params, source, now); err != nil {
		return false, err
	}
	if r.Deadline <= now {
		return false, nil
	}
	schema, err := backend.Schema()
	if err != nil {
		return false, snapshotTxErr(err)
	}
	if r.Manifest.Schema != tx.SchemaDigest(schema) {
		return false, errClosed("snapshot schema mismatch")
	}
	missing, err := tx.Missing(backend, &r)
	if err != nil {
		return false, snapshotTxErr(err)
	}
	if len(missing) > 0 {
		return false, nil
	}
	installRaw, hasInstall, err := backend.Get(tx.InstallKey(transfer))
	if err != nil {
		return false, snapshotTxErr(err)
	}
	var install uint64
	if hasInstall {
		install, err = tx.DecodeU64(installRaw)
		if err != nil {
			return false, snapshotTxErr(err)
		}
	}
	streamed := false
	if r.Manifest.Bytes >= uint64(len(tx.STREAM_MAGIC)) {
		head, err := tx.StreamRead(backend, &r.Manifest, 0, len(tx.STREAM_MAGIC))
		if err != nil {
			return false, snapshotTxErr(err)
		}
		streamed = bytes.Equal(head, tx.STREAM_MAGIC)
	}
	var data []byte
	if !hasInstall {
		digest := sha256.New()
		var total uint64
		for i := 0; i < len(r.Manifest.Chunks); i++ {
			chunk, ok, err := backend.Get(tx.ChunkKey(tx.IN, transfer, uint32(i)))
			if err != nil {
				return false, snapshotTxErr(err)
			}
			if !ok {
				return false, nil
			}
			if err := tx.ValidateChunk(&r.Manifest, source, uint32(i), chunk); err != nil {
				return false, snapshotTxErr(err)
			}
			digest.Write(chunk)
			total += uint64(len(chunk))
			if !streamed {
				data = append(data, chunk...)
			}
		}
		var sum [32]byte
		copy(sum[:], digest.Sum(nil))
		if total != r.Manifest.Bytes || sum != r.Manifest.Digest {
			return false, errAuth("snapshot payload digest")
		}
	}
	if streamed {
		cursor := install
		if !hasInstall {
			cursor = uint64(len(tx.STREAM_MAGIC))
		}
		if cursor < uint64(len(tx.STREAM_MAGIC)) || cursor > r.Manifest.Bytes {
			return false, errProtocol("snapshot installation cursor")
		}
		if cursor < r.Manifest.Bytes {
			var payloads [][]byte
			used := 0
			for cursor < r.Manifest.Bytes && len(payloads) < 16 {
				lnRaw, err := tx.StreamRead(backend, &r.Manifest, cursor, 4)
				if err != nil {
					return false, snapshotTxErr(err)
				}
				length := int(binary.BigEndian.Uint32(lnRaw))
				if length == 0 || length > params.MaxTransactionBytes {
					return false, errOverloaded("snapshot page size")
				}
				if len(payloads) > 0 && used+length > params.BatchBytes {
					break
				}
				used += length
				page, err := tx.StreamRead(backend, &r.Manifest, cursor+4, length)
				if err != nil {
					return false, snapshotTxErr(err)
				}
				payloads = append(payloads, page)
				cursor += uint64(4 + length)
			}
			applied, err := backend.Apply(payloads, []tx.Record{tx.Put(tx.InstallKey(transfer), tx.EncodeU64(cursor))})
			if err != nil {
				return false, snapshotTxErr(err)
			}
			if !applied || cursor < r.Manifest.Bytes {
				return false, nil
			}
		}
	}
	receipt := r
	receipt.Deadline = snapshotDeadline(params, now)
	records := []tx.Record{
		tx.Put(tx.ReceiptKey(transfer), tx.EncodeIncoming(receipt)),
		tx.Delete(tx.HeaderKey(tx.IN, transfer)),
		tx.Delete(tx.InstallKey(transfer)),
	}
	for _, p := range r.Manifest.Progress {
		old := uint64(0)
		if raw, ok, err := backend.Get(tx.ProgressKey(p.Origin)); err != nil {
			return false, snapshotTxErr(err)
		} else if ok {
			old, err = tx.DecodeU64(raw)
			if err != nil {
				return false, snapshotTxErr(err)
			}
		}
		if p.Applied > old {
			old = p.Applied
		}
		records = append(records, tx.Put(tx.ProgressKey(p.Origin), tx.EncodeU64(old)))
	}
	var payloads [][]byte
	if !streamed {
		payloads = [][]byte{data}
	}
	done, err := backend.Apply(payloads, records)
	if err != nil {
		return false, snapshotTxErr(err)
	}
	return done, nil
}

// BuildSnapshotFor builds a snapshot for recipient over a
// prefix-consistent full export (pages from version 0). Chunks land
// in the donor's local kv only; the manifest must fit one frame.
func BuildSnapshotFor(db *sqlite.Conn, backend tx.Backend, params *SnapshotParams, batchBytes, maxBatchBytes int, recipient NodeID, now uint64) (tx.Manifest, error) {
	var zero tx.Manifest
	schemaRaw, err := backend.Schema()
	if err != nil {
		return zero, snapshotTxErr(err)
	}
	schema := tx.SchemaDigest(schemaRaw)
	heads, err := txProgress(db)
	if err != nil {
		return zero, err
	}
	var pages [][]byte
	cursor := Cursor{}
	for {
		batch, err := Export(db, cursor, batchBytes, maxBatchBytes)
		if err != nil {
			return zero, err
		}
		pages = append(pages, batch.Blob)
		if batch.Next.Through == nil {
			break
		}
		cursor = batch.Next
	}
	database, donor := backend.Identity()
	manifest, err := BuildSnapshotStreaming([2]NodeID{database, donor}, recipient, pages, heads, schema, params, now, func(records []tx.Record) error {
		return snapshotTxErr(backend.Commit(records))
	})
	if err != nil {
		return zero, err
	}
	if len(tx.EncodeManifest(manifest)) > FrameBytes {
		return zero, errOverloaded("snapshot manifest too large")
	}
	return manifest, nil
}

// ServeSnapshot builds a snapshot for the requesting peer and streams
// OUT-kv chunks. No serving byte budget: a snapshot can exceed the
// byte semaphore's capacity, so snapshot_bytes + the sessions cap
// bound it instead.
func (e *Engine) ServeSnapshot(peer NodeID, w io.Writer, r io.Reader, req MsgSnapshotRequest) error {
	_ = r
	p, err := loadServeParams(e.db)
	if err != nil {
		return err
	}
	e.mu.Lock()
	group, node, site := e.group, e.node, e.site
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
	params, err := SnapshotParamsFrom(e.db)
	if err != nil {
		return err
	}
	backend := NewBackend(e.db, group, node)
	manifest, err := BuildSnapshotFor(e.db, backend, params, p.batchBytes, p.maxBatchBytes, peer, tx.NowMillis())
	if err != nil {
		return err
	}
	if err := WriteFrame(w, MsgSnapshotManifest{Manifest: tx.EncodeManifest(manifest)}); err != nil {
		return err
	}
	for index := range manifest.Chunks {
		raw, ok, err := backend.Get(tx.ChunkKey(tx.OUT, manifest.Transfer, uint32(index)))
		if err != nil {
			return snapshotTxErr(err)
		}
		if !ok {
			return errProtocol("snapshot chunk expired")
		}
		if err := WriteFrame(w, MsgChunk{Index: uint32(index), Data: raw}); err != nil {
			return err
		}
	}
	if err := WriteFrame(w, MsgEnd{}); err != nil {
		return err
	}
	e.mu.Lock()
	e.sent++
	e.mu.Unlock()
	return nil
}

// FetchSnapshot requests, stages, and installs one snapshot from a
// connected peer, then resumes normal pulls (the manifest boundary
// advances progress heads past the snapshot).
func (e *Engine) FetchSnapshot(peer NodeID, open func() (io.Writer, io.Reader, error)) (NodeID, error) {
	var zero NodeID
	e.mu.Lock()
	sess, ok := e.conns[peer]
	group, node, site := e.group, e.node, e.site
	e.mu.Unlock()
	if !ok || sess == nil {
		return zero, errClosed("snapshot peer is not connected")
	}
	schema, err := Schema(e.db)
	if err != nil {
		return zero, err
	}
	w, r, err := open()
	if err != nil {
		return zero, err
	}
	req := MsgSnapshotRequest{Group: group, Node: node, Site: site, Schema: schema}
	if err := WriteFrame(w, req); err != nil {
		return zero, err
	}
	first, err := ReadFrame(r)
	if err != nil {
		return zero, err
	}
	raw, ok := first.(MsgSnapshotManifest)
	if !ok {
		if em, isErr := first.(MsgError); isErr {
			return zero, errProtocol(em.Text)
		}
		return zero, errProtocol("expected snapshot manifest")
	}
	manifest, err := tx.DecodeManifest(raw.Manifest)
	if err != nil {
		return zero, snapshotTxErr(err)
	}
	transfer := manifest.Transfer
	params, err := SnapshotParamsFrom(e.db)
	if err != nil {
		return zero, err
	}
	backend := NewBackend(e.db, group, node)
	if err := AcceptSnapshot(backend, params, peer, manifest, tx.NowMillis()); err != nil {
		return zero, err
	}
	var index uint32
	for {
		f, err := ReadFrame(r)
		if err != nil {
			return zero, err
		}
		chunk, ok := f.(MsgChunk)
		if !ok {
			if _, isEnd := f.(MsgEnd); isEnd {
				break
			}
			if em, isErr := f.(MsgError); isErr {
				return zero, errProtocol(em.Text)
			}
			return zero, errProtocol("expected sequential snapshot chunks")
		}
		if chunk.Index != index || len(chunk.Data) == 0 || len(chunk.Data) > ChunkBytes {
			return zero, errProtocol("expected sequential snapshot chunks")
		}
		if err := snapshotTxErr(backend.Commit([]tx.Record{tx.Put(tx.ChunkKey(tx.IN, transfer, index), chunk.Data)})); err != nil {
			return zero, err
		}
		index++
	}
	for range 600 {
		now := tx.NowMillis()
		_, ok, err := backend.Get(tx.HeaderKey(tx.IN, transfer))
		if err != nil {
			return zero, snapshotTxErr(err)
		}
		if !ok {
			return transfer, nil
		}
		hdr, _, err := backend.Get(tx.HeaderKey(tx.IN, transfer))
		if err != nil {
			return zero, snapshotTxErr(err)
		}
		incoming, err := tx.DecodeIncoming(hdr)
		if err != nil {
			return zero, snapshotTxErr(err)
		}
		missing, err := tx.Missing(backend, &incoming)
		if err != nil {
			return zero, snapshotTxErr(err)
		}
		if len(missing) > 0 {
			return zero, errProtocol("snapshot donor short-sent chunks")
		}
		done, err := FinishSnapshot(backend, params, peer, transfer, now)
		if err != nil {
			return zero, err
		}
		if done {
			e.touchPeer(peer, manifest.Progress)
			e.mu.Lock()
			e.applied++
			e.mu.Unlock()
			return transfer, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return zero, errClosed("snapshot install did not complete")
}

// RequestSnapshot queues a snapshot pull; progress lands in the
// snapshot status surfaced by Status.
func (e *Engine) RequestSnapshot(peer NodeID, open func() (io.Writer, io.Reader, error)) error {
	e.mu.Lock()
	if e.snapshotStatus == "running" {
		e.mu.Unlock()
		return errClosed("snapshot already running")
	}
	e.snapshotStatus = "running"
	e.mu.Unlock()
	go func() {
		transfer, err := e.FetchSnapshot(peer, open)
		e.mu.Lock()
		defer e.mu.Unlock()
		if err != nil {
			e.lastErr = &recordedError{code: murmurCode(err), kind: murmurKind(err), message: err.Error()}
			e.snapshotStatus = "error: " + err.Error()
			return
		}
		e.snapshotStatus = "ok " + transfer.String()
	}()
	return nil
}
