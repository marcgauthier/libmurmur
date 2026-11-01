// Schema serving: vetting, manifests, adoption, and master push.
//
// Go port of the Engine schema path (vet_fetch, serve_schema_request,
// ingest_manifest, receive_schema_push, adopt_from_peer, push_schema,
// compat_or_spawn) plus the pull-with-adopt-retry wrapper.
package replication

import (
	"io"
	"strings"

	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// vettedKey caches a vet verdict per (peer, claimed digest).
type vettedKey struct {
	peer   NodeID
	digest [32]byte
}

// schemaSentKey tracks the last manifest pushed per peer.
type schemaSentKey struct {
	digest   [32]byte
	sequence uint64
}

func isSchemaMismatch(err error) bool {
	if err == nil {
		return false
	}
	e, ok := err.(*Error)
	if !ok || e.Kind != "Protocol" {
		return false
	}
	return strings.Contains(e.Msg, "schema mismatch")
}

// compatVetted serves a cached vet verdict for a peer schema, else
// spawns one background vet round trip and rejects this pull (the
// puller's retry converges once the verdict lands). The vet stays out
// of the serve path: a blocking reverse request deadlocks when both
// peers mismatch at once.
func (e *Engine) compatVetted(peer NodeID, schema [32]byte) bool {
	key := vettedKey{peer: peer, digest: schema}
	e.mu.Lock()
	v, ok := e.vetted[key]
	e.mu.Unlock()
	if ok {
		return v
	}
	go e.vetFetchAsync(peer, schema)
	return false
}

func (e *Engine) vetFetchAsync(peer NodeID, schema [32]byte) {
	e.mu.Lock()
	sess, ok := e.conns[peer]
	e.mu.Unlock()
	if !ok || sess == nil {
		e.mu.Lock()
		e.vetFail++
		e.mu.Unlock()
		return
	}
	verdict, ok := e.VetFetch(peer, func() (io.Writer, io.Reader, error) {
		s, err := sess.OpenStream()
		if err != nil {
			return nil, nil, err
		}
		return streamWriter(s), streamReader(s), nil
	})
	e.mu.Lock()
	defer e.mu.Unlock()
	if !ok {
		e.vetFail++
		return
	}
	if verdict {
		e.vetOK++
	} else {
		e.vetNo++
	}
	e.vetted[vettedKey{peer: peer, digest: schema}] = verdict
}

// VetFetch runs one vet round trip: fetch the peer's manifest and
// check one-sided pull compatibility. ok=false on transport failure
// (re-vet next pull); any received verdict is deterministic per
// digest and cacheable.
func (e *Engine) VetFetch(peer NodeID, open func() (io.Writer, io.Reader, error)) (verdict, ok bool) {
	w, r, err := open()
	if err != nil {
		return false, false
	}
	if err := WriteFrame(w, MsgSchemaRequest{}); err != nil {
		return false, false
	}
	first, err := ReadFrame(r)
	if err != nil {
		return false, false
	}
	m, ok := first.(MsgSchemaManifest)
	if !ok {
		return false, false
	}
	signed, err := tx.DecodeSignedSchema(m.Manifest)
	if err != nil {
		return false, true
	}
	e.mu.Lock()
	group := e.group
	e.mu.Unlock()
	if signed.Signer != peer || signed.Database != group {
		return false, true
	}
	local, err := ManifestSchemaBytes(e.db)
	if err != nil {
		return false, false
	}
	compat, err := PullerCompatible(local, signed.Schema)
	if err != nil {
		return false, true
	}
	return compat, true
}

// ServeSchemaRequest serves our manifest to any peer. The requester
// decides adoption; non-master manifests are harmless (gated adopters
// record them without applying).
func (e *Engine) ServeSchemaRequest(w io.Writer) error {
	e.mu.Lock()
	group, node, site := e.group, e.node, e.site
	e.mu.Unlock()
	backend := NewBackend(e.db, group, node)
	params, err := SchemaParamsFrom(e.db)
	if err != nil {
		return err
	}
	raw, err := ManifestSchemaBytes(e.db)
	if err != nil {
		return err
	}
	manifest, err := BuildSchemaManifest(backend, params, node, group, raw)
	if err != nil {
		return err
	}
	_ = site
	return WriteFrame(w, MsgSchemaManifest{Manifest: tx.EncodeSignedSchema(manifest)})
}

// IngestManifest vets one manifest from an authenticated peer,
// adopts additive changes, and records. Shared by push and pull paths.
func (e *Engine) IngestManifest(peer NodeID, raw []byte) (tx.SignedSchema, error) {
	var zero tx.SignedSchema
	signed, err := tx.DecodeSignedSchema(raw)
	if err != nil {
		return zero, snapshotTxErr(err)
	}
	params, err := SchemaParamsFrom(e.db)
	if err != nil {
		return zero, err
	}
	local, err := ManifestSchemaBytes(e.db)
	if err != nil {
		return zero, err
	}
	e.mu.Lock()
	group, node := e.group, e.node
	e.mu.Unlock()
	backend := NewBackend(e.db, group, node)
	decision, err := CheckSchemaManifest(backend, params, node, local, &signed, peer)
	if err != nil {
		return zero, err
	}
	if decision == SchemaAdopt {
		applied, err := backend.AcceptSchema(signed.Schema)
		if err != nil {
			return zero, err
		}
		if applied {
			if err := RecordSchemaAccepted(backend, &signed); err != nil {
				return zero, err
			}
			e.mu.Lock()
			e.schemaAdoptions++
			e.mu.Unlock()
		}
	}
	return signed, nil
}

// ReceiveSchemaPush handles an unsolicited master push: ingest, then
// ack everything vetted.
func (e *Engine) ReceiveSchemaPush(peer NodeID, w io.Writer, raw []byte) error {
	signed, err := e.IngestManifest(peer, raw)
	if err != nil {
		return err
	}
	return WriteFrame(w, MsgSchemaAck{Digest: signed.Digest(), Sequence: signed.Sequence})
}

// AdoptFromPeer fetches the peer's manifest, ingests it, and acks.
// Called when a pull fails on schema mismatch with adoption enabled.
func (e *Engine) AdoptFromPeer(peer NodeID, open func() (io.Writer, io.Reader, error)) error {
	w, r, err := open()
	if err != nil {
		return err
	}
	if err := WriteFrame(w, MsgSchemaRequest{}); err != nil {
		return err
	}
	first, err := ReadFrame(r)
	if err != nil {
		return err
	}
	m, ok := first.(MsgSchemaManifest)
	if !ok {
		if em, isErr := first.(MsgError); isErr {
			return errProtocol(em.Text)
		}
		return errProtocol("expected schema manifest")
	}
	signed, err := e.IngestManifest(peer, m.Manifest)
	if err != nil {
		return err
	}
	return WriteFrame(w, MsgSchemaAck{Digest: signed.Digest(), Sequence: signed.Sequence})
}

// PushSchema sends our manifest when the peer has not acked it yet.
// Master-only and best-effort; failures stay silent (the next pull
// re-discovers drift through its mismatch path).
func (e *Engine) PushSchema(peer NodeID, open func() (io.Writer, io.Reader, error)) {
	params, err := SchemaParamsFrom(e.db)
	if err != nil || !params.Master {
		return
	}
	e.mu.Lock()
	group, node := e.group, e.node
	e.mu.Unlock()
	backend := NewBackend(e.db, group, node)
	raw, err := ManifestSchemaBytes(e.db)
	if err != nil {
		return
	}
	manifest, err := BuildSchemaManifest(backend, params, node, group, raw)
	if err != nil {
		return
	}
	key := schemaSentKey{digest: manifest.Digest(), sequence: manifest.Sequence}
	e.mu.Lock()
	if e.schemaSent[peer] == key {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	encoded := tx.EncodeSignedSchema(manifest)
	w, r, err := open()
	if err != nil {
		return
	}
	if err := WriteFrame(w, MsgSchemaManifest{Manifest: encoded}); err != nil {
		return
	}
	first, err := ReadFrame(r)
	if err != nil {
		return
	}
	ack, ok := first.(MsgSchemaAck)
	if !ok || ack.Digest != key.digest || ack.Sequence != key.sequence {
		return
	}
	e.mu.Lock()
	e.schemaSent[peer] = key
	e.sent++
	e.mu.Unlock()
}

// streamWriter adapts a Stream to io.Writer.
func streamWriter(s Stream) io.Writer { return &streamIO{s: s} }

// streamReader adapts a Stream to io.Reader.
func streamReader(s Stream) io.Reader { return &streamIO{s: s} }

type streamIO struct {
	s Stream
}

func (a *streamIO) Write(b []byte) (int, error) {
	if err := a.s.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (a *streamIO) Read(b []byte) (int, error) { return a.s.Read(b) }
