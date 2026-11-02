package replication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// enforceTrust pins siteHex->pubHex pairs in trusted_origins.
func enforceTrust(t *testing.T, db *sqlite.Conn, pins map[string]string) {
	t.Helper()
	var b strings.Builder
	b.WriteByte('{')
	i := 0
	for k, v := range pins {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:%q", k, v)
		i++
	}
	b.WriteByte('}')
	if err := SetSetting(db, "trusted_origins", b.String()); err != nil {
		t.Fatal(err)
	}
}

func siteHex(t *testing.T, db *sqlite.Conn) string {
	t.Helper()
	site, err := SiteID(db)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(site[:])
}

func mustSigner(t *testing.T) *CellSigner {
	t.Helper()
	seed, err := GenerateCellSeed()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewCellSigner(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOriginSignVerify(t *testing.T) {
	s := mustSigner(t)
	other := mustSigner(t)
	c := Cell{Table: "t", PK: []byte{1}, CID: "b", Val: TextVal([]byte("x")), ColVersion: 1, SiteID: bytes.Repeat([]byte{7}, 16)}
	sig := s.SignCell(c)
	pub := s.PublicKey()
	if !VerifyCell(pub, c, sig[:]) {
		t.Fatal("valid signature rejected")
	}
	bad := Cell{Table: "t", PK: []byte{1}, CID: "b", Val: TextVal([]byte("y")), ColVersion: 1, SiteID: bytes.Repeat([]byte{7}, 16)}
	if VerifyCell(pub, bad, sig[:]) {
		t.Fatal("tampered value accepted")
	}
	opub := other.PublicKey()
	if VerifyCell(opub, c, sig[:]) {
		t.Fatal("wrong key accepted")
	}
	if VerifyCell(pub, c, sig[:63]) {
		t.Fatal("short sig accepted")
	}
}

// TestOriginKAT pins the canonical bytes and signature for a fixed
// seed/cell: any drift in CellCanonical breaks interop with the C
// murmur_cell_canonical, so it must fail loud here.
func TestOriginKAT(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	s, err := NewCellSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	site, _ := hex.DecodeString("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	c := Cell{Table: "t", PK: []byte{0x01, 0x09, 0x01}, CID: "v", Val: TextVal([]byte("hello")), ColVersion: 1, SiteID: site}
	sig := s.SignCell(c)
	const want = "8712725f405add2530e7cf0f44722008a825fa31ecc5f45197d3237ac5768613cc48c23c1b0818d7536c0acb232b0d422eb9503ee4a6dfe81e299732a90f890f"
	if got := hex.EncodeToString(sig[:]); got != want {
		t.Fatalf("KAT sig = %s, want %s", got, want)
	}
}

// applyBatch runs a full Stage/Apply receive of blob on db.
func applyBatch(t *testing.T, db *sqlite.Conn, node NodeID, site NodeID, blob []byte, next Cursor) error {
	t.Helper()
	if err := Reset(db, node, site); err != nil {
		t.Fatal(err)
	}
	_, previous, err := Progress(db, node)
	if err != nil {
		t.Fatal(err)
	}
	if err := StageBegin(db, node, 300000); err != nil {
		t.Fatal(err)
	}
	mid := len(blob) / 2
	chunks := [][]byte{blob[:mid], blob[mid:]}
	for i, c := range chunks {
		if err := Stage(db, node, uint32(i), c, 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(blob)
	return Apply(db, node, site, previous, next, uint64(len(blob)), digest)
}

func TestEnforcedExportApply(t *testing.T) {
	donor := openCRR(t)
	makeSyncTable(t, donor, "t")
	if err := donor.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	signer := mustSigner(t)
	pub := signer.PublicKey()
	enforceTrust(t, donor, map[string]string{siteHex(t, donor): hex.EncodeToString(pub[:])})

	batch, err := Export(donor, Cursor{}, 1<<20, 1<<20, signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Blob) < 12 || batch.Blob[4] != 2 {
		t.Fatalf("enforced export must be v2, got version %d", batch.Blob[4])
	}
	cells, err := DecodeCells(batch.Blob)
	if err != nil || len(cells) != 1 || len(cells[0].Sig) != 64 {
		t.Fatalf("v2 decode = %d cells, %v", len(cells), err)
	}

	db := openCRR(t)
	makeSyncTable(t, db, "t")
	donorSite, err := SiteID(donor)
	if err != nil {
		t.Fatal(err)
	}
	enforceTrust(t, db, map[string]string{siteHex(t, donor): hex.EncodeToString(pub[:])})
	donorNode := mustNode(t, strings.Repeat("11", 16))
	if err := applyBatch(t, db, donorNode, donorSite, batch.Blob, batch.Next); err != nil {
		t.Fatalf("honest v2 batch refused: %v", err)
	}
	st, err := db.Prepare("SELECT b FROM t WHERE a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if done, err := st.Step(); err != nil || done {
		t.Fatalf("row missing: %v %v", done, err)
	}
	if st.ColumnText(0) != "x" {
		t.Fatalf("b = %q", st.ColumnText(0))
	}
	st.Close()
	if n, err := countRows(db, "SELECT COUNT(*) FROM murmur_cell_sigs"); err != nil || n != 1 {
		t.Fatalf("stored sigs = %d,%v", n, err)
	}
}

func TestEnforcedForwarding(t *testing.T) {
	// A compromised forwarder cannot forge, but honest forwarding
	// preserves origin bytes: source -> relay -> sink converges
	// with the origin signature intact.
	source := openCRR(t)
	makeSyncTable(t, source, "t")
	if err := source.Exec("INSERT INTO t VALUES(1,'source');"); err != nil {
		t.Fatal(err)
	}
	sourceSigner := mustSigner(t)
	sourcePub := sourceSigner.PublicKey()
	relaySigner := mustSigner(t)
	relayPub := relaySigner.PublicKey()
	pins := map[string]string{
		siteHex(t, source): hex.EncodeToString(sourcePub[:]),
	}
	enforceTrust(t, source, pins)

	original, err := Export(source, Cursor{}, 1<<20, 1<<20, sourceSigner)
	if err != nil {
		t.Fatal(err)
	}
	origCells, err := DecodeCells(original.Blob)
	if err != nil || len(origCells) != 1 {
		t.Fatal(err)
	}

	relay := openCRR(t)
	makeSyncTable(t, relay, "t")
	relaySite, err := SiteID(relay)
	if err != nil {
		t.Fatal(err)
	}
	pins[siteHex(t, relay)] = hex.EncodeToString(relayPub[:])
	enforceTrust(t, relay, pins)
	sourceSite, err := SiteID(source)
	if err != nil {
		t.Fatal(err)
	}
	sourceNode := mustNode(t, strings.Repeat("22", 16))
	if err := applyBatch(t, relay, sourceNode, sourceSite, original.Blob, original.Next); err != nil {
		t.Fatalf("relay refused honest batch: %v", err)
	}
	if err := relay.Exec("INSERT INTO t VALUES(2,'relay');"); err != nil {
		t.Fatal(err)
	}
	forwarded, err := Export(relay, Cursor{}, 1<<20, 1<<20, relaySigner)
	if err != nil {
		t.Fatal(err)
	}
	fwdCells, err := DecodeCells(forwarded.Blob)
	if err != nil || len(fwdCells) != 2 {
		t.Fatalf("forwarded decode = %d,%v", len(fwdCells), err)
	}
	for _, c := range fwdCells {
		if bytes.Equal(c.SiteID, sourceSite[:]) && !bytes.Equal(c.Sig, origCells[0].Sig) {
			t.Fatal("forwarder altered the origin signature")
		}
	}

	sink := openCRR(t)
	makeSyncTable(t, sink, "t")
	enforceTrust(t, sink, pins)
	relayNode := mustNode(t, strings.Repeat("33", 16))
	if err := applyBatch(t, sink, relayNode, relaySite, forwarded.Blob, forwarded.Next); err != nil {
		t.Fatalf("sink refused forwarded batch: %v", err)
	}
	if n, err := countRows(sink, "SELECT COUNT(*) FROM t"); err != nil || n != 2 {
		t.Fatalf("sink rows = %d,%v", n, err)
	}
}

func TestForgedCellViaForwarderRefused(t *testing.T) {
	donor := openCRR(t)
	makeSyncTable(t, donor, "t")
	if err := donor.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	signer := mustSigner(t)
	pub := signer.PublicKey()
	enforceTrust(t, donor, map[string]string{siteHex(t, donor): hex.EncodeToString(pub[:])})
	batch, err := Export(donor, Cursor{}, 1<<20, 1<<20, signer)
	if err != nil {
		t.Fatal(err)
	}
	donorSite, err := SiteID(donor)
	if err != nil {
		t.Fatal(err)
	}

	forge := func(t *testing.T, mutate func(*Cell)) []byte {
		t.Helper()
		cells, err := DecodeCells(batch.Blob)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&cells[0])
		out := EncodeCellsV2(cells)
		if out == nil {
			t.Fatal("re-encode failed")
		}
		return out
	}
	cases := map[string]func(*Cell){
		"value":      func(c *Cell) { c.Val = TextVal([]byte("forged")) },
		"colversion": func(c *Cell) { c.ColVersion++ },
		"table":      func(c *Cell) { c.Table = "t2" },
	}
	for name, mutate := range cases {
		db := openCRR(t)
		makeSyncTable(t, db, "t")
		enforceTrust(t, db, map[string]string{siteHex(t, donor): hex.EncodeToString(pub[:])})
		node := mustNode(t, strings.Repeat("44", 16))
		forged := forge(t, mutate)
		err := applyBatch(t, db, node, donorSite, forged, batch.Next)
		if errKind(err) != "Auth" {
			t.Fatalf("%s forgery: errKind = %v, want Auth", name, err)
		}
	}

	// Unknown origin: re-signed by a key nobody pinned.
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	enforceTrust(t, db, map[string]string{siteHex(t, donor): hex.EncodeToString(pub[:])})
	rogue := mustSigner(t)
	cells, err := DecodeCells(batch.Blob)
	if err != nil {
		t.Fatal(err)
	}
	rsig := rogue.SignCell(cells[0])
	cells[0].Sig = rsig[:]
	resigned := EncodeCellsV2(cells)
	node := mustNode(t, strings.Repeat("55", 16))
	if err := applyBatch(t, db, node, donorSite, resigned, batch.Next); errKind(err) != "Auth" {
		t.Fatalf("rogue-key batch: errKind = %v, want Auth", err)
	}
}

func TestUnsignedBatchRefusedUnderEnforcement(t *testing.T) {
	donor := openCRR(t)
	makeSyncTable(t, donor, "t")
	if err := donor.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	legacy, err := Export(donor, Cursor{}, 1<<20, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Blob[4] != 1 {
		t.Fatalf("legacy export must stay v1, got %d", legacy.Blob[4])
	}
	donorSite, err := SiteID(donor)
	if err != nil {
		t.Fatal(err)
	}

	db := openCRR(t)
	makeSyncTable(t, db, "t")
	signer := mustSigner(t)
	pub := signer.PublicKey()
	enforceTrust(t, db, map[string]string{siteHex(t, donor): hex.EncodeToString(pub[:])})
	node := mustNode(t, strings.Repeat("66", 16))
	if err := applyBatch(t, db, node, donorSite, legacy.Blob, legacy.Next); errKind(err) != "Auth" {
		t.Fatalf("v1 under enforcement: errKind = %v, want Auth", err)
	}
}

func TestEnforcedExportWithoutSigner(t *testing.T) {
	db := openCRR(t)
	makeSyncTable(t, db, "t")
	if err := db.Exec("INSERT INTO t VALUES(1,'x');"); err != nil {
		t.Fatal(err)
	}
	signer := mustSigner(t)
	pub := signer.PublicKey()
	enforceTrust(t, db, map[string]string{siteHex(t, db): hex.EncodeToString(pub[:])})
	if _, err := Export(db, Cursor{}, 1<<20, 1<<20, nil); errKind(err) != "Auth" {
		t.Fatalf("signerless export: errKind = %v, want Auth", err)
	}
}
