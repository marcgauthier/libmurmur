package replication

// Origin signatures for replication cells.
//
// Every replicated cell carries a 64-byte Ed25519 signature made by
// its origin site's key at export time. Signatures travel verbatim
// through forwarders, so any recipient can verify any cell against
// the pinned site key in trusted_origins, regardless of which peer
// delivered it. A compromised forwarder can withhold cells but
// cannot forge another origin's cells.
//
// The local seed lives only in engine memory (loaded at Start from
// origin_key_file). Trust comes from the operator-owned
// trusted_origins setting mapping site hex to pubkey hex. Unknown
// sites and bad signatures fail closed. An empty trusted_origins
// keeps the legacy unsigned v1 wire format.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// CellSigner signs cells with the local origin seed.
type CellSigner struct {
	seed [32]byte
}

// GenerateCellSeed returns fresh random origin seed bytes.
func GenerateCellSeed() ([32]byte, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, err
	}
	return seed, nil
}

// NewCellSigner builds a signer from 32 raw seed bytes.
func NewCellSigner(seed []byte) (*CellSigner, error) {
	if len(seed) != 32 {
		return nil, errors.New("origin seed must be exactly 32 bytes")
	}
	var s CellSigner
	copy(s.seed[:], seed)
	return &s, nil
}

// LoadCellSigner reads a 32-byte raw seed file. The file must hold
// exactly 32 bytes; anything else fails loud.
func LoadCellSigner(path string) (*CellSigner, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewCellSigner(raw)
}

// PublicKey derives the Ed25519 public key for the seed.
func (s *CellSigner) PublicKey() [32]byte {
	priv := ed25519.NewKeyFromSeed(s.seed[:])
	var pub [32]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))
	return pub
}

// SignCell signs one cell's canonical bytes.
func (s *CellSigner) SignCell(c Cell) [64]byte {
	priv := ed25519.NewKeyFromSeed(s.seed[:])
	sig := ed25519.Sign(priv, CellCanonical(c))
	var out [64]byte
	copy(out[:], sig)
	return out
}

// VerifyCell checks one cell against a pinned origin pubkey.
func VerifyCell(pub [32]byte, c Cell, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	return ed25519.Verify(pub[:], CellCanonical(c), sig)
}

// TrustMap pins origin site ids to Ed25519 public keys. Empty means
// unconfigured (legacy unsigned mode); non-empty enforces v2
// signatures everywhere.
type TrustMap map[NodeID][32]byte

// LoadTrustMap parses the trusted_origins setting
// ({"<site-hex>":"<pubkey-hex>", ...}). Malformed entries are
// skipped: an unparseable pin simply never matches (fail closed at
// lookup).
func LoadTrustMap(db *sqlite.Conn) (TrustMap, error) {
	out := TrustMap{}
	// Stores without replication metadata predate trust:
	// unconfigured (legacy), not an error.
	st, err := db.Prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='murmur_config'")
	if err != nil {
		return nil, err
	}
	done, err := st.Step()
	st.Close()
	if err != nil {
		return nil, err
	}
	if done {
		return out, nil
	}
	raw, err := Setting(db, "trusted_origins")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return out, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	for ks, vs := range m {
		sb, err := hex.DecodeString(ks)
		if err != nil || len(sb) != 16 {
			continue
		}
		pb, err := hex.DecodeString(vs)
		if err != nil || len(pb) != 32 {
			continue
		}
		var site NodeID
		var pub [32]byte
		copy(site[:], sb)
		copy(pub[:], pb)
		out[site] = pub
	}
	return out, nil
}

// StoreCellSig persists a verified origin signature for verbatim
// re-export by forwarders.
func StoreCellSig(db *sqlite.Conn, table string, pk []byte, cid string, site []byte, colVersion int64, sig []byte) error {
	return execArgs(db, `INSERT OR REPLACE INTO murmur_cell_sigs("table",pk,cid,site,col_version,sig) VALUES(?1,?2,?3,?4,?5,?6)`,
		[]byte(table), pk, []byte(cid), site, colVersion, sig)
}

// LookupCellSig fetches a stored origin signature. It returns
// (nil, nil) when no signature is stored.
func LookupCellSig(db *sqlite.Conn, table string, pk []byte, cid string, site []byte, colVersion int64) ([]byte, error) {
	st, err := db.Prepare(`SELECT sig FROM murmur_cell_sigs WHERE "table"=?1 AND pk=?2 AND cid=?3 AND site=?4 AND col_version=?5`)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if err := bindAny(st, 1, []byte(table)); err != nil {
		return nil, err
	}
	if err := bindAny(st, 2, pk); err != nil {
		return nil, err
	}
	if err := bindAny(st, 3, []byte(cid)); err != nil {
		return nil, err
	}
	if err := bindAny(st, 4, site); err != nil {
		return nil, err
	}
	if err := bindAny(st, 5, colVersion); err != nil {
		return nil, err
	}
	done, err := st.Step()
	if err != nil {
		return nil, err
	}
	if done {
		return nil, nil
	}
	return append([]byte(nil), st.ColumnBlob(0)...), nil
}

// CellSigGC drops stored signatures with no matching change row.
// Both sides CAST to BLOB: crsql_changes key columns may be TEXT or
// BLOB, and SQLite never equates TEXT with BLOB.
func CellSigGC(db *sqlite.Conn) error {
	return db.Exec(`DELETE FROM murmur_cell_sigs WHERE NOT EXISTS(SELECT 1 FROM crsql_changes c WHERE CAST(c."table" AS BLOB)=CAST(murmur_cell_sigs."table" AS BLOB) AND CAST(c.pk AS BLOB)=CAST(murmur_cell_sigs.pk AS BLOB) AND CAST(c.cid AS BLOB)=CAST(murmur_cell_sigs.cid AS BLOB) AND CAST(c.site_id AS BLOB)=CAST(murmur_cell_sigs.site AS BLOB) AND c.col_version=murmur_cell_sigs.col_version)`)
}
