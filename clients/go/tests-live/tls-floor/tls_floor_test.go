// Live scenario: the QUIC replication endpoint enforces a TLS 1.3 floor.
//
// Port of MURMUR-SQL tls-floor: a 2-node cluster converges a marker over
// QUIC, a TLS-1.2-only QUIC client is refused, a TLS 1.3 client
// completes a handshake and opens a stream, and the mesh still
// converges a post-probe marker. The floor is proven the Go way: a
// MaxVersion-TLS1.2 dial must fail while the identical TLS 1.3 dial
// succeeds. Credentials come from the harness-issued node TLS dir
// (tls/ca.pem, tls/node.pem, tls/node-key.pem); chain verification
// mirrors the product client (roots pinned, server name ignored, leaf
// URI SAN node id parsed) against ALPN murmur-crsqlite/1.
package tlsfloor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/replication"
	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// credentials bundles the probe-side chain, key, and trust roots.
type credentials struct {
	chain [][]byte
	key   []byte
	roots [][]byte
}

// loadCredentials reads node TLS files into probe credentials
// (reference: the PEM reads in build_client_config).
func loadCredentials(t *testing.T, caPath, certPath, keyPath string) credentials {
	t.Helper()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("open ca.pem: %v", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("open cert.pem: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("open key.pem: %v", err)
	}
	var roots [][]byte
	for block, rest := pem.Decode(caPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			roots = append(roots, block.Bytes)
		}
	}
	if len(roots) == 0 {
		t.Fatal("parse ca: no certificates")
	}
	var chain [][]byte
	for block, rest := pem.Decode(certPEM); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		t.Fatal("parse cert: no certificates")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("read key: no PEM block")
	}
	return credentials{chain: chain, key: keyBlock.Bytes, roots: roots}
}

// parsePrivateKey parses a PKCS8, EC, or PKCS1 DER private key.
func parsePrivateKey(t *testing.T, der []byte) any {
	t.Helper()
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatalf("invalid private key: %v", err)
	}
	return key
}

// parseNodeID extracts the replicateddb://node/<hex> URI SAN identity,
// mirroring the product transport's leaf check.
func parseNodeID(der []byte) error {
	peer, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	for _, uri := range peer.URIs {
		s := uri.String()
		const prefix = "replicateddb://node/"
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(s, prefix))
		if err != nil || len(raw) != 16 {
			return errors.New("bad node URI SAN")
		}
		var zero [16]byte
		if [16]byte(raw) == zero {
			return errors.New("zero node id")
		}
		return nil
	}
	return errors.New("missing node URI SAN")
}

// probeTLSConfig builds a probe-side TLS client config with exactly the
// given TLS versions enabled (reference: build_client_config with a
// version pin).
func probeTLSConfig(t *testing.T, creds credentials, minVersion, maxVersion uint16) *tls.Config {
	t.Helper()
	leaf, err := x509.ParseCertificate(creds.chain[0])
	if err != nil {
		t.Fatalf("parse probe leaf: %v", err)
	}
	roots := x509.NewCertPool()
	for _, der := range creds.roots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse trust root: %v", err)
		}
		roots.AddCert(cert)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: creds.chain,
			PrivateKey:  parsePrivateKey(t, creds.key),
			Leaf:        leaf,
		}},
		ServerName:         "murmur.invalid",
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		NextProtos:         []string{replication.ALPN},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("missing peer certificate")
			}
			peer, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			intermediates := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if cert, err := x509.ParseCertificate(raw); err == nil {
					intermediates.AddCert(cert)
				}
			}
			if _, err := peer.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return err
			}
			return parseNodeID(rawCerts[0])
		},
	}
}

func quicConf() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    40,
		MaxIncomingUniStreams: -1,
		EnableDatagrams:       true,
	}
}

// dial opens a QUIC connection to addr with the given TLS config.
func dial(addr netip.AddrPort, conf *tls.Config, timeout time.Duration) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return quic.DialAddr(ctx, addr.String(), conf, quicConf())
}

func TestQUICFloorRejectsBelowTLS13(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "tls-floor",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("cluster setup: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < cluster.Len(); i++ {
		if _, err := cluster.Node(i).Simple(
			"CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("node %d create records: %v", i, err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("node %d replicate records: %v", i, err)
		}
		if err := cluster.Node(i).Flush(); err != nil {
			t.Fatalf("node %d flush: %v", i, err)
		}
	}

	// Mesh positive control: a marker converges over QUIC (TLS 1.3).
	if _, err := cluster.Node(0).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(1), "tls-version-floor-marker"); err != nil {
		t.Fatalf("marker insert: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush marker: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM records ORDER BY id",
		[][]string{{"tls-version-floor-marker"}}); err != nil {
		t.Fatalf("converge marker: %v", err)
	}

	repl, err := netip.ParseAddrPort(cluster.Node(0).Addr)
	if err != nil {
		t.Fatalf("parse node addr %q: %v", cluster.Node(0).Addr, err)
	}
	tlsPaths := cluster.Node(0).TLS
	creds := loadCredentials(t, tlsPaths.Ca, tlsPaths.Chain, tlsPaths.Key)

	// Floor negative: TLS 1.2 is strictly rejected for QUIC (RFC 9001
	// requires TLS 1.3 exclusively). Dialability itself was proven by
	// the mesh above, so any failure here is version-caused.
	legacy := probeTLSConfig(t, creds, tls.VersionTLS12, tls.VersionTLS12)
	legacyConn, err := dial(repl, legacy, 10*time.Second)
	if err == nil {
		_ = legacyConn.CloseWithError(0, "floor violated")
		t.Fatal("TLS 1.2 dial unexpectedly succeeded: floor violated")
	}
	t.Logf("TLS 1.2 dial refused (%v); floor holds", err)

	// Floor positive: TLS 1.3 handshake completes and opens a stream.
	modern := probeTLSConfig(t, creds, tls.VersionTLS13, tls.VersionTLS13)
	conn, err := dial(repl, modern, 10*time.Second)
	if err != nil {
		t.Fatalf("TLS 1.3 dial failed: %v", err)
	}
	openCtx, openCancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := conn.OpenStreamSync(openCtx)
	openCancel()
	if err != nil {
		_ = conn.CloseWithError(0, "probe done")
		t.Fatalf("TLS 1.3 stream open failed: %v", err)
	}
	_ = stream.Close()
	_ = conn.CloseWithError(0, "probe done")

	// Verify mesh replication remains healthy post-probe.
	if _, err := cluster.Node(1).Execute(
		"INSERT INTO records(id, name) VALUES($1, $2)", int64(2), "post-probe-marker"); err != nil {
		t.Fatalf("post-probe insert: %v", err)
	}
	if err := cluster.Node(1).Flush(); err != nil {
		t.Fatalf("flush post-probe: %v", err)
	}
	if err := goharness.AssertRows(cluster, []int{0, 1},
		"SELECT name FROM records ORDER BY id",
		[][]string{{"tls-version-floor-marker"}, {"post-probe-marker"}}); err != nil {
		t.Fatalf("converge post-probe: %v", err)
	}
	failed = false
}
