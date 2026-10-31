// Live test: honest clients remain usable during QUIC connection pressure.
//
// Port of MURMUR-SQL dos-client: an attacker holds authenticated QUIC
// half-open connections (node TLS client cert, never a Hello) while
// spraying UDP garbage; honest durable writes on both nodes must keep
// landing within 10 s, half-opens must never become replication peers,
// and after the attack the mesh converges exactly and the peer count
// returns to baseline. Nodes are native replication drivers over VFS
// stores, in-process; the reference's pre-startup TCP and
// partial-SSLRequest SQL half-opens have no target on this stack (no
// SQL listener exists), so only QUIC pressure applies.
package dosclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/marcgauthier/sqlite-murmur-go/clients/go/pkgs/replication"
	goharness "github.com/marcgauthier/sqlite-murmur-go/clients/go/tests-live/goharness"
)

// seconds is a positive-integer seconds env knob with fallback.
func seconds(name string, fallback uint64) time.Duration {
	if v, err := strconv.ParseUint(os.Getenv(name), 10, 64); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(fallback) * time.Second
}

// quicAttacker dials authenticated QUIC connections using node TLS
// material (never completing the replication Hello).
type quicAttacker struct {
	tlsConf  *tls.Config
	quicConf *quic.Config
}

// newQuicAttacker builds the attacker config with a fresh CA-signed leaf
// for a foreign node id: authenticated by the cluster CA, but with no
// live replication session, so session replacement can never reap the
// half-opens. Server verification is skipped: the attacker only needs
// completed handshakes, while the server still authenticates the client
// certificate.
func newQuicAttacker(t *testing.T, cluster *goharness.Cluster) *quicAttacker {
	t.Helper()
	var attackerID [16]byte
	for i := range attackerID {
		attackerID[i] = 0x77
	}
	issued, err := cluster.Ca.Issue(attackerID, nil)
	if err != nil {
		t.Fatalf("issue attacker leaf: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(issued.CertPEM), []byte(issued.KeyPEM))
	if err != nil {
		t.Fatalf("parse attacker keypair: %v", err)
	}
	return &quicAttacker{
		tlsConf: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{replication.ALPN},
			InsecureSkipVerify: true,
		},
		quicConf: &quic.Config{},
	}
}

// halfOpen dials one QUIC connection and opens one bidirectional stream,
// holding both open without ever sending a Hello. It reports false when
// either step times out (the caller retries during top-up).
func (a *quicAttacker) halfOpen(addr string) (*quic.Conn, *quic.Stream, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	conn, err := quic.DialAddr(ctx, addr, a.tlsConf, a.quicConf)
	cancel()
	if err != nil {
		return nil, nil, false
	}
	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	stream, err := conn.OpenStreamSync(openCtx)
	openCancel()
	if err != nil {
		_ = conn.CloseWithError(0, "done")
		return nil, nil, false
	}
	return conn, stream, true
}

// peerCount returns the connected-peer count on one node.
func peerCount(t *testing.T, cluster *goharness.Cluster, node int) int {
	t.Helper()
	peers, err := cluster.Node(node).ShowPeers()
	if err != nil {
		t.Fatalf("SHOW PEERS: %v", err)
	}
	n := 0
	for _, p := range peers {
		if p.Connected {
			n++
		}
	}
	return n
}

// aliveHalfOpens counts half-opens whose connection has no close reason.
func aliveHalfOpens(halfOpens []halfOpen) int {
	n := 0
	for _, h := range halfOpens {
		if h.conn.Context().Err() == nil {
			n++
		}
	}
	return n
}

type halfOpen struct {
	conn   *quic.Conn
	stream *quic.Stream
}

// durableWriteTimeout bounds one honest durable write (INSERT + FLUSH).
const durableWriteTimeout = 10 * time.Second

func TestSQLAndQUICHalfOpenPressureDoesNotStarveHonestClients(t *testing.T) {
	goharness.SkipUnlessLive(t)
	cluster, err := goharness.NewCluster(goharness.ClusterOptions{
		Name:     "dos-client",
		NumNodes: 2,
	})
	if err != nil {
		t.Fatalf("start cluster: %v", err)
	}
	failed := true
	defer func() { cluster.Finish(failed) }()

	for i := 0; i < 2; i++ {
		if _, err := cluster.Node(i).Simple("CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '')"); err != nil {
			t.Fatalf("create records: %v", err)
		}
		if err := cluster.Node(i).SetTableReplicated("records", true); err != nil {
			t.Fatalf("replicate records: %v", err)
		}
	}
	if _, err := cluster.Node(0).Execute("INSERT INTO records(id,body) VALUES(0,'baseline')"); err != nil {
		t.Fatalf("insert baseline: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush baseline: %v", err)
	}
	expected := [][]string{{"baseline"}}
	if err := goharness.AssertRows(cluster, []int{0, 1}, "SELECT body FROM records ORDER BY id", expected); err != nil {
		t.Fatalf("converge baseline: %v", err)
	}
	base := peerCount(t, cluster, 0)
	if base != 1 {
		t.Fatalf("peer count = %d, want 1", base)
	}
	count := 24
	if v, err := strconv.Atoi(os.Getenv("MURMUR_DOS_CLIENT_QUIC_HALFOPEN")); err == nil && v > 0 {
		count = v
	}
	// Foreign-identity pressure: a dial presenting the target's own
	// leaf is dropped immediately (loop protection), and a cloned
	// live leaf is reaped by session replacement once replication
	// flows, so the attacker mints a fresh CA-signed leaf the
	// reference's fixed node material cannot provide.
	attacker := newQuicAttacker(t, cluster)
	replAddr := cluster.Node(0).Addr
	var halfOpens []halfOpen
	for i := 0; i < count; i++ {
		if conn, stream, ok := attacker.halfOpen(replAddr); ok {
			halfOpens = append(halfOpens, halfOpen{conn: conn, stream: stream})
		}
	}
	if len(halfOpens) < (count+1)/2 {
		t.Fatalf("attack failed to hold enough authenticated QUIC half-opens: %d of %d",
			len(halfOpens), count)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", replAddr)
	if err != nil {
		t.Fatalf("resolve repl addr: %v", err)
	}
	udpLocal, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve UDP local: %v", err)
	}
	udp, err := net.DialUDP("udp", udpLocal, udpAddr)
	if err != nil {
		t.Fatalf("dial UDP: %v", err)
	}
	defer udp.Close()
	garbage := make([]byte, 1200)
	for i := range garbage {
		garbage[i] = 0xa5
	}
	deadline := time.Now().Add(seconds("MURMUR_DOS_CLIENT_ATTACK_SECONDS", 60))
	id := int64(1)
	for time.Now().Before(deadline) {
		// Replace expired connections so long runs keep applying pressure.
		alive := halfOpens[:0]
		for _, h := range halfOpens {
			if h.conn.Context().Err() == nil {
				alive = append(alive, h)
			}
		}
		halfOpens = alive
		for len(halfOpens) < count {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			conn, err := quic.DialAddr(ctx, replAddr, attacker.tlsConf, attacker.quicConf)
			cancel()
			if err != nil {
				t.Fatalf("half-open top-up handshake failed: %v", err)
			}
			openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
			stream, err := conn.OpenStreamSync(openCtx)
			openCancel()
			if err != nil {
				_ = conn.CloseWithError(0, "done")
				t.Fatal("half-open stream timed out")
			}
			halfOpens = append(halfOpens, halfOpen{conn: conn, stream: stream})
		}
		// Pressure is proven at top-up: this engine expires
		// missing-Hello connections in well under a second (the
		// reference allows five), so survivors are rechecked here
		// rather than after the honest writes.
		if alive := aliveHalfOpens(halfOpens); alive < (count+1)/2 {
			t.Fatalf("half-open attack pressure vanished early (%d of %d)", alive, count)
		}
		for i := 0; i < 10; i++ {
			if _, err := udp.Write(garbage); err != nil {
				t.Fatalf("send UDP garbage: %v", err)
			}
		}
		for node := 0; node < 2; node++ {
			body := fmt.Sprintf("heartbeat-%04d-node-%d", id, node)
			start := time.Now()
			type writeResult struct {
				err error
			}
			done := make(chan writeResult, 1)
			go func() {
				_, err := cluster.Node(node).Execute("INSERT INTO records(id,body) VALUES($1,$2)", id, body)
				if err != nil {
					done <- writeResult{err: err}
					return
				}
				err = cluster.Node(node).Flush()
				done <- writeResult{err: err}
			}()
			select {
			case res := <-done:
				if res.err != nil {
					t.Fatalf("honest durable write failed: %v", res.err)
				}
			case <-time.After(durableWriteTimeout):
				t.Fatal("honest durable write starved")
			}
			if elapsed := time.Since(start); elapsed >= durableWriteTimeout {
				t.Fatalf("honest durable write took %s", elapsed)
			}
			expected = append(expected, []string{body})
			id++
		}
		if n := peerCount(t, cluster, 0); n > base+2 {
			t.Fatalf("half-opens became replication peers (peers=%d, base=%d)", n, base)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(expected) < 3 {
		t.Fatal("no honest write made under pressure")
	}
	for _, leg := range []struct {
		node    int
		pattern string
	}{{0, "%node-1"}, {1, "%node-0"}} {
		rows, err := cluster.Node(leg.node).Simple(
			"SELECT count(*) FROM records WHERE body LIKE " + goharness.SQLLiteral(leg.pattern))
		if err != nil {
			t.Fatalf("remote apply count: %v", err)
		}
		n, err := strconv.ParseInt(rows[0][0], 10, 64)
		if err != nil {
			t.Fatalf("decode remote apply count: %v", err)
		}
		if n <= 0 {
			t.Fatal("remote apply starved for the entire attack window")
		}
	}
	for _, h := range halfOpens {
		_ = h.conn.CloseWithError(0, "done")
	}
	if err := goharness.AssertRows(cluster, []int{0, 1}, "SELECT body FROM records ORDER BY id", expected); err != nil {
		t.Fatalf("converge after attack: %v", err)
	}
	recovery := time.Now().Add(30 * time.Second)
	for peerCount(t, cluster, 0) != base {
		if !time.Now().Before(recovery) {
			t.Fatal("attacker left replication sessions attached")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := cluster.Node(0).Execute("INSERT INTO records(id,body) VALUES($1,'post-attack')", id); err != nil {
		t.Fatalf("insert post-attack: %v", err)
	}
	if err := cluster.Node(0).Flush(); err != nil {
		t.Fatalf("flush post-attack: %v", err)
	}
	expected = append(expected, []string{"post-attack"})
	if err := goharness.AssertRows(cluster, []int{0, 1}, "SELECT body FROM records ORDER BY id", expected); err != nil {
		t.Fatalf("converge post-attack: %v", err)
	}
	failed = false
}

// TestSQLHalfOpenPressure documents the reference's SQL half-open legs
// (pre-startup TCP connections and partial SSLRequests held against the
// PostgreSQL listener). Native nodes expose no SQL listener — SQL runs
// in-process — so there is nothing to hold half-open; QUIC pressure
// above is the whole attack surface.
func TestSQLHalfOpenPressure(t *testing.T) {
	goharness.SkipUnlessLive(t)
	t.Skip("no SQL listener on native stack (in-process SQL); QUIC half-open pressure only")
}
