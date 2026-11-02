// Live scenarios: real Low (exporter) and High (importer) domains move
// logical writes across a directory drop.
//
// Port of MURMUR-SQL highlow: the reference moves contact writes across
// a one-way directory drop between separate Low exporter and High
// importer clusters. Seven legs run here against the native bridge
// workers (capture, sender, receiver, typed LWW import); only the
// High-peer mesh leg runs the signed four-node native profile scenario.
//
// Native-vs-reference deviations asserted below (see README.md):
//   - bundles pinned to another source database are ignored in place,
//     not quarantined (routing hints skip unrelated streams);
//   - oversized/tiny inputs count Rejected without a quarantine copy;
//   - a replay of already-committed bytes always stages as Duplicate,
//     even when its signer has since retired; only fresh bytes from a
//     retired signer are quarantined.
package highlow

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	goharness "github.com/marcgauthier/libmurmur/clients/go/tests-live/goharness"
	highlowpeer "github.com/marcgauthier/libmurmur/clients/go/tests-live/highlow-peer"
)

const (
	stream      = "highlow-contacts"
	waitTimeout = 10 * time.Second
	waitPoll    = 10 * time.Millisecond
	schemaBase  = "CREATE TABLE contacts(id TEXT PRIMARY KEY NOT NULL,name TEXT,score INTEGER)"
	schemaEmail = "CREATE TABLE contacts(id TEXT PRIMARY KEY NOT NULL,name TEXT,score INTEGER,email TEXT)"
)

type keys struct {
	seed, signer, secret, recipient [32]byte
}

func makeKeys(t *testing.T, seedByte, secretByte byte) keys {
	t.Helper()
	var k keys
	k.seed[0], k.secret[0] = seedByte, secretByte
	copy(k.signer[:], ed25519.NewKeyFromSeed(k.seed[:])[32:])
	recipient, err := bridge.RecipientPublic(k.secret)
	if err != nil {
		t.Fatal(err)
	}
	k.recipient = recipient
	return k
}

// newDomain boots a single-node cluster with the contacts table.
func newDomain(t *testing.T, name, schema string) *goharness.Cluster {
	t.Helper()
	c, err := goharness.NewCluster(goharness.ClusterOptions{Name: name, NumNodes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Node(0).ExecBatch(schema); err != nil {
		c.Finish(true)
		t.Fatal(err)
	}
	return c
}

func exec(t *testing.T, node *goharness.Node, query string, args ...any) {
	t.Helper()
	if _, err := node.Execute(query, args...); err != nil {
		t.Fatal(err)
	}
}

// contacts renders id=name:score rows in id order (email appended when present).
func contacts(t *testing.T, node *goharness.Node, withEmail bool) string {
	t.Helper()
	expr := "id||'='||name||':'||score"
	if withEmail {
		expr = "id||'='||name||':'||score||':'||ifnull(email,'')"
	}
	rows, err := node.Simple("SELECT group_concat(x,'|') FROM (SELECT " + expr + " AS x FROM contacts ORDER BY id)")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("contacts query returned %d rows", len(rows))
	}
	return rows[0][0]
}

func waitContacts(t *testing.T, node *goharness.Node, want string, withEmail bool) {
	t.Helper()
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		rows, err := node.Simple("SELECT group_concat(x,'|') FROM (SELECT " +
			func() string {
				if withEmail {
					return "id||'='||name||':'||score||':'||ifnull(email,'')"
				}
				return "id||'='||name||':'||score"
			}() + " AS x FROM contacts ORDER BY id)")
		return err == nil && len(rows) == 1 && rows[0][0] == want
	}) {
		t.Fatalf("contacts did not become %q (now %q)", want, contacts(t, node, withEmail))
	}
}

// listBundles returns the .bundle entries of a ferry/spool/quarantine
// directory. Transient *.pending publish temps (native and test-side)
// are excluded: a listing can otherwise catch one mid-publish.
func listBundles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".bundle" {
			names = append(names, e.Name())
		}
	}
	return names
}

// bundleSeq reads the MHB1 stream sequence (offset 52, 8 bytes LE).
func bundleSeq(t *testing.T, b []byte) uint64 {
	t.Helper()
	if len(b) < 60 || string(b[:4]) != "MHB1" {
		t.Fatalf("not an MHB1 bundle (%d bytes)", len(b))
	}
	return binary.LittleEndian.Uint64(b[52:60])
}

func bundleName(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) + ".bundle"
}

func readBundle(t *testing.T, dir, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	// Atomic publish (temp + rename): the receiver polls every 10 ms and
	// would quarantine a partially written file under its own digest.
	// The temp suffix never matches the 64-hex + ".bundle" scan pattern.
	tmp, err := os.CreateTemp(dir, ".tmp-*.pending")
	if err != nil {
		t.Fatal(err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		os.Remove(tmpName)
		t.Fatal(err)
	}
}

// seqMap indexes a spool directory's bundles by stream sequence.
func seqMap(t *testing.T, dir string) map[uint64]string {
	t.Helper()
	out := map[uint64]string{}
	for _, name := range listBundles(t, dir) {
		out[bundleSeq(t, readBundle(t, dir, name))] = name
	}
	return out
}

func configureLow(t *testing.T, low *goharness.Cluster, k keys, tables ...string) {
	t.Helper()
	cfg := bridge.CaptureConfig{Role: bridge.Low, Database: low.Group, Node: low.Node(0).ID,
		Signer: k.seed, Recipient: k.recipient, Stream: stream}
	if err := low.Node(0).ConfigureBridgeCapture(cfg, tables...); err != nil {
		t.Fatal(err)
	}
}

func configureHigh(t *testing.T, high *goharness.Cluster, tables ...string) {
	t.Helper()
	cfg := bridge.CaptureConfig{Role: bridge.High, Database: high.Group, Node: high.Node(0).ID, Stream: stream}
	if err := high.Node(0).ConfigureBridgeCapture(cfg, tables...); err != nil {
		t.Fatal(err)
	}
}

func startSender(t *testing.T, low *goharness.Cluster, dir string) {
	t.Helper()
	if err := low.Node(0).StartBridgeSender(low.Group, stream, dir, true); err != nil {
		t.Fatal(err)
	}
}

func startReceiver(t *testing.T, high *goharness.Cluster, low *goharness.Cluster, secret [32]byte, signers [][32]byte, dir, quarantine string) {
	t.Helper()
	cfg := bridge.ReceiverConfig{Source: low.Group, Exporter: low.Node(0).ID,
		Secret: secret, Signers: signers, Stream: stream, Directory: dir, QuarantineDirectory: quarantine}
	if err := high.Node(0).StartBridgeReceiver(cfg); err != nil {
		t.Fatal(err)
	}
}

// waitPublished waits for the Low sender to publish n artifacts.
func waitPublished(t *testing.T, low *goharness.Cluster, n uint64) {
	t.Helper()
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return low.Node(0).BridgeSenderStatus().Published == n
	}) {
		t.Fatalf("sender did not publish %d artifacts: %+v", n, low.Node(0).BridgeSenderStatus())
	}
}

// waitApplied waits for the High receiver to apply n bundles.
func waitApplied(t *testing.T, high *goharness.Cluster, n uint64) {
	t.Helper()
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Applied == n
	}) {
		t.Fatalf("receiver did not apply %d bundles: %+v", n, high.Node(0).BridgeReceiverStatus())
	}
}

func TestDisconnectedTransferWithOneWayRoleGating(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-low", schemaBase)
	defer func() { low.Finish(t.Failed()) }()
	high := newDomain(t, "highlow-high", schemaBase)
	defer func() { high.Finish(t.Failed()) }()
	if low.Group == high.Group {
		t.Fatal("Low and High share a database id")
	}
	ferry, quarantine := t.TempDir(), t.TempDir()
	k := makeKeys(t, 1, 11)
	configureLow(t, low, k, "contacts")
	startSender(t, low, ferry)
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, quarantine)

	// Role gating: a receiver over the same ferry on the Low node itself
	// must never import — attached Low cannot import typed bridge data.
	reverseGated := false
	reverseCfg := bridge.ReceiverConfig{Source: low.Group, Exporter: low.Node(0).ID,
		Secret: k.secret, Signers: [][32]byte{k.signer}, Stream: stream,
		Directory: ferry, QuarantineDirectory: t.TempDir()}
	if err := low.Node(0).StartBridgeReceiver(reverseCfg); err != nil {
		reverseGated = true
		t.Logf("reverse receiver rejected at configuration: %v", err)
	}

	// LOW SENDS: two writes publish exactly two ferry artifacts.
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('ann','Ann',1)")
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('bob','Bob',2)")
	waitPublished(t, low, 2)
	if names := listBundles(t, ferry); len(names) != 2 {
		t.Fatalf("ferry holds %d files, want 2", len(names))
	}

	// HIGH DOWNLOADS: the receiver applies both and matches Low exactly.
	waitApplied(t, high, 2)
	want := "ann=Ann:1|bob=Bob:2"
	if got := contacts(t, low.Node(0), false); got != want {
		t.Fatalf("low contacts = %q, want %q", got, want)
	}
	waitContacts(t, high.Node(0), want, false)
	if s := high.Node(0).BridgeReceiverStatus(); s.Rejected != 0 || s.LastResult != 0 {
		t.Fatalf("receiver errors on clean transfer: %+v", s)
	}

	// The reverse receiver, if it configured, must still have applied nothing.
	time.Sleep(time.Second)
	if !reverseGated {
		if s := low.Node(0).BridgeReceiverStatusFor(low.Group, stream); s.Applied != 0 {
			t.Fatalf("Low-side receiver imported %d bundles, want 0 (role gating)", s.Applied)
		}
		if got := contacts(t, low.Node(0), false); got != want {
			t.Fatalf("low contacts changed to %q, want %q", got, want)
		}
	}

	// No High->Low leakage: a High-owned claim never flows back to Low.
	exec(t, high.Node(0), "UPDATE contacts SET score=99 WHERE id='ann'")
	time.Sleep(time.Second)
	if got := contacts(t, low.Node(0), false); got != want {
		t.Fatalf("low contacts = %q after High write, want unchanged %q", got, want)
	}
	waitContacts(t, high.Node(0), "ann=Ann:99|bob=Bob:2", false)
}

func TestGapDeliveryWithDuplicateRecovery(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-gap-low", schemaBase)
	defer func() { low.Finish(t.Failed()) }()
	high := newDomain(t, "highlow-gap-high", schemaBase)
	defer func() { high.Finish(t.Failed()) }()
	// Manual ferry: the sender publishes to spool; the test copies bundles
	// into the receiver directory in a controlled order.
	spool, ferry, quarantine := t.TempDir(), t.TempDir(), t.TempDir()
	k := makeKeys(t, 3, 13)
	configureLow(t, low, k, "contacts")
	startSender(t, low, spool)
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, quarantine)

	exec(t, low.Node(0), "INSERT INTO contacts VALUES('r1','R1',1)")
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('r2','R2',2)")
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('r3','R3',3)")
	waitPublished(t, low, 3)
	bySeq := seqMap(t, spool)
	for _, seq := range []uint64{1, 2, 3} {
		if _, ok := bySeq[seq]; !ok {
			t.Fatalf("spool missing sequence %d (have %v)", seq, bySeq)
		}
	}
	deliver := func(seq uint64) {
		t.Helper()
		writeFile(t, ferry, bySeq[seq], readBundle(t, spool, bySeq[seq]))
	}

	// With the middle bundle withheld, only the first applies.
	deliver(1)
	waitApplied(t, high, 1)
	waitContacts(t, high.Node(0), "r1=R1:1", false)

	// The third bundle arrives over the gap: deferred, no skip-ahead.
	deliver(3)
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Deferred >= 1
	}) {
		t.Fatal("gap bundle was not deferred")
	}
	time.Sleep(500 * time.Millisecond)
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 1 {
		t.Fatalf("receiver skipped ahead over the gap: %+v", s)
	}
	if got := contacts(t, high.Node(0), false); got != "r1=R1:1" {
		t.Fatalf("high contacts = %q during gap, want only r1", got)
	}

	// Restoring the middle bundle converges all three.
	deliver(2)
	waitApplied(t, high, 3)
	waitContacts(t, high.Node(0), "r1=R1:1|r2=R2:2|r3=R3:3", false)

	// Duplicate redelivery changes nothing and quarantines nothing.
	before := high.Node(0).BridgeReceiverStatus()
	deliver(1)
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Duplicate > before.Duplicate
	}) {
		t.Fatal("duplicate redelivery was not recognized")
	}
	time.Sleep(300 * time.Millisecond)
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 3 || s.Rejected != 0 {
		t.Fatalf("duplicate changed applied/rejected: %+v", s)
	}
	if got := contacts(t, high.Node(0), false); got != "r1=R1:1|r2=R2:2|r3=R3:3" {
		t.Fatalf("high contacts = %q after duplicate, want unchanged", got)
	}
	if names := listBundles(t, quarantine); len(names) != 0 {
		t.Fatalf("quarantine holds %d files, want 0", len(names))
	}
}

func TestTwoReceiversConverge(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-tworecv-low", schemaBase)
	defer func() { low.Finish(t.Failed()) }()
	highA := newDomain(t, "highlow-tworecv-a", schemaBase)
	defer func() { highA.Finish(t.Failed()) }()
	highB := newDomain(t, "highlow-tworecv-b", schemaBase)
	defer func() { highB.Finish(t.Failed()) }()
	// One shared ferry; each High imports it through an independent lane.
	ferry := t.TempDir()
	k := makeKeys(t, 5, 15)
	configureLow(t, low, k, "contacts")
	startSender(t, low, ferry)
	for _, high := range []*goharness.Cluster{highA, highB} {
		configureHigh(t, high, "contacts")
		startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, t.TempDir())
	}

	exec(t, low.Node(0), "INSERT INTO contacts VALUES('ann','Ann',1)")
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('bob','Bob',2)")
	exec(t, low.Node(0), "UPDATE contacts SET score=3 WHERE id='ann'")
	waitPublished(t, low, 3)
	want := "ann=Ann:3|bob=Bob:2"
	for _, high := range []*goharness.Cluster{highA, highB} {
		waitApplied(t, high, 3)
		waitContacts(t, high.Node(0), want, false)
		if s := high.Node(0).BridgeReceiverStatus(); s.Rejected != 0 || s.LastResult != 0 {
			t.Fatalf("receiver errors: %+v", s)
		}
	}
	if got := contacts(t, low.Node(0), false); got != want {
		t.Fatalf("low contacts = %q, want %q", got, want)
	}
}

func TestForgeriesRejectedWithoutPartialApply(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-forge-low", schemaBase)
	defer func() { low.Finish(t.Failed()) }()
	high := newDomain(t, "highlow-forge-high", schemaBase)
	defer func() { high.Finish(t.Failed()) }()
	spool, ferry, quarantine := t.TempDir(), t.TempDir(), t.TempDir()
	k := makeKeys(t, 7, 17)
	configureLow(t, low, k, "contacts")
	startSender(t, low, spool)
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, quarantine)

	exec(t, low.Node(0), "INSERT INTO contacts VALUES('ann','Ann',1)")
	waitPublished(t, low, 1)
	genuine := readBundle(t, spool, listBundles(t, spool)[0])

	// Each forgery is evicted after its stage: the receiver revisits
	// ferry files every pass and counters count attempts, so a proven
	// file would otherwise drown later exact assertions. Quarantine
	// copies remain as evidence.
	evict := func(name string) {
		t.Helper()
		if err := os.Remove(filepath.Join(ferry, name)); err != nil {
			t.Fatal(err)
		}
	}
	assertHeld := func(stage, name string, quarantined int) {
		t.Helper()
		before := high.Node(0).BridgeReceiverStatus().Rejected
		if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
			return high.Node(0).BridgeReceiverStatus().Rejected > before
		}) {
			t.Fatalf("%s: never rejected: %+v", stage, high.Node(0).BridgeReceiverStatus())
		}
		time.Sleep(300 * time.Millisecond)
		if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 {
			t.Fatalf("%s: applied %d, want 0 (no partial apply): %+v", stage, s.Applied, s)
		}
		if got := contacts(t, high.Node(0), false); got != "" {
			t.Fatalf("%s: high holds %q, want empty", stage, got)
		}
		if names := listBundles(t, quarantine); len(names) != quarantined {
			t.Fatalf("%s: quarantine holds %d files %v, want %d", stage, len(names), names, quarantined)
		}
		evict(name)
	}
	assertIgnored := func(stage, name string, quarantined int) {
		t.Helper()
		before := high.Node(0).BridgeReceiverStatus()
		if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
			return high.Node(0).BridgeReceiverStatus().Scanned > before.Scanned
		}) {
			t.Fatalf("%s: never scanned: %+v", stage, high.Node(0).BridgeReceiverStatus())
		}
		time.Sleep(300 * time.Millisecond)
		if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 || s.Rejected != before.Rejected {
			t.Fatalf("%s: ignored file moved counters: %+v (was %+v)", stage, s, before)
		}
		if got := contacts(t, high.Node(0), false); got != "" {
			t.Fatalf("%s: high holds %q, want empty", stage, got)
		}
		if names := listBundles(t, quarantine); len(names) != quarantined {
			t.Fatalf("%s: quarantine holds %d files %v, want %d", stage, len(names), names, quarantined)
		}
		if _, err := os.Stat(filepath.Join(ferry, name)); err != nil {
			t.Fatalf("%s: file not left in place: %v", stage, err)
		}
		evict(name)
	}

	// Tampered bytes fail authentication and are quarantined.
	forged := append([]byte(nil), genuine...)
	forged[len(forged)-1] ^= 1
	forgedName := bundleName(forged)
	writeFile(t, ferry, forgedName, forged)
	assertHeld("tampered", forgedName, 1)

	// A bundle sealed to the wrong recipient cannot be decrypted here.
	var txn [16]byte
	if _, err := rand.Read(txn[:]); err != nil {
		t.Fatal(err)
	}
	var rogueSecret [32]byte
	rogueSecret[0] = 99
	rogueRecipient, err := bridge.RecipientPublic(rogueSecret)
	if err != nil {
		t.Fatal(err)
	}
	misdirected, err := bridge.Seal(bridge.Header{Database: low.Group, Node: low.Node(0).ID,
		Transaction: txn, Sequence: 1, Stream: stream}, k.seed, rogueRecipient, []byte("misdirected"))
	if err != nil {
		t.Fatal(err)
	}
	misdirectedName := bundleName(misdirected)
	writeFile(t, ferry, misdirectedName, misdirected)
	assertHeld("wrong-recipient", misdirectedName, 2)

	// A rogue domain's bundle is ignored in place: unrelated streams are
	// skipped before authentication, so counters and quarantine hold still.
	var rogueDB [16]byte
	if _, err := rand.Read(rogueDB[:]); err != nil {
		t.Fatal(err)
	}
	rogue, err := bridge.Seal(bridge.Header{Database: rogueDB, Node: low.Node(0).ID,
		Transaction: txn, Sequence: 1, Stream: stream}, k.seed, k.recipient, []byte("rogue"))
	if err != nil {
		t.Fatal(err)
	}
	rogueName := bundleName(rogue)
	writeFile(t, ferry, rogueName, rogue)
	assertIgnored("rogue-domain", rogueName, 2)

	// Oversized inputs are rejected without a quarantine copy.
	big := make([]byte, (16<<20)+1)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	bigName := bundleName(big)
	writeFile(t, ferry, bigName, big)
	assertHeld("oversized", bigName, 2)

	// Wrong-extension files are ignored in place.
	writeFile(t, ferry, "rogue.txt", genuine)
	assertIgnored("wrong-extension", "rogue.txt", 2)

	// The genuine bundle still applies afterwards; nothing was poisoned.
	writeFile(t, ferry, bundleName(genuine), genuine)
	waitApplied(t, high, 1)
	waitContacts(t, high.Node(0), "ann=Ann:1", false)
	if names := listBundles(t, quarantine); len(names) != 2 {
		t.Fatalf("quarantine holds %d files after genuine apply, want 2", len(names))
	}
}

func TestRestartResumesWithoutRecaptureOrReapply(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-restart-low", schemaBase)
	defer func() { low.Finish(t.Failed()) }()
	high := newDomain(t, "highlow-restart-high", schemaBase)
	defer func() { high.Finish(t.Failed()) }()
	ferry, quarantine := t.TempDir(), t.TempDir()
	k := makeKeys(t, 9, 19)
	configureLow(t, low, k, "contacts")
	startSender(t, low, ferry)
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, quarantine)

	exec(t, low.Node(0), "INSERT INTO contacts VALUES('ann','Ann',1)")
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('bob','Bob',2)")
	waitPublished(t, low, 2)
	waitApplied(t, high, 2)
	before := listBundles(t, ferry)
	if len(before) != 2 {
		t.Fatalf("ferry holds %d files, want 2", len(before))
	}

	// A Low restart exports nothing new: the durable queue and baseline
	// marker resume instead of recapturing.
	if err := low.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureLow(t, low, k, "contacts")
	startSender(t, low, ferry)
	time.Sleep(1500 * time.Millisecond)
	if s := low.Node(0).BridgeSenderStatus(); s.Published != 0 {
		t.Fatalf("restarted Low published %d new artifacts, want 0: %+v", s.Published, s)
	}
	after := listBundles(t, ferry)
	if len(after) != len(before) {
		t.Fatalf("ferry file set changed across Low restart: %v -> %v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("ferry file set changed across Low restart: %v -> %v", before, after)
		}
	}

	// A High restart re-applies nothing: durable receipts turn redelivery
	// into duplicates.
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, quarantine)
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Duplicate >= 2
	}) {
		t.Fatalf("replay receipts lost across High restart: %+v", high.Node(0).BridgeReceiverStatus())
	}
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 || s.Rejected != 0 {
		t.Fatalf("restart reapplied or rejected committed bundles: %+v", s)
	}
	want := "ann=Ann:1|bob=Bob:2"
	if got := contacts(t, high.Node(0), false); got != want {
		t.Fatalf("high contacts = %q after restart, want %q", got, want)
	}

	// The restarted pair still transfers: one more write converges.
	exec(t, low.Node(0), "UPDATE contacts SET score=3 WHERE id='ann'")
	waitApplied(t, high, 1)
	waitContacts(t, high.Node(0), "ann=Ann:3|bob=Bob:2", false)
}

func TestSchemaHoldSurvivesRestartAndReleasesOnLocalMigration(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-schema-low", schemaEmail)
	defer func() { low.Finish(t.Failed()) }()
	high := newDomain(t, "highlow-schema-high", schemaBase)
	defer func() { high.Finish(t.Failed()) }()
	ferry, quarantine := t.TempDir(), t.TempDir()
	k := makeKeys(t, 11, 21)
	configureLow(t, low, k, "contacts")
	startSender(t, low, ferry)
	configureHigh := func() {
		t.Helper()
		cfg := bridge.CaptureConfig{Role: bridge.High, Database: high.Group, Node: high.Node(0).ID, Stream: stream}
		if err := high.Node(0).ConfigureBridgeCapture(cfg, "contacts"); err != nil {
			t.Fatal(err)
		}
		startReceiver(t, high, low, k.secret, [][32]byte{k.signer}, ferry, quarantine)
	}
	configureHigh()

	exec(t, low.Node(0), "INSERT INTO contacts VALUES('ann','Ann',1,'ann@x')")
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('bob','Bob',2,'bob@x')")
	waitPublished(t, low, 2)

	// The unknown email column holds both bundles: High stays empty and
	// no DDL crosses the ferry.
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Deferred >= 1
	}) {
		t.Fatal("schema-mismatched bundles were not held")
	}
	time.Sleep(500 * time.Millisecond)
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 || s.Rejected != 0 {
		t.Fatalf("held bundles applied or rejected: %+v", s)
	}
	if got := contacts(t, high.Node(0), false); got != "" {
		t.Fatalf("high holds %q during schema hold, want empty", got)
	}
	cols, err := high.Node(0).Simple("SELECT name FROM pragma_table_info('contacts')")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if c[0] == "email" {
			t.Fatal("email column crossed the ferry without a local migration")
		}
	}

	// The hold survives a High restart.
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh()
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Deferred >= 1
	}) {
		t.Fatal("schema hold did not survive High restart")
	}
	time.Sleep(500 * time.Millisecond)
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 {
		t.Fatalf("held bundles applied after restart without migration: %+v", s)
	}
	if got := contacts(t, high.Node(0), false); got != "" {
		t.Fatalf("high holds %q after restart, want empty", got)
	}

	// A local ADD COLUMN migration releases the held bundles.
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	if err := high.Node(0).ExecBatch("ALTER TABLE contacts ADD COLUMN email TEXT"); err != nil {
		t.Fatal(err)
	}
	configureHigh()
	waitApplied(t, high, 2)
	waitContacts(t, high.Node(0), "ann=Ann:1:ann@x|bob=Bob:2:bob@x", true)
}

func TestSignerRotationAndOutageCatchUp(t *testing.T) {
	goharness.SkipUnlessLive(t)
	low := newDomain(t, "highlow-rotate-low", schemaBase)
	defer func() { low.Finish(t.Failed()) }()
	high := newDomain(t, "highlow-rotate-high", schemaBase)
	defer func() { high.Finish(t.Failed()) }()
	spool, ferry, quarantine := t.TempDir(), t.TempDir(), t.TempDir()
	a := makeKeys(t, 13, 23)
	b := makeKeys(t, 14, 23) // rotation keeps the recipient secret, swaps the signer
	configureLow(t, low, a, "contacts")
	startSender(t, low, spool)
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, a.secret, [][32]byte{a.signer}, ferry, quarantine)
	deliver := func() {
		t.Helper()
		for _, name := range listBundles(t, spool) {
			if _, err := os.Stat(filepath.Join(ferry, name)); err != nil {
				writeFile(t, ferry, name, readBundle(t, spool, name))
			}
		}
	}

	// Round 1 imports under the predecessor key.
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('ann','Ann',1)")
	waitPublished(t, low, 1)
	deliver()
	waitApplied(t, high, 1)

	// Both sides rotate; round 2 imports on top during key overlap.
	if err := low.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureLow(t, low, b, "contacts")
	startSender(t, low, spool)
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, b.secret, [][32]byte{a.signer, b.signer}, ferry, quarantine)
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('bob','Bob',2)")
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return low.Node(0).BridgeSenderStatus().Published == 1
	}) {
		t.Fatalf("rotated Low did not publish round 2: %+v", low.Node(0).BridgeSenderStatus())
	}
	deliver()
	waitApplied(t, high, 1)
	waitContacts(t, high.Node(0), "ann=Ann:1|bob=Bob:2", false)

	// Full rotation: High trusts only the new key now.
	if err := high.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureHigh(t, high, "contacts")
	startReceiver(t, high, low, b.secret, [][32]byte{b.signer}, ferry, quarantine)

	// A retired-signer replay of committed bytes stages as a duplicate:
	// receipts, not trust, decide replays. Nothing changes, nothing is
	// quarantined.
	dups := high.Node(0).BridgeReceiverStatus().Duplicate
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Duplicate > dups
	}) {
		t.Fatal("committed bundles were not recognized as duplicates")
	}
	time.Sleep(300 * time.Millisecond)
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 || s.Rejected != 0 {
		t.Fatalf("replay moved applied/rejected: %+v", s)
	}
	if names := listBundles(t, quarantine); len(names) != 0 {
		t.Fatalf("replay quarantined %d files, want 0", len(names))
	}

	// Fresh bytes under the retired signer are quarantined instead.
	var txn [16]byte
	if _, err := rand.Read(txn[:]); err != nil {
		t.Fatal(err)
	}
	retired, err := bridge.Seal(bridge.Header{Database: low.Group, Node: low.Node(0).ID,
		Transaction: txn, Sequence: 99, Stream: stream}, a.seed, a.recipient, []byte("retired"))
	if err != nil {
		t.Fatal(err)
	}
	retiredName := bundleName(retired)
	writeFile(t, ferry, retiredName, retired)
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Rejected >= 1
	}) {
		t.Fatal("retired-signer bundle was not rejected")
	}
	if names := listBundles(t, quarantine); len(names) != 1 {
		t.Fatalf("quarantine holds %d files %v, want 1", len(names), names)
	}
	// Evict the retired bundle: every revisit would re-reject it (counters
	// count attempts), drowning the exact assertions below. The quarantine
	// copy remains as evidence.
	if err := os.Remove(filepath.Join(ferry, retiredName)); err != nil {
		t.Fatal(err)
	}
	if got := contacts(t, high.Node(0), false); got != "ann=Ann:1|bob=Bob:2" {
		t.Fatalf("high contacts = %q after retired-signer bundle, want unchanged", got)
	}

	// A current-key duplicate of committed bytes stages cleanly too.
	st := high.Node(0).BridgeReceiverStatus()
	dups, rejected := st.Duplicate, st.Rejected
	bySeq := seqMap(t, spool)
	writeFile(t, ferry, bySeq[2], readBundle(t, spool, bySeq[2]))
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Duplicate > dups
	}) {
		t.Fatal("current-key duplicate was not recognized")
	}
	time.Sleep(300 * time.Millisecond)
	if s := high.Node(0).BridgeReceiverStatus(); s.Applied != 0 || s.Rejected != rejected {
		t.Fatalf("current-key duplicate moved applied/rejected: %+v", s)
	}
	if names := listBundles(t, quarantine); len(names) != 1 {
		t.Fatalf("quarantine holds %d files, want 1", len(names))
	}

	// Outage: with the sender down, five events queue durably in Low's
	// outbox across a Low restart, then catch up exactly.
	if err := low.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureLow(t, low, b, "contacts")
	spoolBefore := listBundles(t, spool)
	exec(t, low.Node(0), "INSERT INTO contacts VALUES('backlog','Backlog',0)")
	for _, score := range []int{1, 2, 3, 4} {
		exec(t, low.Node(0), "UPDATE contacts SET score=? WHERE id='backlog'", score)
	}
	if names := listBundles(t, spool); len(names) != len(spoolBefore) {
		t.Fatal("bundles published during the sender outage")
	}
	if err := low.ReopenNode(0); err != nil {
		t.Fatal(err)
	}
	configureLow(t, low, b, "contacts")
	startSender(t, low, spool)
	waitPublished(t, low, 5)
	deliver()
	if !goharness.WaitUntil(waitTimeout, waitPoll, func() bool {
		return high.Node(0).BridgeReceiverStatus().Applied == 5
	}) {
		t.Fatalf("outage backlog did not catch up: %+v", high.Node(0).BridgeReceiverStatus())
	}
	waitContacts(t, high.Node(0), "ann=Ann:1|backlog=Backlog:4|bob=Bob:2", false)
}

func TestHighOwnedFieldReorderConvergesAcrossPeers(t *testing.T) {
	goharness.SkipUnlessLive(t)
	highlowpeer.RunSignedHighLowCluster(t, "highlow-native-reorder")
}
