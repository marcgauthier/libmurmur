package goharness

import (
	"errors"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/bindings/bridge"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/files"
	"github.com/marcgauthier/libmurmur/clients/go/bindings/sqlite"
)

// ConfigureBridgeCapture opts an in-process node into native transactional
// capture for Execute. User tables must already exist. Workers are closed
// with the node; configure again after a node is reopened.
func (n *Node) ConfigureBridgeCapture(cfg bridge.CaptureConfig, tables ...string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil || n.bridgeCapture {
		return errors.New("bridge capture requires an open unconfigured in-process node")
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	for _, name := range tables {
		if _, err := bridge.RegisterTable(n.conn, name); err != nil {
			return err
		}
	}
	if err := bridge.AttachCapture(n.conn, cfg); err != nil {
		return err
	}
	n.bridgeCapture = true
	return nil
}

func (n *Node) StartBridgeSender(source [16]byte, stream, directory string, baseline bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil || n.bridgeSender != nil {
		return errors.New("bridge sender requires an open in-process node without a sender")
	}
	sender, err := bridge.NewSender(n.conn, source, stream, directory, baseline)
	if err != nil {
		return err
	}
	if n.files {
		if err = sender.Files(files.Handle(n.native.NativeDriver())); err != nil {
			sender.Close()
			return err
		}
	}
	if err = sender.Start(10 * time.Millisecond); err != nil {
		sender.Close()
		return err
	}
	n.bridgeSender = sender
	return nil
}

func (n *Node) StartBridgeReceiver(cfg bridge.ReceiverConfig) error {
	return n.configureBridgeReceiver(cfg, true)
}

// ConfigureBridgeReceiverSource loads trusted source keys without scanning a
// directory. Signed source bundles can arrive only through native peer sync.
func (n *Node) ConfigureBridgeReceiverSource(cfg bridge.ReceiverConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil {
		return errors.New("bridge source requires an open in-process node")
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	return bridge.ConfigurePeerSource(n.conn, cfg)
}

func (n *Node) configureBridgeReceiver(cfg bridge.ReceiverConfig, start bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil || n.bridgeReceivers[string(cfg.Source[:])+"\x00"+cfg.Stream] != nil {
		return errors.New("bridge receiver requires an open in-process node without a receiver")
	}
	receiver, err := bridge.NewReceiver(n.conn, cfg)
	if err != nil {
		return err
	}
	if n.files {
		if err = receiver.Files(files.Handle(n.native.NativeDriver())); err != nil {
			receiver.Close()
			return err
		}
	}
	if start {
		if err = receiver.Start(10 * time.Millisecond); err != nil {
			receiver.Close()
			return err
		}
	}

	if n.bridgeReceivers == nil {
		n.bridgeReceivers = make(map[string]*bridge.Receiver)
	}
	n.bridgeReceivers[string(cfg.Source[:])+"\x00"+cfg.Stream] = receiver
	return nil
}

func (n *Node) BridgeSenderStatus() bridge.SenderStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bridgeSender == nil {
		return bridge.SenderStatus{}
	}
	return n.bridgeSender.Status()
}
func (n *Node) BridgeReceiverStatus() bridge.FerryStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out bridge.FerryStatus
	for _, receiver := range n.bridgeReceivers {
		s := receiver.Status()
		out.FilesCompleted += s.FilesCompleted
		out.Scanned += s.Scanned
		out.Applied += s.Applied
		out.Duplicate += s.Duplicate
		out.Deferred += s.Deferred
		out.Rejected += s.Rejected
		if s.LastResult != 0 {
			out.LastResult = s.LastResult
		}
	}
	return out
}
func (n *Node) BridgeReceiverStatusFor(source [16]byte, stream string) bridge.FerryStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	receiver := n.bridgeReceivers[string(source[:])+"\x00"+stream]
	if receiver == nil {
		return bridge.FerryStatus{}
	}
	return receiver.Status()
}
func (n *Node) ReleaseBridgeOwnership(table string, key []any, column *string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil {
		return false, errors.New("bridge release requires an open in-process node")
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	return bridge.ReleaseOwnership(n.conn, table, key, column)
}

// ConfigureBridgePeer enables the native signed High-ownership journal.
func (n *Node) ConfigureBridgePeer(database [16]byte, seed [32]byte, trust map[[16]byte][32]byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil {
		return errors.New("bridge peer requires an open in-process node")
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	if err := bridge.ConfigurePeer(n.conn, database, n.ID, seed); err != nil {
		return err
	}
	if n.files {
		if err := bridge.PeerFiles(n.conn, files.Handle(n.native.NativeDriver())); err != nil {
			return err
		}
	}
	for node, key := range trust {
		if err := bridge.TrustPeer(n.conn, node, key, true); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) ConfigureLowBridgePeer(database [16]byte, seed [32]byte, exporter [16]byte, trust map[[16]byte][32]byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil {
		return errors.New("Low bridge peer requires an open in-process node")
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	if err := bridge.ConfigureLowPeer(n.conn, database, n.ID, seed, exporter); err != nil {
		return err
	}
	for node, key := range trust {
		if err := bridge.TrustPeer(n.conn, node, key, true); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) TrustBridgeSourceOrigin(database, origin [16]byte, key [32]byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.child != nil || n.conn == nil {
		return errors.New("source origin requires an open in-process node")
	}
	sqlite.LockWriter()
	defer sqlite.UnlockWriter()
	return bridge.TrustSourceOrigin(n.conn, database, origin, key, true)
}
