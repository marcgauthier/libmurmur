// Origin enforcement provisioning: seeds, pubkeys, trust pins.
package goharness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// GenerateOriginSeeds returns n random 32-byte origin seeds.
func GenerateOriginSeeds(n int) ([][]byte, error) {
	out := make([][]byte, n)
	for i := range out {
		out[i] = make([]byte, 32)
		if _, err := rand.Read(out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// OriginPubHex derives the Ed25519 public key hex for a seed.
func OriginPubHex(seed []byte) (string, error) {
	if len(seed) != 32 {
		return "", fmt.Errorf("origin seed must be exactly 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey)), nil
}

// SetOrigins writes an explicit trusted_origins pin map
// (site-hex -> pubkey-hex) on the listed nodes (all when empty).
func (c *Cluster) SetOrigins(pins map[string]string, on ...int) error {
	raw, err := json.Marshal(pins)
	if err != nil {
		return err
	}
	targets := on
	if len(targets) == 0 {
		for i := range c.nodes {
			targets = append(targets, i)
		}
	}
	for _, i := range targets {
		if i < 0 || i >= len(c.nodes) {
			return fmt.Errorf("node %d out of range", i)
		}
		if err := c.nodes[i].SetSetting("trusted_origins", string(raw)); err != nil {
			return fmt.Errorf("node %d trust: %w", i, err)
		}
	}
	return nil
}

// EnforceOrigins pins every node's live site id to its seed pubkey
// on every node, turning on origin enforcement cluster-wide.
// seeds[i] must be node i's 32-byte origin seed.
func (c *Cluster) EnforceOrigins(seeds [][]byte) error {
	if len(seeds) != len(c.nodes) {
		return fmt.Errorf("need %d seeds, got %d", len(c.nodes), len(seeds))
	}
	pins := map[string]string{}
	for i, n := range c.nodes {
		site, err := n.SiteHex()
		if err != nil {
			return fmt.Errorf("node %d site: %w", i, err)
		}
		pub, err := OriginPubHex(seeds[i])
		if err != nil {
			return fmt.Errorf("node %d pub: %w", i, err)
		}
		pins[site] = pub
	}
	return c.SetOrigins(pins)
}
