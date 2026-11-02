// Package replication implements the murmur group-replication layer:
// configuration, metadata schema, op application, membership, and the
// SQL/PRAGMA surface. Network transport plugs in behind the Transport
// interface; the core runs fully offline.
package replication

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/marcgauthier/libmurmur/clients/go/pkgs/tx"
)

// NodeID is the shared tx identity (group/node/site/transfer).
type NodeID = tx.NodeID

// ParseID parses a 32-hex-digit node id.
func ParseID(v string) (NodeID, error) {
	var out NodeID
	raw, err := hex.DecodeString(strings.ReplaceAll(v, "-", ""))
	if err != nil || len(raw) != 16 {
		return out, errInvalid(fmt.Sprintf("invalid node id %q", v))
	}
	copy(out[:], raw)
	if out == (NodeID{}) {
		return out, errInvalid(fmt.Sprintf("zero node id %q", v))
	}
	return out, nil
}

// validDNSName reports dot-separated labels of letters, digits,
// hyphens, and underscores; labels never start or end with a hyphen.
func validDNSName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

// checkSocketOrName validates host:port where the host is an IP literal
// or DNS name. It never resolves.
func checkSocketOrName(value string) error {
	if _, err := net.ResolveTCPAddr("tcp", value); err == nil {
		if _, _, err := net.SplitHostPort(value); err == nil {
			return nil
		}
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || !validDNSName(host) {
		return fmt.Errorf("invalid host %q", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// Credential material for the TLS endpoint.
type Credentials struct {
	Chain      [][]byte
	PrivateKey []byte
	Roots      [][]byte
}

// Config is the loaded replication configuration.
type Config struct {
	Group           NodeID
	Node            NodeID
	Site            NodeID
	Bind            *net.TCPAddr
	Advertise       *net.TCPAddr
	Creds           Credentials
	AllowedPeers    map[NodeID]bool
	AllowedNetworks []*net.IPNet
	Bootstrap       []*net.TCPAddr
	Excluded        map[NodeID]bool
	Incarnation     uint64
	Sessions        int
	QueueBytes      int
	BatchBytes      int
	MaxBatchBytes   int
	StagingBytes    int
	StagingTimeout  time.Duration
	PollInterval    time.Duration
	AntiEntropy     time.Duration
	GossipFanout    int
}

// Defaults for every murmur_* setting (stripped names; the PRAGMA
// handler adds the prefix). Query-plane and deprecated-inert keys are
// included so reads behave identically with no engine running.
var defaults = map[string]string{
	"group_id": "", "advertise": "", "certificate": "", "private_key": "",
	"ca": "", "crl_file": "", "crsqlite_extension": "",
	"origin_key_file": "", "trusted_origins": "",
	"bind":                             "0.0.0.0:7443",
	"bootstrap":                        "[]",
	"allowed_peers":                    "[]",
	"allowed_networks":                 "[]",
	"poll_ms":                          "100",
	"anti_entropy_ms":                  "10000",
	"gossip_fanout":                    "3",
	"sessions":                         "32",
	"batch_bytes":                      "1048576",
	"max_batch_bytes":                  "67108864",
	"queue_bytes":                      "67108864",
	"staging_bytes":                    "268435456",
	"staging_timeout_ms":               "300000",
	"writer_local_share":               "90",
	"writer_remote_share":              "10",
	"writer_max_debt_ms":               "1000",
	"writer_maintenance_reserve_every": "100",
	"retention_min_kept":               "1000",
	"retention_max_offline_ms":         "604800000",
	"retention_gc":                     "1",
	"table_replication":                "{}",
	"column_policies":                  "{}",
	"snapshot_bytes":                   "536870912",
	"snapshot_staging_bytes":           "536870912",
	"snapshot_lifetime_ms":             "604800000",
	"snapshot_staging_transfers":       "4096",
	"snapshot_trusted_sources":         "[]",
	"accept_remote_schema":             "1",
	"schema_master":                    "",
	"schema_master_enabled":            "0",
	"kdf":                              "direct",
	"kdf_time":                         "3",
	"kdf_memory_kib":                   "65536",
	"kdf_threads":                      "4",
	"bridge_dir":                       "",
	"files_generation":                 "0",
	"max_file_bytes":                   "4294967296",
	"max_staging_bytes":                "1073741824",
	"fetch_concurrency":                "2",
	"fetch_interval_ms":                "30000",
	"fetch_bind":                       "",
	"bridge_role":                      "",
	"bridge_stream":                    "",
	"bridge_max_bundle_bytes":          "16777216",
	"bridge_max_payload_bytes":         "67108864",
	"bridge_staging_bytes":             "1073741824",
	"files_dir":                        "",
}

// DefaultValue reports the default for a stripped setting name.
func DefaultValue(name string) (string, bool) {
	v, ok := defaults[name]
	return v, ok
}

// Validate checks one setting value. Unknown names, NUL bytes, and
// oversized values fail.
func Validate(name, value string) error {
	if _, ok := defaults[name]; !ok {
		return fmt.Errorf("unknown PRAGMA murmur_%s", name)
	}
	if len(value) > 65536 || strings.ContainsRune(value, 0) {
		return errors.New("setting too large or contains NUL")
	}
	parseUint := func(what string) (uint64, error) {
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("expected %s", what)
		}
		return n, nil
	}
	switch name {
	case "group_id":
		_, err := ParseID(value)
		return err
	case "bind":
		addr, err := net.ResolveTCPAddr("tcp", value)
		if err != nil || addr.IP == nil {
			return errors.New("expected IP:port")
		}
		return nil
	case "advertise":
		if value == "" {
			return nil
		}
		return checkSocketOrName(value)
	case "bootstrap":
		var v []string
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return err
		}
		if len(v) > 4096 {
			return errors.New("too many bootstrap entries")
		}
		for _, entry := range v {
			if err := checkSocketOrName(entry); err != nil {
				return err
			}
		}
		return nil
	case "gossip_fanout":
		n, err := parseUint("fanout 1..32")
		if err != nil || n < 1 || n > 32 {
			return errors.New("gossip_fanout outside 1..32")
		}
		return nil
	case "allowed_peers":
		var v []string
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return err
		}
		if len(v) > 4096 {
			return errors.New("too many peers")
		}
		for _, s := range v {
			if _, err := ParseID(s); err != nil {
				return err
			}
		}
		return nil
	case "allowed_networks":
		var v []string
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return err
		}
		if len(v) > 4096 {
			return errors.New("too many networks")
		}
		for _, s := range v {
			if _, _, err := net.ParseCIDR(s); err != nil {
				return fmt.Errorf("invalid network %q", s)
			}
		}
		return nil
	case "poll_ms", "anti_entropy_ms", "staging_timeout_ms":
		minimum := uint64(10)
		if name == "staging_timeout_ms" {
			minimum = 60000
		}
		n, err := parseUint("milliseconds")
		if err != nil || n < minimum || n > 86400000 {
			return fmt.Errorf("interval outside %d..86400000 ms", minimum)
		}
		return nil
	case "sessions":
		n, err := parseUint("session count")
		if err != nil || n < 1 || n > 256 {
			return errors.New("sessions outside 1..256")
		}
		return nil
	case "batch_bytes", "max_batch_bytes", "queue_bytes", "staging_bytes":
		n, err := parseUint("byte count")
		if err != nil || n < 65536 || n > 1073741824 {
			return errors.New("byte budget outside 64 KiB..1 GiB")
		}
		return nil
	case "writer_local_share":
		n, err := parseUint("local share 1..99")
		if err != nil || n < 1 || n > 99 {
			return errors.New("writer_local_share outside 1..99")
		}
		return nil
	case "writer_max_debt_ms":
		n, err := parseUint("max debt 1..60000 ms")
		if err != nil || n < 1 || n > 60000 {
			return errors.New("writer_max_debt_ms outside 1..60000")
		}
		return nil
	case "writer_maintenance_reserve_every":
		n, err := parseUint("maintenance reserve 1..1000000")
		if err != nil || n < 1 || n > 1000000 {
			return errors.New("writer_maintenance_reserve_every outside 1..1000000")
		}
		return nil
	case "writer_remote_share":
		return errors.New("writer_remote_share is derived from writer_local_share; assign that instead")
	case "retention_min_kept":
		n, err := parseUint("versions to keep 1..1000000")
		if err != nil || n < 1 || n > 1000000 {
			return errors.New("retention_min_kept outside 1..1000000")
		}
		return nil
	case "retention_max_offline_ms":
		n, err := parseUint("offline window 60000..2592000000 ms")
		if err != nil || n < 60000 || n > 2592000000 {
			return errors.New("retention_max_offline_ms outside 60000..2592000000")
		}
		return nil
	case "table_replication":
		var v map[string]bool
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return fmt.Errorf("table_replication map: %v", err)
		}
		if len(v) > 1024 {
			return errors.New("table_replication map too large")
		}
		for name := range v {
			if name == "" || len(name) > 128 {
				return errors.New("bad table name in table_replication")
			}
		}
		return nil
	case "column_policies":
		var v map[string]string
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return err
		}
		for key, policy := range v {
			parts := strings.Split(key, ".")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return fmt.Errorf("column_policies key must be table.column: %s", key)
			}
			switch policy {
			case "Lww", "Counter", "Set", "Min", "Max":
			default:
				return fmt.Errorf("unknown merge policy (want Lww/Counter/Set/Min/Max): %s", policy)
			}
		}
		return nil
	case "snapshot_bytes", "snapshot_staging_bytes":
		n, err := parseUint("byte count")
		if err != nil || n < 65536 || n > 1<<40 {
			return errors.New("snapshot budget outside 64 KiB..1 TiB")
		}
		return nil
	case "snapshot_lifetime_ms":
		n, err := parseUint("milliseconds")
		if err != nil || n < 3600000 || n > 2592000000 {
			return errors.New("snapshot_lifetime_ms outside 3600000..2592000000")
		}
		return nil
	case "snapshot_staging_transfers":
		n, err := parseUint("transfer count")
		if err != nil || n < 1 || n > 65536 {
			return errors.New("snapshot_staging_transfers outside 1..65536")
		}
		return nil
	case "accept_remote_schema", "schema_master_enabled", "retention_gc":
		if value != "0" && value != "1" {
			return fmt.Errorf("%s must be 0 or 1", name)
		}
		return nil
	case "schema_master":
		if value == "" {
			return nil
		}
		_, err := ParseID(value)
		return err
	case "kdf":
		if value != "direct" && value != "argon2id" {
			return errors.New("kdf must be direct or argon2id")
		}
		return nil
	case "kdf_time":
		n, err := parseUint("kdf time 1..32")
		if err != nil || n < 1 || n > 32 {
			return errors.New("kdf_time outside 1..32")
		}
		return nil
	case "kdf_memory_kib":
		n, err := parseUint("kdf memory 1024..16777216 KiB")
		if err != nil || n < 1024 || n > 16777216 {
			return errors.New("kdf_memory_kib outside 1024..16777216")
		}
		return nil
	case "kdf_threads":
		n, err := parseUint("kdf threads 1..32")
		if err != nil || n < 1 || n > 32 {
			return errors.New("kdf_threads outside 1..32")
		}
		return nil
	case "snapshot_trusted_sources":
		var v []string
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			return err
		}
		if len(v) > 4096 {
			return errors.New("too many sources")
		}
		for _, s := range v {
			if _, err := ParseID(s); err != nil {
				return err
			}
		}
		return nil
	case "files_dir":
		return nil
	case "origin_key_file":
		return nil
	case "trusted_origins":
		if value == "" {
			return nil
		}
		var m map[string]string
		if err := json.Unmarshal([]byte(value), &m); err != nil {
			return err
		}
		for ks, vs := range m {
			sb, err := hex.DecodeString(ks)
			if err != nil || len(sb) != 16 {
				return errors.New("trusted_origins keys must be 32-hex site ids")
			}
			pb, err := hex.DecodeString(vs)
			if err != nil || len(pb) != 32 {
				return errors.New("trusted_origins values must be 64-hex ed25519 pubkeys")
			}
		}
		return nil
	default:
		// Bridge/file knobs and certificates: presence-checked only.
		return nil
	}
}
