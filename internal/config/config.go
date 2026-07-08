// Package config loads and validates the gremlind YAML configuration shared by
// the server (concentrator) and client (dialer) roles.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"gremlind/internal/control"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a Go duration string
// (e.g. "15s") in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Auth configures peer authentication for the control channel.
type Auth struct {
	// PSK is the global pre-shared key used when no per-client secret matches.
	PSK string `yaml:"psk"`
	// Clients maps a client ID to its individual secret (takes precedence over PSK).
	Clients map[string]string `yaml:"clients"`
}

// Hooks are optional scripts run on interface up/down (pppd-style ip-up/ip-down).
type Hooks struct {
	Up   string `yaml:"up"`
	Down string `yaml:"down"`
}

// Config is the on-disk configuration. It is IPv6-native: address-family fields
// accept both v6 (default) and v4 values.
type Config struct {
	// Listen is the control-channel bind address, e.g. "[::]:4747".
	Listen string `yaml:"listen"`
	// GRELocal is the server's outer GRE endpoint address (v6 default).
	GRELocal string `yaml:"gre_local"`
	// InnerPool is the CIDR from which inner tunnel addresses are assigned.
	InnerPool string `yaml:"inner_pool"`
	// ServerInner is the server's own inner address (must fall within InnerPool).
	ServerInner string `yaml:"server_inner"`
	// MTU is a hard upper bound on the negotiated tunnel MTU; 0 means "auto".
	MTU int `yaml:"mtu"`
	// GREKey controls whether tunnels use GRE key fields for demux. nil defaults
	// to enabled; false creates plain GRE tunnels without keys.
	GREKey *bool `yaml:"gre_key"`
	// GRESeq controls whether tunnels use GRE sequence-number fields. nil defaults
	// to disabled; both peers use the server's negotiated value.
	GRESeq *bool `yaml:"gre_seq"`
	// AdminSocket is the unix socket path for `gremlind status`; "" disables it.
	AdminSocket string `yaml:"admin_socket"`
	// AdminSocketMode is the socket permission bits, e.g. "0600" or "0660".
	AdminSocketMode string `yaml:"admin_socket_mode"`
	// AdminSocketGroup optionally sets the socket group for shared read access.
	AdminSocketGroup string `yaml:"admin_socket_group"`
	// NetlinkSocket, when set, makes the server ask a local privileged netlinkd
	// broker to provision GRE interfaces instead of opening rtnetlink itself.
	NetlinkSocket string `yaml:"netlink_socket"`
	// MaxPendingHandshakes bounds concurrent unauthenticated handshakes (server
	// role); 0 uses a built-in default. It caps the resources an unauthenticated
	// connection flood can pin.
	MaxPendingHandshakes int `yaml:"max_pending_handshakes"`
	// MaxPendingPerIP bounds concurrent unauthenticated handshakes from a single
	// source IP; 0 uses a built-in default. It stops one source from filling the
	// global pending pool and locking out other clients.
	MaxPendingPerIP int `yaml:"max_pending_per_ip"`

	// DecoyRedirect, when set, makes the HTTP decoy answer non-control probes with
	// a permanent (301) redirect to this location instead of the nginx 404. Use an
	// absolute URL (e.g. "https://example.com/") to avoid a redirect loop.
	DecoyRedirect string `yaml:"decoy_redirect"`
	// GremlinMustHide disables the /imagremlind teapot easter egg so every probe
	// gets the plain decoy (404 or the configured redirect) with no tells.
	GremlinMustHide bool `yaml:"gremlinmusthide"`

	KeepaliveInterval Duration `yaml:"keepalive_interval"`
	KeepaliveTimeout  Duration `yaml:"keepalive_timeout"`
	LeaseTTL          Duration `yaml:"lease_ttl"`

	Auth  Auth  `yaml:"auth"`
	Hooks Hooks `yaml:"hooks"`

	// Client holds dialer-role settings (used by `gremlind connect`).
	Client Client `yaml:"client"`
}

// Client configures the dialer role.
type Client struct {
	// ID identifies this client to the server (matched against auth.clients).
	ID string `yaml:"id"`
	// Secret is the shared secret; falls back to auth.psk when empty.
	Secret string `yaml:"secret"`
	// Iface names the local GRE tunnel interface. Defaults to "grem0"; set
	// this explicitly when a host runs more than one connect instance at
	// once (each needs its own interface name — see -iface / DefaultIface).
	Iface string `yaml:"iface"`
}

// DefaultListen is used when Listen is empty. It is v6-native/dual-stack.
const DefaultListen = "[::]:4747"

// DefaultIface is used when Client.Iface is empty.
const DefaultIface = "grem0"

const MinSecretLen = 32

// Load reads and validates the config at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.ApplyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ApplyDefaults fills in unset fields with their defaults. It is idempotent and
// safe to call on a config that was built without going through Load (e.g. the
// dialer's config-less path), so the keepalive durations are never left zero —
// a zero interval would panic time.NewTicker.
func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.KeepaliveInterval == 0 {
		c.KeepaliveInterval = Duration(15 * time.Second)
	}
	if c.KeepaliveTimeout == 0 {
		c.KeepaliveTimeout = Duration(45 * time.Second)
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = Duration(24 * time.Hour)
	}
	if c.AdminSocketMode == "" {
		c.AdminSocketMode = "0600"
	}
	if c.Client.Iface == "" {
		c.Client.Iface = DefaultIface
	}
}

// GREKeyEnabled reports whether GRE key fields should be used.
func (c *Config) GREKeyEnabled() bool { return c.GREKey == nil || *c.GREKey }

// GRESeqEnabled reports whether GRE sequence-number fields should be used.
func (c *Config) GRESeqEnabled() bool { return c.GRESeq != nil && *c.GRESeq }

// validate performs role-agnostic checks. Fields only required by the server
// role (pool, gre_local) are validated when present; the server startup path
// additionally calls ValidateServer.
func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("invalid listen %q: %w", c.Listen, err)
	}
	if c.MTU < 0 {
		return fmt.Errorf("mtu must be >= 0, got %d", c.MTU)
	}
	if c.MaxPendingHandshakes < 0 {
		return fmt.Errorf("max_pending_handshakes must be >= 0, got %d", c.MaxPendingHandshakes)
	}
	if c.MaxPendingPerIP < 0 {
		return fmt.Errorf("max_pending_per_ip must be >= 0, got %d", c.MaxPendingPerIP)
	}
	if c.KeepaliveInterval.Std() <= 0 {
		return fmt.Errorf("keepalive_interval must be positive, got %s", c.KeepaliveInterval.Std())
	}
	if c.KeepaliveTimeout.Std() <= 0 {
		return fmt.Errorf("keepalive_timeout must be positive, got %s", c.KeepaliveTimeout.Std())
	}
	if c.KeepaliveTimeout.Std() <= c.KeepaliveInterval.Std() {
		return fmt.Errorf("keepalive_timeout (%s) must exceed keepalive_interval (%s)",
			c.KeepaliveTimeout.Std(), c.KeepaliveInterval.Std())
	}
	if c.LeaseTTL.Std() < 0 {
		return fmt.Errorf("lease_ttl must be >= 0, got %s", c.LeaseTTL.Std())
	}
	if _, err := c.AdminMode(); err != nil {
		return err
	}
	if c.InnerPool != "" {
		if _, err := netip.ParsePrefix(c.InnerPool); err != nil {
			return fmt.Errorf("invalid inner_pool %q: %w", c.InnerPool, err)
		}
	}
	if c.GRELocal != "" {
		if _, err := netip.ParseAddr(c.GRELocal); err != nil {
			return fmt.Errorf("invalid gre_local %q: %w", c.GRELocal, err)
		}
	}
	return nil
}

// AdminMode parses AdminSocketMode as octal permission bits.
func (c *Config) AdminMode() (os.FileMode, error) {
	mode, err := strconv.ParseUint(c.AdminSocketMode, 8, 32)
	if err != nil || mode > 0o777 {
		if err == nil {
			err = fmt.Errorf("mode exceeds 0777")
		}
		return 0, fmt.Errorf("invalid admin_socket_mode %q: %w", c.AdminSocketMode, err)
	}
	return os.FileMode(mode), nil
}

// ValidateServer checks fields that the server role additionally requires.
func (c *Config) ValidateServer() error {
	if c.GRELocal == "" {
		return fmt.Errorf("gre_local is required in server mode")
	}
	if c.InnerPool == "" {
		return fmt.Errorf("inner_pool is required in server mode")
	}
	pool, err := netip.ParsePrefix(c.InnerPool)
	if err != nil {
		return fmt.Errorf("invalid inner_pool: %w", err)
	}
	if c.ServerInner == "" {
		return fmt.Errorf("server_inner is required in server mode")
	}
	inner, err := netip.ParseAddr(c.ServerInner)
	if err != nil {
		return fmt.Errorf("invalid server_inner: %w", err)
	}
	if !pool.Contains(inner) {
		return fmt.Errorf("server_inner %s is not within inner_pool %s", inner, pool)
	}
	if c.Auth.PSK == "" && len(c.Auth.Clients) == 0 {
		return fmt.Errorf("auth: at least a psk or per-client secrets are required")
	}
	if c.Auth.PSK != "" && len(c.Auth.PSK) < MinSecretLen {
		return fmt.Errorf("auth: psk must be at least %d bytes", MinSecretLen)
	}
	for id, secret := range c.Auth.Clients {
		if !control.ValidClientID(id) {
			return fmt.Errorf("auth: invalid client id %q (allowed: A-Z a-z 0-9 . _ -, length 1..64)", id)
		}
		if len(secret) < MinSecretLen {
			return fmt.Errorf("auth: secret for client %q must be at least %d bytes", id, MinSecretLen)
		}
	}
	return nil
}
