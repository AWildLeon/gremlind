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
	// FOUPort wraps the GRE tunnel in Foo-over-UDP on this port when set (0
	// disables it, plain GRE as before). Outer traffic then looks like
	// ordinary UDP, which passes through NAT/firewalls/ISPs that block raw
	// GRE (IP protocol 47) outright. Both peers must set the *same* port —
	// each listens on it (EnsureFOUReceive) and targets the peer's copy of
	// it as the encap destination port, so there's no separate negotiation.
	// Not currently supported together with NetlinkSocket (split-privilege
	// mode): registering the FOU receive port needs CAP_NET_ADMIN, which
	// only the netlinkd broker holds in that mode.
	FOUPort uint16 `yaml:"fou_port"`
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

	Auth        Auth        `yaml:"auth"`
	Hooks       Hooks       `yaml:"hooks"`
	MSSClamp    MSSClamp    `yaml:"mss_clamp"`
	HealthCheck HealthCheck `yaml:"healthcheck"`

	// Client holds dialer-role settings (used by `gremlind connect`).
	Client Client `yaml:"client"`
}

// HealthCheck verifies data-plane reachability through the tunnel.
type HealthCheck struct {
	Enabled              bool     `yaml:"enabled"`
	Interval             Duration `yaml:"interval"`
	Timeout              Duration `yaml:"timeout"`
	Failures             int      `yaml:"failures"`
	Actions              []string `yaml:"actions"`                // ordered: log | run_script | reconnect
	Script               string   `yaml:"script"`                 // used by run_script action
	Target               string   `yaml:"target"`                 // empty = negotiated inner peer
	PacketSize           int      `yaml:"packet_size"`            // ping payload bytes; 0 = ping default
	PacketSizes          []int    `yaml:"packet_sizes"`           // optional set of payload sizes to probe
	InterPacketDelay     Duration `yaml:"inter_packet_delay"`     // delay between packet-size probes
	LargePacketDelay     Duration `yaml:"large_packet_delay"`     // delay before probes >= threshold; 0 = inter_packet_delay
	LargePacketThreshold int      `yaml:"large_packet_threshold"` // payload bytes; 0 = any non-default size
	Command              string   `yaml:"command"`                // ping-compatible binary
	BindInterface        bool     `yaml:"bind_interface"`         // pass -I <iface>
}

func (h HealthCheck) WithDefaults() HealthCheck {
	if h.Interval == 0 {
		h.Interval = Duration(30 * time.Second)
	}
	if h.Timeout == 0 {
		h.Timeout = Duration(3 * time.Second)
	}
	if h.Failures == 0 {
		h.Failures = 3
	}
	if len(h.Actions) == 0 {
		h.Actions = []string{"log"}
	}
	if h.Command == "" {
		h.Command = "ping"
	}
	return h
}

func (c *Config) validateHealthCheck() error {
	h := c.HealthCheck
	if h.Interval.Std() <= 0 {
		return fmt.Errorf("healthcheck.interval must be positive, got %s", h.Interval.Std())
	}
	if h.Timeout.Std() <= 0 {
		return fmt.Errorf("healthcheck.timeout must be positive, got %s", h.Timeout.Std())
	}
	if h.Failures <= 0 {
		return fmt.Errorf("healthcheck.failures must be positive, got %d", h.Failures)
	}
	usesScript := false
	for i, action := range h.Actions {
		switch action {
		case "log", "run_script", "reconnect":
			if action == "run_script" {
				usesScript = true
			}
		default:
			return fmt.Errorf("healthcheck.actions[%d] must be \"log\", \"run_script\", or \"reconnect\", got %q", i, action)
		}
	}
	if usesScript && h.Script == "" {
		return fmt.Errorf("healthcheck.script is required when actions contains run_script")
	}
	if h.Target != "" {
		if _, err := netip.ParseAddr(h.Target); err != nil {
			return fmt.Errorf("invalid healthcheck.target %q: %w", h.Target, err)
		}
	}
	if h.PacketSize < 0 || h.PacketSize > 65507 {
		return fmt.Errorf("healthcheck.packet_size must be between 0 and 65507, got %d", h.PacketSize)
	}
	for i, size := range h.PacketSizes {
		if size < 0 || size > 65507 {
			return fmt.Errorf("healthcheck.packet_sizes[%d] must be between 0 and 65507, got %d", i, size)
		}
	}
	if h.InterPacketDelay.Std() < 0 {
		return fmt.Errorf("healthcheck.inter_packet_delay must be >= 0, got %s", h.InterPacketDelay.Std())
	}
	if h.LargePacketDelay.Std() < 0 {
		return fmt.Errorf("healthcheck.large_packet_delay must be >= 0, got %s", h.LargePacketDelay.Std())
	}
	if h.LargePacketThreshold < 0 || h.LargePacketThreshold > 65507 {
		return fmt.Errorf("healthcheck.large_packet_threshold must be between 0 and 65507, got %d", h.LargePacketThreshold)
	}
	if h.Command == "" {
		return fmt.Errorf("healthcheck.command must be non-empty")
	}
	return nil
}

// MSSClamp optionally installs/removes firewall rules that clamp TCP MSS for
// traffic entering/leaving gremlind tunnel interfaces.
type MSSClamp struct {
	Enabled        bool   `yaml:"enabled"`
	Backend        string `yaml:"backend"`   // nftables | iptables
	Direction      string `yaml:"direction"` // out | in | both
	MSSMode        string `yaml:"mss_mode"`  // pmtu | tunnel_mtu
	MSS            int    `yaml:"mss"`       // 0 = mode default, >0 = fixed MSS for both families
	MSS4           int    `yaml:"mss4"`      // overrides mss/mode for IPv4 when >0
	MSS6           int    `yaml:"mss6"`      // overrides mss/mode for IPv6 when >0
	NFTFamily      string `yaml:"nft_family"`
	NFTTable       string `yaml:"nft_table"`
	NFTChain       string `yaml:"nft_chain"`
	NFTManageTable bool   `yaml:"nft_manage_table"`
	IPTablesChain  string `yaml:"iptables_chain"`
	Monitor        bool   `yaml:"monitor"` // nftables: watch ruleset changes and repair missing rules
}

func (m MSSClamp) WithDefaults() MSSClamp {
	if m.Backend == "" {
		m.Backend = "nftables"
	}
	if m.Direction == "" {
		m.Direction = "out"
	}
	if m.MSSMode == "" {
		m.MSSMode = "pmtu"
	}
	if m.NFTFamily == "" {
		m.NFTFamily = "inet"
	}
	if m.NFTTable == "" {
		m.NFTTable = "gremlind"
	}
	if m.NFTChain == "" {
		m.NFTChain = "forward"
	}
	if m.IPTablesChain == "" {
		m.IPTablesChain = "FORWARD"
	}
	return m
}

func (c *Config) validateMSSClamp() error {
	m := c.MSSClamp
	switch m.Backend {
	case "nftables", "iptables":
	default:
		return fmt.Errorf("mss_clamp.backend must be \"nftables\" or \"iptables\", got %q", m.Backend)
	}
	switch m.Direction {
	case "out", "in", "both":
	default:
		return fmt.Errorf("mss_clamp.direction must be \"out\", \"in\", or \"both\", got %q", m.Direction)
	}
	switch m.MSSMode {
	case "pmtu", "tunnel_mtu":
	default:
		return fmt.Errorf("mss_clamp.mss_mode must be \"pmtu\" or \"tunnel_mtu\", got %q", m.MSSMode)
	}
	for field, value := range map[string]int{"mss": m.MSS, "mss4": m.MSS4, "mss6": m.MSS6} {
		if value < 0 || value > 65535 {
			return fmt.Errorf("mss_clamp.%s must be between 0 and 65535, got %d", field, value)
		}
	}
	if m.Backend == "nftables" && (m.NFTFamily == "" || m.NFTTable == "" || m.NFTChain == "") {
		return fmt.Errorf("mss_clamp nft_family, nft_table and nft_chain must be non-empty")
	}
	if m.Backend == "iptables" && m.IPTablesChain == "" {
		return fmt.Errorf("mss_clamp.iptables_chain must be non-empty")
	}
	return nil
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
	// SourceRules constrain which local source address may be used for the
	// control connection, and therefore for the GRE outer endpoint advertised
	// to the server. The first rule that yields a usable address wins.
	SourceRules []SourceRule `yaml:"source_rules"`
	// SourceFallback controls what happens when SourceRules are configured but no
	// rule matches. "fail" is strict; "kernel" leaves source selection to the OS.
	SourceFallback string `yaml:"source_fallback"`
}

// SourceRule selects candidate local source addresses for the dialer.
type SourceRule struct {
	// Ifaces, when non-empty, restricts candidates to addresses configured on
	// these interface names. Empty means all up interfaces.
	Ifaces []string `yaml:"ifaces"`
	// Family optionally restricts candidate/source server families: "ipv4",
	// "ipv6", or "any"/"".
	Family string `yaml:"family"`
	// MatchServerSubnets makes the rule apply only when the configured server
	// resolves to at least one address in these CIDR prefixes.
	MatchServerSubnets []string `yaml:"match_server_subnets"`
	// IncludeSubnets, when non-empty, only allows candidates inside these CIDRs.
	IncludeSubnets []string `yaml:"include_subnets"`
	// ExcludeSubnets removes candidates contained in any listed CIDR prefix.
	ExcludeSubnets []string `yaml:"exclude_subnets"`
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
	if c.MSSClamp.Enabled && (c.MSSClamp.Backend == "" || c.MSSClamp.Backend == "nftables") && c.MSSClamp.NFTTable == "" && c.MSSClamp.NFTChain == "" {
		c.MSSClamp.NFTManageTable = true
	}
	c.MSSClamp = c.MSSClamp.WithDefaults()
	c.HealthCheck = c.HealthCheck.WithDefaults()
	if c.Client.SourceFallback == "" {
		c.Client.SourceFallback = "fail"
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
	if c.FOUPort != 0 && c.NetlinkSocket != "" {
		return fmt.Errorf("fou_port is not supported together with netlink_socket (split-privilege mode)")
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
	if c.MSSClamp.Enabled {
		if err := c.validateMSSClamp(); err != nil {
			return err
		}
	}
	if c.HealthCheck.Enabled {
		if err := c.validateHealthCheck(); err != nil {
			return err
		}
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
	switch c.Client.SourceFallback {
	case "", "fail", "kernel":
	default:
		return fmt.Errorf("client.source_fallback must be \"fail\" or \"kernel\", got %q", c.Client.SourceFallback)
	}
	for i, rule := range c.Client.SourceRules {
		switch rule.Family {
		case "", "any", "ipv4", "ipv6":
		default:
			return fmt.Errorf("client.source_rules[%d].family must be \"ipv4\", \"ipv6\", or \"any\", got %q", i, rule.Family)
		}
		for field, prefixes := range map[string][]string{
			"match_server_subnets": rule.MatchServerSubnets,
			"include_subnets":      rule.IncludeSubnets,
			"exclude_subnets":      rule.ExcludeSubnets,
		} {
			for _, prefix := range prefixes {
				if _, err := netip.ParsePrefix(prefix); err != nil {
					return fmt.Errorf("invalid client.source_rules[%d].%s prefix %q: %w", i, field, prefix, err)
				}
			}
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
