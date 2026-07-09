package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestApplyDefaultsNonZeroKeepalive guards the dialer's config-less path: an
// empty Config must come out with positive keepalive durations, since a zero
// interval would panic time.NewTicker in the keepalive loop.
func TestApplyDefaultsNonZeroKeepalive(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()

	if c.KeepaliveInterval.Std() <= 0 {
		t.Errorf("keepalive_interval = %s, want > 0", c.KeepaliveInterval.Std())
	}
	if c.KeepaliveTimeout.Std() <= 0 {
		t.Errorf("keepalive_timeout = %s, want > 0", c.KeepaliveTimeout.Std())
	}
	if c.KeepaliveTimeout.Std() <= c.KeepaliveInterval.Std() {
		t.Errorf("keepalive_timeout (%s) must exceed interval (%s)",
			c.KeepaliveTimeout.Std(), c.KeepaliveInterval.Std())
	}
}

// TestApplyDefaultsIdempotent makes sure ApplyDefaults never overrides values
// that were already set (e.g. by Load parsing a real config).
func TestGREKeyEnabledDefaultsToTrue(t *testing.T) {
	c := &Config{}
	if !c.GREKeyEnabled() {
		t.Fatal("GREKeyEnabled should default to true")
	}
	v := false
	c.GREKey = &v
	if c.GREKeyEnabled() {
		t.Fatal("GREKeyEnabled should honor explicit false")
	}
}

func TestGRESeqEnabledDefaultsToFalse(t *testing.T) {
	c := &Config{}
	if c.GRESeqEnabled() {
		t.Fatal("GRESeqEnabled should default to false")
	}
	v := true
	c.GRESeq = &v
	if !c.GRESeqEnabled() {
		t.Fatal("GRESeqEnabled should honor explicit true")
	}
}

func TestLoadDecoyOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gremlind.yaml")
	if err := os.WriteFile(path, []byte(`
listen: "[::1]:4747"
keepalive_interval: 15s
keepalive_timeout: 45s
decoy_redirect: "/"
gremlinmusthide: true
netlink_socket: "/run/gremlind-netlink.sock"
gre_seq: true
mss_clamp:
  enabled: true
  backend: "nftables"
  direction: "both"
  mss_mode: "tunnel_mtu"
  mss: 1360
  mss4: 1360
  mss6: 1340
  nft_family: "inet"
  nft_table: "gremlind"
  nft_chain: "forward"
healthcheck:
  enabled: true
  interval: 10s
  timeout: 1s
  failures: 2
  actions: ["log", "run_script", "reconnect"]
  script: "/run/current-system/sw/bin/true"
  target: "fd00:9::1"
  packet_size: 1200
  packet_sizes: [0, 1200, 1372]
  inter_packet_delay: 250ms
  large_packet_delay: 2s
  large_packet_threshold: 1200
  command: "ping"
  bind_interface: true
client:
  source_fallback: "kernel"
  source_rules:
    - family: "ipv6"
      match_server_subnets: ["2001:db8:feed::/48"]
      ifaces: ["ppp0", "wan0"]
      include_subnets: ["2001:db8:1234::/48"]
      exclude_subnets: ["fe80::/10", "10.0.0.0/8"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DecoyRedirect != "/" {
		t.Fatalf("decoy_redirect = %q, want /", c.DecoyRedirect)
	}
	if !c.GremlinMustHide {
		t.Fatal("gremlinmusthide = false, want true")
	}
	if c.NetlinkSocket != "/run/gremlind-netlink.sock" {
		t.Fatalf("netlink_socket = %q, want /run/gremlind-netlink.sock", c.NetlinkSocket)
	}
	if !c.GRESeqEnabled() {
		t.Fatal("gre_seq = false, want true")
	}
	if !c.MSSClamp.Enabled || c.MSSClamp.Backend != "nftables" || c.MSSClamp.Direction != "both" || c.MSSClamp.MSSMode != "tunnel_mtu" || c.MSSClamp.MSS != 1360 || c.MSSClamp.MSS4 != 1360 || c.MSSClamp.MSS6 != 1340 {
		t.Fatalf("mss_clamp = %+v", c.MSSClamp)
	}
	if !c.HealthCheck.Enabled || c.HealthCheck.Failures != 2 || len(c.HealthCheck.Actions) != 3 || c.HealthCheck.Actions[1] != "run_script" || c.HealthCheck.Script == "" || c.HealthCheck.Target != "fd00:9::1" || c.HealthCheck.PacketSize != 1200 || len(c.HealthCheck.PacketSizes) != 3 || c.HealthCheck.InterPacketDelay.Std() != 250*time.Millisecond || c.HealthCheck.LargePacketDelay.Std() != 2*time.Second || c.HealthCheck.LargePacketThreshold != 1200 || !c.HealthCheck.BindInterface {
		t.Fatalf("healthcheck = %+v", c.HealthCheck)
	}
	if len(c.Client.SourceRules) != 1 {
		t.Fatalf("source_rules len = %d, want 1", len(c.Client.SourceRules))
	}
	if c.Client.SourceFallback != "kernel" {
		t.Fatalf("source_fallback = %q, want kernel", c.Client.SourceFallback)
	}
	if got := c.Client.SourceRules[0].Ifaces; len(got) != 2 || got[0] != "ppp0" || got[1] != "wan0" {
		t.Fatalf("source rule ifaces = %#v, want ppp0/wan0", got)
	}
	if c.Client.SourceRules[0].Family != "ipv6" {
		t.Fatalf("source rule family = %q, want ipv6", c.Client.SourceRules[0].Family)
	}
	if got := c.Client.SourceRules[0].IncludeSubnets; len(got) != 1 || got[0] != "2001:db8:1234::/48" {
		t.Fatalf("source rule include_subnets = %#v", got)
	}
}

func TestInvalidSourceRuleExcludeSubnet(t *testing.T) {
	c := &Config{
		Listen: "[::1]:4747",
		Client: Client{SourceRules: []SourceRule{{ExcludeSubnets: []string{"not-a-cidr"}}}},
	}
	c.ApplyDefaults()
	if err := c.validate(); err == nil {
		t.Fatal("validate succeeded with invalid source exclude subnet")
	}
}

func TestInvalidHealthCheck(t *testing.T) {
	for name, hc := range map[string]HealthCheck{
		"interval":               {Enabled: true, Interval: Duration(-time.Second)},
		"timeout":                {Enabled: true, Timeout: Duration(-time.Second)},
		"failures":               {Enabled: true, Failures: -1},
		"actions":                {Enabled: true, Actions: []string{"panic"}},
		"script":                 {Enabled: true, Actions: []string{"run_script"}},
		"target":                 {Enabled: true, Target: "not-an-ip"},
		"packet_size":            {Enabled: true, PacketSize: -1},
		"packet_sizes":           {Enabled: true, PacketSizes: []int{0, 70000}},
		"inter_packet_delay":     {Enabled: true, InterPacketDelay: Duration(-time.Second)},
		"large_packet_delay":     {Enabled: true, LargePacketDelay: Duration(-time.Second)},
		"large_packet_threshold": {Enabled: true, LargePacketThreshold: -1},
		"command":                {Enabled: true, Command: ""},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Config{Listen: "[::1]:4747", HealthCheck: hc}
			if name != "command" {
				c.ApplyDefaults()
			}
			if err := c.validate(); err == nil {
				t.Fatal("validate succeeded, want error")
			}
		})
	}
}

func TestInvalidMSSClamp(t *testing.T) {
	for name, mss := range map[string]MSSClamp{
		"backend":   {Enabled: true, Backend: "pf"},
		"direction": {Enabled: true, Direction: "sideways"},
		"mss_mode":  {Enabled: true, MSSMode: "guess"},
		"mss":       {Enabled: true, MSS: -1},
		"mss4":      {Enabled: true, MSS4: -1},
		"mss6":      {Enabled: true, MSS6: 70000},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Config{Listen: "[::1]:4747", MSSClamp: mss}
			c.ApplyDefaults()
			if err := c.validate(); err == nil {
				t.Fatal("validate succeeded, want error")
			}
		})
	}
}

func TestInvalidSourceRuleFamilyAndFallback(t *testing.T) {
	for name, client := range map[string]Client{
		"family":   {SourceRules: []SourceRule{{Family: "ipx"}}},
		"fallback": {SourceFallback: "shrug"},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Config{Listen: "[::1]:4747", Client: client}
			c.ApplyDefaults()
			if err := c.validate(); err == nil {
				t.Fatal("validate succeeded, want error")
			}
		})
	}
}

func TestApplyDefaultsIdempotent(t *testing.T) {
	c := &Config{
		Listen:            "[2001:db8::1]:5000",
		KeepaliveInterval: Duration(5 * time.Second),
		KeepaliveTimeout:  Duration(20 * time.Second),
	}
	c.ApplyDefaults()

	if c.Listen != "[2001:db8::1]:5000" {
		t.Errorf("listen overwritten: %s", c.Listen)
	}
	if c.KeepaliveInterval.Std() != 5*time.Second {
		t.Errorf("keepalive_interval overwritten: %s", c.KeepaliveInterval.Std())
	}
	if c.KeepaliveTimeout.Std() != 20*time.Second {
		t.Errorf("keepalive_timeout overwritten: %s", c.KeepaliveTimeout.Std())
	}
}
