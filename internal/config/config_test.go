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

// validServerConfig returns a minimal Config that passes ValidateServer, so
// tests can toggle a single field and assert its validation in isolation.
func validServerConfig() *Config {
	c := &Config{
		GRELocal:    "2001:db8::10",
		InnerPool:   "fd00:9::/112",
		ServerInner: "fd00:9::1",
		Auth:        Auth{PSK: "0123456789abcdef0123456789abcdef"},
	}
	c.ApplyDefaults()
	return c
}

func TestValidateServerInterfaces(t *testing.T) {
	tests := []struct {
		name       string
		interfaces map[string]string
		wantErr    bool
	}{
		{"valid", map[string]string{"site-a": "gremlin-a", "site-b": "wg0"}, false},
		{"empty ok", nil, false},
		{"bad client id", map[string]string{"bad id": "gremlin-a"}, true},
		{"too long", map[string]string{"site-a": "abcdefghijklmnop"}, true},
		{"bad charset", map[string]string{"site-a": "gremlin/a"}, true},
		{"leading dash", map[string]string{"site-a": "-eth"}, true},
		{"grem-dash ok", map[string]string{"site-a": "grem-a"}, false},
		{"collides with generated namespace", map[string]string{"site-a": "grem1234"}, true},
		{"reserved grem literal", map[string]string{"site-a": "grem"}, true},
		{"duplicate name", map[string]string{"site-a": "dup", "site-b": "dup"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validServerConfig()
			c.Interfaces = tt.interfaces
			err := c.ValidateServer()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateServer() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
