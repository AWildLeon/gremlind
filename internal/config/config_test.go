package config

import (
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
