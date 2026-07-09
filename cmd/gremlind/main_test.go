package main

import (
	"net"
	"testing"

	"gremlind/internal/config"
)

func TestSecretFromInputsPrecedence(t *testing.T) {
	t.Setenv("GREMLIND_SECRET", "from-env")
	cfg := &config.Config{
		Auth:   config.Auth{PSK: "from-psk"},
		Client: config.Client{Secret: "from-config"},
	}

	if got := secretFromInputs("from-flag", "GREMLIND_SECRET", cfg); got != "from-flag" {
		t.Fatalf("flag secret = %q, want from-flag", got)
	}
	if got := secretFromInputs("", "GREMLIND_SECRET", cfg); got != "from-env" {
		t.Fatalf("env secret = %q, want from-env", got)
	}
	if got := secretFromInputs("", "MISSING_GREMLIND_SECRET", cfg); got != "from-config" {
		t.Fatalf("config secret = %q, want from-config", got)
	}

	cfg.Client.Secret = ""
	if got := secretFromInputs("", "MISSING_GREMLIND_SECRET", cfg); got != "from-psk" {
		t.Fatalf("psk fallback = %q, want from-psk", got)
	}
}

func TestSecretFromInputsCanDisableEnvLookup(t *testing.T) {
	t.Setenv("GREMLIND_SECRET", "from-env")
	cfg := &config.Config{Client: config.Client{Secret: "from-config"}}

	if got := secretFromInputs("", "", cfg); got != "from-config" {
		t.Fatalf("secret = %q, want from-config", got)
	}
}

func TestIfaceAddrIPRejectsUnusableSourceAddresses(t *testing.T) {
	bad := map[string]*net.IPNet{
		"::1/128":     {IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		"127.0.0.1/8": {IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		"fe80::1/64":  {IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	}
	for name, ipnet := range bad {
		if addr, ok := ifaceAddrIP(ipnet); ok {
			t.Fatalf("ifaceAddrIP(%s) = %s, true; want rejection", name, addr)
		}
	}

	ipnet := &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}
	if addr, ok := ifaceAddrIP(ipnet); !ok || addr.String() != "2001:db8::1" {
		t.Fatalf("ifaceAddrIP(global) = %s, %v; want 2001:db8::1, true", addr, ok)
	}
}
