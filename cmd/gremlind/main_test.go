package main

import (
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
