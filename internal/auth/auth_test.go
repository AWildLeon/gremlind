package auth

import "testing"

func TestSecretForPerClientMapIsAllowlist(t *testing.T) {
	clients := map[string]string{"site-a": "per-client-secret"}
	if got := SecretFor("site-a", "global", clients); got != "per-client-secret" {
		t.Fatalf("listed client secret = %q", got)
	}
	if got := SecretFor("site-b", "global", clients); got != "" {
		t.Fatalf("unlisted client should not fall back to global PSK, got %q", got)
	}
}

func TestSecretForGlobalOnlyMode(t *testing.T) {
	if got := SecretFor("anyone", "global", nil); got != "global" {
		t.Fatalf("global-only secret = %q", got)
	}
}
