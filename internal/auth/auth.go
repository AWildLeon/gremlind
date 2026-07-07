// Package auth implements the control-channel authentication: an HMAC-SHA256
// challenge-response over a pre-shared key, so the secret never crosses the wire.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// NonceLen is the length of an authentication challenge nonce.
const NonceLen = 32

// MACLen is the length of a challenge-response MAC (HMAC-SHA256).
const MACLen = sha256.Size

// Nonce is a random authentication challenge.
type Nonce [NonceLen]byte

// NewNonce returns a cryptographically random challenge.
func NewNonce() (Nonce, error) {
	var n Nonce
	if _, err := rand.Read(n[:]); err != nil {
		return Nonce{}, err
	}
	return n, nil
}

// Response computes HMAC-SHA256(secret, nonce||clientID). Binding the client ID
// prevents a response captured for one identity from being replayed as another.
func Response(secret, clientID string, nonce Nonce) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(nonce[:])
	mac.Write([]byte(clientID))
	return mac.Sum(nil)
}

// Verify reports whether got matches the expected response for secret/clientID.
// It is constant-time.
func Verify(secret, clientID string, nonce Nonce, got []byte) bool {
	want := Response(secret, clientID, nonce)
	return hmac.Equal(want, got)
}

// SecretFor resolves the secret for a client: a per-client secret if present,
// otherwise the global PSK. Returns "" if neither is configured.
func SecretFor(clientID, psk string, clients map[string]string) string {
	if s, ok := clients[clientID]; ok {
		return s
	}
	return psk
}
