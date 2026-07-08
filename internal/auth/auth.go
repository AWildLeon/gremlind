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

// ServerProof computes the server's authenticated proof over the accepted
// session parameters. It proves the server knows the same secret and binds the
// reply to this handshake nonce/client ID.
func ServerProof(secret, clientID string, nonce Nonce, sessionPayload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("gremlind server proof v1"))
	mac.Write(nonce[:])
	mac.Write([]byte(clientID))
	mac.Write(sessionPayload)
	return mac.Sum(nil)
}

// Verify reports whether got matches the expected response for secret/clientID.
// It is constant-time.
func Verify(secret, clientID string, nonce Nonce, got []byte) bool {
	want := Response(secret, clientID, nonce)
	return hmac.Equal(want, got)
}

// VerifyServerProof reports whether got is the expected server proof.
func VerifyServerProof(secret, clientID string, nonce Nonce, sessionPayload, got []byte) bool {
	want := ServerProof(secret, clientID, nonce, sessionPayload)
	return hmac.Equal(want, got)
}

// SecretFor resolves the secret for a client. When per-client secrets are
// configured, only listed client IDs are accepted; the global PSK is used only
// in legacy/global-only mode. This prevents a global PSK holder from claiming
// arbitrary unlisted identities when a client allowlist exists.
func SecretFor(clientID, psk string, clients map[string]string) string {
	if len(clients) > 0 {
		return clients[clientID]
	}
	return psk
}

// RandomSecret returns an unguessable secret. It is used to authenticate an
// unknown client ID against a random target so authentication fails uniformly —
// exactly like a wrong credential — instead of revealing that the ID is unknown
// (which would make valid client IDs enumerable).
func RandomSecret() string {
	var b [NonceLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A failing CSPRNG is unrecoverable; return an empty secret, which no
		// valid MAC can match anyway.
		return ""
	}
	return string(b[:])
}
