// Package control implements gremlind's TCP control channel: the signaling that
// GRE itself lacks. It defines the wire messages (proto.go), their binary codec
// (codec.go), and the server/client state machines (server.go, client.go).
package control

import (
	"net/netip"

	"gremlind/internal/auth"
)

// ProtoVersion is the control-protocol version carried in every frame header.
const ProtoVersion uint8 = 1

// MsgType identifies a control message.
type MsgType uint8

const (
	MsgHello          MsgType = 1 // C→S: version/client-id/capabilities
	MsgChallenge      MsgType = 2 // S→C: auth nonce
	MsgAuth           MsgType = 3 // C→S: HMAC challenge-response
	MsgSessionRequest MsgType = 4 // C→S: request a GRE session
	MsgSessionReply   MsgType = 5 // S→C: negotiated session parameters
	MsgEcho           MsgType = 6 // both: keepalive
	MsgEchoAck        MsgType = 7 // both: keepalive reply
	MsgTeardown       MsgType = 8 // both: end the session
	MsgEncrypted      MsgType = 9 // both: encrypted inner control frame
)

// Result codes returned in SessionReply.
type Result uint8

const (
	ResultOK          Result = 0
	ResultAuthFailed  Result = 1
	ResultNoAddresses Result = 2 // inner pool exhausted
	ResultUnsupported Result = 3 // e.g. unknown address family
	ResultInternal    Result = 4
)

func (r Result) String() string {
	switch r {
	case ResultOK:
		return "ok"
	case ResultAuthFailed:
		return "auth-failed"
	case ResultNoAddresses:
		return "no-addresses"
	case ResultUnsupported:
		return "unsupported"
	default:
		return "internal-error"
	}
}

// Message is a control-channel message that can encode/decode its own payload.
type Message interface {
	Type() MsgType
	marshalPayload() []byte
	unmarshalPayload(b []byte) error
}

// Hello is the first message a client sends.
type Hello struct {
	ClientID     string
	Capabilities uint32
}

func (*Hello) Type() MsgType { return MsgHello }

// Challenge carries the server's authentication nonce.
type Challenge struct {
	Nonce auth.Nonce
}

func (*Challenge) Type() MsgType { return MsgChallenge }

// Auth carries the client's random key-exchange nonce. It intentionally no
// longer carries a password-derived MAC: after HELLO/CHALLENGE/AUTH, all
// session setup and keepalive traffic is AEAD-encrypted with keys derived from
// the pre-shared secret and both nonces.
type Auth struct {
	MAC []byte // kept for wire compatibility; contains the client nonce
}

func (*Auth) Type() MsgType { return MsgAuth }

// SessionRequest asks the server to establish a GRE session. OuterMTU is the
// MTU of the client's outer link; the server negotiates the tunnel MTU from it.
type SessionRequest struct {
	OuterMTU       uint16
	RequestedInner netip.Addr // zero value = let the server assign
}

func (*SessionRequest) Type() MsgType { return MsgSessionRequest }

// SessionReply returns the negotiated session parameters. All addresses use the
// same address family, chosen from the client's outer endpoint (IPv6-native).
type SessionReply struct {
	Result      Result
	ClientInner netip.Addr // inner address assigned to the client
	ServerInner netip.Addr // server's inner address (tunnel peer)
	ServerOuter netip.Addr // server's outer GRE endpoint
	GREKey      uint32     // GRE key demultiplexing this session
	MTU         uint16     // negotiated tunnel MTU (both peers set this)
	Message     string     // human-readable detail, esp. on failure
	ServerMAC   []byte     // HMAC proof over successful replies
}

func (*SessionReply) Type() MsgType { return MsgSessionReply }

// Echo is a keepalive probe; the peer replies with EchoAck carrying the same Seq.
type Echo struct {
	Seq uint32
}

func (*Echo) Type() MsgType { return MsgEcho }

// EchoAck answers an Echo.
type EchoAck struct {
	Seq uint32
}

func (*EchoAck) Type() MsgType { return MsgEchoAck }

// Teardown ends the session. Reason is free-form.
type Teardown struct {
	Reason string
}

func (*Teardown) Type() MsgType { return MsgTeardown }

// Encrypted wraps an AEAD-encrypted inner control frame.
type Encrypted struct {
	Ciphertext []byte
}

func (*Encrypted) Type() MsgType { return MsgEncrypted }

// newMessage returns an empty message value for a type, for decoding.
func newMessage(t MsgType) Message {
	switch t {
	case MsgHello:
		return &Hello{}
	case MsgChallenge:
		return &Challenge{}
	case MsgAuth:
		return &Auth{}
	case MsgSessionRequest:
		return &SessionRequest{}
	case MsgSessionReply:
		return &SessionReply{}
	case MsgEcho:
		return &Echo{}
	case MsgEchoAck:
		return &EchoAck{}
	case MsgTeardown:
		return &Teardown{}
	case MsgEncrypted:
		return &Encrypted{}
	default:
		return nil
	}
}
