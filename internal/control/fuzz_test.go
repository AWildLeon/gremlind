package control

import (
	"bufio"
	"bytes"
	"net/netip"
	"reflect"
	"testing"

	"gremlind/internal/auth"
)

// seedMessages are representative, well-formed messages used to seed the fuzz
// corpus so the fuzzer starts from valid frames and mutates outward.
func seedMessages() []Message {
	nonce, _ := auth.NewNonce()
	return []Message{
		&Hello{ClientID: "site-a", Capabilities: 0x1},
		&Challenge{Nonce: nonce},
		&Auth{MAC: auth.Response("secret", "site-a", nonce)},
		&SessionRequest{OuterMTU: 1500, RequestedInner: netip.MustParseAddr("fd00:9::42")},
		&SessionRequest{OuterMTU: 1280},
		&SessionReply{
			Result:      ResultOK,
			ClientInner: netip.MustParseAddr("fd00:9::42"),
			ServerInner: netip.MustParseAddr("fd00:9::1"),
			ServerOuter: netip.MustParseAddr("2001:db8::10"),
			GREKey:      0xdeadbeef,
			MTU:         1400,
			Message:     "ok",
		},
		&SessionReply{ // v4 endpoints
			Result:      ResultOK,
			ClientInner: netip.MustParseAddr("10.99.0.2"),
			ServerInner: netip.MustParseAddr("10.99.0.1"),
			ServerOuter: netip.MustParseAddr("203.0.113.10"),
			MTU:         1476,
		},
		&Echo{Seq: 7},
		&EchoAck{Seq: 7},
		&Teardown{Reason: "client requested"},
	}
}

// FuzzReadMessage feeds arbitrary bytes to the full frame decoder — the exact
// path that runs on data arriving from an untrusted control-channel peer. The
// decoder must never panic: a malformed frame must always surface as an error.
// Any frame it *does* accept must be canonical, i.e. survive a re-encode and
// re-decode unchanged.
func FuzzReadMessage(f *testing.F) {
	for _, m := range seedMessages() {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, m); err == nil {
			f.Add(buf.Bytes())
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, ProtoVersion, byte(MsgEcho)})
	f.Add([]byte{0xff, 0xff, ProtoVersion, byte(MsgHello)}) // huge len, short body

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		for {
			msg, err := ReadMessage(r)
			if err != nil {
				return // any error is acceptable; it must simply not panic
			}

			// An accepted message must round-trip: re-encoding and re-decoding
			// yields an identical value (the wire form is canonical).
			var buf bytes.Buffer
			if err := WriteMessage(&buf, msg); err != nil {
				t.Fatalf("re-encode of accepted %T failed: %v", msg, err)
			}
			got, err := ReadMessage(bufio.NewReader(&buf))
			if err != nil {
				t.Fatalf("re-decode of accepted %T failed: %v", msg, err)
			}
			if !reflect.DeepEqual(msg, got) {
				t.Fatalf("non-canonical message %T:\n in %#v\nout %#v", msg, msg, got)
			}
		}
	})
}

// FuzzPayloadDecode targets each per-message payload decoder directly with a
// message type and arbitrary payload bytes. It asserts the same two invariants
// at the payload layer: never panic, and accepted payloads are canonical.
func FuzzPayloadDecode(f *testing.F) {
	for _, m := range seedMessages() {
		f.Add(uint8(m.Type()), m.marshalPayload())
	}
	// Boundary-ish seeds the mutator can grow from.
	f.Add(uint8(MsgSessionReply), []byte{0x00, 0x10}) // addr length byte = 16, then EOF
	f.Add(uint8(MsgHello), []byte{0xff, 0xff})        // str length 65535, no body

	f.Fuzz(func(t *testing.T, typ uint8, payload []byte) {
		m := newMessage(MsgType(typ))
		if m == nil {
			return // unknown type: nothing to decode
		}
		if err := m.unmarshalPayload(payload); err != nil {
			return // rejected: fine, as long as it did not panic
		}

		// Accepted payload must be canonical under marshal∘unmarshal.
		reencoded := m.marshalPayload()
		m2 := newMessage(MsgType(typ))
		if err := m2.unmarshalPayload(reencoded); err != nil {
			t.Fatalf("re-decode of canonical %T payload failed: %v", m, err)
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("non-canonical %T payload:\n in %#v\nout %#v", m, m, m2)
		}
	})
}
