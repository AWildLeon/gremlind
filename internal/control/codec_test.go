package control

import (
	"bufio"
	"bytes"
	"net/netip"
	"reflect"
	"testing"

	"gremlind/internal/auth"
)

func TestFrameRoundtrip(t *testing.T) {
	nonce, err := auth.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	msgs := []Message{
		&Hello{ClientID: "site-a", Capabilities: 0x1},
		&Challenge{Nonce: nonce},
		&Auth{MAC: auth.Response("secret", "site-a", nonce)},
		&SessionRequest{OuterMTU: 1500, RequestedInner: netip.MustParseAddr("fd00:9::42")},
		&SessionRequest{OuterMTU: 1280}, // zero RequestedInner
		&SessionReply{
			Result:      ResultOK,
			ClientInner: netip.MustParseAddr("fd00:9::42"),
			ServerInner: netip.MustParseAddr("fd00:9::1"),
			ServerOuter: netip.MustParseAddr("2001:db8::10"),
			GREKey:      0xdeadbeef,
			MTU:         1400,
			Message:     "ok",
		},
		&SessionReply{Result: ResultAuthFailed, Message: "bad mac"},
		&SessionReply{ // v4 endpoints must survive too
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

	for _, want := range msgs {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, want); err != nil {
			t.Fatalf("write %T: %v", want, err)
		}
		got, err := ReadMessage(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("read %T: %v", want, err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("roundtrip mismatch\n want %#v\n  got %#v", want, got)
		}
	}
}

func TestReadRejectsUnknownType(t *testing.T) {
	// payloadLen=0, version=1, type=99
	frame := []byte{0x00, 0x00, ProtoVersion, 99}
	_, err := ReadMessage(bufio.NewReader(bytes.NewReader(frame)))
	if err == nil {
		t.Fatal("expected error for unknown message type")
	}
}

func TestReadRejectsBadVersion(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x09, byte(MsgEcho)}
	_, err := ReadMessage(bufio.NewReader(bytes.NewReader(frame)))
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	m := &Echo{}
	if err := m.unmarshalPayload([]byte{0, 0, 0, 1, 0xff}); err == nil {
		t.Fatal("expected trailing-byte error")
	}
}
