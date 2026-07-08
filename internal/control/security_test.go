package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gremlind/internal/auth"
)

// TestNoClientEnumeration verifies the server does not reveal whether a client
// ID is known. In per-client-secret mode (no global PSK), an unknown ID must get
// the same CHALLENGE a known ID gets, so valid IDs cannot be enumerated.
func TestNoClientEnumeration(t *testing.T) {
	est := &fakeEstablisher{result: ResultOK}
	srv := &Server{
		Log:              discardLogger(),
		Clients:          map[string]string{"site-a": "sekret"}, // no PSK
		Establisher:      est,
		KeepaliveTimeout: time.Second,
	}
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	firstReply := func(id string) Message {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := WriteMessage(conn, &Hello{ClientID: id}); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := ReadMessage(bufio.NewReader(conn))
		if err != nil {
			t.Fatalf("read reply for %q: %v", id, err)
		}
		return m
	}

	if _, ok := firstReply("site-a").(*Challenge); !ok {
		t.Fatal("known id should receive a Challenge")
	}
	if m := firstReply("does-not-exist"); !isChallenge(m) {
		t.Fatalf("unknown id must be indistinguishable from a known one, got %T — enumeration oracle", m)
	}
}

func isChallenge(m Message) bool {
	_, ok := m.(*Challenge)
	return ok
}

func TestServerRejectsInvalidClientID(t *testing.T) {
	est := &fakeEstablisher{result: ResultOK}
	srv := &Server{Log: discardLogger(), PSK: "s3cret", Establisher: est, KeepaliveTimeout: time.Second}

	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := WriteMessage(conn, &Hello{ClientID: "bad\nid"}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg, err := ReadMessage(bufio.NewReader(conn))
	if err != nil {
		t.Fatal(err)
	}
	if td, ok := msg.(*Teardown); !ok || td.Reason != ReasonBadClientID {
		t.Fatalf("expected invalid-client-id teardown, got %#v", msg)
	}
	if est.gotParams.ClientID != "" {
		t.Fatalf("invalid client id reached establisher: %+v", est.gotParams)
	}
}

func TestClientRejectsUnauthenticatedSessionReply(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		br := bufio.NewReader(serverConn)
		msg, err := ReadMessage(br)
		if err != nil {
			return
		}
		hello := msg.(*Hello)
		nonce := fixedNonce(1)
		_ = WriteMessage(serverConn, &Challenge{Nonce: nonce})
		if _, err := ReadMessage(br); err != nil { // Auth/client nonce
			return
		}
		if _, err := ReadMessage(br); err != nil { // encrypted SessionRequest bytes
			return
		}
		_ = hello
		// A rogue server that does not know the secret cannot produce encrypted
		// session replies the client accepts.
		_ = WriteMessage(serverConn, &SessionReply{
			Result:      ResultOK,
			ClientInner: netip.MustParseAddr("fd00:9::2"),
			ServerInner: netip.MustParseAddr("fd00:9::1"),
			ServerOuter: netip.MustParseAddr("2001:db8::10"),
			GREKey:      1234,
			MTU:         1400,
		})
	}()

	cl := &Client{Log: discardLogger(), ClientID: "site-a", Secret: "s3cret", OuterMTU: 1500}
	_, err := cl.Handshake(clientConn)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected for unauthenticated server, got %v", err)
	}
}

func fixedNonce(first byte) auth.Nonce {
	var n auth.Nonce
	n[0] = first
	return n
}

// TestOversizedHandshakePayloadRejected verifies the handshake read path rejects
// a frame whose declared payload exceeds the handshake cap before allocating for
// it, so an unauthenticated peer cannot pin large buffers.
func TestOversizedHandshakePayloadRejected(t *testing.T) {
	// Header declares a 5000-byte payload (> maxHandshakePayload of 4096); no body.
	frame := []byte{0x13, 0x88, ProtoVersion, byte(MsgHello)}
	_, err := ReadMessageLimited(bufio.NewReader(bytes.NewReader(frame)), maxHandshakePayload)
	if err == nil {
		t.Fatal("expected oversized handshake payload to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected size-limit rejection, got: %v", err)
	}
}

// TestPerIPHandshakeLimit verifies one source IP cannot exceed the per-IP cap,
// while other IPs remain unaffected, and that releasing frees a slot.
func TestPerIPHandshakeLimit(t *testing.T) {
	s := &Server{MaxPendingHandshakes: 100, MaxPendingPerIP: 3}
	s.sem = make(chan struct{}, s.MaxPendingHandshakes)
	s.perIP = make(map[string]int)

	for i := 0; i < 3; i++ {
		if !s.reserve("2001:db8::1") {
			t.Fatalf("reserve %d from the same IP should succeed", i)
		}
	}
	if s.reserve("2001:db8::1") {
		t.Fatal("reserve beyond the per-IP cap must be shed")
	}
	if !s.reserve("2001:db8::2") {
		t.Fatal("a different IP must still get a slot while one IP floods")
	}
	s.release("2001:db8::1")
	if !s.reserve("2001:db8::1") {
		t.Fatal("reserve after release should succeed")
	}
}

// TestGlobalHandshakeLimit verifies the global cap sheds excess handshakes.
func TestGlobalHandshakeLimit(t *testing.T) {
	s := &Server{MaxPendingHandshakes: 2, MaxPendingPerIP: 100}
	s.sem = make(chan struct{}, s.MaxPendingHandshakes)
	s.perIP = make(map[string]int)

	if !s.reserve("a") || !s.reserve("b") {
		t.Fatal("first two reserves should succeed")
	}
	if s.reserve("c") {
		t.Fatal("reserve beyond the global cap must be shed")
	}
	s.release("a")
	if !s.reserve("c") {
		t.Fatal("reserve after a global release should succeed")
	}
}
