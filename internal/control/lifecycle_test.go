package control

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

func testGrant() SessionGrant {
	return SessionGrant{
		ClientInner: netip.MustParseAddr("fd00:9::2"),
		ServerInner: netip.MustParseAddr("fd00:9::1"),
		ServerOuter: netip.MustParseAddr("2001:db8::10"),
		GREKey:      1,
		MTU:         1400,
	}
}

func settle() {
	for i := 0; i < 5; i++ {
		runtime.Gosched()
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServerNoGoroutineLeakPerSession guards against the per-session watcher
// leak: a concentrator whose clients connect and disconnect repeatedly must not
// accumulate one blocked goroutine per closed session.
func TestServerNoGoroutineLeakPerSession(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
	srv := &Server{Log: discardLogger(), PSK: "s3cret", Establisher: est, KeepaliveTimeout: 500 * time.Millisecond}

	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	oneSession := func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cl := &Client{Log: discardLogger(), ClientID: "site-a", Secret: "s3cret", OuterMTU: 1500}
		if _, err := cl.Handshake(conn); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		conn.Close() // client vanishes; the server must reap the session and its watcher
	}

	oneSession() // warm up
	settle()
	base := runtime.NumGoroutine()

	const N = 40
	for i := 0; i < N; i++ {
		oneSession()
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		settle()
		g := runtime.NumGoroutine()
		if g <= base+5 {
			break // settled back near baseline: no per-session leak
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: base=%d, now=%d after %d sessions", base, g, N)
		}
	}
}

// TestServerGracefulShutdownTearsDown verifies that cancelling the context tears
// down live sessions (down hooks / GRE removal) before Serve returns, rather than
// exiting abruptly and leaking data-plane state.
func TestServerGracefulShutdownTearsDown(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
	srv := &Server{Log: discardLogger(), PSK: "s3cret", Establisher: est, KeepaliveTimeout: time.Second}

	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := &Client{Log: discardLogger(), ClientID: "site-a", Secret: "s3cret", OuterMTU: 1500}
	if _, err := cl.Handshake(conn); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	settle() // let the server register its teardown and enter the keepalive phase

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
	if !est.tornDown {
		t.Error("session was not torn down on graceful shutdown")
	}
}
