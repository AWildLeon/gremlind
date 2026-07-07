package control

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeEstablisher grants a fixed session without touching the data-plane.
type fakeEstablisher struct {
	grant     SessionGrant
	result    Result
	gotParams SessionParams
	tornDown  bool
}

func (f *fakeEstablisher) Establish(_ context.Context, p SessionParams) (SessionGrant, Result, error) {
	f.gotParams = p
	if f.result != ResultOK {
		return SessionGrant{}, f.result, nil
	}
	return f.grant, ResultOK, nil
}

func (f *fakeEstablisher) Teardown(SessionParams, SessionGrant) { f.tornDown = true }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHandshakeSuccess(t *testing.T) {
	grant := SessionGrant{
		ClientInner: netip.MustParseAddr("fd00:9::2"),
		ServerInner: netip.MustParseAddr("fd00:9::1"),
		ServerOuter: netip.MustParseAddr("2001:db8::10"),
		GREKey:      0x2a,
		MTU:         1400,
	}
	est := &fakeEstablisher{grant: grant, result: ResultOK}
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

	cl := &Client{Log: discardLogger(), ClientID: "site-a", Secret: "s3cret", OuterMTU: 1500}
	sess, err := cl.Handshake(conn)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if sess.GREKey != grant.GREKey || sess.ClientInner != grant.ClientInner || sess.MTU != grant.MTU {
		t.Errorf("unexpected session: %+v", sess)
	}
	if est.gotParams.ClientID != "site-a" || est.gotParams.OuterMTU != 1500 {
		t.Errorf("establisher got wrong params: %+v", est.gotParams)
	}
	if !est.gotParams.ClientOuter.IsValid() {
		t.Errorf("expected client outer address to be captured")
	}
}

func TestHandshakeWrongSecret(t *testing.T) {
	est := &fakeEstablisher{result: ResultOK}
	srv := &Server{Log: discardLogger(), PSK: "right", Establisher: est, KeepaliveTimeout: time.Second}

	ln, _ := net.Listen("tcp", "[::1]:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cl := &Client{Log: discardLogger(), ClientID: "site-a", Secret: "wrong", OuterMTU: 1500}
	if _, err := cl.Handshake(conn); err == nil {
		t.Fatal("expected handshake to fail with wrong secret")
	}
	if est.tornDown {
		t.Error("teardown should not run when establish never happened")
	}
}
