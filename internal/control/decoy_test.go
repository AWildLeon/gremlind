package control

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServerServesDecoy404ToProbe verifies the camouflage: a peer that does not
// open with a valid control frame (here, an HTTP request) gets a stock nginx 404
// and is hung up on, never reaching the establisher.
func TestServerServesDecoy404ToProbe(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
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
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/admin", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if got := resp.Header.Get("Server"); got != "nginx" {
		t.Fatalf("Server header = %q, want nginx", got)
	}
	if est.gotParams.ClientID != "" {
		t.Fatalf("probe reached establisher: %+v", est.gotParams)
	}
}

// TestServerDecoyTeapotEasterEgg verifies the /imagremlind easter egg answers
// 418 while other paths stay on the 404 disguise.
func TestServerDecoyTeapotEasterEgg(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
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
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/imagremlind", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", resp.StatusCode)
	}
	if est.gotParams.ClientID != "" {
		t.Fatalf("probe reached establisher: %+v", est.gotParams)
	}
}

func TestServerDecoyRedirect(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
	srv := &Server{Log: discardLogger(), PSK: "s3cret", Establisher: est, KeepaliveTimeout: time.Second, DecoyRedirect: "https://example.com/"}

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
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/admin", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://example.com/" {
		t.Fatalf("Location = %q, want https://example.com/", got)
	}
	if est.gotParams.ClientID != "" {
		t.Fatalf("probe reached establisher: %+v", est.gotParams)
	}
}

func TestServerDecoyGremlinMustHideDisablesEasterEgg(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
	srv := &Server{Log: discardLogger(), PSK: "s3cret", Establisher: est, KeepaliveTimeout: time.Second, GremlinMustHide: true}

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
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	req, _ := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/imagremlind", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if est.gotParams.ClientID != "" {
		t.Fatalf("probe reached establisher: %+v", est.gotParams)
	}
}

// TestServerStillServesControlAfterDecoy makes sure a real client is unaffected:
// its valid Hello frame passes the peek and completes a normal handshake.
func TestServerStillServesControlAfterDecoy(t *testing.T) {
	est := &fakeEstablisher{grant: testGrant(), result: ResultOK}
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
	if _, err := cl.Handshake(conn); err != nil {
		t.Fatalf("legit handshake rejected: %v", err)
	}
	if est.gotParams.ClientID != "site-a" {
		t.Fatalf("establisher not reached, gotParams=%+v", est.gotParams)
	}
}
