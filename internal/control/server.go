package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"gremlind/internal/auth"
)

// handshakeTimeout bounds how long an unauthenticated peer may take to complete
// HELLO→AUTH→SESSION_REQUEST before the server drops it.
const handshakeTimeout = 10 * time.Second

// SessionParams describes an authenticated client's session request, handed to
// the Establisher to provision the data-plane.
type SessionParams struct {
	ClientID       string
	ClientOuter    netip.Addr // outer GRE endpoint, from the control connection
	OuterMTU       uint16
	RequestedInner netip.Addr // zero = server assigns
}

// SessionGrant is the data-plane result of a successful Establish call.
type SessionGrant struct {
	ClientInner netip.Addr
	ServerInner netip.Addr
	ServerOuter netip.Addr
	GREKey      uint32
	MTU         uint16
}

// Establisher provisions and tears down the GRE data-plane for a session. The
// session manager (M3) implements it; the control server stays transport-only.
type Establisher interface {
	// Establish provisions a GRE interface. On failure it returns a non-OK
	// Result and an error describing why.
	Establish(ctx context.Context, p SessionParams) (SessionGrant, Result, error)
	// Teardown removes the data-plane state for a previously granted session.
	Teardown(p SessionParams, g SessionGrant)
}

// Server terminates control connections and drives per-connection session setup.
type Server struct {
	Log         *slog.Logger
	PSK         string
	Clients     map[string]string
	Establisher Establisher

	KeepaliveTimeout time.Duration
}

// Serve accepts connections until ctx is cancelled or the listener errors.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	log := s.Log.With("peer", peer)
	br := bufio.NewReader(conn)

	params, grant, ok := s.handshake(ctx, conn, br, log)
	if !ok {
		return
	}
	log = log.With("client", params.ClientID)
	log.Info("session established",
		"client_inner", grant.ClientInner, "gre_key", grant.GREKey, "mtu", grant.MTU)
	defer func() {
		s.Establisher.Teardown(params, grant)
		log.Info("session torn down")
	}()

	s.keepaliveLoop(ctx, conn, br, log)
}

// handshake runs HELLO→CHALLENGE→AUTH→SESSION_REQUEST→SESSION_REPLY. It returns
// ok=false (after best-effort notifying the peer) on any failure.
func (s *Server) handshake(ctx context.Context, conn net.Conn, br *bufio.Reader, log *slog.Logger) (SessionParams, SessionGrant, bool) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	hello, ok := expect[*Hello](br, log, "hello")
	if !ok {
		return SessionParams{}, SessionGrant{}, false
	}
	secret := auth.SecretFor(hello.ClientID, s.PSK, s.Clients)
	if secret == "" {
		log.Warn("unknown client id", "client", hello.ClientID)
		writeTeardown(conn, "unknown client")
		return SessionParams{}, SessionGrant{}, false
	}

	nonce, err := auth.NewNonce()
	if err != nil {
		log.Error("nonce generation failed", "err", err)
		return SessionParams{}, SessionGrant{}, false
	}
	if err := WriteMessage(conn, &Challenge{Nonce: nonce}); err != nil {
		return SessionParams{}, SessionGrant{}, false
	}

	authMsg, ok := expect[*Auth](br, log, "auth")
	if !ok {
		return SessionParams{}, SessionGrant{}, false
	}
	if !auth.Verify(secret, hello.ClientID, nonce, authMsg.MAC) {
		log.Warn("authentication failed", "client", hello.ClientID)
		writeTeardown(conn, "authentication failed")
		return SessionParams{}, SessionGrant{}, false
	}

	req, ok := expect[*SessionRequest](br, log, "session request")
	if !ok {
		return SessionParams{}, SessionGrant{}, false
	}

	clientOuter := outerAddr(conn.RemoteAddr())
	params := SessionParams{
		ClientID:       hello.ClientID,
		ClientOuter:    clientOuter,
		OuterMTU:       req.OuterMTU,
		RequestedInner: req.RequestedInner,
	}

	grant, result, err := s.Establisher.Establish(ctx, params)
	if err != nil || result != ResultOK {
		msg := "internal error"
		if err != nil {
			msg = err.Error()
		}
		log.Warn("establish failed", "result", result, "err", err)
		WriteMessage(conn, &SessionReply{Result: result, Message: msg})
		return SessionParams{}, SessionGrant{}, false
	}

	reply := &SessionReply{
		Result:      ResultOK,
		ClientInner: grant.ClientInner,
		ServerInner: grant.ServerInner,
		ServerOuter: grant.ServerOuter,
		GREKey:      grant.GREKey,
		MTU:         grant.MTU,
	}
	if err := WriteMessage(conn, reply); err != nil {
		s.Establisher.Teardown(params, grant)
		return SessionParams{}, SessionGrant{}, false
	}
	return params, grant, true
}

// keepaliveLoop replies to Echo probes and drops the peer if it goes silent for
// longer than KeepaliveTimeout. The client drives the probe cadence.
func (s *Server) keepaliveLoop(ctx context.Context, conn net.Conn, br *bufio.Reader, log *slog.Logger) {
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	for {
		conn.SetReadDeadline(time.Now().Add(s.KeepaliveTimeout))
		msg, err := ReadMessage(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				log.Debug("control connection closed", "err", err)
			}
			return
		}
		switch m := msg.(type) {
		case *Echo:
			if err := WriteMessage(conn, &EchoAck{Seq: m.Seq}); err != nil {
				return
			}
		case *Teardown:
			log.Info("peer requested teardown", "reason", m.Reason)
			return
		default:
			// Ignore unexpected but well-formed messages post-establishment.
		}
	}
}

// expect reads the next message and asserts its concrete type.
func expect[T Message](br *bufio.Reader, log *slog.Logger, what string) (T, bool) {
	var zero T
	msg, err := ReadMessage(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Debug("read failed", "want", what, "err", err)
		}
		return zero, false
	}
	typed, ok := msg.(T)
	if !ok {
		log.Warn("unexpected message", "want", what, "got_type", msg.Type())
		return zero, false
	}
	return typed, true
}

func writeTeardown(w io.Writer, reason string) {
	WriteMessage(w, &Teardown{Reason: reason})
}

// outerAddr extracts the IP of a control peer as a netip.Addr (unmapped).
func outerAddr(a net.Addr) netip.Addr {
	if tcp, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}
