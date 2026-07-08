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
	"sync"
	"time"

	"gremlind/internal/auth"
)

// handshakeTimeout bounds how long an unauthenticated peer may take to complete
// HELLO→AUTH→SESSION_REQUEST before the server drops it. It is a var only so
// tests can shrink it; treat it as a constant otherwise.
var handshakeTimeout = 10 * time.Second

// maxHandshakePayload caps the payload size of any message accepted before a
// peer authenticates. Every handshake message (Hello, Auth, SessionRequest) is
// tiny, so this bounds the memory an unauthenticated peer can make the server
// allocate to a few KB instead of the 64 KiB protocol maximum.
const maxHandshakePayload = 4096

// defaultMaxPendingHandshakes bounds how many connections may be mid-handshake
// (accepted but not yet authenticated) at once. Beyond it, new connections are
// shed immediately, so an unauthenticated connection flood cannot exhaust
// goroutines/FDs/memory. Authenticated sessions do not count against it.
const defaultMaxPendingHandshakes = 256

// defaultMaxPendingPerIP bounds concurrent handshakes from one source IP.
const defaultMaxPendingPerIP = 16

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
	SessionKey  uint32 // server-local registry key, not sent on the wire
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

	// MaxPendingHandshakes bounds concurrent in-progress (unauthenticated)
	// handshakes across all peers; 0 uses defaultMaxPendingHandshakes.
	MaxPendingHandshakes int
	// MaxPendingPerIP bounds concurrent in-progress handshakes from a single
	// source IP, so one flooding source cannot fill the global pool and lock out
	// legitimate clients; 0 uses defaultMaxPendingPerIP.
	MaxPendingPerIP int

	sem     chan struct{}  // global pending-handshake semaphore, sized in Serve
	perIPMu sync.Mutex     // guards perIP
	perIP   map[string]int // in-progress handshakes per source IP
}

// Serve accepts connections until ctx is cancelled or the listener errors. It
// bounds concurrent unauthenticated handshakes — globally and per source IP —
// and sheds excess connections so a connection flood from an unauthenticated
// peer can neither exhaust resources nor lock out other clients.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.MaxPendingHandshakes <= 0 {
		s.MaxPendingHandshakes = defaultMaxPendingHandshakes
	}
	if s.MaxPendingPerIP <= 0 {
		s.MaxPendingPerIP = defaultMaxPendingPerIP
	}
	s.sem = make(chan struct{}, s.MaxPendingHandshakes)
	s.perIP = make(map[string]int)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Track in-flight connections so shutdown can wait for their sessions to tear
	// down cleanly (GRE interfaces removed, down hooks run) rather than exiting
	// abruptly and leaking data-plane state.
	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		ip := ipOf(conn.RemoteAddr())
		if !s.reserve(ip) {
			// At capacity: shed load without spending a goroutine or reading a
			// byte from the untrusted peer.
			s.Log.Warn("handshake capacity reached, dropping connection", "peer", conn.RemoteAddr())
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn, func() { s.release(ip) })
		}()
	}
}

// reserve takes a global and a per-IP handshake slot, returning false (holding
// neither) if either is exhausted.
func (s *Server) reserve(ip string) bool {
	select {
	case s.sem <- struct{}{}:
	default:
		return false
	}
	s.perIPMu.Lock()
	if s.perIP[ip] >= s.MaxPendingPerIP {
		s.perIPMu.Unlock()
		<-s.sem
		return false
	}
	s.perIP[ip]++
	s.perIPMu.Unlock()
	return true
}

// release returns the slots taken by reserve. It is called once, when the
// handshake resolves — an established session no longer occupies a slot.
func (s *Server) release(ip string) {
	s.perIPMu.Lock()
	if s.perIP[ip] > 0 {
		s.perIP[ip]--
		if s.perIP[ip] == 0 {
			delete(s.perIP, ip)
		}
	}
	s.perIPMu.Unlock()
	<-s.sem
}

func (s *Server) handle(ctx context.Context, conn net.Conn, release func()) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	log := s.Log.With("peer", peer)
	br := bufio.NewReader(conn)

	// A single watcher for the whole connection: on context cancellation it
	// closes the conn, unblocking any read in progress (handshake or keepalive).
	// It exits when handle returns (defer cancel), so nothing leaks per session —
	// unlike a watcher bound to the server-lifetime context.
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-connCtx.Done()
		conn.Close()
	}()

	params, grant, sec, ok := s.handshake(ctx, conn, br, log)
	// Release the pending-handshake slots the moment the handshake resolves; an
	// established (authenticated) session must not hold them for its whole life.
	release()
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

	s.keepaliveLoop(ctx, conn, sec, log)
}

// handshake runs HELLO→CHALLENGE→AUTH, derives PSK AEAD keys, then exchanges
// SESSION_REQUEST→SESSION_REPLY inside the encrypted channel. It returns
// ok=false (after best-effort notifying the peer) on any failure.
func (s *Server) handshake(ctx context.Context, conn net.Conn, br *bufio.Reader, log *slog.Logger) (SessionParams, SessionGrant, *secureChannel, bool) {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	// Clear the handshake deadline before entering the keepalive phase; otherwise
	// the write half stays pinned to now+handshakeTimeout and the first EchoAck
	// sent after it expires fails with i/o timeout. keepaliveLoop manages its own
	// read deadline from here on (mirrors the client's Handshake).
	defer conn.SetDeadline(time.Time{})

	hello, ok := expect[*Hello](br, log, "hello")
	if !ok {
		return SessionParams{}, SessionGrant{}, nil, false
	}
	if !ValidClientID(hello.ClientID) {
		log.Warn("invalid client id")
		writeTeardown(conn, "invalid client id")
		return SessionParams{}, SessionGrant{}, nil, false
	}
	secret := auth.SecretFor(hello.ClientID, s.PSK, s.Clients)
	if secret == "" {
		// Unknown client. Do not reveal it: continue with an unguessable random
		// secret so the next encrypted read fails exactly like a wrong credential.
		log.Debug("unknown client id (failing uniformly)", "client", hello.ClientID)
		secret = auth.RandomSecret()
	}

	serverNonce, err := auth.NewNonce()
	if err != nil {
		log.Error("nonce generation failed", "err", err)
		return SessionParams{}, SessionGrant{}, nil, false
	}
	if err := WriteMessage(conn, &Challenge{Nonce: serverNonce}); err != nil {
		return SessionParams{}, SessionGrant{}, nil, false
	}

	authMsg, ok := expect[*Auth](br, log, "auth")
	if !ok {
		return SessionParams{}, SessionGrant{}, nil, false
	}
	if len(authMsg.MAC) != auth.NonceLen {
		log.Warn("invalid client key-exchange nonce", "client", hello.ClientID)
		writeTeardown(conn, "authentication failed")
		return SessionParams{}, SessionGrant{}, nil, false
	}
	var clientNonce auth.Nonce
	copy(clientNonce[:], authMsg.MAC)
	sec, err := newServerSecureChannel(secret, hello.ClientID, serverNonce, clientNonce, br, conn)
	if err != nil {
		log.Error("secure channel setup failed", "err", err)
		return SessionParams{}, SessionGrant{}, nil, false
	}

	reqMsg, err := sec.ReadMessage()
	if err != nil {
		log.Warn("authentication failed", "client", hello.ClientID, "err", err)
		return SessionParams{}, SessionGrant{}, nil, false
	}
	req, ok := reqMsg.(*SessionRequest)
	if !ok {
		log.Warn("unexpected encrypted message", "want", "session request", "got_type", reqMsg.Type())
		return SessionParams{}, SessionGrant{}, nil, false
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
		_ = sec.WriteMessage(&SessionReply{Result: result, Message: msg})
		return SessionParams{}, SessionGrant{}, nil, false
	}

	reply := &SessionReply{
		Result:      ResultOK,
		ClientInner: grant.ClientInner,
		ServerInner: grant.ServerInner,
		ServerOuter: grant.ServerOuter,
		GREKey:      grant.GREKey,
		MTU:         grant.MTU,
	}
	if err := sec.WriteMessage(reply); err != nil {
		s.Establisher.Teardown(params, grant)
		return SessionParams{}, SessionGrant{}, nil, false
	}
	return params, grant, sec, true
}

// keepaliveLoop replies to Echo probes and drops the peer if it goes silent for
// longer than KeepaliveTimeout. The client drives the probe cadence. The caller
// (handle) owns the context watcher that closes conn on shutdown.
func (s *Server) keepaliveLoop(ctx context.Context, conn net.Conn, sec *secureChannel, log *slog.Logger) {
	for {
		conn.SetReadDeadline(time.Now().Add(s.KeepaliveTimeout))
		msg, err := sec.ReadMessage()
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				log.Debug("control connection closed", "err", err)
			}
			return
		}
		switch m := msg.(type) {
		case *Echo:
			if err := sec.WriteMessage(&EchoAck{Seq: m.Seq}); err != nil {
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
	msg, err := ReadMessageLimited(br, maxHandshakePayload)
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

// ipOf returns the source IP of a peer address as a string key for per-IP
// accounting, falling back to the full address string if it cannot be parsed.
func ipOf(a net.Addr) string {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}
