package control

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"gremlind/internal/auth"
)

// ErrRejected marks a permanent rejection by the server (bad credentials,
// unknown client, unsupported request). A reconnecting dialer should not retry
// on this error, unlike a transient network failure.
var ErrRejected = errors.New("rejected by server")

// Session holds the negotiated parameters the client uses to build its local
// GRE interface (M4).
type Session struct {
	ClientInner netip.Addr
	ServerInner netip.Addr
	ServerOuter netip.Addr
	GREKey      uint32
	TunnelFlags uint32
	MTU         uint16
}

// Client is the dialer side of the control protocol.
type Client struct {
	Log            *slog.Logger
	ClientID       string
	Secret         string
	OuterMTU       uint16
	RequestedInner netip.Addr

	KeepaliveInterval time.Duration
	KeepaliveTimeout  time.Duration

	// br/sec are established during Handshake and reused by KeepaliveLoop so no
	// buffered bytes are lost between phases and all post-handshake traffic stays
	// encrypted.
	br  *bufio.Reader
	sec *secureChannel
}

// Handshake runs the client half of HELLO→AUTH, derives PSK AEAD keys, then
// completes session setup over the encrypted channel.
func (c *Client) Handshake(conn net.Conn) (*Session, error) {
	if !ValidClientID(c.ClientID) {
		return nil, fmt.Errorf("invalid client id %q", c.ClientID)
	}
	br := bufio.NewReader(conn)
	c.br = br
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	if err := WriteMessage(conn, &Hello{ClientID: c.ClientID}); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	chMsg, err := ReadMessage(br)
	if err != nil {
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	challenge, ok := chMsg.(*Challenge)
	if !ok {
		if td, ok := chMsg.(*Teardown); ok {
			return nil, fmt.Errorf("%w: %s", ErrRejected, td.Reason)
		}
		return nil, fmt.Errorf("expected challenge, got type %d", chMsg.Type())
	}

	clientNonce, err := auth.NewNonce()
	if err != nil {
		return nil, fmt.Errorf("generate client nonce: %w", err)
	}
	if err := WriteMessage(conn, &Auth{MAC: clientNonce[:]}); err != nil {
		return nil, fmt.Errorf("send auth: %w", err)
	}
	sec, err := newClientSecureChannel(c.Secret, c.ClientID, challenge.Nonce, clientNonce, br, conn)
	if err != nil {
		return nil, fmt.Errorf("secure channel setup: %w", err)
	}
	c.sec = sec

	if err := sec.WriteMessage(&SessionRequest{
		OuterMTU:       c.OuterMTU,
		RequestedInner: c.RequestedInner,
	}); err != nil {
		return nil, fmt.Errorf("send session request: %w", err)
	}

	replyMsg, err := sec.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("%w: server authentication failed", ErrRejected)
	}
	switch m := replyMsg.(type) {
	case *SessionReply:
		if m.Result != ResultOK {
			// Address-pool exhaustion is transient; other rejections are permanent.
			if m.Result == ResultNoAddresses {
				return nil, fmt.Errorf("session rejected: %s (%s)", m.Result, m.Message)
			}
			return nil, fmt.Errorf("%w: %s (%s)", ErrRejected, m.Result, m.Message)
		}
		if unknown := m.TunnelFlags &^ (TunnelFlagGREKey | TunnelFlagGRESeq); unknown != 0 {
			return nil, fmt.Errorf("%w: server selected unknown tunnel flags 0x%x", ErrRejected, unknown)
		}
		greKey := uint32(0)
		if m.TunnelFlags&TunnelFlagGREKey != 0 {
			if m.GREKey == 0 {
				return nil, fmt.Errorf("%w: server selected GRE keys without a key", ErrRejected)
			}
			greKey = m.GREKey
		}
		return &Session{
			ClientInner: m.ClientInner,
			ServerInner: m.ServerInner,
			ServerOuter: m.ServerOuter,
			GREKey:      greKey,
			TunnelFlags: m.TunnelFlags,
			MTU:         m.MTU,
		}, nil
	case *Teardown:
		return nil, fmt.Errorf("%w: %s", ErrRejected, m.Reason)
	default:
		return nil, fmt.Errorf("expected session reply, got type %d", replyMsg.Type())
	}
}

// KeepaliveLoop drives Echo probes and detects a dead server, returning when ctx
// is cancelled or the connection fails. It reuses the same bufio.Reader the
// Handshake used implicitly, so callers must not read from conn concurrently.
func (c *Client) KeepaliveLoop(ctx context.Context, conn net.Conn) error {
	sec := c.sec
	if sec == nil {
		return fmt.Errorf("secure channel is not established")
	}

	// Derive a context cancelled when this loop returns, so the helper goroutines
	// below exit promptly on a dropped connection instead of lingering until the
	// parent context is cancelled — otherwise every reconnect leaks a goroutine.
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sendErr := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(c.KeepaliveInterval)
		defer ticker.Stop()
		var seq uint32
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				seq++
				if err := sec.WriteMessage(&Echo{Seq: seq}); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()

	go func() {
		<-loopCtx.Done()
		// Announce shutdown to the server only on a genuine parent cancellation;
		// on a dropped connection the write would just fail harmlessly.
		if ctx.Err() != nil {
			_ = sec.WriteMessage(&Teardown{Reason: ReasonClientBye})
		}
		conn.Close()
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(c.KeepaliveTimeout))
		select {
		case err := <-sendErr:
			return err
		default:
		}
		msg, err := sec.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("keepalive read: %w", err)
		}
		if td, ok := msg.(*Teardown); ok {
			c.Log.Info("server requested teardown", "reason", td.Reason)
			return nil
		}
	}
}
