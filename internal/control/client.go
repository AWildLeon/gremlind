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

	// br is the buffered reader established during Handshake and reused by
	// KeepaliveLoop so no buffered bytes are lost between the two phases.
	br *bufio.Reader
}

// Handshake runs the client half of HELLO→AUTH→SESSION over an established
// connection and returns the negotiated session.
func (c *Client) Handshake(conn net.Conn) (*Session, error) {
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

	mac := auth.Response(c.Secret, c.ClientID, challenge.Nonce)
	if err := WriteMessage(conn, &Auth{MAC: mac}); err != nil {
		return nil, fmt.Errorf("send auth: %w", err)
	}

	if err := WriteMessage(conn, &SessionRequest{
		OuterMTU:       c.OuterMTU,
		RequestedInner: c.RequestedInner,
	}); err != nil {
		return nil, fmt.Errorf("send session request: %w", err)
	}

	replyMsg, err := ReadMessage(br)
	if err != nil {
		return nil, fmt.Errorf("read session reply: %w", err)
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
		return &Session{
			ClientInner: m.ClientInner,
			ServerInner: m.ServerInner,
			ServerOuter: m.ServerOuter,
			GREKey:      m.GREKey,
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
	br := c.br
	if br == nil {
		br = bufio.NewReader(conn)
	}

	sendErr := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(c.KeepaliveInterval)
		defer ticker.Stop()
		var seq uint32
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seq++
				if err := WriteMessage(conn, &Echo{Seq: seq}); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		WriteMessage(conn, &Teardown{Reason: "client shutdown"})
		conn.Close()
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(c.KeepaliveTimeout))
		select {
		case err := <-sendErr:
			return err
		default:
		}
		msg, err := ReadMessage(br)
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
