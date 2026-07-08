// Package provisionrpc exposes the tiny, allow-listed GRE provisioning API used
// to split the Internet-facing control daemon from the privileged netlink worker.
package provisionrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"gremlind/internal/gre"
)

const defaultTimeout = 10 * time.Second

// Provisioner is the narrow interface implemented by the netlink backend.
type Provisioner interface {
	Ensure(gre.Params) error
	Remove(string) error
}

type request struct {
	Op     string     `json:"op"`
	Params gre.Params `json:"params,omitempty"`
	Name   string     `json:"name,omitempty"`
	Local  netip.Addr `json:"local,omitempty"`
}

type response struct {
	MTU   int    `json:"mtu,omitempty"`
	Error string `json:"error,omitempty"`
}

// Client implements session.Provisioner by forwarding requests to netlinkd over
// a local unix socket. It has no netlink or CAP_NET_ADMIN dependency itself.
type Client struct {
	Path string
}

func (c Client) Ensure(p gre.Params) error {
	_, err := c.call(request{Op: "ensure", Params: p})
	return err
}

func (c Client) Remove(name string) error {
	_, err := c.call(request{Op: "remove", Name: name})
	return err
}

func (c Client) OuterMTU(local netip.Addr) (int, error) {
	resp, err := c.call(request{Op: "outer_mtu", Local: local})
	if err != nil {
		return 0, err
	}
	return resp.MTU, nil
}

func (c Client) call(req request) (response, error) {
	var zero response
	conn, err := net.DialTimeout("unix", c.Path, defaultTimeout)
	if err != nil {
		return zero, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(defaultTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return zero, err
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return zero, err
	}
	if resp.Error != "" {
		return zero, errors.New(resp.Error)
	}
	return resp, nil
}

// Server is the privileged, local-only broker. It deliberately accepts only a
// tiny semantic API rather than arbitrary rtnetlink messages.
type Server struct {
	Log      *slog.Logger
	Path     string
	Mode     os.FileMode
	Group    string
	GRELocal netip.Addr // optional allow-list for tunnel outer local address
	Prov     Provisioner
	OuterMTU func(netip.Addr) (int, error)

	mu      sync.Mutex
	created map[string]struct{} // interfaces created by this broker instance
}

func (s *Server) Serve(ctx context.Context) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Mode == 0 {
		s.Mode = 0o600
	}
	if s.Prov == nil {
		return fmt.Errorf("provisionrpc: missing provisioner")
	}
	if s.OuterMTU == nil {
		s.OuterMTU = gre.OuterMTU
	}
	s.mu.Lock()
	if s.created == nil {
		s.created = make(map[string]struct{})
	}
	s.mu.Unlock()
	if err := removeStaleSocket(s.Path); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return fmt.Errorf("provisionrpc: listen: %w", err)
	}
	if s.Group != "" {
		grp, err := user.LookupGroup(s.Group)
		if err != nil {
			ln.Close()
			_ = os.Remove(s.Path)
			return fmt.Errorf("provisionrpc: lookup group %q: %w", s.Group, err)
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			ln.Close()
			_ = os.Remove(s.Path)
			return fmt.Errorf("provisionrpc: parse group %q gid %q: %w", s.Group, grp.Gid, err)
		}
		if err := os.Chown(s.Path, -1, gid); err != nil {
			ln.Close()
			_ = os.Remove(s.Path)
			return fmt.Errorf("provisionrpc: chown socket group: %w", err)
		}
	}
	if err := os.Chmod(s.Path, s.Mode); err != nil {
		ln.Close()
		_ = os.Remove(s.Path)
		return fmt.Errorf("provisionrpc: chmod socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		if st, err := os.Lstat(s.Path); err == nil && st.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(s.Path)
		}
	}()
	s.Log.Info("netlink broker listening", "socket", s.Path)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func removeStaleSocket(path string) error {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("provisionrpc: %s exists and is not a unix socket", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("provisionrpc: remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("provisionrpc: stat socket path: %w", err)
	}
	return nil
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(defaultTimeout))
	var req request
	dec := json.NewDecoder(io.LimitReader(conn, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.reply(conn, response{Error: "decode request: " + err.Error()})
		return
	}
	var resp response
	switch req.Op {
	case "ensure":
		if err := s.validateParams(req.Params); err != nil {
			resp.Error = err.Error()
		} else if err := s.Prov.Ensure(req.Params); err != nil {
			resp.Error = err.Error()
		} else {
			s.markCreated(req.Params.Name)
		}
	case "remove":
		if err := validateName(req.Name); err != nil {
			resp.Error = err.Error()
		} else if !s.wasCreated(req.Name) {
			resp.Error = "refusing to remove interface not created by this broker"
		} else if err := s.Prov.Remove(req.Name); err != nil {
			resp.Error = err.Error()
		} else {
			s.markRemoved(req.Name)
		}
	case "outer_mtu":
		if !req.Local.IsValid() || req.Local.IsMulticast() || req.Local.IsUnspecified() {
			resp.Error = "invalid local address"
		} else if s.GRELocal.IsValid() && req.Local != s.GRELocal {
			resp.Error = "local address not allowed"
		} else if mtu, err := s.OuterMTU(req.Local); err != nil {
			resp.Error = err.Error()
		} else {
			resp.MTU = mtu
		}
	default:
		resp.Error = "unknown operation"
	}
	s.reply(conn, resp)
}

func (s *Server) reply(conn net.Conn, resp response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		s.Log.Debug("netlink broker reply failed", "err", err)
	}
}

func (s *Server) markCreated(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created[name] = struct{}{}
}

func (s *Server) wasCreated(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.created[name]
	return ok
}

func (s *Server) markRemoved(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.created, name)
}

func (s *Server) validateParams(p gre.Params) error {
	if err := validateName(p.Name); err != nil {
		return err
	}
	if !p.Local.IsValid() || !p.Remote.IsValid() || p.Local.Is6() != p.Remote.Is6() {
		return fmt.Errorf("invalid outer endpoints")
	}
	if p.Local.IsMulticast() || p.Remote.IsMulticast() || p.Local.IsUnspecified() || p.Remote.IsUnspecified() {
		return fmt.Errorf("invalid outer endpoints")
	}
	if s.GRELocal.IsValid() && p.Local != s.GRELocal {
		return fmt.Errorf("outer local address not allowed")
	}
	if !p.InnerLocal.IsValid() || p.InnerLocal.IsMulticast() || p.InnerLocal.IsUnspecified() {
		return fmt.Errorf("invalid inner local address")
	}
	if p.InnerPeer.IsValid() && (p.InnerPeer.IsMulticast() || p.InnerPeer.IsUnspecified()) {
		return fmt.Errorf("invalid inner peer address")
	}
	if p.InnerPeer.IsValid() && p.InnerLocal.Is6() != p.InnerPeer.Is6() {
		return fmt.Errorf("inner address families differ")
	}
	if p.LinkLocal.IsValid() && (!p.LinkLocal.Is6() || !p.LinkLocal.IsLinkLocalUnicast()) {
		return fmt.Errorf("invalid link-local address")
	}
	if p.MTU < 576 || p.MTU > 65535 {
		return fmt.Errorf("invalid mtu")
	}
	return nil
}

func validateName(name string) error {
	// Server-side generated names are "grem" (plain GRE) or "grem" + hex key;
	// the dialer uses "grem0". Accept only that tight namespace, never generic
	// interface names or shell metacharacters.
	if name == "grem" || name == "grem0" {
		return nil
	}
	if len(name) <= len("grem") || len(name) > 15 || !strings.HasPrefix(name, "grem") {
		return fmt.Errorf("invalid interface name")
	}
	for _, r := range name[len("grem"):] {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return fmt.Errorf("invalid interface name")
	}
	return nil
}
