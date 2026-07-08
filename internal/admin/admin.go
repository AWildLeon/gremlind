// Package admin exposes a minimal unix-socket management API: connecting to the
// socket yields a JSON snapshot of the active sessions. It backs `gremlind status`.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"gremlind/internal/session"
)

// Serve listens on a unix socket and writes a JSON array of the current
// sessions to each connection. It returns when ctx is cancelled.
func Serve(ctx context.Context, log *slog.Logger, path string, snapshot func() []session.Entry) error {
	return ServeWithOptions(ctx, log, Options{Path: path, Mode: 0o600}, snapshot)
}

// Options controls admin socket filesystem permissions.
type Options struct {
	Path  string
	Mode  os.FileMode
	Group string
}

// ServeWithOptions is like Serve, with configurable socket mode and group.
func ServeWithOptions(ctx context.Context, log *slog.Logger, opts Options, snapshot func() []session.Entry) error {
	path := opts.Path
	mode := opts.Mode
	if mode == 0 {
		mode = 0o600
	}
	// Remove only a stale unix socket from a previous run. Refuse to unlink any
	// other filesystem object at the configured path.
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("admin: %s exists and is not a unix socket", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("admin: remove stale socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("admin: stat socket path: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("admin: listen: %w", err)
	}
	if opts.Group != "" {
		grp, err := user.LookupGroup(opts.Group)
		if err != nil {
			ln.Close()
			_ = os.Remove(path)
			return fmt.Errorf("admin: lookup group %q: %w", opts.Group, err)
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			ln.Close()
			_ = os.Remove(path)
			return fmt.Errorf("admin: parse group %q gid %q: %w", opts.Group, grp.Gid, err)
		}
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			_ = os.Remove(path)
			return fmt.Errorf("admin: chown socket group: %w", err)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		_ = os.Remove(path)
		return fmt.Errorf("admin: chmod socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
			os.Remove(path)
		}
	}()
	log.Info("admin socket listening", "path", path)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			// Bound the write so a local client that connects but never reads
			// cannot pin this goroutine indefinitely.
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := json.NewEncoder(c).Encode(snapshot()); err != nil {
				log.Debug("admin encode failed", "err", err)
			}
		}(conn)
	}
}

// Query connects to the admin socket and returns the session snapshot.
func Query(path string) ([]session.Entry, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var entries []session.Entry
	if err := json.NewDecoder(conn).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}
