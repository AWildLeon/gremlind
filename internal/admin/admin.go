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

	"gremlind/internal/session"
)

// Serve listens on a unix socket and writes a JSON array of the current
// sessions to each connection. It returns when ctx is cancelled.
func Serve(ctx context.Context, log *slog.Logger, path string, snapshot func() []session.Entry) error {
	// Remove a stale socket from a previous run.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("admin: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("admin: listen: %w", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(path)
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
