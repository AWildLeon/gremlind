package admin

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gremlind/internal/session"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestServeRefusesToRemoveNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	if err := os.WriteFile(path, []byte("do not remove"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Serve(context.Background(), testLogger(), path, func() []session.Entry { return nil })
	if err == nil {
		t.Fatal("expected error for non-socket path")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("non-socket path was removed: %v", statErr)
	}
}

func TestServeCreatesPrivateSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, testLogger(), path, func() []session.Entry { return nil })
	}()

	deadline := time.Now().Add(time.Second)
	for {
		st, err := os.Lstat(path)
		if err == nil {
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("socket mode = %o, want 600", st.Mode().Perm())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket was not created: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error after cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after cancel")
	}
}
