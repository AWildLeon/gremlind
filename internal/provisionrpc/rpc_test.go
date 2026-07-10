package provisionrpc

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gremlind/internal/gre"
)

type fakeProv struct {
	ensured gre.Params
	removed string
}

func (f *fakeProv) Ensure(p gre.Params) error { f.ensured = p; return nil }
func (f *fakeProv) Remove(name string) error  { f.removed = name; return nil }

func TestClientServerRoundTrip(t *testing.T) {
	fp := &fakeProv{}
	path := filepath.Join(t.TempDir(), "netlink.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local := netip.MustParseAddr("2001:db8::1")
	srv := &Server{
		Path:     path,
		GRELocal: local,
		Prov:     fp,
		OuterMTU: func(netip.Addr) (int, error) { return 1500, nil },
	}
	go func() { _ = srv.Serve(ctx) }()
	waitForSocket(t, path)

	c := Client{Path: path}
	mtu, err := c.OuterMTU(local)
	if err != nil {
		t.Fatalf("OuterMTU: %v", err)
	}
	if mtu != 1500 {
		t.Fatalf("mtu = %d, want 1500", mtu)
	}
	p := gre.Params{
		Name:       "grem1234",
		Local:      local,
		Remote:     netip.MustParseAddr("2001:db8::2"),
		Key:        1234,
		MTU:        1400,
		InnerLocal: netip.MustParseAddr("10.0.0.1"),
		InnerPeer:  netip.MustParseAddr("10.0.0.2"),
		LinkLocal:  gre.ServerLinkLocal,
	}
	if err := c.Ensure(p); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if fp.ensured.Name != p.Name || fp.ensured.Remote != p.Remote {
		t.Fatalf("ensured = %+v, want %+v", fp.ensured, p)
	}
	if err := c.Remove(p.Name); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if fp.removed != p.Name {
		t.Fatalf("removed = %q, want %q", fp.removed, p.Name)
	}
}

func TestServerRejectsInvalidAndUnknownRemove(t *testing.T) {
	fp := &fakeProv{}
	path := filepath.Join(t.TempDir(), "netlink.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Path: path, Prov: fp}
	go func() { _ = srv.Serve(ctx) }()
	waitForSocket(t, path)

	c := Client{Path: path}
	if err := c.Remove("eth0"); err == nil {
		t.Fatal("Remove eth0 succeeded, want rejection")
	}
	if err := c.Remove("gremdeadbeef"); err == nil {
		t.Fatal("Remove unknown broker-owned name succeeded, want rejection")
	}
	if fp.removed != "" {
		t.Fatalf("privileged backend was called for rejected name %q", fp.removed)
	}
}

func TestServerAllowsPinnedInterfaceNames(t *testing.T) {
	fp := &fakeProv{}
	path := filepath.Join(t.TempDir(), "netlink.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local := netip.MustParseAddr("2001:db8::1")
	srv := &Server{
		Path:       path,
		GRELocal:   local,
		Prov:       fp,
		AllowNames: []string{"gremlin-a"},
	}
	go func() { _ = srv.Serve(ctx) }()
	waitForSocket(t, path)

	c := Client{Path: path}
	base := gre.Params{
		Local:      local,
		Remote:     netip.MustParseAddr("2001:db8::2"),
		MTU:        1400,
		InnerLocal: netip.MustParseAddr("10.0.0.1"),
		InnerPeer:  netip.MustParseAddr("10.0.0.2"),
		LinkLocal:  gre.ServerLinkLocal,
	}

	allowed := base
	allowed.Name = "gremlin-a"
	if err := c.Ensure(allowed); err != nil {
		t.Fatalf("Ensure allowlisted name: %v", err)
	}
	if fp.ensured.Name != "gremlin-a" {
		t.Fatalf("ensured = %q, want gremlin-a", fp.ensured.Name)
	}
	if err := c.Remove("gremlin-a"); err != nil {
		t.Fatalf("Remove allowlisted name: %v", err)
	}

	// A custom name outside the allow-list (and the grem namespace) is rejected
	// before reaching the privileged backend.
	fp.ensured = gre.Params{}
	rejected := base
	rejected.Name = "eth0"
	if err := c.Ensure(rejected); err == nil {
		t.Fatal("Ensure of non-allowlisted eth0 succeeded, want rejection")
	}
	if fp.ensured.Name != "" {
		t.Fatalf("privileged backend called for rejected name %q", fp.ensured.Name)
	}
}

func TestServerRejectsUnsafeAllowName(t *testing.T) {
	fp := &fakeProv{}
	path := filepath.Join(t.TempDir(), "netlink.sock")
	srv := &Server{Path: path, Prov: fp, AllowNames: []string{"bad/name"}}
	if err := srv.Serve(context.Background()); err == nil {
		t.Fatal("Serve accepted an unsafe AllowNames entry, want error")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(path); err == nil && st.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become ready", path)
}
