package session

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"gremlind/internal/control"
	"gremlind/internal/gre"
	"gremlind/internal/ippool"
)

type fakeProv struct {
	ensured []gre.Params
	removed []string
}

func (f *fakeProv) Ensure(p gre.Params) error { f.ensured = append(f.ensured, p); return nil }
func (f *fakeProv) Remove(n string) error     { f.removed = append(f.removed, n); return nil }

func newTestManager(t *testing.T, outerMTU, cap int, prov Provisioner) (*Manager, *ippool.Pool) {
	t.Helper()
	server := netip.MustParseAddr("fd00:9::1")
	pool, err := ippool.New(netip.MustParsePrefix("fd00:9::/112"), server)
	if err != nil {
		t.Fatal(err)
	}
	m := newWith(Config{
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Pool:        pool,
		ServerInner: server,
		GRELocal:    netip.MustParseAddr("2001:db8::10"),
		OuterMTU:    outerMTU,
		MTUCap:      cap,
		UseGREKey:   true,
	}, prov)
	return m, pool
}

// newTestManagerWithLeases mirrors the server startup path: static leases are
// pinned in the pool at construction and threaded into the manager.
func newTestManagerWithLeases(t *testing.T, leases map[string]netip.Addr, prov Provisioner) (*Manager, *ippool.Pool) {
	t.Helper()
	m, pool := newTestManager(t, 1500, 0, prov)
	for _, addr := range leases {
		if err := pool.Pin(addr); err != nil {
			t.Fatal(err)
		}
	}
	m.staticLease = leases
	return m, pool
}

func TestEstablishUsesPinnedInterfaceNamePerClient(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	m.ifNames = map[string]string{"site-a": "gremlin-a"}

	// Pinned client gets its fixed name.
	if _, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-a",
		ClientOuter: netip.MustParseAddr("2001:db8::20"),
		OuterMTU:    1500,
	}); err != nil || res != control.ResultOK {
		t.Fatalf("establish site-a: res=%s err=%v", res, err)
	}
	if len(prov.ensured) != 1 || prov.ensured[0].Name != "gremlin-a" {
		t.Fatalf("expected Ensure for gremlin-a, got %+v", prov.ensured)
	}

	// Unpinned client keeps the default grem+key naming.
	if _, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-b",
		ClientOuter: netip.MustParseAddr("2001:db8::21"),
		OuterMTU:    1500,
	}); err != nil || res != control.ResultOK {
		t.Fatalf("establish site-b: res=%s err=%v", res, err)
	}
	nameB := prov.ensured[1].Name
	if !strings.HasPrefix(nameB, "grem") || nameB == "gremlin-a" {
		t.Errorf("site-b iface = %q, want default grem-prefixed name", nameB)
	}
}

func TestEstablishNegotiatesMTUAndProvisions(t *testing.T) {
	prov := &fakeProv{}
	m, pool := newTestManager(t, 1500, 0, prov)

	grant, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-a",
		ClientOuter: netip.MustParseAddr("2001:db8::20"),
		OuterMTU:    1500,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish: res=%s err=%v", res, err)
	}
	// v6 outer overhead = 40 + 8 = 48 → 1500 - 48 = 1452.
	if grant.MTU != 1452 {
		t.Errorf("negotiated MTU = %d, want 1452", grant.MTU)
	}
	if grant.ClientInner != netip.MustParseAddr("fd00:9::2") {
		t.Errorf("client inner = %s, want fd00:9::2", grant.ClientInner)
	}
	if len(prov.ensured) != 1 || prov.ensured[0].Key != grant.GREKey {
		t.Fatalf("expected one Ensure with key %d, got %+v", grant.GREKey, prov.ensured)
	}
	if pool.InUse() != 1 {
		t.Errorf("pool in use = %d, want 1", pool.InUse())
	}

	m.Teardown(control.SessionParams{}, grant)
	if len(prov.removed) != 1 {
		t.Errorf("expected one Remove, got %v", prov.removed)
	}
	if pool.InUse() != 0 {
		t.Errorf("pool should be empty after teardown, in use = %d", pool.InUse())
	}
}

func TestEstablishCanDisableGREKeys(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	m.useGREKey = false

	grant, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-a",
		ClientOuter: netip.MustParseAddr("2001:db8::20"),
		OuterMTU:    1500,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish: res=%s err=%v", res, err)
	}
	if grant.GREKey != 0 {
		t.Fatalf("grant GRE key = %d, want 0 when disabled", grant.GREKey)
	}
	if len(prov.ensured) != 1 || prov.ensured[0].Key != 0 {
		t.Fatalf("provisioned key = %+v, want key 0", prov.ensured)
	}
	// v6 outer overhead without key = 40 + 4 = 44 → 1500 - 44 = 1456.
	if grant.MTU != 1456 {
		t.Fatalf("MTU = %d, want 1456", grant.MTU)
	}
	m.Teardown(control.SessionParams{}, grant)
	if len(prov.removed) != 1 {
		t.Fatalf("expected teardown to remove unkeyed session, removed=%v", prov.removed)
	}
}

func TestEstablishCanEnableGRESequenceNumbers(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	m.useGRESeq = true

	grant, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-a",
		ClientOuter: netip.MustParseAddr("2001:db8::20"),
		OuterMTU:    1500,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish: res=%s err=%v", res, err)
	}
	if grant.TunnelFlags&control.TunnelFlagGRESeq == 0 {
		t.Fatalf("TunnelFlags = 0x%x, want GRE seq", grant.TunnelFlags)
	}
	if len(prov.ensured) != 1 || !prov.ensured[0].Seq {
		t.Fatalf("provisioned params = %+v, want Seq", prov.ensured)
	}
	// v6 outer overhead = 40 + base GRE 4 + key 4 + seq 4 = 52 → 1448.
	if grant.MTU != 1448 {
		t.Fatalf("MTU = %d, want 1448", grant.MTU)
	}
}

func TestFOUForcesGREKeyAndSequenceOff(t *testing.T) {
	prov := &fakeProv{}
	server := netip.MustParseAddr("fd00:9::1")
	pool, err := ippool.New(netip.MustParsePrefix("fd00:9::/112"), server)
	if err != nil {
		t.Fatal(err)
	}
	m := newWith(Config{
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Pool:        pool,
		ServerInner: server,
		GRELocal:    netip.MustParseAddr("2001:db8::10"),
		OuterMTU:    1500,
		UseGREKey:   true,
		UseGRESeq:   true,
		FOUPort:     5555,
	}, prov)

	grant, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-a",
		ClientOuter: netip.MustParseAddr("2001:db8::20"),
		OuterMTU:    1500,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish: res=%s err=%v", res, err)
	}
	if grant.GREKey != 0 || grant.TunnelFlags&(control.TunnelFlagGREKey|control.TunnelFlagGRESeq) != 0 {
		t.Fatalf("grant key=%d flags=0x%x, want no key/seq", grant.GREKey, grant.TunnelFlags)
	}
	if len(prov.ensured) != 1 || prov.ensured[0].Key != 0 || prov.ensured[0].Seq {
		t.Fatalf("provisioned params = %+v, want no key/seq", prov.ensured)
	}
}

func TestNegotiateMTUTakesMinimumAndCap(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 1400, prov)

	// Client outer MTU (9000) is larger, so server's 1500 wins → 1452, capped to 1400.
	if got := m.negotiateMTU(9000); got != 1400 {
		t.Errorf("mtu = %d, want 1400 (cap)", got)
	}
	// Client outer smaller than server → client drives it: 1400 - 48 = 1352.
	m.mtuCap = 0
	if got := m.negotiateMTU(1400); got != 1352 {
		t.Errorf("mtu = %d, want 1352", got)
	}
	// A bogus tiny client MTU must not underflow or wrap when later encoded.
	if got := m.negotiateMTU(1); got != 1280 {
		t.Errorf("tiny v6 mtu = %d, want IPv6 minimum 1280", got)
	}
}

func TestNegotiateMTUClampsTinyIPv4OuterMTU(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	m.greLocal = netip.MustParseAddr("203.0.113.10")

	if got := m.negotiateMTU(1); got != 576 {
		t.Errorf("tiny v4 mtu = %d, want IPv4 minimum 576", got)
	}
}

func TestExpiredStickyLeaseIsPurged(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	m.leaseTTL = time.Second
	m.leases["old"] = netip.MustParseAddr("fd00:9::42")
	m.leaseTimes["old"] = time.Now().Add(-2 * time.Second)

	m.mu.Lock()
	m.purgeExpiredLeasesLocked(time.Now())
	m.mu.Unlock()

	if _, ok := m.leases["old"]; ok {
		t.Fatal("expired sticky lease was not purged")
	}
}

func TestStickyLeaseReusedAfterTeardown(t *testing.T) {
	prov := &fakeProv{}
	m, pool := newTestManager(t, 1500, 0, prov)
	ctx := context.Background()

	params := control.SessionParams{ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500}
	grant1, _, err := m.Establish(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	m.Teardown(params, grant1)
	if pool.InUse() != 0 {
		t.Fatalf("pool not empty after teardown: %d", pool.InUse())
	}

	grant2, _, err := m.Establish(ctx, params)
	if err != nil {
		t.Fatal(err)
	}
	if grant2.ClientInner != grant1.ClientInner {
		t.Errorf("sticky lease broken: first=%s second=%s", grant1.ClientInner, grant2.ClientInner)
	}
}

func TestStickyLeaseCannotBeClaimedByDifferentClient(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	ctx := context.Background()

	siteA := control.SessionParams{ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500}
	grantA, _, err := m.Establish(ctx, siteA)
	if err != nil {
		t.Fatal(err)
	}
	m.Teardown(siteA, grantA)

	siteB := control.SessionParams{
		ClientID:       "site-b",
		ClientOuter:    netip.MustParseAddr("2001:db8::30"),
		OuterMTU:       1500,
		RequestedInner: grantA.ClientInner,
	}
	grantB, res, err := m.Establish(ctx, siteB)
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish site-b: res=%s err=%v", res, err)
	}
	if grantB.ClientInner == grantA.ClientInner {
		t.Fatalf("site-b claimed site-a sticky lease %s", grantA.ClientInner)
	}

	grantA2, res, err := m.Establish(ctx, siteA)
	if err != nil || res != control.ResultOK {
		t.Fatalf("re-establish site-a: res=%s err=%v", res, err)
	}
	if grantA2.ClientInner != grantA.ClientInner {
		t.Fatalf("site-a did not get its reserved lease back: got %s want %s", grantA2.ClientInner, grantA.ClientInner)
	}
}

func TestStaticLeaseHonouredOnFirstConnect(t *testing.T) {
	prov := &fakeProv{}
	pinned := netip.MustParseAddr("fd00:9::42")
	m, pool := newTestManagerWithLeases(t, map[string]netip.Addr{"site-a": pinned}, prov)

	grant, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "site-a",
		ClientOuter: netip.MustParseAddr("2001:db8::20"),
		OuterMTU:    1500,
		// A conflicting request from the client loses to the server's config.
		RequestedInner: netip.MustParseAddr("fd00:9::99"),
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish site-a: res=%s err=%v", res, err)
	}
	if grant.ClientInner != pinned {
		t.Errorf("client inner = %s, want static lease %s", grant.ClientInner, pinned)
	}
	if prov.ensured[0].InnerPeer != pinned {
		t.Errorf("provisioned inner peer = %s, want %s", prov.ensured[0].InnerPeer, pinned)
	}
	// Claimed through the pool, so in-use bookkeeping stays correct.
	if pool.InUse() != 1 {
		t.Errorf("pool in use = %d, want 1", pool.InUse())
	}
}

func TestStaticLeaseNotHandedToDynamicClient(t *testing.T) {
	prov := &fakeProv{}
	// fd00:9::2 is the first address dynamic allocation would otherwise pick.
	pinned := netip.MustParseAddr("fd00:9::2")
	m, _ := newTestManagerWithLeases(t, map[string]netip.Addr{"site-a": pinned}, prov)
	ctx := context.Background()

	grantB, res, err := m.Establish(ctx, control.SessionParams{
		ClientID: "site-b", ClientOuter: netip.MustParseAddr("2001:db8::30"), OuterMTU: 1500,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish site-b: res=%s err=%v", res, err)
	}
	if grantB.ClientInner == pinned {
		t.Fatalf("dynamic client got site-a's static lease %s", pinned)
	}

	// Nor can a dynamic client ask for it explicitly.
	grantC, res, err := m.Establish(ctx, control.SessionParams{
		ClientID: "site-c", ClientOuter: netip.MustParseAddr("2001:db8::31"), OuterMTU: 1500,
		RequestedInner: pinned,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish site-c: res=%s err=%v", res, err)
	}
	if grantC.ClientInner == pinned {
		t.Fatalf("site-c claimed site-a's static lease %s by request", pinned)
	}

	// site-a still gets it on its own first connect.
	grantA, res, err := m.Establish(ctx, control.SessionParams{
		ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500,
	})
	if err != nil || res != control.ResultOK {
		t.Fatalf("establish site-a: res=%s err=%v", res, err)
	}
	if grantA.ClientInner != pinned {
		t.Errorf("site-a inner = %s, want static lease %s", grantA.ClientInner, pinned)
	}
}

func TestConflictingStaticLeaseFailsInsteadOfFallingBack(t *testing.T) {
	addr := netip.MustParseAddr("fd00:9::42")

	// Two clients configured for the same address. Config validation rejects
	// this, but if it is reached anyway neither client may be quietly moved to a
	// dynamic address — the connection fails instead.
	t.Run("configured for two clients", func(t *testing.T) {
		prov := &fakeProv{}
		m, pool := newTestManagerWithLeases(t, map[string]netip.Addr{"site-a": addr, "site-b": addr}, prov)
		for _, id := range []string{"site-a", "site-b"} {
			_, res, err := m.Establish(context.Background(), control.SessionParams{
				ClientID: id, ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500,
			})
			if err == nil {
				t.Fatalf("establish %s: expected the conflicting static lease to fail the session", id)
			}
			if res != control.ResultNoAddresses {
				t.Errorf("establish %s: result = %s, want %s", id, res, control.ResultNoAddresses)
			}
		}
		if got := len(m.Sessions()); got != 0 {
			t.Errorf("active sessions = %d, want 0 (no dynamic fallback session)", got)
		}
		if pool.InUse() != 0 {
			t.Errorf("pool in use = %d, want 0 (no dynamic fallback address)", pool.InUse())
		}
	})

	// The address is already taken in the pool (a stale allocation).
	t.Run("already allocated", func(t *testing.T) {
		prov := &fakeProv{}
		m, pool := newTestManagerWithLeases(t, map[string]netip.Addr{"site-a": addr}, prov)
		if err := pool.AllocateSpecific(addr); err != nil {
			t.Fatal(err)
		}

		_, res, err := m.Establish(context.Background(), control.SessionParams{
			ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500,
		})
		if err == nil {
			t.Fatal("expected an unavailable static lease to fail the session")
		}
		if res != control.ResultNoAddresses {
			t.Errorf("result = %s, want %s", res, control.ResultNoAddresses)
		}
		if got := len(m.Sessions()); got != 0 {
			t.Errorf("active sessions = %d, want 0 (no dynamic fallback session)", got)
		}
		if pool.InUse() != 1 {
			t.Errorf("pool in use = %d, want 1 (no dynamic fallback address)", pool.InUse())
		}
	})
}

func TestStaticLeaseSurvivesEvictionAndLeaseExpiry(t *testing.T) {
	prov := &fakeProv{}
	pinned := netip.MustParseAddr("fd00:9::42")
	m, pool := newTestManagerWithLeases(t, map[string]netip.Addr{"site-a": pinned}, prov)
	ctx := context.Background()

	p1 := control.SessionParams{ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500}
	grant1, _, err := m.Establish(ctx, p1)
	if err != nil {
		t.Fatal(err)
	}

	// Roaming reconnect from a new outer IP without a teardown: the old session
	// is evicted and the same pinned address is re-claimed.
	p2 := control.SessionParams{ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::99"), OuterMTU: 1500}
	grant2, res, err := m.Establish(ctx, p2)
	if err != nil || res != control.ResultOK {
		t.Fatalf("roaming re-establish: res=%s err=%v", res, err)
	}
	if grant2.ClientInner != pinned || grant1.ClientInner != pinned {
		t.Fatalf("roaming changed inner IP: %s -> %s, want %s throughout", grant1.ClientInner, grant2.ClientInner, pinned)
	}
	if pool.InUse() != 1 {
		t.Errorf("pool in use = %d, want 1 after eviction", pool.InUse())
	}

	// Full teardown, then a sticky lease lapse: neither may move the address.
	m.Teardown(p2, grant2)
	if pool.InUse() != 0 {
		t.Fatalf("pool not empty after teardown: %d", pool.InUse())
	}
	m.leaseTTL = time.Second
	m.mu.Lock()
	m.leaseTimes["site-a"] = time.Now().Add(-2 * time.Second)
	m.mu.Unlock()

	grant3, res, err := m.Establish(ctx, p1)
	if err != nil || res != control.ResultOK {
		t.Fatalf("re-establish after lease expiry: res=%s err=%v", res, err)
	}
	if grant3.ClientInner != pinned {
		t.Errorf("inner after lease expiry = %s, want static lease %s", grant3.ClientInner, pinned)
	}
}

func TestRoamingEvictsStaleSessionAndKeepsInnerIP(t *testing.T) {
	prov := &fakeProv{}
	m, pool := newTestManager(t, 1500, 0, prov)
	ctx := context.Background()

	// First session from outer IP A.
	p1 := control.SessionParams{ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::20"), OuterMTU: 1500}
	grant1, _, err := m.Establish(ctx, p1)
	if err != nil {
		t.Fatal(err)
	}

	// Same client reconnects from a NEW outer IP B, without tearing down first.
	p2 := control.SessionParams{ClientID: "site-a", ClientOuter: netip.MustParseAddr("2001:db8::99"), OuterMTU: 1500}
	grant2, _, err := m.Establish(ctx, p2)
	if err != nil {
		t.Fatal(err)
	}

	if grant2.ClientInner != grant1.ClientInner {
		t.Errorf("roaming changed inner IP: %s -> %s", grant1.ClientInner, grant2.ClientInner)
	}
	if grant2.GREKey == grant1.GREKey {
		t.Errorf("expected a fresh GRE key after roaming, got %d twice", grant2.GREKey)
	}
	// Old interface must have been removed by eviction.
	oldIf := fmt.Sprintf("grem%x", grant1.GREKey)
	if !slices.Contains(prov.removed, oldIf) {
		t.Errorf("stale interface %s was not removed; removed=%v", oldIf, prov.removed)
	}
	// Exactly one active session and one address in use.
	if got := len(m.Sessions()); got != 1 {
		t.Errorf("active sessions = %d, want 1", got)
	}
	if pool.InUse() != 1 {
		t.Errorf("pool in use = %d, want 1", pool.InUse())
	}

	// The stale connection's teardown arrives late: it must be a no-op and must
	// NOT release the inner IP now owned by the new session.
	m.Teardown(p1, grant1)
	if pool.InUse() != 1 {
		t.Errorf("stale teardown corrupted the pool: in use = %d, want 1", pool.InUse())
	}
	if got := len(m.Sessions()); got != 1 {
		t.Errorf("stale teardown removed the live session: sessions = %d, want 1", got)
	}

	// The live session's own teardown frees everything.
	m.Teardown(p2, grant2)
	if pool.InUse() != 0 {
		t.Errorf("pool not empty after live teardown: %d", pool.InUse())
	}
}

func TestOuterFamilyMismatchRejected(t *testing.T) {
	prov := &fakeProv{}
	m, _ := newTestManager(t, 1500, 0, prov)
	_, res, err := m.Establish(context.Background(), control.SessionParams{
		ClientID:    "v4client",
		ClientOuter: netip.MustParseAddr("203.0.113.5"), // v4 vs v6 server
		OuterMTU:    1500,
	})
	if res != control.ResultUnsupported || err == nil {
		t.Fatalf("expected unsupported result, got res=%s err=%v", res, err)
	}
}
