package ippool

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocateSkipsNetworkAndReserved(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00:9::/125") // 8 addresses
	server := netip.MustParseAddr("fd00:9::1")
	p, err := New(prefix, server)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	// ::0 is the network (skipped), ::1 is reserved, so first free is ::2.
	if first != netip.MustParseAddr("fd00:9::2") {
		t.Fatalf("first allocation = %s, want fd00:9::2", first)
	}
}

func TestAllocateUniqueAndExhaust(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/30") // .0 network, .1 .2 .3
	p, _ := New(prefix)
	seen := map[netip.Addr]bool{}
	for i := 0; i < 3; i++ { // .1 .2 .3 usable
		a, err := p.Allocate()
		if err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
		if seen[a] {
			t.Fatalf("duplicate allocation %s", a)
		}
		seen[a] = true
	}
	if _, err := p.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected exhaustion, got %v", err)
	}
}

func TestReleaseReuses(t *testing.T) {
	p, _ := New(netip.MustParsePrefix("10.0.0.0/30"))
	a, _ := p.Allocate()
	p.Release(a)
	b, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("expected released %s to be reused, got %s", a, b)
	}
}

func TestAllocateSpecific(t *testing.T) {
	p, _ := New(netip.MustParsePrefix("fd00:9::/112"))
	want := netip.MustParseAddr("fd00:9::42")
	if err := p.AllocateSpecific(want); err != nil {
		t.Fatal(err)
	}
	if err := p.AllocateSpecific(want); err == nil {
		t.Fatal("expected double-allocation to fail")
	}
	if err := p.AllocateSpecific(netip.MustParseAddr("fd00:8::1")); err == nil {
		t.Fatal("expected out-of-range allocation to fail")
	}
}
