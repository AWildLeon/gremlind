// Package gre manages the GRE data-plane interfaces via a small, dependency-free
// rtnetlink layer (see netlink_linux.go). It selects ip6gre for IPv6 outer
// endpoints (the default) and gre for IPv4, and computes the tunnel MTU overhead
// for negotiation.
package gre

import (
	"fmt"
	"net/netip"
	"strings"
)

// Deterministic link-local addresses assigned per tunnel by role. Every GRE
// interface is its own link, so reusing the same pair on all tunnels is
// collision-free and maximally predictable: the server neighbour is always
// fe80::1, the client neighbour always fe80::2.
var (
	ServerLinkLocal = netip.MustParseAddr("fe80::1")
	ClientLinkLocal = netip.MustParseAddr("fe80::2")
)

// in6AddrGenModeNone disables the kernel's automatic (random EUI64) link-local
// generation (IN6_ADDR_GEN_MODE_NONE).
const in6AddrGenModeNone = 1

// Params fully describes one GRE tunnel interface.
type Params struct {
	Name       string     // interface name (<= 15 chars)
	Local      netip.Addr // outer local endpoint
	Remote     netip.Addr // outer remote endpoint
	Key        uint32     // GRE key (I/O); zero disables GRE key fields
	Seq        bool       // enable GRE sequence number fields (both directions)
	MTU        int        // interface MTU (negotiated)
	InnerLocal netip.Addr // inner address assigned on this interface
	InnerPeer  netip.Addr // inner address of the tunnel peer (routed on-link)
	LinkLocal  netip.Addr // deterministic fe80:: address; zero keeps kernel default
}

// Overhead returns the per-packet encapsulation overhead in bytes for an outer
// endpoint of the given family. keyed defaults to true for compatibility.
func Overhead(outer netip.Addr, keyed ...bool) int {
	useKey := len(keyed) == 0 || keyed[0]
	return OverheadWithOptions(outer, useKey, false)
}

// OverheadWithOptions returns the GRE+outer-IP overhead for explicit GRE key and
// sequence-number settings.
func OverheadWithOptions(outer netip.Addr, keyed, seq bool) int {
	greHeader := 4 // base GRE header
	if keyed {
		greHeader += 4 // key field
	}
	if seq {
		greHeader += 4 // sequence-number field
	}
	if outer.Is6() {
		return 40 + greHeader // IPv6 outer header
	}
	return 20 + greHeader // IPv4 outer header
}

func hostBits(a netip.Addr) int {
	if a.Is4() {
		return 32
	}
	return 128
}

// Ensure creates the GRE interface described by p, assigns its inner address and
// deterministic link-local, routes the peer's inner address on-link, sets the
// MTU and brings it up. Any leftover interface of the same name is removed first.
func Ensure(p Params) error {
	if p.Local.Is6() != p.Remote.Is6() {
		return fmt.Errorf("gre: outer local/remote address families differ (%s vs %s)", p.Local, p.Remote)
	}
	// Clean up any leftover interface with this name from a prior crash.
	if idx, err := linkIndex(p.Name); err == nil {
		_ = linkDel(idx)
	}

	if err := createGRE(p); err != nil {
		return fmt.Errorf("gre: create %s: %w", p.Name, err)
	}
	idx, err := linkIndex(p.Name)
	if err != nil {
		return fmt.Errorf("gre: locate new interface %s: %w", p.Name, err)
	}

	// Unwind on any failure so we never leak a half-configured link.
	cleanup := func(cause error) error {
		_ = linkDel(idx)
		return cause
	}

	// scopeLink (253) keeps the fe80:: address link-scoped.
	const scopeLink = 253
	if p.LinkLocal.IsValid() {
		// Suppress the kernel's random link-local before assigning ours.
		if err := setAddrGenModeNone(idx); err != nil {
			return cleanup(fmt.Errorf("gre: disable addr autogen on %s: %w", p.Name, err))
		}
		if err := addrAdd(idx, p.LinkLocal, 64, scopeLink); err != nil {
			return cleanup(fmt.Errorf("gre: assign link-local %s: %w", p.LinkLocal, err))
		}
	}
	if err := addrAdd(idx, p.InnerLocal, hostBits(p.InnerLocal), 0 /*global*/); err != nil {
		return cleanup(fmt.Errorf("gre: assign %s: %w", p.InnerLocal, err))
	}
	if err := linkSetUp(idx); err != nil {
		return cleanup(fmt.Errorf("gre: set up %s: %w", p.Name, err))
	}
	if p.InnerPeer.IsValid() {
		if err := routeAdd(idx, p.InnerPeer, hostBits(p.InnerPeer)); err != nil {
			return cleanup(fmt.Errorf("gre: route to peer %s: %w", p.InnerPeer, err))
		}
	}
	return nil
}

// Remove deletes the named GRE interface. A missing interface is not an error.
func Remove(name string) error {
	idx, err := linkIndex(name)
	if err != nil {
		return nil // already gone
	}
	if err := linkDel(idx); err != nil {
		return fmt.Errorf("gre: delete %s: %w", name, err)
	}
	return nil
}

// RemovePrefix deletes every interface whose name starts with prefix. It is used
// by netlinkd on startup to clean stale gremlind-owned links after crashes.
func RemovePrefix(prefix string) ([]string, error) {
	links, err := dumpLinks()
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, li := range links {
		if !strings.HasPrefix(li.name, prefix) {
			continue
		}
		if err := linkDel(li.index); err != nil {
			return removed, fmt.Errorf("gre: delete %s: %w", li.name, err)
		}
		removed = append(removed, li.name)
	}
	return removed, nil
}

// isGREKind reports whether an rtnetlink IFLA_INFO_KIND names a GRE tunnel, the
// only link type gremlind ever creates (see createGRE).
func isGREKind(kind string) bool { return kind == "gre" || kind == "ip6gre" }

// RemoveNamedGRE deletes any leftover interface whose name is in names, but only
// when that interface is actually a GRE tunnel. Operator-pinned names (unlike
// the reserved "grem" prefix) can coincide with unrelated system interfaces, so
// the kind check ensures netlinkd startup cleanup never tears down a same-named
// non-GRE device such as a real wg0 or eth0.
func RemoveNamedGRE(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	links, err := dumpLinks()
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, li := range links {
		if _, ok := want[li.name]; !ok || !isGREKind(li.kind) {
			continue
		}
		if err := linkDel(li.index); err != nil {
			return removed, fmt.Errorf("gre: delete %s: %w", li.name, err)
		}
		removed = append(removed, li.name)
	}
	return removed, nil
}

// OuterMTU returns the MTU of the interface that owns the local outer address,
// letting the server contribute its real link MTU to negotiation.
func OuterMTU(local netip.Addr) (int, error) {
	return linkMTUByAddr(local)
}
