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

	// FOUSport/FOUDport wrap the GRE packet in a UDP header (Foo-over-UDP)
	// when FOUDport is non-zero — outer traffic then looks like plain UDP,
	// which passes through NAT/firewalls/ISPs that block raw GRE (protocol
	// 47) outright. FOUSport is this end's own local FOU port (also the port
	// EnsureFOUReceive must be listening on to decapsulate the peer's
	// traffic); FOUDport is the peer's listening port. Both zero disables
	// FOU — the tunnel carries plain GRE as before.
	FOUSport uint16
	FOUDport uint16
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
	return OverheadWithFOU(outer, keyed, seq, false)
}

// OverheadWithFOU is OverheadWithOptions plus the extra 8-byte UDP header
// when the tunnel is wrapped in Foo-over-UDP (see Params.FOUDport).
func OverheadWithFOU(outer netip.Addr, keyed, seq, fou bool) int {
	greHeader := 4 // base GRE header
	if keyed {
		greHeader += 4 // key field
	}
	if seq {
		greHeader += 4 // sequence-number field
	}
	overhead := greHeader
	if outer.Is6() {
		overhead += 40 // IPv6 outer header
	} else {
		overhead += 20 // IPv4 outer header
	}
	if fou {
		overhead += 8 // UDP header
	}
	return overhead
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

// OuterMTU returns the MTU of the interface that owns the local outer address.
func OuterMTU(local netip.Addr) (int, error) {
	return linkMTUByAddr(local)
}

// OuterMTUForPath returns the kernel route MTU for packets from local to remote,
// falling back to the egress link MTU when the route has no explicit/cached PMTU.
func OuterMTUForPath(local, remote netip.Addr) (int, error) {
	return pathMTU(local, remote)
}
