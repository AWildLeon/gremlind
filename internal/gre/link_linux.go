// Package gre manages the GRE data-plane interfaces via netlink. It selects
// ip6gre for IPv6 outer endpoints (the default) and ip_gre for IPv4, and it
// computes the tunnel MTU overhead for negotiation.
package gre

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// Params fully describes one GRE tunnel interface.
type Params struct {
	Name       string     // interface name (<= 15 chars)
	Local      netip.Addr // outer local endpoint
	Remote     netip.Addr // outer remote endpoint
	Key        uint32     // GRE key (I/O), must be non-zero to demux
	MTU        int        // interface MTU (negotiated)
	InnerLocal netip.Addr // inner address assigned on this interface
	InnerPeer  netip.Addr // inner address of the tunnel peer (routed on-link)
}

// Overhead returns the per-packet encapsulation overhead in bytes for an outer
// endpoint of the given family, with a GRE key always present (+4).
func Overhead(outer netip.Addr) int {
	const greWithKey = 4 + 4 // base GRE header + key field
	if outer.Is6() {
		return 40 + greWithKey // IPv6 outer header
	}
	return 20 + greWithKey // IPv4 outer header
}

// Ensure creates the GRE interface described by p, assigns its inner address,
// routes the peer's inner address on-link, sets the MTU and brings it up. It is
// idempotent to the extent of removing a stale interface of the same name first.
func Ensure(p Params) error {
	if p.Local.Is6() != p.Remote.Is6() {
		return fmt.Errorf("gre: outer local/remote address families differ (%s vs %s)", p.Local, p.Remote)
	}
	// Clean up any leftover interface with this name from a prior crash.
	if existing, err := netlink.LinkByName(p.Name); err == nil {
		_ = netlink.LinkDel(existing)
	}

	link := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{Name: p.Name, MTU: p.MTU},
		Local:     p.Local.AsSlice(),
		Remote:    p.Remote.AsSlice(),
		IKey:      p.Key,
		OKey:      p.Key,
	}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("gre: create %s: %w", p.Name, err)
	}

	// From here on, unwind on failure so we don't leak a half-configured link.
	cleanup := func(cause error) error {
		_ = netlink.LinkDel(link)
		return cause
	}

	addr := &netlink.Addr{IPNet: hostNet(p.InnerLocal)}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return cleanup(fmt.Errorf("gre: assign %s: %w", p.InnerLocal, err))
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return cleanup(fmt.Errorf("gre: set up %s: %w", p.Name, err))
	}

	if p.InnerPeer.IsValid() {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       hostNet(p.InnerPeer),
		}
		if err := netlink.RouteAdd(route); err != nil {
			return cleanup(fmt.Errorf("gre: route to peer %s: %w", p.InnerPeer, err))
		}
	}
	return nil
}

// Remove deletes the named GRE interface. A missing interface is not an error.
func Remove(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // already gone
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("gre: delete %s: %w", name, err)
	}
	return nil
}

// OuterMTU returns the MTU of the interface that owns the local outer address.
// It lets the server contribute its real link MTU to negotiation.
func OuterMTU(local netip.Addr) (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, err
	}
	family := netlink.FAMILY_V6
	if local.Is4() {
		family = netlink.FAMILY_V4
	}
	for _, l := range links {
		addrs, err := netlink.AddrList(l, family)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok && ip.Unmap() == local {
				return l.Attrs().MTU, nil
			}
		}
	}
	return 0, fmt.Errorf("gre: no interface owns outer address %s", local)
}

// hostNet returns a host-length IPNet (/32 or /128) for a.
func hostNet(a netip.Addr) *net.IPNet {
	bits := 128
	if a.Is4() {
		bits = 32
	}
	return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(bits, bits)}
}
