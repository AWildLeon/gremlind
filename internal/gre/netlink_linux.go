package gre

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// This file implements the small slice of rtnetlink that gremlind needs,
// directly over an AF_NETLINK socket via golang.org/x/sys/unix — no third-party
// netlink library.

var (
	native = binary.NativeEndian
	nlSeq  atomic.Uint32
)

// errNoDevice is returned when a link lookup finds no matching interface.
var errNoDevice = errors.New("gre: no such device")

// IFLA_GRE_* attribute types (from linux/if_tunnel.h) — not exported by x/sys/unix.
const (
	iflaGreIFlags     = 2
	iflaGreOFlags     = 3
	iflaGreIKey       = 4
	iflaGreOKey       = 5
	iflaGreLocal      = 6
	iflaGreRemote     = 7
	iflaGreEncapType  = 14
	iflaGreEncapFlags = 15
	iflaGreEncapSport = 16
	iflaGreEncapDport = 17

	greSeqFlag = 0x1000 // GRE_SEQ flag in the GRE header flags field
	greKeyFlag = 0x2000 // GRE_KEY flag in the GRE header flags field

	// TUNNEL_ENCAP_FOU from linux/if_tunnel.h — Foo-over-UDP encapsulation.
	tunnelEncapFOU = 1
)

func align4(n int) int { return (n + 3) &^ 3 }

func beU16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func beU32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

// nativeU16 encodes v in host byte order — unlike beU16, used for netlink
// fields the kernel reads with nla_get_u16 (a plain local value, not a
// wire-format field). IFLA_GRE_ENCAP_TYPE/ENCAP_FLAGS are nla_get_u16;
// ENCAP_SPORT/ENCAP_DPORT are nla_get_be16 (real port numbers) and use beU16.
func nativeU16(v uint16) []byte {
	b := make([]byte, 2)
	native.PutUint16(b, v)
	return b
}

// nlmsg builds a single rtnetlink message: a NlMsghdr followed by a fixed
// service header and a sequence of (possibly nested) attributes.
type nlmsg struct{ b []byte }

func newNlmsg(typ, flags uint16) *nlmsg {
	m := &nlmsg{b: make([]byte, unix.SizeofNlMsghdr)}
	native.PutUint16(m.b[4:], typ)
	native.PutUint16(m.b[6:], flags)
	native.PutUint32(m.b[8:], nlSeq.Add(1))
	return m
}

// put appends a fixed service header (IfInfomsg/IfAddrmsg/RtMsg).
func (m *nlmsg) put(hdr []byte) { m.b = append(m.b, hdr...) }

// attr appends a single attribute, padded to a 4-byte boundary.
func (m *nlmsg) attr(typ uint16, data []byte) {
	l := unix.SizeofRtAttr + len(data)
	m.b = append(m.b, byte(l), byte(l>>8), byte(typ), byte(typ>>8))
	m.b = append(m.b, data...)
	for pad := align4(l) - l; pad > 0; pad-- {
		m.b = append(m.b, 0)
	}
}

// beginNested/endNested bracket a container attribute.
func (m *nlmsg) beginNested(typ uint16) int {
	pos := len(m.b)
	m.b = append(m.b, 0, 0, byte(typ), byte(typ>>8))
	return pos
}

func (m *nlmsg) endNested(pos int) {
	l := len(m.b) - pos
	native.PutUint16(m.b[pos:], uint16(l))
}

func (m *nlmsg) finalize() []byte {
	native.PutUint32(m.b[0:], uint32(len(m.b)))
	return m.b
}

// exec sends the request and reads replies. For dump=false it returns after the
// terminating NLMSG_ERROR ack (error code 0 = success). For dump=true it
// collects every response payload until NLMSG_DONE.
func nlExec(req []byte, dump bool) ([][]byte, error) {
	return nlExecProto(unix.NETLINK_ROUTE, req, dump)
}

// nlExecProto is nlExec generalized over the netlink protocol/family, so the
// same minimal request/response plumbing serves both rtnetlink (this file)
// and genetlink (fou_linux.go).
func nlExecProto(proto int, req []byte, dump bool) ([][]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, fmt.Errorf("gre: netlink socket: %w", err)
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("gre: netlink bind: %w", err)
	}
	if err := unix.Sendto(fd, req, 0, sa); err != nil {
		return nil, fmt.Errorf("gre: netlink send: %w", err)
	}

	var out [][]byte
	buf := make([]byte, 65536)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("gre: netlink recv: %w", err)
		}
		b := buf[:n]
		for len(b) >= unix.SizeofNlMsghdr {
			l := int(native.Uint32(b[0:]))
			typ := native.Uint16(b[4:])
			if l < unix.SizeofNlMsghdr || l > len(b) {
				return nil, fmt.Errorf("gre: malformed netlink message")
			}
			payload := b[unix.SizeofNlMsghdr:l]
			switch typ {
			case unix.NLMSG_ERROR:
				errno := int32(native.Uint32(payload[0:]))
				if errno != 0 {
					return nil, fmt.Errorf("gre: netlink: %w", unix.Errno(-errno))
				}
				return out, nil // ack
			case unix.NLMSG_DONE:
				return out, nil
			default:
				cp := make([]byte, len(payload))
				copy(cp, payload)
				out = append(out, cp)
			}
			b = b[align4(l):]
		}
		if !dump {
			return out, nil
		}
	}
}

// nlattr is a parsed attribute.
type nlattr struct {
	typ  uint16
	data []byte
}

func parseAttrs(b []byte) []nlattr {
	var out []nlattr
	for len(b) >= unix.SizeofRtAttr {
		l := int(native.Uint16(b[0:]))
		typ := native.Uint16(b[2:])
		if l < unix.SizeofRtAttr || l > len(b) {
			break
		}
		out = append(out, nlattr{typ, b[unix.SizeofRtAttr:l]})
		b = b[align4(l):]
	}
	return out
}

// --- typed operations ---

type linkInfo struct {
	index int32
	name  string
	kind  string // rtnetlink IFLA_INFO_KIND, e.g. "gre" or "ip6gre"
}

func dumpLinks() ([]linkInfo, error) {
	m := newNlmsg(unix.RTM_GETLINK, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	m.put(make([]byte, unix.SizeofIfInfomsg))
	msgs, err := nlExec(m.finalize(), true)
	if err != nil {
		return nil, err
	}
	var out []linkInfo
	for _, p := range msgs {
		if len(p) < unix.SizeofIfInfomsg {
			continue
		}
		li := linkInfo{index: int32(native.Uint32(p[4:]))}
		for _, a := range parseAttrs(p[unix.SizeofIfInfomsg:]) {
			switch a.typ {
			case unix.IFLA_IFNAME:
				li.name = trimNul(a.data)
			case unix.IFLA_LINKINFO:
				for _, nested := range parseAttrs(a.data) {
					if nested.typ == unix.IFLA_INFO_KIND {
						li.kind = trimNul(nested.data)
					}
				}
			}
		}
		if li.name != "" {
			out = append(out, li)
		}
	}
	return out, nil
}

// linkIndex resolves an interface name to its index by dumping links.
func linkIndex(name string) (int32, error) {
	links, err := dumpLinks()
	if err != nil {
		return 0, err
	}
	for _, li := range links {
		if li.name == name {
			return li.index, nil
		}
	}
	return 0, errNoDevice
}

// linkDel removes a link by index.
func linkDel(idx int32) error {
	m := newNlmsg(unix.RTM_DELLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	ifi := make([]byte, unix.SizeofIfInfomsg)
	native.PutUint32(ifi[4:], uint32(idx))
	m.put(ifi)
	_, err := nlExec(m.finalize(), false)
	return err
}

// linkSetUp brings a link up by index.
func linkSetUp(idx int32) error {
	m := newNlmsg(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	ifi := make([]byte, unix.SizeofIfInfomsg)
	native.PutUint32(ifi[4:], uint32(idx))
	native.PutUint32(ifi[8:], unix.IFF_UP)  // Flags
	native.PutUint32(ifi[12:], unix.IFF_UP) // Change mask
	m.put(ifi)
	_, err := nlExec(m.finalize(), false)
	return err
}

// addrAdd assigns addr/prefix to the link with the given scope, no DAD.
func addrAdd(idx int32, addr netip.Addr, prefix int, scope uint8) error {
	m := newNlmsg(unix.RTM_NEWADDR, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE)
	ifa := make([]byte, unix.SizeofIfAddrmsg)
	ifa[0] = addrFamily(addr)
	ifa[1] = byte(prefix)
	ifa[2] = unix.IFA_F_NODAD
	ifa[3] = scope
	native.PutUint32(ifa[4:], uint32(idx))
	m.put(ifa)
	m.attr(unix.IFA_LOCAL, addr.AsSlice())
	m.attr(unix.IFA_ADDRESS, addr.AsSlice())
	_, err := nlExec(m.finalize(), false)
	return err
}

// routeAdd installs an on-link route to dst/prefix out of the link.
func routeAdd(idx int32, dst netip.Addr, prefix int) error {
	m := newNlmsg(unix.RTM_NEWROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE)
	rtm := make([]byte, unix.SizeofRtMsg)
	rtm[0] = addrFamily(dst)
	rtm[1] = byte(prefix)       // Dst_len
	rtm[4] = unix.RT_TABLE_MAIN // Table
	rtm[5] = unix.RTPROT_BOOT   // Protocol
	rtm[6] = unix.RT_SCOPE_LINK // Scope
	rtm[7] = unix.RTN_UNICAST   // Type
	m.put(rtm)
	m.attr(unix.RTA_DST, dst.AsSlice())
	oif := make([]byte, 4)
	native.PutUint32(oif, uint32(idx))
	m.attr(unix.RTA_OIF, oif)
	_, err := nlExec(m.finalize(), false)
	return err
}

// linkMTUByAddr finds the interface owning outer and returns its MTU.
func linkMTUByAddr(outer netip.Addr) (int, error) {
	idx, err := addrOwner(outer)
	if err != nil {
		return 0, err
	}
	mtu, err := linkMTUByIndex(idx)
	if err != nil {
		return 0, err
	}
	return mtu, nil
}

func linkMTUByIndex(idx int32) (int, error) {
	m := newNlmsg(unix.RTM_GETLINK, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	m.put(make([]byte, unix.SizeofIfInfomsg))
	msgs, err := nlExec(m.finalize(), true)
	if err != nil {
		return 0, err
	}
	for _, p := range msgs {
		if len(p) < unix.SizeofIfInfomsg {
			continue
		}
		if int32(native.Uint32(p[4:])) != idx {
			continue
		}
		for _, a := range parseAttrs(p[unix.SizeofIfInfomsg:]) {
			if a.typ == unix.IFLA_MTU && len(a.data) >= 4 {
				return int(native.Uint32(a.data)), nil
			}
		}
	}
	return 0, fmt.Errorf("gre: MTU not found for ifindex %d", idx)
}

// pathMTU asks the kernel how packets from local to remote would be routed and
// returns that route's MTU. This is more accurate than looking up the interface
// owning the source address when the address lives on a dummy/loopback device,
// when policy routing chooses another egress link, or when a cached PMTU/route
// MTU is lower than the link MTU.
func pathMTU(local, remote netip.Addr) (int, error) {
	if !local.IsValid() || !remote.IsValid() || local.Is6() != remote.Is6() {
		return 0, fmt.Errorf("gre: invalid MTU route lookup local=%s remote=%s", local, remote)
	}

	const (
		rtaDst     = 1
		rtaSrc     = 2
		rtaOIF     = 4
		rtaMetrics = 8
		rtaxMTU    = 2
	)

	m := newNlmsg(unix.RTM_GETROUTE, unix.NLM_F_REQUEST)
	rtm := make([]byte, unix.SizeofRtMsg)
	rtm[0] = addrFamily(remote)
	rtm[1] = byte(remote.BitLen()) // Dst_len
	rtm[2] = byte(local.BitLen())  // Src_len
	m.put(rtm)
	m.attr(rtaDst, remote.AsSlice())
	m.attr(rtaSrc, local.AsSlice())

	msgs, err := nlExec(m.finalize(), false)
	if err != nil {
		return 0, err
	}
	for _, p := range msgs {
		if len(p) < unix.SizeofRtMsg {
			continue
		}
		var ifindex int32
		var routeMTU int
		for _, a := range parseAttrs(p[unix.SizeofRtMsg:]) {
			switch a.typ {
			case rtaOIF:
				if len(a.data) >= 4 {
					ifindex = int32(native.Uint32(a.data))
				}
			case rtaMetrics:
				for _, ma := range parseAttrs(a.data) {
					if ma.typ == rtaxMTU && len(ma.data) >= 4 {
						routeMTU = int(native.Uint32(ma.data))
					}
				}
			}
		}
		if routeMTU > 0 {
			return routeMTU, nil
		}
		if ifindex != 0 {
			return linkMTUByIndex(ifindex)
		}
	}
	return 0, fmt.Errorf("gre: route MTU not found for %s -> %s", local, remote)
}

// addrOwner dumps addresses and returns the index of the link owning outer.
func addrOwner(outer netip.Addr) (int32, error) {
	m := newNlmsg(unix.RTM_GETADDR, unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ifa := make([]byte, unix.SizeofIfAddrmsg)
	ifa[0] = addrFamily(outer)
	m.put(ifa)
	msgs, err := nlExec(m.finalize(), true)
	if err != nil {
		return 0, err
	}
	for _, p := range msgs {
		if len(p) < unix.SizeofIfAddrmsg {
			continue
		}
		idx := int32(native.Uint32(p[4:]))
		for _, a := range parseAttrs(p[unix.SizeofIfAddrmsg:]) {
			if a.typ != unix.IFA_ADDRESS && a.typ != unix.IFA_LOCAL {
				continue
			}
			if ip, ok := netip.AddrFromSlice(a.data); ok && ip.Unmap() == outer {
				return idx, nil
			}
		}
	}
	return 0, fmt.Errorf("gre: no interface owns outer address %s", outer)
}

// createGRE issues RTM_NEWLINK for an ip6gre/gre tunnel with the given keys,
// endpoints, MTU and (optionally) a disabled autogenerated link-local.
func createGRE(p Params) error {
	kind := "gre"
	if p.Local.Is6() {
		kind = "ip6gre"
	}
	m := newNlmsg(unix.RTM_NEWLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
	m.put(make([]byte, unix.SizeofIfInfomsg)) // family AF_UNSPEC, index 0

	m.attr(unix.IFLA_IFNAME, nameAttr(p.Name))
	mtu := make([]byte, 4)
	native.PutUint32(mtu, uint32(p.MTU))
	m.attr(unix.IFLA_MTU, mtu)

	li := m.beginNested(unix.IFLA_LINKINFO)
	m.attr(unix.IFLA_INFO_KIND, nameAttr(kind))
	data := m.beginNested(unix.IFLA_INFO_DATA)
	flags := uint16(0)
	if p.Key != 0 {
		m.attr(iflaGreIKey, beU32(p.Key))
		m.attr(iflaGreOKey, beU32(p.Key))
		flags |= greKeyFlag
	}
	if p.Seq {
		flags |= greSeqFlag
	}
	if flags != 0 {
		m.attr(iflaGreIFlags, beU16(flags))
		m.attr(iflaGreOFlags, beU16(flags))
	}
	m.attr(iflaGreLocal, p.Local.AsSlice())
	m.attr(iflaGreRemote, p.Remote.AsSlice())
	if p.FOUDport != 0 {
		m.attr(iflaGreEncapType, nativeU16(tunnelEncapFOU))
		m.attr(iflaGreEncapFlags, nativeU16(0))
		m.attr(iflaGreEncapSport, beU16(p.FOUSport))
		m.attr(iflaGreEncapDport, beU16(p.FOUDport))
	}
	m.endNested(data)
	m.endNested(li)

	_, err := nlExec(m.finalize(), false)
	return err
}

// setAddrGenModeNone disables the kernel's autogenerated (random EUI64)
// link-local on an existing link, via RTM_SETLINK with a nested
// IFLA_AF_SPEC{AF_INET6{IFLA_INET6_ADDR_GEN_MODE}}. Must run before the link is
// brought up, otherwise the random address is already present.
func setAddrGenModeNone(idx int32) error {
	m := newNlmsg(unix.RTM_SETLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	ifi := make([]byte, unix.SizeofIfInfomsg)
	native.PutUint32(ifi[4:], uint32(idx))
	m.put(ifi)
	af := m.beginNested(unix.IFLA_AF_SPEC)
	in6 := m.beginNested(uint16(unix.AF_INET6))
	m.attr(unix.IFLA_INET6_ADDR_GEN_MODE, []byte{in6AddrGenModeNone})
	m.endNested(in6)
	m.endNested(af)
	_, err := nlExec(m.finalize(), false)
	return err
}

// nameAttr returns a NUL-terminated string attribute payload.
func nameAttr(s string) []byte { return append([]byte(s), 0) }

func addrFamily(a netip.Addr) uint8 {
	if a.Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func trimNul(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
