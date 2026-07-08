package gre

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Minimal genetlink (generic netlink) support, used only to register a
// receive port with the kernel's "fou" (Foo-over-UDP) module — the listening
// counterpart to the IFLA_GRE_ENCAP_* attributes createGRE sets on the
// tunnel netdev itself (see netlink_linux.go). Same no-third-party-library,
// hand-rolled approach as the rtnetlink layer, just a different netlink
// family resolved dynamically (genetlink family IDs aren't fixed like
// rtnetlink's RTM_* constants).

// CTRL_CMD_*/CTRL_ATTR_* (from linux/genetlink.h) and FOU_*  (from
// linux/fou.h) — not exported by x/sys/unix.
const (
	ctrlCmdGetFamily   = 3
	ctrlAttrFamilyName = 2
	ctrlAttrFamilyID   = 1

	fouGenlName    = "fou"
	fouCmdAdd      = 1
	fouAttrPort    = 1 // be16
	fouAttrAF      = 2 // u8
	fouAttrIPProto = 3 // u8
	fouAttrType    = 4 // u8
	fouEncapDirect = 1 // FOU_ENCAP_DIRECT: demux purely on ipproto, no GUE header
)

// genlFamilyID resolves a generic-netlink family name (e.g. "fou") to its
// dynamically-assigned family ID via the GENL_ID_CTRL controller.
func genlFamilyID(name string) (uint16, error) {
	m := newNlmsg(unix.GENL_ID_CTRL, unix.NLM_F_REQUEST)
	m.put([]byte{byte(ctrlCmdGetFamily), 1, 0, 0}) // genlmsghdr{cmd, version, reserved}
	m.attr(ctrlAttrFamilyName, nameAttr(name))
	msgs, err := nlExecProto(unix.NETLINK_GENERIC, m.finalize(), false)
	if err != nil {
		return 0, fmt.Errorf("gre: resolve genl family %q: %w", name, err)
	}
	for _, p := range msgs {
		if len(p) < 4 {
			continue
		}
		for _, a := range parseAttrs(p[4:]) { // skip genlmsghdr
			if a.typ == ctrlAttrFamilyID && len(a.data) >= 2 {
				return native.Uint16(a.data), nil
			}
		}
	}
	return 0, fmt.Errorf("gre: genl family %q not found (fou kernel module not loaded?)", name)
}

// EnsureFOUReceive registers a UDP receive port with the kernel's fou module
// for decapsulating IPv6 Foo-over-UDP traffic carrying GRE (IPPROTO_GRE) —
// the counterpart to a GRE tunnel created with FOUDport set to this same
// port. Equivalent to `ip -6 fou add port <port> ipproto 47`. Idempotent:
// re-adding the same port is not an error.
func EnsureFOUReceive(port uint16) error {
	family, err := genlFamilyID(fouGenlName)
	if err != nil {
		return err
	}
	m := newNlmsg(family, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	m.put([]byte{byte(fouCmdAdd), 1, 0, 0})
	m.attr(fouAttrPort, beU16(port))
	m.attr(fouAttrAF, []byte{unix.AF_INET6})
	m.attr(fouAttrIPProto, []byte{unix.IPPROTO_GRE})
	m.attr(fouAttrType, []byte{fouEncapDirect})
	_, err = nlExecProto(unix.NETLINK_GENERIC, m.finalize(), false)
	if err != nil && !errIsExist(err) {
		return fmt.Errorf("gre: fou add port %d: %w", port, err)
	}
	return nil
}

// errIsExist reports whether err wraps EEXIST/EBUSY-style "already there"
// errno, so re-registering the same FOU port across reconnects isn't fatal.
func errIsExist(err error) bool {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == unix.EEXIST || errno == unix.EBUSY || errno == unix.EADDRINUSE
}
