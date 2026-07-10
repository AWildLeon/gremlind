// This file is intentionally build-tag free (unlike the rest of package gre,
// which is Linux-only): interface-name validation is shared by the
// cross-platform config loader, so it must compile on every target.
package gre

import "strings"

// MaxNameLen is the maximum length of a Linux network interface name. The
// kernel's IFNAMSIZ is 16 bytes including the terminating NUL, leaving 15
// usable characters.
const MaxNameLen = 15

// ValidName reports whether name is a safe network interface name: 1..15 bytes,
// first character alphanumeric, remaining characters limited to letters,
// digits, '_' and '-'. The tight charset keeps operator-chosen names free of
// path separators, shell metacharacters, and the "."/".." pseudo-entries, so
// they can be passed to the privileged netlink broker without further quoting.
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > MaxNameLen {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			continue
		case (r == '_' || r == '-') && i > 0:
			continue
		default:
			return false
		}
	}
	return true
}

// IsGeneratedName reports whether name lies in the built-in auto-generated
// interface namespace: "grem" (plain GRE), "grem0" (dialer), or "grem" followed
// by a hex session key. Operator-pinned names must avoid this namespace so they
// can never collide with a session's default interface name.
func IsGeneratedName(name string) bool {
	if name == "grem" || name == "grem0" {
		return true
	}
	rest, ok := strings.CutPrefix(name, "grem")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
