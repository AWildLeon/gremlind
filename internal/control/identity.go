package control

// ValidClientID reports whether id is safe to use in logs, status output and
// hook environments. Keep the grammar intentionally small: printable protocol
// identifiers only, no whitespace/control chars/terminal escapes.
func ValidClientID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '.', '_', '-':
			continue
		default:
			return false
		}
	}
	return true
}
