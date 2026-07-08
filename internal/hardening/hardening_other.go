//go:build !linux

package hardening

import "log/slog"

// Apply is a no-op on non-Linux platforms.
func Apply(log *slog.Logger) {
	log.Debug("process hardening skipped: unsupported platform")
}
