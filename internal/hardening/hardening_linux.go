//go:build linux

// Package hardening applies small, process-local safety knobs that do not
// replace service-manager sandboxing but make gremlind safer by default.
package hardening

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// Apply tightens process defaults while keeping the daemon able to manage GRE
// links. It is intentionally best-effort: externally imposed sandboxes may
// already deny some operations, and those denials should not make a safer
// environment fail to start.
func Apply(log *slog.Logger) {
	// Files we create should be private unless a specific code path explicitly
	// widens permissions afterwards (e.g. admin_socket_mode).
	oldUmask := unix.Umask(0o077)
	log.Debug("process umask tightened", "old", fmt.Sprintf("%03o", oldUmask), "new", "077")

	// Secrets may live in memory (PSKs, per-client secrets). Do not produce core
	// files and make ptrace/proc-mem style dumping harder for same-UID processes.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Warn("hardening: disable core dumps failed", "err", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Warn("hardening: disable dumpable failed", "err", err)
	}

	// Never gain additional privilege through execve (setuid bits, file caps).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Warn("hardening: no_new_privs failed", "err", err)
	}

	// Do not carry ambient caps. Keep only CAP_NET_ADMIN in the capability
	// bounding set because GRE/netlink provisioning needs it; drop everything
	// else from future execs (notably hooks).
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		log.Debug("hardening: clear ambient caps failed", "err", err)
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		if cap == unix.CAP_NET_ADMIN {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil && os.Geteuid() == 0 {
			log.Debug("hardening: drop capability from bounding set failed", "cap", cap, "err", err)
		}
	}
}
