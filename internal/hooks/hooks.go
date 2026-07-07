// Package hooks runs optional pppd-style scripts when a tunnel interface goes
// up or down, passing session details via the environment.
package hooks

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// Info describes a tunnel event passed to a hook via the environment.
type Info struct {
	Event      string // "up" or "down"
	Iface      string
	ClientID   string
	InnerLocal netip.Addr
	InnerPeer  netip.Addr
	OuterLocal netip.Addr
	OuterPeer  netip.Addr
	GREKey     uint32
	MTU        int
}

func (i Info) env() []string {
	e := os.Environ()
	add := func(k, v string) { e = append(e, k+"="+v) }
	add("GREMLIND_EVENT", i.Event)
	add("GREMLIND_IFACE", i.Iface)
	add("GREMLIND_CLIENT_ID", i.ClientID)
	add("GREMLIND_INNER_LOCAL", i.InnerLocal.String())
	add("GREMLIND_INNER_PEER", i.InnerPeer.String())
	add("GREMLIND_OUTER_LOCAL", i.OuterLocal.String())
	add("GREMLIND_OUTER_PEER", i.OuterPeer.String())
	add("GREMLIND_GRE_KEY", strconv.FormatUint(uint64(i.GREKey), 10))
	add("GREMLIND_MTU", strconv.Itoa(i.MTU))
	return e
}

// Run executes script (if non-empty) with the info exported in the environment.
// Failures are logged but never fatal — a hook must not break the data-plane.
func Run(ctx context.Context, log *slog.Logger, script string, info Info) {
	if script == "" {
		return
	}
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, script)
	cmd.Env = info.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Warn("hook failed", "event", info.Event, "script", script, "err", err, "output", string(out))
		return
	}
	if len(out) > 0 {
		log.Debug("hook output", "event", info.Event, "script", script, "output", string(out))
	}
}
