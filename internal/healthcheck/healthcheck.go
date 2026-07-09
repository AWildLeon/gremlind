package healthcheck

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gremlind/internal/config"
)

// Loop periodically verifies that the negotiated inner peer is reachable through
// the tunnel interface. It returns nil on context cancellation and an error once
// the configured consecutive failure threshold is reached.
func Loop(ctx context.Context, log *slog.Logger, cfg config.HealthCheck, iface string, peer netip.Addr) error {
	if !cfg.Enabled {
		<-ctx.Done()
		return nil
	}
	cfg = cfg.WithDefaults()
	target := peer
	if cfg.Target != "" {
		parsed, err := netip.ParseAddr(cfg.Target)
		if err != nil {
			return fmt.Errorf("healthcheck target: %w", err)
		}
		target = parsed.Unmap()
	}
	if !target.IsValid() {
		return fmt.Errorf("healthcheck target is invalid")
	}

	sizes := packetSizes(cfg)
	failures := 0
	ticker := time.NewTicker(cfg.Interval.Std())
	defer ticker.Stop()

	for {
		if err := probeAllSizes(ctx, cfg, iface, target, sizes); err != nil {
			failures++
			log.Warn("inside-tunnel healthcheck failed", "iface", iface, "target", target, "packet_sizes", sizes, "failures", failures, "max_failures", cfg.Failures, "err", err)
			if failures >= cfg.Failures {
				if reconnect := runFailureActions(log, cfg, iface, target, sizes, failures, err); reconnect {
					return fmt.Errorf("inside-tunnel healthcheck failed %d times for %s via %s: %w", failures, target, iface, err)
				}
				failures = 0
			}
		} else if failures != 0 {
			log.Info("inside-tunnel healthcheck recovered", "iface", iface, "target", target)
			failures = 0
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func runFailureActions(log *slog.Logger, cfg config.HealthCheck, iface string, target netip.Addr, sizes []int, failures int, err error) bool {
	reconnect := false
	for _, action := range cfg.Actions {
		switch action {
		case "log":
			log.Error("inside-tunnel healthcheck threshold reached", "iface", iface, "target", target, "packet_sizes", sizes, "failures", failures, "action", action, "err", err)
		case "run_script":
			if scriptErr := runScript(cfg, iface, target, sizes, failures, err); scriptErr != nil {
				log.Error("inside-tunnel healthcheck script failed", "script", cfg.Script, "iface", iface, "target", target, "action", action, "err", scriptErr)
			} else {
				log.Info("inside-tunnel healthcheck script completed", "script", cfg.Script, "iface", iface, "target", target, "action", action)
			}
		case "reconnect":
			log.Error("inside-tunnel healthcheck requesting reconnect", "iface", iface, "target", target, "packet_sizes", sizes, "failures", failures, "action", action, "err", err)
			reconnect = true
		}
	}
	return reconnect
}

func runScript(cfg config.HealthCheck, iface string, target netip.Addr, sizes []int, failures int, probeErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout.Std())
	defer cancel()
	cmd := exec.CommandContext(ctx, cfg.Script)
	cmd.Env = append(os.Environ(),
		"GREMLIND_HEALTHCHECK_EVENT=failed",
		"GREMLIND_HEALTHCHECK_IFACE="+iface,
		"GREMLIND_HEALTHCHECK_TARGET="+target.String(),
		"GREMLIND_HEALTHCHECK_PACKET_SIZES="+joinInts(sizes),
		"GREMLIND_HEALTHCHECK_FAILURES="+strconv.Itoa(failures),
		"GREMLIND_HEALTHCHECK_ERROR="+probeErr.Error(),
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if stderr.Len() > 0 {
			return fmt.Errorf("%s: %s", err, stderr.String())
		}
		return err
	}
	return nil
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

func probeAllSizes(ctx context.Context, cfg config.HealthCheck, iface string, target netip.Addr, sizes []int) error {
	for i, size := range sizes {
		if i > 0 {
			if err := waitBetweenProbes(ctx, cfg, size); err != nil {
				return err
			}
		}
		if err := pingOnce(ctx, cfg, iface, target, size); err != nil {
			return fmt.Errorf("packet_size=%d: %w", size, err)
		}
	}
	return nil
}

func waitBetweenProbes(ctx context.Context, cfg config.HealthCheck, nextSize int) error {
	delay := cfg.InterPacketDelay.Std()
	threshold := cfg.LargePacketThreshold
	if threshold == 0 {
		threshold = 1
	}
	if nextSize >= threshold && cfg.LargePacketDelay.Std() > 0 {
		delay = cfg.LargePacketDelay.Std()
	}
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func pingOnce(ctx context.Context, cfg config.HealthCheck, iface string, target netip.Addr, packetSize int) error {
	probeCtx, cancel := context.WithTimeout(ctx, cfg.Timeout.Std())
	defer cancel()

	args := []string{"-n", "-c", "1", "-W", pingWaitSeconds(cfg.Timeout.Std())}
	if packetSize > 0 {
		args = append(args, "-s", strconv.Itoa(packetSize))
	}
	if cfg.BindInterface {
		args = append(args, "-I", iface)
	}
	args = append(args, target.String())

	cmd := exec.CommandContext(probeCtx, cfg.Command, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if probeCtx.Err() != nil {
			return probeCtx.Err()
		}
		if stderr.Len() > 0 {
			return fmt.Errorf("%s: %s", err, stderr.String())
		}
		return err
	}
	return nil
}

func packetSizes(cfg config.HealthCheck) []int {
	if len(cfg.PacketSizes) > 0 {
		return cfg.PacketSizes
	}
	return []int{cfg.PacketSize}
}

func pingWaitSeconds(d time.Duration) string {
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}
